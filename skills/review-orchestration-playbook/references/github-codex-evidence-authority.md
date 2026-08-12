# GitHub Codex Provider-Evidence Authority

## Ownership And Load Order

This file is the single detailed narrative protocol source for the GitHub Codex
lane. The Skill and role-specific references route decisions without repeating
wire schemas. Exact closed schemas and transitions live in the
[review-epoch machine](github-codex-review-epoch-state-machine.json) and the
conditional [base-only-retarget machine](base-only-retarget-state-machine.json);
machine JSON overrides neither this authority boundary nor independently pinned
consumer fingerprints.

Load this authority first, then the review-epoch machine. Load the retarget
machine only for a same-head base-only retarget, followed by
[GitHub PR probes](github-pr-probes.md) for acquisition and
[PR readiness](pr-readiness.md) for delivery gates. A summary, fixture, prompt,
or caller projection is never a substitute for those sources in that order.

## Current v41/v23 invariants

Epoch v41 retains the v40 attempt, transport, capture, and append-only history
machinery. It derives `consecutive_same_epoch_missed_ack_count` and the selected
timeout `[300, 600, 1200, 1800]` from complete same-epoch terminal history for
exact `@codex review`; a `selected-timeout` or `history-terminal` mismatch fails
closed. The result timeout remains 3,600 seconds from marker creation and the
overall epoch deadline remains 7,200 seconds from the first-attempt origin.
Neither `eyes`, progress, nor a serial retry resets those clocks. Each epoch
first selects one capture registration and one fresh capture current pointer
through externally addressed absent-to-registered and append CAS records.
Artifact completion closes request orchestration but does not itself complete
the named GitHub lane. Ancestry validation remains `O(B+V+E)`, where B is
authenticated raw bytes and inner closed rows actually read by top-level
validation; each identity is strict-loaded at most once.

The independent required Commit Status authority introduced in v38 remains in
v41. It reads the exact
current-head `/statuses` inventory in GitHub server order, selects the first
case-insensitive `codex/review-gate` context, then requires exact spelling and
the complete canonical producer binding. It never sorts by timestamps or IDs
and never skips a newer unbound or compatibility row to reuse an older success.
The parent-owned registry exact-sets sixteen role-typed initial/final readbacks:
review epoch, statuses, producer binding, run attempt, artifact inventory,
receipt archive, caller workflow, called workflow, and release admission.
Those sixteen roles supply only the required-Action status/producer subgraph.
The reducer's sole input is instead one parent-owned sealed composite coordinate
whose selected closed record contains four independent coordinates: that
sixteen-role status membership, provider validation, the immutable epoch first-
attempt clock, and the current marker/attempt state. Caller dictionaries,
provider or marker summaries, and standalone clock values are not authority.

The consumer caller uses
`JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`
once. GitHub resolves floating `v1` before this Skill runs. The resolved called
workflow SHA `W` is therefore exact-attempt evidence, not a synonym for the
Action commit `C`. Receipt `job.workflow_sha`, receipt `action.ref`, and the
unique run-attempt `referenced_workflows.sha` all equal `W`. The controlled
exact-pinned checkout output, receipt `action.commit_sha`, provenance
`action.commit_oid`, and provenance `tags.v1.peeled_commit_oid` all equal `C`.
The closed provenance `workflow_sha_resolution` contains exactly the signed
major-tag-object and exact-action-commit candidates, and `W` must match exactly
one for the globally selected release. Epoch v39 adds dynamic historical tag-
object OID proof on top of v38: each release candidate independently proves its
release, derived-minor, and historical-major tag objects by exact payload
verification; the separate live `v1` alias object is never reused as a
historical proof. Epoch v40 retained that v39 proof. Epoch v41 additionally
requires deterministic release-scoped retention refs for every candidate's
minor and major historical tag objects so their OIDs remain reachable after
the floating aliases move. The caller SHA, run/event head, `W`, `C`, and
PR/status head are five independent domains.

v41 retains v40's dynamic admission and admits only a globally unique immutable
annotated `v1.x.y`
release at or after `v1.5.1`, producer
receipt schema 1/protocol major 1, decision schema 1/policy major 1, release
provenance schema 2, and the trusted primary signer fingerprint
`EFBBC913F49A5F6E0AF0D248F70246143DC28F32`. The selected release's exact
policy version is retained as a strict SemVer audit value, must have major 1,
and must agree across the selected provenance fields and released decision-
table bytes; producer receipt v1 has no policy-version field and the Skill pins
no policy patch value. Release `v1.5.0`
is never admitted, even with a complete asset; no digest erratum path exists.
Every selected-candidate critical-file digest is recomputed from authenticated
raw bytes, cross-bound to provenance `raw_sha256` and
`frozen_admission_sha256`, and bound to its tree/blob at `C`; the Skill pins no
critical-file SHA. The release commit `C`, exact-attempt `W`, tag-object OIDs,
policy SemVer, digests, and remaining per-release runtime closure are derived
rather than caller supplied.
The consumer also pins neither the selected called-workflow bytes/digest nor
the selected release's complete external Action SHA set. A compatible signed
v1.x release may change comments, called-workflow bytes, and its internally
immutable external Action pins when the selected release remains completely
self-consistent across provenance, both repository trees/blobs, critical
files, and runtime semantic closure.

Retarget v23 consumes `github-codex-base-only-retarget-activity-classification-v4` only through `github-codex-base-only-retarget-activity-classification-membership-v2` and `github-codex-base-only-retarget-activity-classification-registry-readback-v2`, and accepts `github-codex-unused-review-epoch-supersession-v4`. Its aggregation key is immutable epoch/origin plus repository, PR, merge base, and head; movable base-ref name and tip are validated on every row but never split the group. It validates an arbitrary complete byte-identical historical cutover prefix, resolves this cutover's four predecessor authorities by exact memberships and store indices, and then uses one parent-owned single CAS to append logical supersession plus finalized origin. A later serial cutover selects that finalized origin without rewriting or dropping the earlier prefix. Partial, stale, resealed, cross-store, duplicate, reordered, exact-four-only, or out-of-order state fails closed. Its terminal-artifact-scope v2 shape type-sensitively equals the epoch machine's shape, including the six-field `publication_scope`, repository Git-object identity contract, and receipt cross-binding; missing, extra, wrong-type, swapped-base, stale-head, or identity drift fails closed.

Full raw REST comment/reaction response bytes are retained; legitimate extra fields are allowed, but required identity fields are exact. Every item is classified as exact, confirmed-different, or ambiguous. Exact issue-comment evidence requires Bot+App; exact review evidence is Bot-only. Complete RFC 8288 `first`/`prev`/`next`/`last`/`self` relations are validated. An empty exact-provider inline target is inconclusive.

Each associated-inline child's `commit_id` and `original_commit_id` are
independent 40-hex SHAs, not aliases of the parent review commit or current
head. For an inline finding, the parent review commit is carrier context only:
classify both child SHAs separately before aggregation. Any current-head or
parent-proved-ancestor target enters the canonical finding classifier; an
authoritatively resolved inline finding closes, while an unresolved or
unverifiably resolved one blocks. Only a child whose targets are both parent-
proved non-ancestors is audit-only. A value is not malformed merely because it
differs from the parent or head. Only missing, invalid, internally inconsistent,
or unproved values are malformed.

Historical reactions may remain only in one immutable
`github-codex-reaction-history-audit-v1` record. That small record is closed
to `{kind, review_epoch, raw_authority_graph_membership,
validated_projection_sha256, observed_requests, observed_reactions,
final_readback_identity_sha256}`; its raw membership selects one preexisting
parent-owned complete request/reaction pagination and provider-identity graph.
The consumer recomputes the projection and requires an independent final
readback. It creates no reaction state store, current pointer, initialization
CAS, completion CAS, completed audit state, or second completion graph.
Neither the record nor any reaction supplies provider clean, required-status
`PASS`, retry closure, named-lane completion, or readiness. `+1` is never
ACK or clean; `eyes` may ACK only through the main attempt machine.
Caller-built candidates, predicates, expected summaries, and Boolean subset
judgments remain non-authoritative.

Only `local-pre-dispatch-abandon-v1` and `authenticated-pre-acceptance-server-rejection-v1` can prove definitive no dispatch. One absent-to-registered CAS keyed by the exact five-field review epoch first publishes the parent-owned canonical ledger registration/readback together with its stable transport-outcome ledger ID, empty genesis, v2 genesis readback, and revision-one current pointer. The registration readback has no self-identity field: its external immutable key is the SHA-256 of the exact persisted bytes, while an independently content-addressed exact CAS byte record binds that digest, exact epoch and coordinates, one-shot nonce, registration and ledger IDs, and all three genesis identities. The reader enumerates every same-epoch parent-owned ledger, entry, readback, append, pointer, and committed-membership map and requires it to equal the registry-selected reachable set; a canonical chain beside an extra fork, partial or higher stale prefix, or second store fails closed. Membership snapshots themselves form a content-addressed append-transaction/readback chain: deletion, reorder, reseal, stale extra prefix, unreachable receipt, or competing current pointer fails. Starting at the registry-selected current pointer, the reader validates every successor arm and complete record back to genesis, derives resolution only from validated rows, and revalidates every reachable definitive row's phase-specific dispatch claim against epoch, attempt, body, and capability. Any reachable open, ambiguous, malformed, or claim-drifted row blocks retry and blocks append with zero mutation.

Each initial/final current inventory carries a mandatory parent capture-receipt membership. The receipt binds the inventory payload, five raw provider surfaces including the complete selected-request reaction traversal, a preregistered one-shot capability and request-start transaction, a pre-capture current-head readback, and a separately persisted authenticated scope-snapshot membership. That snapshot contains exact raw pull-detail and compare GET receipts, including canonical method/URL/status, operating identity, raw `Date` bytes and digest, normalized UTC second, raw body and digest, plus the parent local unique-merge-base proof. Pull derives lifecycle, repository ID/name, PR, base name/OID, and head; compare and local Git derive the epoch merge base. The epoch is exactly `{repository_id, repository_full_name, pull_request_number, pr_merge_base, head_sha}` while the six-field publication scope separately retains movable base metadata. Initial has no predecessor; final capture points to the exact initial capture membership and its scope predecessor must equal the exact scope membership loaded from that initial receipt. The epoch-owned registry selects the unique registered capture store and its revision-two current pointer; the initial and final append transactions form the only reachable prefix and the consumer exact-sets every capture, scope, capability, request-start, head, response, coordinate, pointer, and append map. Both stores enforce unique epoch/store/revision/index coordinates with absent-or-byte-identical reread semantics. Final uses distinct capability/transaction/pull/compare/snapshot identities, and its pull `Date` is later than both initial response dates. Restamping old bytes, omitting compare, cross-splicing a capture from one chain with a scope predecessor from another, replaying one response for both phases, or hiding a parallel or partial capture chain is inconclusive.

Resource accounting chunk-scans and charges each independently loaded immutable raw UTF-8 string before hashing or admission, memoizes its byte count and digest only after full success, and does not recharge or rehash the same object in one invocation. Deadline or byte overflow publishes neither a partial memo nor a partial admission. The nested review epoch is exactly `{repository_id, repository_full_name, pull_request_number, pr_merge_base, head_sha}`; `base_ref_name` and `base_ref_oid` remain separate scope metadata. `base_ref_oid` and `pr_merge_base` are independently authenticated and may be byte-equal or different; neither substitutes for the other.


## Status And Scope

This reference defines the normative evidence-consumption contract for the
GitHub Codex lane. It separates request-orchestration policy from provider
review results, the required Action Commit Status, named-lane disposition, and
merge readiness. These are four separate layers. `PASS` in this reference means
only the canonically bound exact current-head `codex/review-gate` Commit Status
is `success` after the v41 reducer has accepted a strong current-head clean and
found no applicable open finding or error basis. It does not mean triple
completion or merge readiness.

This is a policy contract. It does not introduce a GitHub client, a runtime
evaluator, or a new provider API.

A legacy unreceipted artifact never becomes a selected terminal-classification
basis or selected completion basis.

## Required Action Producer And Dynamic Release Admission

The consumer installs one per-PR sole-job producer caller using exact
`JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`.
A repository may separately own an independent scheduled dispatcher that
boundedly selects PR targets and transports targeted runs into this caller.
That dispatcher is outside the required Action-producer binding: neither its
workflow nor its runs supply producer evidence, Action-status `PASS`, or an
alternate producer caller. Its exact trigger, cadence, permissions, and other
transport details remain repository implementation policy rather than generic
protocol or epoch-machine inputs.
Parse its authenticated raw bytes as one UTF-8 YAML 1.2 document with
block-style mappings before projection. Reject directives, explicit tags,
anchors, aliases, merge
keys, flow mappings, duplicate or nonscalar keys, and additional documents.
Epoch v41 retains v40's
`caller_workflow_contract.caller_event_type_allowlists` in the review-epoch
machine the sole complete event-type authority for the four currently consumed
Action events: `pull_request_target`, `issue_comment`,
`pull_request_review`, and `pull_request_review_comment`. The repository owns
the selected event-key set, each event subset, and event order; exact equality
with this repository's caller or fixture is never a generic protocol
requirement. When `on.<event>.types` is present, `<event>` must be a key in the
machine map and every member must be a unique plain string from that event's
allowlist. A repository-owned event without `types` remains allowed. This
contract adds no separate rule for `types: []`; the current parser behavior is
unchanged. A flow sequence is allowed only at such an event `types` node;
reject every flow sequence elsewhere. The top-level key set is exactly
`{name, on, permissions,
concurrency, jobs}`; `jobs` contains only `codex-review-gate`, whose job
mapping contains only exact `name: codex/review-gate runner` and the canonical
`uses`. A matching comment, string, environment value, alternate path,
second job, extra job field, step, or compatibility publisher is a decoy, not
authority.
The Action repository owns the called workflow and compatible v1.x producer
runtime. A compatible producer upgrade can still change the Action source and
release without changing every caller, but it is admissible only when the
fixed repository/path, schemas, protocol and policy majors, first-release
boundary, and signer match while the selected signed release internally
cross-binds its exact runtime policy SemVer and critical-file bytes. The Skill
does not fix a policy patch value, critical-file raw SHA, per-run `W`, release
commit `C`, signed tag-object OID, or compatible per-release external Action
SHA. It likewise has no exact called-workflow bytes or raw-SHA pin. Those
workflow bytes and the complete external Action SHA set are selected-release
values derived from signed provenance and independently authenticated Action-C
tree/blob evidence. Comments and internal immutable pins may evolve across
compatible v1.x releases; cross-release byte or pin equality is not an
admission predicate, while any floating, extra, or internally inconsistent use
inside the selected release is `ERROR`.

This deliberately accepts floating `@v1` as a pre-execution trust boundary.
GitHub resolves and executes the called workflow before post-run evidence can
be evaluated. A hostile, corrupt, or inadmissible resolution may therefore
have already run with the caller's delegated permissions. v41 can fail closed
and withhold required-status `PASS`; it cannot undo that execution. This tradeoff
is incompatible with per-consumer immutable-SHA execution pins and is accepted
by the workflow owner for zero-touch compatible v1.x upgrades.

For every selected status, retain independent initial and final authenticated
readbacks of the status inventory and GraphQL status nodes, run attempt,
artifact inventory and ZIP, producer receipt, caller workflow, called workflow,
complete Releases and per-release assets pagination, every candidate release's
authenticated record/provenance/commit/tree/critical blobs, its independently
fetched release, derived `v1.minor`, and historical provenance-`v1` tag objects
plus local signature verifiers, both deterministic release-scoped minor/major
retention refs, and the separate current `v1` alias ref/tag/local signature
verification. These records stay
inside the existing initial/final release-admission components; the parent
registry still has exactly sixteen roles. A trusted loader derives candidates
from the complete raw graph. A caller-supplied candidate list, selected tag, or
validity Boolean is never authority. The minimum authenticated GitHub `Date`
over every final response must be strictly later than the maximum over every
initial response. Ordinary `Date` movement is the freshness fence, not evidence
that protected content mutated.

The release-admission raw graph has exact envelope schema
`urn:joeyteng:codex-review-gate:release-admission:2` and is closed to `schema`,
`release_inventory_capture`, `immutable_releases_setting_capture`, the three
`v1_alias_tag_*` captures, and `candidate_release_admission_captures`. Each
candidate record is closed to `release_tag`, release and asset-inventory
captures, release-tag ref/object/local-verification captures, provenance,
`provenance_minor_tag_retention_ref_capture`,
`provenance_minor_tag_object_capture`,
`provenance_minor_tag_signature_verification_capture`,
`provenance_v1_tag_retention_ref_capture`,
`provenance_v1_tag_object_capture`,
`provenance_v1_tag_signature_verification_capture`,
`source_commit_capture`, `source_root_tree_capture`,
`source_action_subtree_capture`, Action commit/tree, and
`critical_file_captures`. The Action commit capture is the canonical
authenticated `/git/commits/{C}` response and binds its tree to
`provenance.action.tree_oid`. Each critical-file record is closed to `{name,
release_path, tree_blob_oid, raw_blob_capture}`; the raw blob capture binds the
Action repository, exact path, ref `C`, authenticated raw bytes, digest, and
the matching provenance/tree entry.

For candidate `v1.m.p`, derive the exact ordered tag-proof roles as release
`v1.m.p`, minor `v1.m`, and major `v1`. The release role additionally proves
the immutable release ref still resolves to `R`. Derive the minor retention ref
as `refs/tags/codex-review-gate-retention/v1.m.p/minor` and the major retention
ref as `refs/tags/codex-review-gate-retention/v1.m.p/major`. In both initial and
final capture, each ref must return its exact full name, `object.type: tag`, the
corresponding provenance `tag_object_oid` as `object.sha`, and the canonical
Git-tag-object URL. Those two ref captures add exactly four GitHub GETs per
candidate across the two phases. Each role then fetches its tag object directly
by that candidate's provenance `tag_object_oid`, requires the
canonical Action-repository object, exact tag name, and direct commit target
`C`, and recomputes the exact payload and signature digests consumed by the
closed local OpenPGP verifier. Each local result is closed to `{schema,
tag_object_sha, signed_payload_sha256, signature_sha256, verified, method,
signing_key_fingerprint, primary_signer_fingerprint}`. Its signing-key and primary-signer fingerprints
are independently retained and cross-bound respectively to provenance
`signing_key_fingerprint` and `primary_key_fingerprint`; only the primary-
signer predicate must equal the trusted primary fingerprint. The retention refs
are reachability anchors only: they supply no signature, provenance, release
selection, runtime `W`, or compatibility authority. Current floating minor or
major refs are independent live aliases, not historical proof, and may move
after a compatible release. The top-level current-`v1` capture remains a
separate final-stable live-alias observation and may differ from a historical
candidate's provenance-`v1` object without affecting that candidate's
classification.

Before any v41 consumer activates, the producer must correctively backfill the
exact ref `refs/tags/codex-review-gate-retention/v1.5.1/minor` to directly name
`ab610036500f2eacb483abd3a6c272fd86ce5dec` and exact ref
`refs/tags/codex-review-gate-retention/v1.5.1/major` to directly name
`9e9f2377342805156afcb0724f501509ef4e444c`, then independently read them back.
This backfill changes only Git reachability: it must not rewrite or reserialize
the immutable v1.5.1 provenance-v2 asset. For future releases, materialize and
sign all tag objects and the provenance asset, create and verify both retention
refs, and only then make the non-draft immutable GitHub Release discoverable;
move floating aliases only after that release-scoped proof is durable.

The candidate tree capture is the authenticated
`/git/trees/{provenance.action.tree_oid}?recursive=1` response. Its root SHA
equals the Action commit tree, `truncated` is exact `false`, paths are unique
canonical relative Git paths, and every entry uses exactly one legal pair:
`tree/040000`, `blob/100644`, `blob/100755`, `blob/120000`, or
`commit/160000`. Unknown pairs, truncation, duplicate/conflicting paths, or
missing structure are malformed or incomplete. Compare
`provenance.released_tree` only with the non-tree leaf manifest
(`blob` and `commit` entries); tree rows prove recursive structure but are
not leaf-manifest members. Critical files must still bind their exact Action-C
blob leaves and authenticated raw bytes.

Keep five SHA/OID domains independent:

1. the Actions run/event head;
2. caller `GITHUB_WORKFLOW_SHA` and its authenticated raw caller-workflow blob;
3. exact-attempt called-workflow SHA `W`;
4. resolved Action commit `C`; and
5. the current PR/status head.

Do not require accidental equality across domains. Derive `W` only by equality
of receipt `job.workflow_sha`, receipt `action.ref`, and the unique canonical
run-attempt `referenced_workflows.sha`. Derive `C` only by equality of the
controlled exact-pinned checkout output, receipt `action.commit_sha`,
provenance `action.commit_oid`, and provenance
`tags.v1.peeled_commit_oid`. Receipt `action.repository` must equal
`job.workflow_repository`, and `action.immutable` is exact `true`.

Strictly parse the independently authenticated called-workflow bytes at `C`
and verify the complete runtime dataflow. The one checkout receives the exact-
attempt `W` as its ref; it does not receive `C` and must not re-resolve the
current floating `v1`. Checkout peels or resolves `W` and emits one verified
full commit output equal to selected `C`. That output is the sole writer of
the Action-commit environment binding; the one executable local `uses`
resolves only the Action root in that checkout; receipt
`action.commit_sha` comes from the same binding; and it equals provenance
`action.commit_oid` and `tags.v1.peeled_commit_oid`. A fallback, duplicate,
decoy, alternate checkout root, or mismatch is `ERROR`. The provenance
runtime closure is a closed cross-check, not a substitute for parsing this raw
workflow chain.

The closed `runtime_closure.called_workflow.workflow_sha_resolution` is exactly
`{selection, action_commit_oid, candidates}`. `selection` is exact
`selected-sha-equals-exactly-one-candidate`; `action_commit_oid` is `C`; and the
ordered candidates are exactly:

1. `signed-major-tag-object`: `workflow_sha_field` is
   `tags.v1.tag_object_oid`, `workflow_sha` is the selected candidate's
   independently fetched and locally verified historical signed annotated tag-
   object `T`,
   `action_commit_field` is `tags.v1.peeled_commit_oid`, and
   `action_commit_oid` is `C`;
2. `exact-action-commit`: both field names are `action.commit_oid`, and both
   OID values are `C`.

Each candidate is closed to `{kind, workflow_sha_field, workflow_sha,
action_commit_field, action_commit_oid}`. `W` must equal exactly one candidate
`workflow_sha`. The current live form is `W == T`; the permitted future API
form is `W == C`. In both forms the selected candidate's independently proved
signed `v1` tag object `T` directly targets commit `C`. The separate current
floating alias object `T_current` does not enter this equality and may name a
later compatible release. A nested tag, another object type, or multiple
matches is malformed `ERROR`; zero matches with otherwise complete valid tag
proofs establishes that this candidate is `proved-incompatible` with exact-
attempt `W`. Fetch the called workflow at `C`; its
blob and runtime closure must equal the admitted tree and frozen reusable-
workflow raw SHA-256.

Receipt `job.workflow_ref` is exact
`JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@refs/tags/v1`.
The unique run-attempt member has exact `path`
`JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`
and a non-null exact `ref: refs/tags/v1`. Missing or null fails closed. Preserve
the exact-attempt `W`; never replace it with the current floating `v1` value.
Receipt `producer.repository` equals the
independently authenticated caller repository and `producer.server_url` is
exact `https://github.com`.

Provenance `source.commit_oid` names a distinct commit in
`JoeyTeng/codex-review-gate`; it is not `C` and is never pinned by this Skill.
For every candidate and in both initial/final release-admission captures,
authenticate that exact source commit, require its commit tree to equal
`provenance.source.tree_oid`, fetch the complete untruncated recursive source
root tree, and select exactly one `packages/action` tree entry. Independently
fetch that subtree recursively from the source repository. Its root OID and
complete canonical entry projection must equal the independently authenticated
Action-C root tree. Cross-bind the same equality through
`provenance.source.action_subtree`, `provenance.proofs`, critical-file
`source_path` leaves, and corresponding blob digests. Neither provenance self-
declaration nor one repository's capture substitutes for the other. Missing,
incomplete, malformed, cross-candidate, or mismatched source evidence makes the
candidate `malformed-or-incomplete-error`. This stronger dual-repository
binding adds no outer registry role and fixes no source commit or tree, so
compatible signed v1.x releases remain dynamic.

Discover releases only from complete bounded authenticated GitHub Releases
pagination. Classify every semver `v1.x.y` at or after `v1.5.1` as exactly
`valid`, `proved-incompatible`, or `malformed-or-incomplete-error`.
`valid` means every release, asset, both release-scoped retention refs, all
three per-candidate tag-object and local-signature proofs, provenance,
compatibility, exact-attempt W-resolution,
Action-C tree/leaf-manifest, critical-byte, and runtime predicate passes.
`proved-incompatible` requires complete, well-typed, authenticated,
internally unambiguous evidence that proves at least one admission predicate
false; only this class may be excluded. In particular, an independently valid
OpenPGP signature with one unambiguous primary signer whose fingerprint differs
from the trusted signer is `proved-incompatible`, not malformed. An otherwise
complete candidate whose valid two-arm workflow resolution has zero matches for
exact-attempt `W` is likewise `proved-incompatible`; a later current-`v1` alias
value never changes that classification. A missing,
cryptographically invalid, ambiguous, or unverifiable signature remains
`malformed-or-incomplete-error`, as does any missing, malformed, unstable,
wrong-type, wrong-OID, wrong-name, or wrong-URL retention ref; any missing,
wrong-object, or cross-candidate release/minor/major tag proof; or a multiple-
match workflow resolution. An evidence-integrity or cross-binding
contradiction, including any source commit/tree/subtree mismatch or source-
subtree-to-Action-C-root mismatch, is also `malformed-or-incomplete-error`, not
`proved-incompatible`. Any missing page or asset, malformed or
conflicting record, invalid structure, or unverifiable sibling makes the
entire admission `ERROR`, even when another candidate is valid. After
excluding only proved-incompatible candidates, the fully valid set must have
cardinality exactly one; zero or more than one is `ERROR`. Recompute the full
candidate classification vector at final readback. `R` peeling to `C` alone
cannot select a release because multiple patch tags may share one commit.
Current floating `v1` likewise cannot select a historical run. Release
`v1.5.0` is always rejected; no complete-asset or digest-erratum exception
exists.

The selected release must be an authenticated immutable GitHub Release for a
published annotated `v1.x.y` tag at or after `v1.5.1`. The repository immutable-
releases setting, every candidate release and asset graph, the independent
current `v1` alias ref/object `T_current`, every candidate's release `R`,
release-scoped minor/major retention refs, derived-minor and historical-major
`T` tag objects and local verifiers, commit `C`, tree, critical blobs, and the
independently authenticated source commit/root tree/
`packages/action` subtree must remain final-stable. Each candidate's release,
minor, and major tag object directly targets object type `commit` at its `C`;
nested tags are rejected. Release-provenance JSON
is the authenticated release asset; there is no separate provenance-signature
asset. Signature authority comes from repeated strict local OpenPGP verification
of each annotated tag object's exact signed payload and signature. Only after
that cryptographic verification succeeds does the separate trusted-primary-
signer predicate compare the unambiguous fingerprint with
`EFBBC913F49A5F6E0AF0D248F70246143DC28F32`.

The immutable provenance-v2 manifest root is exactly `schema`, `schema_version`, `release`,
`compatibility`, `source`, `action`, `runtime_closure`, `tags`, `proofs`,
`released_tree`, `critical_files`, and `contracts`. Compatibility is the closed
object `{producer_protocol_major, github_immutable_release_required,
receipt_schema, decision_table, called_workflow}`; decision-table `schema_id`
is exact `urn:joeyteng:codex-review-gate:decision-table:1`. Runtime closure's
called workflow is exactly `{repository, caller_selector, caller_reference,
immutable_reference, workflow_sha_resolution, release_path, source_path,
blob_oid, raw_sha256}`. `critical_files.reusable_workflow` has those
path/blob/digest and reference bindings plus `frozen_admission_sha256`.
Within these closed shapes, Action-side `release_path`, blob, digest,
immutable reference, local use, and external-action closure are admission
cross-checks; each `source_path` and `source_checkout` value is closed-validated
and cross-bound to the independently authenticated source commit,
`packages/action` subtree leaf, and matching Action-C runtime leaf under the
dual-repository admission contract above.
Provenance `tags` is closed to the release tag, `v1.minor`, and `v1`; every tag
entry is closed to `{ref, annotated, tag_object_oid, peeled_commit_oid,
signature}`, with the signature object closed to `{verified, method,
signing_key_fingerprint, primary_key_fingerprint}`. For each candidate,
`tags.v1` binds its historical `T` and `C`, the exact derived minor key binds
its separately fetched and verified minor tag object and `C`, and
`tags[release_tag]` binds `R` and `C`. Validate all three actual objects,
payloads, signatures, local verifier results, and the `proofs` map; provenance
fields alone are not verification. Release-admission envelope v2 adds no field
to this provenance shape and does not change any provenance-v2 byte or digest.
Do not invent an `immutable_tag`, retention-ref field, or separate signature
asset inside provenance.

The top-level live-alias proof is closed independently: current
`refs/tags/v1` resolves to tag object `T_current`; the canonical object fetch
names tag `v1`, directly targets commit `C_current`, and its exact payload and
signature plus signing-key and trusted-primary fingerprints pass the same
closed local verifier. `W` still comes only from the
run and receipt. If `W == T_current`, require `C_current == C` as an additional
corroboration of the selected candidate's major-tag arm. If `W != T_current`, a
complete trusted alias move is permitted and neither current value replaces or
invalidates the selected candidate's historical `T`/`C`. Malformed, invalid,
untrusted, or unstable live-alias proof is producer-binding `ERROR`, not a
candidate tri-state result.

Provenance schema
`urn:joeyteng:codex-review-gate:release-provenance:2` must close its
`compatibility`, `runtime_closure`, and
`critical_files.reusable_workflow` contracts. Receipt schema
`urn:joeyteng:codex-review-gate:producer-receipt:1` must report protocol major
1 and decision schema 1/policy major 1. Receipt v1 has no `policy_version`
field and must not be extended or treated as policy-version authority. Retain
the selected provenance's exact `policy_version` as a strict SemVer without a
leading `v`, require major 1, and require type-sensitive equality between
provenance `compatibility.decision_table.policy_version`,
`critical_files.decision_table.policy_version`, and the value strictly parsed
from the authenticated released decision-table raw bytes.
Compatibility called workflow is exact repository
`JoeyTeng/codex-review-gate-action`, path
`.github/workflows/codex-review-gate.yml`, selector `v1`. For every selected-
candidate `critical_files` entry, recompute SHA-256 from the exact authenticated
raw bytes and require it to equal both that provenance entry's `raw_sha256`
and `frozen_admission_sha256`; bind its release path and blob OID to the
complete authenticated tree at `C`. These are selected-release runtime values,
not consumer constants, and no caller digest or cross-candidate record may
substitute for them.
This evidence proves
authenticated run-level causal consistency plus signed immutable-release
admission. It is not cryptographic job provenance, provider request/run/artifact
lineage, or proof of the provider's internal review merge base. Action 1.5.1
defines no online revocation feed or retroactive post-publication revocation
guarantee.

## Historical v37 Fixed Baseline (Audit Only)

The following immutable snapshots explain the result-present design inherited
by v38 and retained by v39, v40, and v41. They are historical comparison evidence, not
current producer admission pins and must never replace the dynamic v1.x
validation above.

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

This was the v37 anti-drift baseline, not a floating reference to either
repository's default branch. It remains useful only to explain and regression-
test the inherited provider-result rationale. It is not an admission rule for
the v41 required Action producer.

Treat the source commit, released-Action commit, common tree ID, complete
15-path manifest, and the result-present decision rationale below as one atomic
historical v37 receipt. Matching only the executable files would not preserve
that historical release envelope, and matching only the prose would not
preserve the implementation that its named regressions exercised. Current
producer authority instead comes exclusively from the dynamic v1.x admission
contract above.

Only provider-result parsing authority is inherited: trustworthy provider
results classify the artifact outcome and supply blocking negative evidence,
while requests and run markers remain producer/audit evidence. The playbook's
raw REST/GraphQL review-thread proof, exact whole-PR scope and lifecycle gates,
closed terminal issue-comment carrier and edit-time rules, independent artifact-
publication scope receipt, and reaction-history audit are local extensions.
They are not attributed to the historical Action snapshot. The inherited
authority does not establish the provider's whole-PR input base, positive lane
completion, required Action producer binding, or merge readiness.

### Why Result-Present Evidence Is Not Whole-PR Completion

“Result-present evidence” means that a complete, trustworthy current-scope
provider artifact can supply an artifact-level clean/findings classification
without proving which request or run caused it. This is deliberately narrower
than lane completion for three reasons:

A complete, trustworthy current-scope provider result can establish the outcome
without proving which request or run caused it.

1. A provider-authored terminal payload carries the actual finding/no-findings
   decision and commit scope of that artifact; it does not authenticate the
   provider's input merge base. A request comment carries only intent to start.
2. GitHub review and issue-comment APIs do not expose a general request/run
   lineage. That absence means the current policy cannot prove positive whole-
   PR completion from a terminal payload; it does not authorize inference.
3. Duplicate or mistimed requests are still actionable orchestration defects,
   but they do not contradict what the provider reported. Keeping them in
   `request_policy` preserves the warning without corrupting the result plane.

With `scope_assurance: artifact-publication-only`, a terminal payload cannot
complete triple or make the PR merge-ready. Terminal findings remain blocking
negative evidence, while terminal clean is classification-only. Positive
completion requires a predeclared
provider-authenticated input-base or request/run/artifact binding, including
lineage; the current accepted schema sets are empty. v41 has no positive named-
lane completion path. A `thumbs-up-clean`/`+1` record is audit-only, and required
Action-status `PASS` is a separate required-check result rather than a triple-
completion claim.
This artifact-publication scope does not attest the provider's internal input
merge base. It is not the only retarget signal: the closed classifier evaluates
`none / observed / unknown`, where one definitive observed prior-epoch signal
selects `observed` and incomplete exclusion selects `unknown` rather than
absence.
Retarget v23 records this disposition as exact
`whole_pr_completion_action: triple-inconclusive`,
`clean_action: audit-only-no-merge-ready`, and
`negative_evidence_action: block-and-report-no-whole-pr-completion`; its
provider-authenticated `accepted_input_base_schemas` and
`accepted_lineage_schemas` sets are empty.
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
a complete terminal carrier; reactions never become v41 result or status
authority. Every exact-provider finding bound to the current head or to a
parent-proved local ancestor is applicable. An unresolved joined thread blocks
until its authoritative GraphQL state is resolved; later clean cannot close it.
An older threadless current-head or ancestor finding may be superseded only by
a strong, final-stable exact-current-head clean at a strictly later trusted
semantic server time. Equal-time or weak clean does not supersede. Only a
finding whose commit is parent-proved not to be an ancestor is audit-only.
Unknown ancestry stays pending while bounded acquisition is meaningful and is
an explicit error after exhaustion.
A truly absent pre-v1 receipt is the narrow legacy exception: only a strictly
older raw artifact recognized as exact `legacy-finding-native-review-v1` or an
old lowercase 10-hex `clean-pending-resolution` carrier may remain in the closed
`legacy_unreceipted_audit` partition. It is never terminal-classification or
completion authority and never becomes a selected basis. A later classified
receipt-bound result may carry the item in `legacy_unreceipted_artifacts`; the
legacy item does not by itself veto that result when every closed migration,
time, stability, precedence, ancestry, and thread gate closes.

## Decision

### Requests And Four Result Layers Are Separate

The request plane controls whether the orchestrator should create another
`@codex review` comment. Four independent layers then represent what the
provider reported, what the required Action check published, whether the named
GitHub lane completed, and whether the PR is merge-ready.

The exact six report planes are `request_policy`, `provider`,
`required_action_status`, `named_github_lane`, `reaction_audit`, and
`readiness`. Request policy and reaction audit are not additional reducer
layers.

| Report plane | Inputs | Authority |
| --- | --- | --- |
| `request_policy` | Exact request comments, their server IDs and times, local-lane ordering, and complete request enumeration | Warn, wait, or forbid another request |
| `provider` | Exact-bot terminal issue comments or pull-request reviews, associated inline comments, review-thread resolution, ancestry, acquisition state, and current scope | Classify `clean`, `findings`, `progress`, `transient-incomplete`, `malformed`, `pending`, or `inconclusive`; this is the sole owner of `evidence_basis` |
| `required_action_status` | Canonical current-head Commit Status plus the full hosted-producer/release binding | Reduce to `PASS`, `FAILURE`, `PENDING`, or `ERROR`; `PASS` means only required status `success` |
| `named_github_lane` | Provider input-base and request/run/artifact lineage authority | v41 has no positive GitHub-lane completion schema; clean or Action `PASS` remains triple-inconclusive |
| `reaction_audit` | The one optional immutable raw reaction-history audit record | Audit only; never clean, PASS, ACK, completion, or readiness authority |
| `readiness` | Required Action status plus all local lanes, CI, exact-secret, conversation, lifecycle, scope, authorization, branch/base, and current-head gates | Merge-ready only when every independent gate passes |

A request is never itself a review result. Conversely, a producer-side request
policy violation does not erase otherwise complete provider-authored result
evidence. Artifact classification and blocking negative-evidence consumption do
not require request/run attribution when the complete snapshot, provider
identity, terminal grammar, evidence ordering, and current scope establish that
artifact outcome. Neither terminal clean nor terminal findings supplies positive
lane completion under the current empty binding-schema sets. Required Action
`PASS` likewise does not fill those missing provider lineage schemas, and no
reaction supplies provider clean or acknowledgement.

### Required Action Status Reduction

Fully RFC-8288-paginate authenticated
`/commits/{head_sha}/statuses?per_page=100&page=1` and preserve GitHub's page
and array order. Case-fold each context only to locate the first matching
`codex/review-gate` row, then require its spelling to be exact. GitHub returns
these rows reverse chronologically; do not client-sort by `created_at`,
`updated_at`, or ID. Do not skip a newer malformed, unbound, differently cased,
or compatibility row to fall back to an older success. Raw-reread every REST
row's `node_id` through GraphQL `StatusContext` and bind context, state, target
URL, creation time, commit OID, and creator identity. A check run never
substitutes for this Commit Status.

The selected target URL identifies one exact run attempt. Initial and final
readbacks must bind that attempt and its complete `referenced_workflows`, the
one live digest-bound producer receipt artifact and closed receipt, the caller
workflow, exact-attempt `W`, called workflow at `C`, the exact two-candidate
resolution, the selected candidate's independent release `R`, minor, and
historical-major `T` tag proofs, the separate current alias `T_current`, and the
globally unique dynamically admitted immutable release. The existing sixteen
external registry roles do not expand; the initial/final release-admission
roles each bind the complete internal raw graph.
Context, head, state, description, creator, or apparent workflow identity alone
never proves the producer. A compatibility publisher remains audit-only even
when every visible status field looks canonical.

The reducer accepts only one parent-owned
`github-codex-sealed-reduction-authority-coordinate-v1`. That coordinate
selects one content-addressed closed
`github-codex-sealed-reduction-authority-record-v1` with exact review epoch and
exactly four component coordinates: the unchanged
`github-codex-required-status-authority-membership-v1` and its sixteen-role
readback graph, a parent-owned final-stable provider-validation row, the
immutable epoch first-attempt clock/cumulative-deadline custody row, and the
current marker/attempt ledger row including an explicit no-marker state. The
consumer independently reads and closed-validates the sealed record and every
component, requires type-sensitive epoch equality, and repeats byte-identical
final readbacks before reduction. Ordinary `provider_events`, status arrays,
marker objects, clock values, validity Booleans, prejoined records, caller
dictionaries, projected summaries, and caller-composed layer outcomes have no
authority.

After proved nonancestor evidence is audit-excluded, reduce in this order:

1. An unresolved applicable thread or unsuperseded applicable threadless
   finding is `FAILURE`. This outranks a simultaneous malformed artifact so
   the proved finding is never hidden.
2. Deterministic applicable malformed evidence is `ERROR` and authorizes no
   blind POST. Before the immutable epoch overall deadline, unknown ancestry,
   transient acquisition, or resource acquisition is `PENDING` while its
   existing bounded local budget remains and `ERROR` after local exhaustion; a
   clean artifact does not mask any such condition before that deadline.
3. Strictly before the overall deadline, only a strong, carrier-valid,
   final-stable clean bound exactly to the
   current head may reach the selected required status. With no blocker,
   canonical `success`, `failure`, `pending`, and `error` project respectively
   to `PASS`, `FAILURE`, `PENDING`, and `ERROR`. A hashless issue-comment clean
   is `ERROR`; no watermark may supply its commit binding. An ancestor-bound
   clean is `PENDING`.
4. Strictly before the overall deadline, without a strong current-head clean,
   required-status success cannot become
   `PASS`. A valid progress event is `PENDING` and does not change any clock.
   `eyes` may only move an admitted attempt from waiting-for-ACK to waiting-for-
   result. `+1` is neither ACK nor clean.
5. Preserve ACK 300 seconds with exponential retry capped at 1,800 seconds and
   result timeout 3,600 seconds from the current attempt's final-stable marker
   `created_at`. Keep those marker clocks independent from the immutable epoch
   first-attempt origin: the latter is the greatest authenticated GitHub
   `Date` in the complete first-attempt pre-request pull/compare pair, and the
   overall deadline is exactly 7,200 seconds later. A serial retry may create a
   new marker clock but must reuse that origin and deadline without reset or
   extension. Every `PENDING` reducer arm is legal only before the overall
   deadline.
6. At or after the overall deadline, preserve this final order: proved
   unresolved thread or unsuperseded applicable finding -> `FAILURE`;
   deterministic malformed or exhausted unknown/transient/resource acquisition
   -> `ERROR`; canonical terminal Action `error` -> `ERROR`; canonical
   terminal Action `failure` -> `FAILURE`; any still-budgeted unknown,
   transient, resource, or other incomplete acquisition -> overall-timeout
   `FAILURE`; only then may an actual complete late strong, final-stable exact-
   current-head terminal clean plus canonical Action `success`, with no
   incomplete acquisition, become `PASS`. Every remaining status-pending,
   progress, eyes-only, ancestor-clean, success-without-strong-clean, or wait
   state is overall-timeout `FAILURE`. A clean-looking artifact or status
   success never masks incomplete acquisition. Late evidence can update only
   through this complete final-stable reducer; it never mutates the deadline.

Every unspecified Boolean-product case is `ERROR`, not an optimistic pass.

The orchestrator must still avoid overlapping or untracked duplicates. Before
posting, it fully enumerates accepted requests and reconciles the parent-owned
epoch ledger for the exact current scope. Keep at most one active controlled
marker in an epoch. A persisted attempt closed as `missed_ack` or `stalled`
may retry serially inside the immutable original `max_wait`; those attempts
remain one named lane. An ambiguous POST remains durably fenced and may be
adopted only through the exact write-ahead/body/comment-ID contract in
[github-codex-review-epoch-state-machine.json](github-codex-review-epoch-state-machine.json).
The only transport outcome that may enter `confirmed-not-persisted` is a closed
parent-owned receipt proving either definitive no-dispatch or deterministic
rejection before service acceptance whose exact binding selects one row in the
canonical stable-ID transport-outcome ledger. Each append publishes a separately
persisted ledger revision, append transaction, v2 readback that binds the prior
parent readback, and durable current pointer; the selected membership carries
the exact ledger/readback/store revision and index coordinates. The record kind is exactly
`parent-observed-local-pre-dispatch-abandon-v1`,
`parent-observed-authenticated-pre-acceptance-server-rejection-v1`, or
`parent-observed-ambiguous-transport-v1`; it cross-binds the epoch, attempt,
operating identity, method, canonical URL, body digest, status/Date/raw response,
transport phase, dispatch claim/capability state, and cause. The ambiguous arm,
or missing, malformed, mismatched, stale, or self-authored evidence, takes
precedence over an internally self-consistent definitive receipt and preserves
`posting_ambiguous` with no successor. A network error, timeout, connection
reset, `5xx`, missing response, or unknown/partially observed transport phase
is `posting_ambiguous`; negative comment history cannot convert it into
non-persistence or authorize a retry.

The consumer starts only from the durable current pointer and iteratively
strict-loads every full v2 readback and full ledger revision to the unique
revision-zero empty genesis. Stable ledger ID, review epoch, predecessor
identity, append transaction, store coordinates, record bytes, digests, and
membership must cross-bind at every step, and each earlier serialized entry
prefix must be byte-identical in its successor. Replacing and resealing an old
valid row, omitting a predecessor, or selecting a self-consistent stale pointer
fails closed. There is exactly one durable parent store and one current pointer
for the exact `(review_epoch, ledger_id)`; neither evidence ID nor evidence
digest can select a parallel branch, and a losing current-pointer CAS mutates
nothing. These authority changes do not alter attempt retry counts,
timeouts, or backoff semantics.
Every gate that could issue a POST must consume one fresh complete parent-owned
`github-codex-request-plane-authority-readback-v2`. The machine JSON is the sole
field-enumeration authority for the root and every nested closed shape; this
reference must not become a second exact schema. A conforming consumer validates
the complete request, source, transition, trigger-policy, producer, producer-head,
and contiguous append history. In particular, it must not omit the root
`transitions` collection, trigger `transition_id`, source `consumer_kind` and
`consumer_id`, the closed transition row, or the `transition` append-entry kind.
Those named obligations are non-exhaustive reminders; closure and every field
set come only from the machine. The producer identity is immutable, its latest
revision is monotonic, and the primary consumer graph forms a complete forward/
reverse bijection. Each request/source retains exactly one initial pending row
and at most one authority-bound closed row in append-only serial history.
`trigger_policy` alone selects the per-class greatest transition revision and
greatest source revision; missing history, a duplicate edge, dangling transition,
wrong predecessor, rewritten pending row, second close, or orphan fails closed.
Latest projections, revisions, and exact-row payload digests remain fully
reconciled. A summary,
latest-only projection, caller reseal, gap,
rollback, or writer/revision reuse is not authority. Every initial-open, successor,
retry-open, write-ahead, dispatch-claim, and pre-transport CAS binds exact
`request_plane_producer_id`, `request_plane_latest_revision`, and
`request_plane_readback_identity_sha256`, refetches that same v2 identity inside
the CAS, and proves that no higher producer revision exists. A stale or
equal-looking different readback sends nothing. Any pending automatic, manual,
or controlled trigger blocks controlled POST. Multiple historical requests
remain artifact-first audit input and do not by themselves make terminal
evidence inconclusive.

Canonical request sources are externally admitted rather than caller-projected.
Automatic sources use
`github-codex-request-plane-automatic-formal-scope-source-v1`; manual sources
use `github-codex-request-plane-manual-formal-scope-source-v1`; controlled
sources carry exact null in `formal_scope_source_binding` because their marker
authority remains in the controlled-attempt ledger. Parent-owned
`github-codex-formal-scope-source-inventory-readback-v1` is a content-addressed
snapshot containing every complete
automatic/manual formal-scope authority lookup. Every inventory lookup is
consumed by exactly one same-class source and every such source consumes exactly
one lookup; phantom, missing, duplicate, cross-class, or unconsumed lookup state
sends nothing.
The snapshot carries no independent predecessor authority; only the committed
request-plane append transaction's exact previous/next inventory identity, raw
bytes, and digest together with the producer-head CAS prove the cross-publication
append-only prefix.

Each request source has exactly one initial null-to-`pending` transition and at
most one authority-bound `pending`-to-`closed` transition. The closed binding is
exactly `pending-provider-reconciliation`, which independently validates one
fresh complete pending reconciliation receipt with no accepted artifact,
provider blocker, or in-flight uncertainty, or `completed-provider-artifact`,
which independently validates one committed completion end-to-end transaction,
its published current-or-validated-ancestor head, and the exact completed
revision. Missing, unregistered, stale, wrong-epoch, blocker-bearing, in-flight,
or self-projected closure evidence fails closed. `trigger_policy` is only the
greatest-revision source/transition projection and never supplies admission,
inventory, or closure authority.

The CAS also independently reads the parent-owned
`github-codex-request-plane-producer-head-readback-v1` and atomically proves
that its producer ID, exact current latest revision, and exact current readback
identity are the same head consumed by the transaction. Replaying an older but
internally self-consistent producer readback is stale authority and sends
nothing. Except for the initial null-predecessor head, each producer head also
binds the exact previous head and previous request-plane readback plus one
committed `github-codex-request-plane-append-transaction-v1` independently read
through `github-codex-request-plane-append-transaction-readback-v1`. The
successor validator independently strict-loads the referenced predecessor-head
and predecessor-request-plane raw bytes from their parent stores, validates
their complete closed shapes, and recomputes their entry digests, readback
identities, and every nested row and append-payload digest before it consumes
the successor. The transaction then proves the complete previous append ledger and each previous
source, request, transition, and automatic/manual formal-scope inventory array
are byte-for-byte and JSON-type-for-type prefixes of the new arrays, including
unchanged old payload digests. State
evolution is append-only; rewriting or resealing any old row is a state
conflict. The same stored identity with replaced raw bytes, additional fields,
resealed nested content, or digest drift is also a state conflict rather than
idempotency. The parent publishes the next request-plane readback, formal-scope
inventory readback, transaction readback, and producer head in one CAS or
publishes none. For each of the exact `automatic`, `manual`, and `controlled` classes,
the complete arrays identify the greatest-revision source. Every request-primary
source has exactly one initial same-class null-to-`pending` transition and at
most one authority-bound `pending`-to-`closed` transition; both historical rows
remain present. A transition may instead have its own transition-primary source.
The trigger policy alone selects the greatest-revision transition,
which points to that same greatest-revision source; it may not point to an older source while a newer
manual or automatic source remains pending. Any wrong predecessor, rewritten
initial transition, double close, missing, extra, conflicting, or partially
reconciled edge fails closed, and a pending manual or automatic trigger
continues to block a controlled POST.

Inventory publication, the append transaction, and every POST-related CAS also
freshly bind the canonical formal-scope parent ledger's exact head-readback
identity, current revision, and current-entry readback identity. The inventory's
greatest consumed lookup revision is not current-head authority. An automatic,
manual, or controlled admission committed after the inventory snapshot makes
that inventory and CAS stale; retry starts only after a fresh readback and at a
newly allocated higher global revision.
Every selected formal-scope head also validates the whole predecessor prefix
through the unique initial row with one invocation-local iterative `O(B+V+E)`
walk. The consumer injects deterministic limits over raw UTF-8 bytes, JSON
nesting depth, reachable heads, bound inner-entry rows, predecessor edges, work
units, ancestry depth, and a monotonic deadline. It charges bytes and
string-aware depth before strict parsing, checks the injected monotonic clock
during the walk, and rejects the whole authority on any overflow; a partially
validated prefix is never accepted. Concrete cap values belong to the
independent consumer contract, not to candidate machine bytes or this prose.
An immediate-predecessor check is not authority.

That machine's top-level `version: 41` is a closed-schema discriminator. Its
`version_contract` enumerates the exact closed machine-root and
`version_contract` field sets and forbids additional fields in either object;
changing either field set requires a new top-level version and matching
consumer schema. Versions 1 through 40 must reject
this shape rather than partially accepting new fields or transition semantics.
Closed-version consumers compare the discriminator and each
`compatible_consumer_versions` member type-sensitively: only the exact JSON
integer `41` qualifies, not an equal numeric alias such as `41.0` or a value of
another JSON type. Both epoch and retarget machine loads first pass the same
consumer-owned strict raw JSON boundary: no more than 1,048,576 UTF-8 bytes,
nesting depth 32, 20,000 aggregate container members, and 20,000 scalar values;
candidate payloads cannot override those limits. Duplicate keys at any depth,
`NaN`, `Infinity`, `-Infinity`, decoded non-finite floats such as `1e999`, lone
surrogates, non-object roots, and bounded decode failures reject. Exact-integer
coordinates reject boolean and floating-point aliases. The migration guard
recursively and type-sensitively covers
every nested object field, array arm, discriminator, and scalar semantic, then
compares the canonical complete candidate snapshot with the consumer-owned
immutable v41 fingerprint.
That baseline is immutable relative to the candidate machine payload: tracked
consumer or test changes cannot generate, register, update, or self-certify it.
A changed snapshot requires a version bump and a matching consumer carrying a
separately fixed fingerprint after prior trusted-bundle external self-policy
review; this repository does not claim an in-repo trust root. Retarget v23 uses
the same independent-anchor rule with
fingerprint
`5464431266c4f2e415647a03f043218ad0661335a552764e3aa84932059a5934`.
The historical epoch v37 fingerprint remains
`dbe23a4fb0d2912f706f0faaffb7de1b5a2b5f309446ee65ac5eeecc7421959c`.
The historical epoch v38 fingerprint remains
`5f776563f9086340a6ddbef7a361e5b3a017d76a9230de47f597c8e4b18c3c02`.
The historical epoch v39 fingerprint remains
`df8488a0d2a1da1b9941d945426f9b3ddd5ed576f512f5152438c2dd1f11238f`.
The historical epoch v40 fingerprint remains
`341c2b84ef3f2c07268e1d35cfedca142fa3a03688e4db0b2e2d42fc30d2c968`.
The current epoch v41 fingerprint is
`8aedaef6711b27acdc956381f116633215fc3ad9c11a3557c5055ba2736cc450`.
The upgrade-only hypothetical v42 fingerprint is
`d78c08c73c844db8ebf1c94110149ede5758015c3d4087c3025fa6da16f9bc82`.
The current formatted v41 machine file has raw SHA-256
`cf105dc35c0fd2e850dbc29dc90432620f6ff7e8e7f304ea048983aa2a618461`;
that byte digest is an audit value, while the canonical semantic fingerprint
is the consumer compatibility authority.
The current and hypothetical fingerprints were frozen by the parent consumer
only after the complete machine bytes stopped changing. The hypothetical v24
retarget fingerprint is
`5bee7ac871d369c440c3a4d14d5b1949a29ee9a0f0bf793cf501c48e9b4e8e0d`.
Neither hypothetical next-version shape is accepted by the current profile.

At epoch v41, ACK/backoff consumes the complete canonical attempt ledger and
independently read ACK/comment authorities. Completion strict-validates the
full parent receipt-store index before selecting one complete byte-identical
candidate receipt, and every reachable completion head and origin shares one
invocation-local linear `O(B+V+E)` memo. Each associated-inline child preserves
independent full 40-hex `commit_id` and `original_commit_id` values and submits
both SHAs to ancestry classification. Pull-request-review provider authority is
the exact REST `chatgpt-codex-connector[bot]` / `Bot` actor; issue-comment
provider authority additionally requires exact
`performed_via_github_app.slug == "chatgpt-codex-connector"`. Controlled
completion independently reads the raw REST issue-comment authority and binds
exact `github-actions[bot]` / `Bot`, canonical ID/URLs/body digest, the
canonical hidden marker envelope, and the complete parent write-ahead.

Retarget v23 keeps authenticated `base_ref_oid` independent from
`pr_merge_base` and requires every duplicated scalar, ID, revision, timestamp,
and scope component to match in JSON type and value. Enforce unique merge-base
capture <= current-scope capture <= new-origin reservation < authorized
transition < supersession < finalized new-origin registration and,
independently, classification < supersession.
Every required authority must be independently loaded before supersession;
self-declared or backfilled records cannot repair causality.
The machine-owned semantic paths for this revision are
`controlled_attempts.request_plane_authority_contract.source_entry_contract`,
`controlled_attempts.request_plane_authority_contract.formal_scope_source_binding_contract`,
`controlled_attempts.request_plane_authority_contract.formal_scope_source_inventory_contract`,
`controlled_attempts.request_plane_authority_contract.transition_entry_contract`,
`controlled_attempts.request_plane_authority_contract.closure_authority_binding_contract`,
`controlled_attempts.request_plane_authority_contract.trigger_policy_entry_contract`,
`controlled_attempts.request_plane_authority_contract.primary_consumer_graph_contract`,
`controlled_attempts.request_plane_authority_contract.append_transaction_contract`,
`controlled_attempts.request_plane_authority_contract.append_transaction_readback_contract`,
`artifact_completion.orchestration_pending_reconciliation_receipt_contract.service_liveness_authority_contract.stalled_eyes_historical_authority_contract.natural_sparse_domain_contract`,
`artifact_completion.review_binding.artifact_commit_ancestry_receipt_contract.merge_base_is_ancestor_exit_code_contract`,
`controlled_attempts.per_attempt_deadline_contract.transition_step_contract`,
`controlled_attempts.per_attempt_deadline_contract.transition_chain_contract`,
`controlled_attempts.per_attempt_deadline_contract.epoch_membership_contract`,
`controlled_attempts.per_attempt_deadline_contract.parent_receipt_store_contract`,
`controlled_attempts.per_attempt_deadline_contract.deadline_transition_compare_and_swap_contract`,
`controlled_attempts.per_attempt_deadline_contract.parent_authority_readback_registry_contract`,
`controlled_attempts.trusted_acknowledgement_contract.late_ack_closed_attempt_reopen_contract.deadline_transition_receipt_atomic_reseal_contract`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.replay_and_conflict_contract.reconciliation_order`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.replay_and_conflict_contract.replay_decision_receipt_contract`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.completion_head_readback_contract`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.completion_current_state_readback_contract`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.completion_append_transaction_contract`,
`controlled_attempts.epoch_attempt_transaction.provider_artifact_completion_contract.completion_append_transaction_readback_contract`,
`artifact_completion.required_action_commit_status_authority_contract`,
`artifact_completion.required_action_commit_status_authority_contract.required_action_producer_binding_contract.release_admission_policy`,
`artifact_completion.required_action_commit_status_authority_contract.required_action_producer_binding_contract.called_workflow_resolution_cross_binding_contract`,
`artifact_completion.required_action_commit_status_authority_contract.required_action_producer_binding_contract.release_provenance_contract.release_admission_raw_graph_contract`,
`artifact_completion.github_lane_status_reduction_contract`,
`artifact_completion.canonical_applicable_finding_classifier_contract`,
and `artifact_completion.thumbs_up_clean_audit_closure_contract`.
This reference explains their security meaning but does not replace their
closed machine field schemas.
Retarget v23 accepts exact nested integer version 4
`github-codex-base-only-retarget-activity-classification-v4` only through
`github-codex-base-only-retarget-activity-classification-membership-v2` and
`github-codex-base-only-retarget-activity-classification-registry-readback-v2`.
It accepts `github-codex-unused-review-epoch-supersession-v4` only through
`github-codex-unused-review-epoch-supersession-membership-v1` and
`github-codex-unused-review-epoch-supersession-registry-readback-v1`.

This producer state machine and the consumer result rule are intentionally
distinct.

Request-policy ordering has two closed clock domains. Local named-lane terminal
events and the `github-codex-pre-post-request-absence-capture-v1` start/finish
use one parent-validated monotonic-nanosecond clock; the capture starts strictly
after both local terminal values and finishes no earlier than it starts. Its
complete authenticated GitHub request inventory retains authenticated HTTP
`Date` in canonical RFC3339 whole seconds as a separate domain. Never compare a
GitHub `Date` or comment `created_at` numerically with local monotonic, local
wall-clock, or fractional instants; missing, drifting, unauthenticated,
incomplete, or cross-domain time evidence makes request policy `unknown`.
Likewise, retained `attempt_write_ahead_created_at` is not a local creation
clock: it must be the strict RFC3339 exact copy of the custody-bound
authenticated `post_eligibility_server_date`. Candidate marker `created_at`
ordering uses that server date and every bound authenticated pre-request
`Date` directly. Local monotonic time is limited to duration and dispatch-guard
enforcement and never enters provider semantic ordering.

`posting`, `posting_ambiguous`, `waiting_ack`, and `waiting_result` are all
open-attempt states for the one-active invariant. The parent-owned epoch ledger
stores a monotonic revision and one nullable `current_attempt`. Opening the
first attempt, or atomically closing a retryable `missed_ack` / `stalled`
attempt and opening its successor, requires a compare-and-swap of that epoch
revision. Do not assume a single writer; a revision/current-attempt mismatch or
two distinct open attempt numbers is a state conflict that fences every new
POST.

Initial open, next-attempt eligibility, retry-open, write-ahead, dispatch claim,
and pre-transport invocation each consume a new complete parent-owned
`github-codex-orchestration-pending-provider-reconciliation-v2` receipt. It
binds the exact review epoch and current epoch revision, exact raw
reconciliation and provider-snapshot UTF-8 bytes/digests, and the same immutable
parent evidence-registry readback, membership schema, and source-capture
validators used by completion. Its closed pending profile contains exactly the
eleven ordered memberships: four initial and four final current-provider
inventory surfaces, final open/unmerged lifecycle, exact current-epoch
base/head/merge-base scope, and stable terminal-candidate selection. Those
memberships independently select preexisting registry rows by exact store,
revision, index, digest, and readback identity; they validate raw REST `Link`
headers and page receipts, complete GraphQL cursors, strict lifecycle/scope raw
bodies, and first/final valid-plus-malformed candidate inventories. Both
candidate inventories must independently derive identical strict empty sets.
Only then are completion's five artifact-specific checks closed-not-applicable,
not omitted or treated as successful; those eleven shared checks plus the five
artifact-specific checks are the full sixteen-check completion registry. Pending runs the same
`canonical_applicable_finding_classifier_contract` over complete history as
completion and readiness. An authoritatively resolved joined thread closes; an
unresolved joined thread or unsuperseded threadless current-head/ancestor
finding invalidates pending and enters provider-blocker reconciliation. Any
other valid, malformed, in-flight, or unstable
candidate likewise invalidates the pending receipt and enters the full
completion/blocker reconciliation instead. The receipt's type-sensitive
projections must still be completion `pending` at revision zero with empty
accepted-terminal, provider-blocker, and in-flight-uncertainty inventories. The
same independently read parent reconciliation row must carry one strict raw
`service_liveness_capture`, its SHA-256 digest, and one closed membership. The
consumer must completely fetch the canonical current-head check-runs endpoint
and retain its exact raw responses, page receipts, and raw `Link` headers.
Independently derive the complete persisted controlled-marker set from the
immutable epoch attempt/marker ledger readback, then bijectively fetch each marker's
canonical fully paginated raw reactions endpoint. Every reaction capture binds
the exact attempt, comment ID, marker-persistence receipt, and authenticated
server time; an omitted marker, omitted page, cross-parent record, or mismatch
fails closed. Strictly parse and closed-validate every check-run and reaction
record. The complete check-run status enum is exactly `queued`, `in_progress`,
`completed`, `waiting`, `requested`, or `pending`; every exact-App current-head
row whose status is not `completed` derives a check-run in-flight key.
Exact-App current-head `completed` rows, plus other-App and wrong-head rows,
remain complete audit input but do not enter the in-flight set and never prove
completion. Any status outside the closed enum, or ambiguous
identity or head, fails closed rather than being normalized to unrelated.
Controlled exact-provider `eyes` reactions derive their separate liveness keys.
The same independently read parent reconciliation row carries
`service_liveness_parent_readback_identity_sha256` and
`final_epoch_cas_service_liveness_readback_identity_sha256`; both must
type-sensitively equal the same fresh parent-readback identity and bind every raw
capture and projection to receipt `inflight_uncertainty_keys`. A missing,
self-projected, summary-only, wrong-coordinate, or forged-digest liveness
authority fails closed. These records are service-liveness and in-flight inputs
only; they never prove provider completion or a clean result and never replace
the eleven phase-separated provider-inventory and final-scope checks. Pending requires the complete
derived in-flight set to be empty.

A validated reaction history may be durably retained only through the small
parent-owned `github-codex-reaction-history-audit-v1` record in the v41
machine. Its content-addressed raw membership, validated projection digest,
observed requests/reactions, and independent final readback preserve audit
history. It has no state store, pointer, initialization CAS, completion CAS, or
absorbing completion state. It cannot arm or close provider orchestration,
authorize or block POST/retry, publish required status, complete the named lane,
or affect readiness. Exact `eyes` ACK authority remains exclusively in the
main attempt machine; `+1` has no ACK or clean authority.

An authenticated revision-0 parent readback whose closed attempt and marker
ledgers are both explicitly empty is the authoritative empty initial history.
A later positive-revision attempt history may also have an exactly empty
persisted-marker set only through the raw, digest-bound, independently read
`github-codex-definitive-no-dispatch-attempt-history-readback-v1` authority.
Its strict prefix covers every contiguous attempt from one through that
revision; every row is exact `post_not_persisted` with a
`resolved-not-dispatched` transport fence and one independently valid
definitive-no-dispatch receipt digest, and no row may have entered transport or
persisted a marker. The marker/reaction traversal remains exactly empty. An
empty marker set never supplies no-dispatch authority by itself. Missing, null,
summarized, gapped, unexplained later-revision, or forged empty state fails
closed, and revision zero can never itself authorize a stalled-`eyes`
classification.

An exact-provider `eyes` reaction already consumed by and bound to an attempt
that later closed as `stalled` is audit-only for a successor only through the
closed `stalled_eyes_historical_authority_contract`. Its authority row has kind
`github-codex-stalled-eyes-historical-authority-v1` and exactly binds the epoch,
attempt, plus exact raw UTF-8 bytes and SHA-256 pairs for the complete immutable
attempt entry, marker record, write-ahead binding, transport fence,
acknowledgement receipt, and ordered ACK/result-deadline receipt chain. The
parent attempt readback first defines the complete attempt-number total domain;
each component ledger is then a naturally sparse keyed subset whose presence is
validated under the referenced attempt's actual lifecycle. Its
membership has kind
`github-codex-stalled-eyes-historical-authority-membership-v1` and exactly
`{kind, attempt, authority_store_id, authority_store_revision,
authority_store_entry_index, authority_entry_sha256,
authority_readback_identity_sha256}`. The consumer independently reads that
preexisting immutable parent row and its exact parent readback, then cross-
binds the selected `stalled` attempt to its complete marker, write-ahead,
transport-fence, ACK, ACK-deadline, and result-deadline chain. Other legal
attempts may omit components their own lifecycle never created; a `missed_ack`
or `post_not_persisted` row cannot be padded, synthesized, or relabelled as
`stalled`. A compact,
compressed, partial, kind-only, caller-registered, or self-resealed summary is not
authority. The reaction neither clears `stalled` nor authorizes retry. A
distinct late or unconsumed `eyes` remains in-flight and blocks the successor
POST gate until full historical reconciliation closes.

The receipt is created after the prior attempt closes (or after initial epoch
registration), immediately before its write-ahead/open gate, and never reused
from an earlier claim or raced ledger read. At transport entry, obtain another
complete receipt after the fresh scope/lifecycle reads and bind its same
independently refetched byte-identical registry readback to the exact dispatch
claim and final compare-and-swap. The gate and builder may not register
captures. Before any projection, every pending registry, readback, receipt,
snapshot, capture, and nested response is strict UTF-8 JSON with duplicate
keys, nonstandard constants, and non-Unicode scalar strings rejected. A stale,
incomplete, self-projected, caller-hashed, forged-digest,
wrong-coordinate, empty-object, summary-only, non-pending, or nonempty receipt
authorizes no successor and no POST; run full provider reconciliation or report
the exact blocker instead.

The durable write-ahead is exactly one complete closed 19-field record in the
parent attempt ledger. Restart, replay, historical validation, adoption, and
transport consumption all reread and type-sensitively revalidate that same
record. A compact record, a proper subset, or a reconstruction assembled across
multiple rows is not authority.

Each initial or retry POST gate uses a fresh nondecreasing authenticated GitHub
response `Date`, never local wall time. The epoch starts with explicit
uninitialized max-wait custody. Its first eligibility CAS atomically appends
the complete authenticated pull-plus-compare receipt pair, initializes custody,
and fixes the immutable first authenticated `Date` plus 7,200-second deadline;
restart rereads that record and may neither recompute nor extend it. Each later
fresh receipt appends singly under the exact epoch CAS. Bind the preflight
receipt to a same-process, suspend-aware monotonic guard whose bounded interval
ends at the durable claim.
After round-trip and whole-second uncertainty deductions,
the exact revision/current-attempt/open-fence compare-and-swap must create the
one-shot claim within the remaining receipt-to-claim budget. Expiry first leaves
`dispatch-pending` with a null claim; it may close as not persisted only when
the parent durably records the closed definitive-no-dispatch receipt and its
matching independent transport-outcome record above, and
it can never resolve as persisted. The successful transition to
`dispatch-entered` durably mints only the original same-process,
non-duplicable capability for that winner; the claim is neither final transport
authorization nor the transport linearization point. That capability may be
consumed at most once. Immediately before the actual transport
invocation, that capability must reapply the same suspend-aware monotonic
deadline, revalidate exact lifecycle `state == open` / `merged == false` /
`merged_at == null`, re-read canonical base/head and the unique merge base, and
require them to equal the claim's exact review epoch. It then repeats the exact
epoch revision/current-attempt/`dispatch-entered`-fence compare-and-swap
revalidation. Only a successful mandatory pre-transport revalidation
compare-and-swap coupled in the same synchronous call path to one-shot
capability consumption and transport entry is final transport authorization
and the transport linearization point. An expired, changed, conflicting, unreadable, or otherwise
unproved recheck invokes no transport. Only the original live process may
atomically close the claimed fence as `resolved-not-dispatched` and the attempt
as `post_not_persisted`, and only when it proves that its non-duplicable
capability was not consumed and persists the exact closed
`local-pre-dispatch-abandon-v1` receipt. A restart, another process, or an
invocation state that is unknown or may have started instead preserves the
claim, enters `posting_ambiguous`, and never authorizes a replacement. The
claim does not attest or promise bounded kernel or network entry, and restart
cannot reconstruct the capability.

A lifecycle/base/head change, another writer, or `max_wait` blocks invocation
at that mandatory recheck. It does not retire the unresolved claim or authorize
a second send. Any late response or exact adoption remains scoped to the
claim's original epoch. Set the monotonic
`orchestration_exhausted` flag only with a fresh closed authenticated GitHub
`Date` receipt whose `Date` is at or after the immutable deadline. Without that
receipt, do not claim exhaustion, do not POST, and keep readiness inconclusive.
The exhaustion CAS appends one epoch-level receipt bound to the exact
before/after revisions and full-ledger digests, the before/after custody
snapshots, and the new authenticated `Date`. Once proved, exhaustion blocks new
sends while preserving `none`, `current_attempt`, every attempt in all nine
states, every transport fence, provider completion, and lifecycle bytes
unchanged. It stops only new automatic request orchestration. It neither closes
provider-artifact acceptance nor prevents full reconciliation of a late
current-epoch artifact; claimed or ambiguous transport remains available only
for first resolution.

Ambiguous transport adoption accepts only one fully paginated authenticated
REST issue comment whose exact raw-body digest and recursive JSON-type-sensitive
envelope match the durable write-ahead. The same comment must have the trusted
controlled-marker author, canonical repository/PR API and HTML URLs, and an
authenticated `created_at` no earlier than both this attempt's durable
write-ahead timestamp and every authenticated pre-request response `Date` bound
there. Persist those actor, endpoint, scope, ID, time, and write-ahead bindings
through a first-resolution compare-and-swap only from `dispatch-entered` or
`posting_ambiguous`. That transition rejects an open successor, writes the
closed `lifecycle_effect_receipt`, moves the fence to `resolved-persisted`, and
increments the epoch revision. A `dispatch-pending`/null claim cannot take this
transition. Only an unadvanced attempt enters `waiting_ack`; an advanced attempt
preserves its current lifecycle. The confirmed-`201` path applies the same
gates.

An exact concurrent or late `201` and exact adoption converge on the same
comment ID, raw digest, and envelope. The first winner performs the state
transition above. An identical loser performs read-only revalidation of the
persisted binding and parent-ledger relation; it leaves the epoch revision and
CAS ledger byte-unchanged, and any diagnostic audit is recorded outside that
ledger. A self-asserted pointer relation is not proof, and any mismatch is a
state conflict. If ACK or timeout already advanced the attempt, first
resolution preserves that lifecycle state. Artifact-first
completion appends to the independent epoch-level
`provider_artifact_completion` ledger. Automatic or manual evidence may append
with no current controlled attempt. A successful membership append leaves
attempt history, `current_attempt`, write-aheads, and transport fences
byte-identical. Completion creates no synthetic attempt and preserves every
open fence; a later first
resolution may close that fence without regressing provider completion, but it
cannot create a successor. The first validated artifact takes `pending ->
completed`, appends one membership, and monotonically closes all future request
orchestration. From that point, no initial/successor open, retry, write-ahead,
dispatch claim, or transport entry is legal, so every further same-epoch POST
is forbidden, even when a prior attempt had
already become retryable as `missed_ack`, `stalled`, or `post_not_persisted`.
An existing ambiguous POST may still resolve or be exactly adopted for audit
without authorizing another attempt. Completion is not absorbing for readiness:
later current-epoch findings, malformed evidence, or unresolved threads rerun
complete reconciliation and may reopen readiness. Each membership binds a
pre-registered, versioned, closed
evidence-authority validation receipt and its exact SHA-256. That receipt has
twelve source-kind-specific closed memberships, each independently resolved
through an immutable parent evidence-registry readback to a parent-preloaded raw
provider identity, terminal grammar and head binding, pre/artifact/post scope,
required inventory and pagination, thread projection,
lifecycle/base/head/merge-base revalidation, or final candidate-stability
capture. The current-state selector is itself an opaque preexisting parent
readback of kind `github-codex-completion-current-state-readback-v2`; the builder
and completion consumer may validate it but cannot create,
register, replace, or reseal it during completion. Each epoch has exactly one
durable parent-owned completion head/current selector/CAS. Its closed
transaction/readback/recovery chain atomically binds the before head, consumes
its one-shot nonce, commits the epoch-ledger and parent receipt-store
before/after images, and publishes the after head. Consumer/reconciler onsite
registration, a stale branch or restart reuse, partial store/ledger visibility,
or a missing or failed readback is a state conflict. The durable
head/transaction/readback kinds are
`github-codex-completion-head-readback-v3`,
`github-codex-completion-end-to-end-transaction-v1`, and
`github-codex-completion-end-to-end-transaction-readback-v1`. The end-to-end
transaction is the sole commit boundary. Its closed bytes bind the raw replay
guard and identity, staged replay decision receipt and decision-store
before/after/readback, opaque selector and both one-shot nonces, completion head
before/after raw bytes and identities, and epoch-ledger/receipt-store
before/after images. Full transaction and readback validation independently
loads the selector by its content-addressed readback identity and requires the
transaction's `review_epoch`, `completion_cas_id`, and
`completion_cas_nonce` to type-sensitively equal the selector, while also
revalidating the selector-bound before-head/ledger/store raw bytes and digests;
resealing either row cannot alter a selector-bound value. One parent CAS consumes both nonces and publishes the
decision audit/readback, ledger, receipt store, lifecycle fence when selected,
and head, or none. The no-op arm keeps the business head, ledger, receipt store,
completion revision, memberships, and outcome byte-identical while appending
exactly one replay-decision audit and one end-to-end transaction row. Append and
lifecycle-invalidated arms publish all layers together. In addition to its
transaction-store and readback identity fields, the closed end-to-end readback
contains exactly `lifecycle_capture_id`, `lifecycle_evidence_store_id`,
`lifecycle_evidence_store_revision`, `lifecycle_evidence_store_entry_index`,
`lifecycle_readback_identity_sha256`, `lifecycle_snapshot_raw_utf8`,
`lifecycle_snapshot_sha256`, `lifecycle_canonical_pull_detail_receipt_sha256`,
`lifecycle_replay_guard_readback_identity_sha256`, `lifecycle_replay_cas_id`,
`lifecycle_replay_cas_nonce`, `lifecycle_review_epoch`,
`lifecycle_base_ref_name`, `lifecycle_base_ref_oid`, `lifecycle_head_oid`,
`lifecycle_pr_merge_base`, `lifecycle_state`, `lifecycle_merged`,
`lifecycle_merged_at`, and `lifecycle_captured_at` as its lifecycle field set.
The readback itself—not a caller projection—
reloads that immutable parent lifecycle snapshot and type-sensitively cross-
binds it to the transaction, replay decision, and guard. Append and no-op require
exact open/false/null; lifecycle-invalidated requires the exact non-open snapshot
that installed the monotonic fence. Deleting, replacing, re-enveloping, or
cross-transaction splicing the lifecycle readback is a state conflict for every
decision arm. Complete completion-head ancestry uses separate consumer-owned
deterministic limits over raw UTF-8 bytes, JSON depth, reachable heads, origin
transactions, authority vertices, inner rows, ancestry/work depth, work units,
and an injected monotonic deadline. Bytes and string-aware depth are charged
before strict parsing, all first-pass row/byte work is counted even when memoized,
and overflow rejects the whole prefix without accepting partial ancestry;
concrete cap values remain an independent consumer choice. A standalone replay-
decision transaction followed by completion append, or standalone completion/
replay lifecycle publication, is not accepted. Neither the candidate builder
nor the current-head gates run before exact response-loss recovery at the
public reconcile entrypoint. Recovery queries the parent transaction store by
the selector CAS ID and nonce, independently validates the complete end-to-end
readback against the same exact selector epoch/CAS ID/nonce,
`reconcile_request_payload_sha256`, selector/before images, decision effects,
and head publication. That old transaction proves idempotency only: recovery
must independently reread the unique current completion head and its complete
current ledger and receipt store, then perform one fresh parent-owned strict
lifecycle/base/head/unique-merge-base reconciliation. Only exact open/current
scope may reclassify that current state and return the current ledger without a
second decision, head, receipt, guard, or nonce append. Fresh non-open scope must
first atomically publish and independently read back the lifecycle-invalidation
transaction and lifecycle-invalidation head origin through the current-head CAS,
then return `lifecycle-invalidated`; close-then-reopen and merge-then-reopen never
clear that fence. A later lifecycle fence, applicable finding, blocker, or other terminal
outcome therefore wins over the stored transaction result. A different payload,
missing current head, or malformed/conflicting current ancestry is a state
conflict.
Receipt authority is resolved by the exact completion-receipt SHA-256 to one
and only one registered completion transaction identity and one independently
loaded matching transaction readback before validation. Zero, duplicate,
missing, mismatched, or extra identity/readback matches are state conflicts;
scanning for any transaction that happens to validate is not an ambiguity-
resolution rule.
Fresh lifecycle is consumed before any candidate membership, receipt, or
transaction. The non-open decision uses
`decision_subject_kind == "lifecycle-snapshot"` with exact null
`immutable_artifact_revision_key_sha256`,
`candidate_transaction_readback_identity_sha256`, and
`completion_receipt_sha256`; malformed, missing, or hostile candidate bytes
therefore cannot suppress the monotonic fence. The same end-to-end CAS publishes
the fence, decision audit, ledger, byte-identical parent receipt store,
registered successor head/current pointer, and transaction readback together.
Each completion-head row binds origin kind, contiguous pointer revision,
predecessor identity, and transaction link. Readback independently reloads the
live decision-audit prefix, selector-bound before head, and both head rows from
their parent stores. A non-no-op after head must be current at the recorded
pointer revision or a validated acyclic contiguous ancestor of a later current
head; any missing or partial publication fails closed. Ordinary external epoch
successors use the existing parent append-only head store and current-pointer
CAS, not a second external transaction/readback. Each strict-loads the
registered predecessor, keeps exact `review_epoch`, provider completion,
lifecycle fence, and parent receipt-store raw bytes/digest/revision byte- and
type-identical, varies only the machine-allowlisted non-completion fields, and
advances per-epoch `head_revision`, `head_pointer_revision`, and canonical
ledger `revision` by exactly one; a byte-neutral successor is invalid.
Consumers recursively revalidate registered predecessor ancestry, and
builder-only validation is insufficient. `head_store_revision` and
`head_store_entry_index` are global append coordinates that may interleave
across epochs, not same-epoch incremented coordinates. A legal empty parent receipt store
has an exact nonnegative integer revision equal to its record count and zero if
and only if empty; a selected membership requires positive revision and exact
type-sensitive revision/index coordinates, with boolean/float aliases rejected.
Neither the candidate builder
nor the completion transaction may register a capture. A missing, replaced, extra, duplicated, malformed,
or non-cross-bound membership or underlying record rejects completion. Parse
every raw registry, receipt, snapshot, capture, response, and artifact value as
strict UTF-8 JSON: duplicate object keys, nonstandard numeric constants, and
non-Unicode-scalar strings fail before projection. REST list captures retain
the real unfiltered top-level arrays and complete resource objects. Human,
unrelated-bot, controlled-marker, nonterminal, malformed, and proved-ancestor
records remain raw audit evidence; classification consumes only exact-provider
current-head or locally proved-ancestor artifacts, after every returned review's
associated-inline endpoint has been fetched. GraphQL thread
captures retain the repository/PR-bound `data...reviewThreads` envelope and
cursor chain, and lifecycle/artifact GET captures retain complete real objects;
security-relevant projections are closed while legitimate extra fields stay
covered by the raw digest. A synthetic `{ "items": [...] }`,
`{ "threads": [...] }`, minimal lifecycle object, or `complete: true` summary
cannot substitute for those raw inventories. The complete provider snapshot
binds their exact digests, every issue/review and audit ID, one per-review
associated-inline pagination transcript for each review ID, all terminal and
malformed revision keys, and the independently selected terminal result.
Every raw item is retained and classified as exact, confirmed-different, or
ambiguous before selection; ambiguous identity cannot be filtered away.
Every REST pagination row additionally binds the exact closed response receipt,
including the raw `Link` header. Parse it under RFC 8288 semantics with quoted
parameter handling: one link-value may carry multiple nonconflicting relations,
other relation values are allowed, and `next`, `prev`, `first`, `last`, and
`self` may coexist. Bind every recognized relation target to the canonical
endpoint and page sequence, require `self` to equal the exact current request,
and let only one unique canonical `next` target advance traversal. Follow that
raw target until the terminal header has no `next`; duplicate or contradictory
recognized relations, malformed syntax, a noncanonical recognized target, or
retaining only the first page while another page is advertised is incomplete.
Every raw
review independently supplies the exact provider, state,
body, `submitted_at`, canonical API/HTML/PR URLs, and commit from which terminal,
malformed, and candidate revision-key inventories are recomputed. An eligible
malformed artifact retains its identity, semantic server time, and revision key
in the same greatest-time precedence and both stability inventories; a newer or
equal-precedence malformed artifact blocks an older clean result. GraphQL
top-level `errors` is absent or exactly `[]`; every returned thread must carry a
nested `comments.pageInfo` with typed `hasNextPage == false` because the current
completion schema has no separate child-cursor transcript. Every raw REST inline
comment joins exactly once to a GraphQL comment by canonical positive-decimal
`fullDatabaseId`, exact URL, and the exact parent review's canonical
`pullRequestReview.fullDatabaseId`; orphan, duplicate, wrong-parent, and
conflicting-URL joins fail closed.

The completion membership and closed receipt also carry the same
type-sensitive, byte-identical `formal_scope_authority_lookup` used by the
canonical admission registry. On first append, the independent parent
completion transaction directly consumes the full canonical authority ledger;
there is no compact completion-only authority. It re-reads the preexisting
current-epoch final authority entry and global admission allocation, the exact
admission and authority-context raw UTF-8 bytes/digests, and every required
source-kind stage membership and stage row. Automatic requires the complete
origin/event/registry/preliminary/finalization/fence chain; manual and both
controlled source kinds require the complete
origin/preliminary/finalization/fence chain. For every stage, independently
cross-bind the append transaction, stage binding, authenticated-`Date` receipt,
exact raw bytes/digests, store revision/index, and readback identity. Derive the
source kind, control class, exact epoch, and fence-before-artifact ordering from
that complete chain. The candidate builder may not mint, register, summarize,
replace, or splice authority; compact projections and cross-admission stage or
allocation reuse fail closed. After the mandatory fresh replay lifecycle
snapshot and replay-decision receipt pass, history lookup accepts only the exact
canonical lookup in the byte-identical membership and receipt and cannot
substitute a newly supplied readback or stage chain.

Completion also independently reads the complete historical epoch state, not
a candidate-supplied projection: every attempt, marker, ACK, deadline,
write-ahead, transport fence, and transport outcome—including closed and
superseded attempts—must be present through full parent-owned readbacks. The
complete formal-scope stage chain and the complete historical attempt/fence/
marker/ACK/deadline state are simultaneous completion inputs. Missing history,
a compact summary, or a self-projected receipt rejects completion even when the
selected artifact is otherwise valid.

Artifact identity is an immutable revision tuple: native carrier/ID/API URL, immutable
native creation time, a carrier-closed semantic server-time field—review
`submitted_at` or issue-comment `created_at`/`updated_at`—and the exact
authenticated artifact-GET response-body digest.
`completed -> completed` may append a distinct native artifact or a strictly
later fully validated revision of the same native artifact, including a later
clean-to-findings change. Append order never acts as a sticky any-finding latch.
First run `canonical_applicable_finding_classifier_contract` across the
complete membership history. A joined inline finding closes only when its
authoritative final-stable GraphQL state is `isResolved == true`; an unresolved
or unverifiably resolved inline finding remains blocking and no later clean
closes it. A threadless current-head or parent-proved-ancestor finding remains
blocking unless a strong, final-stable exact-current-head clean has strictly
later trusted semantic server time. Equal-time, weak, ancestor, hashless, or
unstable clean never supersedes it. Only after that derived blocker set is empty
may the greatest semantic-time set choose among otherwise eligible terminal
artifacts; an equal-time cross-channel set still fails closed. An older
distinct artifact may append for audit without overwriting the selected outcome.

Finding-first and malformed handling are independent. An applicable current-
head or parent-proved-ancestor finding that remains unresolved or unsuperseded
after the canonical classifier selects findings before clean, even when another
artifact is malformed. Every eligible malformed artifact separately preserves
an inconclusive blocker; its presence never removes, downgrades, or hides that
derived applicable finding.

Before replay searches history or returns a no-op, consume one preexisting
single-use `github-codex-artifact-replay-cas-guard-v1`, then obtain and independently
read one new closed `github-codex-artifact-replay-lifecycle-snapshot-v1` under
`replay_lifecycle_snapshot_contract`. Its
`github-codex-replay-lifecycle-canonical-pull-detail-receipt-v1` is a fresh
authenticated canonical pull-detail `GET` receipt that binds exact method and
URL, integer status, response identity, canonical GitHub `Date`, raw strict-
UTF-8 body bytes, and their digest to the epoch current head, actual
`base_ref_name`, and current base-tip `base_ref_oid`. It also binds immutable
parent evidence-store coordinates and readback identity, projected lifecycle,
capture time, this replay CAS's nonce, and its parent-owned lower-bound
authority. The same snapshot also carries one complete parent-owned immutable
`github-codex-replay-unique-merge-base-readback-v1`. That readback binds the
exact epoch, `base_ref_name`, `base_ref_oid`, `head_oid`, and unique
`pr_merge_base`; independently strict-loads a canonical authenticated compare
receipt for `/compare/{base_ref_oid}...{head_oid}` whose
`merge_base_commit.sha` equals that merge base; and binds parent-validated local
Git with lazy fetching disabled running exact argv
`git merge-base --all base_ref_oid head_oid`, whose strict UTF-8 stdout is one
lowercase 40-hex line and no second line with the same value. Pull detail,
compare, and local-Git authority are all obtained after the replay lower bound,
independently reread by content-addressed identity inside the same CAS, and
type-sensitively agree with the enclosing epoch and snapshot. A base-only
retarget, nonunique merge base, coordinate mismatch, or resealed authority is a
state conflict before history lookup, no-op, or append. The snapshot capability is single-use: replay, copy, restart, or a
CAS loser cannot consume it again. Any lifecycle other than exact
`state: open`, `merged: false`, `merged_at: null` atomically installs or observes
the monotonic lifecycle-invalidated fence at the replay CAS and rejects replay.
The fence's `first_invalidated_epoch_revision` remains the immutable installing
CAS revision even after later lifecycle-orthogonal successors or transport
convergence advance the current ledger; every such successor preserves the
fence byte- and type-identically.
Missing, stale, unregistered, self-resealed, malformed, or conflicting capture
evidence is a state conflict.

Replay also requires one closed
`github-codex-artifact-replay-decision-v1` under
`replay_decision_receipt_contract`. It binds the epoch, immutable artifact
revision key, current epoch revision and ledger digest, the fresh lifecycle
capture coordinates/readback/raw digest, the same CAS nonce and lower-bound
authority, and exactly one decision from
`byte-neutral-idempotent-no-op`, `append-new-membership`,
`lifecycle-invalidated`, or `state-conflict`. The no-op arm must bind the unique
existing membership and fresh open capture inside the same replay CAS; a
caller-issued or summary-only decision is not authority. The parent stages the
decision and complete decision-store after-image without publishing either.
Only the completion end-to-end transaction may append the decision,
independently reread it through
`github-codex-replay-decision-store-readback-v1`, consume the replay guard and
selector nonces, and atomically publish the matching ledger, receipt-store,
lifecycle, and completion-head effects. The independently validated end-to-end
readback is required before any byte-neutral return. A partial decision-only,
receipt-only, ledger-only, lifecycle-only, or head-only effect is invalid. Only
after that single commit boundary passes may the same immutable revision with the same validation
receipt, artifact-scope receipt, provider snapshot, outcome, and semantic time
be found in closed history. It is a byte-neutral business-state no-op only when
that complete closed receipt is byte-identical to the immutable parent-store
receipt and the atomic transaction appends exactly one replay-decision audit
entry. The business epoch/completion revision, artifact membership, latest
outcome, and selected evidence remain unchanged even after later
ACK/fence/max-wait or completion appends. First append validates
the closed automatic/manual/controlled source-state projection; automatic/manual
permit a null attempt, while a controlled receipt selects and fully validates
either the current open attempt/fences or one append-only historical terminal
attempt/fences whose top-level current pointer may already be null. Every attempt
and fence object is complete and closed; the open-fence number list is
positive-safe, sorted, and unique.
The same native artifact with a regressed semantic time, or an equal semantic
time but different body digest or outcome, is a state conflict; malformed later
evidence never appends.
Exhaustion remains monotonic.
Zero matches, near matches, incomplete pagination, or conflicting IDs remain
fenced; none proves that the write failed.

### Formal-Broad Request Classification

The review epoch is the exact tuple `(repository identity, PR number,
pr_merge_base, head_sha)`. Classify a request from the authenticated REST raw
issue-comment `body`, never rendered HTML or web-UI text:

- A bare manual body is formal broad only when stripping outer ASCII
  whitespace yields exact case-sensitive `@codex review`. ASCII HT/LF/VT/FF/CR
  and space are the only permitted outer differences, so trailing LF and CRLF
  are accepted; Unicode whitespace and visible suffix text are not.
- A trusted controlled marker is formal broad only when the first visible
  command is exact `@codex review`, followed by one blank line and the closed
  hidden `codex-review-gate-marker` envelope from the trusted actor defined by
  the epoch contract. The parent-owned ledger and write-ahead must additionally
  bind the exact review epoch, attempt number, exact rendered raw-body digest,
  and recursively JSON-type-sensitive intended envelope. Matching shape and
  actor identity without that binding is not a trusted controlled marker.
  Before either bare-manual or controlled classification, require strict UTF-8
  and cap the complete raw body at 16,384 bytes. Before parsing or comparing
  the untrusted controlled envelope, additionally cap root-object JSON depth at
  16, aggregate object-members-plus-array-elements at 256, and aggregate JSON
  leaf scalars at 256. Any raw gate or controlled-envelope gate failure is
  focused/nonformal and fences controlled orchestration; it never falls back
  to a partial envelope or the bare-command path.
- Any visible focus or other instruction remains a distinct focused request.
  It is never silently normalized into formal broad.

Requests and markers orchestrate liveness, retry, and audit. They are not
provider findings authority. Automatic, manual, and controlled terminal
candidates share the provider-evidence rules below, including one singular
closed artifact-scope receipt per candidate. Multiple serial or external
same-epoch requests alone do not make the provider result inconclusive.

Formal-scope admission is closed and epoch-bound, but it remains only a
lane-eligibility record, not provider findings authority or request/run
causation. Automatic, manual, and controlled admission share one immutable
append-only parent formal-scope authority ledger with one global monotonic
revision space. Whether the caller presents authority context explicitly or
implicitly, it may supply only the closed lookup binding; the validator must
independently read the exact authority entry and every referenced stage row by
store, revision, index, entry digest, and readback identity, then validate the
exact admission/context bytes and digests before parsing them type-sensitively.
Every producer requires the same non-circular two-phase formal-scope admission
before its artifact may be classified: an immutable preliminary payload, its
bound finalization, and a fresh authenticated post-finalization `Date` fence
strictly before artifact semantic time. A manual or controlled comment still
requires its authenticated comment GET plus pre/post-comment pull-detail and
compare receipts in that preliminary payload. A pre-artifact scope pair alone
is not a substitute, and no request/run attribution is inferred. A controlled
serial retry is liveness only; it cannot repair, retroactively scope, or
authorize an older artifact. This admission binds only artifact-publication
scope; it does not attest the provider's whole-PR input base, complete triple,
or make the PR merge-ready.
The origin append CAS atomically allocates one globally unique immutable parent
admission entry; every closed membership, stage row, authenticated-Date receipt,
and final authority entry resolves and binds that allocation plus the exact
parent-read stage-binding bytes and digest. A second otherwise complete chain
cannot reuse the admission ID. Missing, extra, replaced, or cross-admission
membership data fails closed. Membership, stage row, and receipt additionally share one parent
store ID/revision/index and closed append-transaction digest. The exact raw
receipt bytes, digest, and parsed receipt agree, and strict ordering uses those
actual membership coordinates rather than a row's self-reported revision.
Every formal-stage response is the canonical pull-detail resource, and every
formal pull-detail receipt—including the manual/controlled pre-comment,
post-comment, and fence reads—binds both its exact raw response body and closed
projection to `state` as the exact JSON string `open`, `merged` as the exact JSON
boolean `false`, and `merged_at` as exact JSON null. Parse the raw body as strict
UTF-8 JSON that rejects duplicate object keys, nonstandard constants, and
non-Unicode scalar strings before projection, then compare it type-sensitively
with the projection; string, numeric, or boolean aliases fail closed. Any observed
closed, merged, type-coerced, or otherwise non-open pull-detail response rejects
the entire admission even if a later receipt observes the PR reopened.
After any automatic, manual, or controlled request or provider service start is
durable, every observer at every machine-mandated lifecycle phase treats its snapshot
as a monotonic parent-epoch transition input. An observer that sees a strict raw
projection not exactly open/unmerged must resolve
`github-codex-parent-lifecycle-authority-lookup-v1`, call the parent epoch CAS
through `github-codex-lifecycle-invalidation-transaction-v1`, independently
validate `github-codex-lifecycle-invalidation-transaction-readback-v1`, and
atomically change `lifecycle_invalidated_fence` from exact null to one complete
closed parent-owned fence; merely rejecting its own admission stage is
insufficient. Installation succeeds only after the parent durably flushes the
transaction and the independently registered transaction/after-ledger readback
validates the committed bytes; a returned CAS result alone is not authority. The
fence selects the preexisting immutable lifecycle capture by capture ID, store
ID, revision, entry index, readback identity, raw bytes, and digest, then records the first invalidating
phase and values. It is byte-identical forever: a later open snapshot, reopen,
restart, retry, replay, or readiness pass cannot clear, replace, or regress it.
Initial/successor/retry open, write-ahead, dispatch claim, pre-transport entry,
artifact completion or replay, and final readiness all require exact null from
the complete independently read current parent epoch ledger. A missing,
unreadable, malformed, extra, conflicting, self-projected, or failed-readback
fence/capture state is a state conflict that fences every such path.
The lifecycle successor head directly carries the parent-preallocated
transaction ID. The transaction and readback cross-bind that ID with the exact
capture lookup, store coordinates, readback identity, raw bytes, digest,
non-open projection, predecessor/successor heads and ledgers, and current-head
CAS. Initial heads and ordinary external successors must first validate the
full closed provider-completion and lifecycle-fence arms; byte equality cannot
turn equal malformed values into authority. Completion ancestry uses shallow
core validators and one shared invocation-local memoized iterative `O(B+V+E)`
walk over every reachable head, origin transaction/readback, selector, and
lifecycle authority. There is no current-head early return or nested fresh
ancestry cache. Each reachable immutable row is validated at most once per
invocation, cycles fail closed, and restart rereads authority instead of
reusing a cache.
Each stage append accepts only an original opaque, same-process, parent-minted
one-shot response-acquisition capability already bound to that stage's closed
pull-detail operation. It accepts no response callback, cached response, or
authenticated time; after allocation readback the parent consumes the
capability before response bytes exist, performs the request itself, and
persists that exact response receipt. Copy, replay, process restart, or failure
after consumption cannot reconstruct or retry the acquisition and cannot
backfill a stage.
After independent finalization readback, the parent mints a nonduplicable
one-shot capability that starts the fence pull/compare request. The fence
receipt binds that capability, the preceding stage membership/readback, and the
request-start transaction; the append path does not accept a cached naked
response. Consequently an actor cannot collect old increasing GitHub `Date`
responses, wait for an artifact, and backfill an apparently ordered chain.

The process-local fence capability is only the live holder. Its parent-owned
issued row already binds the closed canonical pull-detail/compare operations.
Fence mint accepts only the original parent-minted response-acquisition
capability, never a caller-selected authenticated time or response. Request
start accepts no caller response callback, precomputed response, or
caller-selected operations: one guarded CAS appends the exact request-start
transaction, advances the durable capability head, and binds revision/index,
raw-row digest, and independent readback identity before the parent consumes
the bound acquisition capability and response bytes exist.
A copied holder, concurrent loser, retry after transport failure, or restart
after request-start cannot start a second request; issued-only restart cannot
reconstruct a live holder.

Automatic admission uses six already-persisted stage rows in strict order:
review-epoch origin, source event, event-registry append, preliminary,
finalization, and post-finalization fence. Every row carries a complete
authenticated GitHub `Date` response receipt, including raw Date bytes/digest,
normalized time, canonical request/identity/status, and raw response
body/digest, while both Date values and global ledger revisions increase
strictly. The final authority row is later and only references those existing
stage rows. Its chain must also end strictly before artifact semantic time.
Equal or late values, backfill, a naked timestamp, regenerated context,
cross-admission/epoch readback reuse, or any missing/mismatched independent
readback is `triple-inconclusive`.

Manual and controlled admission use their corresponding origin, preliminary,
finalization, and fence rows in that same ledger. Their preliminary
payload contains the canonical authenticated comment GET plus raw pre- and
post-comment pull-detail and compare response receipts, exact raw-body digests,
and authenticated `Date` values. Both scope projections must derive the same
exact `(repository, PR, pr_merge_base, head_sha)`, and the authenticated dates
must bracket the classifier-selected comment semantic time. The authenticated
comment receipt type-preservingly binds the raw actor (`user.login`,
`user.type`, and App identity when present), canonical comment API URL, PR HTML
URL, parent issue API URL, repository identity, PR number, positive comment ID,
exact UTF-8 body and SHA-256, `created_at`, `updated_at`, response `Date`, and
the classifier-selected semantic time. Every copy in preliminary,
finalization, and post-finalization records must match exactly; normalized,
synthetic, missing, or mismatched values are inconclusive. The controlled
record additionally binds the confirmed or exactly adopted marker. A missing
historical pre-comment bracket cannot be created by a later observation and
cannot relabel the comment into a different epoch after a base retarget.
For both control classes, authenticated GitHub `Date` values and parent-ledger
revisions are strictly ordered origin, preliminary, finalization, fence, then
the later final authority row; the fence Date is strictly before artifact
semantic time, and the preliminary/finalization revision fields equal their
stage-row revisions.
Missing, equal-time, late, wrong-epoch, unbound, mutable, or circular admission
is `triple-inconclusive`. The separate
request-time sidecar remains required only
where request-policy or reaction authority consumes that request.

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
- `duplicate-observed` means more than one overlapping, extra, or otherwise
  nonconforming accepted request exists for the same immutable whole-PR scope.
  Registered serial retry attempts are recorded in the epoch attempt audit and
  do not add named lanes; they are not independently a provider-result blocker.
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
clean. Never silently normalise nonconforming duplicate history into
`compliant`, and never create an untracked repair request. Machine-authorized
serial retries are governed only by the one-active, durable-close, immutable-
deadline rules above.

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
  `200`. Its raw body supplies the canonical positive PR number, actual selected
  `base.ref` as `base_ref_name`, full lowercase current base-tip `base.sha` as
  `base_ref_oid`, and full lowercase `head.sha`.
- `compare` is exact `GET` of
  `https://api.github.com/repos/<owner>/<repo>/compare/<pull.base.sha>...<pull.head.sha>`
  with integer status `200`. Build that URL only from the authenticated pull
  body's exact endpoint SHAs. Its raw body must repeat the selected base tip as
  `base_commit.sha` and supply the unique `merge_base_commit.sha`; never require
  or trust `head_commit`, and never infer head from `commits[-1]`.
- The two independently parsed records derive one exact observation
  `(repository, pr, base_ref_name, base_ref_oid, pr_merge_base, head)`. The
  pre-request and post-request observations must be type-preserving identical.
  They must also equal the enclosing
  historical or current scope before that request or any child reaction enters
  the enclosing scope's request/reaction authority. A valid tuple with the same
  repository and PR but an older head remains old-epoch audit evidence; the
  dedicated same-head/different-merge-base classification follows the
  base-only-retarget rule below. Preserve the individual response `Date`
  values; do not require the two sequential GETs in one phase to share a
  timestamp. Every pre `Date` is no later than the request semantic time or
  POST response, every post `Date` is no earlier than the POST response, and
  every receipt `Date` is no later than the frozen history as-of bound.

`base_ref_name` and `base_ref_oid` are authenticated selected-PR metadata, not
epoch-identity substitutes. The epoch remains keyed by independently derived
`pr_merge_base` and head. A base-tip change alone does not create a new epoch
when merge base and head remain unchanged, but the stale point-in-time
observation cannot satisfy a fresh scope or transport CAS.

`request_comment_receipt` is the exact authenticated response to parent-owned
`POST` of `https://api.github.com/repos/<owner>/<repo>/issues/<pr>/comments`
with integer status `201` and an exact submitted body accepted by the
formal-broad classifier above. Preserve the complete raw body, including a
trusted hidden marker envelope when present. Independently project its raw
response body to the controlled request's eight-field record:

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

This sidecar does not enter or alter the machine-owned raw provider fetch graph.
`request_scope_receipts` is separate parent-owned write-time evidence and is
never inserted as a provider fetch kind, page, or endpoint response. No
caller-supplied transcript version or envelope may gain authority merely by
adding or validating this sidecar.

A missing, malformed, duplicate, extra, or mismatched sidecar closes only the
request/reaction planes. Set `request_policy.status: unknown` with no invented
timing or duplicate warning, forbid another POST for that observed scope, and
do not use the affected request or any child reaction for reaction-history
audit. It does not erase a separately complete, trustworthy
current-scope terminal payload: terminal selection continues normally and may
still yield clean or findings while the request-policy report remains
`unknown`, provided that artifact has its own complete
`parent-recorded-terminal-artifact-scope-v2` receipt. A read failure that
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
`parent-recorded-terminal-artifact-scope-v2` receipt.
Store the unique receipt as that artifact wrapper's singular
`artifact_scope_receipt` beside, never inside, the raw endpoint inventory.
Do not insert it into transcript schema version 4.
An otherwise applicable pre-v1 artifact enters that audit-only exception only
when the parent-owned receipt-disposition authority below durably proves that
the receipt record was absent before the version-1 cutover. Raw-minus-normalized
does not prove absence. Preserve a disposition-qualified legacy artifact only
through the raw endpoint inventory and the closed Legacy Receipt Migration
partition below; that audit-only exception cannot select a result or basis.

Each receipt rejects unknown fields and contains exactly:

- `kind: parent-recorded-terminal-artifact-scope-v2`;
- `repository_git_object_identity_sha256`, the lowercase SHA-256 of the
  parent-frozen identity for the exact local repository Git object database
  used by object and ancestry checks;
- `publication_scope`, the exact six-field closed projection
  `{repository, pr, base_ref_name, base_ref_oid, pr_merge_base, head}`;
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
pre/post pull and compare bodies independently bind the actual selected
`base_ref_name`, current base-tip `base_ref_oid`, independently derived merge
base, and head; those raw projections together form the exact
`(repository, pr, base_ref_name, base_ref_oid, pr_merge_base, head)` observation.
No sibling ID or scope assertion
may substitute for projecting the receipt's raw bodies.

Both pre/post scope observations always bind the epoch's exact current head;
they never follow a finding artifact's older commit. Artifact commit identity
is projected separately from `artifact_get_receipt`. Ancestor applicability is
accepted only through a complete parent-owned
`github-codex-local-artifact-commit-ancestry-receipt-v1` selected from a
`github-codex-local-artifact-ancestry-registry-readback-v1`; a caller result,
self-hash, naked `git merge-base` return code, or receipt outside that full
registry readback is not ancestry authority.

Strictly parse and retain the complete raw GitHub response bytes and verify
their digests, but compare the closed authority projection rather than require
the whole REST object to equal a synthetic minimal object. Real pull, compare,
review, and issue-comment resources contain legitimate extra GitHub fields.
Those fields remain covered by the retained-body digest and stability check;
they neither become authority fields nor make an otherwise exact projection
invalid. Mutation, omission, ambiguity, or type drift in any projected
security-relevant field still fails closed.

The only accepted legacy receipt shape is exact
`parent-recorded-terminal-artifact-scope-v1` with exactly `kind`,
`pre_artifact_scope_receipts`, `artifact_get_receipt`, and
`post_artifact_scope_receipts`; it never silently acquires the v2 repository
identity. Accept it only when one preexisting immutable parent-owned migration
registry row has kind
`parent-proved-terminal-artifact-scope-v1-migration-v1` and exact fields
`kind`, `review_epoch`, `artifact_scope_receipt_sha256`,
`migration_registry_revision`, and `migration_readback_identity_sha256`. The
consumer independently reads that row by its positive revision and readback
identity and type-sensitively matches the epoch and exact v1 receipt digest.
Missing, malformed, resealed, wrong-epoch, wrong-digest, self-projected,
relabelled, extended, or inferred migration evidence is inconclusive. The
migration record admits only the unchanged v1 schema and only when its artifact
commit equals current `review_epoch.head_sha`. It never proves ancestor
applicability; an ancestor finding requires v2 repository-object identity plus
the closed parent-owned local ancestry proof.

Both pre and post pull/compare pairs must independently project the same exact
base OID, exact current `review_epoch.head_sha`, and unique local merge base.
That current repository/PR/base/head tuple is mandatory for clean, malformed,
and finding artifacts alike; a pull-detail or compare head never becomes the
artifact's ancestor commit. The artifact GET/native/parsed commit is a separate
field. Clean and malformed artifact commits must equal the current epoch head.
A finding artifact commit may equal that head or appear in one complete,
strictly sorted unique commit set selected by a closed parent-owned local
ancestry receipt. That receipt independently reads one immutable registry row
binding the exact review epoch, repository Git-object identity, current head,
artifact commit set, commit-object checks, and `merge-base --is-ancestor`
results. Every non-current finding commit requires local object type `commit`
and exact ancestry exit `0`. Exact exit `1` proves a non-ancestor and moves only
that older finding to audit-only; any other ancestry exit is unproved and makes
the provider decision inconclusive. Missing objects,
shallow/promisor/fetch-dependent checks, wrong-head, self-projected receipts, or
unproved ancestry reject positive artifact authority. Open lifecycle remains an independent mandatory
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
summary. Build the canonical Compare URL as `{pull.base.sha}...{pull.head.sha}`.
Then require the Compare body to repeat the selected base tip as exact
`base_commit.sha` and supply one unique `merge_base_commit.sha`. Do not require
or trust `head_commit`, and never infer head from `commits[-1]`. The current
authority join is exactly repository/PR/pr_merge_base/head; a Compare response
for another pull-detail endpoint pair cannot lend its merge base to this scope.
In short, the pull body supplies base/head, the exact derived Compare request
URL binds that pair, and the Compare body repeats base and supplies merge base.

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

Reusing that persisted scope receipt does not reuse its artifact GET as final
revalidation. At the independent final reconciliation point, obtain a fresh
authenticated `200` response from the canonical exact-artifact REST URL, never
the reviews or issue-comments list endpoint. Its authenticated `Date` must be
strictly later than every response `Date` retained in the persisted receipt;
strictly parse and digest its complete raw body, then require its closed
projection—including native identity, URLs, exact provider identity, body,
state, semantic time, and commit—to remain type-preservingly identical to the
persisted candidate. Bind those fresh raw receipt bytes and digest into final
stability. A missing, stale, malformed, list-derived, content-changed, or
identity-changed fresh GET leaves the reused receipt `triple-inconclusive`.

GitHub's relevant semantic timestamps and HTTP `Date` headers have only
whole-second authority here. Equality between a pre-scope `Date` and the
artifact semantic time therefore cannot prove which event happened first: an
old-scope artifact may have been created earlier in that second, followed by a
same-head base retarget and the pre read. Treat equality as inconclusive rather
than binding the artifact retroactively to the later scope. This strict edge is
specific to the pre-to-artifact causal boundary; the exact artifact GET and
the parent-ordered post reads may share a second with the preceding event.

This receipt is artifact/scope provenance, not request provenance. It does not
name a request or run and does not establish request/run/artifact lineage. A
missing or malformed request-time sidecar still closes only request/reaction
authority, while a missing, malformed, unmatched, unstable, or over-budget
artifact-scope receipt makes that terminal artifact unusable for current-scope
precedence. Receipt capture and validation use a bounded, non-borrowing receipt
ledger under the fixed evidence resource profile; no receipt may create an
unbudgeted traversal or fresh deadline inside one decision pass.

The artifact receipt deliberately defines **artifact-publication scope**. A
complete receipt binds the artifact to the exact six-field
`{repository, pr, base_ref_name, base_ref_oid, pr_merge_base, head}` projection
observed around publication. Every accepted artifact snapshot also carries
that exact closed `publication_scope` sibling; the validator cross-binds it to
the receipt and the authenticated current projection, so absent or internally
self-consistent but stale publication metadata fails closed. The immutable epoch scope key and short-marker
companion remain exactly `{repository, pr, pr_merge_base, head}`;
`base_ref_name` and `base_ref_oid` are point-in-time authenticated publication
metadata and do not rekey the epoch. Every pre/post pull and compare observation
binds the current head. An ancestor artifact commit is admitted only from the
exact artifact GET plus parent-owned local ancestry authority. This does not attest the provider's internal input
merge base, prove whole-PR review, or establish merge readiness. A valid same-
head/different-merge-base request sidecar remains one `observed` retarget
shortcut; a missing or malformed sidecar makes request policy unknown and
disables reaction audit without erasing independently stable artifact
classification or blocking findings. Positive terminal-payload completion would
require a predeclared provider-authenticated input-base or request/run/artifact-
lineage schema; the current accepted sets are empty, and request timing or caller
narrative cannot substitute.

### Legacy Receipt Migration

Legacy receipt migration never adopts an old artifact retroactively. The
parent-owned disposition authority, never raw-minus-normalized inference,
decides whether an old carrier is eligible for the audit-only partition. A
same-head request or terminal result observed before the parent captured the artifact
pre-scope boundary cannot acquire receipt authority from a later current-scope
read. Before migration classification can close, derive the raw applicable
artifact set from each complete current endpoint inventory after ordinary actor,
carrier, grammar, commit-applicability, inline-join, and thread checks plus the
two migration-only carrier checks below. Malformed or unknown terminal-looking
provider identities remain in the raw set and cannot be filtered away.

Raw-minus-normalized is not receipt-absence authority. Every migration input
therefore carries one independent closed parent-owned disposition ledger in
the `artifact_scope_receipt_dispositions` sibling. Its exact root fields are
`{kind, scope, sealed_pre_cutover_checkpoint, cutover_authority_record,
cutover_revision, ledger_revision, entries}`; `kind` is
`parent-recorded-artifact-scope-receipt-dispositions-v1`; and `scope` has
exactly `{repository, pull_request, pr_merge_base, head}` equal to the
evaluated epoch. Both revisions are positive safe integers. The durable ledger
is append-only, and the parent-private validation context independently binds
both the canonical ledger payload SHA-256 and the exact raw endpoint
base-payload SHA-256. The public sidecar contains neither binding. A sidecar
self-hash, a recomputed digest, set subtraction, or a normalized projection is
not that authority.

The sidecar always carries one non-null closed `cutover_authority_record`. Its
exact outer fields are `{kind, cutover_authority_id, scope,
cutover_authority_revision, payload_utf8, payload, payload_sha256}` and its
kind is `parent-sealed-artifact-scope-receipt-cutover-authority-v1`. Its
`payload` is closed to `{scope, cutover_authority_revision,
sealed_checkpoint_binding}`. Both scope values equal the ledger scope, the
outer and payload authority revisions are type-sensitively identical, and the
sidecar `cutover_revision` type-sensitively equals that authority revision.
`payload_utf8` is the exact immutable UTF-8 JSON bytes persisted, read back,
and parent-sealed at that revision; strict parsing must produce `payload`
type-sensitively with no duplicate object keys. `payload_sha256` is the
lowercase SHA-256 of those exact bytes. The payload's
`sealed_checkpoint_binding` is exact `null` or one closed
`{checkpoint_id, checkpoint_revision, checkpoint_payload_sha256}` object. The
parent-private binding independently pins the authority ID, revision, and
payload digest; current inventory, sidecar self-hash, reconstruction, reseal,
or backfill cannot create this authority.

Absence authority originates only in an immutable parent checkpoint sealed
before the v1 cutover. Before cutover, that checkpoint must already bind the
exact raw artifact identity, source-record digest, raw-inventory digest, and
the fact that no receipt record existed. The parent-sealed cutover authority
record binds the sealed checkpoint ID, digest, and revision without rewriting
it. A checkpoint, cutover authority,
disposition, or absence claim first created, reconstructed, amended, or
backfilled after cutover cannot support `legacy-pre-v1-absent-v1`, even if later
inventories are self-consistent.

The sidecar always carries the closed field `sealed_pre_cutover_checkpoint`,
and its presence is determined only by
`cutover_authority_record.payload.sealed_checkpoint_binding`. An exact null
binding requires an exact null public checkpoint. A non-null binding requires
one always-non-null closed `parent-sealed-pre-v1-artifact-checkpoint-v1` record
whose ID, revision, and payload digest type-sensitively equal that binding,
even when the current sidecar contains no `legacy-pre-v1-absent-v1` entry.
Every absent entry still requires the non-null binding and public checkpoint,
and matches exactly one null-receipt inventory entry in that checkpoint
payload. The exact parent-private checkpoint ID and payload digest were already
sealed before cutover.
The current raw inventory or sidecar cannot create, register, reseal, or extend
this checkpoint.

Each raw applicable artifact has exactly one closed entry with
`{channel, id, source_record_sha256, disposition,
artifact_scope_receipt_sha256, recorded_revision}`; no duplicate, extra, or
missing identity is accepted. `receipt-record-present-v1` requires a lowercase
SHA-256 receipt digest and exactly one matching normalized wrapper whose
`artifact_scope_receipt` passes the full closed validator.
`legacy-pre-v1-absent-v1` requires a null receipt digest, a positive
`recorded_revision` type-sensitively equal to the checkpoint revision bound in
the authority payload, with that checkpoint revision strictly less than
`cutover_authority_record.cutover_authority_revision`; the sidecar's equal
`cutover_revision` is only a projection of that sealed authority. It also
requires the parent's sealed immutable
pre-cutover checkpoint for that exact raw source identity and digest. It is the only disposition
eligible for `legacy_unreceipted_audit`. A receipt record that is present but
malformed, unstable, wrong-epoch, or omitted from normalized output is never
absence. An unreadable or unknown ledger, a late-created absent entry, a
scope/source/receipt-digest mismatch, revision rollback, or initial/final ledger
drift fails closed.

With that independent disposition authority, prove this exact disjoint union:

```text
raw_applicable_artifacts
  = receipt_bound_normalized_artifacts ⊎ legacy_unreceipted_audit
```

Here, receipt-bound normalized artifacts are the only terminal-classification
authority. The legacy unreceipted audit is the closed negative/audit projection
for exactly two raw-internal migration carriers; it is not a general home for
unreceipted artifacts and is not another classification or completion source.
An ordinary unreceipted current-grammar `clean` or `finding` cannot enter. Match
the sets one-to-one by exact `(channel, positive native id)` with no duplicate,
overlap, omission, or unprojectable raw item.

The only migration-only legacy carriers are:

1. `legacy-finding-native-review-v1`: an exact-provider `COMMENTED` or
   `CHANGES_REQUESTED` native review with the closed `### 💡 Codex Review`
   layout, one same-repository full-SHA blob path/line URL equal to native
   `commit_id`, one matched `P0/red`, `P1/orange`, `P2/yellow`, or
   `P3/lightgrey` badge, bounded title/prose without a URI-like prefix, the
   exact normalized nine-line disclosure, and no associated inline child.
2. `clean-pending-resolution`: an old exact clean issue comment whose raw
   lowercase 10-hex commit marker remains unresolved. Preserve the raw prefix;
   a non-current prefix additionally needs the complete independent parent-owned
   initial/final trusted-bundle prefix-disambiguation and ancestry receipts.

Both are migration-only audit/classification inputs, never provider carriers,
candidate bases, required-status PASS, reaction authority, or named-lane
completion. No third carrier
exists; near-miss grammar, ordinary unreceipted clean/findings, unresolved
threads, unstable projections, or unproved ancestry/prefix mapping fail closed.

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

The legacy list is audit-only for terminal classification and positive
completion authority. Recognized strictly older entries do not control ordinary
terminal precedence:

- An old `clean-pending-resolution` marker never establishes clean, becomes a
  selected basis, enters the provider classification as clean, or supersedes a
  finding.
- An exact old `legacy-finding-native-review-v1` carrier remains audit-only.
  Ordinary receipt-bound current-head or ancestor findings stay in normal
  complete history and enter the v41 finding classifier.
  An old finding whose commit is the current head or a parent-proved ancestor
  follows the same authoritative thread-closure and strictly-later strong-
  current-head-clean supersession rules as every other finding; the legacy
  carrier itself supplies neither closure nor supersession authority.
- Any still-unresolved applicable target thread remains a blocker and prevents
  the tolerated legacy partition from closing.

An unreceipted malformed terminal artifact, unknown role, incomplete target
join, or unknown/malformed required item field likewise cannot enter the
tolerated legacy list. Each makes the partition unproved and fails closed; do
not hide it under an audit role.

Every classified terminal clean or findings result must therefore select an
artifact from `receipt_bound_normalized_artifacts` and embed that artifact's
valid receipt. No `legacy_unreceipted_audit` item may become a completion
classification basis. A legacy unresolved-thread blocker instead leaves the lane
`triple-inconclusive` and is never promoted into a receipt-bound basis. If no
independently validated stable receipt-bound blocker basis exists, report
literal `provider.evidence_basis: null`; do not manufacture a basis merely to display
the rejected legacy artifact.

Preserve both complete initial and final raw endpoint inventories. For
migration completion, their provider decision-authority projections—terminal
artifacts, applicable findings, joined thread state, canonical provider
nonterminal audit records, the complete
`artifact_scope_receipt_dispositions` sidecar and its externally bound
digests, the receipt-bound normalized member, and the closed legacy member—must
be type-preserving identical, and the disjoint partition must close
independently in both passes. Ledger revisions may never move backward, and no
entry may change disposition. Raw request, reaction, and
request-sidecar bytes remain on their separate plane: preserve and reevaluate
them, but request/reaction-only drift does not overturn an otherwise identical
receipt-bound terminal classification. This is the same result-present boundary used
outside migration.

Every non-null terminal-shaped `provider.evidence_basis` exposes the single stable
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

The agent does not perform a receipt-repair POST and never POSTs another
same-scope request to repair this legacy gap. Any later same-epoch
receipt-bound artifact may be classified only when its own non-circular
two-phase formal-scope admission, artifact receipt, final stability, and
ordinary precedence gates close. A controlled serial retry is liveness only;
it cannot repair or retroactively authorize an older artifact.
There are only two recovery paths:

1. A separately authorized ordinary substantive change creates a real new head;
   never manufacture an empty or anchor commit.
2. After the parent persists the standard pre-artifact pull/compare pair, the
   caller may explicitly perform one caller-owned manual exact `@codex review`
   trigger on the unchanged head. The agent neither performs nor repeats that
   POST and never synthesizes its sidecar. Request policy remains `unknown`,
   reaction-history audit supplies no decision authority, and only a later fully receipted artifact
   may classify clean/findings or supply blocking negative evidence; it cannot
   complete triple and need not be attributed to the manual request.

A proved `base-changed-same-head` event is terminal for that unchanged head
because head-bound provider evidence cannot prove coverage of the retargeted
merge base. It blocks prior-epoch retirement, every same-head POST, and every
same-head artifact admission; same-head automatic, manual, or controlled
production does not bypass it, and publication after the retarget cannot enter
the putative current-base epoch. The lane remains `triple-inconclusive` until a
separately authorized ordinary substantive change creates a genuinely new head
and therefore a normal new epoch. Never manufacture an empty or anchor commit
for that purpose. This migration rule preserves result-present classification
authority without weakening whole-PR publication scope or creating a hidden
request/run/artifact join. It also preserves alignment with the fixed Action
rationale: artifact classification still comes from a trustworthy provider result without
request/run attribution; request markers and audit history remain separate;
and every unresolved inline or unsuperseded threadless current-head or parent-
proved-ancestor finding remains blocking. An authoritatively resolved inline
finding is closed; only a parent-proved non-ancestor is audit-only before the
classifier. Request history and receipt migration never substitute for those
resolution, supersession, or ancestry decisions.

Like the request-time sidecar, the receipt consists of point-in-time reads. It
proves the recorded pre/artifact/post observations and detects an observed
scope mismatch, but it does not prove that no intermediate `A -> B -> A`,
close/reopen, or other ABA transition occurred. Equality of the initial/final
raw decision-authority projections and their digests likewise cannot prove
that no intermediate provider-state ABA occurred, and no final digest proves
that GitHub state stayed unchanged after that digest was computed. Preserve
both limitations in reports rather than describing the envelope as continuous
scope or post-read stability attestation; a later observation invalidates the
prior terminal-classification decision.

## Terminal Artifact Precedence

Evaluate provider artifacts independently of request count and before consuming
the required Commit Status:

1. Re-read exact PR lifecycle, base/head OIDs, unique local merge base, frozen
   whole-PR range, and the v41 review epoch. A scope or lifecycle mismatch fails
   closed.
2. Independently and completely paginate initial and final issue comments,
   reviews, every review's associated inline comments, GraphQL threads and
   nested comments, and the request/reaction surfaces retained for audit.
   Provider artifact, thread, and finding sets must be stable. Request/reaction-
   only drift affects only request policy and reaction audit.
3. Validate the unique
   `parent-recorded-terminal-artifact-scope-v2` receipt for each admitted
   terminal-looking artifact, including its authenticated pre/artifact/post
   envelope, repository identity, exact artifact GET, publication scope, and
   final reread. Legacy receipt migration remains audit-only and cannot create
   terminal authority.
4. Admit only exact provider identity. Terminal issue comments require REST
   `chatgpt-codex-connector[bot]` / `Bot` plus exact App binding; reviews
   require the exact Bot identity. Lookalikes and ambiguous actors fail closed.
5. Parse every terminal-looking resource through the sole fixed grammar below.
   Before the epoch overall deadline, valid progress is nonterminal `PENDING`.
   Deterministic malformed evidence is `ERROR`; incomplete acquisition is
   transient `PENDING` only while its existing bounded budget remains and the
   overall deadline has not arrived, and `ERROR` after local exhaustion.
6. Classify every finding commit independently. Parent-proved nonancestors are
   removed from the reducer and retained audit-only; they are not malformed or
   progress and do not reset clocks. Unknown ancestry is `PENDING` only while
   the bounded local-object/ancestry budget remains and the overall deadline has
   not arrived, and `ERROR` after local exhaustion. A still-budgeted progress,
   transient, or unknown arm at the overall deadline follows the terminal
   timeout reducer rather than remaining `PENDING`.
7. For each current-head or parent-proved-ancestor finding, strict-load its
   thread-authority tagged union. A fully joined thread with authoritative
   `isResolved == true` is closed. An unresolved or unverifiably resolved
   thread is `FAILURE` and later clean cannot close it. A threadless finding is
   `FAILURE` unless a strong carrier-valid, final-stable exact-current-head
   clean has strictly later trusted semantic server time. Equal-time clean,
   ancestor clean, hashless clean, or unstable clean never supersedes.
8. A proved remaining finding takes precedence over simultaneous malformed
   evidence so it cannot be hidden; retain the malformed error basis for audit.
   Only after the blocking finding set is empty may terminal clean participate.
   Within otherwise eligible terminal artifacts, order by trusted semantic
   server time. Equal-time cross-carrier terminal sets are ambiguous and
   `ERROR`; within one carrier, findings precede clean and the greatest stable
   positive native ID selects only after outcome and scope agree.
9. A clean issue comment must have one full-40 current-head marker or one
   lowercase-10 marker plus the parent-owned stable resolution companion. A
   clean review must bind its exact commit ID to the current head and have no
   remaining inline/thread blocker. Hashless issue clean is `ERROR`; a
   watermark is never commit authority. Ancestor- or old-head clean is
   `PENDING`.
10. Perform the independent final reread of lifecycle, scope, raw provider
    inventories, receipts, thread joins, ancestry, candidate selection, and all
    required Action-producer components. For the producer, re-read the exact
    attempt and complete `referenced_workflows`, archive/receipt, caller and
    called workflow, complete Releases/assets/per-candidate raw graph,
    every candidate's independent release `R`, derived-minor, and historical-
    major `T` objects and local verifiers, the separate current alias
    `T_current`, globally unique immutable release, commit `C`, tree, and
    critical blobs; repeat every exact-payload signature verification and
    rederive `W`, `C`, and the unique two-candidate resolution using only the
    selected candidate's `T`/`C`, without replacing historical `W` or candidate
    proof with current floating `v1`. A stable strong current-head
    clean enters the Action reducer only after every provider-side gate closes.

Reactions do not participate in this precedence. `eyes` may only ACK the
selected attempt through the main state machine and `+1` is audit-only. A
terminal clean remains provider classification only. The separately validated
required Commit Status may become `PASS`, but neither result completes the
named triple lane or establishes merge readiness.
### Fixed Terminal-Payload Grammar

This section is the sole canonical terminal classifier for both completion and
pending reconciliation. Run it over every fully fetched exact-provider
terminal-looking resource before candidate construction or the
applicable-versus-audit partition; no downstream phase may reclassify a body.
In particular, `state == "COMMENTED"` plus a `Reviewed commit` marker is never
a clean review. It is findings only through the exact top-level-finding or
inline-parent branch below; otherwise it is malformed.

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
`source_ordering_key`, `source_evidence`, and report
`provider.evidence_basis` to `null`.
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

   **Reviewed commit:** `<LOWERCASE_10_OR_40_HEX_SHA>`
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

   The reviewed commit marker occurs exactly once and uses exactly 10 or 40
   lowercase hexadecimal characters. Only the 10/40 carrier lengths and the
   short carrier's fail-closed REST resolution outcome align with the fixed
   Action baseline at `16366aa81270ad2c875d2ceb8ce194f5b2308af6`; the closed
   grammar in this section remains the stricter playbook contract. A
   40-character reference is used directly and must equal the selected current
   head. A 10-character reference requires the independent closed
   `parent-recorded-reviewed-commit-resolution-v1` companion below; its two
   authenticated exact-repository GitHub REST reads of
   `/repos/<OWNER>/<REPO>/commits/<PREFIX>` must stably and uniquely resolve
   the prefix to the same lowercase full 40-character SHA, the SHA must start
   with the prefix, and it must equal both `parsed_commit` and the selected
   current head. Missing evidence and `404`, `409`, `422`, `429`, any `5xx`,
   malformed/non-object JSON, a non-full or non-prefix SHA, ambiguity, drift,
   or a different head fail closed. A 40-character marker must not carry this
   resolution companion. Either accepted carrier remains only an
   `artifact-publication-only` classification; it does not attest provider
   input scope, request/run/artifact lineage, or positive lane completion.

   The only permitted clean-result suffix is exactly two LF characters
   followed immediately by a nonblank first disclosure line and the official
   disclosure below. For that clean-result suffix only, trim leading/trailing
   whitespace from each line, drop blank lines, and require the remaining nine
   lines to equal this closed sequence exactly. Do not apply this normalization
   to the result body, clean lead, tagline, marker, or two-LF boundary. A
   changed link or line, an extra nonempty line, a missing line, a third LF, or
   an intervening whitespace-only line is malformed. This whitespace-tolerant
   disclosure rule does not widen top-level finding grammar.

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
   thread join below. The review is clean only when every target is
   authoritatively resolved or the target set is empty.
   Every exact-provider target child with a complete REST plus GraphQL
   parent/thread join and a nonempty normalized body is a finding regardless
   of `Finding:`, severity, or any other body prefix, and therefore takes
   part in the canonical finding history before the clean-looking parent is
   evaluated. Preserve its actual lowercase
   full-SHA `commit_id` and `original_commit_id` and add both to the complete
   artifact ancestry union. An unread, incomplete, malformed, orphaned,
   duplicate, or conflicting target join is inconclusive or malformed, never
   clean. The authoritative joined GraphQL `isResolved` value is disposition
   authority: exact `true` closes that inline finding after the complete join
   remains final-stable; `false` or unverifiable resolution remains blocking
   and later clean cannot close it. An `APPROVED` / `No findings.` review may
   be clean only when every exact-provider target child is authoritatively
   resolved or no such child exists. Fully fetched human or
   unrelated-bot comments, null-parent replies,
   and threads containing no target child remain audit context. They neither
   create a selected-review finding nor supply resolution for one. An empty
   exact-provider target body is inconclusive. `Looks good.`, coverage
   summaries, alternative punctuation,
   additional prose, links, HTML, comments, and code fences are malformed
   under this stricter playbook grammar.
3. **Top-level finding.** Require a normalized body with the exact first line
   `### 💡 Codex Review` followed by one or more nonempty LF-delimited finding
   lines. The body either ends after the final finding line or appends exactly
   two LF characters plus the byte-for-byte line form of the disclosure block
   above; per-line whitespace normalization is not applied to findings, and no
   other suffix or intervening line is accepted. Each finding line has this
   exact grammar:

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
   `pull_request_review_id` equal to the parent review ID, actual lowercase
   full-SHA `commit_id` and `original_commit_id`, and a nonempty normalized
   body. Preserve both child commit fields rather than rewriting either to `P`,
   add both to the complete ancestry union, and require each to equal current
   head or carry its own complete parent-owned ancestry disposition. The fully
   paginated child list and review-thread join supply the findings regardless
   of body prefix. A missing child, missing or conflicting parent join,
   unproved child SHA, incomplete page, or any other parent body is
   inconclusive or malformed, never clean.

The enclosing current scope and the artifact commit are distinct fields. In
every normalized current record, `scope.head` is the exact current PR head and
never changes to match an older artifact. A clean issue comment's
`parsed_commit` and a clean review's native `commit_id` must equal that current
`scope.head`; a clean bound only to an ancestor cannot enter the current clean
classification. Every terminal clean payload, including one bound to the
current head, remains provider classification only: it may contribute to the
required Action reducer but cannot complete the named lane or make the PR
merge-ready. Reactions supply no positive completion. A finding issue comment's `parsed_commit`, finding review's native
`commit_id`, or inline-parent/child commit may instead be the current head or a
locally proved ancestor. Preserve that SHA as the artifact commit while keeping
`scope.head` current. Exact current-head equality is the receipt-free fast path
and permits a null ancestry receipt; admit only each non-head value through its
matching parent-owned local Git object/ancestry receipt. A missing or
unreadable required ancestry result is inconclusive; a proved non-ancestor remains
audit-only and cannot block or complete the current scope. It must not appear
in normalized `active_top_level_findings` or `unresolved_thread_findings`; such
an injection is a raw/normalized projection mismatch and selects `unknown`.

This separation keeps every `H1 finding -> H2 clean` sequence explicit. The raw
and normalized projections retain H1. An unresolved joined thread continues to
block H2; an authoritatively resolved thread closes; and a threadless H1 may be
superseded only when H2 is a strong exact-current-head clean at a strictly later
trusted semantic server time. Never make the projections agree by rewriting
H1 to H2 or silently dropping it; the canonical classifier records the exact
closure or supersession basis. A parent-proved nonancestor stays solely in raw
audit.

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
raw_reviewed_commit_marker: <exact marker line for clean, otherwise absent>
commit_ref: <exact lowercase 10- or 40-character clean marker ref, otherwise absent>
commit_resolution_basis: direct-full-sha-v1 | parent-recorded-reviewed-commit-resolution-v1
scope:
  repository: OWNER/REPO
  pr: <positive PR number>
  base_ref_name: <actual selected PR base ref name>
  base_ref_oid: <full lowercase current base-tip SHA>
  pr_merge_base: <lowercase full SHA>
  head: <lowercase full SHA>
```

The three marker/resolution fields are required together only for accepted
clean issue comments and absent from finding or malformed records. Even when
`commit_ref` is 10 characters, `parsed_commit` remains the resolved lowercase
full 40-character SHA. The object rejects unknown fields and review-only fields such as `state`,
`submitted_at`, `commit_id`, and inline-thread joins. Require
`updated_at >= created_at`. When the two times are equal, require
`server_time == created_at` and `server_time_field == created_at`; when they
differ, require `server_time == updated_at` and
`server_time_field == updated_at`. `api_url`, `url`, actor, App, body,
normalization, grammar result, parsed commit, and scope all participate in the
type-preserving initial/final equality check. The issue-comment ID shares its
native namespace with request, progress, and other provider comments, so one
ID cannot describe conflicting records in those roles.

For a clean issue comment, `parsed_commit == scope.head` is mandatory. For a
finding issue comment, `parsed_commit` is the artifact commit and may differ
from `scope.head` only when current raw authority proves it is an ancestor;
the enclosing scope remains current. Apply the same distinction to a review's
native `commit_id` and to its joined inline children.

Before this join, a raw lowercase 10-character carrier has semantic and role
`clean-pending-resolution`; it is non-authoritative and cannot enter clean
selection. Only an exact companion join on artifact ID, immutable scope,
`commit_ref`, and resolved full head may normalize it to clean. Apply that same
closed join in the current path, complete-history path, and sidecar-blind
historical path. Sidecar-blind may disregard a request-scope sidecar, but it
must never disregard or synthesize this resolution companion.

The 10-character branch stores the independent parent-owned companion beside,
not inside, the unchanged closed
`parent-recorded-terminal-artifact-scope-v2` wrapper:

```yaml
kind: parent-recorded-reviewed-commit-resolution-v1
artifact_id: <same positive issue-comment ID>
scope: <same immutable repository, PR, merge-base, and current-head object>
commit_ref: <exact lowercase 10-character marker ref>
resolved_commit: <lowercase full 40-character current head>
initial_receipt: <closed raw GET response receipt>
final_receipt: <closed raw GET response receipt>
```

Each response receipt has exactly `method`, `request_url`, `status`,
`date_header`, `body_utf8`, and `body_sha256`; `method` is `GET`, the URL is
the authenticated exact-repository
`https://api.github.com/repos/<OWNER>/<REPO>/commits/<commit_ref>`, and status
is exactly `200`. Strict duplicate-key-rejecting JSON parsing must produce one
object with a lowercase full-SHA top-level `sha`. Recompute the raw UTF-8 body
digest, require the initial and final raw bodies and resolved SHA to remain
identical, and bind every field to the artifact ID and exact current scope.
Parse the retained HTTP `Date` fields and require
`artifact GET <= initial resolution <= every post-scope snapshot <= final resolution`;
same-second equality is allowed at each of these non-strict edges. These closed
raw receipts, their digests, and their checked cross-wrapper order are the
contract evidence. A prose assertion that the parent invoked or authenticated
the calls in that order, or a self-reported `authenticated` or `tls_attested`
boolean, cannot substitute for them. The authenticated trusted GitHub reader is
an execution trust root; the receipt contract does not claim that its raw fields
alone attest TLS. An ordinary artifact wrapper plus five raw scope/artifact
responses costs six records. This companion adds two independent resolution
responses, so a short-marker wrapper carries seven raw responses and costs
eight records total.

Before actor or parent classification, validate every associated inline record
against the same closed nine-field schema: `id`, `url`, `user_login`,
`user_type`, `pull_request_review_id`, `commit_id`, `original_commit_id`,
`body`, and `normalized_body`. Reject unknown or missing fields, non-full-SHA
commit IDs, invalid parent IDs, and body-normalization mismatches. Only after
that validation may a complete human, unrelated-bot, or exact-provider
null-parent record remain audit context rather than target finding evidence.
Audit-only status never permits malformed evidence to disappear.

All other terminal-looking exact-provider comments or reviews are malformed
for receipt-bound current selection. The two closed migration-only legacy
carriers above may classify only a strictly older raw pre-v1 audit item; a
near-miss to either legacy grammar remains malformed and cannot use the audit
exception. In particular, these near misses never complete clean: a missing or
duplicate reviewed-commit marker, a short reference without its complete stable
resolution companion outside the exact legacy audit-only branch, a marker with
any length other than 10 or 40, a mixed-case or mismatched SHA,
`No findings!`, an empty `APPROVED` review, `Looks good.`, an unlisted tagline,
an extra footer, a short-SHA or cross-repository finding URL, conflicting
finding SHAs, a malformed percent escape or line anchor, a clean body
containing a finding line, an empty inline parent, or an inline child whose
parent ID is wrong, whose `commit_id` or `original_commit_id` is not a full
lowercase SHA, whose duplicate projections are internally inconsistent, or
whose required repository-object and ancestry classification is missing or
unproved. A child SHA may legally differ from the parent review commit, from
the other child SHA, and from current head when each full SHA has its own
complete parent-owned ancestry proof. A `PENDING` review
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

The same clean record with marker `0123456789` is also positive only when its
closed resolution companion stably resolves that exact prefix to
`0123456789abcdef0123456789abcdef01234567` on both authenticated reads.

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
| `finding-with-whitespace-disclosure` | top-level finding | whitespace-varied disclosure suffix | `malformed` |
| `inline-parent-positive` | inline-parent review | non-`Finding:` exact-provider target child body | `findings` |
| `inline-parent-ancestor-child-positive` | inline-parent review | child commit/original commit are a parent-proved ancestor | `findings` |
| `inline-parent-nonempty-positive` | inline-parent review | exact container body and disclosure | `findings` |
| `clean-issue-short-sha` | clean issue comment | 10-character marker resolved by stable exact-repository receipts | `clean` |
| `clean-issue-live-disclosure-whitespace-positive` | clean issue comment | 10-character marker plus trimmed closed disclosure lines | `clean` |
| `clean-issue-disclosure-third-lf` | clean issue comment | three-LF marker-to-disclosure boundary | `malformed` |
| `clean-issue-disclosure-space-line` | clean issue comment | whitespace-only marker-to-disclosure line | `malformed` |
| `clean-issue-mutated-disclosure` | clean issue comment | mutated disclosure line | `malformed` |
| `clean-issue-disclosure-extra-nonempty` | clean issue comment | extra nonempty disclosure line | `malformed` |
| `clean-issue-disclosure-changed-link` | clean issue comment | changed disclosure link | `malformed` |
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
| `inline-parent-wrong-child-commit` | inline-parent review | unproved child `commit_id` | `malformed` |
| `inline-parent-wrong-original-commit` | inline-parent review | unproved child `original_commit_id` | `malformed` |

Contract tests must encode this table as data, exercise every row against a
closed reference classifier, and assert the four accepted grammar branches are
all represented. Adding or changing a grammar branch requires changing both
the table and classifier in the same reviewed range.

### Duplicate Scenarios

`R1` and `R2` are accepted requests for the same immutable scope. `R2` is
either a machine-authorized serial retry after `R1` closed or an uncontrolled
duplicate; request history must make that distinction. `clean1` and `clean2`
are trustworthy terminal clean artifacts ordered by trusted provider time.
They supply provider classification that may enter the separate required
Action reducer, not positive named-lane completion.

| Scenario | Artifact classification | Request audit | Evidence decision |
| --- | --- | --- | --- |
| `R1-clean1-R2-pending` | `clean` | compliant when `R2` is an authorized serial retry; otherwise `duplicate-observed` | `clean1` remains the latest terminal result. Do not post another request. |
| `R1-clean1-R2-clean2` | `clean` | compliant when `R2` is an authorized serial retry; otherwise `duplicate-observed` | `clean2` is the latest terminal artifact. |
| `R1-R2-clean1-clean2` with overlapping open attempts | `clean` | `duplicate-observed` | `clean2` is the latest terminal artifact even though the artifacts expose no request/run mapping. |
| `R1-findings1-R2-clean2` | `clean` only for a strictly older threadless finding and strong current-head `clean2`; otherwise `findings` | classify independently | Authoritative thread resolution or the narrow strictly-later threadless supersession rule decides; request ordering itself does not. |
| `R1-clean1-R2-findings2` | `findings` | classify independently | `findings2` is authoritative. |

The scenarios above define how to consume provider evidence after multiple
requests exist. `R2` may be a machine-authorized serial retry only after `R1`
has the machine-required durable terminal/no-dispatch closure; otherwise it is
a producer warning. Legal serial retries remain one logical named lane and do
not receive `duplicate-observed` merely because more than one bound request is
present. In both cases request count remains outcome-neutral after complete
provider reconciliation.

If the final current reread first observes a fully validated, receipt-bound R2,
retain it in the final request audit and report the resulting duplicate
warning. Terminal selection compares the complete provider artifact/thread/
finding projection while isolating this request-plane delta, so stable `clean1`
can still classify clean. An absent, malformed, or over-budget R2 sidecar
instead makes request policy unknown. Neither case enters the optional reaction
audit unless its one raw graph membership and independent final readback
already contain the exact request/reaction evidence; neither exception applies
to a newer finding, malformed terminal artifact, unresolved thread, or
scope/lifecycle change.

## Finding Authority

`canonical_applicable_finding_classifier_contract` is the only
finding-disposition authority used by provider classification, pending
reconciliation, required Action status, and readiness. Every finding is
classified independently; one child's ancestry or resolution never changes a
sibling or its parent review.

Each closed finding record contains `finding_key`, carrier and native parent/
child IDs, exact commit, resolution state, `thread_authority`, and ancestry
disposition. The thread field is a tagged union:

- issue-comment and review-body findings are threadless, require
  `resolution_state: not-applicable`, and carry exact null thread authority;
- every selected-review inline finding carries one parent-owned
  `github-codex-authoritative-thread-join-membership-v1`. Its coordinates and
  readback identity select complete raw REST inline pages plus complete raw
  GraphQL thread/nested-comment pages. The reader recomputes the one-to-one REST
  child -> GraphQL comment -> parent review -> thread join and derives
  resolution only from typed `isResolved`.

GraphQL pagination begins at null cursors, follows each opaque nonempty
`endCursor` exactly when typed `hasNextPage == true`, and terminates only on
typed false. Normalize GraphQL `BigInt` and REST numeric IDs to the same
positive canonical decimal form, then bind comment IDs, parent review IDs, and
canonical URLs bijectively. Missing pages, duplicate joins, orphan targets,
parent or URL conflicts, ambiguous actor identity, wrong types, or caller-
supplied `thread_resolved` fields make the evidence malformed. Human,
unrelated-bot, null-parent, and non-target threads remain audit context and
cannot close a provider finding.

Apply disposition in this order:

1. A parent-proved nonancestor is audit-only and removed before carrier/result
   reduction. It is not malformed or progress and changes no deadline.
2. Unknown ancestry is `PENDING` only during bounded local-object/ancestry
   acquisition before the epoch overall deadline and `ERROR` after local
   exhaustion. If the overall deadline arrives first, apply the final-deadline
   reducer.
3. An inline current-head or proved-ancestor finding closes only when its exact
   authoritative thread membership recomputes `isResolved == true` and that
   raw authority remains final-stable. Otherwise it is `FAILURE`; later clean
   never resolves it.
4. A threadless current-head or proved-ancestor finding is `FAILURE` unless a
   strong carrier-valid, final-stable exact-current-head clean has strictly
   later trusted semantic server time. Equal-time, hashless, old/ancestor, or
   unstable clean does not supersede it.

Top-level issue comments have no GitHub resolution bit. Associated inline
comments are part of their parent review's payload; a clean-looking review with
one remaining inline finding is findings. Incomplete associated-comment or
thread pagination is transient only while bounded acquisition remains, then
`ERROR`. A deterministic broken join is immediately `ERROR`. If a proved
finding and malformed evidence coexist, report the finding `FAILURE` first
while retaining the malformed basis for audit; neither may be omitted.

## Reaction History Audit

v41 has no reaction profile that can supply provider clean, required Action-
status `PASS`, acknowledgement, named-lane completion, or readiness. The only
optional retained shape is one immutable
`github-codex-reaction-history-audit-v1` record closed to:

`{kind, review_epoch, raw_authority_graph_membership,
validated_projection_sha256, observed_requests, observed_reactions,
final_readback_identity_sha256}`.

Its membership selects one preexisting parent-owned complete raw request,
reaction-pagination, and provider-identity graph. The consumer recomputes the
projection and requires a distinct final raw readback. Caller-built candidates,
aggregate reaction counts, historical sample/profile labels, provider
declarations, self-hashed summaries, and copied provider prose remain
non-authoritative.

The audit contract is deliberately one-way:

- exact `eyes` may supply ACK only through the main attempt machine's
  `trusted_acknowledgement_contract`; an audit label cannot ACK;
- `+1` is audit-only and supplies neither clean nor ACK;
- every other reaction is audit-only;
- no reaction changes artifact precedence, finding/thread disposition,
  deadlines, retry eligibility, required Commit Status, lane disposition, or
  readiness; and
- no reaction state store, pointer, initialization CAS, completion CAS,
  completed audit state, sampling cutoff, or second completion graph exists.

This removal does not weaken terminal provider evidence. Current terminal
issue comments, reviews, inline findings, and thread resolution continue to use
the complete current raw authority below.
## Current Raw Provider-Evidence Authority

A normalized `current.initial_snapshot` / `current.final_snapshot` pair is a
derived reader-facing view. Even when those two objects agree, it cannot prove
that the current endpoint universe was fetched or that every current/ancestor
finding commit was checked locally. It is insufficient for terminal clean,
terminal findings, required-status reduction, or the optional reaction audit.

Before accepting any current terminal clean/findings result, the parent
independently fetches two complete raw current
endpoint inventories: one initial traversal and a new final traversal
immediately before acceptance. Each inventory has the closed endpoint shape
`{repository, pull_number, head, resource_budget, fetches, capture_receipt_membership}` and may additionally carry the separate siblings `request_scope_receipts` and `artifact_scope_receipt_dispositions`; no other root field is accepted. `capture_receipt_membership` is mandatory and selects the separately persisted phase-freshness receipt described above. `resource_budget` is mandatory and
must type-preservingly equal
`artifact_completion.evidence_resource_budget_contract.exact_config`: exact
`{profile: github-codex-evidence-resource-budget-v1, schema_version: 1,
max_seeded_pull_requests: 512, max_controlled_requests: 512,
max_fetch_attempts: 8192, max_retained_pages: 4096, max_records: 20000,
max_page_body_bytes: 8388608, max_retained_utf8_bytes: 67108864,
deadline_seconds: 900}`. Every numeric value is an exact positive JSON integer;
candidate, caller, release, and test-owned constants cannot override it. This
is one parent-owned monotonic ledger for the entire composed reduction, not a
per-plane allowance: provider evidence; required Action REST/GraphQL statuses;
run, artifact, archive, caller-workflow and called-workflow captures; and every
Release, asset, tag, provenance, source commit/tree/subtree, Action commit/tree,
critical-file and runtime raw-blob capture all share its cumulative fetch,
page, record, retained-byte, seeded/controlled-request, and one 900-second
deadline limits. The per-body byte cap applies to each retained body, while the
retained UTF-8 cap is cumulative. Initial and final phases, all candidates, and
all siblings neither receive a new budget nor may split, reset, refund, borrow,
override, or reseal the ledger. Its `fetches`
use the machine's closed raw fetch/page records, pagination rules, raw bodies,
and digests and cover the current pull detail, compare, issue
comments, reviews, every PR review's associated inline endpoint before
terminal-looking or provider classification, raw GraphQL review
threads/comments, and every controlled-request reaction endpoint.
`request_scope_receipts` and `artifact_scope_receipt_dispositions` are
parent-owned sidecar evidence, not members of or new kinds inside those
fetches. The disposition sidecar is required whenever migration would classify
any raw applicable artifact outside receipt-bound normalized wrappers. Its
closed schema, exhaustive raw identity/source-digest join, independent
parent-private raw-base/ledger digest binding, and initial/final stability are
validated before the legacy partition; raw-minus-normalized is never treated as
absence. The two inventories are independent API
traversals, not aliases, copies of one body, normalized snapshots, or
projections supplied by the caller. Both must independently derive the same
complete provider-artifact, target-thread, and finding-commit sets.
Request/reaction set equivalence and request-scope-sidecar stability are additionally
mandatory only when classifying request policy or reaction evidence. Missing
pages, over-budget traversal, provider artifact/thread drift, or finding-commit
drift still blocks terminal authority; a missing, malformed, or
request-scope-sidecar-only drift instead makes request policy and the affected reaction authority
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
  finding enters the authoritative closure/supersession reducer;
- `1`: local Git proves that the finding commit is not an ancestor of the
  current head, so it remains audit evidence but is not a current/ancestor
  blocker.

A missing ancestry receipt, missing local object, duplicate or extra ancestry
receipt, a return code other than the exact values above, a raw-derived
commit-set mismatch, provider-artifact/thread drift, or ancestry-receipt drift
makes ancestry unknown: required status is `PENDING` only while bounded
acquisition remains and the epoch overall deadline has not arrived, and
`ERROR` after local exhaustion. At the overall deadline a still-budgeted
unknown follows timeout `FAILURE` unless a higher-priority final-deadline arm
applies. The initial
and final ancestry-receipt arrays must be type-preserving identical and must
each cover exactly the full commit set derived from its corresponding raw
inventory. Request-scope sidecars remain a separate plane: their absence,
malformation, or reread drift cannot veto a stable terminal payload, but it
makes request policy and the optional reaction audit `unknown`.

For ordinary terminal classification, the complete raw projection must equal the
normalized current record before terminal precedence is applied. Legacy
receipt migration instead proves the explicit raw-to-receipt-qualified join
`raw_applicable_artifacts = receipt_bound_normalized_artifacts ⊎
legacy_unreceipted_audit`; the normalized current record contains only the
receipt-bound wrappers, while the closed audit-only member remains derived
from both raw inventories and their stable, externally bound
`artifact_scope_receipt_dispositions` sidecars. A raw-only artifact or thread
that is neither in
the receipt-bound normalized member nor admissible under that exact legacy
partition makes provider classification inconclusive. Every current-head or
parent-proved ancestor finding must remain present in the compared projection.
An authoritatively resolved joined thread closes; an unresolved thread blocks;
and a threadless finding is superseded only by a strictly later strong current-
head clean. Human, unrelated-bot, null-parent,
and unrelated-only thread state cannot contribute resolution, while a
malformed target join still fails closed. Every accepted terminal
`provider.evidence_basis` embeds both independent raw current endpoint inventories and
both parent-owned local Git ancestry-receipt arrays; external ledgers or
normalized current snapshots do not replace them.

A raw current endpoint inventory is already selected to one exact PR and
contains exactly one retained detail fetch set. Its parser charges and parses
the real pull-detail page exactly once, derives the scope from that page plus compare,
and validates the outer PR/head selector against the result. It must not create
or charge a synthetic seed, pre-parse the pull under another tracker, grant a
second deadline, or mutate retained bytes after budget validation.

### Reaction Semantics

`+1` has no fallback role in v41. It never supplies provider clean, required
Action-status `PASS`, ACK, retry closure, named-lane completion, or readiness.
Exact-provider `eyes` is liveness-only and may ACK only the selected attempt
through the main attempt-machine contract; it never resets the ACK, result, or
overall deadline. Missing, ambiguous, malformed, or drifting reaction evidence
affects only the optional reaction audit and cannot erase a separately stable
terminal payload. It also cannot make incomplete current provider evidence
complete.
## No-Start And Non-Completion States

At the v41 authority profile, the accepted structured
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
not a clean review result. However, the v41 authority profile intentionally
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
Report its future versioned provider classification and
`provider.evidence_basis.kind: no-start-rejection`; it never supplies a clean result.
Missing response remains `pending` while bounded waiting is meaningful.
After waiting is exhausted, generic failure, unknown identity, absent grammar,
ambiguous no-start wording, or any contradictory start evidence remains
`triple-inconclusive`.

## Required Report Fields

Report exactly the six decision/audit planes named below without collapsing
them. `requested_shape`, `effective_shape`, and `review_epoch` are envelope
metadata, not additional planes. Only `provider` may contain
`evidence_basis`.

```yaml
requested_shape: single | double | triple
effective_shape: single | double | triple
review_epoch: <exact five-field epoch identity>

request_policy:
  status: compliant | warning | unknown | not-applicable
  early_request_observed: true | false | unknown
  duplicate_observed: true | false | unknown
  evidence: [...]

provider:
  classification: clean | findings | progress | transient-incomplete | malformed | pending | inconclusive
  evidence_basis: <closed provider terminal/no-start/blocking basis or null>
  selected_artifact: <exact native identity or null>
  publication_scope: <six-field scope or null>
  scope_assurance: artifact-publication-only | null
  applicable_findings: [...]
  closed_findings: [...]
  superseded_threadless_findings: [...]
  nonancestor_audit: [...]
  unknown_ancestry: [...]
  transient_acquisition: [...]
  final_stability: stable | unstable | incomplete

required_action_status:
  context: codex/review-gate
  head_sha: <exact PR/status head>
  overall_deadline_state: before-overall-deadline | at-or-after-overall-deadline
  reduction_authority_coordinate: <one parent-owned github-codex-sealed-reduction-authority-coordinate-v1>
  reduction_authority_components:
    required_action_status_registry_membership_coordinate: <parent-owned 16-role membership coordinate>
    provider_validation_coordinate: <parent-owned final-stable provider validation coordinate>
    epoch_first_attempt_clock_coordinate: <parent-owned immutable epoch-origin/deadline coordinate>
    current_marker_attempt_coordinate: <parent-owned current attempt/marker coordinate>
  epoch_first_attempt_origin_at: <immutable authenticated GitHub Date>
  current_marker_created_at: <current-attempt marker time or null>
  selected_status:
    id: <positive integer>
    node_id: <StatusContext node ID>
    state: success | failure | pending | error
    target_url: <exact run-attempt URL>
  decision: PASS | FAILURE | PENDING | ERROR
  reason: <closed reducer reason>
  producer_binding:
    caller_repository: <owner/repo>
    caller_workflow_path: <path>
    caller_uses: JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1
    run_id: <positive integer>
    attempt: <positive integer>
    run_event_head: <40-hex>
    caller_workflow_sha: <40-hex>
    exact_attempt_workflow_sha_W: <40-hex>
    checkout_ref_W: <same exact-attempt W>
    checkout_verified_output_C: <40-hex>
    action_commit_environment_C: <same C>
    local_action_root_commit_C: <same C>
    action_commit_C: <40-hex>
    selected_candidate_signed_v1_tag_object_T: <40-hex>
    selected_candidate_signed_v1_minor_tag_object: <40-hex>
    immutable_release_tag_object_R: <40-hex>
    current_v1_alias_tag_object_T_current: <40-hex>
    current_v1_alias_target_commit_C_current: <40-hex>
    workflow_sha_resolution:
      selection: selected-sha-equals-exactly-one-candidate
      action_commit_oid: <C>
      selected_candidate: signed-major-tag-object | exact-action-commit
      candidates: <exact ordered two closed candidates>
    pr_status_head: <40-hex>
    receipt_schema: urn:joeyteng:codex-review-gate:producer-receipt:1
    producer_protocol_major: 1
    decision_schema: urn:joeyteng:codex-review-gate:decision-table:1
    decision_schema_version: 1
    policy_major: 1
    policy_version: <selected-release exact SemVer with major 1>
    release_tag: <globally unique immutable annotated v1.x.y at or after v1.5.1>
    release_candidate_classifications: <complete ordered valid | proved-incompatible | malformed-or-incomplete-error vector>
    recursive_action_tree_complete: true
    source_commit: <selected-release independently authenticated source commit distinct from C>
    recursive_source_root_tree_complete: true
    source_action_subtree_binding: independently-authenticated-equals-Action-C-root-tree
    release_provenance_schema: urn:joeyteng:codex-review-gate:release-provenance:2
    trusted_signer_fingerprint: EFBBC913F49A5F6E0AF0D248F70246143DC28F32
    selected_release_critical_file_sha256:
      action_package: <selected-release lowercase-64-hex raw SHA-256>
      action_definition: <selected-release lowercase-64-hex raw SHA-256>
      reusable_workflow: <selected-release lowercase-64-hex raw SHA-256>
      producer_receipt_schema: <selected-release lowercase-64-hex raw SHA-256>
      decision_table: <selected-release lowercase-64-hex raw SHA-256>
    v1_5_0_complete_asset: fail-closed-not-admitted
    digest_erratum_supported: false
    final_readback_registry: <16-role parent membership>
  assurance: authenticated-run-consistency-plus-signed-immutable-release-admission
  non_guarantees:
    - no-cryptographic-job-provenance
    - no-provider-request-run-artifact-lineage
    - no-provider-input-merge-base-attestation
    - floating-v1-executed-before-validation
    - no-online-or-retroactive-revocation-guarantee

named_github_lane:
  disposition: pending | blocked-findings | triple-inconclusive
  positive_completion_basis: null

reaction_audit:
  present: true | false
  record_identity: <audit readback or null>
  supplies_clean: false
  supplies_PASS: false
  supplies_ACK: false

readiness:
  result: merge-ready | pending | blocked | inconclusive
  required_action_PASS: true | false
  other_required_gates: [...]
```

`PASS` is written only when the v41 reducer accepted the selected current-head
status and full producer binding. The report must retain all five SHA/OID
domains even when values happen to be byte-equal. It must separately retain the
three-source `W` equality, four-source `C` equality, the selected candidate's
independently proved release `R`, minor, and historical-major `T` objects, the
separate current alias `T_current` and `C_current`, both ordered resolution
candidates, and the unique selected candidate. The current floating `v1` ref is
never reported as a replacement for exact-attempt `W` or a historical
candidate proof.

For a proved pre-provider blocker, provider classification and
`provider.evidence_basis` may be null. During eligible bounded waiting, report
the observed provider classification and a null provider basis. A terminal
artifact records only
artifact-publication scope; clean is classification-only and findings remain
blocking. Unknown ancestry and transient acquisition must report the remaining
budget state, overall-deadline state, and pending-to-error or timeout-failure
transition reason. A deterministic malformed basis reports `ERROR` and no
automatic POST. `evidence_basis` is forbidden in `request_policy`,
`required_action_status`, `named_github_lane`, `reaction_audit`, and
`readiness`; those planes may reference their own memberships or reasons but
must not duplicate the provider basis.

The named GitHub lane has no positive completion basis in v41 because the
accepted provider input-base and request/run/artifact-lineage schema sets are
empty. Required Action `PASS` is still necessary for readiness, but the
readiness result must independently enumerate local lanes, CI, conversation,
exact-secret, lifecycle, scope, authorization, branch/base, and current-head
gates.

## Hosted Action Alignment And Playbook Extensions

Provider-result parsing rationale is inherited from the historical v37 Action
baseline. Required Commit Status authority now comes only from the dynamically
admitted hosted reusable workflow and its signed immutable v1.x release; neither
source establishes provider whole-PR input binding, named-lane completion, or
merge readiness. The stricter evidence carriers and scope gates below are deliberate
playbook extensions and must not be “corrected” by copying the Action
implementation mechanically:

1. **Whole-PR scope and lifecycle are stricter.** The Action baseline binds a
   clean artifact to the current head and validates a complete evidence
   snapshot. This playbook additionally requires exact selected-PR lifecycle,
   base OID, head OID, one local merge base, and equality with the frozen
   whole-PR range, plus the independent artifact-time scope receipt described
   below. The current retarget contract is exact integer version `23`, compatible
   only with `[23]`; versions 1 through 22 reject it. Its scope includes the
   actual `base_ref_name` and keeps current base-tip `base_ref_oid` independent
   from `pr_merge_base`. Apply the retarget machine's closed `none` / `observed` / `unknown`
   prior-epoch activity classification only after exact-version membership and
   independent readback select the classification and supersession event from
   the parent append-only store. After that readback, recompute `evidence_sha256`
   over the exact closed preimage, derive the class from the exact type-sensitive
   origin and four inventory inputs under the fixed consumer algorithm, and
   require the stored `classification` to type-sensitively equal the derived
   value. Candidate- or consumer-sealed nested records are not authority. Only
   derived complete `none` plus an authorized
   exact-current range may supersede an unused epoch, and `none` requires a
   provider-native append-only no-inflight attestation covering automatic,
   controlled, and manual triggers. The current machine-owned accepted registry
   is empty and caller/current-consumer override is forbidden, so `none` is
   unreachable; complete current snapshots alone select `unknown`,
   and publication time never relabels a late same-head artifact. `observed`
   remains `base-changed-same-head` and terminally blocks prior-epoch
   retirement, every same-head POST, and every same-head artifact admission;
   only a genuine new head may start a new epoch. `unknown` is
   `prior-epoch-third-lane-activity-unverified`.
   Only an explicitly version-bumped hypothetical future machine with its own
   closed consumer profile and nonempty machine-owned registry may demonstrate
   `none`. Before supersession, independently reread and JSON-type-sensitively
   cross-bind exact repository ID/full name, PR number, unchanged head SHA,
   immutable `range_origin {kind, base_sha, head_sha}`, complete current
   classification/current scope, actual authorized transition or recovery
   authority, and canonical prior/new origins. Exact open lifecycle, fresh
   unique merge-base authority, new epoch, reason, unique merge-base capture <=
   current-scope capture <= new-origin reservation < authorized transition <
   supersession < finalized new-origin registration, and classification <
   supersession remain mandatory. All
   required authorities are independently loaded before supersession, and every
   duplicated scalar/ID/revision/timestamp/scope component must match in JSON
   type and value. Any cross-record splice or causal backfill is `unknown` and
   fails closed; M1 authority cannot be reused at M2.
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
5. **Reaction history is audit-only.** The historical Action collected
   `plusOne` but did not use it as terminal provider-result authority. v38 went
   further, and v39, v40, and v41 retain that rule: `+1` is never clean, PASS, ACK, retry
   closure, named-lane
   completion, or readiness. Optional historical profiles and declarations are
   retained only in the small raw-reaction audit record.
6. **`eyes` remains orchestration-only.** Only an exact-provider `eyes`
   reaction fetched from the persisted marker's canonical fully paginated
   reactions endpoint and joined through its marker-persistence receipt and
   write-ahead may consume that attempt's ACK. The state-changing receipt lives
   in an immutable append-only parent ACK store; the attempt holds only its
   compact membership. That membership and receipt select an independently
   preregistered immutable reconciliation snapshot by ID, revision, entry
   index, and digest, and one atomic epoch CAS verifies and publishes the
   receipt, membership, snapshot relation, and attempt transition. The receipt
   or source cannot register or self-hash its own snapshot. Provider comments,
   checks, runs, unregistered liveness records, and identity or parent
   lookalikes remain epoch-level audit/liveness only. Historical controlled
   marker persistence is a compact membership that independently loads one
   closed REST comment authority/readback with exact `github-actions[bot]` /
   `Bot` identity, canonical API/HTML/issue URLs, positive ID, raw body/digest,
   creation/update/response times, epoch, attempt, and write-ahead. Parent or
   caller self-attestation is not authority. Before ACK-backoff derivation,
   validate the complete canonical v41 attempt ledger through the current
   attempt. Derive `consecutive_same_epoch_missed_ack_count` from the complete
   prior-attempt terminal history by counting only the consecutive same-epoch
   `missed_ack` suffix, then select exactly `[300, 600, 1200, 1800]`.
   A selected-timeout or history-terminal mismatch rejects; caller or persisted
   count/window is output validation only. The attempt ledger stores
   deadline history only as compact
   `github-codex-deadline-transition-history-membership-v1`; all full R1/C2/C3
   receipts live only in append-only
   `github-codex-deadline-transition-receipt-store-v1`.
   `github-codex-deadline-transition-cas-v1` atomically publishes the compact
   after-ledger, one full receipt-store append, and transaction/readback or none;
   `github-codex-deadline-transition-cas-readback-v1` independently resolves
   membership and recomputes exact before/after ledger, store, and receipt
   raw-byte SHA-256 values. R1 is the single missed-ACK step. C2 keeps R1 bytes
   and JSON types unchanged and appends the ACK-bound reopen; C3 keeps the full
   C2 transition prefix unchanged and appends the result timeout. Steps exclude
   after-ledger digests. C2 resolves step 1's compact membership through its
   parent CAS transaction readback and recomputes the exact after-ledger raw
   SHA-256; a step-owned `epoch_ledger_sha256_after` is not authority. Later
   continuity uses the same prior-CAS proof, avoiding self-reference. The late ACK
   precedes any successor retry CAS and no arm extends a deadline. Historical
   stalled-`eyes` authority joins compact membership to the complete
   parent-store receipt; summaries, reconstruction, or changed/reordered
   prefixes fail closed. This
   playbook records later `eyes` as liveness audit; `eyes` never supplies
   result authority and there is no `+1` fallback.
   Full receipt variants are
   `github-codex-authenticated-deadline-transition-v2` and
   `github-codex-authenticated-deadline-transition-chain-v1`.
7. **Duplicate result consumption aligns with the Action; warning codes are a
   playbook extension.** Stable current-head result evidence is not rejected by
   marker or audit history in the fixed baseline. This playbook inherits that
   consumer rule, while adding `duplicate-observed` and forbidding overlapping
   or untracked duplicate requests. The current epoch machine may still open one
   serial same-epoch successor after `missed_ack`, `stalled`, or definitive
   not-dispatched close only inside the immutable original `max_wait`, while
   provider completion is still pending, and with a fresh complete
   provider-reconciliation receipt at every successor gate.
8. **Early-result consumption aligns with the Action; local-lane sequencing is
   a playbook extension.** The fixed baseline accepts stable clean evidence
   regardless of marker timing. This playbook additionally requires local
   terminal artifacts before it sends a new GitHub request and reports
   `early-request-observed` when that producer order was violated. Do not
   discard a later independently trustworthy provider result solely because of
   that producer-side sequencing defect.
9. **Complete current raw capture is a playbook extension.** The parent
   performs independent initial and final traversals of the exact selected PR's
   pull detail, compare, issue comments, reviews, every per-review inline
   endpoint, GraphQL threads/comments, and the selected controlled-request
   reaction endpoint when ACK or optional reaction audit requires it. Machine-
   owned budgets and raw pagination/readback contracts apply; no historical
   discovery profile, caller transcript, or provider declaration supplies
   decision authority.
10. **Request-time scope sidecars are a playbook extension.** The fixed Action
    comparison does not establish the exact scope of a parent-created request.
    This playbook separately captures closed pre/post pull-and-compare receipts
    and the exact POST response, binds every reaction parent one-to-one to that
    scope, and fails the request/reaction planes closed when the sidecar is
   absent. It neither changes the provider raw-fetch graph nor creates
   request/run lineage, and it does not veto an independently trustworthy
    terminal payload with its own complete artifact-time scope receipt.
11. **Artifact-time whole-PR receipts are a playbook extension.** Result-present
    acceptance is inherited, but the fixed Action comparison does not prove an
    artifact's merge base at its semantic server time. This playbook requires
    the singular closed `parent-recorded-terminal-artifact-scope-v2` receipt
    with pre pull/compare, exact artifact GET, and post pull/compare responses.
    The envelope binds the artifact body/digest/identity and artifact-time
    whole-PR scope without naming a request or run. Clean and malformed
    evidence require the current tuple; a proved-ancestor finding preserves its
    artifact commit while normalized `scope.head` and every pre/post
    pull-detail/compare head remain current. An
    artifact that does not strictly follow every trustworthy pre observation
    cannot be retroactively scoped. Equal point reads still do not exclude an
    intermediate ABA transition.
## Non-Goals

- Do not treat checks, Commit Status, acknowledgements, progress comments,
  reactions, sticky state, deadlines, or request markers as provider clean.
  The canonically bound required Commit Status has its own PASS reducer.
- Do not weaken exact bot identity or full pagination to make a profile fit.
- Do not use a caller transcript, normalized current snapshot, reaction audit,
  copied provider prose, or external ancestry ledger as
  reaction-clean authority; v41 defines no such authority.
- Do not insert request-time scope receipts into the provider raw-fetch graph,
  infer request/run lineage from them, or claim matching pre/post scope
  snapshots exclude an intermediate ABA transition.
- Do not reconstruct an artifact-time receipt from later current metadata,
  omit the exact artifact GET, add unversioned fields to its closed object, or
  claim its pre/artifact/post point reads prove continuous or ABA-free scope.
- Do not conflate `scope.head` with a finding's artifact commit. Clean must bind
  current head; ancestor findings remain projected through local ancestry
  receipts and then use authoritative thread closure or the narrow strictly-
  later threadless supersession rule. Only a parent-proved nonancestor is
  excluded audit-only before reduction.
- Do not reattach a request/reaction from one receipt-derived scope epoch to
  another, even when the repository, PR number, or head matches.
- Do not carry an optional reaction-audit record across repositories or
  epochs, create a second reaction state graph, or consume it in the v41
  reducer.
- Do not create a duplicate request, empty commit, or synthetic provider
  artifact to escape an inconclusive state.
- Do not claim the policy itself proves provider behaviour; every counted
  outcome still requires the complete evidence and final-stability checks
  above.
- Do not pin per-run `W`, `C`, `T`, `R`, the selected called-workflow raw bytes
  or digest, or compatible external Action SHAs;
  dynamically validate the globally unique signed immutable release. Do not pin
  its policy patch value or critical-file raw hashes either. Require the exact
  selected-release policy SemVer to have major 1 and agree across provenance
  and released decision-table bytes, and require every critical-file digest to be
  internally self-consistent and tree/blob-bound at `C`. A compatible signed
  v1.x.y release may change those runtime values without a Skill update.
- Do not claim dynamic admission proves cryptographic job execution, provider
  request/run/artifact lineage, provider input merge base, online revocation,
  named-lane completion, or merge readiness. Required Action `PASS` proves none
  of those by itself.
