# GitHub PR Probes

This reference owns endpoint selection, raw-capture expectations, and bounded probe shapes. It does not classify provider evidence or restate machine schemas. Load [github-codex-evidence-authority.md](github-codex-evidence-authority.md) first for evidence meaning and [pr-readiness.md](pr-readiness.md) for gate ordering.

## Probe Order

For a selected PR, collect evidence in this order:

1. Fetch pull detail and classify `state`, `merged`, and `merged_at`. Stop on any lifecycle value other than exact `open` / `false` / `null`.
2. Read `base.ref`, `base.sha`, and `head.sha`; fetch Compare for that exact base/head pair and independently derive one merge base.
3. Apply base-only-retarget or generic range-mismatch policy only after lifecycle and scope reads succeed.
4. When the GitHub lane is eligible, capture complete request, provider-artifact, inline-comment, thread, reaction, and check-run inventories; complete required Commit Status pagination with GraphQL `StatusContext` node rereads; and capture the selected producer's exact run attempt including `referenced_workflows`, artifact inventory, receipt ZIP, closed receipt, caller workflow bytes, controlled exact-pinned checkout result, the separate final-stable current-`v1` alias proof `T_current -> C_current`, called-workflow commit/tree/blob evidence at candidate `C`, complete GitHub Releases inventory, every candidate's provenance asset and independent release-`R`/derived-`v1.minor`/historical-`v1`-`T` tag-object and local-verifier proofs, and distinct source commit/tree proofs.
5. Repeat lifecycle, scope, exact-artifact GET, and terminal-set captures at the authority-defined boundaries; at final reconciliation, independently repeat the complete required Commit Status/GraphQL capture and re-read every selected producer input from step 4, including each candidate's exact closed `workflow_sha_resolution` and three tag proofs plus the separate current-`v1` `T_current/C_current` alias proof.

Steps 4 and 5 also capture and then independently re-read each candidate's two
deterministic release-scoped minor/major retention refs. The current floating
minor and major aliases remain separate observations and never substitute.

Explicit-range-only single or double review skips these PR probes.

## Core Metadata

Prefer typed `gh` output for orientation:

```bash
gh pr view <number> --repo <owner/repo> \
  --json number,url,state,isDraft,mergedAt,baseRefName,baseRefOid,headRefName,headRefOid,headRepository
```

Use authenticated REST pull detail for evidence capture:

```text
GET /repos/{owner}/{repo}/pulls/{pull_number}
```

The capture must retain the exact canonical URL, status, authenticated server `Date`, raw response body bytes and digest, operating identity, and the projected lifecycle and base/head fields. Legitimate extra GitHub fields remain retained and digest-bound.

Derive Compare from the pull body's exact SHAs:

```text
GET /repos/{owner}/{repo}/compare/{base.sha}...{head.sha}
```

Require the Compare body to repeat the base and prove one merge base. `base_ref_oid` and `pr_merge_base` are separately authenticated and may be byte-equal or different; neither source may substitute for the other. Do not use `head_commit`, `commits[-1]`, a locally guessed base branch, or a floating ref as merge-base authority.

With lazy fetching disabled, require both endpoint commits locally and run bounded no-fetch Git ancestry checks. A PR-specific frozen range covers the whole PR only when `base_sha == pr_merge_base` and `head_sha == headRefOid`.

## Provider Inventories

The canonical authority may require these exact-host resources:

```text
GET /repos/{owner}/{repo}/issues/{pull_number}/comments?per_page=100&page=1
GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews?per_page=100&page=1
GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments?per_page=100&page=1
GET /repos/{owner}/{repo}/issues/comments/{comment_id}
GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}
GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions?per_page=100&page=1
GET /repos/{owner}/{repo}/commits/{head_sha}/check-runs?per_page=100&page=1
```

Review-thread capture uses GitHub GraphQL because REST does not expose complete thread resolution state. Retain raw GraphQL pages and bijectively join every inline comment to its REST child and parent review using stable native identifiers and URLs. Do not infer a missing thread, comment, or page from counts or normalized summaries.

For each candidate artifact, fetch the exact native resource again. A page-list row, check run, reaction, or caller projection never substitutes for that exact GET.

## Required Action Status And Producer Receipt

The required Action-hosted reusable workflow publishes a Commit Status, not a check run. Consumer installation is one-time: preserve the repository-owned events, permissions, and concurrency, and make the per-PR caller workflow's only job use exact `JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`. The called path is the same `.github/workflows/codex-review-gate.yml`. Floating `@v1` is the accepted pre-execution trust boundary; it is not a Skill-pinned immutable launch ref.

A repository may separately own an independent scheduled dispatcher that boundedly selects PR targets and transports targeted runs into this caller. Do not collect, register, or reduce the dispatcher workflow or its runs as producer evidence: it supplies neither Action-status `PASS` nor alternate producer-caller authority. Its exact trigger, cadence, and permissions remain repository policy outside the generic evidence protocol.

Collect these read-only resources through the parent-owned raw recorder; the GraphQL call is a node query, never a mutation. Release-asset URLs must come from the authenticated release response rather than caller construction:

```text
GET  /repos/{owner}/{repo}/commits/{head_sha}/statuses?per_page=100&page=1
POST /graphql  # StatusContext node(node_id)
GET  /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}
GET  /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page=1
GET  /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip
GET  /repos/{owner}/{repo}/contents/{workflow_path}?ref={caller_workflow_sha}
GET  /repos/JoeyTeng/codex-review-gate-action
GET  /repos/JoeyTeng/codex-review-gate-action/git/ref/tags/v1
GET  /repos/JoeyTeng/codex-review-gate-action/git/tags/{T}
GET  /repos/JoeyTeng/codex-review-gate-action/releases?per_page=100&page=1
GET  /repos/JoeyTeng/codex-review-gate-action/releases/{release_id}
GET  /repos/JoeyTeng/codex-review-gate-action/releases/{release_id}/assets?per_page=100&page=1
GET  {release_provenance_asset_api_url}
GET  /repos/JoeyTeng/codex-review-gate-action/git/ref/tags/{release_tag}
GET  /repos/JoeyTeng/codex-review-gate-action/git/ref/tags/codex-review-gate-retention/{release_tag}/minor
GET  /repos/JoeyTeng/codex-review-gate-action/git/ref/tags/codex-review-gate-retention/{release_tag}/major
GET  /repos/JoeyTeng/codex-review-gate-action/git/tags/{release_tag_object_oid}
GET  /repos/JoeyTeng/codex-review-gate-action/contents/.github/workflows/codex-review-gate.yml?ref={C}
GET  /repos/JoeyTeng/codex-review-gate-action/git/commits/{C}
GET  /repos/JoeyTeng/codex-review-gate-action/git/trees/{provenance.action.tree_oid}?recursive=1
GET  /repos/JoeyTeng/codex-review-gate-action/git/blobs/{workflow_blob_sha}
GET  /repos/{source_owner}/{source_repo}/git/commits/{source_commit_oid}
GET  /repos/JoeyTeng/codex-review-gate/git/trees/{provenance.source.tree_oid}?recursive=1
GET  /repos/JoeyTeng/codex-review-gate/git/trees/{provenance.source.action_subtree.tree_oid}?recursive=1
```

The three recursive tree resources are deliberately distinct: the released Action root named by `provenance.action.tree_oid`, the source-repository root named by `provenance.source.tree_oid`, and the source `packages/action` subtree named by `provenance.source.action_subtree.tree_oid`. Send every tree request with `?recursive=1`, strict-load its closed response, and require `truncated == false` before consuming any entry or deriving a manifest.

Fully RFC-8288-paginate `/statuses` and preserve server order. Context matching is case-insensitive: select the first row whose `context` case-folds to `codex/review-gate`, then require that selected spelling to be exact. Do not skip a newer case variant, compatibility row, or unbound row to reuse an older success. Retain each row's ID, `node_id`, context, Commit Status state, target URL, description, creator, and times; for every row, raw-reread its `node_id` as exact GraphQL `StatusContext` and bind ID, context, upper-case state, target URL, creation time, commit OID, and creator type/login/database ID. No accepted REST status-by-ID GET exists for this contract; never invent `/statuses/{status_id}`.

Initial and final status observations are independent complete raw traversals with independent GraphQL rereads. The ordered required-context subsequence must remain type-sensitively equal. Unrelated contexts may churn, but every raw page and row in each observation must independently validate; required-context row, order, multiplicity, pagination, or node-binding drift is unstable.

The selected status `target_url` must be exact `https://github.com/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}`. The corresponding attempt request binds run ID/attempt, workflow ID, event, terminal state, run/event head, path, and the complete `referenced_workflows` value; its response `url` and `html_url` correctly name the base run without the attempt suffix. Fully paginate artifacts and require exactly one live `codex-review-gate-producer-receipt-{run_id}-{attempt_number}` whose ID/URLs/times/digest and workflow-run association validate. Its digest-bound ZIP has exactly one unencrypted file, `codex-review-gate-producer-receipt.json`.

Strict-load that file as closed producer receipt v1 under the authority's exact schema. Require completed execution, exact status count, contiguous one-based status sequence, unique IDs/node IDs, producer protocol major 1, decision schema 1, and decision policy major 1. Receipt v1 has no `policy_version` field; do not invent one or treat the receipt as policy-version authority. Bind receipt run/attempt/target URL and exactly one manifest member containing the selected status's PR, reviewed head, exact context, state, description, target URL, creator, REST ID, and GraphQL node ID.

Keep these roles independent and accept equality only through the closed resolution contract:

1. the Actions run/event head from the attempt;
2. the caller-workflow SHA from the receipt's caller `environment` and exact caller-workflow blob;
3. the PR/status head from authenticated PR scope plus REST/GraphQL status evidence;
4. server-returned workflow SHA value `W`;
5. the selected candidate's independently authenticated historical signed annotated `v1` tag-object OID `T`;
6. called reusable-workflow commit `C` from the controlled exact-pinned checkout; and
7. the separately authenticated current floating-`v1` alias object/target `T_current/C_current`.

Fetch caller workflow bytes at the receipt's exact 40-hex caller `GITHUB_WORKFLOW_SHA`, bind its own repository/path/ref/digest, and require its only job to use exact `JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`. Do not require the attempt's run/event `head_sha` to equal caller `GITHUB_WORKFLOW_SHA`, and do not equate either one with `W`, candidate `T/C`, current alias `T_current/C_current`, or the PR/status head.

Bind the receipt's called-job repository/path/ref fields and Action repository structurally to the unique canonical exact-attempt `referenced_workflows` entry and the caller's exact producer/path/`@v1` selection. Require the unique entry's ref to be exact `refs/tags/v1`; missing, null, another ref, zero candidates, or multiple candidates fails closed. Define `W` only by exact equality across receipt `job.workflow_sha`, receipt `action.ref`, and that unique entry's `sha`. Define `C` only by exact equality across the parent-controlled exact-pinned checkout output, receipt `action.commit_sha`, provenance `action.commit_oid`, and provenance `tags.v1.peeled_commit_oid`. Receipt or caller self-assertion without those independent bindings is not authority.

For every release candidate, strict-load its provenance `workflow_sha_resolution` as a closed object with exactly two ordered arms: that candidate's independently fetched and locally OpenPGP-verified historical signed annotated `v1` tag object `T` directly targeting `C`, and exact Action commit `C` resolving to itself. Count type-sensitive `W` matches against those two values: zero is `proved-incompatible` only when every other candidate proof is complete, valid, and unambiguous; one makes only the runtime-resolution arm eligible; more than one is malformed `ERROR`. The separate current floating alias must be independently authenticated and final-stably reread as signed `T_current -> C_current`; it is live audit/stability evidence, never a substitute for exact-attempt `W` or any historical candidate's `T/C` proof. If `W == T_current`, additionally require `C_current == C`; otherwise a valid compatible alias move may differ. Resolve and fetch the reusable workflow plus released Action tree and critical-file bytes at candidate `C`, and bind their Git blob identities and raw digests to provenance.

Discover release candidates only through a complete bounded authenticated GitHub Releases inventory; tag/ref inventories, receipt text, current floating aliases, or caller input cannot select the release. For every candidate, independently fetch by its provenance OIDs and locally OpenPGP-verify the exact signed payload/signature of its immutable release tag object `R`, derived `v1.minor` tag object, and historical provenance-`v1` tag object `T`; each must directly target that candidate's `C`. Admit exactly one candidate only after its release is non-draft, non-prerelease, immutable, compatible with producer receipt schema v1, producer protocol major 1, decision schema 1, decision policy major 1, and release-provenance schema v2; its complete asset inventory contains exactly one valid provenance-v2 JSON asset; the GitHub-reported canonical `sha256:<64-lowercase-hex>` digest binds the downloaded bytes; all three tag proofs pass; and its closed `workflow_sha_resolution` has one `W` match. `v1.5.0` is explicitly never admitted and has no erratum or retrofit path; `v1.5.1` is the first admitted semantic boundary. Provenance `source.commit_oid` is the distinct source-repository commit and must not equal-bind to `C`; authenticate it independently and prove declared source-subtree/released-Action-tree equality as a separate content relation. Retain exact SemVer `policy_version` as audit evidence, require major 1 and equality across provenance `compatibility.decision_table`, provenance `critical_files.decision_table`, and the authenticated released decision-table bytes; validate the actual provenance maps rather than inventing receipt fields or a signature asset. Never fill an unknown `W`, candidate `R/T/C`, current alias `T_current/C_current`, source commit, workflow digest, asset digest, policy version, or signer from a Skill pin, caller input, status prose, or receipt self-assertion.

Derive the complete ordered release-candidate classification vector and assign every candidate exactly `valid`, `proved-incompatible`, or `malformed-or-incomplete-error`. Only complete, well-typed, authenticated, internally unambiguous evidence that proves an admission predicate false is `proved-incompatible`; specifically, a valid OpenPGP signature by one unambiguous primary signer different from the trusted signer or an otherwise complete candidate with zero `W` matches belongs there. One `W` match is only eligible pending all other predicates; more than one is malformed. Missing, invalid, ambiguous, or unverifiable tag evidence and every integrity or cross-binding contradiction are errors. Any malformed/incomplete candidate or invalid/unstable current-alias proof makes the whole producer binding `ERROR`; otherwise exclude only proved-incompatible candidates and require the remaining valid cardinality to be exactly one.

This evidence establishes authenticated GitHub run-level consistency plus signed immutable-release admission; it is not cryptographic attestation that the job executed particular bytes. Because floating `@v1` resolves before post-run verification, a rejected producer may already have executed with caller permissions; rejection can withhold `PASS` but cannot undo execution. The contract defines no online revocation feed or retroactive post-publication revocation guarantee. Compatible v1.x upgrades change only Action source/release and signed provenance, so the consumer caller and Skill carry no patch-release SHA, selected called-workflow bytes/digest pin, workflow-blob pin, or selected release external Action SHA-set pin.

Re-read the selected status node, exact attempt including complete `referenced_workflows`, artifact inventory/ZIP/receipt, caller workflow blob, controlled exact-pinned checkout evidence, separate authenticated current alias `T_current/C_current`, called workflow/commit/tree/critical blobs at candidate `C`, repository immutable-release setting, complete GitHub Releases and asset inventory, every candidate's provenance bytes/digest including closed `workflow_sha_resolution`, release-`R`/minor/historical-`T` tag objects and local verifiers, and source commit/tree at final reconciliation. Require type-stable bindings and bytes, the complete match-count vector, repeated candidate tag proofs, stable separate current-alias proof, repeated subtree equality, and globally unique valid release. Noncanonical repository-side compatibility publishers remain audit-only and never enable fallback. These probes produce and register component evidence only. Reduction accepts solely the one parent-owned sealed composite coordinate binding required-status membership, final provider validation, immutable epoch-origin clock, and current marker/attempt state; raw probes, caller dictionaries, and independently composed projections cannot decide an outcome.

The release-admission raw capture envelope is exact
`urn:joeyteng:codex-review-gate:release-admission:2`. For each candidate, derive
the two retention-ref paths only from its strict `release_tag`. In both initial
and final phases require the exact full ref name, `object.type == "tag"`,
`object.sha` equal to the corresponding provenance minor/major
`tag_object_oid`, and the canonical object URL. The two refs add four GETs per
candidate across both phases. They retain Git reachability only and never
supply signature, provenance, release selection, `W`, or compatibility
authority; current floating aliases remain independent.

Release-admission envelope v2 adds no field to the immutable provenance-v2
asset and must not change its bytes or digest. Before enabling a v41 consumer,
correctively create and read back the v1.5.1 retention refs so
`.../v1.5.1/minor` directly names
`ab610036500f2eacb483abd3a6c272fd86ce5dec` and `.../v1.5.1/major` directly
names `9e9f2377342805156afcb0724f501509ef4e444c`. For every future release,
materialize and sign the tag objects and provenance asset, create and verify
both retention refs, and only then publish the non-draft immutable GitHub
Release; a later floating-alias move is a separate operation.

At final reconciliation, re-read both refs for every candidate and require
their exact ref/type/OID/URL bindings to remain type-sensitively stable. A
missing, wrong, malformed, or drifting retention ref makes that candidate
malformed or incomplete and therefore makes the whole release admission
`ERROR`; a live alias move never excuses or poisons a stable retention ref.

## Raw Pagination Contract

Before acquisition, type-sensitively load the epoch machine's exact `artifact_completion.evidence_resource_budget_contract.exact_config` and create one parent-owned composed-operation budget ledger covering the provider and required-Action REST/GraphQL, run/attempt, artifact/archive/workflow, release/asset/tag/provenance, source/Action tree, and raw-resource graph. Require every captured `resource_budget` to equal that configuration. Counters, retained UTF-8 bytes, and deadline are cumulative across the operation; only the body ceiling is per body. No initial/final capture, candidate/sibling evaluation, caller, release, or test input may reset, split, refund, borrow, override, or reseal the ledger. Exhaustion yields no partial authority and follows the owning plane's canonical reducer.

Every paginated capture must:

- begin at the canonical page-1 URL with `per_page=100`;
- retain each request URL, status, raw `Link` header, exact raw UTF-8 body, body digest, and page order; retain authenticated response `Date` only when an independent receipt contract explicitly lists it;
- strictly parse RFC 8288 relations, including `first`, `prev`, `next`, `last`, and `self` when present;
- follow exactly one canonical `next` chain until a terminal page has no `next`;
- reject loops, gaps, duplicate native IDs, conflicting relation targets, missing advertised pages, redirects, partial output, and reserialized bodies;
- preserve human, unrelated-bot, nonterminal, malformed-looking, and out-of-scope records for later canonical classification rather than prefiltering them.

Initial and final provider inventories are independent complete traversals. Persist and strictly parse both; a shared dictionary, reused traversal result, normalized digest, or matching summary is not two observations.

## Bounded Command Shapes

Use `gh` for compact metadata and GraphQL/REST orientation. Keep broad inventory calls bounded by endpoint, page size, and explicit page traversal; capture full raw authority through the parent-owned HTTP recorder required by the machine contract. A `gh --paginate` display can help diagnose a mismatch but does not by itself prove raw header/body custody.

For Actions state, start with compact status:

```bash
gh pr checks <number> --repo <owner/repo>
gh run list --repo <owner/repo> --branch <head-branch> --limit 20
```

Fetch a single run or bounded log only after resolving its exact ID. Follow `$bounded-command-output` for uncertain or verbose output: set a wall-clock limit, preserve exit status, retain a bounded artifact, and surface only decisive lines. Never treat truncated log output as a complete check or provider-evidence inventory.

## Probe Failures

Authentication ambiguity, redirects, missing pages, unstable lifecycle or scope, multiple merge bases, raw-body decode failure, invalid `Link`, or final-set drift fails closed. Report the exact failed probe and keep the existing PR unchanged. Endpoint success alone never establishes clean provider completion or merge readiness.
