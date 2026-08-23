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

## Immutable Scope

Freeze these fields before consuming evidence:

```yaml
repository: owner/name
pull_request: 123
host: github.com
head_sha: 40-lowercase-hex
```

Only exact-host `github.com` is supported by this contract. Read the PR again
immediately before accepting a result and require the same head. A clean result
for an older head is stale. A finding on the current head or a locally proved
ancestor in the current PR range remains applicable until resolved or
superseded under the rules below.

An advance of the target base tip does not by itself invalidate head-bound
provider evidence. If the head and unique merge base are unchanged, the frozen
local range is unchanged too, although freshness, mergeability, queue, and
base-tip-sensitive CI gates must be reacquired. Do not claim that a provider
comment, review, reaction, or ordinary check proves the base.

After a merge-base change on an unchanged head, the parent may reuse the
head-bound GitHub result after a complete final reread confirms the same head
and no unresolved applicable provider finding. It must rerun every invalidated
local and readiness gate against the new merge base, and it must reconcile any
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
- reactions on each candidate exact `@codex review` request when the fallback
  may be needed; and
- current-head check runs or statuses used as a preferred merge/status basis.

Start each connection at its first page, follow the returned cursor or next
link, and stop only at the provider's typed terminal pagination state. Summary
reaction counts are not actor evidence. Partial pages, broken cursor chains,
ambiguous IDs, or unstable final rereads are inconclusive.

Preserve raw IDs, URLs, actor fields, states, bodies, commit IDs, and server
timestamps. Parse only documented provider carriers with an anchored parser.
Unknown terminal-looking provider prose is malformed evidence, not a clean
result and not silently ignorable.

## Evidence Strength

Evaluate the following bases in order:

1. A trustworthy repository merge/status check that is demonstrably associated
   with the current head and the GitHub Codex review result.
2. A trustworthy exact-provider terminal clean issue comment or pull-request
   review for the current head.
3. The exact-provider `+1` reaction fallback on the selected current-head
   request.

The first basis is preferred when it exists because repositories commonly
aggregate the review into a merge-oriented check. Association must be derived
from current-head check/run metadata or an explicitly documented repository
contract; never guess a workflow or check name. A generic successful check,
an App start marker, or a status from another head does not qualify.

Preference does not silently enlarge what the check proves. Unless its
documented contract explicitly binds the PR base, the related merge/status
check remains head-associated GitHub-lane evidence and the local readiness
plane still owns base assurance.

No positive basis bypasses the complete unresolved-finding scan.

## Terminal Results

A terminal provider artifact is a provider-authored issue comment or review
whose known carrier unambiguously reports either findings or no findings. Bind
it to the current head through either:

- an exact full `commit_id` exposed by the carrier (resolve a known short ID
  through the exact repository API and require a unique current-head match);
  or
- a stable current-head request epoch when an issue-comment carrier exposes no
  commit field: select the unique latest exact `@codex review` request, prove
  the same head immediately before and after that request and at artifact/final
  reread, require the artifact's server time to follow the request, and require
  no newer request in the complete snapshot.

The second basis associates public evidence with a stable head epoch; it does
not claim visibility into the provider's internal input selection. Record
`head_binding: explicit-commit | stable-request-epoch`.

A terminal clean artifact passes only when all of these hold:

- its actor has the exact provider identity;
- its accepted head binding resolves to the exact current head;
- its grammar is a known clean carrier rather than generic praise or review
  state alone;
- every associated inline-comment page and relevant thread page is complete;
- there is no unresolved applicable GitHub Codex finding; and
- scope, lifecycle, raw pages, and selected evidence remain stable on the
  final reread.

An `APPROVED` review is not clean when an associated provider inline comment
contains a finding. A clean body never overrides an unresolved thread finding.

A terminal finding blocks immediately once exact identity, scope, and carrier
are trustworthy. Missing positive evidence cannot neutralize a finding.

## Finding Precedence And Resolution

Classify provider findings independently of human conversation state.

- For an inline finding, only the raw GraphQL thread node's typed `isResolved`
  value resolves that thread. `isOutdated`, a human reply, or a synthesized
  REST field is not resolution.
- Join an inline REST comment to exactly one GraphQL thread comment by stable
  IDs and its parent review. An orphan, duplicate join, parent mismatch, or
  incomplete nested page is inconclusive.
- A top-level provider finding remains active until a later trustworthy
  provider clean artifact on the same or a locally proved descendant head
  supersedes it.
- A later clean never supersedes an unresolved provider thread finding.
- A finding from a non-ancestor old head is audit context, not an applicable
  current-range finding. An inability to prove ancestry is inconclusive.

When terminal candidates share the latest semantic server time, findings win
over clean within the same GitHub channel. Conflicting latest candidates from
different channels, a latest malformed candidate, or a contradictory commit
binding is inconclusive. Use `submitted_at` for reviews and the body-effective
server time for issue comments (`updated_at` when edited, otherwise
`created_at`). Do not compare IDs across GitHub resource types.

## Reaction-Only Fallback

Reaction fallback is intentionally small. It requires no historical sampling,
provider declaration digest, or receipt sidecar.

Accept it only when every condition holds:

1. The parent selected the unique latest visible exact `@codex review` request
   for the current head epoch.
2. The PR head was read immediately before and after the request and has the
   same value when the reaction and final snapshot are read.
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

If the POST outcome was ambiguous, the producer may repeat the same exact
request after backoff. Such repeats are semantically idempotent producer
recovery, not additional review lanes. Keep a single in-flight recovery owner,
prefer the latest visible request for fallback, and report duplicates as an
audit warning. Never let duplicate request count erase trustworthy terminal
provider evidence.

## Service And Pending Evidence

An exact-App current-head check/run can prove that the service started. A
successful App check is not by itself a clean review because it may represent
startup or aggregation and can coexist with findings.

Absent evidence, transport failure, a timeout, a cancelled or skipped run,
free-form provider failure prose, or unknown identity is not a pass. Keep a
retryable state `pending`; after a non-retryable contradiction or malformed
stable snapshot, report `inconclusive`. Recovery policy is defined in
[github-pr-probes.md](github-pr-probes.md).

## Decision Table

| Complete current-head state | Lane result |
| --- | --- |
| Trusted associated merge/status check is clean and no provider finding is unresolved | `pass` |
| Trusted terminal clean artifact and no provider finding is unresolved | `pass` |
| Valid reaction fallback and no provider finding is unresolved | `pass` |
| Any applicable unresolved provider finding | `findings` |
| Work is running or failure is retryable | `pending` |
| Pagination, identity, grammar, scope, ordering, or final stability cannot be proved | `inconclusive` |
| No selected supported PR | `not-applicable` |

Only the first three rows complete the GitHub lane. Other PR conversations and
required checks can still block overall PR readiness.

## Required Report

Record compact, reproducible evidence:

```yaml
github_codex_lane:
  status: pass | findings | pending | inconclusive | not-applicable
  repository: owner/name
  pull_request: 123
  head_sha: 40-lowercase-hex
  scope_assurance: latest-head-only
  base_assurance: local-pr-readiness
  basis: merge-status | terminal-clean | reaction-clean | null
  evidence:
    id: stable-github-id-or-null
    url: https://github.com/...-or-null
    server_time: RFC3339-or-null
    head_binding: explicit-commit | stable-request-epoch | current-head-status | null
    request_id: stable-github-id-or-null
  request_policy:
    status: compliant | warning | unknown | not-applicable
    warnings: []
  unresolved_provider_findings: []
  last_reason: stable-machine-readable-reason
```

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
