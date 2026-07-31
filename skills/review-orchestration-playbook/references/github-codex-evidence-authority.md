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

Only the provider-result authority is inherited: trustworthy provider results
decide the outcome, while requests and run markers remain producer/audit
evidence. The playbook's raw REST/GraphQL review-thread proof, exact whole-PR
scope and lifecycle gates, closed terminal issue-comment carrier and edit-time
rules, and conditional `+1` fallback are local extensions. They must not be
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
same-time channel evidence, stale scope, or unstable final re-read still blocks.
An unresolved thread finding is not superseded by a later clean artifact.

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
3. Admit only exact provider identity. Terminal comment/review evidence
   requires REST `user.login == "chatgpt-codex-connector[bot]"` and
   `user.type == "Bot"`. A lookalike, missing field, or differently cased
   identity is inconclusive.
4. Parse terminal-looking issue comments and reviews only with the fixed
   grammar below and an exact commit binding. No other clean or finding syntax
   is active at this baseline. A terminal-looking malformed artifact is
   evidence conflict, not ignorable prose.
5. Before ordinary artifact ordering, fail closed on any exact-provider
   terminal-signal review whose state is `DISMISSED`, missing, or unknown. It is
   a whole-snapshot inconclusive blocker because no trusted transition time is
   available; its original `submitted_at` cannot make it older than, or
   superseded by, another artifact.
6. Order trustworthy terminal artifacts by trusted semantic server time. For
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
7. Select the latest trustworthy terminal artifact. A newer or equal-time
   malformed or scope-conflicting terminal-looking artifact blocks an older
   clean result.
   A newer finding blocks an older clean result. A latest explicit clean
   artifact may yield `clean` only after the finding and final-stability gates
   below.
8. If no trustworthy current-scope terminal payload exists, apply the selected
   provider profile. Only `thumbs-up-clean` can reach the weak `+1` fallback;
   `mixed` still requires terminal payload for a clean result. A later `+1` or
   `eyes` reaction remains audit and liveness evidence; it does not demote,
   replace, or reorder an already selected terminal payload. The newer-`eyes`
   exclusion applies only while evaluating the reaction-only fallback.
9. Perform the final re-read. The result counts only if scope, lifecycle,
   request history, profile inputs, provider evidence, and target-thread state
   are unchanged. Reaction clean also requires a new independent raw final
   current endpoint inventory plus repeated parent-owned local Git ancestry
   receipts for every raw-derived finding commit; normalized snapshot equality
   alone is insufficient.

An exact-App check or check run is service-start evidence only. It is not a
terminal provider artifact and never proves clean, even when its conclusion is
`success`.

### Fixed Terminal-Payload Grammar

The accepted grammar is deliberately narrower than arbitrary provider prose.
Treat an API body as a well-formed Unicode scalar-value sequence, then normalize
it in this exact order:

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
closed branches below.

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
and do not let a later-looking clean supersede them.

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
   clean. An `APPROVED` / `No findings.` review with zero children is the only
   clean review shape in this branch. Fully fetched human or unrelated-bot
   comments, null-parent replies,
   and threads containing no target child remain audit context. They neither
   create a selected-review finding nor supply resolution for one. Empty
   bodies, `Looks good.`, coverage summaries, alternative punctuation,
   additional prose, links, HTML, comments, and code fences are malformed
   under this stricter playbook grammar.
3. **Top-level finding.** Require a normalized body with the exact first line
   `### 💡 Codex Review` followed by one or more nonempty LF-delimited finding
   lines and no other lines. Each finding line has this exact grammar:

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
| `finding-positive` | top-level finding | none | `findings` |
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
cursor, follow each opaque returned `endCursor` exactly, and terminate only at
typed `hasNextPage == false`. The raw audit retains all fetched comments and
threads; target selection happens only after complete pagination.

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

The raw `discovery_endpoint_transcript`, not the candidate array, inventory
entries, or count, is the historical-universe authority. Store it in both the
initial and final inventory, with each inventory produced by its own
independent fetch traversal. Its closed top-level shape is exactly
`{schema_version: 3, repository, scope_discovery, scopes}`.
`scope_discovery` is exactly one `repository_pull_requests` REST fetch record
for an
independently fetched, fully paginated repository-wide
`GET /repos/<owner>/<repo>/pulls?state=all&sort=created&direction=asc&per_page=100`
traversal, starting at that canonical URL and following every raw
`Link rel=next` page. It is not a projection of the per-scope records. Each
scope is exactly `{pull_number, fetches}`, where `pull_number` is a canonical
positive integer and `fetches` is seeded from one raw repository-list record.
Each fetch is exactly
`{kind, transport, parent_comment_id, pages}`. The only fetch kinds are
`pull_requests`, `compare`, `issue_comments`, `reviews`, `inline_comments`,
`review_threads`, and `request_reactions`.

Every canonical pull number returned anywhere in the repository-wide list must
seed exactly one complete PR-detail traversal, including the exact current PR
and PRs that later prove to be outside the 30-day window, contain only
confirmed non-provider activity, or otherwise normalize as non-candidates.
There may be no unseeded list record, duplicate scope, caller-injected scope,
or scope silently removed before detail parsing. The scope's `pull_requests`
fetch is the canonical detail GET for that exact number. The fixed parser takes
`base.sha` and `head.sha` from that raw detail record, binds those exact values
into the canonical compare request, and takes `pr_merge_base` only from
`compare.merge_base_commit.sha`; neither `base.sha` nor
`merge_commit_sha` substitutes for the merge base.

A schema-version-3 `review_threads` response stores the real GraphQL
`comments { nodes pageInfo }` connection inside each raw thread node; it never
stores the report's normalized `comments.pagination_complete/pages` shape in
the response body. Version 3 accepts that nested connection only when its
first response is already complete (`hasNextPage == false` and
`endCursor == null`). A nested `hasNextPage == true` requires a separately
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
noncanonical or invalid dates are rejected. A GraphQL page records exact request URL
`https://api.github.com/graphql`, integer status, `link_header: null`, the
exact requested `request_after` cursor or null, and the same bounded raw
body/digest; the fixed parser reads raw `pageInfo.hasNextPage` and
`pageInfo.endCursor` from that body. REST traversal follows raw
`Link rel=next` until none remains.
GraphQL traversal starts at null, requires each next `request_after` to equal
the prior raw `endCursor`, and terminates only at typed
`hasNextPage == false`.

The transcript envelope is closed, but endpoint JSON objects are forward
compatible: the versioned fixed projector reads and type-checks every field
used by policy while ignoring unrelated GitHub response additions. The raw page
digest still binds all response bytes. A versioned fixed parser independently
derives the complete set of candidate scope keys and scope-final bases from the
projected records, then derives `entries` in the closed shape
`{scope_key, source_ordering_key, source_evidence}` and
`candidate_universe_count`. `source_evidence` is exactly
`{carrier, channel, semantic, native_identity, source_record_sha256}`. It binds
reaction versus terminal-artifact carrier, request-reaction versus review or
issue-comment channel, `+1` / `eyes` / clean / findings / malformed semantics,
the native parent-and-ID or channel-and-ID identity, and the digest of the
canonical policy projection. Review projection digests include the review,
associated inline records, and joined thread nodes; issue-comment digests bind
the projected comment; reaction digests bind the parent ID and projected
reaction. Same time and numeric ID alone therefore cannot substitute one
carrier, channel, or semantic result for another.

The closed candidate evaluator independently validates each complete candidate
array element and requires its full authority projection to equal the
raw-derived entry. Initial/final candidate arrays must also be type-preserving
identical. Audit-only normalized fields that do not originate in one endpoint
are not falsely described as raw-derived. These checks never prove the
transcript complete merely by agreeing with one another. In particular,
deleting a candidate, deleting its inventory entry, and decrementing the count
while leaving its raw fetch record present must fail closed. Missing required
child fetches, an unreadable page, a repository-list or detail traversal that
exceeds any predeclared page/count/byte/time evidence budget, a broken
Link/cursor chain, a body-digest mismatch, initial/final semantic drift, or any
projection mismatch selects `unknown`; no completeness flag can override it.
Never truncate the repository-wide seed, skip a seeded PR, or keep an older
in-budget subset after overflow. A version-2 transcript has no independent
repository-wide seed and therefore cannot prove `thumbs-up-clean`, even when
its derived candidates, entries, and counts are internally consistent.

The parent GitHub fetch path that captured each response is a trusted workflow
boundary. The stored offline transcript and hashes preserve the bytes supplied
to the decision, but do not themselves provide a cryptographic proof of GitHub
TLS origin. Do not describe the record as a TLS attestation.

A candidate basis at the lower boundary is outside the window; one at the upper
boundary is inside. Every trusted server time in every historical/current raw
record must be no later than `as_of_server_time`, including controlled-request
times and confirmed-different-actor reactions that are excluded from provider
semantic ordering. Any later artifact is impossible in the frozen observation
and makes the profile `unknown`.

Raw discovery includes the exact current scope and every confirmed
non-candidate PR. The fixed parser first completes and validates every seeded
detail traversal, derives the full classified scope inventory, and only then
excludes the exact current scope from the historical candidate set. The
current outcome is validated separately and never counts toward the
three-outcome history minimum. A historical scope is a candidate when it
contains a terminal-looking provider record, an exact-bot reaction on a
controlled request, or a provider-like record whose identity is missing or
ambiguous. Historical candidates exclude the exact current scope. A scope
containing only confirmed different actors is not provider behaviour and
becomes a confirmed non-candidate only after full parsing; its raw scope and
bounded records remain in discovery audit evidence. They cannot cause ordinary
human comments, reviews, inline threads, or reactions to masquerade as provider
behaviour. A confirmed different actor is not provider behaviour. A provider
terminal artifact may form a
candidate even when no controlled request was observed. Reaction-only evidence
still requires the exact controlled parent and can never arise without a
request.
Complete pagination and scope inventory must prove that universe and its
recorded count by derivation from the raw transcript. The initial and final
enumerations must be semantically identical for the same frozen interval.
Opaque GraphQL cursor bytes need only form a valid chain within each traversal;
stable node content and derived universe, rather than cursor-byte equality,
establish final equivalence. The current outcome's selected basis must not be
later than the same `as_of_server_time`; its complete raw evidence snapshot is
subject to that bound as well.

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
request's ID, URL, `created_at`, `updated_at`, normalized body, and scope. Use
`created_at` as its request semantic time only when
`updated_at == created_at`; otherwise use `updated_at`, because that is when
the currently observed exact request body became authoritative. Record the
selected value and
`request_server_time_field: created_at | updated_at`. Record every reaction's
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
`@codex review`, or a reaction without that direct parent makes the selected
candidate unclassifiable and the profile `unknown`, even when the reaction
actor is the exact bot.

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
immediately before acceptance. Each inventory uses the closed shape
`{repository, pull_number, head, fetches}`. Its `fetches` use the same closed
fetch/page records, pagination rules, raw bodies, and digests as discovery
schema version 3 and cover the current pull detail, compare, issue comments,
reviews, associated inline comments, raw GraphQL review threads/comments, and
every controlled-request reaction endpoint. The two inventories are
independent API traversals, not aliases, copies of one body, normalized
snapshots, or projections supplied by the caller. Each must independently
derive the same complete provider-artifact, request/reaction, target-thread,
and finding-commit sets. Missing pages, over-budget traversal, projection
drift, or initial/final semantic drift selects `unknown`.

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

A missing receipt, missing local object, duplicate or extra receipt, a return
code other than the exact values above, a raw-derived commit-set mismatch, or
any initial/final inventory or receipt drift makes the current provider
classification `unknown`. The initial and final receipt arrays must be
type-preserving identical and must each cover exactly the full commit set
derived from its corresponding raw inventory.

For terminal completion, the complete raw projection must equal the normalized
current record before terminal precedence is applied. A raw-only artifact or
thread that the normalized record omits makes the profile `unknown`. An
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

### +1 Fallback

+1 fallback requires all of the following:

1. `provider_profile is thumbs-up-clean`; `mixed` cannot use this fallback.
2. The parent directly fetched, authenticated, and twice matched the active
   exact-provider GitHub declaration artifact above. Generic issuer/source
   labels, copied prose, and self-hashed paraphrases do not satisfy it.
3. The complete bounded 30-day same-repository historical candidate universe,
   derived from a schema-version-3 repository-wide seed, excludes the exact
   current scope only after every seeded PR—including current and confirmed
   non-candidates—was fully traversed and parsed. It selects 3 to 10 outcomes
   and every selected candidate is eligible under the profile rule above. No
   incomplete, conflicting, ambiguous, over-budget, or unfavourable candidate
   was skipped. A version-2 transcript cannot satisfy this condition. Every
   selected history entry records its immutable scope, exact selected
   controlled request, exact child `+1` reaction, every accepted same-scope
   request/reaction audit, the scope-final `candidate_basis`, and strict
   request-semantic-time-before-reaction ordering. The trusted GitHub
   `as_of_server_time`, exact half-open interval, complete classified seed
   inventory/count, and every pre-sort candidate basis also satisfy the window
   contract above.
4. The parent recorded the exact accepted request comment for the exact
   current whole-PR scope, including `created_at`, `updated_at`, normalized body,
   selected semantic server time, and its field name, before consuming any
   reaction.
5. The reaction has exact provider identity.
6. The `+1` was created strictly after the request's semantic server time,
   using `created_at` only for an unedited request and `updated_at` otherwise.
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
    complete repository-wide seed and every seeded PR classification, every
    candidate before sorting, every ordered historical request/reaction sample,
    the exact current request and reaction, the independently fetched raw
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

```yaml
request_policy:
  status: warning
  warnings:
    - duplicate-observed
provider_profile: mixed
evidence_basis:
  kind: pull-request-review
  selection_snapshots:
    initial: <complete lifecycle/scope/pagination/candidate/thread snapshot>
    final: <repeat the complete identical selection snapshot>
  artifact:
    initial_snapshot: <complete selected review record>
    final_snapshot: <repeat the complete identical review record>
    source_channel: reviews
    id: 123456789
    url: https://github.com/OWNER/REPO/pull/123#pullrequestreview-123456789
    user_login: chatgpt-codex-connector[bot]
    user_type: Bot
    state: APPROVED
    body: No findings.
    normalized_body: No findings.
    server_time: 2026-07-30T00:00:00Z
    server_time_field: submitted_at
    commit_id: 0123456789abcdef0123456789abcdef01234567
    associated_inline_comments:
      pagination_complete: true
      records: []
    review_thread_pages: <complete raw GraphQL pages and nested comment pages>
    thread_findings: []
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

| Lane state | `provider_profile` | `evidence_basis` |
| --- | --- | --- |
| Proved pre-provider ineligibility or blocker: no PR, unsupported host/identity, selected PR closed before start, or scope/lifecycle failure before provider evaluation | `null` | `null`; report the exact effective-double or blocker reason separately |
| Eligible and waiting with no selected provider artifact | Computed profile, or `unknown` when it cannot yet be established | `null` |
| Accepted terminal clean or findings result | `terminal-payload` or `mixed` | Selected issue comment or pull-request review plus complete initial/final raw current authority |
| Accepted weak reaction clean | `thumbs-up-clean` | Exact accepted `+1` reaction plus its controlled request and scope; provider declaration identity/digest and every ordered historical request/reaction sample |
| Future accepted authenticated no-start rejection after an explicit grammar policy activates it | Actually recomputed profile, normally `terminal-payload` or `mixed` | Exact `no-start-rejection` issue comment plus its controlled request and scope |
| Inconclusive evidence | Computed profile or `unknown` | Stable blocking artifact when one exists; otherwise `null` |

For a pull-request review, `server_time` is the exact REST `submitted_at` and
`server_time_field` is `submitted_at`. For an unedited issue comment, use exact
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
Git ancestry receipts. The raw projection must type-preservingly equal the
normalized current selection input; a selected-artifact summary or normalized
snapshot without that authority is not auditable evidence.

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
      discovery_endpoint_transcript:
        schema_version: 3
        repository: OWNER/REPO
        scope_discovery:
          kind: repository_pull_requests
          transport: rest
          parent_comment_id: null
          pages:
            - request_url: https://api.github.com/repos/OWNER/REPO/pulls?state=all&sort=created&direction=asc&per_page=100
              status: 200
              link_header: <raw REST Link header or null>
              request_after: null
              body_utf8: <bounded raw repository-wide pull-list JSON response>
              body_sha256: <recomputed lowercase SHA-256>
        scopes:
          - pull_number: <positive PR number seeded by scope_discovery>
            fetches:
              - kind: pull_requests | compare | issue_comments | reviews | inline_comments | review_threads | request_reactions
                transport: rest | graphql
                parent_comment_id: <positive request-comment ID or null>
                pages:
                  - request_url: <exact REST URL or https://api.github.com/graphql>
                    status: 200
                    link_header: <raw REST Link header or null for GraphQL>
                    request_after: <null for REST/first GraphQL page or prior raw endCursor>
                    body_utf8: <bounded raw JSON response body>
                    body_sha256: <recomputed lowercase SHA-256>
      scope_classifications:
        - pull_number: <every seeded PR, including current and confirmed non-candidates>
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
    final_inventory: <repeat the complete identical initial_inventory record>
    initial_candidates:
      - <complete candidate snapshot defined below>
    final_candidates:
      - <repeat every complete initial candidate snapshot in the same order>
  current:
    raw_endpoint_inventories:
      initial:
        repository: OWNER/REPO
        pull_number: 123
        head: <full lowercase SHA>
        fetches:
          - kind: pull_requests | compare | issue_comments | reviews | inline_comments | review_threads | request_reactions
            transport: rest | graphql
            parent_comment_id: <positive request-comment ID or null>
            pages:
              - <same closed raw page shape used by discovery schema version 3>
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
    request:
      id: 123456
      url: <exact issue-comment URL>
      created_at: <server time>
      updated_at: <server time>
      request_server_time: <created_at when unedited, otherwise updated_at>
      request_server_time_field: created_at | updated_at
      normalized_body: "@codex review"
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
      - request: <same seven request fields>
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
      request: <same seven request fields>
      reaction: <same seven reaction fields>
      same_scope_request_audit:
        - request: <same seven request fields>
          reactions:
            - <same seven reaction fields>
```

Every REST request ID, reaction ID, reaction parent ID, and selected
request/reaction ID in this report is an exact positive JSON integer, never a
quoted decimal string, boolean, or float. Canonical positive decimal text is
reserved for GraphQL BigInt-to-REST join comparison and does not change the
REST/report JSON type.

The report embeds both independently fetched schema-version-3 raw historical
discovery endpoint transcripts, including each complete repository-wide pull
seed, every seeded PR traversal, and every current/candidate/non-candidate
classification. It also embeds both raw-derived source-authority inventories
and both independently validated complete candidate arrays, including
candidates outside `samples`; a count, version-2 transcript, or external ledger
reference is insufficient. Each complete candidate snapshot repeats these
fields: `complete`, all six pagination results, the four
`evidence_state` artifact arrays with stable IDs/times, lifecycle, immutable
scope, every controlled request, every individual reaction (including
confirmed-different-actor reactions), selected request/reaction IDs when present,
`same_scope_request_audit`, and `candidate_basis`. The initial and final
inventory records and candidate arrays must be structurally identical.

`current.raw_endpoint_inventories.initial` and `.final` are independent,
complete endpoint traversals and each is the authority for its corresponding
raw finding-commit set. The parent-owned
`current.local_git_ancestry_receipts.initial` and `.final` cover exactly those
sets and accept only local object-check return code `0` plus ancestry return
code `0` or `1`. The two receipt arrays and raw authority projections must be
type-preserving identical. `current.initial_snapshot` and `.final_snapshot`
likewise embed the complete reader-facing field set for the exact current scope
and must be structurally identical, but neither normalized snapshot substitutes
for the raw inventories or ancestry receipts. Every raw
artifact/request/reaction time in both historical and current inventories is
checked against the recorded as-of bound before actor filtering or candidate
selection. This lets a reader distinguish a valid
11-candidate universe from one whose unselected candidate was truncated,
incompletely paginated, changed on final reread, or contained a future
confirmed-human reaction.

`provider_declaration.asserted_text` stores the exact authenticated line, not a
summary. `normalized_sha256` is recomputed with the recorded normalization
algorithm after projecting each canonical REST receipt body. The history
window is derived arithmetically from the initial receipt's canonical `Date`;
its label, URL alone, or arbitrary integer cannot substitute for that receipt.
The final declaration receipt proves a stable re-read but does not move
`as_of_server_time`, replace `as_of_receipt`, or replace `as_of_api_url`. Every candidate
basis must satisfy
`window_start_exclusive < candidate_basis.server_time <=
window_end_inclusive`, and the current basis cannot be later than the same
as-of time.

Each `samples[]` entry independently proves exact parent/child identity and
`reaction.created_at > request.request_server_time`, and its
`same_scope_request_audit` enumerates every accepted request parent plus every
fully paginated reaction for that scope. The selected request must appear in
that audit with the same fields. Each reaction's `parent_request_id` and
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
discovery endpoint transcript, independently rederive the repository-wide
seed coverage, every seeded PR classification, the historical inventory/count,
and every universe candidate before sorting, and revalidate every ordered
`samples[]`. Independently re-fetch the final raw current endpoint inventory,
rederive its complete finding-commit set, repeat every parent-owned local Git
ancestry receipt, and revalidate every `current` field and cross-parent audit.
Missing data, non-`0` object resolution, ancestry return codes outside exact
`0`/`1`, budget overflow, or any initial/final drift selects `unknown`.
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
   whole-PR range. A base-only retarget on the same head remains
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
9. **Repository-wide discovery schema version 3 is a playbook extension.**
   This playbook independently and fully paginates the repository-wide
   state-all PR list, traverses every seeded PR including current and confirmed
   non-candidates, and excludes current only after full parsing. Version 2
   cannot prove the fallback, and evidence-budget overflow selects `unknown`.
   None of these discovery gates is attributed to the fixed Action baseline.

## Non-Goals

- Do not treat checks, status contexts, acknowledgements, progress comments,
  `eyes`, sticky state, deadlines, or request markers as clean results.
- Do not weaken exact bot identity or full pagination to make a profile fit.
- Do not use a version-2 transcript, truncated repository seed, normalized
  current snapshot, or external ancestry ledger as reaction-clean authority.
- Do not carry a profile across repositories or beyond the bounded 30-day
  evidence window.
- Do not create a duplicate request, empty commit, or synthetic provider
  artifact to escape an inconclusive state.
- Do not claim the policy itself proves provider behaviour; every counted
  outcome still requires the complete evidence and final-stability checks
  above.
