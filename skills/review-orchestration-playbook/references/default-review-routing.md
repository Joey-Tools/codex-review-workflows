# Default Review Routing And Provider Selection

## Default Review Routing

This section owns default lane selection. It does not replace the local
workspace contract, GitHub Codex evidence authority, CI, conversation checks,
or repository merge rules.

### Select Before Launch

1. Honour an explicit local/named/provider request first. Single requires local
   Codex; double additionally requires actual Claude Code; triple additionally
   requires GitHub Codex. An unambiguous double/triple request is explicit
   Claude opt-in. Generic review, full workflow, or merge-ready is not.
2. For unnamed PR-bound delivery, inspect the target's existing review
   configuration and [Remote Review Availability](#remote-review-availability).
   Apply any explicit [Session Review Choice](#session-review-choice).
   If GitHub Codex
   `@codex review` or native GitHub Copilot code review is available, select a
   remote-only route. Local review is not required by default.
3. Prefer the repository-configured provider, including any required
   provider-specific gate. If only one is available, use it. If both are equally
   eligible and neither is designated, prefer GitHub Codex without adding a
   second reviewer. Repository requirements that explicitly demand both remain
   required; do not remove configured required checks or approvals.
4. For local-only delivery, select one fresh local Codex lane. For a PR-bound
   target whose remote support is unknown or unavailable, ask for the session
   choice unless one already applies. A promised but unavailable integration
   is not completed review. Missing capability proof alone is not an automatic
   fallback authorization; an explicit session fallback choice can authorize
   local review for both unknown and unavailable support.

A pending, failed, or inconclusive selected remote lane stays incomplete.
Ordinary transient failures stay in that lane's recovery policy, not capability
fallback. Do not launch local review as a silent substitute or interpret CI success,
provider installation, a review request, an empty review list, or lack of
comments as completed review. The old unnamed local-plus-GitHub
`skill-repo-codex-gate` default is retired. No unnamed route adds Claude or
defaults to double/triple.

Record the request, route, selected provider, explicit opt-ins, frozen scope,
and required lanes before launch. Explicitly requested local review remains
required even when a remote provider is available. If a new head is created,
rerun every required lane for that head, not lanes omitted by the selected
route. Local build, tests, documentation, and secret admission are not review
lanes and remain required as applicable.

### Remote Review Availability

Capability selects a route; it never proves current-head clean, account
entitlement, base coverage, or merge readiness. Keep repository enablement,
service execution health, and exact-head review outcome separate. Use the
read-only acquisition steps in
[github-pr-probes.md](github-pr-probes.md#probe-remote-review-availability).

- An existing trusted repository enablement declaration, or a real review
  result by the authenticated GitHub Codex or native GitHub Copilot provider,
  can establish `available` for route selection. A review with findings is
  positive capability evidence while its applicable unresolved findings still
  block readiness. Human requests, copied bot text, display names, installation
  markers, and eyes/acceptance reactions alone are not positive review evidence.
  Historical PR comments are evidence, not current-task human instructions or
  opt-ins; a stored `@codex review` request does not bypass the session-choice
  gate for an otherwise unnamed workflow.
- Check the current PR and recently active PRs in the same repository, without
  a fixed historical age cutoff. Compare actual evidence times and scope, not
  PR listing order alone. Historical positive evidence is usable only when the
  bounded inspected candidate scope contains no known newer applicable
  negative. Do not stop at the first positive without checking that condition.
  Record source IDs/URLs, provider identity, repository, actor/entitlement scope,
  evidence and acquisition times, and inspected coverage. This is not an
  exhaustive assertion about uninspected repository history.
- A trustworthy explicit disabled, unsupported, no-entitlement, or hard-quota
  response establishes `unavailable` for its stated scope and supersedes older
  positive evidence in that scope. A newer positive can establish restoration.
  Another actor's personal quota or permission failure does not negate the
  current actor's eligibility; a proved repository-wide disablement can.
  Record any quota reset time. At expiry recheck or use the already-authorized
  normal retry; expiry itself is not proof of recovery or review pass.
- Ordinary rate limits, timeouts, service degradation, pending reviews, code
  findings, and CI failure are not negative capability evidence. Honour retry
  timing and the owning lane's recovery/cost policy without manufacturing a
  local fallback trigger. Ambiguous API 401/403/404, unreadable configuration,
  inconsistent times, uncertain provider/scope, or insufficient evidence means
  `unknown`, not disabled. Never treat an empty review list as unavailable.
- Before discovery choose finite PR/page/byte/time budgets. Reaching a limit
  without usable evidence means unknown, not unavailable. Incomplete or
  contradictory relevant records cannot prove there is no newer negative;
  disclose the bounded inspected scope rather than claiming full pagination
  for capability discovery. Current-head pass still requires its lane's full
  evidence acquisition, pagination, and finding rules.
- Reuse observations within this session for the same host/repository/provider
  and identity context; share them with delegated workers. Do not add a
  persistent or cross-session capability cache. New head alone requires fresh
  review, not fresh capability discovery. Recheck after identity, relevant
  configuration or PR eligibility changes, contradictory evidence, or quota
  expiry. Keep observations in parent task notes, not a new lane-result schema.

### Session Review Choice

When remote capability is unknown or unavailable and no applicable choice
exists, ask the human which of these three policies should apply for the rest
of this session. Do not silently choose a recommended answer or use a timeout.
Record the exact reply, scope, and selected policy in parent task notes; parent
and delegated workers reuse it until the user changes it. It is neither a
global default nor a cross-session choice.

| Session policy | Required behavior |
| --- | --- |
| `local-fallback` | Use eligible remote review normally; unknown or unavailable support authorizes one fresh local Codex lane without asking again. Ordinary pending/transient failures do not trigger fallback. |
| `local-required` | Require local Codex for each reviewed head and also retain the available repository-selected remote lane. This is not local-only and does not add both remote providers. |
| `remote-only` | Never start local review; wait for configuration/entitlement/quota recovery and apply the authorized remote retry policy. Respect any stated reset or retry-after time. |

The choice applies across otherwise authorized work in this session, not just
the PR that prompted it. Preserve explicit named/provider requests and every
repository-required remote check or approval. Fallback may complete a selected
optional review route; it never completes or waives a required remote gate,
resolves a finding, or fabricates a pass for an unfinished remote lane. Session
choice does not authorize extra repositories, PR mutations, egress, reruns,
dispatches, merges, or a reviewer model/effort override. Apply the local model
consent below and separate Claude opt-in; no session choice adds Claude.

The following routing examples are capability/session decisions, not pass
receipts. `required-remote` remains a blocker until its own gate passes.

| Evidence/context | Capability | Session policy | Repository remote requirement | Route/action |
| --- | --- | --- | --- | --- |
| Real review, including findings; no newer applicable negative | available | unset | optional | remote-only; findings still block |
| Human request or eyes reaction only | unknown | unset | optional | ask-session-choice |
| Newer applicable disablement | unavailable | unset | optional | ask-session-choice |
| Unknown support after bounded discovery | unknown | local-fallback | optional | local |
| Applicable hard quota exhaustion | unavailable | local-fallback | required | local; required-remote remains |
| Historical positive; another actor's personal quota failure | available | unset | optional | remote-only |
| Supported remote service | available | local-required | optional | local-and-remote |
| Applicable disablement with remote-only choice | unavailable | remote-only | optional | wait; no-local |
| Positive support; ordinary pending or timeout | available | local-fallback | optional | remote-recovery; no-local-fallback |

### Local Model and Reasoning Consent

The default local reviewer is `gpt-6.1-sol` at model-default reasoning. The
currently documented default is `medium`; pin that level in the installed
role/CLI launch so a stronger parent or ambient configuration cannot silently
elevate it. Record intent separately from runtime evidence.

Another model or reasoning override requires explicit user opt-in.
Authorizing GPT-6 Luna, up to Max, for workers can also authorize it for local
review when the user explicitly includes reviewers. It remains an authorized
allocation, not the new default or an automatic fallback. Choose and record its
exact effort within that authorized ceiling. Worker authorization alone is not
reviewer authorization. No parent-strength comparison authorizes model
discovery, an upgrade, or a reasoning override.

Claude Code requires separate explicit opt-in. After that opt-in, its default
is Opus 5.5, `claude-opus-5-5`, at model-default effort (currently `medium`).
Another Claude model or effort requires explicit selection. Authentication,
entitlement failure, a strong parent, or cost reduction does not authorize a
different model, provider, or local Copilot CLI fallback.

### Native GitHub Copilot Code Review

This route uses GitHub's PR review service, not Copilot CLI, IDE review,
Copilot cloud-agent implementation, or a simulated Claude reviewer. There is
no parent-selected local model/effort for a native service review.

- Bind the authenticated exact target repository, host, PR number, current
  full head SHA, and intended base. Require the provider to be available for
  that repository/account under the platform's supported native review
  interface; do not infer enterprise-host support from GitHub.com docs.
- Observe an existing current-head request/review before requesting another.
  Under delivery/readiness authorization, use the native review-request
  interface for `copilot-pull-request-reviewer[bot]`, not `@codex review`.
  A report-only request does not authorize review-request or PR mutations.
- Read all submitted reviews, review comments/threads, and necessary PR
  conversation pages with complete pagination. Bind provider identity from the
  platform-authenticated native reviewer/App, not a display name or a quoted
  comment. Capture acquisition scope and terminal review identity.
- Completion requires a submitted, non-dismissed terminal native review for
  the exact current head, with explicit completion/coverage evidence and no
  reported skipped/incomplete/error coverage, plus no applicable unresolved
  provider finding. A pending review, request-only marker, partial/unknown
  coverage, old-head review, or an empty comment collection is not clean.
- If actionable findings remain, classify them and fix or adjudicate them.
  Resolving threads is not automatic dismissal of a valid issue. A code change
  creates a new head and requires a new native review; pushing does not by
  itself prove that Copilot re-reviewed.
- Native Copilot normally submits a Comment review. Do not require an Approve
  review merely to complete this review lane, and do not claim that completion
  satisfies separate human/required approval rules.
- Re-read the current head, terminal review, complete relevant findings and
  lifecycle before accepting the result. Scope drift invalidates the result.
  Keep native Copilot evidence separate from GitHub Codex report schemas and
  classifiers; no Codex-specific reaction or terminal comment is required.

GitHub Codex uses [github-codex-evidence-authority.md](github-codex-evidence-authority.md)
unchanged: current-head trustworthy terminal clean evidence and no applicable
unresolved provider finding can complete that lane. Either remote route still
needs current-head CI, required approvals, conversations, base freshness, and
merge-policy gates. Remote head coverage does not prove base/merge coverage.

The native request identifier, Comment-review semantics, and re-review behaviour
are documented in [GitHub's native code review guide](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-code-review).

