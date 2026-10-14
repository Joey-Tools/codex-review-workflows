---
id: 20261005-mrr001
title: Model Defaults and Remote-First PR Review
status: active
created: 2026-10-05
updated: 2026-10-05
branch: codex/review-model-routing-policy-20261005
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/127
supersedes: []
superseded_by:
---

# Model Defaults and Remote-First PR Review

## Decisions and Reasons

- Use GPT-6.1 Sol for the parent agent. GPT-6 Luna, up to Max, is authorized for token-intensive work and local review; the user explicitly extended the worker authorization to reviewers.
- An explicitly requested local reviewer defaults to GPT-6.1 Sol at the model's default reasoning level, not the parent's Extra High. Pin the currently documented default, `medium`, in the reviewer role so inherited configuration cannot silently elevate it.
- Other reviewer models or reasoning overrides require explicit user opt-in. A stronger parent is not permission to discover, upgrade, or substitute the reviewer.
- PR-bound delivery defaults to remote-only review when the target provides GitHub Codex `@codex review` or native GitHub Copilot code review. Avoid duplicate paid local review; local-only delivery retains a local Codex gate. Unknown or unavailable PR-bound capability instead enters the user's session-choice gate, never an unrequested automatic local review.
- Prefer the target's configured remote provider; do not add both providers merely because both exist. Pending remote evidence never becomes a local-only pass. Explicitly requested local/named lanes remain mandatory.
- Claude Code requires explicit opt-in, including an unambiguous named double/triple request. Its authorized default model is Opus 5.5; do not add Claude to a generic workflow or enable automatic fallback to another provider.
- Native GitHub Copilot code review is not Copilot CLI and does not satisfy the named Claude lane. Its terminal review is head-bound; completed review and resolved findings do not replace human approval, CI, or merge-policy requirements.
- Preserve complete merge-inclusive frozen ranges, exact-head review evidence, user authority boundaries, and signed base-refresh merge commits. This policy work is separate from installer recovery and other threads' GitHub Actions/status-check/ruleset implementation.
- Keep routing and native Copilot completion in the existing `review-lane-contracts.md` reference. A new reference file would require a separate closed-inventory migration in the private overlay; reusing the existing reference preserves that inventory without broadening source admission.
- Remote capability uses trusted repository enablement or real provider review results from recently active same-repository PRs, including reviews with findings. There is no fixed historical age cutoff; bounded acquisition must check for newer applicable negative evidence, record its inspected scope, and never claim exhaustive history. Requests and eyes reactions alone are not positive support evidence.
- Disabled/unsupported/no-entitlement and hard quota exhaustion are capability negatives, scoped to the stated repository/provider/identity and reset time. Another actor's personal quota is not a negative for the current actor. Ordinary rate limits, timeout, degraded service, pending, findings, and CI failure remain separate execution/readiness facts.
- Share capability observations within this session without a persistent cache. Recheck identity, relevant configuration, eligibility, contradictions, and quota expiry, not every new head. Each new head still invalidates its review results.
- Ask once when support is unknown/unavailable: local fallback for both states, mandatory local plus the available selected remote, or remote-only wait/retry. The human's exact choice applies through the session until changed, including delegated work. It never expands mutation/egress authority or waives required remote checks and unresolved findings.

## Ownership

- Canonical review repository: review routing, local profile, optional Claude default, reviewer role, focused contract tests, and delivery handoff.
- Private overlay: short global parent/delegation defaults and routing/consent locators; canonical review resources are promoted by the source-sync workflow, not independently rewritten.
- Workspace wrapper: remove the repository exception that mandates local plus GitHub review.
- Historical journals and compatibility fixtures retain their historical meaning unless they directly assert an active default.

## Execution Checklist

- [x] Confirm user choices and inspect active canonical and installed policy.
- [x] Prepare independent canonical/private worktrees; preserve unrelated workspace.toml edits.
- [x] Update active policy, role, launch defaults, and narrowly affected tests.
- [x] Run focused offline validation and record actual results.
- [x] Prepare the separate canonical policy slice with focused validation.
- [x] Confirm the availability and session-choice design with the user.
- [x] Validate the availability guidance and update the existing PR.
- [ ] Promote merged canonical sources through private source sync/release.
- [ ] Verify installation on reachable target hosts; report unavailable hosts and outstanding promotion dependencies explicitly.

## Local Validation Evidence

- Availability/session-policy follow-up: `test_contracts.py` completed 42 tests with one private-layout-only skip. Both affected skills passed metadata validation, and project journal validation and `git diff --check` passed.
- A fresh-context GPT-6 Luna Max worker exercised ten offline routing scenarios. One initially ambiguous fixture conflated historical PR requests with current-task consent; explicit source attribution in the fixture and policy resolved that ambiguity on retest. The final predictions preserved session reuse, actor-scoped quota negatives, reset rechecks, remote-required gates, and new-head review invalidation. These instruction exercises are not live provider reviews or current-head pass receipts.
- `test_contracts.py`: 41 tests completed, with one private-layout-only skip in the public repository. The new regression preserves the Sol default while accepting explicitly reviewer-inclusive Luna authorization up to Max.
- Runtime/model/stream checks: 135 focused offline tests passed, including all 117 Claude stream validator tests. Opus 5.5 requires matching init, message, and terminal model evidence; older 4.8/4.7 identities remain valid only for historical stream validation, not the default new-launch chain.
- Canonical skill metadata validation, project journal validation, and `git diff --check` passed. Offline checks used fixtures and mocks, not real Codex/Claude backend review; they do not establish release or installer success.
- The workflow-hygiene attribution workstream passed 75 tests and preserves historical model labels. The private overlay passed 19 affected migration tests and a parent rerun of eight global-guidance/sync/attribution tests; its canonical-source promotion remains pending.
- Expanded local Codex contract module: all 14 tests passed. The full provider module completed 950 tests in 427.214 seconds but returned `FAILED (failures=1, errors=4, skipped=3)`: a runner-level `ulimit -f 8192` incorrectly limited four large fixtures, and the outer macOS sandbox rejected one native broker probe. This failed run is not recorded as a green module or full-suite gate.
- Removing the runner's file-size limit exposed one stale Codex mock profile in the bound-stdout test. It now uses the active model/effort constants while preserving the large payload, path-replacement attack, real finding, and assertions. All four affected fixture tests passed on final narrow rerun; the parent separately passed the exact native broker test outside the nested sandbox using only temporary paths and synthetic in-memory credentials.
- The 950-test module was not rerun in full after that fixture-only repair. A redundant second attempt was stopped after approximately 30 seconds. Offline logs remain at `/private/tmp/review-model-tests.CbMyhb`; the interrupted second attempt overwrote the first full log, so its retained prefix is not evidence of a completed run. The first run's failure summary and tracebacks remain in the task record.
- These results are not a claim that the full repository suite, live provider review, release, or delivery gate has passed.

## Sources

- User decisions in Desktop task `01a029a7-1fac-7f50-8d62-16206c099cd9`, 2026-10-05.
- [OpenAI GPT-6.1 Sol model](https://developers.openai.com/api/docs/models/gpt-6.1-sol): supported reasoning levels and current default `medium`.
- [Anthropic Opus 5.5](https://platform.claude.com/docs/en/models/opus-5-5/overview): exact model ID `claude-opus-5-5` and current default effort `medium`.
- [GitHub native Copilot code review](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-code-review): native review requests, completion, re-review, and separate approval requirements.
- [GitHub list pull requests](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests) and [GitHub CLI API](https://cli.github.com/manual/gh_api): update-time candidate ordering and explicit GET query syntax for read-only discovery. The example is not a byte/time enforcement wrapper.
