# Review Egress Consent

This reference defines destination and data-scope consent for named review. It does not define reviewer eligibility, provider evidence, retry state, or readiness; load [review-lane-contracts.md](review-lane-contracts.md) for lane I/O and [github-codex-evidence-authority.md](github-codex-evidence-authority.md) for GitHub evidence.

## Named Shape Consent

An unambiguous request for single, double, or triple review is contemporaneous consent for scoped code-review egress to exactly that shape:

- single authorizes OpenAI Codex;
- double additionally authorizes Anthropic Claude Code;
- triple additionally authorizes GitHub Codex on an eligible exact-host `github.com` PR.

The selected reviewer is a trusted processor for the named repository and frozen range. It may receive original tracked diff content, necessary tracked context, bounded tool-derived evidence, the review prompt, and its own result, including tracked repository secrets. Do not redact or rewrite tracked reviewer input because a separate secret-delta gate reports a finding.

Consent authorizes no mutation except the bare-triple request-comment flow described below. It does not authorize GitHub Copilot or another substitute reviewer, untracked files, unrelated repositories, broad workspace or home-directory content, discovery of authentication credentials, branch creation, commits, push, PR creation, PR metadata mutation, an anchor commit, fixes, delivery, or merge. Approval-gated Claude invocation must restate the exact repository and `base_sha..head_sha`.

## Destination Boundaries

- The Codex reviewer receives an independent clean read-only workspace and frozen refs, not a parent-injected full diff.
- The named-direct Claude lane receives another independent clean read-only workspace and uses its separately validated runtime and ordinary local login.
- The GitHub lane may send the scoped request and consume same-PR provider evidence only on exact `github.com`. Unsupported hosts or identities do not inherit that destination consent.
- The low-level `isolated_review` helper is a separate supplied-diff/private-Git processor contract and never counts as a named lane.

## GitHub Serial Attempts

Bare-triple consent authorizes only an eligible existing PR's scoped `@codex review` request comment and the serial attempts that the canonical epoch machine permits. All attempts remain one logical GitHub lane. Consent never authorizes overlapping requests, an untracked repair request, a blind retransmission after ambiguous transport, or a synthetic commit. Request/marker records remain orchestration and audit data; provider evidence authority comes only from the canonical [GitHub Codex provider-evidence contract](github-codex-evidence-authority.md).

## Independent Admission Controls

Secret-delta scanning is an independent PR/master admission control. It neither starts a reviewer nor changes the named-review egress scope. A clean scan admits delivery; a violation or inconclusive scan blocks admission according to the playbook without retroactively revoking already authorized scoped reviewer inspection.
