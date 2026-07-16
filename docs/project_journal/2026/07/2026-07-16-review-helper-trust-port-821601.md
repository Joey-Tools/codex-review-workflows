---
id: 20260716-821601
title: Review Helper Trust Hardening Port
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: wip/review-helper-trust-port
pr: 53
supersedes: []
superseded_by:
---

# Review Helper Trust Hardening Port

## Summary

This work semantically ports the still-applicable security hardening from
private-overlay PR 82 onto the canonical repository. The final integration
also incorporates canonical `master` through
`4da59bf424f941f61bf36fd1f9871ad09dff8d3a`. It preserves canonical floating
publisher-signed Claude provenance, immutable executable snapshots, macOS and
Linux/WSL2 isolation, the synthetic-token catalog, and the Python 3.10
contract. It does not cherry-pick or restore obsolete private-overlay account
metadata behavior.

## Applicability Matrix

| PR 82 area | Decision | Canonical implementation and evidence |
| --- | --- | --- |
| Recursive strict JSON | Port | One bounded parser rejects recursive duplicate keys, non-standard constants, invalid UTF-8, excessive nesting, non-finite floats, and integer literals longer than 1024 digits before conversion. Claude/Copilot output, Keychain credentials, Linux credentials/settings, signed provenance, and local review state use strict parsing. Focused tests cover every negative form on Python 3.10 and 3.13. |
| Warmup and fallback evidence | Port | Authentication is deterministic only for one supported complete result-error shape with the exact known login message and no conflicting category. Unknown fields or event shapes and malformed usage remain inconclusive or runtime-unverified. Entitlement requires requested-model usage evidence. |
| macOS owner-only reads and ACLs | Port to files canonical reads | Trust exports, caller CA snapshots, and generated trust inputs use descriptor-anchored bounded regular-file reads, reject symlinks, hardlinks, FIFOs, growth, public modes, and ACL entries, allow an allocated empty ACL, and fail closed on unknown ACL errors. |
| Credential/account stability | Port without metadata bridge | The current account is bound once, the Keychain value is read twice and compared, expiry covers one bounded model attempt, and freshness is repeated at the final launch boundary. If freshness expires there, one complete executable, trust/TLS, authentication, broker, and sandbox preflight retry is allowed; a second expiry is inconclusive. Every model attempt repeats the same sequence and preserves earlier completed attempts. Linux/WSL2 credential staging remains unchanged except for shared strict JSON. |
| macOS trust and TLS | Port and bind to signed provenance | Authoritative deny wins, constrained or omitted roots are excluded from the complete merge, and unconditional roots from user, admin, and system trust domains are all eligible for export. Caller material is bounded and certificate-only, private keys are rejected, and every attempt re-exports trust and rebuilds the bundle. Across domains, blocked policy errors outrank inconclusive errors, which outrank unavailable exports. The exact bundled root set is extracted from and rebound to the publisher-verified snapshot; initial inspection verifies every root self-signature, while later boundaries require the signed executable SHA-256 and exact extracted root set without replaying per-certificate OpenSSL. A policy-excluded bundled root blocks. Every failure terminalizes structured trust evidence. Linux/WSL2 keeps its canonical private CA preparation. |
| Regular-file output limits | Port into shared supervisor | `run_bounded_capture` applies an exact logical limit with a kernel overflow sentinel, raises a low inherited soft limit when the hard limit permits it, blocks before launch when the hard limit cannot preserve the sentinel, and normalizes EFBIG/SIGXFSZ without treating an arbitrary positive child exit code as a signal. macOS trust export uses this shared path. |
| Supervisor and fallback policy | Port | Every attempt remains inside existing timeout, stream budget, process-group, and containment contracts. Only verified authentication or entitlement evidence authorizes fallback; capacity, network, timeout, model mismatch, malformed output, and inspection failures do not. Explicitly inconclusive or transient evidence returns 75, while `runtime-unverified` is a blocked non-75 outcome. |
| Nonzero Claude result regression | Canonical-only addition | Nonzero stdout can never become a final artifact. Strictly recognized structural failures may retain a justified category; empty, malformed, non-UTF-8, duplicate-key, non-standard-constant, unknown, and success-looking envelopes receive a bounded sanitized `reason` in attempt/status evidence instead of empty-stderr `category=other`. |

## Obsolete Overlay Tests

- Tests for reading, validating, exporting, or racing `~/.claude.json` account
  metadata are intentionally omitted. Canonical local login does not read that
  file; a source contract test asserts the absence of the path, while Keychain
  account binding and double-read tests cover the live credential source.
- Tests tied to an exact Claude 2.1.202 artifact or a native-Claude-only lane are
  obsolete. Canonical accepts publisher-signed releases
  `>=2.1.187,<3.0.0`, retains immutable snapshots, supports macOS and
  Linux/WSL2, and keeps the policy-controlled Copilot fallback.
- Overlay fixture permutations that duplicated canonical CA directory,
  executable snapshot, supervisor, synthetic-token, and Python-version tests
  are not copied. Focused negative tests were added for each retained PR 82
  reviewer finding, and the complete canonical suite remains the regression
  authority.
- Overlay-specific account fields in egress evidence are omitted because no
  account-metadata bridge remains. Credentials and credential metadata remain
  excluded from reviewer-visible egress artifacts.

## Validation

- Python 3.10.19 complete canonical suite with the `tomli` test backport: 802
  tests run, 4 skipped, no failures.
- Python 3.13.0 complete canonical suite: 802 tests run, 9 skipped, no failures.
- Focused Python 3.13 suites: providers 331 tests run with 6 skipped and
  provenance 90 tests run with no skips or failures; earlier current-range
  common 49 and repository contract 14 test suites also passed.
- Final-head review remediation covers strict signed-manifest numeric parsing,
  system-domain custom roots, bounded snapshot revalidation without repeated
  OpenSSL self-signature work, and blocked `runtime-unverified` outcomes.
- Ruff lint, provider-file format checks, Python compile, and staged repository
  diff checks passed. The locally installed Ruff formatter still names the
  pre-existing layout in `claude_provenance.py` and its two test files; those
  files were not mechanically reformatted because doing so creates unrelated
  whole-file churn.
