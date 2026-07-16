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
`8c095454d2d5cb25b6a2c1fb544de5e7487ba423`. It preserves canonical floating
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

- Python 3.10.19 complete canonical suite with the `tomli` test backport and
  `PYTHONDONTWRITEBYTECODE=1`: 820 tests run, 9 skipped, no failures. Disabling
  bytecode writes keeps the intentional `RLIMIT_FSIZE` tests from truncating
  uv's own `_virtualenv.pyc` import hook.
- Python 3.13.0 complete canonical suite: 820 tests run, 9 skipped, no failures.
- Focused Python 3.13 suites: the 3 `SSL_CERT_DIR` regressions passed, providers
  ran 353 tests with 6 skipped, and provenance ran 90 tests with no skips or
  failures; earlier current-range common 49 and repository contract 14 test
  suites also passed.
- Final-head review remediation covers strict signed-manifest numeric parsing,
  system-domain custom roots, bounded snapshot revalidation without repeated
  OpenSSL self-signature work, blocked `runtime-unverified` outcomes,
  mismatched model-usage evidence, supported `maxOutputTokens` telemetry, and
  extended ACL rejection for root-owned CA sources while preserving normal
  Linux/WSL2 hard-linked certificate layouts. Explicit macOS `TrustAsRoot`
  anchors retain non-self-issued CA certificates through strict partial-chain
  verification rather than incorrectly requiring a root self-signature.
- The current-head P2 follow-up treats configured `SSL_CERT_DIR` entries as one
  certificate union: safe empty directories can precede a valid directory, the
  complete all-empty union is rejected, and any unsafe member still blocks.
- Final independent-review remediation gives an empty CA source its own typed
  exception so a source filename cannot disguise private-key or malformed
  certificate failures. macOS Keychain output now removes exactly one required
  command-terminating LF, compares both raw credential reads before parsing,
  and preserves every preceding control byte for strict JSON rejection.
- A Claude-family lane that cannot make any model attempt because both Claude
  and the policy-authorized Copilot fallback are unavailable is blocked with
  exit 1. Exit 75 is reserved for a last attempt that actually ended as
  inconclusive or transient.
- The current-head review preflight correctly rejected a newly added literal
  private-key marker in a synthetic negative fixture. The fixture now builds
  the same marker from non-credential-shaped byte fragments at runtime; both
  complete Python suites were rerun after that source-only repair.
- Independent current-head review found that final-invocation authentication
  classification did not yet enforce the warmup's exact known login message,
  empty error payloads, and single authentication signal. Both paths now share
  those fail-closed criteria across stdout and stderr, so mixed
  auth/entitlement/transient evidence cannot authorize Copilot fallback even
  when classifier priority would otherwise select one category.
- Frozen Codex review also found that executable revalidation still allowed an
  owner-writable `0700` mode after publisher verification. Initial and repeated
  verified-snapshot inspection now require exact `0500`, so digest-preserving
  mode drift cannot reopen the immutable executable to current-user writes.
- Final independent review found that an executable-inspection race inherited
  the generic blocked trust-domain priority and could tie with, then mask, a
  later malformed policy. The domain collector now records that typed race as
  priority-1 inconclusive before the generic `ReviewError` branch, so any later
  priority-2 policy block wins; a three-domain regression covers the ordering.
- The next independent review closed three related fail-open edges. Launch I/O
  failures from the already-discovered trust helper, trust-settings export, or
  certificate export are inspection-inconclusive rather than deterministic tool
  absence. Owner-file `open`, `fstat`, and `read` I/O failures now enter the same
  typed path, allowing a later malformed or denied trust domain to retain blocked
  precedence. Finally, a post-warmup fresh credential permits review only after
  the exact supported success envelope; unknown or future output remains
  inconclusive even when the warmup happened to refresh Keychain state.
- A current-head follow-up also requires final-invocation entitlement evidence
  to originate in the strict structured stdout result. Non-structured stderr
  wording about account, plan, or model availability can no longer authorize an
  Opus downgrade or Copilot fallback, even when the envelope otherwise carries
  exact requested-model usage.
- The next independent review closed two trust-domain leaks. A discovered
  OpenSSL root verifier whose launch fails now remains inspection-inconclusive
  instead of becoming deterministic tool absence, so it cannot authorize the
  Copilot fallback. macOS model attempts also preserve a separate pre-merge
  parent/proxy TLS environment for both local-login warmup and final review;
  Claude's merged bundled/caller/Node CA set is exposed only to the sandboxed
  Claude process and no longer widens the upstream CONNECT proxy trust store.
- The final `origin/master` integration preserves this branch's strict JSON and
  runtime-failure contract while adopting the canonical JWT retirement: legacy
  exemptions may cover only catalog-declared generic assignments or GitHub
  tokens, and JWT findings are never suppressible.
- Ruff 0.13.2 lint, Python compile, project-journal validation, the official
  skill validator through its documented uv/PyYAML fallback, and working-tree
  diff checks passed. No provider/test formatter churn was retained:
  Ruff would also rewrite three pre-existing current-head expressions outside
  this P2 fix. The previously documented formatter drift in
  `claude_provenance.py` and its two test files remains untouched.
