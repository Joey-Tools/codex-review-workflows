---
id: 20260716-821601
title: Review Helper Trust Hardening Port
status: completed
created: 2026-07-16
updated: 2026-07-20
branch: wip/review-helper-trust-port
pr: 53
supersedes: []
superseded_by:
---

# Review Helper Trust Hardening Port

## Summary

This work semantically ports the still-applicable security hardening from
private-overlay PR 82 onto the canonical repository. The final integration
also incorporates the canonical `master` state from the final pre-merge sync.
It preserves canonical floating
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
  `>=2.1.211,<3.0.0`, retains immutable snapshots, supports macOS and
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

- Python 3.10.19 complete canonical suite with `tomli==2.2.1` and
  `PYTHONDONTWRITEBYTECODE=1`, run outside the inner sandbox: 1240 tests run,
  4 skipped, no failures. Disabling
  bytecode writes keeps the intentional `RLIMIT_FSIZE` tests from truncating
  uv's own `_virtualenv.pyc` import hook.
- Python 3.13.0 complete canonical suite, run outside the inner sandbox with
  bytecode writes disabled: 1240 tests run, 4 skipped, no failures.
- Final focused Python 3.13 regressions ran 10 tests with no failures, including
  deadline exhaustion, direct and deferred output limits, Python 3.10 cause
  fallback, Python 3.11+ notes, and strict post-inspection authentication. The
  complete repository contract suite ran 20 tests with no failures.
- The 2026-07-20 trust-boundary pass binds proxy CA snapshots to exact raw
  bytes, safely falls back from a symlinked Linux default CA file to the
  bounded compiled-in CA directory, and binds every macOS replacement CA
  variable to the canonical helper bundle. The final bundle is set to `0400`
  and its exact path, mode, digest, directory-input absence, bypass-input
  absence, and certificate-store mode are rechecked at profile construction
  and immediately before launch. The complete Python 3.13 suite ran 1280 tests
  with 4 skips and no failures; the focused repository contract suite ran 20
  tests with no failures.
- Final-head review remediation covers strict signed-manifest numeric parsing,
  system-domain custom roots, bounded snapshot revalidation without repeated
  OpenSSL self-signature work, blocked `runtime-unverified` outcomes,
  mismatched model-usage evidence, supported `maxOutputTokens` telemetry, and
  extended ACL rejection for root-owned CA sources while preserving normal
  Linux/WSL2 hard-linked certificate layouts. Explicit macOS `TrustAsRoot`
  anchors retain non-self-issued CA certificates without incorrectly requiring
  a root self-signature.
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
- The post-integration independent review reproduced that Apple's fixed
  LibreSSL 3.3.6 does not accept `-partial_chain`. Trust-anchor verification now
  probes the fixed client's actual capabilities: supporting clients keep strict
  partial-chain validation, while LibreSSL applies the same strict CA and DER
  validity policy plus bounded public-key extraction. The provider suite
  includes both capability branches and a real fixed-`/usr/bin/openssl` test.
- The next helper-backed review found that caller CA-directory metadata and
  enumeration I/O still escaped the typed inspection boundary. Initial/final
  `fstat`, bounded `scandir`, and per-entry `stat` failures now remain
  inspection-inconclusive, while unsafe metadata, symlinks, and input limits
  retain their existing blocked `ReviewError` classification.
- Current-head GitHub review then exposed root-EUID handling, Apple's extended
  ACL API, empty-domain export files, Node CA opt-in, and metadata-only open
  failure gaps. Root-owned system files now retain their TCB policy under UID 0,
  ACL inspection uses `acl_get_fd_np` with `ACL_TYPE_EXTENDED`, no-settings is
  classified from the fixed tool result rather than destination-file absence,
  and `NODE_EXTRA_CA_CERTS` is emitted only for an explicit caller opt-in.
- The independent and offline reviews split stream limits from regular-file
  export limits, classify directory close failure without masking a prior
  policy rejection, require explicit X.509 v3 anchors, and make trust-export
  cleanup preserve an existing deny. New proof tests also bind the already
  present macOS caller-directory symlink rejection and trust-race terminal
  inconclusive behavior.
- The next offline trust audit corrected Apple's external Trust Settings edge
  cases: an entry without a `trustSettings` array is rejected instead of being
  promoted, while an empty usage-constraints dictionary applies the documented
  implicit `TrustRoot` result. Caller CA file readers now also preserve a prior
  policy rejection when descriptor close fails; a close-only failure remains
  inspection-inconclusive for both path and `dir_fd` inputs.
- The final old-head helper review found that mode and ownership checks did not
  reject macOS extended ACLs on the publisher-verified executable snapshot or
  its private directory chain. Snapshot inspection now binds the explicit review
  `container_dir`, opens the true review root and every descendant through stable
  `openat` descriptors, and checks the executable plus the complete directory
  chain on every revalidation. Lexically non-normal paths are rejected before
  descriptor traversal, a nested directory named `.codex-tmp` cannot truncate
  that boundary, and inherited ACLs on any chain member fail closed before
  credentials or review content reach the executable.
- The final clean-context review separated deterministic isolation violations
  from transient inspection failures. Non-normal or escaping paths, symlinks,
  unsafe owner/mode/link metadata, and present ACL entries now remain blocked;
  descriptor I/O, close failures, ACL API failures, and identity races remain
  inspection-inconclusive. Focused tests assert both exception classes before
  the complete Python 3.10 and 3.13 suites.
- The final PR-readiness follow-up requires transient Claude failures to carry
  structured stdout evidence; stderr-only network wording cannot authorize a
  trusted retry or fallback. Owner-only bounded file reads also preserve an
  earlier policy rejection when descriptor close fails, while a close-only I/O
  failure remains inspection-inconclusive. Dedicated regressions cover both
  close paths and the stderr-only envelope before the two complete suites.
- The frozen-diff trust audit now checks extended ACLs on every opened caller
  CA directory descriptor and resolves each certificate fingerprint according
  to macOS user, admin, then system domain priority. A lower-priority domain
  cannot change a higher-priority `TrustRoot` into `TrustAsRoot`, and
  `TrustAsRoot` accepts only non-self-issued strict CA anchors. CA workspace,
  snapshot, verification-input, and generic directory operational I/O remains
  inspection-inconclusive, while stable symlink, metadata, ACL, and trust-policy
  violations remain blocked even when cleanup also fails.
- The final trust-tool audit replaces `Path.is_file()` probes with explicit
  metadata inspection, so operational `stat` failures cannot masquerade as
  deterministic OpenSSL or Security-tool absence. X.509 issuer and subject
  names are compared through conservative RDN/OID normalization; only printable
  ASCII DirectoryString values are complete enough to prove inequality, while
  Unicode StringPrep cases fail closed. A differently encoded but semantically
  self-issued name cannot enter the `TrustAsRoot` path. Generated CA and
  bundled-root verification files also preserve a primary policy rejection
  across both descriptor-close and temporary-file cleanup failures.
- The latest trust-budget review moves the absolute verification deadline ahead
  of certificate normalization and passes that same deadline through DER
  validation, OpenSSL metadata inspection, temporary-file creation, ACL checks,
  write/fsync preparation, capability probing, and final validation. Preparation
  can consume the remaining budget, in which case no OpenSSL process starts and
  the operation remains a timeout rather than receiving a fresh subprocess
  budget.
- A terminal trust-policy evidence write failure remains secondary to the
  blocked or inconclusive trust failure. Production `runner-error.txt` output
  now recognizes both Python 3.11+ exception notes and the Python 3.10 cause
  fallback, emits one fixed redacted diagnostic, and never renders the private
  evidence-write or output-limit exception text. End-to-end cases cover direct
  and deferred trust-domain stream/regular-file limits.
- Authentication guidance now matches the implemented post-attempt inspection
  contract: unstructured HTTP 401 or authentication fragments cannot override
  inconclusive credential reinspection. Only a strict request/model-bound
  result envelope can establish `blocked-authentication`; partial result text
  and loose stderr fragments remain non-authoritative.
- Ruff 0.13.2 lint, Python compile, project-journal validation, and the official
  skill validator passed. No formatter churn was retained: full-file
  `ruff format --check` still reports existing drift in the three changed Python
  files, while range checks over every newly added implementation, test, and
  contract hunk pass. That unrelated drift remains untouched.
