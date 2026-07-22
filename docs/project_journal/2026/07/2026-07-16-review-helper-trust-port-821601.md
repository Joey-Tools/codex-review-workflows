---
id: 20260716-821601
title: Review Helper Trust Hardening Port
status: completed
created: 2026-07-16
updated: 2026-07-22
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
- The deadline follow-up keeps one absolute budget through parent preparation,
  both OpenSSL launches, and the child process itself. `run_bounded_capture`
  uses a ready/launch/close-on-exec status handshake for absolute deadlines, so
  a parent scheduling pause during the launch handshake cannot make a late
  result acceptable; relative timeout callers retain their existing launch
  path. The wrapper recomputes its remaining budget after signal preparation
  and arms a child timer, while the parent independently rejects any result
  observed at or after the deadline. This is a bounded timeout contract, not a
  hard real-time guarantee that target userspace can never execute after the
  wall-clock boundary. Pending `ForwardedSignal` and other cancellation outrank a
  simultaneous timeout, and captured buffers are zeroized on every exceptional
  exit. Bundled-root validation now applies the same precedence to outer
  canonicalization, extensions, hashing, dictionary publication, temporary
  directory cleanup, and final success. Both OpenSSL result pairs are zeroized,
  and no immutable public-key output copy is retained. Twelve focused provider
  regressions and the complete Python 3.13 common/provider suites pass; the
  combined host-level result is 770 tests run, 3 skipped, and no failures. The
  parent owns fresh review and the final repository-wide suite.
- Fresh frozen-diff review then closed the remaining launch-boundary races. The
  absolute-deadline child now arms a kernel interval timer before preparation;
  the remaining budget is recomputed after signal setup, closing the practical
  pre-arm scheduling gap. A relative `setitimer` cannot establish a hard
  real-time execution cutoff across its final userspace clock/syscall race, so
  the helper promises bounded termination and rejection of late results rather
  than impossible instruction-level timing. Signal forwarding becomes active as
  soon as the deadline wrapper process is published, so a forwarded termination
  signal cannot be ignored between the parent's final check and launch
  authorization.
  The parent temporarily unblocks forwarded signals and restores the caller's
  exact entry mask after cleanup; the child independently unblocks its alarm and
  cancellation signals before arming the timer. Buffered status parsing
  classifies coalesced `RT` and launch-pipe `EPIPE` as the original timeout, and
  cleanup synchronously reaps a dead direct child even when Linux reports no
  live process-group members.
  Every bounded non-process operation now checks the shared deadline before and
  after execution, and a new control-flow cancellation raised by temporary-root
  cleanup outranks an older policy error. Focused scheduling, signal, pre-expiry,
  and cleanup regressions pass, as does the Python 3.13 common/provider suite.
  A final review clarified that the timer does not guarantee an instruction-level
  cutoff across the final clock, timer-arm, and `execve` races; late results are
  rejected and the process is terminated and reaped within the bounded cleanup
  contract. Sensitive OpenSSL captures keep forwarded signals blocked before
  capture through consumer validation and buffer zeroization, then restore the exact
  caller mask; a pending cancellation is delivered only after zeroization.
  The focused common/provider result is 783 tests run, 4 skipped, and no
  failures. The nested macOS `sandbox-exec`
  broker test is expected to fail inside Codex's outer sandbox and passes in the
  host-level suite. Proxy CA subject-hash probes also retain a per-call absolute
  deadline bounded by the shared inspection deadline, so a parent scheduling
  gap cannot restart a relative launch budget. The final repository-wide Python
  3.13 run completed 1,361 tests with 5 skips and no failures; Ruff lint/format,
  `py_compile`, project
  journal validation, and the official skill validator also pass.
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
- An earlier current-head GitHub review found two executable-discovery regressions.
  Automatic discovery initially proved and skipped a stable dangling leaf
  symlink, while an explicit dangling override remained
  inspection-inconclusive. A later current-head review correctly identified
  that the automatic exception could misclassify Claude as unavailable and
  authorize a forbidden fallback. Both automatic and explicit dangling leaf
  symlinks are now inspection-inconclusive; a truly missing stable path remains
  absent. A regular file with execute bits is
  accepted only when the current user also has effective execute access; stable
  inaccessible candidates are skipped after the same metadata recheck. Focused
  Python 3.13 tests cover dangling-leaf replacement, inaccessible-candidate
  fallback, and the explicit-override boundary. Per the final operator request,
  this follow-up was validated only on Python 3.13. The final host-level suite
  ran 1333 tests with 4 skips and no failures; a preceding inner-sandbox run's
  sole failure was traced to the outer sandbox denying the test's nested
  `sandbox-exec`, not to broker behavior.
- Ruff 0.13.2 lint and full-file format checks pass for the four owned Python
  files. Python 3.13 `py_compile`, project-journal validation, and the official
  skill validator also pass; the validator ran through a Python 3.13 `uv`
  environment because the host interpreter does not include PyYAML.
- The final macOS broker hardening removes runtime compilation and every
  user-owned executable carrier. A reproducible universal Mach-O with a macOS
  13.0 deployment target is installed explicitly at a digest-keyed
  root-owned `0555` path; runtime verification rejects unsafe ancestors,
  symlinks, ACLs, hardlinks, digest drift, and dependency drift before
  credential selection. Existing shared install parents are validation-only
  and are never repaired or permission-modified by the root installer.
  A helper-private Unix identity endpoint releases the in-memory TCP capability
  only after same-user/group, bound session/PGID, and running CDHash checks.
  The broker waits for the TCP authorization ACK before reading update stdin,
  and the Seatbelt profile binds the kernel canonical socket path obtained from
  `F_GETPATH`. Replacement sockets can cause only a fail-closed denial of
  service. The final Python 3.13 repository suite ran 1,386 tests with 5 skips
  and no failures; the focused provider suite ran 719 tests with 3 skips, and
  the common suite ran 89 tests with 1 skip. Ruff lint/format, Python 3.13
  `py_compile`, both broker architectures, Bash syntax, ShellCheck, strict code
  signing, byte-for-byte artifact reproduction, and `git diff --check` pass.
- The current-head integration makes runtime-process authorization a two-phase
  prepare/commit boundary, so a late or failed identity preparation cannot
  authorize `exec`. macOS credential selection owns and zeroizes both mutable
  copies across every control-flow exit, and identity-server startup and cleanup
  share one absolute deadline with cancellation precedence. The root installer
  creates valid shared parents atomically without a post-create permission
  transition, while broker reproducibility runs as an ordinary hosted
  `macos-26` user and is explicitly documented as a reproducibility gate rather
  than a trust boundary. Low-level helper maintenance now ships a self-contained
  Python 3.13 independent Codex supervisor with isolated `CODEX_HOME`, bounded authenticated
  evidence, app-server stdio, exact model/effort verification, sealed terminal
  evidence, and exact process/checkout settlement. A cleanup-lock regression
  also avoids a redundant same-mode `fchmod` that could change ctime during a
  concurrent waiter's identity sampling while still repairing modes restricted
  by an unusual umask. Final host-level Python 3.13 validation ran 1,428 main
  tests with 5 skips and 268 independent-supervisor tests with 4 skips; the
  repository contract suite ran 42 tests. Ruff lint and independent-package
  format checks, Python 3.13 compileall, Bash syntax, ShellCheck, actionlint,
  canonical CI byte comparison, broker developer byte reproduction, and
  `git diff --check` pass. The hosted-only broker `--check` remains a required
  CI gate because its exact Xcode path is intentionally unavailable locally.
- The first frozen-diff preflight remained local and blocked before egress on
  three credential-shaped supervisor fixtures. The unused refresh fixture now
  uses helper-catalog ID `refresh-a`; JWT-shape and malformed-token tests build
  their values at runtime from non-credential-shaped fragments because the
  catalog access-token shape intentionally does not satisfy that parser test.
  The three affected Python 3.13 test modules run 34 tests with no failures.
- The final upstream integration adopts the canonical clean-worktree Codex,
  direct Claude Code, and current-head GitHub Codex review shapes from PRs 68-70.
  The supplied-diff helper and independent supervisor remain low-level security
  tools with dedicated CI; neither satisfies a named review lane or becomes an
  implicit PR-readiness gate. Named double/triple consent no longer authorizes
  the helper's Copilot compatibility path, which requires a separate explicit
  supplemental request.
- The last old-head frozen review found that supervisor preflight accepted a
  primary diff larger than its final 4 MiB evidence allowance and accepted an
  explicit nonexistent or nonexecutable Codex path. Preflight now rejects both
  conditions before attempt, prompt, or worktree creation; complete Codex
  signature, version, schema, snapshot, and auth verification remains in `run`
  before any model request.
- Pre-remediation integrated-head validation used only Python 3.13 as
  requested. The host-level canonical suite ran 1,427 tests with 5 skips, and
  the independent supervisor suite ran 271 tests with 4 skips. Ruff lint,
  the independent package format gate, Python 3.13 compileall, Bash syntax,
  ShellCheck, actionlint, canonical CI fixture equality, project-journal
  validation, the
  official skill validator, `git diff --check`, and broker developer byte
  reproduction all pass. The hosted-only broker `--check` remains a required
  `macos-26` CI gate because this host does not provide the pinned
  `/Applications/Xcode_26.6.app` toolchain path.
- The first hosted `macos-26` run exposed that GitHub's `macos-26-arm64`
  image repackages all six pinned build tools even though Xcode 26.6 build
  17F113 and SDK 26.5 build 25F70 match the developer installation. The build
  gate now selects separately reviewed developer and hosted-runner digest sets
  while requiring both contexts to reproduce the same tracked broker bytes.
- A fresh-context Codex review found that the production reviewer referenced an
  untracked aggregate-schema sidecar and that `check-attr` under-budgeted legal
  output for many short paths. Production now generates each stage's schema
  from the authenticated snapshot in a lease-owned `0700` work root. The
  attribute budget now covers the exact two-record `unset`/`unspecified`
  encoding and has a 200-short-path regression.
- Hosted CI also exposed test-environment drift without weakening production
  policy: managed-auth fixtures now execute the selected Python 3.13 runtime,
  live no-child integration skips hosts that do not match its exact production
  macOS pin, and cross-platform provider tests use scoped macOS identity
  doubles while retaining direct fail-closed coverage for non-macOS hosts. The
  first follow-up Ubuntu run found that individual tests could mutate the
  shared `sys.platform` object and that a deep checkout path exceeded Linux's
  Unix-socket limit. The fixture now captures the real host before per-test
  mocks and uses a short, unique, owner-only temporary identity directory on
  non-Darwin hosts. A Python 3.13 forced-Linux harness reran the exact five
  failures successfully before the complete 1,428-test host suite passed with
  5 skips.
- Post-review remediation validation used only Python 3.13. The host-level
  canonical suite ran 1,428 tests with 5 skips, and the independent supervisor
  suite ran 272 tests with 4 skips. The 39-test repository contract suite,
  Ruff lint and format checks, compileall, Bash syntax, ShellCheck, actionlint,
  canonical CI fixture equality, project-journal validation, the official
  skill validator, broker developer byte reproduction, and `git diff --check`
  all pass.
- The final current-head GitHub Codex finding removed the automatic-reviewer
  dangling-leaf exception, so a stale Claude symlink cannot authorize Copilot
  fallback even when a later valid candidate exists. The two focused Python
  3.13 dangling-symlink tests and all 90 common tests passed. The complete
  host-level Python 3.13 suite then ran 1,428 tests with 5 skips and no failures;
  Ruff lint and format checks pass for the changed Python files.
- A final fresh-context review found that the required independent-supervisor
  job could pass after silently skipping the live no-child integration when a
  hosted runner drifted from the pinned macOS runtime. The job now runs on
  `macos-26`, invokes the live integration through a zero-skip runner, and
  converts runtime-pin or Seatbelt availability drift into a required-CI
  failure while preserving ordinary local skips on unpinned hosts. GitHub's
  hosted `macos-26` image remains on 26.4 while the production host pin is
  26.5.2, so CI uses an exact test-only 26.4 runtime/build/kernel/sandbox-exec
  profile without changing the production allowlist.
- A whole-range fresh-context review found that the low-level supplied-evidence
  supervisor could emit `overall_status: completed` without an explicit machine
  label preventing named-lane counting. Every new attempt state and public JSON
  envelope now carries `review_contract: supplied-diff-no-git` and
  `named_lane_eligible: false`. State reads and pre-write transitions reject
  missing, malformed, forged, or integer-zero eligibility, while the public CLI
  overwrites conflicting producer metadata with the fixed ineligible contract.
  Exit zero, clean review status, requested model, and `No findings.` cannot
  upgrade this helper into a canonical named lane.
- Full-suite load exposed that the Python fake app-server fixtures had only
  1.0-1.4 seconds after cleanup reservation for interpreter startup, marker
  publication, and protocol work. Production correctly timed out and cleaned
  those processes before their fixture markers appeared. Test-only budgets now
  allow five seconds while preserving the production full-lifecycle deadline
  and every strict stage, code, PID, and descendant assertion.
- Final host-level validation used only Python 3.13. All 6 live no-child
  integration tests ran without skips inside the complete 280-test independent
  supervisor suite, and the 1,429-test main suite passed with 5 platform skips.
  The 82 focused lifecycle tests and 40 repository contract tests pass. Ruff
  lint and formatting, compileall, Bash syntax, ShellCheck, actionlint,
  canonical CI fixture equality, project-journal validation, the official skill
  validator, synthetic-token validation, broker developer byte reproduction,
  and `git diff --check` also pass.
- GitHub Actions run 29821520816 disproved the assumption that an exact hosted
  runtime fingerprint establishes production isolation capability. The
  `macos-26` runner matched macOS 26.4 build 25E246, Darwin 25.4.0, arm64, and
  the pinned `sandbox-exec` digest, but its outer Seatbelt made nested Seatbelt
  unavailable and left process-group, start-identity, and post-exec RLIMIT
  evidence ambiguous. Hosted CI now runs every deterministic supervisor test
  through an exact-count zero-skip runner and separately requires this hosted
  environment to match the reviewed fail-closed blocker signature. The six
  no-child profile cases and the existing snapshot Seatbelt adversarial case
  form a seven-test production live gate and are no longer claimed by Hosted
  CI. They remain a required trusted-Mac Python 3.13 delivery gate for
  isolation-boundary changes until a separately reviewed ephemeral isolated
  Mac runner exists. The gate is explicitly operator-enforced rather than a
  branch-protection status: the final PR evidence must bind seven passes with
  zero skips to the exact current head, and every push invalidates that record.
- Three focused read-only reviews found and closed five weaknesses in the split
  gate design. The live runner now rejects duplicate required identities; the
  deterministic runner pins both the exact count and a stable SHA-256 digest of
  all selected test identities. Hosted evidence normalizes outer-Seatbelt and
  early-leader-exit reasons without retaining raw stderr or paths, verifies the
  actual arm64 process, matches all 24 structured observations, and requires
  the exact production-derived blocker set with no unreviewed extras. The
  operator-only nature of the trusted-Mac gate and its exact-head invalidation
  rule are explicit in PR-readiness policy.
- Post-remediation validation used only Python 3.13. The host-level main suite
  ran 1,429 tests with 5 platform skips; the deterministic independent suite
  ran 276 tests with zero skips; and the trusted-Mac live isolation gate ran all
  7 tests with zero skips. The 21 focused no-child unit tests and 40 repository
  contract tests pass. Ruff lint and formatting, compileall, actionlint,
  canonical CI fixture equality, project-journal validation, the official
  skill validator, synthetic-token validation, and `git diff --check` pass.
- A fresh-context Codex review of
  `3134c1cb849ad473f154f4a2ad73ca96484a34ca..6a0f8989ac2fdbb0a9607f20c6c090c9f51624d7`
  found three remaining trust gaps: the external ChatGPT auth carrier did not
  reject extended ACLs, arbitrary printable PR URLs remained inside the trusted
  model instruction zone, and the native Keychain broker used optimizable
  `memset` calls for sensitive buffers.
- Auth loading and every subsequent use boundary now open the exact owner-only
  `.codex` directory and `auth.json` through retained no-follow descriptors,
  bind the stable directory and file generations, and run the shared macOS
  ACL/xattr verifier before and after inspection. Directory replacement,
  metadata races, malformed verifier evidence, and descriptor-close uncertainty
  fail closed. PR URLs must be byte-canonical HTTPS pull-request URLs before any
  runtime directory is created and are revalidated when model input is built;
  the URL is retained only in a canonical JSON block explicitly labeled as
  untrusted review metadata. The broker now uses C11 `memset_s` for credential,
  capability, script, and overflow-probe buffers. Its universal artifact is
  pinned at SHA-256
  `fcdf6d473ec5c6fa76488da0b115d147fe5e5fa576ed33710ecd3fd7186e0b46`,
  size 101728, with arm64 CDHash
  `8af40bf4caf7e2398fb59182082ea57caa12ed9a` and x86_64 CDHash
  `a5de7fbd8785b8baddb34da1d8477aa4f741efa0`; both slices import
  `_memset_s`.
- Final remediation validation used only Python 3.13. The host-level main suite
  ran 1,430 tests with 5 platform skips and no failures; the deterministic
  independent suite ran 286 tests with zero skips; 40 repository contract tests
  and the native broker read/update and installer regressions pass. The pinned
  Xcode 26.6 / SDK 26.5 developer build reproduced the broker byte-for-byte.
  Ruff lint and the relevant format gate, compileall, Bash syntax, ShellCheck,
  actionlint, canonical CI fixture equality, and `git diff --check` pass.
- A subsequent whole-range fresh-context Codex review of
  `3134c1cb849ad473f154f4a2ad73ca96484a34ca..68c21f208e8eda2c823faff2771a18c8b1759fa6`
  found that evidence admission bounded the raw diff, evidence bundle, and
  rendered prompt but not the final JSONL `turn/start` record. A prompt rich in
  JSON escape characters could therefore pass the 6 MiB raw prompt limit and
  exceed the 8 MiB encoded record limit only after reviewer launch.
- Prelaunch admission now decodes the actual prompt once, constructs the shared
  `turn/start` request shape with worst-case legal dynamic fields, and applies
  the production canonical JSONL encoder before returning prepared input. The
  live protocol uses the same request and parameter constructors, so request
  shape changes cannot silently drift from the admission proof. Regression
  tests cover both ordinary input and a 4 MiB backslash prompt that remains
  below the raw limit but must fail with `record-size` before stream activity.
  Validation used only Python 3.13: the host-level main suite ran 1,430 tests
  with 5 expected platform skips and no failures, while the deterministic
  independent suite ran 288 tests with zero skips.
- The final canonical integration merges `origin/master` at
  `7e8a718c799b7968b45e306cbdcb02d8b5879f57`. It preserves this branch's
  strict JSON, deadline/RLIMIT, executable/TLS, authentication, and failure
  classification hardening while adopting descriptor-bound workspace launch,
  bound attempt output, one-time helper-private cleanup, tracked-context
  review visibility, and the exact secret-admission state machine. The merged
  process supervisor carries caller descriptors and descriptor-CWD handoff
  through both wrappers, then publishes process start only after every exec
  boundary succeeds. Manual validation used only Python 3.13 as requested: the
  host-level main suite ran 1,740 tests with 6 expected skips, the provider
  suite ran 776 tests with 3 expected skips, the state suite ran 169 tests, the
  common suite ran 93 tests with 1 expected skip, and the deterministic
  independent suite ran 288 tests with zero skips. Ruff lint, conflict-file
  formatting, compileall, Bash syntax, ShellCheck, actionlint, strict launcher
  C syntax, synthetic-token catalog validation, project-journal validation,
  the official skill validator, and `git diff --check` pass.
- Exact-head self-hosting of the candidate stateful helper at
  `aaf9ed01e1fb83237c2690388dc342edd220d16c` exposed a raw Git LFS pointer
  test fixture that made full-tree materialization fail closed before reviewer
  launch. The pointer detector is intentionally independent of current
  `.gitattributes`, so the fix keeps the parser samples as runtime byte
  constants inside `test_lfs.py` and removes the three standalone fixture
  blobs instead of weakening detection. The focused Python 3.13 LFS parser
  suite passes; the replacement head must repeat all exact-head gates.
- A fresh-context Codex review of
  `7e8a718c799b7968b45e306cbdcb02d8b5879f57..8ed6d197d6715dbcf00d7c9429c4ad640be37ffd`
  found two private-state custody gaps. Retention and checkout roots checked
  only POSIX owner/write bits, so a macOS extended ACL could expose or permit
  mutation. Recursive path creation and later absolute-path reopen also did
  not authenticate writable ancestors or retain the retention-root identity.
- Private runtime paths now use a component-by-component no-follow descriptor
  walk with root/current-user ownership, non-writable ancestor policy, a
  narrow sticky-directory exception, and fixed root-owned Darwin aliases.
  Descriptor-based macOS metadata inspection rejects every ACL, quarantine,
  and unknown xattr on private nodes while allowing only OS-created provenance
  metadata; trusted system ancestors additionally permit rootless metadata.
  The retention lease holds its root descriptor, creates attempts with
  `mkdirat`, revalidates the lexical binding, and records durable retention and
  attempt identities. Private state, prompt, final, settlement, cleanup, and
  runtime artifacts are checked both at creation and after reopen/publication.
- Remediation validation used only Python 3.13. The host-level main suite ran
  1,740 tests with 6 expected platform skips, and the deterministic independent
  suite ran 299 tests with zero skips. Ruff lint and formatting, compileall,
  project-journal validation, the official skill validator, and
  `git diff --check` pass. Under the repository's operator-enforced policy, the
  seven-test trusted-Mac live gate remains current-head PR evidence and must be
  run after the final branch push rather than embedded in this pre-push commit.
- Before final review, the branch integrated the newer `origin/master` head
  `eaec097bd731c801a5f5a3e6628a8e9dad8fa4c9`, including the canonical named
  Claude lane and current-head GitHub Codex evidence policy. Post-integration
  validation used only Python 3.13: the host-level main suite ran 1,825 tests
  with 6 expected platform skips, the deterministic independent suite ran 299
  tests with zero skips, and the three formatter-touched provider/installer
  modules ran 266 focused tests with 1 expected platform skip. Ruff lint and
  the PR-range format gate, compileall, Bash syntax, ShellCheck, actionlint,
  strict C syntax for both launchers, synthetic-token catalog validation, the
  project-journal validator, the official skill validator, and `git diff
  --check` pass. The exact-head trusted-Mac live gate still follows the final
  push, as required by repository policy.
- Direct exact-secret admission on the first aligned PR head found one
  positive-count synthetic refresh-token fixture: the same catalog value was
  retained once by the provider tests and added once by the independent
  supervisor tests. The fixture now has one canonical literal in the
  self-contained independent test package, and both suites import that shared
  value. This preserves the baseline global raw occurrence count without
  splitting the value or weakening admission. Python 3.13 focused validation
  passes 14 independent auth-carrier tests and 156 provider tests with 1
  expected platform skip; exact-range admission is rerun against the resulting
  signed commit before review resumes.
- The first current-head Hosted Runner gate then failed only because its new
  no-child fail-closed signature returned a boolean mismatch with no actionable
  evidence; runtime version, build, Darwin release, architecture, and
  `sandbox-exec` digest still matched the pin. Mismatch output now includes a
  bounded structured comparison of expected/observed blockers, normalized
  observations, parent limits, missing evidence fields, and each signature
  subcheck. It does not retain raw probe stderr or repository data. The focused
  Python 3.13 no-child suite passes all 27 tests outside the enclosing Codex
  Seatbelt; the next Hosted run supplies the exact drift needed for calibration.
- GitHub Actions run 29849786188, job 88699424062, then showed that the earlier
  outer-Seatbelt-denial model was too narrow. All RLIMIT probes still exited
  before post-exec leader binding, but every Seatbelt and combined probe had a
  bound PID, process group, session, Darwin start identity, profile digest, and
  expected RLIMIT before terminating with `SIGKILL` without probe output. The
  parser now maps only that exact empty-output signal shape to a stable
  `probe-killed-before-evidence` reason. The Hosted matcher requires all 24
  observations, their layer-specific identity and limit fields, and the exact
  production-derived blocker set; it does not infer the unobserved cause of the
  signal. Python 3.13 passes all 27 focused no-child tests and the corresponding
  repository contract test. The final local gate also passes all 1,825 main
  tests with 6 expected platform skips, all 299 deterministic independent tests
  with zero skips, and all 57 repository contract tests.
- The final pre-review integration merges `origin/master` at
  `0af66e7cc247d05276d9059d689677ed2d279283`. Semantic conflict resolution
  preserves both this branch's descriptor-bound reviewer launch and the newer
  refresh-transaction ownership, signal-mask, broker-identity, and durable
  recovery contracts. Validation used only Python 3.13: the exact post-format
  main suite passed all 2,257 tests with 6 host-gated skips, the deterministic
  independent supervisor suite passed all 299 tests with zero skips, and the
  post-format Linux runtime suite passed all 251 tests with 1 host-gated skip.
  Ruff lint and the PR-range format gate, compileall, strict launcher C syntax,
  Bash syntax, ShellCheck, actionlint, canonical CI fixture equality, both
  official skill validations, project-journal validation, synthetic-token
  catalog validation, broker developer byte reproduction, and `git diff
  --check` pass. No local Python 3.10 run was performed.
- GitHub Actions run 29858821134 passed the macOS platform suite, deterministic
  independent supervisor, and hosted broker byte-reproduction jobs. Ubuntu
  exposed one merge-only fixture gap: after receiving the required fake broker,
  the missing-process-start-proof regression reached macOS identity allocation
  without the non-Darwin identity-directory fixture used by neighboring tests.
  The regression now injects its existing private `0700` identity directory,
  preserving the production allocator and the terminal fail-closed assertion.
  Run 29860285900 showed that the first placement matched an adjacent success
  regression; the final correction moves the mock into the named failing test
  and asserts that its allocator was called. The exact targeted test and the
  complete Python 3.13 main suite pass; the latter ran all 2,257 tests with 6
  host-gated skips. No local Python 3.10 run was performed; the replacement
  GitHub Actions head remains its platform gate.
- The first final-suite attempt hit one unrelated one-second cleanup-lock
  timeout. The exact regression then passed alone, all 169 `test_state.py`
  tests passed in module order, and a second complete Python 3.13 run passed
  all 2,257 tests with 6 host-gated skips. No production change was made for
  the non-reproducing timing failure.
- The branch then integrated `origin/master` at
  `217a3571bd05611d79f85dba5c0068a17ea74168`, including the floating Claude
  release and stream-compatibility contracts from PR #74. The merge was clean
  and retained the corrected Linux regression fixture. Post-integration
  validation used only Python 3.13: the exact regression passed, the complete
  main suite passed all 2,294 tests with 6 host-gated skips, and the independent
  deterministic supervisor passed all 299 tests with zero skips. Full-tree
  Ruff lint, the 75-file PR-range format gate, compileall, Bash syntax,
  ShellCheck, actionlint, strict Linux-launcher C syntax, canonical CI fixture
  equality, all four repository skill validations, project-journal validation,
  synthetic-token catalog validation, and pinned-Xcode broker byte
  reproduction pass. Ruff 0.13.2 also identifies three baseline-identical
  files outside the PR range that it would now reformat; they remain unchanged.
- Fresh-context Codex review of `217a357..eda22a2` found two shutdown and test
  isolation gaps. `CatFileBatch.close()` now drains stdout and stderr
  concurrently under one bounded deadline, caps diagnostics, and terminates and
  reaps on timeout or overflow; watchdog regressions cover a full stderr pipe,
  an open-pipe producer, and unexpected stdout. Independent supervisor fixtures
  now live in a process-scoped private runtime root outside the source checkout.
  The root selection validates the complete ancestor chain and uses the current
  checkout parent or linked worktree common checkout parent before account or OS
  runtime fallbacks, so a `/private/tmp` review worktree does not weaken the
  executable trust policy or inherit sticky ancestors. Validation used only
  Python 3.13: both affected modules passed 55 tests with 1 host-gated skip, the
  deterministic supervisor passed all 299 tests in the main worktree, and the
  same 299-test gate passed with zero skips from a detached `/private/tmp`
  linked worktree. The complete main suite passed all 2,294 tests with 6
  host-gated skips outside the enclosing Codex Seatbelt; inside it, the only
  failure was the expected inability to nest the keychain broker's own
  `sandbox-exec`, and that exact test passed outside the outer sandbox.
- Final review of `217a357..9a56da4` and the remaining current-head GitHub
  conversations found five additional fail-closed gaps. Exec-budget preflight
  measured the ambient parent environment instead of the projected isolated
  reviewer environment; the actual launch boundary also omitted the final
  `sandbox-exec` argv. Auth-carrier inspection converted `KeyboardInterrupt`
  and `SystemExit` into a generic carrier error. Shared retained-state JSON
  accepted `NaN`, infinity, and exponent overflow. `git cat-file --batch`
  could block while stderr filled during a request, and leader-only shutdown
  could leave descendants running. The fixes make exec-budget inputs explicit
  at preflight and recheck the exact sandbox argv before fork, preserve auth
  control-flow priority while closing every descriptor, enforce finite JSON
  numbers for decoding and canonical output, and use a deadline-bound selector
  plus start-identity-anchored process-group termination for every cat-file
  exit path. Regressions include stderr flooding, held pipes, an exited wrapper
  with a `SIGTERM`-resistant child, and a child that closes all standard I/O.
  Python 3.13 passes all 102 directly affected tests; the deterministic suite
  identity is intentionally advanced from 299 to 315 tests before the final
  full-suite gate. No local Python 3.10 run was performed.
- Current-head GitHub Codex review of `9a56da4` identified three valid App
  Server boundary gaps. The strict JSON decoder did not normalize parser-level
  recursion exhaustion, the protocol rejected the pinned runtime's initial
  `userMessage` lifecycle item, and turn validation expected `full` snapshots
  even though Codex Desktop `0.145.0-alpha.18` emits `notLoaded` with an empty
  item list for turn start, started, and completed records. The protocol now
  admits only the exact submitted prompt as the first undecorated user message,
  treats validated item lifecycle notifications as canonical evidence, and
  accepts only the consistent `notLoaded + []` or `full + exact observed items`
  turn shapes. Parser recursion is normalized at the protocol, auth-carrier,
  private-state JSON, no-child probe, and mutation-probe boundaries. The fourth
  review finding, which proposed replacing the hosted macOS profile with the
  production host profile, was rejected: Actions run 29870408435 on the same
  head proved the hosted image still matched macOS 26.4 build 25E246, Darwin
  25.4.0, and the reviewed `sandbox-exec` digest. Hosted and production pins
  remain intentionally separate and fail closed on actual drift.
- Final local validation used only Python 3.13. The directly affected unit set
  passed all 83 tests; the deterministic independent-supervisor gate passed all
  315 tests in 100.457 seconds; and the complete host-level suite passed all
  2,294 tests in 409.548 seconds with 6 expected host/filesystem skips. An
  inner-sandbox focused run reproduced the expected inability to nest one
  Seatbelt integration, while the complete outer-sandbox run passed that path.
  Ruff lint, changed-file formatting, compileall, actionlint, strict Linux
  launcher C syntax, project-journal validation, and `git diff --check` pass.
  Ruff 0.13.2 still identifies the same three unchanged baseline files outside
  this change range that it would reformat; they remain untouched.
- A final orchestration audit found that the documented lane sequence required
  both local reviewers to finish before `@codex review`, but did not classify an
  accidentally early same-head request or prevent its later terminal payload
  from counting. The policy now records
  `github-request-before-local-terminal` as a fail-closed
  `triple-inconclusive` outcome. Later local completion cannot cure the request,
  the provider payload cannot count, and no second request is allowed until a
  separately authorized ordinary change creates a new head. Contract tests bind
  the rule across the skill, PR-readiness guide, lane contract, GitHub probes,
  prompt template, agent interface, and canonical README.
- Full-suite load also reproduced a supervisor timing bug: a cancelled spawn
  worker received only the ordinary 0.5-second join budget even after `Popen`
  had returned and the worker had become the sole owner of process-group
  cleanup. That cleanup can legitimately consume three bounded termination
  phases, so the parent could mark a live worker as leaked, skip the quiescence
  callback, and retain only an inner cleanup diagnostic. The parent now keeps
  the short budget for a factory still blocked inside `Popen`, but grants the
  complete derived cleanup budget after `owner.completed` proves that no new
  handle can arrive. Process-group polling also reaps an exited leader before
  probing the group again, avoiding a full zombie-only grace interval on
  platforms where `killpg(pid, 0)` reports zombies. A deterministic integration
  test drives cleanup across both budgets and proves one owner, one termination,
  no false leak, and one quiescence callback; a separate regression binds the
  reap-before-reprobe behavior. Python 3.13 passes the 155-test common module,
  the 60-test contract module, the 315-test deterministic supervisor gate, and
  a 20-iteration reproduction probe with zero callback failures. The complete
  host-level Python 3.13 suite passes all 2,299 tests in 430.726 seconds with 6
  expected platform/filesystem skips. Its preceding inner-sandbox run reached
  the same 2,299 tests but could not nest the keychain broker's own
  `sandbox-exec`; that exact test and the complete suite both pass outside the
  enclosing Codex Seatbelt. Ruff lint and changed-file formatting, Python 3.13
  compileall, project-journal validation, the official skill validator, and
  `git diff --check` also pass. No local Python 3.10 run was performed.
- Fresh-context Codex review then found a separate ordinary Git-command
  supervision gap: `run_bounded()` could reap a successful group leader before
  proving that its original process group had no remaining members. A
  background process could therefore outlive the authorized command and keep
  mutating shared Git metadata. Bounded Git commands now start in an independent
  session, bind PID, process-start identity, PGID, and SID before supervision,
  observe leader exit without reaping through `waitid(..., WNOWAIT)`, and prove
  the original process group empty before the single final reap. Cleanup repeats
  `SIGKILL` while a bounded Darwin `libproc` or Linux `/proc` enumeration still
  finds another original-group member; error paths preserve the primary timeout
  or overflow classification and attach cleanup failures as causes. The
  identity-less setup-abort path also proves that the numeric PID is still the
  same unreaped child before signaling its group. Deliberate `setpgid()` or
  `setsid()` escape remains outside this process-group custody contract and is
  not described as covered. Three regressions exercise successful leader exit
  with a resistant child, overflow with detached standard I/O, and selector
  setup failure including the already-reaped-child boundary. Python 3.13 passes
  the 22 directly affected tests, the 60 contract tests, the expanded 318-test
  host-level deterministic supervisor gate in 149.559 seconds, and the complete
  host-level 2,299-test suite in 531.949 seconds with 6 expected
  platform/filesystem skips.
  The exact nested keychain-broker test also passes at host level. Ruff lint and
  changed-file formatting, Python 3.13 compileall, project-journal validation,
  the official skill validator, and `git diff --check` pass. No local Python
  3.10 run was performed.
- Fresh-context review of `faa78095bb7d0b8d0e51562f68adb051885636e0`
  found that the checkout worker's own process group did not own the fresh Git
  sessions launched beneath it, and that a timed-out direct helper could be
  forgotten before another lease-bearing state helper started. Checkout workers
  now install cancellation ownership before the first Git process, defer signal
  delivery to bounded lifecycle checkpoints, retain exact Git process handles
  and group anchors across cleanup failure, and make one fresh closure retry.
  A still-unproven closure is explicit evidence that prevents later failure
  writers and worktree cleanup. Direct helpers likewise receive a second bounded
  termination attempt; any final signaling, waiting, or reaping uncertainty is
  latched process-wide and prevents later helpers, recovery, custody deletion,
  or destructive cleanup.
- Follow-up source audit found four propagation gaps before the replacement
  commit. The phase-0 worker failure path did not reap and classify through the
  common closure record; repository inspection and raw materialization wrapped
  `GitProcessClosureUnproven` as ordinary validation failures; final worktree
  cleanup could write manual-recovery state after an unproven Git cleanup; and
  the direct-helper latch covered repeated timeouts but not other signaling or
  wait failures. All four boundaries now preserve or freshly settle the closure
  marker before any writer. Python 3.13 passes the 5 exact regressions, the
  93-test combined Git/runtime/review/supervisor set, and the expanded
  327-test deterministic supervisor gate in 107.901 seconds. No local Python
  3.10 run was performed.
- An intermediate pre-commit validation used only Python 3.13. The complete host-level
  suite passed all 2,299 tests in 429.182 seconds with 6 expected
  platform/filesystem skips. The 60 repository contract tests, Ruff lint and
  changed-file format gates, compileall, project-journal validation, the
  official skill validator, and `git diff --check` pass. The host Python 3.13
  installation does not include PyYAML, so the official validator ran in a
  Python 3.13 `uv --with pyyaml` environment. No local Python 3.10 run was
  performed.
- Two follow-up read-only marker-propagation audits found five additional
  fail-closed gaps after that intermediate full-suite pass. A post-fork identity
  failure could lose its child receipt; incomplete attempt-supervisor handoff
  cleanup could discard a still-live group; sanitized-view cleanup could delete
  paths before Git closure retry; `run_bounded()` finalizers could replace the
  receipt-bearing marker; and pre-handoff abort could swallow an unresolved Git
  closure. Fork failures now retain a partial `SpawnedProcess`, make two bounded
  PID/original-group settlement attempts before reap, and enter the same
  process-wide latch on final failure. Incomplete handoff proves the entire
  anchored group empty, sanitized views remain retained while Git closure is
  unknown, finalizer diagnostics cannot replace the marker, and pre-handoff
  abort promotes the closure gap into the outer terminal result. Eight exact
  Python 3.13 regressions pass, and deterministic discovery is pinned at 331
  tests. No local Python 3.10 run was performed.
- Final post-audit validation used only Python 3.13. The complete host-level
  suite passed all 2,299 tests in 417.109 seconds with 6 expected
  platform/filesystem skips; the 331-test deterministic supervisor gate passed
  in 116.759 seconds, and the 97-test combined Git/runtime/review/supervisor set
  passed in 61.943 seconds. The 60 contract tests, Ruff lint and changed-file
  formatting, compileall, project-journal validation, the official skill
  validator, and `git diff --check` pass. No local Python 3.10 run was
  performed.
- The final 2026-07-22 master synchronization merged review-result semantics
  from PR 75 and secret-prefix proof accounting from PR 76 without rewriting
  branch history. The only textual conflict combined this workstream's
  local-lane-before-GitHub-request order record with PR 75's review-result
  presentation rules. Host-level Python 3.13 validation then passed all 2,322
  tests with 6 expected skips, the deterministic supervisor gate passed all 331
  tests, and the trusted-Mac live gate passed all 7 tests. Ruff lint and the
  75-file PR-range format gate, compileall, Bash syntax, ShellCheck, actionlint,
  strict launcher C syntax, project-journal validation, the official skill
  validator, `git diff --check`, and the local broker developer reproducibility
  check also pass. No local Python 3.10 run was performed.
- The first current-head GitHub macOS 26.4 hosted no-child gate exposed a
  timing-dependent signature assumption: the rlimit baseline process bound its
  post-exec identity before receiving `SIGKILL`, producing 69 blockers instead
  of the previously calibrated 72, while a same-head rerun produced the earlier
  all-unbound shape and passed. Both runs remained ambiguous, incompatible, and
  non-production-capable on the same pinned runtime. The hosted matcher now
  accepts only two strict rlimit evidence shapes: unbound leader exit, or a
  completely bound `(0, 0)`-rlimit leader killed before evidence. It derives the
  exact blocker set from that shape while retaining all 24 observations,
  runtime identity, parent-limit stability, and exact-set equality. Seatbelt and
  combined observations remain restricted to the bound-then-killed shape.
  Python 3.13 passes the focused 72/69/48-blocker regression and all 331
  deterministic supervisor tests.
- A direct certified Claude Code 2.1.216 lane then completed clean process
  supervision but correctly failed the 2.1.212 strict stream baseline because
  its init and terminal events contained newly added metadata fields. The
  baseline schema and global compatible range remain unchanged. The
  `extended-2x` structural profile now owns the shared 2.1.216-and-later field
  shape, while the exact-selected-version 2.1.216 overlay owns only its nullable
  `estimated_tokens` and `estimated_tokens_delta` fields. The profile digest
  binds both layers into preflight evidence; exact overlays cannot override
  structural fields, malformed metadata is inconclusive, and unreviewed semantic
  constants are blocked. The 53-test Python 3.13 validator module and focused compatibility
  contract tests pass. The complete host-level Python 3.13 suite passes all
  2,329 tests in 282.459 seconds with 6 expected skips, and the independent
  331-test deterministic supervisor gate passes in 86.958 seconds. Ruff lint,
  changed-file formatting, compileall, JSON parsing, project-journal validation,
  the official skill validator, and `git diff --check` also pass. No local
  Python 3.10 run was performed.
- The post-adaptation direct Claude Code 2.1.216 validation used the certified
  executable and the frozen whole-PR range. Process supervision returned zero,
  remained quiescent, produced no stderr or overflow, and the exact-version
  structural profile plus exact nullable estimated-token overlay accepted the
  919,791-byte canonical stream. The validated review artifact was clean,
  confirming that the structural/overlay split admits the observed 2.1.216
  stream without widening the 2.1.212 legacy profile or unrelated exact-version
  semantics.
- The branch subsequently merged default-branch commit
  `8cab8ffeb4b26f2ec74dcc801671624bfabe9fcf` as signed merge commit
  `15c5c79ad310e6934c8c44551738ab87ee14da3b`. The resulting Python 3.13
  host suite ran 2,581 tests with 6 expected skips; its only in-app failure was
  the known nested `sandbox-exec` denial, and the exact broker test passed when
  rerun outside the Desktop sandbox. No local Python 3.10 run was performed.
- A fresh-context Codex review of
  `8cab8ffeb4b26f2ec74dcc801671624bfabe9fcf..15c5c79ad310e6934c8c44551738ab87ee14da3b`
  found two remaining production gaps. The app-server reviewer path authenticated
  only the primary diff even though the evidence format supported bounded nearby
  context, and auth lifetime revalidation relied on independent wall-clock reads.
  The checkout worker now inspects at most 128 size-eligible changed regular
  blobs in raw-path order, skips binary or unrepresentable candidates, and
  authenticates up to 32 UTF-8 head blobs within the existing 64-KiB-per-file
  and 512-KiB-total retained limits. The reviewer restores the exact manifest
  and passes the verified paths through the production input builder. Auth
  evidence now binds wall and suspend-aware monotonic baselines using
  `CLOCK_BOOTTIME` on Linux/WSL and `mach_continuous_time` on Darwin. Locked
  sampling and high-water updates reject rollback and preserve a failed expiry
  decision across retries.
- A separate current Claude Code 2.1.216 calibration run exposed two strict
  launch/schema mismatches before its artifact could count: the direct launch
  omitted `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, so init reported
  `analytics_disabled: false`, and assistant messages carried an optional
  `diagnostics: null` field. The fixed launch environment now requires disabled
  nonessential traffic, while the closed extended stream profile permits
  `diagnostics` only when it is exactly null. Missing diagnostics remains valid;
  any non-null value remains inconclusive. No local Python 3.10 run was
  performed.
- Three focused read-only audits then exercised the finding repairs rather than
  accepting their first implementation. They found that evidence-incompatible
  legal Git paths could block the complete diff, binary candidates could consume
  the text budget, repeated auth checks could lose their clock high water,
  ordinary monotonic clocks did not charge system sleep, concurrent samples could
  commit out of order, an expiry failure was not latched, and `diagnostics: null`
  had been admitted by the legacy stream profile. The final implementation skips
  optional invalid/binary context within a bounded 128-candidate scan, serializes
  suspend-aware clock sampling and commits high water before expiry, and permits
  optional-null `diagnostics` only for `extended-2x`; explicit regressions cover
  every case. No local Python 3.10 run was performed.
- The resulting pre-sync Python 3.13 host suite ran 2,584 tests in 2,252.670
  seconds with 6 expected skips. Its only in-app failure was the known nested
  `sandbox-exec` denial in the one-shot Claude keychain broker test; that exact
  test passed in 2.762 seconds when rerun outside the Desktop sandbox. The
  341-test deterministic supervisor gate, 78-test helper integration set,
  162-test validator/contract set, Ruff lint and formatting, compileall, JSON
  parsing, project-journal validation, the official skill validator, and
  `git diff --check` also pass. No local Python 3.10 run was performed.
- The final default-branch synchronization advanced through
  `bea5e7ad1312be1c15a0af7785eda74a8fb5282d` and resolved eight textual
  conflicts without discarding either policy line. The trusted, manifest-bound
  `named_lane_guard` remains the self-migration control-plane skeleton, while
  the branch's terminal-local-lanes-before-GitHub-request rule, structural
  stream profiles, and exact-version overlays remain explicit. The integrated
  runtime additionally routes regular-file monitor creation through the common
  thread-start wrapper, binds `version_adaptations` into the stream-validator
  compatibility profile, and forces
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` in the formal Claude child
  environment. A repository contract now rejects retained merge markers in
  every manifest-bound guard source.
- Post-integration validation used only Python 3.13. Ten exact runtime/provider
  regressions, the 190-test validator/contract set, the 163-test named-lane
  module, the 198-test common-runtime module with one expected platform skip,
  and the 341-test deterministic supervisor gate all passed. Full discovery ran
  2,787 tests in 1,767.498 seconds with 6 expected skips; its sole in-app failure
  was the known nested `sandbox-exec` denial in the one-shot Claude keychain
  broker test, and that exact test passed outside the Desktop sandbox in 3.056
  seconds. Ruff lint, Python 3.13 compilation, strict launcher C syntax, both
  official skill validations, project-journal validation, `git diff --check`,
  and the Xcode 26.6 developer broker byte-reproducibility check passed. Ruff's
  format check reports only five pre-existing default-branch formatting
  deviations outside this workstream's added lines; they remain unchanged to
  avoid unrelated churn. No local Python 3.10 run was performed.
- The first formal fresh-context Codex review of
  `bea5e7ad1312be1c15a0af7785eda74a8fb5282d..863e72c9df881812a25d035c5e29c16a10a6b0f5`
  found that preflight admitted the raw 4-MiB primary-diff limit without
  charging canonical JSON escaping against the final 5-MiB evidence-bundle
  limit. The repaired path briefly acquires the existing authenticated source
  custody before attempt creation, reads and verifies the held diff, and uses
  the same primary-only bundle constructor as the runtime. CJK, backslash,
  exact serialized-boundary, invalid-content, and no-attempt CLI regressions
  are now part of the fixed 345-test deterministic supervisor identity. That
  gate passes all 345 tests in 149.728 seconds. A full Python 3.13 discovery ran
  2,787 tests in 2,100.850 seconds with 6 expected skips; the only implementation
  failure was the known nested Desktop `sandbox-exec` denial in the one-shot
  keychain broker test, while the other failure was the stale repository
  contract count updated in this same change. The exact repository-contract
  regression then passed, and the exact broker test passed outside the Desktop
  sandbox in 3.067 seconds. Python 3.13 compilation, Ruff lint, focused
  formatting, both skill validators, project-journal validation, strict Linux
  launcher C syntax, and `git diff --check` also pass. The whole-file Ruff
  format check still reports the pre-existing `test_contracts.py` deviation;
  this change does not reformat that unrelated file. No local Python 3.10 run
  was performed.
- The second formal fresh-context Codex review of
  `bea5e7ad1312be1c15a0af7785eda74a8fb5282d..9e34b1539f0ec4293aafea651fe9497589ee57d0`
  found that final-message validation rejected every non-clean finding that
  quoted the exact `No findings.` sentinel. The validator now treats only an
  exact normalized sentinel as clean and preserves every other non-empty
  message as findings, including contradictory output and an inline quoted
  sentinel. The focused 22-test prompt/app-server regression set, Ruff lint
  and formatting, `git diff --check`, and all 345 deterministic supervisor
  tests pass under Python 3.13.
- Before refreezing the final review range, the branch incorporated
  default-branch commit `35271bec152f1ccaf484ffa738948d17107f42f9`
  through signed merge commit `a246f1c1ff37fbfb47b69f62913ae274295e49df`.
  The incoming private-layout test compatibility change merged without
  conflicts. All 255 affected contract and named-lane tests and all 345
  deterministic supervisor tests pass under Python 3.13 after integration.
