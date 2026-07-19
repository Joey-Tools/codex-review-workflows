---
id: 20260715-7c1501
title: Claude CLI Platform Capabilities
status: completed
created: 2026-07-15
updated: 2026-07-17
branch: codex/claude-cli-trust-followup
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/46
supersedes: []
superseded_by: 20260717-c17a11
---

# Claude CLI Platform Capabilities

## Summary

- The user asked to remove the operational friction caused by pinning the review
  helper to one Claude Code CLI patch while preserving the review lane's
  credential, provenance, and isolation boundaries.
- The target policy accepts publisher-verified Claude Code releases
  `>=2.1.187,<3.0.0`; it does not pin `latest` or one current patch release.
- Claude Code was the only helper CLI with an exact executable-version pin.
  Codex CLI and Copilot CLI already use identity, capability, and output
  verification without an exact CLI version; their model IDs, and the Claude
  Code/Copilot reviewer model IDs, remain intentionally pinned.
- The user explicitly distinguished provenance of the executable that will
  receive review data and credentials from wrapper/script rejection. Native
  file format and platform compatibility are not publisher identity.

## Current State

- The runtime trust contract is recorded in
  `skills/review-orchestration-playbook/references/claude-runtime-trust.md` and
  summarized in the skill and helper contracts. The worktree implementation now
  contains the corresponding version, provenance, capability, Linux sandbox,
  and credential paths. The earlier exact-archive Linux validation is recorded
  below; the final follow-up head is revalidated again before PR 46 merges.
- Publisher provenance is based on Anthropic's fixed release-signing GPG
  fingerprint plus the signed per-version manifest and platform checksum.
  macOS code signing and notarization are not current acceptance gates; they may
  be future optional defense-in-depth checks, but cannot replace the manifest.
- Every synchronous manifest/signature fetch runs under one process-level
  absolute deadline spanning DNS, connection/TLS, response headers, bounded
  body reads, and teardown. It fails closed before egress when the main-thread
  timer cannot be installed without replacing an existing process timer or
  when `SIGALRM` is blocked. Cleanup ownership is recorded before signal/timer
  mutation, and the previous handler is restored only after the timer is known
  to be disarmed.
- The fixed-path native GPG source is a host-trust dependency used to verify the
  signature, not part of Anthropic publisher provenance. It must pass
  native-format, owner, executable-mode, and stable file/path checks. Linux/WSL2
  accepts only root-owned `/usr/bin/gpg{,2}`. macOS may also accept canonical
  same-user Homebrew GPG; only root/current-user-owned Homebrew directories with
  the exact `admin` group may be group-writable, while verifier and dependency
  files must not be group/world-writable. That `admin` group is an explicit
  macOS host TCB boundary. The helper retains a stable source descriptor, copies
  it into a fresh current-user `0700` home below an explicit helper-owned private
  root, and publishes a `0500` execution snapshot. Copying the main executable
  does not freeze libraries loaded later: fixed root-owned `/usr/bin/otool`
  recursively captures the macOS Mach-O closure, requires the main executable
  to select exactly `/usr/lib/dyld`, rejects loader commands in dependencies,
  limits non-sealed dependencies to canonical Homebrew `opt`/`Cellar` roots,
  and rejects mutable dyld search commands. Sealed macOS endpoints terminate
  traversal as platform TCB; every
  non-sealed Homebrew branch is recursively captured. Linux/WSL2 proves the
  loader-visible `PT_DYNAMIC` table maps consistently through exactly one file-
  backed `PT_LOAD` at byte and loader-page granularity, rejects other page-
  rounded mappings over that table, rejects `DT_RPATH`/`DT_RUNPATH` and
  `DT_AUDIT`/`DT_DEPAUDIT` in the main snapshot before a loader process may run,
  and requires the canonical x64/arm64 glibc interpreter. The helper captures
  the loader's lexical/resolved root-owned identity, proves native mount
  provenance, matching architecture, `ET_DYN` type, no second interpreter or
  unsafe tag, and a floating glibc version `>=2.27,<3.0`. It invokes that loader
  directly with `--list`, rejects unsafe dependencies after the proven trace but
  before GPG, and rebuilds the same loader version and closure for exact equality
  before every GPG call. Musl and unknown host-GPG loaders are unavailable. Only the
  private snapshot may traverse
  a root-owned exact-`01777` system-temp ancestor. Its non-final directories use
  device/inode/type/mode/owner/group anchor identities so GPG may create sibling
  keyring/lock files without invalidating the closure; the executable itself,
  glibc loader, and dependencies retain full identities. On WSL2, mountinfo proves both
  old and refreshed snapshot, loader, lexical dependency, and resolved endpoint
  paths are Linux-native. An already safe `otool` launch/nonzero failure is
  inconclusive. The runtime report records the fixed source path as
  `gpg_verifier`, separately from publisher provenance.
- GPG and Linux security-sensitive host-tool calls use explicit minimal
  environments. Inherited dynamic-loader variables, shell startup state,
  compiler flags, and toolchain overrides cannot influence GPG, loader/`ldd`, tool
  capability probes, or launcher compilation.
- Native Mach-O/ELF shape, execute permission, architecture, and Linux libc
  target only exclude scripts, interpreter wrappers, and incompatible artifacts;
  they do not prove publisher identity.
- Before provenance, version identity runs without network, workspace, or
  credentials. Its environment is constructed from a fixed allowlist rather
  than filtered caller state, so credential-bearing proxy URLs, custom CA
  paths, authentication values, review metadata, and unrelated variables never
  reach an unverified candidate. Linux/WSL2 uses a synthetic-root bootstrap
  sandbox with only root-owned, non-group/world-writable system library roots
  and does not run `ldd`. Only after the signed checksum passes may trusted
  root-owned `ldd` collect exact read-only dynamic dependencies for the final
  sandbox.
- Immediately after the signed manifest, size, and SHA-256 checks pass, the
  helper materializes a digest-keyed `0500` copy inside its current-user-only
  verified executable snapshot directory. The same snapshot is captured before
  the model chain and runs bounded help, post-provenance dependency discovery,
  authentication-bearing preparation, and every model attempt; the original
  package-manager path is not executed again or rediscovered between attempts.
- Compatibility accepts the version range, requires every public option used by
  the real helper commands to appear uniquely in bounded help, and parses the
  required safe-mode meanings without exact-matching complete help text.
  Missing, negated, duplicated, or contradictory semantics fail closed. There
  is no credential-free fixed-input behavioral canary; the final real invocation
  and strict structured-output/effective-model validation provide behavioral
  evidence, while model and effort remain explicit launch arguments.
- The helper explicitly requires Python 3.10 or newer before importing its
  runtime modules, and CI runs the minimum supported version on both platforms.
- The third fixed-range review found that treating the safe-mode description as
  one keyword bag still allowed a negated sentence to retain every required
  token. The repair validates separate positive claims for customizations,
  managed policy, runtime behavior, and the environment assignment. Terms use
  token/phrase boundaries; relevant claims reject negation, exceptions,
  conditions, contrast, modality, temporal/default weakening, and opposite
  states. `CLAUDE_CODE_SAFE_MODE=1` must be the one exact assignment, while an
  unrelated sentence may still contain harmless negation. After removing the
  one option-declaration token, any additional safe-mode self-reference fails
  closed unless the whole sentence matches a bounded positive template:
  continued enforcement, a direct required action, preserved
  auth/policy/runtime behavior, or an explicit prohibition on
  disabling/bypassing safe mode. Literal `safe mode`, `safe-mode`, and
  `--safe-mode` names share one token rule. Once a self-reference appears, its
  anaphoric antecedent remains active through the complete option block; both
  subject and object pronoun continuations must match positive templates. This
  avoids an open-ended negative-wording parser while still admitting bounded
  harmless wording changes.
- A later PR-readiness review found a temporal reversal that still satisfied the
  customization keyword set: text could claim customizations were disabled and
  then restored after startup. Customization disablement now uses a bounded
  whole-sentence positive grammar. It requires that the enumerated
  customizations start, are, remain, or stay disabled, optionally for a bounded
  whole-review/session duration. It rejects execution before disablement,
  restoration after startup, conditional or temporary transitions, unsafe
  enumerations, and additional relevant sentences that do not independently
  satisfy a positive grammar. A later residual audit replaced the remaining
  customization-name enumeration with true per-sentence default denial: every
  sentence must match a bounded customization, policy, runtime, environment,
  positive self/anaphoric, or online-information grammar. This also rejects
  unknown surfaces such as `.claude/settings.json`, `CLAUDE.local.md`, auto
  memory, and context shims regardless of their verb. The real `2.1.202`
  troubleshooting-purpose suffix is explicitly bounded and accepted; harmless
  whitespace wrapping around the enumeration remains accepted.
- That review also found that strict `O_NOFOLLOW` reads rejected standard
  OpenSSL hash directories. CA directories are now pinned by descriptor and
  enumerated with explicit entry bounds. The bounded link resolver supports the
  Ubuntu layout `hash.0 -> local-name.pem -> /usr/share/...crt`, validates every
  traversed link/directory and the final stable regular-file descriptor, and
  writes only extracted certificates as private `0600` regular files under the
  original hash basename. Linux/WSL2 similarly builds a helper-private bundle
  and revalidates its complete resolved path identity while serializing the
  `bubblewrap` command. As with runtime-library mounts, this does not claim an
  FD-bound atomic handoff against another same-euid process.
- `NODE_EXTRA_CA_CERTS` is now the sole Claude-specific Node TLS input. It
  passes the existing fail-closed CA-file validation and private-copy boundary;
  macOS exposes only the exact helper-owned copy, while Linux/WSL2 reuses one
  fixed-path private bundle. Node-only configuration retains default system
  trust, replacement CA inputs preserve their existing semantics, and Node
  certificates are appended and deduplicated. Codex, Copilot, pre-provenance
  probes, proxy/GPG host tools, arbitrary `NODE_*`, TLS-verification bypasses,
  and private-key inputs remain outside this behavior.
- The helper uses layered enforcement. Seatbelt on macOS and `bubblewrap` plus
  `socat` on Linux/WSL2 enforce host filesystem, process, write, and network
  isolation. On Linux/WSL2, the publisher-verified Claude permission engine is
  an additional trusted boundary between runtime authentication reads and
  model-visible file reads. WSL1 and native Windows remain unsupported.
- macOS accepts official thin arm64 and x64 artifacts and selects the signed
  manifest entry from the artifact architecture. An x64 artifact may run through
  Rosetta on Apple Silicon, so the policy does not require exact host-CPU
  equality; the actual bootstrap probe must still execute successfully.
- WSL2 is positively classified only when the kernel release or version has an
  explicit `wsl2` or `microsoft-standard` identity marker. `/run/WSL`, any
  nonempty `WSL_INTEROP` value (including an invalid or missing endpoint),
  distro environment, binfmt evidence, and a generic `microsoft` kernel identity
  remain conservative weak WSL-presence signals. They do not prove WSL2 and may
  classify ambiguous or spoofed state as unsupported WSL1. If a guest removes
  both the marker and
  every weak signal, it is observationally indistinguishable from native Linux
  and follows that classification. The common Linux/WSL mount guard therefore
  rejects positive DrvFS/Windows provenance independently of WSL classification,
  while positively identified WSL2 additionally requires proven native Linux
  backing.
- WSL2 requires the Claude executable, local-login credential, frozen review
  state, and all helper runtime state—including the provenance cache and
  verified snapshot—to remain in the WSL Linux filesystem. In addition to the
  fast lexical/resolved `/mnt/<drive>` rejection, the helper strictly parses
  bounded `/proc/self/mountinfo` and rejects DrvFS/Windows provenance reached by
  custom automounts, bind mounts, or aliases. Missing, malformed, oversized,
  non-canonical, or non-covering mount information fails closed.
- Repository CI keeps the exact required `test` status context as an
  `always()` aggregate over the Ubuntu and macOS `platform-tests` matrix. The
  aggregate succeeds only when the complete matrix result is `success`, so a
  failure, cancellation, or skipped dependency cannot satisfy the branch rule.
- Existing Linux helper runtime directories are validated without mutation:
  they must already be real current-user paths with the required owner/mode and
  stable no-follow identity. The helper creates a missing directory once but
  never follows a symlink or `chmod`s an unsafe existing path into compliance.
- Post-provenance dynamic-loader and library paths retain complete component
  identities from discovery through sandbox construction and are revalidated
  again for the final mount set. The fixed no-shell Linux launcher blocks and
  checks pending termination signals across proxy/workload process-group
  handoffs, forwards cancellation to both groups, and reaps leftovers.
- macOS local login retains the one-shot Keychain broker. Linux and WSL2 mount a
  helper-owned read-only private copy of the validated current-user `0600`
  credential for runtime authentication; read-only prevents mutation, while the
  separate file-tool policy below prevents model-visible reads. Linux/WSL2
  perform no warmup or refresh; every model attempt independently requires the
  host credential to cover that attempt's 30-minute timeout plus the 2-minute
  safety margin, then creates a new private staged copy. An explicit API key
  skips local credential staging.
- Linux credential staging owns cleanup from the first successful file create:
  a write, sync, or mode-finalization failure zeroes and unlinks the partial
  credential before control returns. If unlink itself fails, the staged bytes
  are still zeroed, the cleanup failure is reported, and directory cleanup does
  not replace it with a less useful `rmdir` exception. Cancellation,
  `GeneratorExit`, scrub interruption, and an indeterminate failed `close` all
  still reach unlink; after a failed close the same numeric descriptor is never
  retried, and cleanup reopens only through the private no-follow path.
  Cleanup-time control-flow exceptions remain control-flow exceptions after
  unlink/rmdir attempts; an existing body exception remains primary and gains
  a visible cleanup diagnostic on both Python 3.10 and newer runtimes.
  The validated source fd also closes before its payload may be returned; a
  failed close zeroes that payload, keeps earlier validation/control-flow
  errors correctly classified, and never retries the numeric descriptor.
- The second fixed-range review found that a read-only `/config` mount prevented
  credential mutation but did not stop Claude's model-visible file tools from
  reading the staged credential. API-key mode also exposed a carrier through
  `/proc/self/environ`. The repair keeps the floating `>=2.1.187,<3.0.0` range
  instead of forcing `2.1.208`: Linux/WSL2 now uses `dontAsk`, exposes only
  `Read`, allows only `Read(./**)`, explicitly denies every non-workspace
  synthetic-root mount with absolute double-slash rules, and rejects ASCII `@`
  file mentions before authentication and again at each attempt. macOS retains
  its existing `default` plus `Read,Grep,Glob` contract.
- Linux sandbox command construction strictly parses the final settings and CLI
  policy, requires both root and recursive denies for all mounted top-level
  paths, and rejects a separate mount below `/workspace`. A future mount cannot
  silently become model-readable. `/config` protects the staged local-login
  copy; `/proc` and `/dev` denies protect an API key and descriptor aliases.
  The original host credential is never mounted.
- Retained `claude-runtime.json` state records both `source_executable` and the
  actual `verified_executable` snapshot, plus the selected GPG verifier and
  signed-release evidence. On macOS, its phases distinguish publisher and
  capability verification, per-attempt authentication outcomes, runtime launch,
  and attempt completion. Linux/WSL2 publishes `runtime-ready` only after the
  current attempt's credential staging and isolation probe; an unavailable
  credential prevents that phase. Bounded supervisor failures instead advance
  to `attempt-inconclusive` with a stable failure class. Nested sandbox,
  authentication, and attempt statuses avoid claiming final enforcement before
  the relevant probe or launch occurs.
- The former exact `2.1.187` plus artifact-digest pin entered with local-login
  and Keychain hardening because Claude Code receives credentials and review
  data, and one fixed binary made that trust contract easy to audit. Wrapper
  rejection was only one input-shape gate. The replacement preserves publisher
  provenance and execution stability while allowing compatible signed 2.x
  releases to float.
- Candidate discovery and failure classification preserve the same trust
  distinction. Failure to resolve or stat the selected executable is an
  inspection-I/O ambiguity and is therefore inconclusive, never ordinary
  unavailability. For automatic discovery, a clean absence of trusted GPG,
  probe sandbox, or trusted review-tool prerequisites may still follow the
  explicitly authorized Copilot fallback. The same prerequisite absence under
  `CODEX_REVIEW_CLAUDE_PATH` is a blocked configuration error because the user
  explicitly selected that path; authentication and loopback unavailability
  retain their existing authorized fallback behavior.

## Next Steps

- None for this workstream.

## Evidence

- Exact-version identity and Homebrew digest pin entered canonical `master` in
  `a483bad04585b121a4766da9bc4c446c4ad46114` (`Default Claude reviews to local
  login (#42)`).
- Topic history identifies the two policy steps as
  `2e8342e3469d1320bf11964fc1982808dedfe999` (`Harden Claude credential and tool
  preflight`) and `ba40ba3fd65b67ad1cb3605e2533f4cf15880737` (`Pin trusted Claude release
  digests`).
- A real local integration check against installed Claude Code `2.1.202`
  verified Anthropic's signed `darwin-arm64` manifest with the stable-descriptor
  private GPG execution snapshot, matched SHA-256
  `7414f707861e2fe5afef33a466f888a8d2170e5028f5e9d2858f1d3ef45ffca5`,
  materialized the private Claude executable snapshot, and ran the version/help
  capability validation from that snapshot. This check did not expose review
  content or credentials.
- The complete helper test suite passed locally: 406 tests in 69.789 seconds,
  with six environment-gated tests skipped. The touched `common.py` tests also
  passed independently: 33 tests in 4.481 seconds.
- After the first fixed-range Codex review, three P2 findings were corrected:
  Linux launcher compilation unavailability now preserves authorized fallback,
  release downloads enforce a monotonic total response deadline, and CA sources
  are read through one stable no-follow descriptor with strict byte and identity
  checks. The expanded local suite then passed 414 tests in 67.493 seconds with
  six environment-gated tests skipped.
- A hash-matched archive plus the bounded portability patch was validated on
  `codex-hoteng-srv-01` under a private Linux-filesystem task directory. The
  remote full suite passed 414 tests with three skips; provider tests passed 180
  tests with two skips; and Linux runtime tests passed 34 tests with one skip.
  The real `bubblewrap` namespace-shape probe passed. The final opt-in isolation
  integration remained explicitly dependency-blocked because the host lacks a
  trusted native `/usr/bin/socat`; no remote package or repository was changed,
  and the Ubuntu CI job installs `socat` before running that test.
- The credential/file-tool repair's focused capability, Linux runtime, provider,
  and repository-contract suites passed 239 tests with six environment-gated
  skips. The same focused change passed `ruff check`, `py_compile`, and
  `git diff --check` before the final full-suite and remote reruns.
- The final complete suite passed locally with 422 tests in 68.156 seconds and
  six skips. The hash-matched final snapshot passed all 422 tests on
  `codex-hoteng-srv-01` in 30.548 seconds with three Linux environment skips,
  plus remote `py_compile`, `actionlint`, strict GCC with the production POSIX
  feature macro, and the real `bubblewrap` namespace-shape probe. The remote
  snapshot used a private home-directory task root, a private `TMPDIR`, and
  non-writable source parents; an initial `/tmp`/group-writable staging shape
  was rejected by the trusted-path tests as designed. The CA in-place mutation
  fixture now forces a distinct metadata timestamp so coarse or same-tick Linux
  filesystems exercise the intended race classification deterministically.
- After the third fixed-range review, the safe-mode continuation and CA-link
  repairs expanded the complete local suite to 456 tests; all passed in 65.348
  seconds with nine environment-gated skips. The final focused local provider
  suite passed 201 tests with six skips. On `codex-hoteng-srv-01`, the same CA
  implementation passed all 199 provider tests with two skips, materialized the
  host's real `/etc/ssl/certs` directory, read the default CA bundle symlink,
  passed the Ubuntu hash-link focused matrix, and preserved the correct base for
  an absolute input whose final symlink target is relative. Remote temporary
  state was removed after validation.
- A final portability audit added `ssl.get_default_verify_paths().capath` to the
  Linux default trust sources. A capath-only fixture with both a regular PEM and
  its OpenSSL hash symlink passed through the same stable directory descriptor,
  global entry/input/output limits, and certificate deduplication as configured
  `SSL_CERT_DIR` inputs.
- The stricter parser accepted the unmodified bounded help from the installed
  Claude Code `2.1.202` and rejected the negated, conditional, contradictory,
  imprecise-assignment, and anaphoric-continuation fixtures. The final touched
  Python files passed `ruff check` and `py_compile`; both C helpers passed strict
  Clang syntax checks; `actionlint`, the isolated-PyYAML skill validator,
  `git diff --check`, and the project-journal validator all passed.
- The final CA race fixtures explicitly set private file and directory modes,
  so they exercise their intended identity/content cases independently of the
  invoking user's `umask`. The Linux-focused suite passed 44 tests with three
  skips both normally and under `umask 000`; the full local suite passed all 456
  tests in 57.787 seconds with nine environment-gated skips.
- Git commit `f815dff` was exported as a Git archive with SHA-256
  `583a2320e396bc411ccfe4e33158e5aec75af478520a1cca673262777ab08c0c`;
  the copied archive matched that digest on `codex-hoteng-srv-01`. After the
  extracted source parents were normalized to remove group/other write bits,
  the exact snapshot passed all 456 tests in 35.935 seconds with three Linux
  environment skips, remote `compileall`, `actionlint`, and strict GCC launcher
  compilation. The trust checks deliberately rejected the archive's original
  group-writable source-parent mode before normalization. The opt-in real
  `bubblewrap` plus `socat` isolation integration remains dependency-gated on
  this host because `/usr/bin/socat` is absent; no host package was installed.
- GitHub rulesets `16583548` and `16590367` require the exact `test` and
  `codex/review-gate` contexts on the default branch; the active pull-request
  rulesets allow squash merge only. `actionlint` and the 12 repository contract
  tests passed after the stable aggregate job was added.
- The subsequent fixed-range Codex review found one P2 in the staged-credential
  error path: a partial `.credentials.json` could survive a failed write before
  the caller received its path, and `rmdir` could mask the original exception.
  Fault-injection coverage now exercises partial write, `fsync`, `fchmod`, and
  unlink failures. The focused credential suite passed all six tests; the
  expanded full local suite passed all 460 tests in 63.053 seconds with nine
  environment-gated skips, plus `ruff`, `py_compile`, and `git diff --check`.
- The implementation-bearing commit `fa6f5f2` was exported with SHA-256
  `13fabba8c5828c6b2732a73da43639d2a3544e01b938a115564835da695f3d3e`,
  and the copied archive matched on `codex-hoteng-srv-01`. Its exact snapshot
  passed all 460 tests in 36.677 seconds with three Linux environment skips,
  plus remote `compileall`, `actionlint`, and strict GCC launcher compilation.
- A narrow credential-lifecycle audit then found two P2 cancellation/close
  gaps, and the fixed-range Codex review of `c4b1918` found two P1 findings
  (undeclared Python minimum and an explicit safe-mode self-reversal) plus one
  P2 (URL-open phases outside the total fetch deadline). The repairs add
  `KeyboardInterrupt`, body-exception, `GeneratorExit`, close-failure,
  safe-mode-self-contradiction, and stalled-header fault coverage. Python 3.9
  now exits at the entrypoint with the declared 3.10 requirement instead of
  failing after a partial runtime import. The expanded full local suite passed
  all 467 tests in 61.898 seconds with nine environment-gated skips.
- Review-fix commit `66cb334` was exported with SHA-256
  `5402a815ccde0944d99ba99b8bb5835edb18b7baf9059736d92d2687bbfb8e96`;
  the copied archive matched on `codex-hoteng-srv-01`. Its exact snapshot passed
  all 467 tests in 35.978 seconds with three Linux environment skips, plus
  remote `compileall`, `actionlint`, and strict GCC launcher compilation.
- The final bounded security audits closed process-deadline signal-mask and
  cleanup-ownership gaps, source/staged credential close and control-flow
  faults, Python 3.10 cleanup diagnostics, and safe-mode self/anaphoric parser
  bypasses. Independent focused audits reported no remaining P0-P2 findings.
  The installed Claude Code `2.1.202` still passed its unmodified version/help
  capability probe with all 16 required options. The final complete local suite
  passed all 483 tests in 59.653 seconds with nine environment-gated skips.
  `ruff`, `compileall`, `actionlint`, strict C syntax checks for both helpers,
  `git diff --check`, project-journal validation, and the isolated-PyYAML skill
  validator also passed.
- Pre-final review input commit `1bed9d5` was exported as a Git archive with
  SHA-256 `a1ea3165c651280d6aecf36498d1da37ad97c0f36f036d46a1afa7f92456dd9c`;
  the copied archive matched that digest on `codex-hoteng-srv-01`. The exact
  Linux snapshot passed all 483 tests in 36.395 seconds with three explicit
  platform/opt-in skips, followed by remote `compileall`, `actionlint`, and
  strict GCC syntax checks for both C helpers. One non-failing Python
  `ResourceWarning` reported a test subprocess object as still running during
  collection, but the process was reaped and the complete suite exited zero.
  Both the private remote task directory and local archive were removed after
  validation.
- The subsequent fixed-range Codex review of `0682597..5fed950` found one P1:
  WSL2 signature verification still created its private GPG home and verifier
  snapshot below `/tmp` without proving that the covering mount was not DrvFS.
  The repair removes the implicit temp-root default and requires the caller to
  supply a helper-owned `0700` root inside isolated review state. The provenance
  verifier identity-checks the requested/resolved paths and complete parent
  chains; WSL2 batches that chain against one bounded mountinfo snapshot before
  private-home creation and before every GPG call. Windows-backed provenance is
  invalid, unavailable or malformed mount evidence is inconclusive, and an
  existing unsafe directory is rejected without `chmod` repair. Regression
  coverage includes direct and ancestor DrvFS mounts, a Linux submount below a
  DrvFS parent, single-read batch behavior, malformed/missing mountinfo,
  symlinked parents, identity mutation, and pre-home/pre-GPG rejection. The
  three touched runtime suites passed 331 tests with nine skips; the final
  expanded local suite passed all 492 tests in 61.194 seconds with nine skips. A
  real macOS smoke reverified installed Claude Code `2.1.202` against the signed
  `darwin-arm64` manifest, reproduced SHA-256
  `7414f707861e2fe5afef33a466f888a8d2170e5028f5e9d2858f1d3ef45ffca5`,
  materialized the helper-owned `0500` executable snapshot under the new
  explicit private GPG root, and passed the snapshot version/help capability
  probes without review content or credentials.
- Review-fix commit `ba81a37` was exported as a Git archive with SHA-256
  `680d03b5c0866c9aa44c96b411044dea67a12bee8582fcdfbf80e6b5a0db6890`;
  the copied archive matched on `codex-hoteng-srv-01`. As intended, the first
  extracted run rejected Git archive directories carrying group-write bits.
  After removing group/other write bits only from the private extracted copy,
  the exact snapshot passed all 492 tests in 37.113 seconds with three explicit
  platform/opt-in skips. One non-failing `ResourceWarning` again reported a
  test subprocess object while collection was still running; the process was
  reaped and the complete suite exited zero. Remote `compileall`, actionlint
  over both explicit workflow paths, and strict GCC syntax checks for both C
  helpers passed. The host's installed Claude Code `2.1.196` also matched the
  signed `linux-x64` manifest SHA-256
  `eb933c6dd5534db89b83ba09009d5c0932bd1395f7e3bb0f34ba37eec37bbade`
  and produced a helper-owned `0500` snapshot with `/usr/bin/gpg`; its sandboxed
  version/help capability probe remained explicitly dependency-blocked because
  the host has no trusted native `socat`. No package was installed or boundary
  bypassed. The private remote task directory, local archive, and smoke scripts
  were removed after validation.
- The corrected whole-range Codex review of `0682597..7e1173f` found one P2:
  WSL2 mountinfo read, parse, or coverage uncertainty could still be caught as
  generic runtime unavailability at review-state and runtime-root checks,
  authorizing an otherwise prohibited Copilot fallback. The repair preserves
  `LinuxRuntimeInspectionInconclusive` as
  `ClaudeExecutableInspectionInconclusive` at every WSL path-provenance
  boundary, including review state, runtime state, credential source, and
  executable candidate inspection. The accompanying bounded audit found that
  ELF descriptor `open`, `fstat`, `pread`, and `close` errors had the same
  downgrade risk, so those are now inspection-inconclusive while deterministic
  format, architecture, and libc failures remain invalid candidates. Descriptor
  reads use the initial file size and initial/final metadata identities to keep
  stable truncation invalid while treating an in-range short read or metadata
  mutation as inconclusive. A secondary descriptor-close failure no longer
  replaces a format error or control-flow exception; it is attached as a
  visible diagnostic. Known DrvFS coverage is a blocked isolation-boundary
  mismatch rather than runtime unavailability. Nine focused regression tests
  assert these classifications, the absence of Claude-home creation after an
  inconclusive state inspection, preservation of blocked DrvFS results, bounded
  huge offsets, and primary-error retention during close failure. The combined
  Linux/provider suites passed all 274 tests with nine environment-gated skips;
  targeted `ruff` passed, followed by the complete local suite at 501 tests in
  55.926 seconds with nine environment-gated skips. `compileall`, `actionlint`,
  strict direct `/usr/bin/clang` syntax checks for both C helpers,
  `git diff --check`,
  project-journal validation, and the isolated-PyYAML skill validator all
  passed. The earlier PATH-resolved Clang attempts were blocked by an
  environment `ccache` temp-directory permission error and were not counted as
  validation evidence; likewise, the first skill-validator attempt lacked
  PyYAML and was replaced by the passing isolated dependency run. Two bounded
  internal code-review iterations found the close-error and short-read gaps;
  the final code and test/documentation reviews both reported `No findings.`
- Final implementation commit `7ecb26a` was exported as a Git archive with
  SHA-256 `f7cb62d80c8cbc62e60b0ceb16113a17ba41c2c9f345714e67810e312a86de6a`;
  the copied archive matched that digest on `codex-hoteng-srv-01`. After the
  private extracted source copy had its Git-archive group/other write bits
  removed, the exact snapshot passed all 501 tests in 37.323 seconds with three
  explicit platform/opt-in skips, followed by remote `compileall`, `actionlint`
  over both workflow files, and strict GCC syntax checks for both C helpers.
  The host's installed `/home/codex/.local/bin/claude` resolved to the native
  x64 ELF `/home/codex/.local/share/claude/versions/2.1.196`, targeted glibc via
  `/lib64/ld-linux-x86-64.so.2`, and selected the `linux-x64` manifest entry.
  The real publisher-provenance smoke used fixed `/usr/bin/gpg`, verified the
  Anthropic-signed manifest, matched size `245373752` and SHA-256
  `eb933c6dd5534db89b83ba09009d5c0932bd1395f7e3bb0f34ba37eec37bbade`,
  and materialized the digest-keyed private `0500` executable snapshot. Native
  ELF, architecture, interpreter, and libc validation established that the
  source was an executable artifact compatible with this host rather than a
  script wrapper; the separate signed manifest plus exact size/SHA established
  Anthropic publisher identity. No review content or credential was supplied,
  and the private remote task directory plus local archive/smoke script were
  removed after validation.
- The final whole-range Codex review of `0682597..dace7db` reported one P1 and
  one P2 in the Linux/WSL2 file boundary. The P1's direct Git attack premise was
  already rejected during frozen-tree materialization and the pre-egress
  workspace scan, but the low-level Linux command builder did not independently
  carry that invariant. Frozen Git targets are now required to be relative and
  must never walk outside the workspace, even transiently; immediately before
  every isolation-probe or authenticated sandbox command is serialized, a
  bounded no-follow identity scan rechecks the complete workspace. Stable
  internal relative links remain supported, while `/config`, `/proc` magic
  links, absolute or chain escapes, loops, races, and inspection failures fail
  closed. Final-command inspection uncertainty is preserved as
  `ClaudeExecutableInspectionInconclusive`, so it cannot authorize Copilot
  fallback.
- The P2 correctly identified that overlay/FUSE mountinfo strings could hide
  Windows-backed storage. WSL2 mount provenance is now explicitly three-state:
  known DrvFS/Windows evidence is blocked; only ext4 with WSL `/dev/sdX` source
  and backing-free tmpfs are accepted; overlay, FUSE, 9p, virtiofs,
  loop/device-mapper/network-backed, and unknown filesystems are
  inspection-inconclusive. Overlay backing paths are deliberately not parsed as
  proof because mountinfo cannot bind those strings to the kernel-held backing
  dentries. The design trusts the WSL kernel's mountinfo report and excludes a
  malicious WSL root. Legal mount-option comma/colon escapes are decoded once,
  while unknown escapes remain fail-closed. Regression coverage includes both
  authentication carriers, internal links, transient escapes, indirect block
  sources, same-depth mixed mounts, and parser escapes. An internal repair audit
  found that the first symlink limit counted materialized intermediate
  directories even though the frozen Git entry limit does not; the final limit
  counts only symlinks, with deep-directory coverage proving that ordinary tree
  shape cannot consume it. The three touched suites passed all 337 tests with
  nine skips; the complete local suite passed all 511 tests in 62.975 seconds
  with nine environment-gated skips. Final code and test/documentation audits
  both reported `No findings.`, and targeted
  `ruff`, `compileall`, `actionlint`, `git diff --check`, project-journal
  validation, and the isolated-PyYAML skill validator passed.
- Review-fix commit `6db9583` was exported as a 250132-byte Git archive with
  SHA-256 `047f6f692b33337c0b45b3e4f88734c6a4a665a1b5b7fdcf4d5bbd420d32985b`;
  the copied archive matched on `codex-hoteng-srv-01`. Its exact normalized
  private snapshot passed all 511 tests in 37.771 seconds with three explicit
  platform/opt-in skips, followed by remote `compileall`, both explicit
  `actionlint` workflow checks, and strict GCC syntax checks for both C helpers.
  A non-failing `ResourceWarning` again reported a test subprocess during the
  run, but the process was reaped and the suite exited zero. An initial logging
  wrapper used zsh's read-only `status` variable after the suite completed and
  was not counted as validation evidence; the direct rerun supplied the zero
  exit status above.
- The same exact Linux snapshot reverified installed Claude Code `2.1.196` as a
  native x64 glibc ELF with interpreter `/lib64/ld-linux-x86-64.so.2`, selected
  the signed `linux-x64` manifest through fixed `/usr/bin/gpg`, matched size
  `245373752` and SHA-256
  `eb933c6dd5534db89b83ba09009d5c0932bd1395f7e3bb0f34ba37eec37bbade`,
  and materialized the digest-keyed private `0500` snapshot. The first smoke
  completed verification but used the wrong result-field name while printing;
  only the corrected zero-exit structured run was counted. No credential or
  review content was supplied. The remote task directory, local archive, and
  smoke script were removed after validation.
- The final whole-range review of `0682597..b6e0b6f` found that the macOS
  pre-provenance version probe still received inherited proxy variables even
  though authentication and review variables were removed. Proxy URLs can
  themselves contain usernames, passwords, or bearer material, so the
  unverified candidate could read credentials before its signed checksum was
  established. The repair replaced the filtered environment with a closed,
  fixed preflight environment containing only safe-mode controls, helper-owned
  home/temp paths, a fixed `/usr/bin:/bin` path, C locale, and no-color output.
  Proxy, custom-CA, authentication, review, and unrelated caller variables are
  structurally absent; publisher-verified review execution still receives the
  helper's authenticated loopback proxy configuration. Exact-dictionary tests
  inject upper/lowercase credential-bearing proxies, API-key and CA variables,
  and an arbitrary secret sentinel to prevent future allowlist drift. A focused
  security audit reported no residual pre-provenance credential exposure. The
  installed macOS Claude Code `2.1.202` returned zero for both `--version` and
  `--help` under the exact minimal environment. The focused regression tests,
  `ruff`, `compileall`, and `git diff --check` passed; the complete local suite
  passed all 512 tests in 65.624 seconds with nine environment-gated skips.
- PR #45's first Python 3.10 CI run exposed two deterministic portability gaps.
  Both platform jobs imported the Python 3.11+ `tomllib` module directly from
  tests even though the helper deliberately supports and tests Python 3.10; CI
  now installs pinned `tomli==2.2.1`, and the tests use it only as the pre-3.11
  fallback. The macOS job also proved that `/tmp` is the root-owned system alias
  for `/private/tmp`: the private proxy-socket validator now accepts only that
  exact root alias while still rejecting every symlink below it. Regression
  coverage exercises the accepted private `/tmp` socket, a private child
  symlink rejection, and the existing non-private-parent rejection. The focused
  macOS socket test passed outside the parent sandbox, the contract and Linux
  suites passed 83 tests locally, and the complete suite passed all 512 tests
  in 67.901 seconds with nine environment-gated skips. `ruff`, `actionlint`,
  and `git diff --check` also passed before the CI-fix commit.
- The next Ubuntu job passed the Python 3.10 import boundary and all 512 test
  bodies except two host-integration assertions. GitHub's runner exposes at
  least one default hashed CA symlink through a group- or world-writable path;
  the helper correctly rejects that mutable trust source. The two tests now
  skip only for the existing unsafe-owner or writable-path safety errors while
  continuing to fail for every other `ReviewError`. Synthetic tests still
  require safe CA symlink traversal and explicitly verify rejection of writable
  parents and targets, so CI portability does not weaken the runtime policy.
- Initial PR-readiness reviews produced two false positives and one actionable
  Linux prompt-path finding. ASCII `@` remains rejected only in the prompt bytes
  sent through Claude's file-mention parser; the frozen diff is separate Read
  input, so decorators, email addresses, npm scopes, and review mentions in
  changed source remain supported. A regression test now proves that boundary.
  Malformed Claude JSON already returns `(None, None)`, records a non-successful
  attempt, and advances `claude-runtime.json` to `attempt-complete`; a direct
  attempt test now proves that retained-state behavior. The actionable issue
  was that the default prompt named host-absolute workspace/diff paths and
  command-oriented probes even though Linux mounts the workspace at
  `/workspace` and exposes only `Read` under the cwd-relative `Read(./**)`
  permission rule. Default prompts now use `.` and `.codex-review/review.diff`
  with tool-aware bounded-read guidance. Linux also
  projects complete host path tokens in custom prompts to sandbox-visible
  `/workspace` absolutes, preserves canonical workspace descendants, rejects
  escaping/non-canonical components and ambiguous sibling/file suffixes,
  appends an explicit Read-only boundary, and rechecks the 64-KiB prompt limit
  before authentication and again at the attempt boundary. Claude's Read tool receives
  absolute `file_path` values while `Read(./**)` remains the separate
  cwd-relative permission rule.
- After the host-CA guard and PR-review regressions, the complete local suite
  passed all 520 tests in 65.259 seconds with nine host-gated skips. `ruff`,
  `compileall`, actionlint, and `git diff --check` passed as well; project-journal
  validation is rerun after each evidence update.
- An exact `5915bf84` archive was also validated on `codex-hoteng-srv-01`
  (Ubuntu x86_64, Python 3.12.3): its local and remote SHA-256 matched
  `9cb891e680a60acfdb38674d57f664806c0d5f5213460a3ba55401a3b4367c79`,
  all 512 tests passed in 41.933 seconds with three expected skips, and
  `compileall` plus actionlint 1.7.12 passed. Both real system-CA integration
  tests passed there. Its `002c0b4f.0` two-hop chain ends at a root-owned 0644
  certificate through root-owned 0755 directories, confirming that the GitHub
  runner result is a host trust-layout difference rather than a Linux-wide
  regression. All local and remote validation artifacts were removed.
- Prompt-projection fix `0723a22e3db9c3bb2a35e6ffe495baf9c840ef8f` was
  exported as a 1341440-byte Git archive with SHA-256
  `2915390dd6595a8a344d00606349836b862afc5ac78f4eba626b0d1a4b1c29a8`.
  The exact archive passed all 520 tests on `codex-hoteng-srv-01` in 38.416
  seconds with three expected skips, followed by `compileall`, actionlint
  1.7.12, and five focused Linux prompt-projection tests. A first wrapper run
  was discarded because its global `umask 077` changed a test fixture's
  expected `0755` mode to `0700`; the counted rerun kept only the task root
  private and used deterministic `umask 022` for the test process.
- Fixed-range PR-readiness review against `0682597..0723a22` produced four
  actionable trust findings. The private GPG main-file snapshot did not freeze
  dynamic libraries opened later, so a mutable Homebrew dependency could forge
  signature output. The safe-mode customization keyword set accepted a claim
  that disabled customizations and restored them after startup. Initial
  executable `resolve`/`stat` I/O failures were misclassified as clean runtime
  unavailability. Finally, an explicit `CODEX_REVIEW_CLAUDE_PATH` could still
  fall back to Copilot when trusted GPG, the probe sandbox, or trusted `rg` was
  missing. Each finding was independently reproduced before repair. GitHub
  Codex found no additional major issue on `0723a22`; its older Linux-path
  thread was answered with the exact fix evidence and resolved.
- Adversarial review of the first GPG closure repair found that Linux direct
  host execution cannot reuse only the resolved identities intended for later
  `bubblewrap` bind mounts: the ELF loader resolves lexical symlinks and search
  policy again at process start. It also found uncaught Python 3.10-3.12
  symlink-loop `RuntimeError` paths and an `otool` launch-race exception. The
  final policy therefore gives host GPG its own loader closure, rejects mutable
  loader search policy, captures lexical and resolved identities, and rebuilds
  the closure for equality before every call; all resolve/launch inspection
  races remain inconclusive rather than authorizing fallback.
- After those repairs, the four focused capability/provenance/Linux/provider
  modules passed all 403 tests with nine environment-gated skips. The complete
  local suite passed all 547 tests in 73.736 seconds with nine skips. Full
  runtime/test `ruff`, `compileall`, Python 3.10 grammar parsing across 20 files,
  both workflow actionlint checks, strict Clang syntax checks for both C
  helpers, `git diff --check`, project-journal validation, and the isolated
  PyYAML skill validator passed. A real macOS publisher smoke used the fixed
  Homebrew GPG source and its six captured non-sealed dylibs to verify installed
  Claude Code `2.1.202` as `darwin-arm64`, size `243631376`, and SHA-256
  `7414f707861e2fe5afef33a466f888a8d2170e5028f5e9d2858f1d3ef45ffca5`.
  No credential or review content was supplied.
- The same source snapshot received focused validation on
  `codex-hoteng-srv-01`: 77 Linux tests passed with one expected skip and all 79
  provenance tests passed. Real root-owned `/usr/bin/gpg` produced a 12-endpoint
  host-execution ELF closure that rebuilt identically, then completed all three
  GPG operations against Anthropic's signed `2.1.202` manifest. The first real
  Linux smoke exposed intentional keyring/lock writes changing the private GPG
  home directory timestamp; non-final snapshot directories now retain anchor
  identities while the final executable remains fully identity-pinned. The
  corrected smoke passed, and local/remote temporary files were removed.
- A final security audit then found four residual fail-open surfaces. Broad
  customization prose could add an unknown positive verb, WSL1 interop markers
  could be mistaken for WSL2, a Mach-O executable could select a custom dynamic
  linker, and ELF audit tags could load code outside the `ldd` dependency list.
  The repair default-denies all extra customization-surface sentences while
  preserving the exact upstream troubleshooting-purpose suffix, requires an
  explicit WSL2 kernel identity marker, requires one main
  `LC_LOAD_DYLINKER=/usr/lib/dyld` and none in dependency images, rejects main
  `DT_AUDIT`/`DT_DEPAUDIT` tags before list-only `ldd`, and rejects dependency
  tags after the trace but before any real GPG operation.
- After that repair, the four focused capability/provenance/Linux/provider
  modules passed all 408 tests with nine environment-gated skips. The complete
  local suite passed all 552 tests in 75.275 seconds with nine skips. Full
  runtime/test `ruff`, `compileall`, Python 3.10 grammar parsing across 20 files,
  both workflow actionlint checks, strict Clang syntax checks for both C
  helpers, `git diff --check`, and project-journal validation passed. The normal
  skill-validator wrapper lacked local PyYAML; its documented isolated
  `uv --with pyyaml` fallback validated the skill successfully.
- The final real macOS smoke verified installed Claude Code `2.1.202` through
  the fixed Homebrew GPG source and recursive six-dependency Mach-O closure,
  matched the signed `darwin-arm64` artifact size `243631376` and SHA-256
  `7414f707861e2fe5afef33a466f888a8d2170e5028f5e9d2858f1d3ef45ffca5`,
  materialized the digest-keyed executable snapshot, and accepted the installed
  release's real safe-mode help contract. The first sandboxed attempt could not
  nest Seatbelt; the narrow host rerun supplied no credential or review data and
  removed its temporary state.
- A final read-only residual audit found three more trust-boundary gaps. The
  customization check still depended on an enumerated noun list and missed
  `.claude/settings.json`, `CLAUDE.local.md`, auto memory, or an unknown future
  surface. A WSL2 guest that removed both its kernel marker and every weak
  interop signal was indistinguishable from native Linux, contradicting the
  earlier unconditional unsupported claim and skipping the DrvFS guard. Finally,
  ELF dynamic tags were read from `PT_DYNAMIC.p_offset` without proving that the
  loader-visible virtual range mapped to the same file bytes through `PT_LOAD`.
- The repair applies true per-sentence default denial to the complete safe-mode
  option block; documents the markerless-guest observability limit; runs positive
  Windows/DrvFS mount-provenance rejection for both Linux and WSL classifications;
  and requires the `PT_DYNAMIC` address, memory, and file-backed ranges to map
  consistently through exactly one `PT_LOAD` before parsing tags or invoking
  `ldd`. Native Linux retains its normal filesystem variety after the common
  positive Windows-provenance rejection, while positively identified WSL2 keeps
  the stricter local-backing allowlist.
- A final ELF mapping review found that raw virtual-range uniqueness was still
  weaker than the Linux loader's page-granular mapping behavior. The final
  inspection therefore requires every `PT_LOAD` file offset and virtual address
  to be congruent at the bounded host page size, rounds memory intervals with
  overflow checks, and rejects any second load segment whose mapped pages alias
  the file-backed `PT_DYNAMIC` pages before an `ldd` subprocess can start.
- The last parser and documentation audit found three bounded residuals. A
  customization anaphor could remain active across intervening policy or online-
  information sentences; it is now accepted only immediately after the
  customization declaration. Semver components now have a nine-digit bound and
  conversion failures stay inside the capability-error classification instead
  of escaping before provenance. Finally, the WSL contract now states the
  implementation's conservative rule that any nonempty raw `WSL_INTEROP` value
  and a generic `microsoft` kernel identity are ambiguous presence signals even
  when the endpoint is invalid or missing; independent regressions cover both
  cases.
- After those final repairs, the four focused capability/provenance/Linux/provider
  modules passed all 420 tests with nine environment-gated skips. The complete
  local suite passed all 564 tests in 67.919 seconds with nine skips. Full
  runtime/test `ruff`, `compileall`, Python 3.10 grammar parsing across 20 files,
  both workflow actionlint checks, strict Clang syntax checks for both C helpers,
  the isolated PyYAML skill validator, `git diff --check`, and project-journal
  validation passed. The real macOS `2.1.202` signed-release, six-dependency GPG
  closure, digest-keyed snapshot, and safe-mode help smoke also passed again
  without credential or review data. Final independent security and
  documentation/contract audits reported no remaining P0-P2 findings.
- Exact commit `2ca3bb3` was exported as a 1484800-byte Git archive with
  SHA-256 `172d4d37121562fcaf305c5eb1295595f70fbe5409a93693ef197a7d0fb6f79e`.
  Its first authoritative run on `codex-hoteng-srv-01` exposed a real Linux
  compatibility bug before GPG verification: eight unrelated `nsfs` mounts had
  roots such as `mnt:[4026532676]` and `net:[4026532575]`, which the parser
  incorrectly required to be absolute paths. This caused 37 errors and 14
  failures through the common mount guard; that run is not counted as passing
  evidence. Linux `nsfs_show_path` intentionally emits a namespace name plus
  bracketed inode. The repair accepts that strict bounded grammar only for an
  exact `nsfs` record, checks the inode against unsigned 64-bit range, and keeps
  absolute canonical requirements for every ordinary filesystem root and every
  mount point. Non-`nsfs` opaque roots and malformed namespace handles still
  fail closed; the root field remains unused by path coverage and Windows-
  provenance decisions.
- After the `nsfs` repair, the four focused capability/provenance/Linux/provider
  modules passed all 423 tests with nine environment-gated skips. The complete
  local suite passed all 567 tests in 70.498 seconds with nine skips. Full
  runtime/test `ruff`, `compileall`, Python 3.10 grammar parsing across 20 files,
  both workflow actionlint checks, strict Clang syntax checks for both C helpers,
  the isolated PyYAML skill validator, `git diff --check`, and project-journal
  validation passed. An independent security audit confirmed that the bounded
  root exception cannot affect mount coverage or DrvFS provenance and reported
  no P0-P2 findings.
- Repair commit `289d9cbb0504e0db3690ffb52f2238f46c868536` was
  exported as a 1484800-byte Git archive with SHA-256
  `df720c67c78893f5dca211445d2b9ca760e778674c8ddcb8fc32105e215b0407`;
  the copied archive matched on `codex-hoteng-srv-01`. An initial extraction
  below `/tmp` was intentionally discarded because the real trusted-runtime
  path check rejected the world-writable `/tmp` ancestor before fixture-specific
  assertions. Re-extracting the same archive below a private `/home/codex`
  directory exercised the real trust precondition and passed all 567 tests in
  38.981 seconds with three platform/opt-in skips. Remote `compileall`, both
  workflow actionlint 1.7.12 checks, and strict GCC syntax checks for both C
  helpers passed. The real root-owned `/usr/bin/gpg` host closure passed the
  loader-page and dynamic-table checks, verified Anthropic's signed Claude Code
  `2.1.196` `linux-x64` artifact at size `245373752` and SHA-256
  `eb933c6dd5534db89b83ba09009d5c0932bd1395f7e3bb0f34ba37eec37bbade`,
  and materialized the expected digest-keyed mode-`0500` snapshot. No credential
  or review content was supplied.
- Exact-range review of follow-up PR 46 found that the provider treated every
  provenance-verifier runtime failure as if a deterministic dependency were
  absent, which could authorize the automatic Copilot fallback. The repair adds
  a dedicated dependency-unavailable subtype. Only proven absence or unsupported
  platform/capability uses it; GPG launch failures, snapshot I/O errors, and
  source-path inspection races are inconclusive and block fallback. Source-level
  `EIO`, post-inspection `ENOENT`, GPG-launch, snapshot-creation, and provider
  routing tests pin that classification boundary. A present wrapper, unsafe GPG
  path/metadata, non-root Linux verifier, or unsafe macOS `otool` is invalid and
  blocked rather than being relabeled as dependency absence.
- The same review initially alleged that dependency audit tags could execute in
  the first Linux `ldd` trace. Pinned glibc source disproved that exact mechanism:
  audit tags are collected from the already-checked main map, and ordinary list
  mode exits before normal relocation and application initialization. The audit
  exposed a narrower real contract gap, however: proving only `/usr/bin/ldd`
  ownership did not prove which implementation or loader semantics would run.
  The final design removes `ldd` from the host-GPG provenance boundary. It
  statically requires the architecture's canonical glibc interpreter, captures
  both lexical and resolved identities, proves root ownership/mode/native mount,
  matching architecture, `ET_DYN`, no nested interpreter or unsafe tags, accepts
  floating glibc `>=2.27,<3.0`, and invokes only the captured loader's direct
  `--list` interface. Musl and unknown host-GPG loaders are unavailable. Every
  real GPG call rechecks loader identity/version and exact closure equality.
- A read-only probe on `codex-hoteng-srv-01` confirmed the production x64 path
  `/lib64/ld-linux-x86-64.so.2`, Ubuntu glibc `2.39`, no loader `PT_INTERP`, and
  a directly listable `/usr/bin/gpg` closure. This is host/runtime capability
  evidence, not publisher provenance for Claude Code or GPG.
- The first real direct-loader GPG smoke on the follow-up implementation found a
  Linux compatibility error that synthetic tests had missed: glibc's
  `libc.so.6` is an executable `ET_DYN` dependency and legitimately carries a
  `PT_INTERP` naming the same canonical glibc loader. Rejecting every dependency
  interpreter therefore blocked the real Ubuntu GPG closure. The corrected rule
  permits only that already-proven canonical interpreter on dependencies and
  still rejects musl, custom, relative, or inconsistent interpreters; the loader
  itself must continue to have no second `PT_INTERP`. Positive `libc.so.6`-shape
  and negative musl-interpreter regressions pin the distinction.
- After the fallback-classification and direct-loader repairs, the focused
  provenance/provider/Linux modules passed all 414 tests with nine
  environment-gated skips. The complete local suite passed all 584 tests in
  66.277 seconds with nine skips. Full runtime/test `ruff`, `compileall`, both
  workflow actionlint checks, strict Clang syntax checks for both C helpers, and
  `git diff --check` passed. Python 3.10 grammar parsing across 20 files, the
  isolated PyYAML skill validator, and project-journal validation had also
  passed on the same implementation/docs set before this evidence-only entry.
- After merging current `master` (`8f336c5`) and repairing the real
  `libc.so.6` interpreter compatibility issue, the focused
  provenance/provider/Linux modules passed all 415 tests with nine skips. The
  merged complete local suite passed all 668 tests in 125.832 seconds with nine
  skips. Full runtime/test `ruff`, `compileall`, both workflow actionlint checks,
  strict Clang checks for both C helpers, `git diff --check`, and project-journal
  validation passed before committing the compatibility repair.
- Compatibility repair commit `be86e4c` was exported as an exact Git archive
  with SHA-256
  `8d9b65322997813c5403b2617123e2e401c3bd8c4ea0f29390aa6aaf2cfa0d2d`;
  the copied archive matched on `codex-hoteng-srv-01`. The remote account's
  default `umask 0002` correctly triggered group-writable safety failures, while
  `0077` made one deliberate `0755` negative fixture private; neither run is
  counted as passing evidence. With the standard non-group-writable `0022`
  test umask, the same archive passed all 668 tests in 90.044 seconds with three
  platform/opt-in skips. Remote `compileall`, actionlint 1.7.12 on both
  workflows, strict GCC with the launcher's production POSIX feature macro, and
  strict GCC for the Keychain broker all passed.
- The same exact Linux archive then rebuilt and revalidated the real root-owned
  `/usr/bin/gpg` closure through glibc `2.39`: the canonical lexical loader was
  `/lib64/ld-linux-x86-64.so.2`, its resolved endpoint was
  `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`, and the captured closure had
  13 dependencies. Three real GPG operations verified Anthropic's signed Claude
  Code `2.1.196` `linux-x64` artifact at size `245373752` and SHA-256
  `eb933c6dd5534db89b83ba09009d5c0932bd1395f7e3bb0f34ba37eec37bbade`,
  then materialized a single-link mode-`0500` digest snapshot. No credential or
  review content was supplied, and the smoke's temporary GPG/snapshot roots
  were removed automatically.
- The final independent Codex PR review of
  `27b054c171516288226f92473aee882a7b0c2652..fe197f9ad7aea023738cd3c1b7c18d43cd6d48c8`
  found one P1 in the bounded safe-mode help grammar: the required runtime
  capability sentence accepted `or` between authentication, model selection,
  built-in tools, and permissions, so a disjunctive claim could satisfy the
  lexical all-term check without guaranteeing every capability. The repair
  permits only conjunctive enumeration in that positive runtime grammar and
  adds regressions for all-`or`, Oxford-comma-`or`, and mixed `and`/`or`
  variants. The focused capability suite passed all 27 tests. The complete
  post-merge suite passed all 671 tests in 111.205 seconds with nine skips;
  `ruff check`, Python 3.10 grammar parsing, `compileall`, actionlint, the
  isolated skill validator, project-journal validation, and `git diff --check`
  passed. A credential-free real help smoke also accepted all 16 required
  options from installed Claude Code `2.1.202` under the tightened grammar.
- The Claude-only Node extra-CA implementation passed 17 focused regressions,
  all 405 provider/Linux/common/contract tests with nine environment-gated
  skips, and the complete 709-test local suite with nine skips in 255.393
  seconds. Full helper `py_compile`, touched-file `ruff check`, strict C11
  launcher syntax under Apple Clang 21.0.0, the isolated skill validator,
  project-journal validation, and `git diff --check` also passed. The real Linux
  isolation gate remains assigned to the required Ubuntu CI job and is not
  claimed as local macOS evidence.
- Anthropic corporate network configuration documents the supported custom-CA
  entrypoint: https://code.claude.com/docs/en/corporate-proxy
- Node.js documents the process-startup additive trust semantics of
  `NODE_EXTRA_CA_CERTS`:
  https://nodejs.org/api/cli.html#node_extra_ca_certsfile
- Anthropic installation, signed-manifest, release-key fingerprint, and platform
  signature documentation: https://code.claude.com/docs/en/installation
- Anthropic Seatbelt, `bubblewrap`, `socat`, WSL2, and WSL1 sandboxing
  documentation: https://code.claude.com/docs/en/sandboxing
- Anthropic macOS Keychain and Linux `0600` credential documentation:
  https://code.claude.com/docs/en/authentication
- Anthropic CLI flag and help-surface documentation:
  https://code.claude.com/docs/en/cli-usage
- Anthropic permission syntax, double-slash absolute paths, and the `2.1.208`
  file-reading propagation boundary:
  https://code.claude.com/docs/en/permissions
- Anthropic `dontAsk` and built-in tool behavior documentation:
  https://code.claude.com/docs/en/permission-modes and
  https://code.claude.com/docs/en/tools-reference
- Microsoft WSL interop documentation showing that `/run/WSL` and
  `WSL_INTEROP` are shared by WSL1 and WSL2:
  https://wsl.dev/technical-documentation/interop/
- Microsoft custom-kernel verification example retaining a
  `WSL2-Microsoft` kernel marker:
  https://learn.microsoft.com/en-us/community/content/wsl-user-msft-kernel-v6
- Apple dynamic-linker documentation for `/usr/lib/dyld` and
  `LC_LOAD_DYLINKER`:
  https://developer.apple.com/forums/tags/linker
- GNU C Library dynamic-linker hardening guidance for `DT_AUDIT` and
  `DT_DEPAUDIT`:
  https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html
- Pinned GNU C Library loader/list implementation used to justify the direct
  `--list` contract:
  https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/elf/rtld.c
- Linux kernel ELF mapping implementation:
  https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
- Linux kernel namespace-filesystem path implementation:
  https://github.com/torvalds/linux/blob/master/fs/nsfs.c
- System V ELF program-header and page-congruence specification:
  https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html
