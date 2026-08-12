# Claude Runtime Trust And Platform Capabilities

This document primarily defines the trust and compatibility contract enforced
by the low-level Claude Code runtime used by `isolated_review`. A documented
platform or version is supported only when every applicable gate below passes.
The canonical named-double lane has the trusted `named_lane_guard run-claude`
supervisor bind accepted publisher evidence to a private verified snapshot of
the actual Claude Code bytes and launch that snapshot as its direct child under
[canonical-claude-lane.md](canonical-claude-lane.md); it reuses applicable
publisher-verification primitives, native-sandbox boundary, and failure
vocabulary here, but never the helper's
executable snapshot, dependency closure, supplied-diff workspace, outer sandbox,
credential carrier, catalog,
guarded writeback, recovery, or prompt contract.

## Contents

- [Policy Summary](#policy-summary)
- [Canonical Lane Applicability](#canonical-lane-applicability)
- [Acceptance Sequence](#acceptance-sequence)
- [Publisher Provenance](#publisher-provenance)
- [Capability Probes](#capability-probes)
- [Supported Platforms And Outer Sandbox](#supported-platforms-and-outer-sandbox)
- [Credentials](#credentials)
- [Runtime Report](#runtime-report)
- [Failure Classification And Low-Level Fallback](#failure-classification-and-low-level-fallback)
- [Official Sources](#official-sources)

## Policy Summary

### Canonical Lane Applicability

The direct canonical lane and the low-level helper are separate launch paths.
For named double/triple review, follow `canonical-claude-lane.md`: use a clean
detached Git worktree, no prepared diff, explicit tracked guidance reads, and a fresh
`claude` process launched from the trusted supervisor's guard-created snapshot.
Its **Canonical Executable Provenance** section owns the direct lane's complete
executable contract: verify the installed source against the signed release
manifest, persist the accepted parent-private preflight result, pass it through
mandatory `--preflight-result`, and let
`run-claude` copy the matching source from an opened no-follow descriptor into a
private mode-`0500` snapshot after the relevant identity/policy plus signed
size/SHA-256 checks. Launch identity intentionally excludes `mtime`, `ctime`,
and `nlink`, so benign churn in those fields is accepted. For a `named-direct`
release selected at the canonical `>=2.1.226` feature gate, the same guard also
owns the session ID and manages the descriptor-bound
`$HOME/.claude/session-env/<uuid>` lifecycle described below; this does not
change the global compatibility floor. The snapshot bytes,
not the mutable raw source path, are executed; replacement of that raw path
after binding cannot change the launched bytes, and no parent before/after
raw-path check is required. The process receipt records this as
`launch_binding.mode: verified-snapshot`. Snapshot copy and full rehash share
the lane's monotonic deadline. Snapshot creation/handoff and later cleanup are
separate forwarded-signal-masked critical sections; between them the bounded
supervisor owns structured signal forwarding and process cleanup. An incomplete
cleanup is structured `inconclusive` / `snapshot-cleanup` evidence with exact
`process_reason` plus either exact `retained_path` while the lexical output-parent
binding is revalidated or descriptor-bound `retained_locator` device/inode/leaf
evidence after lexical drift; no output is published. Cleanup uses the retained
output-parent descriptor and recorded leaf identity, while lexical parent
revalidation remains an output-publication gate. Output publication, rollback,
and the complete flushed `launch_binding` receipt share one signal-masked CLI
commit transaction: a pre-receipt signal or receipt write/flush failure removes
the output pair, while a post-receipt signal cannot create a false failure.
Before stream validation, the parent
compares that receipt's preflight SHA-256, source identity/path, and signed
artifact size/SHA-256 with the accepted launch binding. For guarded
`named-direct >=2.1.226`, it also exact-checks the canonical session ID and the
closed session-environment guarantee descriptor defined below. The validator
separately rereads the preflight result and does not consume `launch_binding`. Sections below
that describe executable snapshots or dependency closures, `.git`-free
materialization, supplied-diff prompts, helper-private credential carriers, or
helper-owned outer sandboxes remain helper-only: the canonical launch snapshot
does not confer those guarantees and cannot make an
`isolated_review` artifact count as the canonical lane.

The canonical lane's machine control path is also separate from the env-shebang
compatibility wrappers. Invoke the trusted absolute Python interpreter with
`-I -B -S` and `named_lane_guard preflight-claude` for compatible-version and provenance selection,
then `named_lane_guard run-claude` for launch/process supervision, only after
successful cleanup invoke `named_lane_guard validate-claude-stream` for terminal
artifact classification, and only after validator acceptance invoke the
manifest-bound `named_lane_guard classify-review-result` profile for semantic
disposition. The default guard profile retains its exact four-module raw closure,
including `review_runtime.claude_version_policy`;
the three additional subcommands select only their declared manifest-bound
raw-source and companion profiles, including the version-policy, capability,
stream-compatibility, audited-baseline, closed-profile-schema, and result-classifier
dependencies. None uses ordinary package import resolution, and launch
supervision, output validation, and post-acceptance disposition cannot replace one
another.

The formal preflight does not inherit or trust ambient `HOME`. The guard derives
the current POSIX account with `pwd.getpwuid(os.getuid())`, requires its nonempty
absolute home to resolve to an accessible directory, and binds that canonical
path directly into the preflight consumer. The compatibility wrapper may still
use its process `HOME` for low-level callers, but that behavior cannot satisfy a
named lane or self-policy-migration review.

Concretely, `preflight-claude` raw-loads the exact provenance closure plus
`review_runtime.claude_version_policy`, `review_runtime.claude_capabilities`,
`review_runtime.claude_stream_contract`, and
`review_runtime.named_claude_preflight`. `validate-claude-stream` raw-loads the
standalone validator plus its exact required runtime-source closure.
`classify-review-result` binds and revalidates the exact
`review_runtime.review_result` source before executing its already loaded
classifier. The guard
binds and revalidates `review_runtime/claude_code_release.asc`,
`references/claude-stream-compatibility.json`,
`references/claude-2.1.212-stream-schema.json`,
`references/claude-stream-schema.json`, and the manifest-bound
capability-contract source bytes. Companion revalidation repeats
no-follow descriptor/type safety checks and compares the complete bounded bytes;
a safe ordinary-file replacement with identical content is harmless, and no
persistent `dev`/`ino` identity is required across the two reads. The provenance
consumer verifies with the immutable release-key bytes captured by the guard's
initial validated read and never reopens that path after final validation.
The stream-contract and validator consumers parse the immutable compatibility,
baseline, profile-schema, and capability bytes from the guard's initial validated reads without
reopening those paths after final validation. Neither profile reads or executes its env-shebang
compatibility wrapper or needs an extra `--` separator before its downstream
arguments.

The canonical lane and low-level helper share the stable publisher-verified
compatibility range `>=2.1.211,<3.0.0`, defined once in
`scripts/review_runtime/claude_version_policy.py`. Exact patch versions remain
facts in signed per-version artifact manifests, schema baselines, and helper
credential-lock catalog entries; they are not the global eligibility policy.
Claude Code `2.1.212` is the audited per-version stream-schema baseline, not a
global eligibility pin. The canonical lane additionally requires its
publisher-first preflight, mandatory credential-free `--help` advertised-capability probe,
accepted parent-private preflight evidence, preflight-bound strict stream profile,
and installed-path identity/digest revalidation. Its only authentication interface
is ordinary local Claude CLI login in trusted real `HOME`; it accepts no API key,
OAuth-token environment interface, or helper carrier. The publisher-verified CLI may
update ordinary CLI-owned authentication and runtime state in that control
plane, including credential refresh and possible cache or tool-result
artifacts. Those accepted CLI side effects are not model-authorized review
mutations and do not authorize model/tool writes or deliberate host mutations.
The canonical lane does not enumerate or attest every CLI-owned `HOME` write,
and it does not take a complete real-`HOME` diff. The canonical lane does not use or
claim the helper's credential-lock catalog, broker, staged carrier, guarded
writeback, or recovery guarantees.
`--no-session-persistence` does not make the CLI process or real `HOME`
immutable, and cache or tool-result artifacts may retain review-derived data
according to upstream CLI behavior. Authentication rejection is still
`blocked-authentication`; when ordinary refresh is forbidden or only API-key or
OAuth-token credentials are available, the lane also reports
`blocked-authentication` instead of widening the launcher environment. Ambiguous
credential persistence is inconclusive, and neither condition authorizes another
provider.

For a preflight-selected `named-direct >=2.1.226` release, the canonical UUIDv4
session ID remains a guard-owned control-plane input, while its filesystem
namespace is only guard-managed and descriptor-bound. The guard rejects caller
session/resume/cloud, background, and worktree selectors. Before creating or
opening `$HOME/.claude/session-env`, it takes an exclusive advisory BSD `flock`
on the stable no-follow descriptor for real `$HOME/.claude` and retains that
lease through snapshot creation, handoff, supervision, positive quiescence, and
cleanup or recovery-evidence construction. This lease serializes only cooperative
controls that take the same lock. The signed Claude CLI's expected idempotent
`mkdir` for the selected leaf and every non-cooperative same-euid host process
remain host-TCB assumptions; the lock does not prevent their namespace writes.

The guard generates a best-effort 122-bit-random lowercase canonical UUIDv4,
retries rather than deliberately adopting `EEXIST`, creates the parent/leaf as
needed, and records the objects seen by the first successful no-follow opens.
Those parent/leaf device-inode-directory-type/uid identities are observed
bindings, not proof of `mkdir` origin or continuous custody. After the verified
launch snapshot is ready, handoff revalidates device/inode/type, current-account
uid/access/ACL policy, exact leaf mode `0700`, and emptiness before process start.
Directory `mtime`, `ctime`, `nlink`, and benign parent child-entry churn are not
mutation evidence. Missing, replaced, nonempty, and unreadable or otherwise
unprovable state remain distinct fail-closed conditions. Hostile same-euid gaps
between parent/leaf `mkdir` and first open, handoff or runtime ABA, and final
`stat` to `rmdir` are excluded from the guarantee.

The bounded supervisor's callback supplies only positive proof of process
quiescence; it neither performs nor triggers descriptor cleanup. After that
proof, the outer cleanup path separately acquires a forwarded-signal mask before
descriptor-relative, nonrecursive removal and never deletes unexpected children.
If that callback does not run, the guard retains the possibly active fence and
namespace lease through recovery-evidence construction, emits `process-leak`,
preserves the original supervision failure in `process_reason`, and reports the
first-bound parent/leaf identities together with any revalidated path. Successful
cleanup observes only that the selected name is absent after `rmdir`; it does not
prove creation origin or eliminate the final-window same-euid ABA.

The successful receipt keeps these limits machine-readable. The parent must
require `launch_binding.session_env.identity_binding` to equal
`first-no-follow-open-after-exclusive-mkdir`, require
`creation_origin_proven` to be exact boolean `false`, and exact-check
`creation_origin_guarantee` as
`best-effort-122-bit-uuidv4-leaf-immediate-nofollow-open-cooperative-claude-control-directory-flock-same-uid-host-tcb`,
`namespace_exclusivity_guarantee` as
`exclusive-advisory-claude-control-directory-flock-cooperative-same-uid-host-tcb`,
`cleanup_guarantee` as
`descriptor-custody-emptiness-revalidation-nonrecursive-rmdir-cooperative-claude-control-directory-flock-same-uid-host-tcb`,
and `cleanup_observation` as `selected-name-absent-after-rmdir`. A missing,
differently typed, or differently valued field fails the parent comparison.

### Native Selected-Deny Read Boundary

For the accepted real-`HOME` native-sandbox review design, keep these layers distinct:

- For the canonical direct lane, real `HOME` is the trusted ordinary Claude CLI control plane and its clean detached Git worktree is the review scope. The low-level helper instead uses its supplied-diff/private-Git workspace and, for local login, its broker/carrier/catalog transaction; those helper guarantees do not transfer to the direct lane.
- The model may receive `Read`, `Grep`, `Glob`, and sandboxed `Bash`, with read-only behavior required by the prompt and permission contract.
- Launch must request global `denyWrite` and critical-sensitive-root `denyRead` for credential/configuration roots, the original source checkout, other review-state roots, `/proc`, and `/dev`; those requested controls define the native-sandbox enforcement boundary. Keep global `denyWrite` intact and add no `allowWrite` exception for the guard-managed, descriptor-bound session-environment path: precreation and cleanup are outer control-plane actions and do not authorize sandboxed Bash to write there. A canonical worktree's registered Git metadata/object paths remain part of its logical read-only scope even when their physical storage is outside the worktree directory.
- Native-sandbox `allowRead` entries are exceptions within a selected-deny policy, not a global host-read whitelist. Sandboxed Bash can technically read a host path that is outside the detached worktree when that path is not covered by `denyRead`. The prompt/model scope therefore explicitly forbids all outside-workspace reads; do not describe the selected-deny policy as re-opening only the current workspace or private Git view.
- Capability probes and the first `system/init` event report only their documented fields. They do not prove the final merged native-sandbox configuration, merged admin-managed permission arrays, or path-rule evaluation; that limitation applies even to Claude Code 2.1.212 baseline output. Persist sandbox controls as requested configuration and do not promote init/capability output into independent evidence of effective enforcement.
- For the canonical direct lane, require exactly one leading `system/init` and one trailing terminal `result`, plus the preflight-bound compatibility fields defined in `canonical-claude-lane.md`. For guarded `named-direct >=2.1.226`, the parent must require a canonical receipt `launch_binding.session_id` and pass it unchanged as `--expected-session-id`; init `session_id` is mandatory and must equal that canonical UUIDv4. Every admitted intermediate event retains its existing required match-to-init binding, and terminal `session_id`, when present, must match init. Absence, malformed syntax, or a valid mismatch of the frozen init value is inconclusive. The CLI input stays optional for older named-direct and helper/provider profiles. Missing, duplicate, malformed, misordered, or mismatched observable evidence must otherwise fail closed. This strict envelope proves only reported invocation fields and still does not attest the merged sandbox, managed permission arrays, or path evaluation.
- Select the closed `legacy-base` stream profile for `>=2.1.211,<2.1.216` and the closed `extended-2x` profile for `>=2.1.216,<3.0.0`. Both profiles validate every admitted intermediate event against a closed, session-bound contract; unknown init, intermediate, terminal, or nested fields fail closed. In `extended-2x`, optional assistant `diagnostics` accepts only `null` or the exact closed object `{"cache_miss_reason":{"type":"unavailable"}}`; `legacy-base` forbids the field. Both the direct lane and low-level helper pass captured Claude output through this canonical validator after their distinct workspace, sandbox, and authentication preparation.
- Post-attempt worktree validation can prove the inspected worktree and private Git state are unchanged at validation time. It cannot prove that no transient write or outside-workspace read/side effect occurred.

This boundary is an accepted model-behavior tradeoff, not full host-read isolation. A stronger outer sandbox may add protection, but must not be inferred from selected `denyRead` / `allowRead` settings or init output.

- For both launch paths, accept installed Claude Code release versions
  `>=2.1.211,<3.0.0` only after all
  path-applicable provenance, platform, capability, authentication, and isolation
  checks pass. For the low-level helper only, local-login refresh writeback
  additionally requires an exact version/platform/SHA-256 entry from the signed
  artifact in the credential-lock protocol catalog. The canonical direct lane
  uses the ordinary control-plane contract above instead, and helper explicit
  API-key/OAuth-token modes bypass the local-login catalog and transaction.
- Do not pin either production path to `latest`, `stable`, or one current patch
  release. Neither path upgrades Claude Code; each validates an installed release.
- Treating one audited patch as the complete compatibility policy was a compact
  trust shortcut, but it was not a reliable wrapper detector: native Mach-O/ELF
  shape rejects scripts and
  interpreter wrappers, while signed artifact verification separately proves
  Anthropic publisher provenance and capability probes bound the CLI contract.
- Reject prerelease, development, unparseable, and future-major versions unless
  this contract is deliberately revised.
- The `2.1.211` floor deliberately trusts the current CLI's refresh behavior and
  explicit login-expiry signals. The helper no longer compensates for older
  authentication bugs with a custom OAuth freshness warmup. Internal
  credential-lock coordination is separately artifact-certified: the initial
  catalog covers `2.1.211` Darwin arm64/x64 and Linux glibc/musl arm64/x64, with
  WSL2 reusing the matching Linux artifact.
- Treat the fixed Anthropic release-signing key fingerprint and the signed
  per-version manifest as publisher provenance. A version string, executable
  bit, native file format, install path, or self-reported identity is not
  publisher provenance.
- For the low-level helper, after the signed manifest, size, and SHA-256 checks pass, materialize a
  helper-owned private executable snapshot and stop executing the source path.
  Only the snapshot may run the help probe, dependency discovery, credential-
  bearing preparation, or final review.
- Treat the fixed-path native GPG source as a separately validated host
  dependency. It verifies the Anthropic signature but is not itself evidence of
  Anthropic publisher provenance. Retain its stable descriptor, copy it into a
  fresh private GPG home below an explicit helper-owned `0700` root, and run all
  GPG operations only through the resulting mode-`0500` execution snapshot.
  Copying the main executable does not freeze the dynamic libraries loaded by
  that snapshot, so capture every non-sealed runtime dependency branch once and
  revalidate it before every GPG call. On WSL2, prove the private root,
  complete root path chain, loader, and dependency paths are Linux-native.
- Run GPG and Linux security-sensitive host tools with explicit minimal
  environments. Do not inherit loader, shell-startup, compiler, or toolchain
  override variables from the caller.
- Run every candidate executable probe before publisher verification with a
  fixed credential-free environment, not a denylist-filtered copy of the caller
  environment. Inherited proxy URLs, custom CA paths, authentication material,
  review metadata, and unrelated caller variables must be absent.
- Treat `NODE_EXTRA_CA_CERTS` as a Claude-only, process-startup additive CA
  input. It is never part of the shared reviewer environment, never inferred
  from `SSL_CERT_FILE`, and never supplied to the unverified candidate probe or
  security-sensitive host tools.
- Use layered enforcement. The helper-owned outer sandbox enforces host
  filesystem, process, write, and network isolation. On Linux and WSL2, the
  signed Claude runtime's permission engine additionally separates files that
  the runtime must read for authentication from files its model-visible `Read`
  tool may access. Neither layer substitutes for the other.
- Except for the explicitly shared applicability rules above, this document
  describes the low-level supplied-diff helper runtime. Its compatibility
  Copilot backend is not the actual Claude Code lane required by named
  double/triple review. Named-shape consent does not authorize provider
  substitution; any supplemental Copilot run requires a separate explicit user
  request and never completes the named shape.

## Acceptance Sequence

Fail closed and preserve this ordering for every automatically discovered or
explicitly configured Claude Code candidate:

1. Resolve the candidate to a stable regular file and revalidate the file around
   inspection so a symlink or replacement race cannot switch the executable.
2. Require the execute bit and a native binary. On macOS, require an official
   thin 64-bit arm64 or x64 Mach-O artifact and select the manifest entry from
   that artifact architecture. An x64 artifact may run through Rosetta on Apple
   Silicon, so macOS does not require exact host-CPU equality; the bounded
   bootstrap probe must still execute successfully. On Linux and WSL2, require
   an ELF matching the host architecture and a libc target that maps to the
   host release artifact. Reject scripts, interpreter wrappers, fat Mach-O
   binaries, and incompatible artifacts. These checks exclude incompatible
   execution shapes; they do not establish provenance.
3. Before provenance is known, run only the identity and version probe in a
   bootstrap sandbox with no review workspace, authentication material, host
   configuration, writes, or network. macOS uses a deny-by-default Seatbelt
   profile. Linux and WSL2 use a synthetic-root `bubblewrap` sandbox containing
   the candidate, an isolated home and temporary directory, and only narrowly
   selected root-owned, non-group/world-writable system library roots. Do not
   run `ldd` on the unverified candidate. Pass only fixed safe-mode controls,
   helper-owned home/temp paths, a fixed system-only `PATH`, a deterministic C
   locale, and `NO_COLOR`; do not inherit proxy, CA, authentication, review, or
   other caller state. Bound time and both output streams.
4. Parse exactly one stable release version and require the shared range
   `>=2.1.211,<3.0.0` from the single canonical policy source. The direct lane
   and low-level helper apply their own later runtime gates, but neither may
   replace this range with one globally pinned patch.
5. Fetch the manifest and detached signature for that exact version through the
   parent helper. Resolve GPG only from the fixed host paths, validate the source
   path, retain a stable source descriptor, and copy from that descriptor into a
   fresh private execution snapshot below a helper-owned root. On WSL2, reject
   Windows-backed provenance for the root, its resolved target, and every parent
   before creation and recheck the same identities and mount provenance before
   every GPG call. Capture the GPG snapshot's recursive dynamic dependency
   closure under the platform-specific host-tool policy and revalidate the
   complete closure before each call. Use only the snapshot to decode the key,
   list its fingerprint, and verify the detached signature. Strictly parse the
   signed manifest and compare the installed binary's SHA-256 with the checksum
   for the detected platform and architecture.
6. Copy the verified source into a helper-owned, current-user-only snapshot,
   rehash the copy against the signed size and SHA-256, publish it atomically as
   a checksum-keyed `0500` executable, and revalidate it before reuse. The source
   candidate is not executed after this point, and the verified snapshot is
   captured once for the complete Claude model-attempt chain. Every later
   descriptor-anchored revalidation requires exact mode `0500`; any owner,
   group, or world write-bit drift rejects the snapshot before execution.
7. On Linux and WSL2, only after the signed checksum passes, allow trusted
   root-owned `ldd` to collect the exact dynamic loader and shared-library files
   needed by the verified snapshot and final sandbox. Require each dependency to
   be root-owned and non-group/world-writable before mounting it read-only.
   Capture each dependency and parent-component identity, then revalidate those
   exact identities while building the sandbox command and immediately before
   final mounting.
8. Run the bounded help capability probe against only the verified snapshot
   inside the outer sandbox. Do not expose local credentials or tracked review
   content until provenance and capabilities pass.
9. Establish the platform-specific file-tool contract before credentials are
   exposed. macOS retains `Read`, `Grep`, and `Glob`. Linux and WSL2 require
   `dontAsk`, expose only `Read`, allow only `Read(./**)`, reject prompt file
   mentions, and deny every non-workspace synthetic-root mount with absolute
   double-slash rules. Command construction must fail closed when a mount lacks
   coverage or appears below `/workspace`.
10. On macOS, require one bounded Bun `root_certs.cpp` store in the publisher-
    verified executable snapshot and accept only cryptographically self-signed
    CA members whose KeyUsage, when present, permits certificate signing;
    unrelated embedded PEM data is never promoted. Before every model attempt,
    revalidate that snapshot and exact root evidence, export all authoritative
    trust domains, apply explicit-deny precedence, omit constrained or invalid
    roots, and rebuild a certificate-only helper bundle from current system,
    bundled, permitted additional, and snapshotted caller material.
11. For local login at every model-attempt boundary, prepare one platform-
    specific private credential carrier. On macOS, securely read the current-account Keychain
    item plus the empirically compatible file under the account's `pwd` home,
    validate their structure, UTF-8 token encodability, and refresh-token
    presence, select the candidate with the later access-token expiry, and load
    it into the restricted broker.
    On Linux and WSL2, validate the host credential file and stage a private
    copy. An expired access token is accepted when a usable refresh token remains;
    there is no warmup or attempt-duration freshness gate. An explicit API key
    or OAuth token skips local credential selection, staging, and the internal
    lock-protocol gate. Before local-login preparation, require the captured signed artifact
    to resolve to one exact certified lock protocol; an unknown artifact is
    inspection-inconclusive before credentials or review data are exposed.
12. Launch only the one captured verified snapshot for every real model attempt
    in a fresh outer sandbox; never rediscover or fall back to the mutable source
    installation between Opus attempts. The trusted runtime may refresh only
    inside the temporary carrier. On macOS, atomically reserve attempt-scoped
    durable-journal quota before any filesystem write for every generation
    admitted to durable staging, then commit it to its own helper-private recovery
    carrier. The journal is bounded to eight generations and 8 MiB of payload.
    The last generation and 1 MiB are reserved for one terminal recovery
    generation, and every reservation consumes generation and byte quota for
    the rest of the attempt even if the write or publication fails. At the
    locked generation linearization point, publish and
    acknowledge it only if it is still current and the runtime is not
    abandoned. When an update would consume the terminal reserve, the broker
    atomically proves that it is still the current pending generation, closes
    later `W` admission, commits that exact payload to the final journal slot,
    and NACKs without publication or host writeback. Later `W` requests receive
    an explicit NACK before their callback or filesystem work. The terminal
    generation invalidates any older staged host-writeback candidate, marks
    credential inspection inconclusive, and pauses without Copilot fallback.
    A superseded or failed
    generation is not acknowledged, but its carrier remains in the bounded
    journal until post-quiescence finalization or failure recovery.
    On Darwin, every file and directory synchronization in that commit performs
    `fsync` followed by `F_FULLFSYNC`; an unavailable or failed full sync NACKs
    the generation. Acknowledgement therefore proves successful full-sync calls
    plus exact readback, not host persistence or an absolute hardware guarantee.
    This is Darwin's strongest available best-effort power-loss barrier; storage
    hardware may still fail to honor it. After the broker
    server and every handler have fully quiesced, one outer-runtime owner proves
    the newest carrier, removes older journal entries, detaches the latest
    acknowledged rotation, performs guarded host writeback, and deletes the final
    recovery copy only after that write and its parent directories have passed
    the same Darwin full-sync boundary.
    The latest exact-verified generation is always the canonical current carrier.
    If quota rejection, a malformed update, or durable-stage failure leaves no
    staged host-writeback candidate, finalization reports it as the sole current
    recovery artifact, removes every other
    non-authoritative complete journal entry, and reports failed stale-entry
    cleanup separately as cleanup residue. If staged or non-staged control flow
    leaves any stale carrier unvisited, cleanup reporting is promoted to the
    recovery-root scope without changing the canonical current carrier.
    Linux/WSL2 instead uses a bounded watcher
    and a synchronous final drain before cleanup. At each host commit, acquire
    the artifact-certified primary and legacy refresh locks, maintain their
    5-second heartbeat, recheck both macOS carrier snapshots or the Linux/WSL2
    host file, and write only if the complete observed state still matches the
    current baseline. If Linux/WSL2 Claude exits after a
    staged rotation but before releasing helper-owned locks, reclaim only the
    exact empty private staged locks after both watcher join and a normal
    supervisor return prove writer quiescence, then retry the final drain once.
    Before exposing the macOS broker, prevalidate its stable recovery-root
    cleanup scope. If macOS cannot prove broker-handler quiescence, the server irreversibly
    closes its pending-update publication/acknowledgement gate before boundedly
    draining handlers already inside the commit critical section. Runtime
    abandonment latching and pending detachment are recorded independently, and
    detachment may be retried without reopening publication. The event-only
    abandonment callback and timed detach are bounded; detach timeout leaves
    payload ownership with the server. A terminal durable stage racing the event
    either self-registers or is transferred by the bounded recovery worker under
    the runtime lock. Recovery runs even for a detached `None` payload and
    converges that stage. Timeout reporting takes only a nonblocking runtime-state
    snapshot and otherwise reports the stable recovery-root cleanup scope without
    claiming a current carrier. Once quiescence is unproven, outer finalization
    does not wait for or consume runtime state still owned by a late handler or
    recovery worker. Whenever abandonment recovery observes
    any durable journal entry or quiescence stage, its final error also reports
    that root, even when it separately reports an exact current carrier. After an actual
    bounded recovery timeout, the
    handler/recovery state machine exclusively owns in-flight stage cleanup. Any
    late stage or fallback is exact-cleaned by that state machine or remains
    within the pre-reported recovery-root cleanup scope. Report a carrier as
    current only after its no-follow path identity and exact payload are verified;
    an unverified or incomplete existing file is cleanup-only, and a vanished
    temp is unreported.
    Shutdown uncertainty with no `W` generation produces no current recovery
    credential; a pre-reported recovery-root cleanup scope remains cleanup-only.
    If guarded post-quiescence writeback
    fails, retain the newest verified carrier or durably materialize a newer
    pending payload before reporting its path. Otherwise
    retain and report the Linux/WSL2 private recovery carrier rather than
    deleting the only possibly
    valid refresh token. Validate structured output, effective
    model, and terminal status before accepting text as review evidence. A strict
    entitlement result may select the later Opus model; an authentication result
    instead stops as `blocked-authentication`. The requested effort remains
    explicit in every real command.

## Publisher Provenance

Use Anthropic's Claude Code release-signing primary-key fingerprint as the fixed
trust anchor:

```text
31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE
```

Anthropic publishes the release key at the fixed key URL below. The helper
vendors a copy, pins its full primary fingerprint, and uses only these release
endpoints for a detected version `<version>`:

```text
https://downloads.claude.ai/keys/claude-code.asc
https://downloads.claude.ai/claude-code-releases/<version>/manifest.json
https://downloads.claude.ai/claude-code-releases/<version>/manifest.json.sig
```

The helper uses an isolated keyring containing only its bundled public key and
requires that key's primary fingerprint to exactly match the pinned value on
every use. A matching email, key ID, signature status message, or key downloaded
over TLS is insufficient. Update the bundled key only through an explicit policy
change.
Verify the detached signature before trusting any manifest field. Parse the
bounded JSON with duplicate-key rejection, select one exact platform entry, and
compare the local binary's size and SHA-256 with that signed entry.

The signature verifier is resolved only from fixed native paths. Linux and
WSL2 accept only root-owned system GPG; macOS may additionally accept a
same-user Homebrew installation:

```text
Linux/WSL2: /usr/bin/gpg{,2}
macOS:      /usr/bin/gpg{,2}, /usr/local/bin/gpg{,2}, /opt/homebrew/bin/gpg{,2}
```

The resolved source must be a native executable regular file owned by root or
the current user on macOS, or root on Linux/WSL2, and must not itself be group-
or world-writable. Its file identity and complete parent path identity must
remain stable across inspection. Every parent must be owned by root or the
current user, and group/world-writable parents are rejected except for canonical
macOS Homebrew directories owned by root or the current user and group-writable
only by the exact `admin` group. Homebrew `admin` membership is therefore an
explicit macOS host TCB boundary, not evidence that GPG came from Anthropic.

The helper does not execute that replaceable source path. It opens the validated
source with no-follow semantics, keeps the stable descriptor, and copies from
that descriptor into the fresh current-user `0700` GPG home created directly
below an explicit helper-owned private root inside the isolated review state.
The root is not selected from ambient `TMPDIR`, `TMP`, or `TEMP`. Its requested
path, resolved path, and full parent chains must remain identity-stable. WSL2
additionally reads bounded mountinfo once per stability check and rejects any
Windows-backed filesystem covering any member of that chain. The copy is
bounded and rehashed, published as a single-link mode-`0500` execution snapshot,
and revalidated against the stable source descriptor. Key dearmoring,
fingerprint listing, and detached-signature verification all run through this
one snapshot. The selected fixed source path, not the ephemeral snapshot, is
recorded as `gpg_verifier`, alongside `gpg_verifier_trust:
fixed-path-native-host-tool` and separately from `publisher_provenance:
anthropic-signed-manifest`.

The execution snapshot freezes the inspected main GPG file but does not freeze
what the platform dynamic loader opens later. On macOS, fixed root-owned
`/usr/bin/otool` recursively inspects the snapshot's Mach-O dependency closure.
Sealed `/usr/lib/**` and `/System/Library/**` endpoints remain part of the macOS
platform TCB. The main executable must contain exactly one
`LC_LOAD_DYLINKER` naming `/usr/lib/dyld`, and dependency images may not contain
that command. Every non-sealed endpoint must remain below canonical
`/opt/homebrew/{opt,Cellar}` or `/usr/local/{opt,Cellar}` roots; unresolved
dyld-relative references, `LC_RPATH`, `LC_DYLD_ENVIRONMENT`, path escapes, an
untrusted owner, and group/world-writable dependency files are rejected. Both
the lexical symlink chain and resolved file chain are captured. Homebrew parent
directories may use only the explicit `admin` group-write exception above.
After the fixed tool passes its metadata prerequisite, an `otool` launch error
or nonzero inspection result is inconclusive and cannot authorize fallback.
Executable discovery treats an initial `FileNotFoundError`/`ENOENT` as an absent
automatic candidate only after a bounded, component-wise `lstat`/no-follow walk
proves a stable missing component. A resolved parent symlink is accepted only
when repeated no-follow metadata and target-directory identity checks bind the
same resolution. A dangling final or parent symlink, a symlink or parent-path
race, `EACCES`, `EIO`, `ESTALE`, or another metadata/access inspection failure
is inconclusive.
An existing symlink whose final `stat` succeeds remains a candidate; the full
Claude provenance validator owns its lexical and resolved-chain policy. The same
absence distinction applies to an explicit executable override, except that a
proven absent or non-executable explicit override remains a blocking
configuration error.

On Linux and WSL2, the private snapshot copied from the root-owned fixed-path GPG
source is inspected only after that source is trusted. Stable-descriptor ELF64
inspection requires the loader-visible `PT_DYNAMIC` address, memory, and file-
backed ranges to map consistently through exactly one `PT_LOAD` at byte and
loader-page granularity. Every load must keep its file/virtual page offsets
congruent, and no other page-rounded load mapping may cover the dynamic table.
Only then does the helper reject `DT_RPATH`, `DT_RUNPATH`, `DT_AUDIT`, and
`DT_DEPAUDIT` in the main snapshot before any loader process starts. Host GPG is
then restricted to the architecture's canonical glibc interpreter
(`/lib64/ld-linux-x86-64.so.2` on x64 or
`/lib/ld-linux-aarch64.so.1` on arm64); musl and unknown interpreters are not
supported for this host-trust dependency. The lexical and resolved loader paths
must be root-owned, non-group/world-writable, Linux-native ELF64 `ET_DYN` images
matching the host architecture, with no second `PT_INTERP`, mutable loader path,
or audit tag. A credential-free `--version` probe must identify glibc in the
floating range `>=2.27,<3.0`. The helper then invokes that captured loader
directly as `loader --list <gpg-snapshot>`; it never delegates this boundary to
an implementation-variable `ldd` script. The pinned glibc list path may map
dependencies but exits before application relocation, constructors, or entry
code. The helper immediately rejects mutable loader paths, audit tags, a
noncanonical interpreter, non-`ET_DYN` type, incompatible architecture, or
unsafe provenance in every reported dependency before any real GPG operation.
A dependency such as glibc's executable `libc.so.6` may carry only the same
already-proven canonical interpreter; arbitrary or musl interpreters remain
invalid. This ordering
prevents a malformed alternate/page-overlaid main dynamic table from activating
audit code while still allowing the proven loader to report the exact dependency
graph. Before every call the helper revalidates every old identity, reruns the
same loader version and list probes, reparses the complete ELF closure, and
requires the refreshed structure and glibc version to equal the original.
Only the private snapshot identity may traverse a root-owned exact-`01777`
system-temp ancestor. Its non-final directory identities retain stable
device/inode/type/mode/owner/group anchors but deliberately ignore entry-count
and timestamp churn while the same GPG operation creates keyrings, locks, and
other sibling files. The final snapshot executable retains its complete
identity; the glibc loader and dependency chains also retain complete identities and may
not traverse writable ancestors. WSL2 proves the old and refreshed snapshot,
loader, lexical, and resolved paths have Linux-native mount provenance. A changed
or unreadable identity/closure is inconclusive, while a stable unsafe owner,
mode, path, or load-command policy is blocked.

Each GPG call receives only its isolated home, fixed locale, and fixed system
path. Inherited `LD_*`, `DYLD_*`, shell-startup, compiler, and toolchain override
variables are absent. The Linux glibc-loader probes, post-provenance `ldd`,
`bubblewrap`, `socat`, `rg`, compiler probes, and launcher compilation use the
same fixed-minimal-environment principle, with only the host-tool home, locale,
path, and temporary directory provided.

Anthropic documents detached manifest signatures for releases from `2.1.89`
onward, which covers the complete shared supported version range in this
contract. Each selected release still requires its own signed per-version
manifest and matching artifact digest; this coverage is not a floating `latest`
trust decision.
One process-level absolute deadline covers DNS resolution, connection and TLS
setup, response headers, body reads, and response teardown for each bounded
manifest/signature fetch; per-socket timeouts are not the total-time boundary.
The synchronous fetch fails closed before egress if that deadline cannot be
installed without replacing an existing process timer or if `SIGALRM` is
blocked in the calling thread. Handler and timer cleanup ownership is recorded
before either process-level mutation. The previous handler is restored only
after the helper has disarmed the timer or independently confirmed that it is
clear; an indeterminate armed timer retains the guard handler and fails closed.
Manifest download, signature, parse, or file-race failures must never be
reinterpreted as model entitlement or authentication failures.

The current helper does not use macOS code signing or notarization as an
acceptance gate. Those checks may be added later as optional defense in depth,
but they must never replace or weaken the signed-manifest and checksum gate. The
signed manifest is the publisher-provenance mechanism on every supported
platform.

After the source binary matches the signed artifact, the helper copies it with
no-follow, stable-descriptor checks into a current-user-owned `0700` snapshot
directory. The digest-keyed snapshot is rehashed during the copy, published
atomically with exact mode `0500`, and fully revalidated before reuse. This is
the executable-stability boundary: the original installation path may be
managed or replaced by a package manager, but it cannot be switched between
provenance verification and the capability/final launches because those stages
execute only the private snapshot. An owner-writable mode is not a valid private
execution snapshot even when the bytes still match the signed digest.

## Capability Probes

Compatibility is capability-based within the shared accepted version range. Do not
match the complete `--help` output or pin whitespace and unrelated wording from
one release.

The one leading `--safe-mode` declaration token is syntax, not a semantic
claim. After removing it, any additional sentence that refers to safe mode
itself fails closed unless the complete normalized sentence matches a bounded
positive template: continued enforcement, a direct required action, no effect
on the explicitly preserved auth/model/tool/permission or managed-policy
subjects, or a clear prohibition on disabling or bypassing safe mode. Literal
space-separated, hyphenated, and option-token names share one rule. Once such a
self-reference appears, subject/object anaphora remains bound to it through the
rest of the option block and must also match a positive template. Concrete
customization, policy, runtime, and environment claims are still validated
separately. This default-deny self-reference rule avoids treating an
ever-growing list of negative auxiliaries as a semantic parser.

Require every public option used by the final review command to appear exactly
once in the bounded `--help` output from the
verified executable snapshot. This includes print mode, model and effort
selection, structured output, session non-persistence, safe mode, permission
mode, settings and MCP isolation, browser and slash-command disablement, and
the tool boundary. The permission-mode help must advertise `dontAsk` before a
Linux/WSL2 credential can be exposed. macOS retains `Read`, `Grep`, and `Glob`;
Linux and WSL2 expose only `Read`. Do not exact-match the complete help text,
whitespace, descriptions, or unrelated options. Although upstream notes that
general help can omit some supported flags, an omitted public option or
required mode that this helper actually invokes is treated as incompatible and
fails closed.

For safe mode, require one unambiguous option and positive semantics that disable
local customizations, including instructions, skills, plugins, hooks, MCP
servers, custom commands and agents, and other user/project configuration, while
preserving authentication, model selection, built-in tools, and permission
handling. Reject negated, duplicated, internally contradictory, or weakened
semantics. Accept harmless wording, wrapping, punctuation, and ordering changes
when those required and forbidden meanings remain unambiguous.

The customization-disablement evidence is a bounded whole-sentence positive
grammar, not unordered keyword presence. The accepted claim must state that all
of the enumerated customizations start, are, remain, or stay disabled, optionally
for a bounded whole-review/session duration. The exact upstream
troubleshooting-purpose suffix remains accepted because it does not add a
runtime predicate. Temporal transitions such as executing before disablement
or restoring after startup are rejected even when the same sentence also
contains every required noun and the word `disabled`. Every sentence in the
option block is default-denied unless it independently matches one bounded
grammar for customization disablement, managed-policy preservation, runtime
preservation, the exact environment assignment, a positive safe-mode self or
anaphoric claim, or a bounded documentation/information topic that remains
available online. This avoids relying on open-ended lists of customization names
or unsafe verbs such as `restore`, `honor`, or `enable`.

Treat each required meaning as a bounded positive claim rather than a bag of
substrings. Required terms use token or phrase boundaries; unrelated sentences
may use harmless negation, but a relevant sentence fails closed on negation,
exceptions, conditions, contrasts, modality, temporary/default qualifiers, or
the opposite state. Require exactly one complete
`CLAUDE_CODE_SAFE_MODE=1` assignment, so longer values, prefixed names,
duplicates, and conflicting assignments cannot satisfy the probe.

Neither path claims a credential-free fixed-input behavioral canary. Preflight
capability evidence consists of the accepted release range, required public
options, and parsed safe-mode semantics. It proves only the advertised surface,
not actual launch semantics or the final merged sandbox. Behavioral acceptance
comes from the final real review invocation plus the canonical preflight-bound
strict stream validator, exact effective-model, error-state, and terminal-
artifact validation. Both launch paths bind Claude output to the selected
compatible version and closed stream profile; their workspace, executable-
launch, sandbox, and authentication contracts remain separate.

The outer sandbox remains authoritative for host filesystem, process, write,
and network isolation after these probes pass. It deliberately makes the
platform credential carrier readable to the trusted Claude process, so the
Linux/WSL2 permission policy is an additional publisher-runtime boundary for
model-invoked file reads. A future CLI may preserve every documented flag while
changing internal behavior; it must still satisfy both layers before receiving
credentials or review data.

## Supported Platforms And Outer Sandbox

The Claude lane supports only these helper enforcement shapes:

- **macOS:** an official thin arm64 or x64 Mach-O Claude Code artifact inside a
  helper-generated Seatbelt profile, currently launched through
  `/usr/bin/sandbox-exec`. The manifest platform key follows the artifact
  architecture; an x64 artifact may run through Rosetta on Apple Silicon.
- **Linux:** a native ELF Claude Code binary inside a helper-generated
  `bubblewrap` sandbox, with `socat` available for the helper-controlled network
  relay.
- **WSL2:** the Linux ELF and `bubblewrap`/`socat` path, only after the kernel
  release or version contains an explicit `wsl2` or `microsoft-standard`
  identity marker. `/run/WSL`, any nonempty `WSL_INTEROP` value (including an
  invalid or missing endpoint), distro environment, the generic binfmt marker,
  and a generic `microsoft` kernel identity are conservative weak WSL-presence
  evidence. They cannot authorize WSL2 support, and ambiguous or spoofed state
  may therefore fail closed as unsupported WSL1. A custom kernel without a
  recognizable WSL2 marker is unsupported whenever one of those weak signals
  remains. If a
  guest also removes every weak signal, it is observationally indistinguishable
  from native Linux and follows that classification. The shared Linux/WSL mount
  guard therefore rejects positive DrvFS/Windows provenance independently of
  WSL classification; positively identified WSL2 additionally requires proven
  local native Linux backing.

Native executable-shape checks reject interpreter wrappers and incompatible
artifacts; they do not prove publisher identity or distinguish every possible
native launcher from the publisher artifact. Linux reads ELF metadata from a
no-follow descriptor with exact-size reads and compares descriptor metadata
before and after parsing. A stable malformed or truncated artifact is invalid,
while an in-range short read, descriptor I/O error, or metadata change is
inconclusive and cannot authorize fallback. Publisher identity is established
later and separately by the Anthropic-signed manifest plus exact artifact size
and SHA-256.

WSL1 and native Windows are unsupported because this helper contract does not
provide an enforceable outer sandbox for them. Do not silently run Claude Code
without the outer sandbox. Missing Seatbelt, `bubblewrap`, `socat`, required
namespace support, trusted GPG, trusted `rg`, or another secure-runtime
prerequisite is runtime unavailability for an automatically discovered candidate
and a blocked configuration error for an explicit override.

WSL2 must keep the discovered Claude executable, local-login credential source,
frozen review/state container, and helper runtime state on the WSL Linux
filesystem. Runtime state includes the provenance cache, verified executable
snapshot, the dedicated private GPG temporary root, isolated home/temp/config
directories, proxy socket, compiler output, and mounted runtime dependencies.
The helper first rejects lexical or resolved literal paths such as `/mnt/c`,
then strictly parses bounded `/proc/self/mountinfo` and checks the deepest mount
covering each path. Known DrvFS or Windows-drive provenance in the filesystem
type, source, or mount options is blocked. Only WSL's local ext4 storage with a
`/dev/sdX` source and backing-free tmpfs are currently treated as proven by this
inspection. Overlay, FUSE, 9p, virtiofs, loop/device-mapper/network-backed, and
unknown filesystems are inspection-inconclusive: mountinfo path strings cannot
prove their backing dentries, so the helper does not recursively guess at
overlay layers. GPG root validation batches its complete path chain against one
mountinfo snapshot per check, including ancestors hidden by a Linux submount.
This also rejects a custom automount root, bind mount, or alias that hides the
literal `/mnt/<drive>` name. Missing, unreadable, malformed, oversized,
non-canonical, or non-covering mount information fails closed instead of
assuming Linux ownership and mode semantics. This proof trusts the WSL kernel's
`/proc/self/mountinfo` report and excludes a malicious WSL root from the threat
model; a future broader storage policy needs device-identity or backing-object
proof, not a larger filesystem-name allowlist.

Every mount point and every ordinary filesystem root must remain an absolute
canonical path. The one bounded kernel-native exception is an exact `nsfs`
record whose root matches a lowercase namespace name plus one unsigned 64-bit
inode, such as `net:[4026531840]`; Linux `nsfs_show_path` emits this opaque form
for namespace bind mounts. The opaque root is retained only as parsed metadata
and never participates in path coverage or Windows-provenance decisions.

Linux/WSL2 runtime directories use create-or-validate semantics. The helper may
create a missing directory with its required mode, but an existing directory
must already be a real current-user-owned path, exact `0700` where private or
otherwise non-group/world-writable, and stable across no-follow path/descriptor
inspection. It never follows a symlink or repairs a pre-existing path with
`chmod`.

After provenance, each dynamic loader/library path and every parent component
is captured with its owner, mode, device, inode, type, size, and timestamps.
Those identities are revalidated when the sandbox command is assembled and
again before mounting, so a root-library path cannot be swapped after `ldd`.
The fixed no-shell proxy/reaper launcher also blocks `SIGTERM`, `SIGINT`,
`SIGHUP`, and `SIGQUIT` across each fork/process-group handoff, checks pending
signals before publishing child state, restores default child handlers, forwards
cancellation to the proxy and workload groups, and terminates/reaps leftovers.

The final sandbox exposes only the frozen review workspace, helper-owned control
files, selected runtime files, validated certificate copies, the restricted
review-tool path, and the platform credential carrier. Network traffic is routed
through a helper-owned proxy with the same explicit Anthropic-target policy used
by the review lane. Claude's built-in sandbox is not relied upon for the outer
host boundary. On Linux and WSL2, however, the signed Claude permission engine
is part of the trusted computing base for the narrower distinction between
runtime authentication reads and model-invoked file reads.

Custom TLS sources are copied rather than mounted from their original paths.
The Claude-only `NODE_EXTRA_CA_CERTS` input uses the same absolute-path, stable
no-follow identity, owner/mode, bounded-read, PEM-only, private-key rejection,
and private-`0600` materialization policy as the existing CA-file inputs. On
macOS, the proxy snapshot digest binds the exact captured file bytes rather
than only normalized certificate blocks. The final merged bundle is atomically
materialized in helper-private storage and changed to exact `0400` mode. The
helper verifies its exact path, mode, and digest while constructing the
Seatbelt profile and repeats the same checks immediately before `sandbox-exec`
launch. This detects ordinary
path and content drift at the helper boundary. As with the Linux mount
handoff, it does not claim protection from a malicious same-euid host process
after the final check.
`SSL_CERT_FILE` and `SSL_CERT_DIR` retain their existing handling. The latter is
enumerated through a fixed directory descriptor with bounded entry counts and
supports normal OpenSSL hash links, including the multi-hop relative/absolute
layout used by Ubuntu. Link depth and path components are bounded; every
traversed link and directory plus the final no-follow regular file is
owner/mode/identity checked and revalidated around a bounded read. Only PEM
certificates are materialized, never private-key material. The helper keeps the
original hash basename but writes a private `0600` regular file instead of
recreating a symlink. Multiple configured directories form one certificate
union: safe empty directories do not reject a later admissible certificate, but
the complete union must contain at least one certificate. Every configured
directory is still validated, so an unsafe member blocks even when another
member supplies a valid certificate. Empty-certificate classification uses a
dedicated exception type rather than source-path or error-message text; a file
name therefore cannot disguise private-key or malformed-certificate rejection.

On macOS, caller CA inputs use owner-only, single-link regular-file reads with
no symlinks, FIFOs, extended ACL entries, or identity/growth races. The helper
captures bounded certificate material once for the proxy while retaining an
exact raw-byte digest binding for later runtime preparation. Before every
attempt it re-exports user, admin, and system
trust settings into bounded helper files. The exact no-settings response is
accepted only with `security` status `1`; signal and other abnormal exits remain
inconclusive. Explicit deny wins even when another
domain or sibling entry is malformed. Constrained, missing, expired, non-root,
or otherwise invalid additional certificates are excluded from the complete
merged bundle, regardless of which input also contains them. The exact embedded
root set is evidence derived from the publisher-verified snapshot; if a host
policy excludes a root still reachable through Claude's bundled store, the lane
blocks rather than weakening signed provenance. Every trust preparation writes
a sanitized terminal `claude-trust-policy.json` record.

Upstream HTTPS proxy trust is prepared separately from Claude runtime trust.
Caller CA files and directories are copied once into a dedicated helper-owned
snapshot for the complete model chain, preserving proxy CA precedence while
excluding publisher-bundled and host-added Claude roots. The helper initializes
one in-memory TLS context from the captured bytes and reuses it for every
upstream proxy connection. Replacement directories contribute only canonical
OpenSSL hash-index entries whose suffix sequence and certificate subject hash
are verified with the fixed OpenSSL client under one shared 20-second deadline
and a 512-certificate budget for the complete snapshot and replacement-context
initialization. The deadline is rechecked after each subprocess and before
acceptance; duplicate material is verified once. The in-memory context enables
strict X.509 verification and partial-chain trust anchors without loading
ambient roots. Default trust uses explicit compiled-in OpenSSL CA-file material
captured through the same stable descriptor reader. On Linux, a symlinked
compiled-in CA file is not followed; the helper instead snapshots and
hash-validates the compiled-in CA directory when available. It never consults
caller-controlled environment lookup or retains a lazy CA directory. Original
caller paths are not reopened. Between model attempts, helper snapshot paths
are reopened only to verify their exact raw-byte bindings; individual upstream
connections continue to reuse the already prepared in-memory context without
reloading trust material.
An unconstrained `TrustRoot` entry must be a strict currently valid self-signed
CA root. An unconstrained `TrustAsRoot` entry may instead be a non-self-issued
CA or intermediate certificate: it must retain strict CA and certificate-signing
extensions, a current strict DER validity window, and a parseable public key.
When the selected highest-priority domain contains independent unconstrained
`TrustRoot` and `TrustAsRoot` entries for one fingerprint, the helper preserves
both authorizations. It accepts the certificate when either the strict
self-signed-root validation or the non-self-issued TrustAsRoot validation
succeeds; one authorization does not collapse or replace the other. A
lower-priority domain cannot add, remove, or constrain those selected
authorizations. Explicit deny, malformed policy, and constraints selected from
the highest-priority domain retain their terminal precedence.
The fixed OpenSSL client performs partial-chain validation when it advertises
that capability. Apple's fixed LibreSSL omits partial-chain support, so that
host uses the same deterministic DER policy plus bounded public-key extraction;
the ignored issuer signature is not part of an explicitly selected trust
anchor's authority.
The fixed Security and OpenSSL tools are unavailable only when their inspected
executable or a deterministically required capability is absent. A signal,
unexpected nonzero exit, unknown help output, or failed `find-certificate` or
certificate-verification operation is inspection-inconclusive and cannot
authorize reviewer fallback.

Linux and WSL2 coalesce validated certificates into the existing single private
bundle mounted read-only at `/etc/ssl/certs/ca-certificates.crt`. If
`NODE_EXTRA_CA_CERTS` is the only configured CA input, the helper begins with
the default system trust and appends and deduplicates the Node certificates. If
a replacement input (`CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, or `SSL_CERT_DIR`) is configured, the
helper preserves the existing replacement semantics, then appends and
deduplicates the Node certificates. The sandbox sets `NODE_EXTRA_CA_CERTS` to
the fixed bundle path only when the caller explicitly supplied it; no additional
host mount is created. The same private bundle also remains the final sandbox's
`SSL_CERT_FILE`. This is an intentional single-bundle runtime design, not a
claim that replacement and additive inputs become separate in-sandbox trust
domains. The helper's parent/proxy TLS context still consumes the original
caller environment and does not read `NODE_EXTRA_CA_CERTS`. The bundle's
complete resolved path identity is captured and rechecked while the read-only
`bubblewrap` command is serialized. Like the existing runtime-library mounts,
this fixes the selected resolved source but does not claim an FD-bound, atomic
path-to-mount handoff against another same-euid process.

`SSL_CERT_FILE` remains an independent caller input for the helper's parent/proxy
TLS path and does not cause the Node variable to be set. The parent proxy TLS
context, pre-provenance candidate probe, GPG, and security-sensitive host-tool
environments do not consult `NODE_EXTRA_CA_CERTS`. Arbitrary `NODE_*`,
`NODE_TLS_REJECT_UNAUTHORIZED=0`, mTLS private-key inputs, and private-key
material remain outside the contract.

On macOS, each model attempt captures the parent/proxy TLS environment before
building the Claude-only merged bundle. The final review proxy uses that
pre-merge environment; only the sandboxed Claude process receives the merged
bundle through the helper-private `0400` path admitted by the Seatbelt profile.
A discovered fixed OpenSSL verifier that then fails to launch or
returns an operating-system I/O error is inspection-inconclusive, never
deterministic tool absence, and cannot authorize Copilot fallback.

Linux and WSL2 fix cwd at `/workspace`, use `dontAsk`, expose only `Read`, and
pre-approve only `Read(./**)`. Every other top-level path mounted into the
synthetic root is denied both at the root and recursively with absolute
double-slash rules, for example `Read(//auth)`, `Read(//auth/**)`,
`Read(//proc)`, and `Read(//proc/**)`. A single leading slash would be relative
to the settings source rather than the filesystem root and is not accepted.
The command builder derives top-level roots from the actual mount set and fails
closed if any lacks deny coverage; it also rejects a separate mount below
`/workspace`, where the allow rule would otherwise cover it.

Prompt path rendering is platform-specific even though the stored default
prompt remains portable and workspace-relative. Claude's `Read.file_path` input
uses an absolute path: macOS receives the helper-owned host workspace and diff
paths, while Linux and WSL2 receive `/workspace` and
`/workspace/.codex-review/review.diff`. This is distinct from the
`Read(./**)` permission pattern, whose `./` is anchored to the sandbox cwd.
Linux custom-prompt host paths are projected only when they appear as complete,
delimiter-bounded path tokens. Canonical descendants below the workspace are
preserved beneath `/workspace`; `.`/`..`/empty path components, a sibling
suffix, a diff-file extension, or an embedded-prefix occurrence are ambiguous
and fail closed before authentication instead of being rewritten by a broad
substring replacement.
The projected prompt gets an explicit Read-only tool contract and is rechecked
against the 64-KiB limit both before authentication and at the attempt boundary.

The frozen Git materializer rejects absolute symlink targets and any relative
target whose component walk leaves the workspace, even if later `..`/name
components would return to it. The pre-egress workspace scan still validates the
completed link graph. Linux and WSL2 additionally repeat a bounded no-follow
link/identity scan immediately before every isolation-probe or final sandbox
command is serialized. Stable relative links whose complete chains remain
inside `/workspace` continue to work; `/auth`, `/proc` magic links, absolute
links, transient or final escapes, loops, link races, and inspection I/O failures
all fail closed before the authenticated workload starts. As with the final
path-to-mount handoff, this does not claim protection from a malicious same-euid
host process after the last identity check.

The low-level helper's supported range starts at `2.1.211`, after Anthropic's
documented `2.1.208`
boundary for reliable propagation of `Read` rules to `Grep`, `Glob`, LSP, and
prompt file mentions. Linux and WSL2 nevertheless retain the narrower defense-
in-depth contract: they do not expose those search tools and reject ASCII `@`
file-mention syntax in the complete review prompt before launch. The frozen diff
remains available through the workspace-only `Read` tool. macOS keeps its
existing `Read`/`Grep`/`Glob` contract because Seatbelt supplies the outer
filesystem boundary.

## Credentials

Except for the canonical direct-lane authentication contract above, this
section specifies the low-level helper's private local-login credential staging
and writeback implementation. Do not apply its catalog, broker, carrier, lock,
or recovery requirements to the canonical real-`HOME` lane. The helper first
applies `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local-login
precedence; either winning explicit source bypasses this entire local-login
section.

For a catalogued local-login artifact, the credential boundary begins with one
outer host refresh transaction before the first carrier read. The certified
primary and legacy lock lease remains held while the helper selects and exposes
the credential, Claude performs any network refresh, the macOS broker or
Linux/WSL2 supervised process becomes quiescent, durable recovery state is
settled, and the latest rotation is verified in the host carrier. A concurrent
helper therefore waits before credential exposure and reads the post-transaction
host state only after acquiring its own lease. macOS snapshot and persistence
operations and Linux/WSL2 watcher writeback reuse this outer lease; the private
staged-carrier locks remain separate. A no-rotation attempt with proven
quiescence or a fully verified latest host commit releases the lease. If process
or broker quiescence is unproven, a rotation is not durably committed, a private
carrier must be retained, or cleanup cannot be proved, the helper abandons the
lease: it stops the heartbeat, closes owned descriptors, intentionally leaves
the shared lock directories as a stale fence, attaches only descriptor-bound
recovery evidence without a lexical pathname, and pauses. It never automatically
deletes that fence or treats it as authentication failure or Copilot fallback
evidence. Explicit API-key or OAuth-token mode performs no local-login carrier
read and does not enter this transaction.

An explicitly supplied `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` remains
an optional override and does not require local-login credential access or an
internal credential-lock protocol entry. Opaque-forward only the precedence
winner and remove the lower-priority explicit source. Never pass Claude and
Copilot credentials into the same child environment.

Before local-login credential access on any platform, bind the verified
executable, release version, manifest platform key, and signed SHA-256 from
`claude-runtime.json` to the exact credential-lock protocol catalog. The initial
catalog contains the six supported Darwin and Linux artifacts for `2.1.211`;
WSL2 uses its matching Linux artifact. Unknown versions, platforms, checksums,
or mismatched executable evidence are inspection-inconclusive before credentials
or review data are exposed. They are not authentication failures, runtime
unavailability, or Copilot fallback reasons. This extra gate applies only to
helper local login: an uncatalogued but otherwise compatible signed release
remains eligible for the named direct lane and for low-level-helper API-key or
OAuth-token mode.

On macOS, retain the capability-authenticated temporary Keychain broker but
allow it to coordinate the current CLI's normal refresh behavior without giving
the final Claude process direct host credential access. Before each model
attempt, after trusted executable, review-tool, and TLS preparation, the parent
reads the current-account `Claude Code-credentials` item with Apple's trusted
client. It also resolves the current account through `pwd.getpwuid(os.getuid())`
and safely inspects `<pwd-home>/.claude/.credentials.json`; caller-controlled
`HOME` never selects this source. The file must be a stable no-follow regular
file owned by the current user with exact mode `0600`, bounded size, and valid
credential JSON. This macOS file source is based on observed current Claude Code
compatibility behavior; Anthropic's public authentication documentation does
not guarantee it as the macOS storage contract.

The broker is a reviewed, prebuilt universal Mach-O with arm64 and x86_64
slices, hardened-runtime ad-hoc signatures, and a macOS 13.0 deployment target.
Its source and tracked artifact live beside `providers.py`. Runtime code pins the
artifact SHA-256 and both slice CDHashes, but never invokes a compiler or
installer. The broker uses C11 `memset_s` to clear userspace credential,
capability, script, and overflow-probe buffers before release or return. This
does not claim that compiler registers, kernel buffers, or external process
buffers are wiped. Before credential selection, it requires the exact artifact at
`/Library/Joey-Tools/CodexReview/brokers/<sha256>/security`; every ancestor must
be a real root-owned directory with no group/world write or extended ACL, and
the leaf must be a root-owned single-link regular file with mode `0555`, no
extended ACL, the pinned digest, and an accepted native dependency closure.
Missing installation is runtime-unavailable. Unsafe metadata, identity drift,
or a digest/code-identity mismatch is blocked or inspection-inconclusive and
never exposes credentials or enables an authentication fallback.

Build and install are explicit maintenance operations:

```bash
skills/review-orchestration-playbook/scripts/build_claude_keychain_broker_macos.sh \
  --developer-check
skills/review-orchestration-playbook/scripts/install_claude_keychain_broker_macos.sh \
  --install \
  < skills/review-orchestration-playbook/scripts/review_runtime/claude_keychain_broker
```

The build script has no artifact-output mode. It pins both source and artifact
digests, compiles both slices with the fixed deployment target, combines them,
applies the fixed identifier and hardened-runtime ad-hoc signature, and requires
the rebuilt SHA-256 and bytes to equal the tracked artifact. It also pins Xcode
26.6 build 17F113, the macOS 26.5 SDK, Apple clang/linker, codesign, and every
build-tool digest, and rechecks those pins after compilation. Developer and
GitHub-hosted runner tool digests are pinned separately because the hosted
`macos-26-arm64` image repackages the same versioned Xcode toolchain; both modes
must still reproduce the same tracked broker bytes.

The mandatory `broker-reproducibility` job runs `--check` as the ordinary
GitHub-hosted `macos-26` runner user. It requires the exact hosted-runner context,
pinned toolchain and tool digests, source/artifact digests, and byte-for-byte
reproduction, and never returns a skip code. This is a required reproducibility
gate, not an independent trust root or security boundary. It establishes no
trusted-builder, root-sealed, or root-owned provenance. Required review and
branch protection protect changes to the workflow, build script, source,
artifact, and pins that define the gate. `--developer-check` is only a local
convenience for reproducing the pinned bytes; it is not the required hosted gate
and establishes no provenance.

The shell opens the tracked artifact for stdin before the non-root installer
entry invokes `sudo`. The entry freezes the reviewed production functions into
the root command value already held in memory; root therefore never resolves or
reopens either the checkout script or artifact path. The root worker accepts no
path or policy parameters and runs under a scrubbed environment. It writes the
already-opened bytes into a private `0600` staging file inside the digest
directory, verifies the exact size, pinned digest, and all-architecture code
signature, then applies the final root-owned `0555`, single-link, no-ACL
metadata before an atomic no-clobber rename. It creates missing digest-keyed
directories with safe metadata but only validates existing shared parents; it
never changes an existing directory's owner, mode, or ACL. An artifact rotation
uses a separately reviewed release procedure to create the candidate and must
update every coupled pin in the same reviewed change: `providers.py` runtime
artifact SHA-256 and both slice CDHashes; installer expected SHA-256 and byte
size; build-script source/artifact SHA-256, Xcode/SDK version and build pins,
tool versions, and clang/ld/lipo/vtool/`codesign_allocate`/codesign digests; and
`test_installer.py` expected SHA-256, size, and native architecture/signature
identity expectations. The ordinary-user GitHub-hosted `macos-26` `--check`,
macOS tests, required review/branch protection, and explicit digest-keyed
installation must then pass. The verifier never emits or overwrites a candidate
and must not replace or reinterpret a different installed digest in place.

The capability is never placed in the Claude environment. A private Unix
identity endpoint releases it only to a same-user/same-group process whose PID
is in the committed Claude session and process group and whose running CDHash
matches one pinned broker slice; session and process-group membership are
rechecked after CDHash inspection. The Seatbelt rule uses the kernel canonical
socket path obtained from the open directory descriptor, while the broker
connects through the stable volume/inode path. The broker then presents the
capability to the loopback credential server and must receive an authorization
ACK before reading `security -i` stdin or requesting the initial credential.
Replacing the Unix socket can therefore cause denial of service but cannot
obtain a usable capability or credential payload.

Runtime process binding is deliberately two phase. First, a deadline-bounded
daemon worker performs only pure PID/session/process-group inspection and returns
an immutable binding; it receives no credential-service object, owns no server
lock, and cannot commit or retain service state. After that worker finishes in
time, the parent thread rechecks the absolute attempt deadline and performs the
nonblocking credential-server commit. A busy or changed binding fails closed.
Only the parent thread can then send exec authorization, after another deadline
check. A late inspection result is inert: it cannot mutate, authorize, or retain
the credential service after the parent has timed out or begun cleanup.

Credential selection and the immediate comparison copy live inside one outer
`try/finally` zeroization owner. That owner is established before runtime locks,
events, random capability material, durable-stage state, or broker initialization
and scrubs both buffers on selection-copy failure, initialization failure,
control-flow exit, and ordinary teardown.

Identity-service startup observation and failure cleanup share one absolute
deadline, including the shutdown request and joins. Once bind may have happened,
every startup failure first runs bounded cleanup. Forwarded signals and other
control-flow exceptions win over ordinary inspection/cleanup diagnostics, while
the losing diagnostics remain attached. Every model attempt allocates a fresh
private identity directory; no later attempt reuses the endpoint. Cleanup
verifies the originally bound socket's device/inode identity but never unlinks
that pathname after a separate stat; whole-run private-directory cleanup owns
removal. A replaced or missing entry is inspection-inconclusive and is never
deleted by name.

For each structurally valid source, require non-empty access and refresh tokens
that encode as UTF-8 without unpaired surrogates, and parse the access-token
expiry. Access-token expiry alone is not login expiry. Select
the candidate with the later expiry even when both access tokens are already
expired, then load that payload into the broker. The broker serves the initial
fixed lookup once and accepts only the exact bounded credential-store update
forms needed for refresh. Concurrent updates receive monotonic generations.
Every `W` generation admitted to durable staging first atomically reserves
generation and payload-byte quota before any filesystem
write. The attempt-scoped durable journal accepts at most eight generations and
8 MiB of payload. A reservation remains consumed for the rest of the attempt,
including when the later filesystem write or generation publication fails. The
generation writes a distinct private recovery carrier, synchronizes its file,
containing directories, review-container entry, and review-root entry, renames
it under a synchronized parent, and reads back the exact payload. On Darwin,
each such synchronization runs `fsync` and then requires `F_FULLFSYNC`; the
same barrier covers pwd-home host-file replacement before the final recovery
carrier can be removed. A missing command or failed full sync is
credential-inspection-inconclusive and cannot authorize acknowledgement or
cleanup. If the final carrier rename completed before a full-sync or identity
check failed, only an exact re-proof of the acknowledged path and payload digest
may retain it as recovery-only evidence; it is never published for host
writeback. Only after that durable commit does the broker enter the generation
linearization point under the current-generation lock. It publishes and
acknowledges the generation only if it is still current and the runtime is not
abandoned. The eighth generation and final 1 MiB are reserved for terminal
recovery. When an update would enter that reserve, the server atomically closes
later update admission only if that update is still the current pending
generation, commits the exact payload into the terminal slot, and returns a
NACK without calling the publication linearization point. A superseded
candidate consumes no quota or filesystem work; later `W` requests are
explicitly NACKed before their callback. The terminal generation invalidates
any older staged host-writeback candidate, records
credential-inspection-inconclusive, and pauses without Copilot fallback. A
superseded, abandoned, or failed generation returns failure without
acknowledgement, but its carrier remains in the bounded journal until
post-quiescence finalization or failure recovery. A successful broker acknowledgement therefore proves durable
recovery staging, not host persistence or an absolute power-loss guarantee.
`F_FULLFSYNC` is Darwin's strongest available best-effort persistence request,
and storage hardware may still fail to honor it. A
generation that fails structural validation invalidates any older published
host-writeback candidate while leaving the older durable carrier available for
recovery. It never exposes
`/usr/bin/security`, the Keychain service, the file source, or arbitrary update
commands to Claude. The parent retains both carriers' existence, payload and
refresh-token digests, plus the file identity, not only the selected carrier.
Carriers with the same refresh-token digest are one logical login even when
their access-token payloads or expiry metadata differ. After the server and
every handler have quiesced, the outer runtime is the single host-persistence
owner: it detaches the latest acknowledged credential, removes older durable
generations only after the newest is proven, and then acquires the
artifact-certified primary `.oauth_refresh.lock` and legacy sibling lock. A
quota rejection, malformed update, or failed durable stage may leave no staged
host-writeback candidate. In that case finalization selects and reports one exact
verified complete journal carrier as the sole current recovery credential,
removes every other non-authoritative complete entry, and reports a stale entry
whose cleanup fails separately as `authentication.recovery_cleanup_artifact`. A
control-flow interruption while removing an older generation stops immediately:
the owner does not begin host writeback or cleanup of the latest carrier. The
latest exact-verified generation remains the canonical current carrier. If a
staged or non-staged control-flow stop leaves any stale carrier unvisited,
cleanup reporting is promoted to the macOS recovery-root scope. It
maintains the certified
5-second heartbeat, rechecks both carriers under those locks, and performs
guarded writeback against each carrier's own current payload. The helper
prevalidates the stable macOS recovery-root cleanup scope before broker exposure.
On unquiescent shutdown, the server first irreversibly closes the pending-update
publication/acknowledgement gate, then boundedly drains handlers already inside
the commit critical section. Runtime abandonment latching and pending detachment
have independent state, so detachment may be retried without reopening
publication. The abandonment callback only sets an event and is itself bounded;
it never waits for the runtime-state lock. Timed detachment uses one deadline
across both credential locks and transfers no payload on timeout. A terminal
durable stage racing the abandonment event either self-registers or is
transferred to the quiescence stage by the bounded recovery worker under the
runtime lock. Recovery executes for a detached `None` payload as well as a
credential payload and converges that stage. Recovery-timeout reporting takes
only a nonblocking runtime-state snapshot. If the lock is contended, it reports
the stable macOS recovery-root cleanup scope without claiming a current carrier.
Once quiescence is unproven, outer finalization does not wait for or consume
runtime state still owned by a late handler or recovery worker.
Whenever abandonment recovery sees any durable journal entry or quiescence
stage, the final error also reports that root so old generations, a failed
quiescence stage, and any fallback retain visible ownership even beside an exact
current carrier. After an actual bounded recovery timeout, the handler/recovery state machine
is the unique owner of any in-flight stage cleanup. A stage or fallback that
completes late is exact-cleaned by that state machine or remains inside a
pre-reported recovery-root cleanup scope. A handler that
finishes a durable write after abandonment cannot acknowledge, mutate host
state, or overwrite the authoritative fallback. When no `W` generation exists,
shutdown uncertainty reports the quiescence failure without a current recovery
credential; a pre-reported recovery-root scope remains cleanup-only. A bounded heartbeat join timeout
marks the lease as release-started, not release-complete.
The owning release call performs one further bounded
cleanup attempt while preserving the first timeout as its primary diagnostic;
if both joins time out, it reports cleanup as inconclusive and pauses for
controlled operator cleanup after confirming that no credential writer remains.
Intentionally retained shared refresh-lock directories never authorize a lexical
recovery or cleanup pathname; report only descriptor-bound residue. The lease
then remains terminal, so queued or later
release calls repeat the same diagnostic instead of retrying deletion.
An interruption after descriptor or lock removal starts has the same terminal
policy. Recovery metadata remains visible even when an earlier credential
operation stays primary, and a forwarded signal carries the descriptor-bound
diagnostic in its detail. It never silently labels a
potentially orphaned lock as completed cleanup. Every
successful post-quiescence write advances the full baseline, including the new
file identity, for final verification and subsequent model attempts. Supported
Claude Code login/refresh writers therefore serialize across the complete host
refresh transaction rather than only the final commit; observed concurrent
changes win and successful refresh-token rotation is normally retained. The
Keychain and POSIX file do not share one transaction. After the
file commit, a failed Keychain command therefore triggers locked readback: an
already-complete update is accepted, an exact file-new/Keychain-old state gets
one bounded Keychain retry against the original Keychain payload, and any other
state pauses without overwriting it. For a Keychain-only refresh, the same
readback requires an unrelated file carrier to remain unchanged or absent rather
than incorrectly requiring it to contain the refreshed Keychain value. If the
retry remains partial, preserve the
new file credential because token rotation may already have invalidated the old
refresh token, report the synchronization failure as inspection-inconclusive,
and pause without a login prompt or Copilot fallback. This dual-lock
compare-before-write guard is not an atomic compare-and-swap guarantee against
unrelated external writers that bypass both locks.

The same preservation boundary has two ownership domains. When broker-handler
quiescence cannot be proved, only the handler/recovery state machine retains the
newest acknowledged durable generation or materializes a newer pending
structurally validated rotation; outer finalization does not inspect that runtime
state. After proven quiescence, an outer shutdown owner handles a Keychain-only
guarded write that exhausts its bounded retry or a first file-carrier write that
fails. That owner retains the newest acknowledged durable generation only after
revalidating its carrier, or durably replaces it with a newer pending rotation
and verifies the resulting carrier before reporting it. An uncertain shutdown with no `W` generation, or a
carrier-creation failure that left no verifiable file, carries the original
failure without current recovery-credential metadata; a pre-reported
recovery-root cleanup scope remains separate cleanup evidence.
The carrier and `config` directories are `0700`; `config/.credentials.json` is
an owner-only, single-link regular file with exact mode `0600`. It is outside
the Claude-visible Seatbelt paths and is never passed through the child
environment. Report only the absolute path of a carrier or artifact whose exact
payload was verified when claiming it as current, never token contents, and
pause as inspection-inconclusive
without a login prompt or Copilot fallback.
An unverified or incomplete file is cleanup-only and may be reported only as
`authentication.recovery_cleanup_artifact`. After verified host commit, cleanup reopens the carrier through no-follow
directory descriptors, rechecks directory and credential identity, removes the
credential and directories in order, and synchronizes every containing
directory. Cleanup uncertainty pauses and reports only
`authentication.recovery_cleanup_artifact`; it never turns successful host
persistence into a claim that the leftover copy is the current credential.
An already-committed host file remains preserved. If recovery replacement or
finalization fails after a complete private update file was written, retain and
report that exact artifact instead of losing its location. A later successful,
read-back-verified replacement removes bounded stale update artifacts. If no
complete recovery copy can be proven and no artifact actually exists, report no
candidate or attempted path. If an actually existing incomplete update cannot
be removed or safely inspected, report its exact path only as cleanup residue;
never present it as a recoverable current credential.

The current recovery credential and cleanup residue are separate report fields.
Before a verified recovery commit, a complete uncommitted update whose no-follow
path identity and exact payload are reverified after the triggering failure is
`authentication.recovery_artifact`. After a replacement is fully fsynced and
read-back verified, `config/.credentials.json` is the current
`authentication.recovery_artifact`. If deleting an older temp fails, its exact
path is `authentication.recovery_cleanup_artifact`. An incomplete update that
cannot be removed uses the same cleanup-only field. Neither an older nor an
unverified or incomplete artifact is ever described as the newest or current
recovery value. A temp that disappears before final post-failure path
verification is neither current nor cleanup metadata.

Recovery-carrier removal advances cleanup ownership only after each destructive
syscall: from the credential file to `config`, then the carrier, then the stable
recovery root. A current credential is republished after a cleanup failure only
when its no-follow identity and exact payload are still proven. Cleanup metadata
must name an existing no-follow identity-stable scope. A vanished child is not
reported, while concurrent entry churn beneath the same directory inode does
not invalidate that directory as the cleanup scope.

Current-artifact proof is bound to the authoritative source content, not to
whatever bytes happen to occupy the reported path later. Marker capture receives
the digest already proven by durable staging or exact recovery writeback, rejects
a payload mismatch, and freezes the absolute path, strong file identity, and
complete root-to-parent no-follow ancestor chain. A same-content replacement
before capture is harmless and becomes the marker-time identity only after the
same owner, mode, and exact digest checks; a same-content replacement after
capture is rejected. Reporting reopens and rechecks every directory edge plus
the credential inode and digest. Path/proof propagation and clearing are paired,
so a bare path, a post-capture new inode, or an ancestor replacement cannot be
promoted to current recovery metadata.

The `security -i` transport-size limit applies only when the selected source is
the Keychain or when matching refresh-token digests require a file-selected
rotation to update the Keychain too. A structurally valid but unselected
Keychain credential from a distinct logical login remains part of the observed
snapshot, but its encoded update size does not block an independently usable
file credential that will never write that Keychain item.

Helper-lock or Claude-lock contention, heartbeat/lease compromise, a stale
shared lock, a change to either macOS carrier, and credential inspection I/O uncertainty are
inspection-inconclusive. They pause the lane without a `claude auth login`
instruction and without Copilot fallback because they do not prove that the
login is invalid. The helper never automatically deletes a stale shared lock;
controlled cleanup requires first confirming that no credential writer remains.

On Linux and WSL2, every model attempt validates the documented Claude Code
credential file as a non-symlink regular file owned by the current user with
exact mode `0600`. Access and refresh tokens must be non-empty UTF-8-encodable
strings without unpaired surrogates; the same parser rejects an unsafe staged
rotation before host writeback. Before the first credential read, the helper
opens every absolute directory component from the filesystem root through the
credential parent with `O_DIRECTORY|O_NOFOLLOW`, retains that complete
descriptor chain for the attempt, and rejects a symlink at any ancestor or the
credential leaf. Reads, directory locking, refresh-lock mutation, replacement,
and parent-directory sync stay relative to those retained descriptors; the
helper revalidates every path edge before commit and after sync, so retargeting
an earlier ancestor cannot redirect a read or write into a replacement tree.
The refresh-lock helper's borrowed anchors are descriptor-only; the credential
anchor owns complete edge revalidation. If cleanup of a descriptor-bound lock
fails after path movement, the helper publishes no lexical cleanup path because
that pathname is no longer authoritative; it pauses with an identity-only
recovery warning instead of directing cleanup at a replacement tree. On watcher timeout, an explicit
cleanup-reached handoff makes either the parent or the exiting worker close the
descriptor chain, whichever completes the ownership transition last, without
waiting behind filesystem inspection. For that attempt, copy it into a new helper-owned writable
`/auth` carrier root with private config at `/auth/config`; the original host
credential is never mounted. The layout permits the primary lock under the
config plus the legacy sibling `/auth/config.lock`. Before binding the carrier
root at `/auth`, require its canonical `config` child and direct-helper-root
shape, and reject any equality or ancestor/descendant overlap with the separate
helper home or temporary roles; one host directory must never be exposed at
both an authentication and a general writable mount. Require valid credential
JSON plus a usable refresh token, but do not require future access-token
lifetime. The trusted runtime may update only the staged carrier through its
authentication path, while the inner permission policy denies all of `/auth`
from model-visible `Read`. A 50-ms metadata watcher takes staged locks only after
a possible change, releases them before taking host locks, validates the stable
payload, and guarded-writes every rotation while advancing its payload and file-
identity baseline. After an ordinary watcher stop, a bounded synchronous final
drain rechecks the staged and host states before cleanup. A normal supervisor
return, including a nonzero Claude exit, proves that the supervised `bubblewrap`
process group is quiescent. If exact helper-owned staged primary or legacy locks
remain at that point, first preflight both paths as unchanged, empty,
current-user-owned `0700` directories, remove them in reverse acquisition order,
and retry the final drain once. Freshness is irrelevant for this narrowly scoped
recovery because process quiescence is the safety proof. Never apply it to the
host credential directory or a shared lock. If the supervisor times out or
reports a process leak, lock recovery is unsafe, the retry fails, or guarded host
writeback remains unproven while a staged update may be newer, retain the private
carrier under the review container and record its recovery path without token
contents. Stop first linearizes closure of new background-writeback admission,
so a candidate whose last blocking read completes after closure cannot begin
host writeback. If the initial bounded watcher join itself times out, classify
the attempt as inspection-inconclusive, retain the carrier immediately, and
skip concurrent final drain, payload scrubbing, and carrier cleanup. If a
background writeback was admitted before stop and remains in flight, report
host state as ambiguous because that already-started commit may still complete;
do not claim an exclusive recovery handoff. The watcher is a daemon only so
such an uninterruptible operation cannot keep the helper alive after the
bounded failure report; normal paths still join it and the recovery copy is
never silently deleted. A control-flow signal is re-raised only after the
retained path has been attached to its visible diagnostic. The parent uses the
same artifact-certified primary and legacy host locks with heartbeat and rejects
any external host change instead of adopting it. This serializes the complete
attempt with supported Claude Code login/refresh writers but cannot atomically
close it for unrelated writers that bypass both locks. Reject
unsafe ownership,
mode, symlink, path-race, size, or JSON structure, and never persist or print
credential contents in review state. Every retained source descriptor must close
successfully before a validated payload is returned; close failure zeroes the
in-memory copy, preserves any earlier validation/control-flow error, and fails
closed without retrying the same numeric descriptor.

Credential staging owns cleanup from the first successful create through the
final close. Ordinary successful and non-recoverable cleanup scrubs, closes,
unlinks, and removes directories in a bounded order even when the body exits
through cancellation or generator closure. The intentional exception is an
unpersisted, still-usable staged credential: if writer quiescence or guarded
writeback cannot be proved, leave its exact-mode-`0600` file inside the
exact-mode-`0700` carrier, retain the review container, and expose only the
carrier path as recovery metadata. A cleanup-time `KeyboardInterrupt`, `SystemExit`, or other
`BaseException` control-flow signal is never converted into an ordinary
credential error; an already-active body exception remains primary and receives
the cleanup diagnostic. Python 3.10 records that diagnostic in the preserved
exception chain through a dedicated diagnostic cause because
`BaseException.add_note()` is available only from Python 3.11.

A private staged carrier prevents direct host-file mutation but does not hide a
secret from the Claude process that must authenticate with it. The Linux/WSL2
inner permission policy therefore denies `/auth` from model-visible `Read`.
In explicit API-key or OAuth-token mode, it also
denies `/proc` and `/dev` so `Read(//proc/self/environ)` and file-descriptor
aliases cannot expose the winning authentication variable. This boundary trusts the
publisher-verified Claude runtime to enforce its own tool permissions against
prompt injection; `bubblewrap` cannot distinguish two reads made by the same
process. Stronger isolation would require an external authentication proxy that
injects credentials without ever placing the real secret in the Claude process.

## Runtime Report

The helper writes `claude-runtime.json` so retained state distinguishes the
candidate that was discovered from the executable that was actually accepted.
Its trust fields include `source_executable`, `verified_executable` (the private
snapshot reused by the complete model chain), release version/platform,
manifest and signature URLs, signed checksum, publisher fingerprint, and the
separately trusted fixed source path in `gpg_verifier`. The ephemeral private
GPG execution snapshot is deliberately not a durable trust identity; the report
labels the source as `gpg_verifier_trust: fixed-path-native-host-tool` and keeps
publisher provenance separate.

The phase and nested status fields advance only as their enforcement point is
reached:

1. `publisher-and-capabilities-verified`: the signed release, private snapshot,
   and safe-mode/help capability contract passed. `outer_sandbox.status` remains
   `pending-runtime-launch` and `authentication.status` remains `pending`.
2. Authentication preparation records only the selected carrier kind and
   readiness state; it never persists credential contents, refresh tokens, or
   bearer-capable expiry metadata. Artifact lock-protocol certification happens
   before either local-login carrier is read. macOS reaches `sandbox-auth-staged`
   only after both carrier snapshots are captured and the selected source is
   loaded into the restricted broker. Linux/WSL2 reaches it only after the
   private staged carrier and real isolation probe are ready. Access-token expiry
   alone does not create an error phase.
3. Authentication failure is explicit. Missing, malformed, unsafe, or
   refresh-token-less local credentials, plus a final-runtime `Login expired`,
   HTTP 401, or refresh failure, write `blocked-authentication` and the operator
   action `claude auth login`. A rejected explicit API key or OAuth token instead
   instructs the operator to unset or replace its exact winning variable; an
   explicit source is not evaluated as a helper local-login refresh token. The
   phase carries no Copilot fallback eligibility.
   Credential-source/broker I/O races, lock contention, heartbeat failure,
   uncatalogued lock protocols, or bounded-supervision failures remain
   inconclusive. For every Keychain-broker, TCP-proxy, and Unix-proxy endpoint,
   only an explicit OS policy or socket-capability bind errno is deterministic
   secure-runtime unavailability. Unknown, resource/capacity, or
   address-contention bind errors, Unix-socket permissioning failure,
   thread-start failure, serve-start uncertainty, and a post-ready serve-loop
   failure are inconclusive, while an unsafe broker is blocked. When
   refresh persistence leaves a private carrier for operator recovery,
   `authentication.recovery_carrier` records only that path and never the
   credential payload. A simultaneous final-runtime authentication rejection
   remains the primary `blocked-authentication` classification, but both the
   runtime report and operator-facing error retain the verified recovery
   diagnostic. If writing that report fails, the replacement error inherits the
   same validated recovery metadata instead of obscuring the carrier.
4. Platform preparation: Linux/WSL2 reports `runtime-ready` only after the
   current attempt's credential staging and real isolation probe, with
   `outer_sandbox.status: isolation-probe-verified` and
   `authentication.status: sandbox-auth-staged`. macOS reports
   `runtime-launching` with `outer_sandbox.status: profile-generated` only when
   the restricted temporary broker and Seatbelt launch are prepared.
5. `attempt-inconclusive`: a bounded supervisor timeout, output overflow, drain
   failure, or retained descendant interrupted an attempted model launch. The
   report records `attempt.category: inconclusive` and a stable `failure_class`
   rather than leaving an earlier readiness phase as the apparent terminal
   result.
6. `attempt-complete`: the report records the final sandbox status, attempt
   category, bounded reason and return code, and requested/effective model and
   effort. A separate `claude-trust-policy.json` generation records the terminal
   trust/bundle result for the latest attempt.

These records are evidence about which gates ran; an early phase must never be
described as an enforced final launch.

## Failure Classification And Low-Level Fallback

| Condition | Terminal classification | Copilot fallback |
| --- | --- | --- |
| No automatic candidate, supported platform unavailable, or a shared-range automatic candidate in the low-level helper path cleanly lacks a required non-security capability or secure runtime dependency | `runtime-unavailable` | Only after a separate explicit supplemental Copilot request; never satisfies named double |
| A helper-owned Keychain-broker, TCP-proxy, or Unix-proxy bind fails with an explicit OS policy or socket-capability errno | `runtime-unavailable` | Only after a separate explicit supplemental Copilot request; never satisfies named double |
| The pinned root-owned Keychain broker is missing | `runtime-unavailable` before credential selection | Only after a separate explicit supplemental Copilot request; never satisfies named double |
| The installed Keychain broker or an ancestor has unsafe metadata, identity drift, an unexpected digest/CDHash, or an invalid native dependency closure | `blocked` or `inconclusive`; report the exact verification gate and pause | No |
| Local/API/OAuth authentication is missing, malformed, unsafe, refresh-token-less when applicable, or actually rejected as `Login expired`, HTTP 401, or refresh failure | `blocked-authentication`; request `claude auth login` for local login or unset/replace the exact explicit API/OAuth variable, then pause | No |
| Signed artifact has no exact credential-lock protocol entry, either macOS carrier changed, lock contention/heartbeat failed, or credential inspection was unstable | `inconclusive`; report the exact coordination/inspection gate and pause without a login prompt | No |
| The current macOS update would consume the reserved eighth generation or final 1 MiB | `inconclusive`; atomically close later `W` admission, durably stage that current update in the terminal recovery slot, invalidate any older staged host-writeback candidate, and NACK without publication or host writeback; NACK later requests before their callbacks or filesystem work | No |
| The macOS broker cannot prove handler quiescence, bounded abandonment or detach is inconclusive, or its latest acknowledged durable rotation cannot be completely guarded-written to every required host carrier | `inconclusive`; irreversibly close pending publication/ACK before draining entered commit sections, use an event-only bounded abandonment latch and timed retryable detach, transfer no payload on timeout, converge a racing terminal stage through bounded recovery even for detached `None`, and use only a nonblocking timeout snapshot; any abandonment journal/quiescence stage keeps the recovery-root cleanup scope in the final error even beside an exact current carrier; after an actual recovery timeout, let only the handler/recovery state machine exact-clean a late stage/fallback or keep it within that root scope | No |
| A verified macOS recovery replacement succeeds but deleting an older credential temp fails | `inconclusive`; report verified `config/.credentials.json` as `recovery_artifact`, report the old exact temp separately as `recovery_cleanup_artifact`, and pause | No |
| An unverified or incomplete macOS recovery temp cannot be removed or safely inspected | `inconclusive`; keep the carrier, report the temp only as `recovery_cleanup_artifact`, and never claim it is a current credential | No |
| A Linux/WSL2 staged rotation cannot be safely drained, recovered, or guarded-written to the host | `inconclusive`; retain the private recovery carrier, report its path, and pause | No |
| Explicit override has the wrong version, platform, binary shape, capability contract, or lacks trusted GPG, probe sandbox, or trusted review tool prerequisites | `blocked` configuration error | No |
| Wrong publisher fingerprint, invalid signature, checksum mismatch, contradictory safe-mode semantics, unsafe runtime metadata, or an isolation-boundary mismatch | `blocked` security error | No |
| Authoritative macOS trust deny, malformed trust policy, excluded bundled root, private-key caller CA, or mismatched bundled-root evidence | `blocked` security error with terminal trust evidence | No |
| Manifest/probe timeout, output overflow, executable resolve/stat I/O failure, other inspection I/O failure, file race, transient network failure, unknown/resource/capacity/address-contention bind failure, Unix-socket permissioning failure, broker/proxy thread-start or serve-start uncertainty, post-ready serve-loop failure, or missing trustworthy terminal artifact | `inconclusive` | No |
| Explicit model entitlement or organization-policy denial from a final review invocation after exact effective-model verification | Existing same-Claude-runtime model fallback; a different backend is supplemental only | Only after a separate explicit supplemental Copilot request; never satisfies named double |

If the primary runtime is unavailable and the authorized fallback executable is
also absent before any model launch, the lane is deterministically blocked with
non-retry exit `1`. A zero-attempt outcome never receives transient exit `75`;
that code remains reserved for actual inconclusive or transient evidence.

Authentication failure never becomes runtime unavailability. The helper reports
`blocked-authentication`, tells the operator to run `claude auth login` for local
login or unset/replace the winning explicit `ANTHROPIC_API_KEY` /
`CLAUDE_CODE_OAUTH_TOKEN`, and pauses for an explicit retry. Access-token expiry
alone is not this state: the current CLI may refresh
inside the temporary carrier, and the parent uses validated guarded writeback to
retain a rotation when the observed host source still matches.
Only stderr and structured primary error fields are failure-classification
evidence. Primary authentication evidence wins over mixed transient or
entitlement words, while repository-controlled partial result text is never
classified and cannot authorize an authentication, model, or Copilot fallback.
Only a strict entitlement result from a launched final review can advance to the
later Opus model. After the complete Claude chain is entitlement-blocked, the
low-level helper may enter its compatibility Copilot backend only when the user
separately requested that supplemental provider; named double/triple consent is
not that request, and the result never completes the Claude Code lane. Missing
or mismatched model metadata stops the lane as `runtime-unverified` or
`model-mismatch` and never authorizes fallback. `explicit-claude-review` remains
Anthropic-only.

An unsupported future patch inside the shared version range on the low-level helper path may
be treated as automatic
runtime unavailability only when it cleanly lacks a required public capability.
An uncatalogued internal credential-lock protocol is instead inconclusive for
local login and remains usable with an explicit API key or OAuth token. Evidence
of tampering, contradictory claims, or boundary failure is blocked, not converted
into availability fallback. Capacity, rate limits, timeouts, and 5xx errors never
authorize a model or backend switch. On WSL2, a path positively covered by a
Windows-backed mount or a stable workspace-link escape is a blocked
isolation-boundary mismatch. Mount information that cannot be bounded, strictly
parsed, matched to a runtime path, or used to prove local native backing is an
inconclusive inspection failure; so is a workspace-link identity race or I/O
failure. Neither case is ordinary runtime unavailability, so neither can
authorize Copilot fallback.

Claude stdout can never provide a final artifact when the process exits
nonzero. Strictly recognized failure envelopes may retain bounded structural
classification, but malformed, duplicate-key, non-standard-constant, unknown,
or success-looking nonzero envelopes are fail-closed and receive a sanitized
machine-readable attempt reason. Authentication becomes deterministic only for
the documented complete result shape, the exact known login result, no populated
error payload, and exactly one authentication signal category. The final review
invocation applies those checks to its complete supported envelope; the helper
collects fallback signal categories across both stdout and stderr, and mixed
authentication and entitlement/transient semantics remain inconclusive
regardless of which stream or priority branch supplied them.
Every supported authentication, entitlement, or transient category additionally
requires a valid `modelUsage` entry matching the exact requested model.
Entitlement also requires an explicit model-entitlement code or entitlement
text that names a model or the requested model; account-level denial of an
unrelated feature or tool remains inconclusive even with matching model usage.
Every other non-empty recursive error-payload string and the top-level failure
`result` must match the closed neutral grammar (`error` or `request rejected`).
Raw code and text values reject CR/LF before normalization. Unknown identifiers,
future denial variants, and mixed feature evidence therefore remain inconclusive
even when an explicit model code is present.
Transient classification follows the same exact failure-envelope allowlist;
stderr-only or structurally ambiguous network text remains inconclusive.
Missing, malformed, or wrong-model `modelUsage` never authorizes model or
backend fallback.

A verifier dependency is `runtime-unavailable` only when its fixed source is
deterministically absent or the supported platform/capability is not present.
A present but non-native, untrusted-owner, writable, set-id, non-executable, or
otherwise unsafe GPG/`otool`/glibc-loader candidate is a blocked security error.
A resolve, stat, open, copy, launch, or non-authentication I/O failure is
inconclusive. A final-runtime credential refresh failure is instead
`blocked-authentication`.
An operational `OSError` while creating, entering, or cleaning a helper-owned
bundled-root verification directory, and an `OSError` while closing a CA source
directory after an otherwise successful read, are likewise inconclusive.
Arbitrary programmer exceptions are not reclassified. Cleanup failure never
replaces an active trust-policy, certificate-parse, or other typed error. The
final invocation treats entitlement as fallback evidence only when the strict
structured result contains the entitlement signal; stderr-only account, plan,
or model wording remains inconclusive even beside an otherwise valid result
envelope and exact requested-model usage. The generic provenance-operation
exception therefore never authorizes Copilot
fallback; only its dedicated deterministic-dependency subtype may enter the
compatibility path after a separate explicit supplemental Copilot request.

Persist the detected runtime version, platform and architecture, source and
verified-snapshot paths, manifest and signature URLs, signing-key fingerprint,
selected GPG verifier, verified checksum, required-option and safe-mode results,
outer-sandbox implementation and status, credential mode and status,
requested/effective model and effort, and terminal category.
Never persist the manifest signing private material, credential contents, token
metadata that can act as a bearer secret, or unbounded probe output.

## Official Sources

- [Claude Code advanced setup](https://code.claude.com/docs/en/installation):
  supported native platforms, version management, signed per-version manifests,
  the fixed release-key fingerprint, checksums, and upstream platform-signature
  information. Platform signatures are not a current helper acceptance gate.
- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing): Seatbelt
  on macOS, `bubblewrap` plus `socat` on Linux and WSL2, and the WSL1 limitation.
- [Claude Code authentication](https://code.claude.com/docs/en/authentication):
  macOS Keychain storage and the Linux `0600` credential file.
- The additional macOS `pwd`-home credential-file source is an empirically
  verified compatibility source for current Claude Code releases, not a storage
  location guaranteed by the official authentication documentation above.
- [Claude Code corporate network configuration](https://code.claude.com/docs/en/corporate-proxy):
  the supported enterprise custom-CA entrypoint for Claude Code.
- [Node.js `NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#node_extra_ca_certsfile):
  process-startup handling and additive PEM trust semantics.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage): the
  supported command/flag surface and the upstream warning that general help may
  omit flags; the helper still requires every public flag it invokes to be
  declared by the installed release.
- [Claude Code permissions](https://code.claude.com/docs/en/permissions):
  absolute double-slash path syntax and the `2.1.208` boundary for propagating
  `Read` rules to other file-reading surfaces.
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks#pretooluse-input):
  the built-in `Read` tool's absolute `file_path` input contract.
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes):
  `dontAsk` denies actions that are not pre-approved in non-interactive runs.
- [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference):
  built-in tool names and file-access behavior.
- [Linux OverlayFS documentation](https://docs.kernel.org/filesystems/overlayfs.html):
  upper/lower/data-only layers, nesting, and mount-option forms that make a
  mountinfo path string insufficient as backing-object identity proof.
- [Linux proc mountinfo documentation](https://docs.kernel.org/filesystems/proc.html):
  kernel-provided mount identifiers, roots, mount points, filesystem types,
  sources, and per-superblock options.
- [Linux nsfs source](https://github.com/torvalds/linux/blob/master/fs/nsfs.c):
  `nsfs_show_path` emits namespace roots as a name plus bracketed inode rather
  than an absolute path.
- [Microsoft WSL disk-space documentation](https://learn.microsoft.com/en-us/windows/wsl/disk-space):
  WSL2 distro VHD storage and its default ext4 filesystem.
- [Microsoft WSL interop technical documentation](https://wsl.dev/technical-documentation/interop/):
  `/run/WSL` and `WSL_INTEROP` select an interop server for both WSL1 and WSL2,
  so their presence cannot identify the sandbox-capable generation.
- [Microsoft WSL custom-kernel guide](https://learn.microsoft.com/en-us/community/content/wsl-user-msft-kernel-v6):
  the documented custom-kernel verification output retains an explicit
  `WSL2-Microsoft` kernel identity marker.
- [Apple linker documentation](https://developer.apple.com/forums/tags/linker):
  third-party executables use `/usr/lib/dyld`, selected by
  `LC_LOAD_DYLINKER`; custom dynamic-linker support is vestigial and unsupported.
- [GNU C Library dynamic-linker hardening](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html):
  `DT_AUDIT` and `DT_DEPAUDIT` can introduce audit-module callbacks and hooking,
  so the host-tool closure rejects them before any real GPG execution.
- [GNU C Library list-mode source](https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/elf/rtld.c#L1766-L1792):
  glibc collects embedded audit tags from the main map before dependency mapping.
  The same pinned source's list branch prints the mapped closure and exits before
  normal relocation or application initialization; the helper proves the
  canonical loader identity before using only its direct `--list` interface.
- [Linux ELF loader source](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c):
  `PT_LOAD` file offsets, virtual addresses, and sizes are rounded with the
  architecture/page alignment before mapping, so dynamic-table identity must be
  proven at page granularity rather than only over raw segment intervals.
- [System V ELF program-header specification](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html):
  loadable segment file offsets and virtual addresses must be congruent modulo
  the page size, and `p_filesz` may not exceed `p_memsz`.
