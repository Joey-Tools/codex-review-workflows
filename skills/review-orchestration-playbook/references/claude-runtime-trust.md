# Claude Runtime Trust And Platform Capabilities

This document defines the trust and compatibility contract enforced by the
Claude Code runtime used by `isolated_review`. A documented platform or version
is supported only when every applicable gate below passes.

## Contents

- [Policy Summary](#policy-summary)
- [Acceptance Sequence](#acceptance-sequence)
- [Publisher Provenance](#publisher-provenance)
- [Capability Probes](#capability-probes)
- [Supported Platforms And Outer Sandbox](#supported-platforms-and-outer-sandbox)
- [Credentials](#credentials)
- [Runtime Report](#runtime-report)
- [Failure Classification And Fallback](#failure-classification-and-fallback)
- [Official Sources](#official-sources)

## Policy Summary

- Accept installed Claude Code release versions `>=2.1.187,<3.0.0` after all
  provenance, platform, capability, credential, and isolation checks pass.
- Do not pin the helper to `latest`, `stable`, or one current patch release. The
  helper never upgrades Claude Code and reviews the installed release it finds.
- The former exact patch pin was a compact trust-and-compatibility shortcut for
  the one CLI that receives local authentication and review data. It was not a
  reliable wrapper detector: native Mach-O/ELF shape rejects scripts and
  interpreter wrappers, while signed artifact verification separately proves
  Anthropic publisher provenance and capability probes bound the CLI contract.
- Reject prerelease, development, unparseable, and future-major versions unless
  this contract is deliberately revised.
- Treat the fixed Anthropic release-signing key fingerprint and the signed
  per-version manifest as publisher provenance. A version string, executable
  bit, native file format, install path, or self-reported identity is not
  publisher provenance.
- After the signed manifest, size, and SHA-256 checks pass, materialize a
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
4. Parse exactly one release version and require `>=2.1.187,<3.0.0`.
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
   captured once for the complete Claude model-attempt chain.
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
10. At every model-attempt boundary, prepare the platform-specific private
    credential carrier for only that attempt's 30-minute timeout plus the
    2-minute safety margin. On macOS, first check freshness; only when the
    current window is insufficient, run the fixed no-tools, no-workspace-read
    warmup with the current attempt's model, then re-read and validate the
    Keychain item. Linux and WSL2 never warm or refresh credentials; each
    attempt independently validates and stages a new private copy. An explicit
    API key skips local-login warmup and staging. If the warmup returns an
    explicit entitlement or organization-policy denial in a strict top-level
    error result, with structured-error classification and exact effective-model
    verification, persist that fallback evidence and end the current model
    boundary without starting the final broker or review sandbox, even when
    credential freshness remains insufficient. Successful structured output
    plus entitlement-shaped stderr never authorizes fallback.
11. Launch only the one captured verified snapshot for every real model attempt
    in a fresh outer sandbox; never rediscover or fall back to the mutable source
    installation between Opus attempts. If entitlement selects a later Opus
    model, repeat step 10 before that attempt. Validate structured output,
    effective model, and terminal status before accepting text as review
    evidence. The requested effort remains explicit in every real command.

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
onward, which covers the complete supported version range in this contract.
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
execute only the private snapshot.

## Capability Probes

Compatibility is capability-based within the accepted version range. Do not
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

Require every public option used by the macOS authentication warmup or final
review command to appear exactly once in the bounded `--help` output from the
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

The helper does not claim a credential-free fixed-input behavioral canary. The
preflight capability evidence is the accepted release range, the required
public options, and the parsed safe-mode semantics. Behavioral acceptance comes
from the final real review invocation plus strict structured-output,
effective-model, error-state, and terminal-artifact validation.

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
macOS, the rewritten variable names only the exact helper-owned copy; the
Seatbelt profile grants `file-read*` to that file literally, does not grant a
parent-directory subpath read, and does not disclose the caller path through
the profile or launch arguments. Literal ancestor metadata checks remain part
of safe path traversal.
`SSL_CERT_FILE` and `SSL_CERT_DIR` retain their existing handling. The latter is
enumerated through a fixed directory descriptor with bounded entry counts and
supports normal OpenSSL hash links, including the multi-hop relative/absolute
layout used by Ubuntu. Link depth and path components are bounded; every
traversed link and directory plus the final no-follow regular file is
owner/mode/identity checked and revalidated around a bounded read. Only PEM
certificates are materialized, never private-key material. The helper keeps the
original hash basename but writes a private `0600` regular file instead of
recreating a symlink.

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

Linux and WSL2 fix cwd at `/workspace`, use `dontAsk`, expose only `Read`, and
pre-approve only `Read(./**)`. Every other top-level path mounted into the
synthetic root is denied both at the root and recursively with absolute
double-slash rules, for example `Read(//config)`, `Read(//config/**)`,
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
inside `/workspace` continue to work; `/config`, `/proc` magic links, absolute
links, transient or final escapes, loops, link races, and inspection I/O failures
all fail closed before the authenticated workload starts. As with the final
path-to-mount handoff, this does not claim protection from a malicious same-euid
host process after the last identity check.

The supported range continues to start at `2.1.187` instead of forcing an
upgrade to `2.1.208`. Anthropic documents reliable propagation of `Read` rules
to `Grep`, `Glob`, LSP, and prompt file mentions only from `2.1.208`. Therefore
Linux and WSL2 do not expose those search tools and reject ASCII `@` file-mention
syntax in the complete review prompt before launch. The frozen diff remains
available through the workspace-only `Read` tool. macOS keeps its existing
`Read`/`Grep`/`Glob` contract because Seatbelt does not expose the Linux
credential shape.

## Credentials

An explicitly supplied `ANTHROPIC_API_KEY` remains an optional override and does
not require local-login credential access. Never pass Claude and Copilot
credentials into the same child environment.

On macOS, retain the capability-authenticated, one-shot Keychain broker. Before
each model attempt, after trusted executable, review-tool, and TLS preparation,
the parent reads and validates the current Claude Code item with Apple's trusted
client. The token needs to cover only the current bounded attempt plus its
safety margin, currently `1800 + 120 = 1920` seconds. A sufficiently fresh token
is not refreshed. Otherwise the helper runs the fixed-input safe-mode warmup
with the current attempt's model, no tools, and no workspace read, then re-reads
and validates the item. The final broker performs another read and fail-closed
single-attempt validation before its one-shot handoff. The final Claude process
cannot execute `/usr/bin/security`, access Keychain services directly, update
the host item, or refresh OAuth credentials during the review. Every later
model attempt repeats this refresh-if-needed and validation sequence. A
strictly structured, exact-model-verified entitlement denial from the warmup is
recorded only as model-chain fallback evidence with no final text; it skips the
final broker and repository-review launch, and the next model still starts from
its own freshness boundary. Its bounded complete stdout/stderr capture is copied
to the formal attempt logs after the temporary warmup output directory closes.
An explicit authentication failure remains unavailable even when the refreshed
Keychain item is structurally fresh enough for a later attempt.

On Linux and WSL2, every model attempt validates the documented Claude Code
credential file as a non-symlink regular file owned by the current user with
exact mode `0600`. For that attempt, copy it into a new helper-owned `0700`
directory as a private `0600` file and expose only that staged copy's config
directory through a read-only mount at `/config`; the original host credential
is never mounted. Parse the OAuth expiry and require the same single-attempt
`1920`-second window before launch. Linux and WSL2 perform no pre-chain staging,
warmup, refresh, or host-credential write; a missing or insufficiently fresh
credential is unavailable unless an explicit `ANTHROPIC_API_KEY` is supplied.
Reject unsafe ownership, mode, symlink, path-race, size, or JSON structure, and
never persist or print credential contents in review state. The source
descriptor must close successfully before a validated payload is returned;
close failure zeroes the in-memory copy, preserves any earlier
validation/control-flow error, and fails closed without retrying the same
numeric descriptor.

Credential staging owns cleanup from the first successful create through the
final close. Scrub, close, unlink, and directory removal are attempted in a
bounded order even when the body exits through cancellation or generator
closure. A cleanup-time `KeyboardInterrupt`, `SystemExit`, or other
`BaseException` control-flow signal is never converted into an ordinary
credential error; an already-active body exception remains primary and receives
the cleanup diagnostic. Python 3.10 records that diagnostic in the preserved
exception chain through a dedicated diagnostic cause because
`BaseException.add_note()` is available only from Python 3.11.

A read-only mount prevents mutation but does not hide a secret from the Claude
process that must authenticate with it. The Linux/WSL2 inner permission policy
therefore denies `/config` from model-visible `Read`. In API-key mode, it also
denies `/proc` and `/dev` so `Read(//proc/self/environ)` and file-descriptor
aliases cannot expose `ANTHROPIC_API_KEY`. This boundary trusts the
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
2. macOS `authentication-preflight-complete`: after review-tool and TLS
   preparation for the current attempt, API-key configuration or local-login
   refresh/validation passed. Authentication status becomes `configured` or
   `freshness-verified`; `authentication.model` and `validated_for_model` both
   identify the current model whose attempt window was checked. When this
   outcome is published for a later Opus attempt, it clears the previous
   attempt subtree, restores the outer-sandbox
   status to pending, and is not a whole-chain freshness guarantee.
3. macOS authentication preparation failure before a model launch is explicit.
   `authentication-preflight-inconclusive` records the current model and stable
   warmup failure class without inventing a formal review attempt. This includes
   supervision failures from the credential freshness read immediately before
   or after the warmup.
   `authentication-preflight-unavailable` also covers an attempt-local failure
   of the restricted Keychain broker, with the same consent-gated fallback
   policy as an unavailable credential.
   A structured transient warmup remains inconclusive when the post-warmup read
   also finds that broker unavailable. During final staging, credential-read
   supervision failures use failure class `credential-read` with no model
   attempt, while broker failure or a warmup/final-staging loopback failure
   resets the phase to unavailable before the Claude CLI launch.
   `authentication-preflight-entitlement` records a strict, exact-model-verified
   warmup entitlement attempt while keeping `outer_sandbox.status` at
   `pending-runtime-launch` and `validated_for_model` unset. This is fallback
   evidence with no final text, not a final review launch or clean artifact.
   `authentication-preflight-unavailable` records an explicitly unavailable
   current-attempt Keychain credential. Linux/WSL2 credential unavailability
   prevents `runtime-ready` from being published and is retained through the
   ordinary unavailable error artifact instead of a macOS preflight phase.
4. Platform preparation: Linux/WSL2 reports `runtime-ready` only after the
   current attempt's credential staging and real isolation probe, with
   `outer_sandbox.status: isolation-probe-verified` and
   `authentication.status: sandbox-auth-staged`. macOS reports
   `runtime-launching` with `outer_sandbox.status: profile-generated` only when
   the final one-shot broker and Seatbelt launch are prepared.
5. `attempt-inconclusive`: a bounded supervisor timeout, output overflow, drain
   failure, or retained descendant interrupted an attempted model launch. The
   report records `attempt.category: inconclusive` and a stable `failure_class`
   rather than leaving an earlier readiness phase as the apparent terminal
   result.
6. `attempt-complete`: the report records the final sandbox status, attempt
   category and return code, and requested/effective model and effort.

These records are evidence about which gates ran; an early phase must never be
described as an enforced final launch.

## Failure Classification And Fallback

| Condition | Terminal classification | Copilot fallback |
| --- | --- | --- |
| No automatic candidate, supported platform unavailable, accepted-range candidate lacks a required non-security capability, or usable local/API authentication is absent at the current attempt boundary | `runtime-unavailable` or `auth-unavailable` | Only for explicit double/triple-review consent |
| Explicit override has the wrong version, platform, binary shape, capability contract, or lacks trusted GPG, probe sandbox, or trusted review tool prerequisites | `blocked` configuration error | No |
| Wrong publisher fingerprint, invalid signature, checksum mismatch, contradictory safe-mode semantics, unsafe credential metadata, or an isolation-boundary mismatch | `blocked` security error | No |
| Manifest/probe timeout, output overflow, executable resolve/stat I/O failure, other inspection I/O failure, file race, transient network failure, capacity error, or missing trustworthy terminal artifact | `inconclusive` | No |
| Explicit model entitlement or organization-policy denial from a final review invocation, or from a fixed-input warmup after exact effective-model verification | Existing same-lane model/backend fallback policy | Only as already authorized by the lane contract |

A transient, timed-out, output-limited, drain-failed, or process-leaking macOS
warmup is `inconclusive` and returns exit `75`; it never authorizes Copilot. If
an earlier Opus attempt completed with entitlement metadata, that evidence stays
persisted while the model whose inconclusive authentication gate failed is not
recorded as a launched attempt. A verified warmup entitlement is recorded as an
attempt with no final text, but missing or mismatched model metadata stops the
lane as `runtime-unverified` or `model-mismatch` and never authorizes fallback.
Transient and authentication classifications retain their existing precedence.
Every later Opus model independently repeats the freshness/warmup boundary. A
credential that is explicitly unavailable at a later model boundary follows
only the existing double/triple-review consent gate; `explicit-claude-review`
remains Anthropic-only.

An unsupported future patch inside the version range may be treated as automatic
runtime unavailability only when it cleanly lacks a required capability. Evidence
of tampering, contradictory claims, or boundary failure is blocked, not converted
into availability fallback. Capacity, rate limits, timeouts, and 5xx errors never
authorize a model or backend switch. On WSL2, a path positively covered by a
Windows-backed mount or a stable workspace-link escape is a blocked
isolation-boundary mismatch. Mount information that cannot be bounded, strictly
parsed, matched to a runtime path, or used to prove local native backing is an
inconclusive inspection failure; so is a workspace-link identity race or I/O
failure. Neither case is ordinary runtime unavailability, so neither can
authorize Copilot fallback.

A verifier dependency is `runtime-unavailable` only when its fixed source is
deterministically absent or the supported platform/capability is not present.
A present but non-native, untrusted-owner, writable, set-id, non-executable, or
otherwise unsafe GPG/`otool`/glibc-loader candidate is a blocked security error.
A resolve, stat, open, copy, launch, or refresh I/O failure is inconclusive. The
generic provenance-operation exception therefore never authorizes Copilot
fallback; only its dedicated deterministic-dependency subtype may do so.

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
