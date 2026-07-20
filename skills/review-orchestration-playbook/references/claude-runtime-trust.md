# Claude Runtime Trust And Platform Capabilities

This reference defines the one supported Claude Code review runtime. Clean and WIP are content variants inside this boundary; they are not different authentication, HOME, permission, or sandbox modes.

## Policy Summary

A Claude review is accepted only when all of these statements are true:

1. The native Claude Code executable is publisher-verified and exactly version `2.1.212`.
2. The review cwd is a helper-owned literal detached Git worktree backed by a private minimal Git database, bound to the recorded exact head or WIP digest, and stored with all review state outside the source checkout under the fixed canonical system temporary root `/tmp`.
3. `HOME` is the current operating-system account's real home and is passed to the ordinary trusted Claude CLI for authentication and configuration.
4. The model runs in `dontAsk` mode with `Read`, `Grep`, `Glob`, and `Bash`; `Read(./**)` allows detached-workspace file access, unmatched permission requests are denied, and explicit path rules deny real-HOME secrets plus `/proc` and `/dev` escape surfaces.
5. The unique first `system/init` event proves effective `dontAsk` mode, the exact built-in tool set, requested model, and authentication indicator; the unique matching terminal result is last.
6. Claude's native sandbox is requested with `failIfUnavailable`, sandboxed Bash auto-approval disabled, worktree/HOME writes denied, broad original-source-checkout, per-UID review-namespace, real-HOME, `/proc`, and `/dev` Bash reads denied before re-opening only the current detached workspace and private Git view, credential/proxy variables removed from sandboxed commands, and unsandboxed-command escape disabled. These settings are recorded as requested because Claude Code 2.1.212 does not expose their effective values or merged managed permission arrays in `system/init`.
7. After every completed Claude attempt, the helper reruns exact external-workspace validation before accepting a result or trying another model. The detached snapshot, private Git state, diff, and prompt must remain unchanged.
8. Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. Explicit values are opaque-forwarded and never parsed, logged, or persisted; `auth status --json` must prove a compatible effective provider/method/source tuple before review content enters the child process.
9. Sensitive-content, egress, structured-output, requested/effective-model, process, time, and byte-limit checks pass.

The prompt defines authorized review scope, but it is not an OS security boundary. The acceptance boundary is the documented `dontAsk` baseline, workspace file allowlist, explicit tool/path denials, strict effective `system/init` evidence, and terminal evidence. The inline native-sandbox configuration is defense in depth: an unavailable sandbox makes a launch fail when the request is honored, but the runtime report does not mislabel that request as an independently observed effective policy.

## Publisher Provenance

The helper accepts a Claude Code release only after this order completes:

1. Resolve a native Mach-O or ELF candidate from a bounded trusted location or an explicit absolute override.
2. Run the version/identity probe in a fixed credential-free environment with no review data, proxy credentials, custom CA paths, authentication variables, or real HOME exposure.
3. Require exact version `2.1.212` and a supported native platform/architecture. Every other release fails closed until equivalent permission, path-rule, sandbox, and output evidence supports a deliberate version update.
4. Verify Anthropic's signed per-version manifest with the fixed release-signing fingerprint `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`.
5. Match the exact platform artifact checksum from that manifest.
6. Copy the verified executable into a helper-private checksum-keyed snapshot and use only that immutable snapshot for every later capability probe and review attempt.

A version string, executable bit, native file format, install path, code signature, notarization state, or self-reported identity does not replace the signed manifest. Probe, manifest-download, signature, checksum, binary-identity, dependency, or file-race uncertainty fails closed.

The fixed-path native GPG source remains a separately validated host-trust dependency, not Anthropic publisher provenance. Its stable copied executable and runtime dependency closure must pass the existing platform identity and non-writability checks before each verification call.

## Supported Platforms

- macOS: official thin arm64 or x64 Mach-O, including x64 through Rosetta on Apple Silicon; native Claude sandbox backed by Seatbelt.
- Linux: native matching-architecture ELF and libc; native Claude sandbox backed by `bubblewrap` and its required relay dependency.
- WSL2: the matching Linux runtime only after positive WSL2 kernel identity and `/proc/self/mountinfo` proves both the source checkout and external review container use supported local native Linux filesystems.
- WSL1 and native Windows: unsupported.

Known Windows-backed, shared, layered, loop-backed, network-backed, FUSE, or unknown WSL2 filesystem provenance is blocked or inspection-inconclusive according to the existing mount contract. Path spelling alone never proves WSL2 or native backing.

## Detached Worktree Boundary

The helper always launches Claude with cwd set to its own detached Git worktree. That worktree:

- is detached at the exact resolved head;
- has a helper-owned minimal Git database containing the scanned base/head endpoint commits and their tree/blob closures; WIP mode additionally contains its generated snapshot tree/blob closure, while intermediate commit history and history-only objects are intentionally unavailable;
- is never registered in the source repository's common Git directory;
- does not update source refs, reuse source administrative files, run source hooks/filters, or write objects into the source object database;
- remains immutable to model tools and is cleaned independently of every user worktree.

The worktree, private Git database, control artifacts, logs, and state share one external per-run container. The fixed `/tmp` base is resolved to a canonical real directory and accepted only when it is root-owned with exact mode `01777`. The helper then creates current-user-owned exact-`0700` namespaces for the effective UID and SHA-256 of the canonical source path before the generated per-run container. It never selects this root from caller `TMPDIR` or source-repository content.

Clean mode is the default and requires a clean source checkout. Explicit `--include-source-wip` captures staged changes, unstaged changes, deletions, mode/symlink changes, and non-ignored untracked files into the same kind of detached worktree. Capture must be race-checked and digest-bound, and every diff, inventory, scanner, prompt, and reviewer read must use the captured artifact. A WIP digest is review-only artifact evidence and cannot satisfy a formal PR-readiness or merge-ready exact-commit gate.

Source `.codex-tmp` content is never filtered as helper state. Ordinary Git ignore/status semantics apply, any reported record makes clean mode dirty, and WIP capture rejects `.codex-tmp` as a reserved helper path. Stateful artifacts retained under `/tmp` may survive helper workspace cleanup but can be lost on reboot or host temporary-file cleanup, so they are operational evidence rather than durable storage.

Submodules stay uninitialized and unfetched. Missing objects, unsafe links, conflicts, dirty submodules, capture races, or any file/entry/byte budget breach fail closed.

## Real HOME And Read-Only Model Tools

After provenance and capability validation, the ordinary Claude CLI receives the current account's real home resolved from the operating-system account database. Caller-controlled `HOME` does not select it, and inherited `XDG_CONFIG_HOME` is removed so alternate config discovery cannot escape the real-HOME boundary. The CLI may use supported local authentication and configuration from that home and may refresh ordinary login through Claude Code's own implementation.

The final command uses Claude `dontAsk` mode and exposes only:

- `Read`, `Grep`, and `Glob` under the explicit `Read(./**)` detached-workspace allow rule;
- `Bash` under Claude Code's non-prompting read-only command policy, with the native sandbox requested as defense in depth.

The reviewer prompt forbids reads outside the detached workspace. In `dontAsk` mode, `Read(./**)` authorizes workspace-relative file access and unmatched permission requests are automatically denied; other retained reviews therefore remain unmatched. Claude Code 2.1.212 applies `Read` path rules to `Grep` and `Glob`. Deny-first rules cover the root and descendants of `/proc` and `/dev`, preventing Linux process-environment and descriptor-alias reads even when an admin-managed allow exists, and separately cover sensitive real-HOME paths. Symlink targets outside the allowed workspace do not inherit the lexical allow. Editing, web, and task tools are disabled. Admin-managed policy remains part of the trusted ordinary CLI control plane, so the helper does not claim the visible CLI allowlist is the only possible managed allow; explicit denies continue to take precedence.

For Bash, the inline native-sandbox request asks Claude Code to remove authentication and proxy variables, deny writes to both the worktree and real HOME, deny broad original-source-checkout, per-UID review-namespace, real-HOME, `/proc`, and `/dev` reads, re-open only the current detached workspace and its private Git view, and disable unsandboxed-command escape. Ignored or otherwise uncaptured source-checkout content, other retained reviews, and home-directory content remain outside authorized review scope even though they belong to the same operating-system account and the real HOME is present in the ordinary CLI process environment.

The model-backed launch explicitly sets `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=0`. In Claude Code 2.1.212, setting it to `1` strips credentials broadly but also forces the effective permission mode to `default`, which is incompatible with this helper's required and verified `dontAsk` contract. Credential removal from sandboxed Bash instead uses the native sandbox `credentials.envVars` deny rules together with `failIfUnavailable: true`; credential-free version/help probes may still use the broad subprocess scrub because they do not enter a model-backed permission mode. Disabling the broad scrub means it is not a defense for other subprocess surfaces, so hooks are disabled, MCP is strict and empty, plugins/skills/slash commands are disabled, the file-tool allow/deny rules protect explicit carriers from process pseudo-files, and the exact init surface must match before a result is accepted.

The real-HOME Claude control plane itself is not placed in a filesystem-read-only outer sandbox. Ordinary CLI internals may create real-HOME cache or tool-result artifacts even with session persistence disabled; those control-plane writes are outside the model-tool read-only claim. The helper therefore does not describe real `HOME` as immutable and does not claim that post-attempt workspace validation covers it.

Claude Code 2.1.212 also creates an empty `.claude/.cc-writes` atomic-write staging directory in the review cwd when native Bash sandboxing is first used. Immediately before launch, the provider proves whether that exact entry is absent and records the filesystem identity of an already-existing real `.claude` parent. After normal return, or after the common runner has completed its bounded managed-process-group termination and I/O teardown before raising, the provider does not clean any pre-existing snapshot entry; only an entry proven absent before launch can become a cleanup candidate. This is not a claim that a descendant which escaped the managed process group has exited. The provider opens the workspace, `.claude`, and `.cc-writes` through no-follow directory descriptors, requires any pre-existing parent to retain its bound identity throughout cleanup, accepts only the exact current-user-owned `0700` empty staging directory, and removes it with descriptor-relative non-recursive `rmdir`. An original snapshot parent is never removed. A parent created with the staging directory must remain empty and retain its identity, is atomically moved into a freshly created helper-private quarantine, and is identity-checked there before non-recursive removal; a swapped candidate is retained in quarantine and rejected rather than being restored through a replace-capable rename. The unchanged common workspace validator then runs. A disappeared or replaced parent, symlink, wrong owner or mode, nonempty staging directory, or any remaining unexpected topology is never recursively cleaned. On a normal result this is terminal `permission-mismatch`; while a supervision or forwarded-signal exception is already unwinding, it is retained as a secondary redacted diagnostic so the primary exception classification remains intact.

The native sandbox is requested with `failIfUnavailable: true`, `autoAllowBashIfSandboxed: false`, and `allowUnsandboxedCommands: false`. Claude Code v2.1.212 `dontAsk` mode rejects permission requests that do not match an allow rule, while its non-prompting Bash baseline permits read-only inspection commands. Read path rules also apply to recognized Bash file readers such as `cat`, `head`, `tail`, and `sed`; arbitrary interpreters are not members of the non-prompting read-only set. The helper does not perform an additional model-backed behavioral request before every review. Instead, it requires the actual review stream to report effective `permissionMode: dontAsk`, the exact `Read`/`Grep`/`Glob`/`Bash` tool set, the requested model, no MCP/slash/skill/plugin surface, and the expected authentication indicator. Observable init changes fail closed. The 2.1.212 init schema does not report effective sandbox fields, merged managed permission arrays, or path-rule evaluation, so those settings remain requested/validated inputs rather than independently observed runtime evidence. If Claude Code changes `dontAsk` semantics, file-rule propagation, init evidence, tool naming, Bash sandbox behavior, or rule precedence, the exact supported-version pin must be updated and reviewed before another release is accepted.

After every completed attempt, exact `validate_external_workspace(review)` validation checks the materialized snapshot, private Git database and administrative state, generated diff, and prompt before any result or model fallback can be accepted. Any observable mutation is terminal `permission-mismatch`; authentication and result evidence remain unused. This post-run check proves only the exact inspected state at validation time. It does not prove that no transient write occurred, nor can it prove the absence of an out-of-workspace side effect.

## Authentication

The caller environment is frozen once and reduced to exactly one selected explicit carrier:

1. non-empty `ANTHROPIC_API_KEY` wins;
2. otherwise non-empty `CLAUDE_CODE_OAUTH_TOKEN` wins;
3. otherwise Claude Code uses ordinary local login from real HOME.

Both explicit values and inherited credential-bearing proxy URLs are included in parent-side redaction inputs, but only the winning explicit variable enters the Claude control plane. Routing-only proxy endpoints and `NO_PROXY` values are not safe global replacement strings and are excluded from output redaction. The helper necessarily tests whether each explicit value is non-empty and copies the winner into the child environment as an opaque string; it never interprets the value as a credential. Raw values plus their JSON-escaped, Unicode-escaped, `repr`, and `ascii` output forms are redacted before streamed stdout/stderr reach disk. Authentication and all proxy variables remain requested removed from sandboxed Bash environments.

The helper never:

- reads or parses a Keychain item or Claude credential file;
- invokes a credential query or replacement command;
- copies a credential into a temporary home, file, argument, or sandbox carrier;
- stages or watches refresh-token changes;
- writes authentication state back to the host;
- persists bearer-capable token contents or refresh metadata in review state.

This deliberately delegates local-login discovery, Keychain/file access, locking, refresh, and persistence to the installed publisher-verified Claude Code control plane, just as an ordinary interactive invocation would. The review helper owns only opaque environment selection, redaction, model-tool policy, and outcome classification.

Before any review prompt is supplied, the verified CLI runs a bounded, redacted `auth status --json` preflight with the same real HOME, filtered environment, safe mode, setting-source suppression, and inline settings. Accepted tuples are exact: first-party `api_key` from `ANTHROPIC_API_KEY`, first-party `oauth_token` for the requested `CLAUDE_CODE_OAUTH_TOKEN` path, or first-party `claude.ai` for ordinary local login. Claude Code 2.1.212 returns valid JSON plus a nonzero status for `loggedIn: false`; the helper parses that evidence before interpreting the process status and reports `blocked-authentication` with the selected carrier's recovery action. Cloud providers, Claude apps gateway, `apiKeyHelper`, other logged-out state, unknown providers/methods, or an API-key source mismatch are blocked. The actual `system/init` event then cross-checks `apiKeySource` before a terminal result can mark authentication `used`.

Claude Code 2.1.212 reports both `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_AUTH_TOKEN` as the same first-party `oauth_token` method with no carrier field. The helper filters `ANTHROPIC_AUTH_TOKEN` out of the caller environment and does not claim that the CLI schema can distinguish an opaque managed-policy injection of those two carriers. Runtime and egress evidence therefore record the requested carrier separately from the effective provider/method/API-key-source fields instead of mislabeling the requested name as a proven effective carrier.

A launched explicit API key, explicit OAuth token, or local login that Claude rejects is `blocked-authentication`. Tell the operator to unset or replace `ANTHROPIC_API_KEY`, unset or replace `CLAUDE_CODE_OAUTH_TOKEN`, or run `claude auth login`, respectively, then pause for an explicit retry. Authentication failure never authorizes a model downgrade or Copilot fallback. Access-token expiry by itself is not failure when ordinary Claude Code can refresh the login.

## Network And TLS

The Claude control plane inherits the helper's standard proxy and CA environment so an ordinary supported installation can reach Anthropic through the user's configured network. The helper does not build a separate CONNECT proxy or copy CA material for the final review. Credential-bearing proxy URLs are included in parent-side output redaction; routing-only proxy endpoints and `NO_PROXY` values are not globally replaced. All proxy variables are requested removed from sandboxed Bash environments. Web tools are disabled; any Bash network attempt remains subject to `dontAsk` permission handling and the requested native-sandbox policy. Network, proxy, TLS, or routing failure never becomes authentication or entitlement evidence. Credential-free version/help bootstrap probes remain wrapped by the existing host probe sandbox; the authenticated, model-backed review itself launches the verified Claude executable directly.

## Capability And Output Verification

Credential-free capability probes verify the exact public flags the helper invokes and the accepted release's documented safe-mode/`dontAsk` contract, including tool visibility, setting-source suppression, streaming structured output, requested model, effort request, and session/export controls. The inline sandbox settings are requested fail-closed on the actual launch; no separate model-backed behavioral probe is claimed.

Claude output is accepted only as strict JSONL with one `system/init` event first and one terminal result last. The bounded file is consumed in one pass while retaining only the two contract events and aggregate error state; a large number of small records cannot expand into an unbounded in-memory event list. Duplicate/misordered contract events, duplicate JSON keys, non-standard constants, malformed errors, partial result text attached to errors, missing model evidence, model substitution, permission-mode changes, tool widening, or authentication-indicator changes fail closed. Additive non-security init metadata is ignored. The requested effort is recorded, but current Claude output does not provide an independently verified effective-effort field. Repository-controlled output never supplies authentication, entitlement, runtime-availability, or fallback evidence.

All launches use finite deadlines, bounded stdout/stderr artifacts, process containment, signal forwarding, descendant cleanup, and post-quiescence artifact checks. Timeout, overflow, drain failure, retained descendants, or missing terminal output is `inconclusive`.

## Failure Classification

- `blocked-authentication`: Claude rejected the selected API key, OAuth token, or ordinary local login.
- `blocked`: deterministic policy, configuration, permission, provenance, unsupported-platform, or capability failure.
- `inconclusive`: transient network/capacity/timeout, bounded-I/O, race, lifecycle, or unverifiable-output failure.
- entitlement fallback: only a strictly verified denial for the requested Claude model may advance to the next pinned model; both models must be entitlement-blocked before an already-consented Copilot fallback.
- deterministic runtime fallback: only verified runtime absence/unavailability under existing `double-review` or `triple-review` consent may enter Copilot.

Capacity, rate limits, timeouts, network errors, 5xx responses, missing artifacts, model substitution, findings, authentication problems, and inspection uncertainty are never fallback reasons.

## Runtime Report

Persist only redaction-safe evidence:

- source and verified executable paths, version, platform, architecture, manifest/signature/checksum evidence, and verifier identity;
- requested native-sandbox implementation/settings, effective init-contract status, and `dontAsk`/read-only tool policy;
- workspace content mode, base/head/tree identity, and WIP digest when present;
- requested authentication carrier plus the effective provider/method/API-key-source fields returned by the CLI, without credential contents or bearer-capable token metadata;
- requested/effective model, requested effort and effective effort when observable, attempt category, bounded log paths, and terminal status.

Never persist credential contents, bearer-capable token metadata, real-HOME file contents, or unbounded probe output.

## Official Sources

- [Claude Code advanced setup](https://code.claude.com/docs/en/installation): native platforms, version management, signed manifests, release-key fingerprint, and checksums.
- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing): native sandbox behavior and supported platforms.
- [Claude Code authentication](https://code.claude.com/docs/en/authentication): ordinary local and explicit authentication behavior.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage): command and flag surface.
- [Claude Code settings](https://code.claude.com/docs/en/settings): managed-policy precedence over CLI settings and the limits of source-level status reporting.
- [Claude Code configuration diagnostics](https://code.claude.com/docs/en/debug-your-config): settings diagnostics and active-source visibility.
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes): `dontAsk` mode and permission semantics.
- [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference): built-in tool names and file/shell behavior.
- [Claude Code corporate network configuration](https://code.claude.com/docs/en/corporate-proxy): supported proxy and custom-CA inputs.
