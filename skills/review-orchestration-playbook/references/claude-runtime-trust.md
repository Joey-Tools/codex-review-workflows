# Claude Runtime Trust And Platform Capabilities

This reference primarily defines the low-level Claude Code runtime used by `isolated_review`. Clean and WIP are content variants inside that boundary; they are not different authentication, HOME, permission, or sandbox modes. The helper is diagnostic-only, records `review_contract: supplied-diff-private-git` and `named_lane_eligible: false`, and cannot satisfy a named review lane.

The canonical named-double lane is a separate direct Claude Code launch governed by [canonical-claude-lane.md](canonical-claude-lane.md). The canonical lane does not inherit the helper-only explicit-auth precedence, supplied-diff prompt, private-minimal-Git materialization, executable snapshot, or exact `2.1.212` compatibility pin.

## Policy Summary

A low-level helper Claude review is accepted only when all of these statements are true:

1. The native Claude Code executable is publisher-verified and exactly version `2.1.212`.
2. The review cwd is a helper-owned literal detached Git worktree backed by a private minimal Git database, bound to the recorded exact head or WIP digest, and stored with all review state outside the source checkout under the fixed canonical system temporary root `/tmp`.
3. `HOME` is the current operating-system account's real home and is passed to the ordinary trusted Claude CLI for authentication and configuration.
4. The model runs in `dontAsk` mode with `Read`, `Grep`, `Glob`, and `Bash`; `Read(./**)` records intended detached-workspace access, unmatched permission requests are denied, and explicit path rules deny critical real-HOME secrets plus `/proc` and `/dev` escape surfaces.
5. The unique first `system/init` event proves only its documented fields: effective `dontAsk` mode, exact built-in tool set, requested model, and authentication indicator. The unique matching terminal result is last.
6. Claude's native sandbox is requested with `failIfUnavailable`, sandboxed Bash auto-approval disabled, global write denial, critical-sensitive-root read denials, credential/proxy-variable denial, and unsandboxed-command escape disabled. The worktree and private Git view are listed in `allowRead`, but those entries are not a global host-read whitelist.
7. The prompt/model contract forbids outside-workspace reads. This is the scope boundary for host paths not covered by native-sandbox `denyRead`; it is not independently enforced by `allowRead`.
8. The sandbox settings are recorded as requested because Claude Code 2.1.212 does not expose the final merged native-sandbox configuration, merged admin-managed permission arrays, or path-rule evaluation in `system/init` or capability output.
9. After every completed attempt, exact external-workspace validation must find the detached snapshot, private Git state, diff, and prompt unchanged before a result or model fallback is accepted. This proves inspected state only, not the absence of a transient write or outside-workspace side effect.
10. Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. Explicit values are opaque-forwarded and never parsed, logged, staged, brokered, persisted, or written back; `auth status --json` must prove a compatible effective provider/method/source tuple before review content enters the child process.
11. Sensitive-content, egress, structured-output, requested/effective-model, process, time, and byte-limit checks pass.

This is an accepted selected-deny model-behavior tradeoff, not full host-read isolation. Native-sandbox `allowRead` entries describe intended scope but do not prove every other host path unreadable. A stronger outer sandbox may add protection, but none is inferred from selected `denyRead` / `allowRead` settings, capability probes, or init output.

## Canonical Lane Applicability

For named double or triple review, follow [canonical-claude-lane.md](canonical-claude-lane.md): launch a fresh actual `claude` process directly in a separate clean Git worktree over the frozen range, send no prepared full diff, and let Claude read tracked guidance and inspect the range itself. The canonical file owns that lane's executable, authentication, worktree, prompt, evidence, and failure contract. Follow its direct executable rules and do not create a helper snapshot.

An `isolated_review` artifact does not become canonical because the actual backend happened to be Claude Code, because it exited `0`, or because its findings are clean. Its supplied-diff/private-minimal-Git contract remains machine-ineligible for named-lane counting. The helper's Copilot compatibility backend requires separate explicit consent and never counts as Claude Code.

## Publisher Provenance

The helper accepts a Claude Code release only after this order completes:

1. Resolve a native Mach-O or ELF candidate from a bounded trusted location or an explicit absolute override.
2. Run the version/identity probe in a fixed credential-free environment with no review data, proxy credentials, custom CA paths, authentication variables, or real HOME exposure.
3. Require exact version `2.1.212` and a supported native platform/architecture. Every other release fails closed until equivalent permission, path-rule, sandbox, and output evidence supports a deliberate version update.
4. Verify Anthropic's signed per-version manifest with the fixed release-signing fingerprint `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`.
5. Match the exact platform artifact checksum from that manifest.
6. For the low-level helper, after the signed manifest, size, and checksum checks pass, copy the verified executable into a helper-private checksum-keyed snapshot and use only that immutable snapshot for every later capability probe and review attempt.

A version string, executable bit, native file format, install path, code signature, notarization state, or self-reported identity does not replace the signed manifest. Probe, manifest-download, signature, checksum, binary-identity, dependency, or file-race uncertainty fails closed.

The fixed-path native GPG source remains a separately validated host-trust dependency, not Anthropic publisher provenance. Its stable copied executable and runtime dependency closure must pass the platform identity and non-writability checks before each verification call.

## Supported Platforms

- macOS: official thin arm64 or x64 Mach-O, including x64 through Rosetta on Apple Silicon; native Claude sandbox backed by Seatbelt.
- Linux: native matching-architecture ELF and libc; native Claude sandbox backed by separately identity-verified `bubblewrap` and `socat` executables. Their verified directories are bound ahead of every other host-tool directory in final Claude `PATH`, because Claude's absolute `bwrapPath` and `socatPath` overrides are managed-settings-only inputs.
- WSL2: the matching Linux runtime only after positive WSL2 kernel identity and `/proc/self/mountinfo` proves both source checkout and external review container use supported local native Linux filesystems.
- WSL1 and native Windows: unsupported.

Known Windows-backed, shared, layered, loop-backed, network-backed, FUSE, or unknown WSL2 filesystem provenance is blocked or inspection-inconclusive according to the mount contract. Path spelling alone never proves WSL2 or native backing.

## Detached Worktree Boundary

The helper always launches Claude with cwd set to its own detached Git worktree. That worktree:

- is detached at the exact resolved head;
- has a helper-owned private minimal Git database containing the scanned base/head endpoint commits and their tree/blob closures; WIP mode additionally contains its generated snapshot tree/blob closure, while intermediate history and history-only objects are intentionally unavailable;
- is never registered in the source repository's common Git directory;
- does not update source refs, reuse source administrative files, run source hooks/filters, or write objects into the source object database;
- remains immutable to model tools and is cleaned independently of every user worktree.

The worktree, private Git database, control artifacts, logs, and state share one external per-run container. The fixed `/tmp` base is resolved to a canonical real directory and accepted only when it is root-owned with exact mode `01777`. The helper creates current-user-owned exact-`0700` namespaces for effective UID and the canonical source-path digest before the generated per-run container. It never selects this root from caller `TMPDIR` or repository content.

Clean mode is the default and requires a clean source checkout. Source inspection uses short-lived helper-private Git metadata under verified `/tmp`, anchored at actual source `HEAD` and attached only to the source object directory and exact per-worktree index. A bounded config-only query under the operating-system account home and actual worktree context selects the final `core.excludesFile` plus typed `core.ignoreCase` and `core.precomposeUnicode` values; the configured excludes file is secure-read and frozen. Operational `status`, `diff`, `ls-files`, and `ls-tree` still suppress source-local, system, and global configuration and receive only the validated path-semantics settings, so repository hooks, aliases, filters, and diff drivers cannot execute. The deliberate `core.filemode=true` setting prevents source configuration from hiding a mode-only change.

Explicit `--include-source-wip` captures staged changes, unstaged changes, deletions, mode/symlink changes, and non-ignored untracked files into the same kind of detached worktree. Regular-file and symlink-target bytes share the aggregate snapshot budget. Captured blobs are imported in one bounded Git process and the complete raw-path overlay is applied through one NUL-delimited index update. Capture is race-checked and digest-bound, and every diff, inventory, scanner, prompt, and reviewer read uses the same artifact. A WIP digest is review-only evidence and cannot satisfy a formal PR-readiness or merge-ready exact-commit gate.

Source `.codex-tmp` content is never filtered as helper state. Ordinary Git ignore/status semantics apply, any reported record makes clean mode dirty, and WIP capture rejects `.codex-tmp` as reserved. Retained `/tmp` artifacts are operational evidence rather than durable storage.

Gitlinks present only in the selected artifact stay uninitialized and unfetched. A gitlink in actual source `HEAD` or the active index fails closed before source status inspection. Missing objects, unsafe links, conflicts, capture races, or any file/entry/byte budget breach fail closed.

## Real HOME And Read-Only Model Tools

After provenance and capability validation, the ordinary Claude CLI receives the current account's real home resolved from the operating-system account database. Caller-controlled `HOME` does not select it, and inherited `XDG_CONFIG_HOME` is removed so alternate config discovery cannot escape the real-HOME boundary. The CLI may use supported local authentication and configuration from that home and may refresh ordinary login through Claude Code's own implementation.

The final command uses Claude `dontAsk` mode and exposes only:

- `Read`, `Grep`, and `Glob` under the explicit `Read(./**)` detached-workspace rule;
- `Bash` under Claude Code's non-prompting read-only command policy, with native sandbox requested as defense in depth.

The reviewer prompt forbids reads outside the detached worktree and its logical private Git view. `Read(./**)` records workspace-relative file access and `dontAsk` denies unmatched permission requests; Claude Code 2.1.212 also applies `Read` path rules to `Grep`, `Glob`, and recognized Bash file readers such as `cat`, `head`, `tail`, and `sed`. Editing, web, and task tools are disabled. Deny-first rules cover critical sensitive real-HOME paths plus `/proc` and `/dev`; admin-managed policy remains part of the trusted ordinary CLI control plane.

For sandboxed Bash, inline settings request removal of authentication and proxy variables, global write denial, and read denial for original source checkout, other review-state roots, critical real-HOME roots, `/proc`, and `/dev`. `allowRead` entries name the current detached worktree and private Git view, but they are exceptions inside a selected-deny policy, not a global host-read whitelist. Sandboxed Bash can technically read another host path outside the worktree when no `denyRead` covers it. The prompt/model scope therefore explicitly forbids all outside-workspace reads; do not describe the selected-deny policy as re-opening only the current workspace or private Git view.

The model-backed launch sets `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=0`. In Claude Code 2.1.212, setting it to `1` strips credentials broadly but also forces effective permission mode to `default`, incompatible with the required `dontAsk` contract. Credential removal from sandboxed Bash instead uses native-sandbox `credentials.envVars` deny rules with `failIfUnavailable: true`; credential-free probes may still use broad subprocess scrubbing. Hooks are disabled, MCP is strict and empty, plugins/skills/slash commands are disabled, and exact init fields must match before a result is accepted.

The real-HOME Claude control plane itself is not described as filesystem-immutable. Ordinary CLI internals may create cache or tool-result artifacts even with session persistence disabled; those control-plane writes are outside the model-tool read-only claim. Post-attempt workspace validation does not cover them.

Claude Code 2.1.212 may create an empty `.claude/.cc-writes` atomic-write staging directory in review cwd when native Bash sandboxing is first used. The provider may remove only an entry proven absent before launch, exact empty, current-user-owned, mode `0700`, and identity-stable through no-follow descriptors plus helper-private quarantine. Pre-existing, swapped, nonempty, or otherwise unsafe entries are retained and rejected. The unchanged common workspace validator then runs; cleanup diagnostics never replace a primary supervision or forwarded-signal failure.

The native sandbox is requested with `failIfUnavailable: true`, `autoAllowBashIfSandboxed: false`, and `allowUnsandboxedCommands: false`. The actual stream must report `permissionMode: dontAsk`, the exact tool set, requested model, no unexpected MCP/slash/skill/plugin surface, and expected authentication indicator. Observable init changes fail closed. The `2.1.212` init schema does not report effective sandbox fields, merged managed permission arrays, or path-rule evaluation, so init cannot prove the merged sandbox. These remain requested inputs rather than independently observed runtime evidence.

After every completed attempt, exact external-workspace validation checks materialized snapshot, private Git database and administrative state, generated diff, and prompt before any result or fallback can be accepted. Mutation is terminal `permission-mismatch`. This check proves only the exact inspected state at validation time; it does not prove that no transient write or outside-workspace side effect occurred.

## Authentication

The caller environment is frozen once and reduced to exactly one selected explicit carrier:

1. non-empty `ANTHROPIC_API_KEY` wins;
2. otherwise non-empty `CLAUDE_CODE_OAUTH_TOKEN` wins;
3. otherwise Claude Code uses ordinary local login from real HOME.

Both explicit values and inherited credential-bearing proxy URLs enter parent-side redaction inputs, but only the winning explicit variable enters the Claude control plane. The helper necessarily tests whether each explicit value is non-empty and copies the winner into the child environment as an opaque string. It never interprets the value as a credential. Selected raw and normalized output forms are redacted before streamed stdout/stderr reach disk. Authentication and proxy variables remain requested removed from sandboxed Bash environments.

The helper never:

- reads or parses a Keychain item or Claude credential file;
- invokes a credential query or replacement command;
- copies a credential into a temporary home, file, argument, or sandbox carrier;
- stages or watches refresh-token changes;
- writes authentication state back to the host;
- persists bearer-capable token contents or refresh metadata in review state.

Local-login discovery, Keychain/file access, locking, refresh, and persistence belong entirely to the installed publisher-verified Claude Code control plane, as with an ordinary CLI invocation. The helper has no managed credential protocol and owns only opaque environment selection, redaction, model-tool policy, and outcome classification.

Before any review prompt is supplied, the verified CLI runs a bounded, redacted `auth status --json` preflight with the same real HOME, filtered environment, safe mode, setting-source suppression, and inline settings. Accepted tuples are exact: first-party `api_key` from `ANTHROPIC_API_KEY`, first-party `oauth_token` for requested `CLAUDE_CODE_OAUTH_TOKEN`, or first-party `claude.ai` for ordinary local login. Valid logged-out JSON is parsed before nonzero process status is classified. Cloud providers, Claude apps gateway, `apiKeyHelper`, other logged-out state, unknown providers/methods, or API-key source mismatch are blocked. The actual `system/init` event then cross-checks `apiKeySource` before authentication is marked used.

Claude Code 2.1.212 reports both `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_AUTH_TOKEN` as the same first-party `oauth_token` method with no carrier field. The helper filters `ANTHROPIC_AUTH_TOKEN` from caller environment and records the requested carrier separately from effective provider/method/API-key-source fields; it does not mislabel the requested name as a proven effective carrier.

A launched explicit API key, explicit OAuth token, or local login that Claude rejects is `blocked-authentication`. Tell the operator to unset or replace `ANTHROPIC_API_KEY`, unset or replace `CLAUDE_CODE_OAUTH_TOKEN`, or run `claude auth login`, respectively, then pause. Authentication failure never authorizes a model downgrade or Copilot fallback. Access-token expiry alone is not failure when ordinary Claude Code can refresh the login.

## Network And TLS

The Claude control plane inherits standard proxy and CA environment so an ordinary supported installation can reach Anthropic through the user's configured network. The helper does not build a separate CONNECT proxy or copy CA material for final review. Credential-bearing proxy variants enter parent-side output redaction; unsafe or ambiguous credential forms fail closed, while routing-only proxy endpoints and `NO_PROXY` values are not globally replaced. Proxy variables are requested removed from sandboxed Bash. Web tools are disabled. Network, proxy, TLS, or routing failure never becomes authentication or entitlement evidence.

## Capability And Output Verification

Credential-free capability probes verify the exact public flags and the accepted release's documented safe-mode/`dontAsk` contract, including tool visibility, setting-source suppression, streaming structured output, requested model, effort request, and session/export controls. Inline sandbox settings are requested fail-closed on actual launch; no separate model-backed behavioral probe is claimed.

Claude output is accepted only as strict JSONL with one `system/init` event first and one terminal result last. The bounded file is consumed in one pass while retaining only the two contract events and aggregate error state. Duplicate/misordered events, duplicate JSON keys, non-standard constants, malformed errors, partial result text attached to errors, missing model evidence, model substitution, permission-mode changes, tool widening, or authentication-indicator changes fail closed. Additive non-security init metadata is ignored. Requested effort is recorded, but current output does not independently verify effective effort. Repository-controlled output never supplies authentication, entitlement, availability, or fallback evidence.

All launches use finite deadlines, bounded stdout/stderr artifacts, process containment, signal forwarding, descendant cleanup, and post-quiescence artifact checks. Timeout, overflow, drain failure, retained descendants, or missing terminal output is `inconclusive`.

## Failure Classification

- `blocked-authentication`: Claude rejected the selected API key, OAuth token, or ordinary local login.
- `blocked`: deterministic policy, configuration, permission, provenance, unsupported-platform, or capability failure.
- `inconclusive`: transient network/capacity/timeout, bounded-I/O, race, lifecycle, or unverifiable-output failure.
- entitlement fallback: only a strictly verified denial for the requested Claude model may advance to the next pinned model; both models must be entitlement-blocked before separately authorized compatibility Copilot fallback.
- deterministic runtime fallback: only verified runtime absence/unavailability under `explicit-claude-with-copilot-fallback` consent may enter Copilot.

Capacity, rate limits, timeouts, network errors, 5xx responses, missing artifacts, model substitution, findings, authentication problems, and inspection uncertainty are never fallback reasons. Any helper fallback result remains diagnostic-only and never satisfies a named lane.

## Runtime Report

Persist only redaction-safe evidence:

- `review_contract: supplied-diff-private-git` and `named_lane_eligible: false`;
- source and verified executable paths, exact version, platform, architecture, manifest/signature/checksum evidence, and verifier identity;
- requested native-sandbox settings, documented init-contract status, and `dontAsk`/read-only model policy, without claiming effective merged sandbox proof;
- workspace content mode, base/head/tree identity, and WIP digest when present;
- requested authentication carrier plus effective provider/method/API-key-source fields, without credential contents or bearer-capable token metadata;
- requested/effective model, requested effort and effective effort when observable, attempt category, bounded log paths, and terminal status.

Never persist credential contents, bearer-capable token metadata, real-HOME file contents, or unbounded probe output.

## Official Sources

- [Claude Code advanced setup](https://code.claude.com/docs/en/installation): native platforms, version management, signed manifests, release-key fingerprint, and checksums.
- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing): native sandbox behavior and supported platforms.
- [Claude Code authentication](https://code.claude.com/docs/en/authentication): ordinary local and explicit authentication behavior.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage): command and flag surface.
- [Claude Code settings](https://code.claude.com/docs/en/settings): managed-policy precedence over CLI settings and source-level reporting limits.
- [Claude Code configuration diagnostics](https://code.claude.com/docs/en/debug-your-config): settings diagnostics and active-source visibility.
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes): `dontAsk` mode and permission semantics.
- [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference): built-in tool names and file/shell behavior.
- [Claude Code corporate network configuration](https://code.claude.com/docs/en/corporate-proxy): supported proxy and custom-CA inputs.
