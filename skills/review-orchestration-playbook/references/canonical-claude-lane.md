# Canonical Claude Code Lane

Use this contract for the actual Anthropic Claude Code lane in named double and triple review. Do not route this lane through `isolated_review`: that helper materializes a supplied diff in a helper-owned detached worktree backed by private minimal Git and is diagnostic-only.

## Workspace And Process

1. Create a lane-unique clean Git working tree at the same frozen `head_sha` used by the Codex lane. Prefer a lane-private local clone or private bare object store plus worktree under the task's temporary root, so required Git metadata does not live under the denied implementation checkout. This is a local Git setup step, not a network clone or prepared-diff materialization. With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, prove that the exact range and both endpoint trees are locally complete without rendering a full diff; hydrate missing objects before freezing or block the lane. Remove remote URLs before model launch. Verify clean status, exact `HEAD`, both commits, and bounded read-only range queries.
2. Start a new actual `claude` process with its working directory set to that worktree. Do not use `--continue`, `--resume`, `--from-pr`, `--fork-session`, or `--worktree`.
3. Preserve the real user `HOME` as Claude's trusted authentication and CLI control plane. The model-visible review scope is the detached working tree plus only its lane-private Git metadata/object paths that read-only Git needs for the frozen refs.
4. Send the small control prompt through stdin. Do not create a prompt or diff file in the worktree, and do not send a prepared diff, changed-file contents, Codex findings, or parent suspicions.

The canonical launch is a direct Claude Code invocation, not a call to any helper reviewer:

```text
<resolved-compatible-claude-path>
  --print
  --model <claude-opus-4-8-or-authorized-4-7>
  --effort max
  --permission-mode dontAsk
  --output-format stream-json
  --verbose
  --no-session-persistence
  --safe-mode
  --no-chrome
  --disable-slash-commands
  --strict-mcp-config
  --mcp-config {"mcpServers":{}}
  --setting-sources ""
  --settings <inline-native-sandbox-json>
  --tools Read,Grep,Glob,Bash
  --allowedTools Read(./**),Grep,Glob,Bash
  --disallowedTools Edit,Write,NotebookEdit,WebFetch,WebSearch,Task
```

Run the compatible-version selection preflight below before the parent revalidates the selected CLI's provenance and constructs the fixed reviewed launch. Pass settings inline; do not write them into the review workspace. `--safe-mode` disables automatic customizations and slash-skill loading, not the built-in `Read` tool. The prompt therefore tells Claude to read applicable tracked `AGENTS.md`, repo-local skill documents, and project guidance from the worktree explicitly. It must not read an installed skill or guidance file outside the worktree.

The inline settings must also set `disableBundledSkills: true`. `--safe-mode` alone is not evidence that bundled skills are absent; the explicit setting is required before the init `skills` field can be expected to be empty.

## Compatible-Version Selection Preflight

The canonical Claude Code compatibility range is `>=2.1.211,<3.0.0`, defined once in [`claude_version_policy.py`](../scripts/review_runtime/claude_version_policy.py). Every consumer imports that policy; documentation, a per-version manifest, and a stream fixture must not redefine production eligibility. Only strict three-component stable releases are eligible. Versions below the floor, prereleases, development labels, unparseable versions, and version `3.0.0` or later are blocked before candidate execution. Claude Code `2.1.212` is the audited per-version stream-schema baseline, not a global eligibility pin.

Before any prompt, credential, authentication, repository, range, PR, or review-workspace input is exposed to Claude, invoke [`named_claude_preflight`](../scripts/named_claude_preflight). It considers candidates in this order:

1. an explicit absolute `--claude-path` override, optionally paired with its declared `--claude-version`;
2. the highest compatible stable side-by-side install under `$HOME/.local/share/claude/versions/`; then
3. the first present controlled active-install path from `$HOME/.local/bin/claude`, `/opt/homebrew/bin/claude`, and `/usr/local/bin/claude`.

An explicit override is authoritative: missing, unusable, unsupported, or ambiguous explicit input fails closed and never falls through. Side-by-side enumeration is descriptor-bound, count-bounded, identity-stable, and ordered by parsed release components rather than lexical path order; out-of-range and prerelease directory names are not eligible candidates. Candidate presence is tri-state: only exact absence may advance priority, while I/O, resolution, enumeration, or identity uncertainty stops as `candidate-inspection-inconclusive`. Caller `PATH` is ignored. Before executing any candidate, require an in-range version declaration from an explicit override or a resolved native-installer `versions/<semver>` target. A missing declaration is blocked; a declaration outside the compatibility range is blocked without execution.

For the declared compatible version, require a native executable for the supported platform and verify the fixed Anthropic signing key, signed per-version manifest, selected platform artifact, exact size, and SHA-256 before any probe. Bind the returned publisher evidence back to the requested path, release version, platform, and `claude` binary identity, and capture the descriptor-bound source identity including `ctime`. Open mutable candidate and source descriptors with nonblocking, no-follow semantics, then require a regular descriptor with the expected complete identity before reading a native header, hashing, or copying; a FIFO or replacement race is inconclusive rather than a blocking read. Before creating the private GPG directory, resolve the system temporary parent to its canonical path and give the verifier a real private child path; aliases such as macOS `/tmp -> /private/tmp` do not weaken the requested-path-equals-resolved-path check.

Only while that source identity remains stable, materialize a private digest-verified executable snapshot. Run bounded `<private-snapshot> --version` and then bounded `<private-snapshot> --help` with empty stdin, fixed `/` cwd, and a fixed credential-free environment that carries no prompt, credential, repository, range, PR, or workspace input. Reverify the snapshot after each probe. The reported version, declared version, and signed artifact version must match exactly. The mandatory credential-free `--help` probe verifies only the advertised capability surface used by the reviewed argv, including the safe-mode contract; it does not prove launch semantics, the actual final argv, the final merged sandbox, managed permission arrays, or path-rule evaluation. A missing or incompatible advertised surface fails closed. After both probes, perform a fresh descriptor-bound hash of the mutable source against the signed size and SHA-256 and recheck its identity; stat identity alone is insufficient. Source drift takes precedence over any observed version mismatch.

The helper erases the temporary snapshot before return and never executes the mutable installation path. It may fetch signed release metadata needed for verification, but never downloads or installs a Claude executable and never creates, changes, or repairs an active symlink. Acquiring a missing compatible release, installing a different patch, changing the active release, or repairing a symlink is a separate host mutation that requires explicit authorization and the official installer/version manager. In particular, do not install or downgrade to `2.1.212` merely because it is the schema baseline.

The helper emits exactly one bounded JSON object. Successful evidence uses `classification: accepted` and `reason: compatible-version-selected`; it binds `selected_version`, `declared_version`, `observed_version`, the fixed resolved source path, descriptor identity, signed per-version artifact metadata, capability status, and the current stream-compatibility/profile, audited-baseline, and capability-contract source digests. Deterministically missing or unusable compatible selection is blocked as `compatible-version-unavailable`; an unsupported declaration is blocked as `unsupported-version`; coherent signed/declared/observed version disagreement is blocked as `signed-version-identity-mismatch`; an advertised-surface mismatch is blocked as `capability-contract-mismatch`; and invalid signed metadata, signer identity, signature, manifest, artifact identity, or artifact digest is blocked as `publisher-verification-failed`. Candidate, publisher dependency/network, snapshot, probe, stream-contract, or identity uncertainty is inconclusive. Never collapse uncertainty into deterministic unavailability or continue to a lower-priority candidate after uncertain inspection.

Persist the accepted JSON in a parent-owned, parent-private regular file outside the model-visible worktree. It must be owned by the current user, have exactly one link, expose no group or world permission bits, and stay descriptor-stable while read. Symlinks, hard links, workspace-local evidence, special files, and identity drift fail closed. Only then may the parent pass its selected `resolved_path` and signed-artifact identity to the canonical provenance revalidation and direct launch below. Any version, provenance, capability, or stream-contract failure preserves the requested shape: a requested double remains double-but-blocked, and a requested triple remains blocked because its Claude lane is incomplete. Independently proved GitHub Codex unavailability may make that triple's effective shape double, but the effective double is still incomplete until Claude succeeds.

## Canonical Executable Provenance

The canonical direct lane uses the user's installed actual Claude Code executable at the one resolved path accepted by the selection preflight. Before exposing credentials, review metadata, or repository content, the parent must:

1. resolve the selected executable without later `PATH` lookup and reject a missing, non-regular, non-executable, script/interpreter-wrapper, prerelease, development, unsupported-platform, or future-major candidate;
2. verify the fixed Anthropic release-signing key, signed manifest for the selected compatible version, expected platform artifact, exact size, and SHA-256 of the stable resolved installed file, using `verify_claude_release` or equivalent checks before executing the candidate;
3. require exact agreement among the accepted preflight's declared, observed, selected, and signed-artifact versions; bind the accepted capability and stream-contract evidence; and construct the fixed reviewed argv above; and
4. immediately before launch, revalidate the same path identity, signed artifact size, and SHA-256, launch that exact resolved path directly, then revalidate it again after process completion. Any drift or uncertainty makes the lane inconclusive.

The mandatory credential-free `--help` probe is part of preflight and verifies only the advertised capability surface. It does not prove the actual launch argv, runtime semantics, final merged sandbox, managed permission arrays, or path evaluation. Publisher binding, the fixed argv, strict leading-init/terminal validation, and source revalidation remain separate gates; no one gate substitutes for another.

The accepted preflight's private executable snapshot is temporary evidence for its credential-free version and help probes; it is erased before return and is never the later review-launch path. The direct review launch does not reuse that snapshot and does not call `snapshot_verified_claude_executable`; it also does not inherit the low-level helper's dependency-closure, outer-sandbox, credential-carrier, catalog, guarded-writeback, or recovery contracts. It intentionally uses the revalidated host-installed executable path for the actual ordinary real-`HOME` CLI process; the before/after identity and digest checks detect drift but do not claim the stronger immutability of the helper snapshot. The same publisher-verified `>=2.1.211,<3.0.0` eligibility range applies to both canonical and helper paths, while their later isolation and credential contracts remain distinct. Record only non-secret provenance metadata such as resolved path, selected version, platform, artifact digest, capability/profile binding, and verification state.

## Authentication Control Plane

The canonical direct lane uses ordinary Claude CLI authentication selected before launch with precedence `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local login in real `HOME`. Opaque-forward only the winning explicit value and remove the lower-priority explicit source from the child environment. It does not use the low-level helper's credential broker, staged carrier, credential-lock catalog, guarded writeback, or recovery journal, and it must not claim those helper-only guarantees.

After publisher verification and before review input, run the exact revalidated CLI's bounded `auth status --json` against that selected environment and require its non-secret status/source evidence to agree with the parent selection. Do not inspect, copy, log, or persist credential values; the strict stream validator independently binds the selected source to observable init evidence.

Real `HOME` is a trusted control plane. The publisher-verified Claude CLI may update ordinary CLI-owned authentication and runtime state there, including credential refresh and possible cache or tool-result artifacts. These are accepted CLI control-plane side effects, not model-authorized review mutations; they do not authorize model/tool writes or deliberate host mutations. This contract does not enumerate or attest every CLI-owned `HOME` write. The model prompt still forbids direct reads of real-`HOME` content, and the native sandbox must deny model-visible credential/configuration roots. Do not inspect, copy, print, or place credential contents in review state.

Large tool output may be persisted or spilled by Claude Code into a CLI-owned real-`HOME` tool-result path. The CLI report or `persistedOutputPath` metadata alone is an allowed control-plane observation and does not block the lane. The model must never follow that report with `Read`, `Grep`, or `Glob` against the outside-worktree path. It must instead rerun a narrower bounded command that addresses only worktree paths and returns a bounded result. A direct structured tool read of the spilled path adds deterministic blocked evidence and blocks the lane when the rest of the stream is conclusive. Final classification still follows the global failure precedence: concurrent malformed or otherwise inconclusive evidence produces `inconclusive` with the combined reasons, never accepted findings.

If organization policy forbids ordinary CLI control-plane writes, use an explicitly authorized API key or OAuth token only when that mode satisfies the same policy, or report the lane blocked; do not silently introduce the helper credential wrapper. A reported `Login expired`, an explicit HTTP/status 401, an explicit OAuth/credential/login/authentication/token refresh failure, or a directly adjacent authentication state of expired, invalid, or unauthorized is `blocked-authentication`: ask Joey to unset or replace the winning explicit variable, or run `claude auth login` for local login, then wait for an explicit retry. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit failures are not authentication evidence and remain `inconclusive`; an authentication word separated from `error`/`failure` by one of those resource terms does not change that result. A bare child exit code 401, credential-file or other ambiguous credential I/O, a generic non-authentication refresh failure, or uncertain persistence state is also `inconclusive`. Neither condition authorizes provider fallback. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable. The lane does not take or verify a complete real-`HOME` diff, so cache or tool-result artifacts may retain review-derived data according to upstream CLI behavior. Post-run worktree cleanliness does not attest what the trusted control plane changed or prove that no transient control-plane write occurred.

## Native Sandbox Contract

The inline settings request all of the following:

- hooks disabled;
- bundled skills disabled explicitly;
- native sandbox enabled with fail-if-unavailable;
- sandboxed Bash never auto-approved and unsandboxed commands forbidden;
- global write denial for model-visible tools and sandboxed commands;
- read denial for critical sensitive roots such as authentication, credential, SSH, GPG, cloud, Codex, Claude, and other private configuration roots;
- explicit read entries for the clean worktree and its registered Git metadata/object store;
- credential-file and secret-environment denial;
- no MCP, browser, editing, web, task, or other state-changing tool surface.

Construct the inline JSON from resolved absolute paths with this shape; never interpolate credentials or repository content into it:

```json
{
  "disableAllHooks": true,
  "disableBundledSkills": true,
  "permissions": {
    "deny": ["Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Task"]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "autoAllowBashIfSandboxed": false,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": [
        "<credential-and-private-config-root>",
        "<implementation-checkout>",
        "<other-review-state-root>",
        "/proc",
        "/dev"
      ],
      "allowRead": ["<clean-worktree>", "<registered-git-metadata-or-object-root>"],
      "denyWrite": ["/"]
    },
    "credentials": {
      "files": [{"path": "<sensitive-file-or-root>", "mode": "deny"}],
      "envVars": [{"name": "<secret-environment-name>", "mode": "deny"}]
    }
  }
}
```

Enumerate every applicable sensitive root and every Git metadata/object root rather than leaving placeholder values in a real invocation. If a protected root would contain required Git metadata, create the worktree layout so those scopes do not overlap; do not rely on `allowRead` to override a broader `denyRead`.

Treat this as a selected-deny native sandbox, not a global host-read whitelist. `allowRead` records the intended review scope but does not prove every other host path is unreadable; sandboxed Bash may technically read another path not covered by `denyRead`. The prompt/model contract therefore forbids direct reads outside the worktree. Read-only Git may internally access only the worktree's registered Git metadata/object paths for the frozen range; that logical Git metadata is part of the review workspace and is not permission to inspect the source checkout, parent directory, real `HOME`, or another review.

Capability output and `system/init` evidence cannot attest the final merged sandbox, managed permission arrays, or path-rule evaluation. This limitation applies even to the audited Claude Code 2.1.212 baseline output. Record the settings as requested configuration. Do not promote help or init output into independent proof of effective enforcement, and do not restore the retired complex outer global-read-isolation design.

If the required native sandbox, global write deny, sensitive-root denies, tool restrictions, actual Claude executable, or structured-output verification cannot be established, report the lane as `blocked` or `inconclusive` under the failure contract. Never weaken the boundary or substitute Copilot.

## Structured Init And Terminal Evidence

Parse `stream-json` as bounded strict UTF-8 JSONL. Every nonblank line must be one JSON object; reject duplicate keys, nonstandard constants, undecodable text, or non-JSON output. The first nonblank record must be the sole event with `type: system` and `subtype: init`; the last nonblank record must be the sole event with `type: result`. A missing, duplicate, malformed, out-of-order, or trailing contract event makes the lane `inconclusive`; partial findings do not count. A structurally valid terminal event that fails the success acceptance schema is passed to the failure classifier below rather than being classified by this envelope rule.

Capture bounded raw stdout in parent-owned state outside the model-visible
worktree. The canonical lane must pass those captured bytes through
[`validate_claude_stream.py`](../scripts/validate_claude_stream.py); prose-only
inspection or an ad hoc parser does not satisfy this gate. Keep stderr separate
and give the validator the same resolved cwd, concrete model, and selected
authentication source used to construct the direct Claude CLI argv:

```text
python3 <playbook>/scripts/validate_claude_stream.py
  --cwd <resolved-clean-worktree>
  --model <claude-opus-4-8-or-authorized-4-7>
  --preflight-result <absolute-parent-private-accepted-preflight-json>
  --authentication-source <api-key-or-oauth-token-or-local-login>
  --process-returncode <exact-child-returncode>
  --input <bounded-raw-stream-jsonl>
```

The preflight evidence path must be absolute and must resolve outside the reviewer worktree to a descriptor-stable, single-link regular file owned by the current user, with no group or world permission bits and a maximum size of 16 KiB. The validator parses it as strict JSON, requires exact accepted selection/publisher/identity/capability fields, and binds the selected version plus current compatibility-profile, audited-baseline, and capability-contract source digests before parsing review output. Symlinked, hard-linked, workspace-local, special-file, missing, stale, permissive, malformed, or mismatched evidence is `inconclusive` and cannot supply findings.

The executable/importable validator accepts only the exact trust-source/profile pairing that produced its runtime binding: `named-parent-private-preflight` is valid only for `named-direct`, and `low-level-helper` is valid only for `helper-linux` or `helper-darwin`. Every cross-pairing fails as `validator.runtime-binding-invalid` before stream parsing.

The validator applies the compatible machine contract and
fixed upper bounds of 8 MiB total input, 10,000 raw lines, 1 MiB per line,
and 128 decimal digits per JSON integer. JSON floating-point tokens are parsed
exactly as decimal values, with at most 256 characters, 128 significand digits,
and an absolute explicit exponent no greater than 308. These parser bounds do
not depend on Python's process-global integer-string conversion limit and prevent
binary floating-point overflow or negative underflow from changing a metric's
sign.
It emits one JSON object with `classification: accepted` and the verbatim
`findings` only after the exact child process return code is integer zero and
every envelope, init, and terminal-success check passes. A nonzero child return
code, including `401`, is `inconclusive` by itself; authentication classification
requires recognized structured authentication evidence rather than an exit-code
guess. When the fully validated stream instead supplies deterministic structured
`blocked` or `blocked-authentication` evidence, preserve that classification even
with a nonzero child return code; the return code never turns such a failure into
success. An invalid or missing child return code is always `inconclusive`.
Every failure emits a fail-closed `blocked`, `blocked-authentication`, or
`inconclusive` classification without a `findings` field. Validator acceptance
attests only the reported invocation fields and terminal artifact; it never
claims proof of the final merged sandbox, managed permission arrays, or path-rule
evaluation. It also does not classify accepted prose as clean, findings, or
undetermined. Preserve the accepted `findings` value exactly and pass it to
[`review_result.py`](../scripts/review_runtime/review_result.py) only after this
artifact gate succeeds. That canonical disposition helper records semantic
outcome and presentation without changing the validator or rewriting the result.

The validator is a machine interface, not a help-text interface. `-h`, `--help`,
missing or unknown arguments, and invalid choices all return nonzero, emit exactly
one `inconclusive` JSON object on stdout, and leave stderr empty. Exit status zero is reserved for `accepted` output.

The current [`claude-stream-compatibility.json`](claude-stream-compatibility.json) contract uses `strict-version-and-launch-profiles` mode, binds the audited [`claude-2.1.212-stream-schema.json`](claude-2.1.212-stream-schema.json) baseline and closed [`claude-stream-schema.json`](claude-stream-schema.json) runtime contract, and selects a reviewed closed profile by the exact preflight version: `legacy-base` for `>=2.1.211,<2.1.216`, and `extended-2x` for `>=2.1.216,<3.0.0`. The baseline is not a global eligibility pin. For every in-range selected release, the contract adapts the baseline `claude_code_version` constant to the exact accepted preflight-selected version. The structural profile governs init, intermediate-event, and terminal surfaces; exact-version additive metadata contracts are applied only afterward and cannot override the baseline or structural profile. The reviewed exact `2.1.216` overlay retains only the optional init fields `estimated_tokens` and `estimated_tokens_delta`, each with the exact value `null`; later patches do not inherit that overlay. Both structural profiles keep envelope, model identity, init, intermediate-event, and terminal surfaces closed, and `extended-2x` explicitly admits only its reviewed additional fields and variants. An in-range future patch is not rejected merely because of its patch number, but it is accepted only when its observed structure matches the applicable closed structural profile plus any exact-version overlay. Unknown or incompatible structure fails closed until a reviewed compatibility-profile update permits it. This compatibility result does not claim that every admitted patch received an independent per-version audit.

Before accepting the result, compare the leading init against that preflight-bound compatibility contract. Require all of these observable fields:

- `cwd` equals the resolved lane-unique clean worktree exactly;
- `permissionMode` equals `dontAsk`;
- `tools` is a duplicate-free set exactly equal to `Read`, `Grep`, `Glob`, and `Bash`;
- `mcp_servers`, `slash_commands`, `skills`, and `plugins` are present and exactly empty arrays;
- `model` equals the requested concrete model string exactly, without alias normalization or silent substitution;
- `claude_code_version` equals the publisher-verified preflight version; and
- `apiKeySource` is a string that exactly matches the runtime-bound authentication class: `ANTHROPIC_API_KEY` for explicit API-key mode and `none` for explicit OAuth-token or ordinary local-login mode. This init field distinguishes API-key from non-API-key operation only; the parent-selected OAuth-token versus local-login source remains bound by the earlier exact-CLI `auth status --json` evidence and the launch environment.

Missing, malformed, or conflicting required fields fail closed as `inconclusive` and cannot count as the Claude lane. A well-formed required field that mismatches the frozen launch is a deterministic `blocked` configuration/policy mismatch. The init top-level field set is closed under the selected structural profile plus any exact-version overlay. `legacy-base` permits only the common reviewed fields plus optional nonempty `session_id`. `extended-2x` additionally requires the reviewed exact `output_style`, ordered `agents`, ordered `capabilities`, analytics/feedback booleans, nonempty `uuid`, and `fast_mode_state: off`. Exact selected `2.1.216` additionally permits only the optional init fields `estimated_tokens` and `estimated_tokens_delta`, each exactly `null`; no other selected version inherits those fields. Any other field, missing required profile field, reordering, fixed-value drift, or malformed exact-overlay value is `inconclusive` until a reviewed compatibility-profile update permits it. These observable init fields still do not prove the final merged sandbox, managed permission arrays, or path-rule evaluation.

Validate every record between init and terminal against the selected profile's closed, session-bound intermediate contract. The reviewed event families are `system/thinking_tokens`, assistant messages, user tool results, and `rate_limit_event`; each has a closed top-level and nested field set, and every event with a session binding must match the init session. The rate-limit contract admits only the reviewed ordinary `allowed` and extended `allowed_warning` variants, including bounded numeric ratios and exact boolean/string/integer types. An unknown type, subtype, field, nested variant, missing required field, malformed value, or session mismatch is `inconclusive`; no intermediate event may be ignored merely because the terminal result looks successful.

As an additional observable scope gate, the validator inspects assistant `tool_use` input only. The official tool-input schema requires `Read.file_path` to be absolute; the gate also requires every present `Grep.path` or `Glob.path` to be absolute. It never anchors or expands a relative path or home shorthand such as `~`; those values are `intermediate.tool-path.scope-unverified`. An omitted `Glob.path` uses the exact resolved `cwd`, as specified by the tool schema. An omitted `Grep.path` remains outside the gate's proved path semantics rather than being silently treated as cwd.

Every `Glob` call must also supply a nonblank bounded `Glob.pattern`. The validator proves a bounded parent-free relative subset that admits ordinary wildcard components, recursive `**`, character classes, and at most 64 simple brace alternatives, including common patterns such as `**/*.py` and `src/**/*.{py,md}`. Leading `./` components are safely removed before checking, so `./**/*.py` is accepted; intermediate `.` remains fail closed. It does not implement or claim a complete glob parser. Absolute patterns, exact `..` path components, home shorthand, backslash escapes, extglob tokens such as `@(` or `!(`, nested or malformed braces, and over-limit alternatives fail closed. A lexical or symlink-resolved escape contributes `intermediate.tool-path.outside-workspace`; syntax or semantics that cannot be proved contributes `intermediate.tool-path.scope-unverified`. Every expanded brace alternative is checked independently, so an escaping alternative contributes outside-workspace evidence even when another alternative is safe.

Wildcard directory components require more than a literal-prefix check. The validator conservatively treats each dynamic directory component as potentially matching every child directory and treats `**` as recursive. It traverses those possibilities under fixed global entry, state, and depth limits, resolves every encountered symlink before following it, rejects any reachable outside-worktree symlink, and returns `scope-unverified` when enumeration, identity, or a resource bound prevents a complete validation-time proof. Internal symlink aliases are allowed and deduplicated by resolved-directory state. Every scan iterator is closed before return, and this scan reuses the one cwd binding rather than opening a second workspace binding.

For `named-direct`, the validator opens the exact resolved cwd descriptor once at validation start, binds its directory identity, reuses that one binding for all structured path and pattern checks, and rechecks the named cwd against the descriptor immediately before returning. It closes the descriptor on every exit. Lexical containment and symlink-resolved containment are both required, and machine reasons never contain the inspected path. This is validation-time evidence under the lane's read-only, no-concurrent-workspace-mutation assumption. It cannot prove which target a tool opened earlier, cannot eliminate an ABA replacement that changes away and back between tool execution and validation, and does not turn the validator into the real access-control boundary. The prompt/model scope, parent-controlled workspace, and requested native sandbox remain that boundary.

An outside-worktree value or symlink escape adds deterministic blocked evidence; it does not override the validator's global precedence. Any concurrent malformed, authentication-mixed, or other inconclusive evidence makes the final classification `inconclusive` with all applicable reasons. The gate deliberately does not recurse into user tool-result content or `persistedOutputPath`, because those may report trusted CLI control-plane writes. It also does not parse `Bash` command strings or prove every shell expansion, runtime read, or unreported tool effect. It is not complete host-read enforcement: those remaining behaviors stay under the prompt/model and parent contract.

For the terminal `result`, require the audited baseline's exact acceptance structure:

- `type` is the string `result`, `subtype` is the string `success`, and `is_error` is the boolean `false`;
- `result` is a required string whose `strip()` value is nonempty; preserve the original string verbatim as the findings payload. The validator returns it unchanged and does not apply clean-sentinel or presentation policy;
- `modelUsage` is a required nonempty object; every key is a nonempty model-ID string and every value is an object. Under the current compatibility profile, the baseline-reviewed aliases for requested `claude-opus-4-8` are `claude-opus-4-8` and `claude-opus-4.8`; the aliases for requested fallback `claude-opus-4-7` are `claude-opus-4-7` and `claude-opus-4.7`. At least one key must belong to the exact requested model's set. The only baseline-reviewed auxiliary key is `claude-haiku-4-5-20251001`. A key from the other supported primary-model set is a deterministic blocked model substitution even when a requested-model key is also present; any other model-usage key is `inconclusive` until a reviewed compatibility-profile or versioned-schema update permits it. Thus a `claude-opus-4-8` request with only or with both a `claude-opus-4-7` key is never accepted;
- `duration_ms` and `duration_api_ms`, when present, are nonnegative integers; `num_turns` is a positive integer; `total_cost_usd` is a nonnegative finite exact-decimal number within the stream parser's lexical and exponent bounds; `session_id` and `uuid` are nonempty strings; and `usage` is an object. When both init and terminal events report `session_id`, the values must match exactly or the stream is `inconclusive`. A missing optional metric is acceptable, but a present value with the wrong type or range is `inconclusive`;
- under `legacy-base`, the extended fields `fast_mode_state`, `terminal_reason`, `time_to_request_ms`, `ttft_ms`, and `ttft_stream_ms` are forbidden. Under `extended-2x`, successful results require `fast_mode_state: off`, `terminal_reason: completed`, and nonnegative integer latency fields; reviewed failure variants may include those fields only with the same strict values and types;
- `stop_reason`, when present, is exactly `null` or `end_turn`. Any other value—including `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, or `refusal`—is a deterministic blocked incomplete or abnormal terminal result and cannot supply findings;
- `structured_output`, when present, is exactly `null` because the canonical launch does not request a structured-output schema. A non-null value is contradictory evidence and makes the lane `inconclusive`;
- `error` and `errors`, when present, are explicitly empty: `null`, a whitespace-only string, an empty array, or an empty object;
- `api_error_status`, when present, is `null` or a whitespace-only string; and
- `permission_denials`, when present, is an empty array.

A non-success subtype, `is_error: true`, blank/non-string `result`, missing or malformed `modelUsage`, no requested-model match, unaccepted `stop_reason`, non-null `structured_output`, nonempty `error`/`errors`, nonempty `api_error_status`, or nonempty/malformed `permission_denials` fails closed and cannot supply findings. Classify a structurally valid permission denial, output truncation/abnormal stop, exact-model mismatch, or configuration/policy mismatch as `blocked`. When a non-success terminal follows any deterministic init or terminal blocker, absence of error prose preserves `blocked` and does not add a generic unclassified reason. Classify only a structurally valid recognized `Login expired`, explicit HTTP/status 401, explicit OAuth/credential/login/authentication/token refresh error, or directly adjacent expired/invalid/unauthorized authentication state as `blocked-authentication`. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit errors, credential-file/I/O errors, a bare child exit code 401, non-authentication refresh failure, malformed evidence, contradictory evidence, or mixed-category evidence are `inconclusive`.

The only non-authentication error prose that authorizes the pinned-model fallback is a strict recognized model-entitlement or organization-policy denial, including exact account/plan model-access denials and reviewed structured model-entitlement codes. The validator emits `classification: blocked` with machine reason `terminal.model-entitlement-denial` or `terminal.organization-policy-denial`; a parent may advance from `claude-opus-4-8` to `claude-opus-4-7` only when every classified message belongs to those two categories. Mixed, extended, authentication, resource/quota/capacity/rate-limit, unclassified, or ambiguous evidence is `inconclusive`, and prose inspection outside the validator never authorizes fallback. Post-acceptance result disposition is separate: prose inspection may choose only `summary-only`, `actionable-findings`, or `undetermined` for `classify_review_result`, after artifact acceptance has already succeeded.

The machine-readable compatibility profile is [claude-stream-compatibility.json](claude-stream-compatibility.json), bound to the audited [Claude Code 2.1.212 baseline](claude-2.1.212-stream-schema.json) and the closed runtime profile in [claude-stream-schema.json](claude-stream-schema.json). Its `strict-version-and-launch-profiles` mode selects the structural version and launch profiles whose required and optional field lists form closed allowlists for init, every intermediate event family, and every terminal variant. It then applies exact-version additive metadata contracts without allowing them to override those structural contracts; the exact `2.1.216` overlay permits only optional init `estimated_tokens` and `estimated_tokens_delta` fields with `null` values. Any other field, including an unknown error-bearing field, makes the lane `inconclusive` until a reviewed compatibility-profile update explicitly adds it. Do not infer a model alias, event variant, or harmless metadata field from punctuation, provider convention, or a later CLI version. The fail-closed compatibility guarantee covers the stream envelope, leading init, intermediate sequence, terminal variants/fields, session binding, and model identity; it still does not prove absence of unreported runtime effects.

This evidence verifies only what the CLI reports about that invocation. It does not prove the final merged native sandbox, merged admin-managed permission arrays, path-rule evaluation, or absence of unreported CLI control-plane side effects. Capability output and init evidence must never be promoted into such proof.

## Guidance And Evidence

The control prompt must require Claude to:

1. read repo-wide tracked guidance;
2. obtain changed-path metadata only;
3. read applicable path-scoped `AGENTS.md`, repo-local domain skills, and tracked project guidance;
4. inspect the exact range incrementally with bounded Git, `Read`, `Grep`, `Glob`, and sandboxed read-only Bash; if a command reports persisted or spilled output outside the worktree, do not read that path and rerun a narrower bounded worktree-scoped command instead;
5. never run `fetch`, `pull`, or another networked Git operation because the parent already proved the frozen scope locally complete;
6. avoid direct reads outside the logical review workspace and every mutation; any direct structured outside-workspace tool read invalidates the lane rather than findings being accepted;
7. return findings only; when clean, optionally emit one concise non-actionable positive/coverage summary, then make the final nonempty logical line exactly `No findings.`. Never emit that sentinel when any finding remains.

Accept only the strict init/result evidence above from the actual Claude process. Extract the terminal result verbatim and bind it to the frozen range in the parent-owned lane record. Record validator classification as `artifact_status`; only after `accepted`, call [`review_result.py`](../scripts/review_runtime/review_result.py) to record `review_outcome` and `presentation`. Exact or outer-ASCII-whitespace-only sentinel is `clean` / `canonical-clean`; one non-actionable positive/coverage prefix plus a unique final exact sentinel is `clean` / `extended-clean`; an actionable prefix overrides the sentinel as `findings` / `contradictory`; uncertainty or conflict with the sentinel is `undetermined` / `ambiguous`; and other accepted text is `undetermined` / `nonconforming`. Quoted, inline, repeated, non-final, or Unicode-separated sentinel text is not canonical clean. This disposition step never substitutes for validator acceptance and never normalizes the raw result. Progress, tool traces, partial JSON, silent model substitution, and helper output do not count.
