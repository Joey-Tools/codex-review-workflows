# Canonical Claude Code Lane

Use this contract for the actual Anthropic Claude Code lane in named double and triple review. Do not route this lane through `isolated_review`: that helper materializes a supplied diff in a `.git`-free workspace and is diagnostic-only.

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

The canonical direct lane uses the ordinary Claude CLI authentication selected by the user: local login in real `HOME`, or an explicitly supplied API key. It does not use the low-level helper's credential broker, staged carrier, credential-lock catalog, guarded writeback, or recovery journal, and it must not claim those helper-only guarantees.

Real `HOME` is a trusted control plane. The publisher-verified Claude CLI may update ordinary CLI-owned authentication and runtime state there, including credential refresh and possible cache or tool-result artifacts. These are accepted CLI control-plane side effects, not model-authorized review mutations; they do not authorize model/tool writes or deliberate host mutations. This contract does not enumerate or attest every CLI-owned `HOME` write. The model prompt still forbids direct reads of real-`HOME` content, and the native sandbox must deny model-visible credential/configuration roots. Do not inspect, copy, print, or place credential contents in review state.

If organization policy forbids ordinary CLI control-plane writes, use an explicitly authorized API key only when that mode satisfies the same policy, or report the lane blocked; do not silently introduce the helper credential wrapper. A reported `Login expired`, an explicit HTTP/status 401, an explicit OAuth/credential/login/authentication/token refresh failure, or a directly adjacent authentication state of expired, invalid, or unauthorized is `blocked-authentication`: ask Joey to run `claude auth login` on that host and wait for an explicit retry. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit failures are not authentication evidence and remain `inconclusive`; an authentication word separated from `error`/`failure` by one of those resource terms does not change that result. A bare child exit code 401, credential-file or other ambiguous credential I/O, a generic non-authentication refresh failure, or uncertain persistence state is also `inconclusive`. Neither condition authorizes provider fallback. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable. The lane does not take or verify a complete real-`HOME` diff, so cache or tool-result artifacts may retain review-derived data according to upstream CLI behavior. Post-run worktree cleanliness does not attest what the trusted control plane changed or prove that no transient control-plane write occurred.

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
  --api-key-source <none-or-ANTHROPIC_API_KEY>
  --process-returncode <exact-child-returncode>
  --input <bounded-raw-stream-jsonl>
```

The preflight evidence path must be absolute and must resolve outside the reviewer worktree to a descriptor-stable, single-link regular file owned by the current user, with no group or world permission bits and a maximum size of 16 KiB. The validator parses it as strict JSON, requires exact accepted selection/publisher/identity/capability fields, and binds the selected version plus current compatibility-profile, audited-baseline, and capability-contract source digests before parsing review output. Symlinked, hard-linked, workspace-local, special-file, missing, stale, permissive, malformed, or mismatched evidence is `inconclusive` and cannot supply findings.

The executable/importable validator applies the compatible machine contract and
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

The current [`claude-stream-compatibility.json`](claude-stream-compatibility.json) profile uses `strict-structural-baseline` mode. [`claude-2.1.212-stream-schema.json`](claude-2.1.212-stream-schema.json) is the audited per-version baseline; it is not a global eligibility pin. For every in-range selected release, the profile adapts the baseline `claude_code_version` constant to the exact accepted preflight-selected version. It may also define exact-version additive metadata contracts that cannot override a baseline field. The reviewed `2.1.216` adaptation is scoped only to an exact selected `2.1.216`; later patches do not inherit it. All other listed init, terminal, envelope, and model-identity surfaces remain closed. An in-range future patch is therefore not rejected because of its patch number, but it is accepted only when its observed structure remains compatible with the closed baseline plus any exact-version adaptation. Unknown or incompatible structure fails closed until a reviewed compatibility-profile or versioned-schema update permits it. This compatibility result does not claim that every admitted patch received an independent per-version audit.

Before accepting the result, compare the leading init against that preflight-bound compatibility contract. Require all of these observable fields:

- `cwd` equals the resolved lane-unique clean worktree exactly;
- `permissionMode` equals `dontAsk`;
- `tools` is a duplicate-free set exactly equal to `Read`, `Grep`, `Glob`, and `Bash`;
- `mcp_servers`, `slash_commands`, `skills`, and `plugins` are present and exactly empty arrays;
- `model` equals the requested concrete model string exactly, without alias normalization or silent substitution;
- `claude_code_version` equals the publisher-verified preflight version; and
- `apiKeySource` is a string that exactly matches the parent-selected and preflight-verified authentication source: `ANTHROPIC_API_KEY` for explicit API-key mode and `none` for ordinary local login.

Missing, malformed, or conflicting required fields fail closed as `inconclusive` and cannot count as the Claude lane. A well-formed required field that mismatches the frozen launch is a deterministic `blocked` configuration/policy mismatch. The baseline init top-level field set is closed: only the required fields above plus an optional nonempty string `session_id` are accepted. Exact selected `2.1.216` additionally permits the profile's reviewed optional metadata fields: exact duplicate-free `agents` and `capabilities` sets, boolean analytics/feedback flags, null token estimates, `fast_mode_state: off`, `output_style: default`, and a nonempty `uuid`. Malformed metadata is `inconclusive`; a well-formed but unreviewed set or constant is `blocked`. The adaptation does not permit `hooks` or any other field, and the same fields remain unknown for every other selected version. These observable init fields still do not prove the final merged sandbox, managed permission arrays, or path-rule evaluation.

For the terminal `result`, require the audited baseline's exact acceptance structure:

- `type` is the string `result`, `subtype` is the string `success`, and `is_error` is the boolean `false`;
- `result` is a required string whose `strip()` value is nonempty; preserve the original string verbatim as the findings payload. The validator returns it unchanged and does not apply clean-sentinel or presentation policy;
- `modelUsage` is a required nonempty object; every key is a nonempty model-ID string and every value is an object. Under the current compatibility profile, the baseline-reviewed aliases for requested `claude-opus-4-8` are `claude-opus-4-8` and `claude-opus-4.8`; the aliases for requested fallback `claude-opus-4-7` are `claude-opus-4-7` and `claude-opus-4.7`. At least one key must belong to the exact requested model's set. The only baseline-reviewed auxiliary key is `claude-haiku-4-5-20251001`. A key from the other supported primary-model set is a deterministic blocked model substitution even when a requested-model key is also present; any other model-usage key is `inconclusive` until a reviewed compatibility-profile or versioned-schema update permits it. Thus a `claude-opus-4-8` request with only or with both a `claude-opus-4-7` key is never accepted;
- `duration_ms` and `duration_api_ms`, when present, are nonnegative integers; `num_turns` is a positive integer; `total_cost_usd` is a nonnegative finite exact-decimal number within the stream parser's lexical and exponent bounds; `session_id` and `uuid` are nonempty strings; and `usage` is an object. When both init and terminal events report `session_id`, the values must match exactly or the stream is `inconclusive`. A missing optional metric is acceptable, but a present value with the wrong type or range is `inconclusive`;
- `stop_reason`, when present, is exactly `null` or `end_turn`. Any other value—including `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, or `refusal`—is a deterministic blocked incomplete or abnormal terminal result and cannot supply findings;
- `structured_output`, when present, is exactly `null` because the canonical launch does not request a structured-output schema. A non-null value is contradictory evidence and makes the lane `inconclusive`;
- `error` and `errors`, when present, are explicitly empty: `null`, a whitespace-only string, an empty array, or an empty object;
- `api_error_status`, when present, is `null` or a whitespace-only string; and
- `permission_denials`, when present, is an empty array.

For exact selected `2.1.216`, the terminal allowlist also permits the reviewed optional metadata `fast_mode_state: off`, `terminal_reason: completed`, and nonnegative finite `time_to_request_ms`, `ttft_ms`, and `ttft_stream_ms` values. Malformed metrics are `inconclusive`; well-formed unreviewed constants are `blocked`. No other selected version inherits these fields.

A non-success subtype, `is_error: true`, blank/non-string `result`, missing or malformed `modelUsage`, no requested-model match, unaccepted `stop_reason`, non-null `structured_output`, nonempty `error`/`errors`, nonempty `api_error_status`, or nonempty/malformed `permission_denials` fails closed and cannot supply findings. Classify a structurally valid permission denial, output truncation/abnormal stop, exact-model mismatch, or configuration/policy mismatch as `blocked`. When a non-success terminal follows any deterministic init or terminal blocker, absence of error prose preserves `blocked` and does not add a generic unclassified reason. Classify only a structurally valid recognized `Login expired`, explicit HTTP/status 401, explicit OAuth/credential/login/authentication/token refresh error, or directly adjacent expired/invalid/unauthorized authentication state as `blocked-authentication`. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit errors, credential-file/I/O errors, a bare child exit code 401, non-authentication refresh failure, malformed evidence, contradictory evidence, or mixed-category evidence are `inconclusive`.

The only non-authentication error prose that authorizes the pinned-model fallback is a strict recognized model-entitlement or organization-policy denial, including exact account/plan model-access denials and reviewed structured model-entitlement codes. The validator emits `classification: blocked` with machine reason `terminal.model-entitlement-denial` or `terminal.organization-policy-denial`; a parent may advance from `claude-opus-4-8` to `claude-opus-4-7` only when every classified message belongs to those two categories. Mixed, extended, authentication, resource/quota/capacity/rate-limit, unclassified, or ambiguous evidence is `inconclusive`, and prose inspection outside the validator never authorizes fallback. Post-acceptance result disposition is separate: prose inspection may choose only `summary-only`, `actionable-findings`, or `undetermined` for `classify_review_result`, after artifact acceptance has already succeeded.

The machine-readable compatibility profile is [claude-stream-compatibility.json](claude-stream-compatibility.json), bound to the audited [Claude Code 2.1.212 baseline](claude-2.1.212-stream-schema.json). Their baseline lists plus any exact-version additive metadata contracts form closed top-level allowlists. Adaptations are selected only by the exact publisher-verified preflight version, cannot override baseline fields, and are included in the preflight-bound profile digest. Any other init or terminal field, including an unknown error-bearing field, makes the lane `inconclusive` until a reviewed compatibility-profile or versioned-schema update explicitly adds it. Do not infer a model alias or harmless metadata field from punctuation, provider convention, or a later CLI version. The fail-closed compatibility guarantee covers the stream envelope, leading init, terminal variants/fields, and model identity; it does not validate every intermediate event's internal shape or prove absence of unreported runtime effects.

This evidence verifies only what the CLI reports about that invocation. It does not prove the final merged native sandbox, merged admin-managed permission arrays, path-rule evaluation, or absence of unreported CLI control-plane side effects. Capability output and init evidence must never be promoted into such proof.

## Guidance And Evidence

The control prompt must require Claude to:

1. read repo-wide tracked guidance;
2. obtain changed-path metadata only;
3. read applicable path-scoped `AGENTS.md`, repo-local domain skills, and tracked project guidance;
4. inspect the exact range incrementally with bounded Git, `Read`, `Grep`, `Glob`, and sandboxed read-only Bash;
5. never run `fetch`, `pull`, or another networked Git operation because the parent already proved the frozen scope locally complete;
6. avoid direct reads outside the logical review workspace and every mutation;
7. return findings only; when clean, optionally emit one concise non-actionable positive/coverage summary, then make the final nonempty logical line exactly `No findings.`. Never emit that sentinel when any finding remains.

Accept only the strict init/result evidence above from the actual Claude process. Extract the terminal result verbatim and bind it to the frozen range in the parent-owned lane record. Record validator classification as `artifact_status`; only after `accepted`, call [`review_result.py`](../scripts/review_runtime/review_result.py) to record `review_outcome` and `presentation`. Exact or outer-ASCII-whitespace-only sentinel is `clean` / `canonical-clean`; one non-actionable positive/coverage prefix plus a unique final exact sentinel is `clean` / `extended-clean`; an actionable prefix overrides the sentinel as `findings` / `contradictory`; uncertainty or conflict with the sentinel is `undetermined` / `ambiguous`; and other accepted text is `undetermined` / `nonconforming`. Quoted, inline, repeated, non-final, or Unicode-separated sentinel text is not canonical clean. This disposition step never substitutes for validator acceptance and never normalizes the raw result. Progress, tool traces, partial JSON, silent model substitution, and helper output do not count.
