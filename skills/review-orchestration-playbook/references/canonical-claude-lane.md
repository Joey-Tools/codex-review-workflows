# Canonical Claude Code Lane

Use this contract for the actual Anthropic Claude Code lane in named double and triple review. Do not route this lane through `isolated_review`: that helper materializes a supplied diff in a `.git`-free workspace and is diagnostic-only.

## Workspace And Process

1. Create a lane-unique clean Git working tree at the same frozen `head_sha` used by the Codex lane. Prefer a lane-private local clone or private bare object store plus worktree under the task's temporary root, so required Git metadata does not live under the denied implementation checkout. This is a local Git setup step, not a network clone or prepared-diff materialization. With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, prove that the exact range and both endpoint trees are locally complete without rendering a full diff; hydrate missing objects before freezing or block the lane. Remove remote URLs before model launch. Verify clean status, exact `HEAD`, both commits, and bounded read-only range queries.
2. Start a new actual `claude` process with its working directory set to that worktree. Do not use `--continue`, `--resume`, `--from-pr`, `--fork-session`, or `--worktree`.
3. Preserve the real user `HOME` as Claude's trusted authentication and CLI control plane. The model-visible review scope is the detached working tree plus only its lane-private Git metadata/object paths that read-only Git needs for the frozen refs.
4. Send the small control prompt through stdin. Do not create a prompt or diff file in the worktree, and do not send a prepared diff, changed-file contents, Codex findings, or parent suspicions.

The canonical launch is a direct Claude Code invocation, not a call to any helper reviewer:

```text
claude
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

Validate the installed CLI's advertised option/capability surface before launch. Pass settings inline; do not write them into the review workspace. `--safe-mode` disables automatic customizations and slash-skill loading, not the built-in `Read` tool. The prompt therefore tells Claude to read applicable tracked `AGENTS.md`, repo-local skill documents, and project guidance from the worktree explicitly. It must not read an installed skill or guidance file outside the worktree.

The inline settings must also set `disableBundledSkills: true`. `--safe-mode` alone is not evidence that bundled skills are absent; the explicit setting is required before the init `skills` field can be expected to be empty.

## Canonical Executable Provenance

The canonical direct lane uses the user's installed actual Claude Code executable at one exact resolved path. Before exposing credentials, review metadata, or repository content, the parent must:

1. resolve the selected executable without later `PATH` lookup and reject a missing, non-regular, non-executable, script/interpreter-wrapper, prerelease, development, unsupported-platform, or future-major candidate;
2. obtain its version using a fixed credential-free environment and require exactly Claude Code `2.1.212` for this named direct lane;
3. verify the fixed Anthropic release-signing key, signed per-version manifest, expected platform artifact, exact size, and SHA-256 of the stable resolved installed file, using `verify_claude_release` or equivalent checks;
4. validate the advertised option/capability surface only after publisher verification; and
5. immediately before launch, revalidate the same path identity, signed artifact size, and SHA-256, launch that exact resolved path directly, then revalidate it again after process completion. Any drift or uncertainty makes the lane inconclusive.

This direct lane does not call `snapshot_verified_claude_executable`, copy the CLI into a helper-owned executable snapshot, or inherit the helper's dependency-closure, outer-sandbox, credential-carrier, catalog, guarded-writeback, or recovery contracts. It intentionally trusts the host-installed executable path and ordinary host runtime to remain stable between the parent checks; those checks do not claim the stronger immutability of the helper snapshot. The broader publisher-verified `>=2.1.211,<3.0.0` range in `claude-runtime-trust.md` belongs to the low-level helper and does not make another CLI version eligible for this named direct lane. Record only non-secret provenance metadata such as resolved path, version, platform, artifact digest, and verification state.

## Authentication Control Plane

The canonical direct lane uses the ordinary Claude CLI authentication selected by the user: local login in real `HOME`, or an explicitly supplied API key. It does not use the low-level helper's credential broker, staged carrier, credential-lock catalog, guarded writeback, or recovery journal, and it must not claim those helper-only guarantees.

Real `HOME` is a trusted control plane. The publisher-verified Claude CLI may update ordinary CLI-owned authentication and runtime state there, including credential refresh and possible cache or tool-result artifacts. These are accepted CLI control-plane side effects, not model-authorized review mutations; they do not authorize model/tool writes or deliberate host mutations. This contract does not enumerate or attest every CLI-owned `HOME` write. The model prompt still forbids direct reads of real-`HOME` content, and the native sandbox must deny model-visible credential/configuration roots. Do not inspect, copy, print, or place credential contents in review state.

If organization policy forbids ordinary CLI control-plane writes, use an explicitly authorized API key only when that mode satisfies the same policy, or report the lane blocked; do not silently introduce the helper credential wrapper. A reported `Login expired`, HTTP 401, or refresh failure is `blocked-authentication`: ask Joey to run `claude auth login` on that host and wait for an explicit retry. Ambiguous credential I/O or persistence state is `inconclusive`. Neither condition authorizes provider fallback. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable. The lane does not take or verify a complete real-`HOME` diff, so cache or tool-result artifacts may retain review-derived data according to upstream CLI behavior. Post-run worktree cleanliness does not attest what the trusted control plane changed or prove that no transient control-plane write occurred.

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

Claude Code 2.1.212 `system/init` or capability output cannot attest the final merged sandbox, managed permission arrays, or path-rule evaluation. Record the settings as requested configuration. Do not promote init output into independent proof of effective enforcement, and do not restore the retired complex outer global-read-isolation design.

If the required native sandbox, global write deny, sensitive-root denies, tool restrictions, actual Claude executable, or structured-output verification cannot be established, report the lane as `blocked` or `inconclusive` under the failure contract. Never weaken the boundary or substitute Copilot.

## Structured Init And Terminal Evidence

Parse `stream-json` as bounded strict UTF-8 JSONL. Every nonblank line must be one JSON object; reject duplicate keys, nonstandard constants, undecodable text, or non-JSON output. The first nonblank record must be the sole event with `type: system` and `subtype: init`; the last nonblank record must be the sole event with `type: result`. A missing, duplicate, malformed, out-of-order, or trailing contract event makes the lane `inconclusive`; partial findings do not count. A structurally valid terminal event that fails the success acceptance schema is passed to the failure classifier below rather than being classified by this envelope rule.

Before accepting the result, compare the leading init against a reviewed, version-specific expected-init contract for the publisher-verified installed CLI. For Claude Code 2.1.212, require all of these observable fields:

- `cwd` equals the resolved lane-unique clean worktree exactly;
- `permissionMode` equals `dontAsk`;
- `tools` is a duplicate-free set exactly equal to `Read`, `Grep`, `Glob`, and `Bash`;
- `mcp_servers`, `slash_commands`, `skills`, and `plugins` are present and exactly empty arrays;
- `model` equals the requested concrete model string exactly, without alias normalization or silent substitution;
- `claude_code_version` equals the publisher-verified preflight version; and
- `apiKeySource` is a string that exactly matches the parent-selected and preflight-verified authentication source: `ANTHROPIC_API_KEY` for explicit API-key mode and `none` for ordinary local login in Claude Code 2.1.212.

Missing, malformed, or conflicting required fields fail closed as `inconclusive` and cannot count as the Claude lane. A well-formed required field that mismatches the frozen launch is a deterministic `blocked` configuration/policy mismatch. A CLI version other than exact `2.1.212` is blocked before review input is exposed; adding another version requires its own reviewed init and terminal schema. Additive metadata may be recorded only when it does not alter a required field or widen the observable runtime surface.

For the Claude Code 2.1.212 terminal `result`, require this exact acceptance schema:

- `type` is the string `result`, `subtype` is the string `success`, and `is_error` is the boolean `false`;
- `result` is a required string whose `strip()` value is nonempty; preserve the original string verbatim as the findings payload;
- `modelUsage` is a required nonempty object; every key is a nonempty model-ID string and every value is an object. For Claude Code 2.1.212, the only reviewed terminal aliases for requested `claude-opus-4-8` are `claude-opus-4-8` and `claude-opus-4.8`; the only aliases for requested fallback `claude-opus-4-7` are `claude-opus-4-7` and `claude-opus-4.7`. At least one key must belong to the exact requested model's set. The only reviewed auxiliary key is `claude-haiku-4-5-20251001`. A key from the other supported primary-model set is a deterministic blocked model substitution even when a requested-model key is also present; any other model-usage key is `inconclusive` until a reviewed schema update permits it. Thus a `claude-opus-4-8` request with only or with both a `claude-opus-4-7` key is never accepted;
- `duration_ms` and `duration_api_ms`, when present, are nonnegative integers; `num_turns` is a positive integer; `total_cost_usd` is a nonnegative finite number; `session_id` and `uuid` are nonempty strings; and `usage` is an object. A missing optional metric is acceptable, but a present value with the wrong type or range is `inconclusive`;
- `stop_reason`, when present, is exactly `null` or `end_turn`. Any other value—including `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, or `refusal`—is a deterministic blocked incomplete or abnormal terminal result and cannot supply findings;
- `structured_output`, when present, is exactly `null` because the canonical launch does not request a structured-output schema. A non-null value is contradictory evidence and makes the lane `inconclusive`;
- `error` and `errors`, when present, are explicitly empty: `null`, a whitespace-only string, an empty array, or an empty object;
- `api_error_status`, when present, is `null` or a whitespace-only string; and
- `permission_denials`, when present, is an empty array.

A non-success subtype, `is_error: true`, blank/non-string `result`, missing or malformed `modelUsage`, no requested-model match, unaccepted `stop_reason`, non-null `structured_output`, nonempty `error`/`errors`, nonempty `api_error_status`, or nonempty/malformed `permission_denials` fails closed and cannot supply findings. Classify a structurally valid permission denial, output truncation/abnormal stop, exact-model mismatch, or configuration/policy mismatch as `blocked`. Classify a structurally valid recognized login-expired, HTTP 401, or authentication-refresh error as `blocked-authentication`. Malformed, contradictory, mixed-category, or otherwise untrustworthy terminal evidence is `inconclusive`.

The machine-readable Claude Code 2.1.212 contract is [claude-2.1.212-stream-schema.json](claude-2.1.212-stream-schema.json). Its required and optional terminal-field lists form a closed top-level allowlist. Any other terminal field, including an unknown error-bearing field, makes the lane `inconclusive` until a reviewed schema update explicitly adds it. Do not infer a model alias or harmless metadata field from punctuation, provider convention, or a later CLI version.

This evidence verifies only what the CLI reports about that invocation. It does not prove the final merged native sandbox, merged admin-managed permission arrays, path-rule evaluation, or absence of unreported CLI control-plane side effects. Capability output and init evidence must never be promoted into such proof.

## Guidance And Evidence

The control prompt must require Claude to:

1. read repo-wide tracked guidance;
2. obtain changed-path metadata only;
3. read applicable path-scoped `AGENTS.md`, repo-local domain skills, and tracked project guidance;
4. inspect the exact range incrementally with bounded Git, `Read`, `Grep`, `Glob`, and sandboxed read-only Bash;
5. never run `fetch`, `pull`, or another networked Git operation because the parent already proved the frozen scope locally complete;
6. avoid direct reads outside the logical review workspace and every mutation;
7. return findings only, or exactly `No findings.` when clean.

Accept only the strict init/result evidence above from the actual Claude process. Extract the terminal findings verbatim and bind them to the frozen range in the parent-owned lane record. Progress, tool traces, partial JSON, silent model substitution, and helper output do not count.
