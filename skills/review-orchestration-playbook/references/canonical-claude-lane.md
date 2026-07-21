# Canonical Claude Code Lane

Use this contract for the actual Anthropic Claude Code lane in named double and triple review. Do not route this lane through `isolated_review`: that helper materializes a supplied diff with helper-private minimal Git, records `named_lane_eligible=false`, and is diagnostic-only.

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

## Canonical Executable Provenance

The canonical direct lane uses the user's installed actual Claude Code executable at one exact resolved path. Before exposing credentials, review metadata, or repository content, the parent must:

1. resolve the selected executable without later `PATH` lookup and reject a missing, non-regular, non-executable, script/interpreter-wrapper, prerelease, development, unsupported-platform, or future-major candidate;
2. obtain its version using a fixed credential-free environment and require `>=2.1.211,<3.0.0`;
3. verify the fixed Anthropic release-signing key, signed per-version manifest, expected platform artifact, exact size, and SHA-256 of the stable resolved installed file, using `verify_claude_release` or equivalent checks;
4. validate the advertised option/capability surface only after publisher verification; and
5. immediately before launch, revalidate the same path identity, signed artifact size, and SHA-256, launch that exact resolved path directly, then revalidate it again after process completion. Any drift or uncertainty makes the lane inconclusive.

This direct lane does not call `snapshot_verified_claude_executable`, copy the CLI into a helper-owned executable snapshot, or inherit the helper's supplied-diff/private-minimal-Git workspace, explicit-auth precedence, clean/WIP capture, post-run validation, or retained-state contracts. It intentionally trusts the host-installed executable path and ordinary host runtime to remain stable between the parent checks; those checks do not claim the stronger immutability of the helper snapshot. Record only non-secret provenance metadata such as resolved path, version, platform, artifact digest, and verification state.

## Authentication Control Plane

The canonical direct lane uses the ordinary Claude CLI authentication selected by the user: local login in real `HOME`, or an explicitly supplied API key. It does not inherit the low-level helper's `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local-login selection contract, opaque-forwarding record, or retained diagnostic state, and it must not claim those helper-only guarantees. Both runtimes may preserve real `HOME` as the ordinary CLI control plane, but a helper result never becomes this named lane.

Real `HOME` is a trusted control plane. The Claude CLI may read and refresh its own ordinary authentication there; that narrowly scoped CLI authentication side effect is not a model-authorized review mutation and is the only planned host write outside the lane workspace. The model prompt still forbids direct reads of real-`HOME` content, and the native sandbox must deny model-visible credential/configuration roots. Do not inspect, copy, print, or place credential contents in review state.

If organization policy forbids ordinary CLI credential refresh, use an explicitly authorized API key or report the lane blocked; do not silently introduce the helper credential wrapper. A reported `Login expired`, HTTP 401, or refresh failure is `blocked-authentication`: ask Joey to run `claude auth login` on that host and wait for an explicit retry. Ambiguous credential I/O or persistence state is `inconclusive`. Neither condition authorizes provider fallback, and post-run worktree cleanliness does not attest what the trusted authentication control plane changed.

## Native Sandbox Contract

The inline settings request all of the following:

- hooks disabled;
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

## Guidance And Evidence

The control prompt must require Claude to:

1. read repo-wide tracked guidance;
2. obtain changed-path metadata only;
3. read applicable path-scoped `AGENTS.md`, repo-local domain skills, and tracked project guidance;
4. inspect the exact range incrementally with bounded Git, `Read`, `Grep`, `Glob`, and sandboxed read-only Bash;
5. never run `fetch`, `pull`, or another networked Git operation because the parent already proved the frozen scope locally complete;
6. avoid direct reads outside the logical review workspace and every mutation;
7. return findings only, or exactly `No findings.` when clean.

Accept only a complete structured terminal success from the actual Claude process. Verify the requested/effective model when the runtime reports it, extract the findings verbatim, and bind them to the frozen range in the parent-owned lane record. Progress, tool traces, partial JSON, silent model substitution, and helper output do not count.
