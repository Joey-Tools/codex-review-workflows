---
id: 20260703-b4e9d1
title: Default Claude Reviews To Local Login
status: completed
created: 2026-07-03
updated: 2026-07-03
branch: wip/claude-local-login
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/42
supersedes: []
superseded_by:
---

# Default Claude Reviews To Local Login

## Summary

- Claude-family reviews now use the ordinary local Claude login by default while retaining an optional `ANTHROPIC_API_KEY` override.

## Current State

- Claude Code runs with verified `--safe-mode`, restricted read-only tools, disabled setting sources, an isolated home, a capability-authenticated memory-only parent query plus native broker restricted to Claude's current-account Keychain item, and an Anthropic-only local CONNECT proxy.
- A stale access token is refreshed only by a separate fixed-input, no-tools Claude 2.1.187 safe-mode warmup using ordinary Keychain behavior; the final review revalidates that the refreshed token covers the complete two-model timeout chain, serves it once per attempt through a read-only broker, blocks OAuth refresh egress, and rejects every Keychain update command.
- Claude Code 2.1.187 and trusted `rg` must be native Mach-O executables; script or wrapper installations are rejected, the final sandbox reads the Claude executable only by exact path, and the child `PATH` is reduced to the restricted broker plus the verified `rg` directory.
- Custom CA environment paths are reduced to validated certificate-only copies under the helper container before entering the sandbox, with distinct source directories kept separate.
- Uppercase and lowercase corporate proxy variables are preserved before Claude is routed through the helper-owned local proxy, with lowercase task overrides taking precedence over uppercase system defaults.
- Selected upstream proxy URLs and ports are validated before the helper binds its local proxy; malformed, zero, and out-of-range ports fail closed as configuration errors.
- The parent helper honors the original `NO_PROXY` / `no_proxy` list when choosing direct versus corporate-proxy routing for each pinned Anthropic target.
- HTTPS corporate proxy tunnels drain OpenSSL's already-decrypted pending data before waiting on the underlying socket.
- Missing Claude authentication can fall back to GitHub Copilot only for explicitly authorized double or triple reviews.
- A transient or unclassified authentication-warmup failure is inconclusive and cannot trigger Copilot fallback; only a classified authentication failure is treated as unavailable local login.
- A missing/non-native trusted `rg` or automatically discovered non-native Claude candidate is treated as Claude runtime unavailability and follows the authorized Copilot fallback rule; an invalid explicit Claude path remains a configuration error.
- Trusted `rg` discovery skips invalid or non-native candidates and continues to the next pinned path.
- Loopback bind failures for the Keychain broker or Anthropic CONNECT proxy are converted to structured Claude runtime unavailability; the final sandbox no longer reads host Spotlight databases.
- OAuth credential buffers are zeroed on every broker exit path, including loopback bind and broker-thread startup failures; an already-bound broker socket is closed if its serving thread cannot start.
- An already-bound Anthropic CONNECT proxy socket is likewise closed if its serving thread cannot start, and the failure remains eligible for authorized runtime-unavailable fallback.
- Missing or failing local broker toolchains are consistently classified as Claude runtime unavailability for explicitly authorized fallback.
- Keychain stdout/stderr are captured into separately bounded in-memory buffers and zeroed after use; custom CA directories are enumerated only up to the global entry limit before sorting or inspecting entries.
- Skill policy, egress language, helper contract, and provider tests describe the same behavior.

## Next Steps

- None for this workstream.

## Evidence

- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests`
- Native broker integration: clang compilation, rejected wrong capability without consumption, sandboxed one-shot fixture delivery, second-read denial, stdin/direct update denial, and in-memory zeroing passed.
- Real local-auth smoke: the fixed no-tools warmup refreshed an expired credential through ordinary Claude behavior; the final read-only sandbox reported `loggedIn: true`, `authMethod: claude.ai`, `apiProvider: firstParty`, and about 478 remaining token minutes without `ANTHROPIC_API_KEY`.
- Real bounded Keychain smoke: the local Claude credential was read through separate stdout/stderr streaming limits, validated for the complete two-model review chain, and zeroed without printing or persisting credential contents.
- macOS sandbox smoke probe: Claude authentication status remained readable, trusted `rg` could search the frozen workspace, and `/bin/sh` hook execution was blocked.
- Local CONNECT proxy smoke probe: the warmup route permits `api.anthropic.com:443` plus `platform.claude.com:443`, while the final review permits only the API target and rejects OAuth refresh plus unrelated hosts.
- HTTPS upstream proxy regression: two buffered 64 KiB TLS chunks were forwarded before the tunnel returned to `select()`.
