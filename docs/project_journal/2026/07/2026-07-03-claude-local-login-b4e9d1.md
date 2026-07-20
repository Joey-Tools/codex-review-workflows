---
id: 20260703-b4e9d1
title: Default Claude Reviews To Local Login
status: completed
created: 2026-07-03
updated: 2026-07-17
branch: codex/claude-local-login
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/42
supersedes: []
superseded_by: 20260717-c17a11
---

# Default Claude Reviews To Local Login

## Summary

- Claude-family reviews now use the ordinary local Claude login by default while retaining an optional `ANTHROPIC_API_KEY` override.

## Current State

- Claude Code runs with verified `--safe-mode`, restricted read-only tools, disabled setting sources, an isolated home, a capability-authenticated memory-only parent query plus native broker restricted to Claude's current-account Keychain item, and an Anthropic-only local CONNECT proxy.
- Before every model attempt, a stale access token is refreshed only when it cannot cover that attempt's 30-minute timeout plus the 2-minute safety margin. The fixed-input, no-tools safe-mode warmup uses the current attempt's model and the publisher-verified executable snapshot without workspace access, then the helper re-reads and validates the Keychain item. The final read-only broker performs another single-attempt validation, serves the credential once, blocks OAuth refresh egress, and rejects every Keychain update command. Later Opus attempts repeat the same refresh-if-needed sequence.
- The authentication warmup cannot read the frozen review workspace even while its narrowly pinned API and OAuth refresh egress is enabled.
- Claude Code releases `>=2.1.187,<3.0.0` and trusted `rg` must be native Mach-O executables; script or wrapper installations are rejected, the final sandbox reads the verified executable snapshot only by exact path, and the child `PATH` is reduced to the restricted broker plus the verified `rg` directory.
- Before any Claude process can access the warmup Keychain path, the fixed Anthropic GPG fingerprint must verify the release's signed manifest and that manifest's SHA-256 must match the selected arm64 or x64 artifact.
- Custom CA environment paths are reduced to validated certificate-only copies under the helper container before entering the sandbox, with distinct source directories kept separate.
- Uppercase and lowercase corporate proxy variables are preserved before Claude is routed through the helper-owned local proxy, with lowercase task overrides taking precedence over uppercase system defaults.
- Selected upstream proxy URLs and ports are validated before the helper binds its local proxy; malformed, zero, and out-of-range ports fail closed as configuration errors.
- The parent helper honors the original `NO_PROXY` / `no_proxy` list when choosing direct versus corporate-proxy routing for each pinned Anthropic target.
- HTTPS corporate proxy tunnels drain OpenSSL's already-decrypted pending data before waiting on the underlying socket.
- HTTPS corporate proxy validation honors a copied `GIT_SSL_CAINFO` bundle when it is the configured trust source.
- Historical helper-only behavior allowed a supplemental GitHub Copilot attempt only under separate explicit Copilot consent. It never satisfied a named double or triple review; current named shapes require actual Claude Code and are defined by `20260720-7f2001`.
- A transient or unclassified authentication-warmup failure is inconclusive and cannot trigger Copilot fallback; only a classified authentication failure is treated as unavailable local login.
- A missing/non-native trusted `rg` or automatically discovered non-native Claude candidate is treated as Claude runtime unavailability and follows the authorized Copilot fallback rule; an invalid explicit Claude path remains a configuration error.
- Trusted `rg` discovery skips invalid or non-native candidates and continues to the next pinned path.
- Executable inspection or hashing races are inconclusive and cannot authorize Copilot fallback; a trusted `rg` that disappears after preflight remains classified as secure-runtime unavailability.
- Loopback bind failures for the Keychain broker or Anthropic CONNECT proxy are converted to structured Claude runtime unavailability; the final sandbox no longer reads host Spotlight databases.
- OAuth credential buffers are zeroed on every broker exit path, including loopback bind and broker-thread startup failures; an already-bound broker socket is closed if its serving thread cannot start.
- An already-bound Anthropic CONNECT proxy socket is likewise closed if its serving thread cannot start, and the failure remains eligible for authorized runtime-unavailable fallback.
- Missing or failing local broker toolchains are consistently classified as Claude runtime unavailability for explicitly authorized fallback.
- Keychain stdout/stderr are captured into separately bounded in-memory buffers and zeroed after use; custom CA directories are enumerated only up to the global entry limit before sorting or inspecting entries.
- The credential broker transfers its one-shot mutable buffer without creating an immutable credential copy, zeroes it after sending, and waits for request handlers before teardown.
- The Claude sandbox grants literal access to the public system CA bundle instead of the complete `/private/etc/ssl` subtree; validated helper-owned custom CA copies remain supported.
- `CLAUDE_CODE_TMPDIR` is pinned to the helper-owned `TMPDIR`, so Claude does not require access to the host-global `/tmp/claude-$UID` tree.
- Logged reviewer commands allow a 0.5-second natural process-group shutdown window before treating descendants as leaks; Linux zombie-only groups are ignored, while persistent live descendants are still terminated and rejected.
- Provider tests use helper-owned executable fixtures for macOS-only Keychain and trusted-tool prerequisites, so the canonical Ubuntu CI exercises policy behavior without depending on host binaries.
- Skill policy, egress language, helper contract, and provider tests describe the same behavior.

## Next Steps

- None for this workstream.

## Evidence

- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests` (`298` tests passed; `2` loopback-dependent tests skipped in the restricted local sandbox)
- Native broker integration: clang compilation, rejected wrong capability without consumption, sandboxed one-shot fixture delivery, second-read denial, stdin/direct update denial, and in-memory zeroing passed.
- Real local-auth smoke: the fixed no-tools warmup refreshed an expired credential through ordinary Claude behavior; the final read-only sandbox reported `loggedIn: true`, `authMethod: claude.ai`, `apiProvider: firstParty`, and about 478 remaining token minutes without `ANTHROPIC_API_KEY`.
- Historical bounded Keychain smoke: the local Claude credential was read through separate stdout/stderr streaming limits, exercised the aggregate-lifetime gate that existed when PR #42 landed, and was zeroed without printing or persisting credential contents. The 2026-07-16 per-model-attempt workstream replaces only that freshness rule and preserves the zeroing evidence.
- Final exact-CA runtime smoke no longer hit global-temp, permission-mode, TLS-file, or sandbox-denial failures; its network-auth terminal check was inconclusive because the host's ordinary `claude auth status --json` had changed to `loggedIn: false`.
- macOS sandbox smoke probe: Claude authentication status remained readable, trusted `rg` could search the frozen workspace, and `/bin/sh` hook execution was blocked.
- Local CONNECT proxy smoke probe: the warmup route permits `api.anthropic.com:443` plus `platform.claude.com:443`, while the final review permits only the API target and rejects OAuth refresh plus unrelated hosts.
- HTTPS upstream proxy regression: two buffered 64 KiB TLS chunks were forwarded before the tunnel returned to `select()`.
