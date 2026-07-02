---
id: 20260703-b4e9d1
title: Default Claude Reviews To Local Login
status: completed
created: 2026-07-03
updated: 2026-07-03
branch: wip/claude-local-login
pr:
supersedes: []
superseded_by:
---

# Default Claude Reviews To Local Login

## Summary

- Claude-family reviews now use the ordinary local Claude login by default while retaining an optional `ANTHROPIC_API_KEY` override.

## Current State

- Claude Code runs with verified `--safe-mode`, restricted read-only tools, disabled setting sources, an isolated home, a capability-authenticated memory-only parent query plus native broker restricted to Claude's current-account Keychain item, and an Anthropic-only local CONNECT proxy.
- OAuth refresh updates are accepted only through Claude 2.1.187's exact current-account/service stdin Keychain form; the parent validates bounded OAuth JSON and uses a cross-process lock plus compare-and-swap against the launch credential before persisting rotated tokens, while oversized credentials and argv updates fail closed.
- Claude Code 2.1.187 and trusted `rg` must be native Mach-O executables; script or wrapper installations are rejected, the final sandbox reads the Claude executable only by exact path, and the child `PATH` is reduced to the restricted broker plus the verified `rg` directory.
- Custom CA environment paths are reduced to validated certificate-only copies under the helper container before entering the sandbox, with distinct source directories kept separate.
- Uppercase and lowercase corporate proxy variables are preserved before Claude is routed through the helper-owned local proxy, with lowercase task overrides taking precedence over uppercase system defaults.
- Selected upstream proxy URLs and ports are validated before the helper binds its local proxy; malformed, zero, and out-of-range ports fail closed as configuration errors.
- The parent helper honors the original `NO_PROXY` / `no_proxy` list when choosing direct versus corporate-proxy routing for each pinned Anthropic target.
- HTTPS corporate proxy tunnels drain OpenSSL's already-decrypted pending data before waiting on the underlying socket.
- Missing Claude authentication can fall back to GitHub Copilot only for explicitly authorized double or triple reviews.
- A missing or non-native trusted `rg` is treated as Claude runtime unavailability and follows the same authorized Copilot fallback rule.
- Skill policy, egress language, helper contract, and provider tests describe the same behavior.

## Next Steps

- None for this workstream.

## Evidence

- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests`
- Native broker integration: clang compilation, rejected wrong capability without consumption, sandboxed one-shot fixture delivery, second-read denial, exact stdin refresh updates, argv-update denial, and in-memory zeroing passed.
- Real local-auth smoke: sandboxed Claude Code 2.1.187 reported `loggedIn: true`, `authMethod: claude.ai`, and `apiProvider: firstParty` without `ANTHROPIC_API_KEY`.
- macOS sandbox smoke probe: Claude authentication status remained readable, trusted `rg` could search the frozen workspace, and `/bin/sh` hook execution was blocked.
- Local CONNECT proxy smoke probe: `api.anthropic.com:443` and `platform.claude.com:443` succeeded through the localhost-only sandbox route, while `example.com:443` was rejected.
- HTTPS upstream proxy regression: two buffered 64 KiB TLS chunks were forwarded before the tunnel returned to `select()`.
