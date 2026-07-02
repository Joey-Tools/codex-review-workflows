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
- Claude Code and trusted `rg` must be native Mach-O executables; script or wrapper installations are rejected, and the final sandbox reads the Claude executable only by exact path rather than exposing its parent directory.
- Custom CA environment paths are reduced to validated certificate-only copies under the helper container before entering the sandbox, with distinct source directories kept separate.
- Uppercase and lowercase corporate proxy variables are preserved before Claude is routed through the helper-owned local proxy.
- HTTPS corporate proxy tunnels drain OpenSSL's already-decrypted pending data before waiting on the underlying socket.
- Missing Claude authentication can fall back to GitHub Copilot only for explicitly authorized double or triple reviews.
- Skill policy, egress language, helper contract, and provider tests describe the same behavior.

## Next Steps

- None for this workstream.

## Evidence

- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests`
- Native broker integration: clang compilation, rejected wrong capability without consumption, sandboxed one-shot fixture delivery, second-read denial, and in-memory zeroing passed.
- Real local-auth smoke: sandboxed Claude Code 2.1.187 reported `loggedIn: true`, `authMethod: claude.ai`, and `apiProvider: firstParty` without `ANTHROPIC_API_KEY`.
- macOS sandbox smoke probe: Claude authentication status remained readable, trusted `rg` could search the frozen workspace, and `/bin/sh` hook execution was blocked.
- Local CONNECT proxy smoke probe: `api.anthropic.com:443` and `platform.claude.com:443` succeeded through the localhost-only sandbox route, while `example.com:443` was rejected.
- HTTPS upstream proxy regression: two buffered 64 KiB TLS chunks were forwarded before the tunnel returned to `select()`.
