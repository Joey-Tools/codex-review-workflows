---
id: 20260719-c63d11
title: Use Real-HOME Read-Only Claude Reviews
status: completed
created: 2026-07-19
updated: 2026-07-19
branch: codex/claude-explicit-auth-sources-pr
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/63
supersedes:
  - 20260703-b4e9d1
  - 20260715-7c1501
  - 20260716-662f2c
  - 20260717-c17a11
superseded_by:
---

# Use Real-HOME Read-Only Claude Reviews

## Summary

- Claude reviews now use one combined runtime: the verified Claude Code control plane receives the current account's real `HOME`, while model tools remain read-only inside a helper-owned detached Git worktree.
- Clean exact-head content is the default. Explicit `--include-source-wip` captures staged, unstaged, and non-ignored untracked files into a scanned, digest-bound review-only artifact.
- Authentication follows `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. The helper opaque-forwards only the winning explicit value without parsing, logging, staging, brokering, or persisting it; Claude Code continues to own ordinary local-login discovery and refresh state.

## Current State

- Each review workspace is a literal detached Git worktree backed by a helper-owned minimal Git database. It does not register in the source common Git directory, touch source refs, or conflict with other worktrees.
- Default preparation rejects dirty source state. WIP capture requires explicit consent, uses the same immutable workspace and runtime boundary, and binds the complete captured content to a recorded digest.
- WIP evidence is suitable for fixed-artifact feedback but not for formal PR-readiness or merge-ready exact-commit gates; those gates require a clean committed head.
- Claude Code `>=2.1.212,<3.0.0` must pass publisher-provenance, public-capability, and structured-output checks. Every accepted review stream proves effective plan mode, the exact `Read`/`Grep`/`Glob`/`Bash` tool set, the requested model, and compatible authentication evidence. The launch requests fail-closed native sandbox settings, but v2.1.212 does not expose effective sandbox or merged managed-permission fields; admin-managed policy remains part of the trusted ordinary CLI control plane.
- The verified control plane may use ordinary Claude Code local login and refresh behavior from real `HOME`. Explicit API-key or OAuth-token values are forwarded only according to precedence and are requested to be removed from model subprocesses. The prompt requires read-only behavior, and an exact post-attempt validation rejects any observable worktree, private-Git, diff, or prompt mutation before accepting a result. This does not claim proof against transient writes or out-of-workspace side effects.
- Sensitive-content and escaping-symlink checks cover the exact selected artifact, including non-ignored untracked files in WIP mode, before any provider egress.

## Next Steps

- None for this workstream.

## Evidence

- PR: https://github.com/Joey-Tools/codex-review-workflows/pull/63
- Runtime and workspace contracts: `skills/review-orchestration-playbook/SKILL.md`, `references/helper-contract.md`, `references/claude-runtime-trust.md`, and `references/egress-consent.md`.
- Contract regressions: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Full local suite: 666 tests passed.
