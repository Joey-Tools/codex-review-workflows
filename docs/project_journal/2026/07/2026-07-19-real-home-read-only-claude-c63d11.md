---
id: 20260719-c63d11
title: Use Real-HOME Read-Only Claude Reviews
status: completed
created: 2026-07-19
updated: 2026-07-20
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
- The detached workspace, private Git database, logs, and state now live outside the source checkout under the fixed canonical system temporary root `/tmp`. The root must be a root-owned exact-`01777` real directory; current-user-owned exact-`0700` effective-UID and canonical-source-path-digest namespaces contain each private run.
- Source `.codex-tmp` content receives no helper status filter: ordinary Git ignore/status rules apply, any reported entry makes clean mode dirty, and WIP capture treats the path as reserved. Retained `/tmp` state is not durable across reboot or host temporary-file cleanup.
- On WSL2, `/proc/self/mountinfo` must prove both the source checkout and external review container use supported local native Linux filesystems; Windows-backed provenance is blocked and unproven provenance is inconclusive.
- Only Claude Code `2.1.212` is eligible after publisher-provenance, public-capability, and structured-output checks; other releases fail closed until the behavioral contract is revalidated and deliberately advanced. Every accepted review stream proves effective `dontAsk` mode, the exact `Read`/`Grep`/`Glob`/`Bash` tool set, the requested model, and compatible authentication evidence. `Read(./**)` authorizes detached-workspace file access and unmatched requests are denied; deny-first rules protect real-HOME secrets plus `/proc` and `/dev`. The Bash sandbox denies reads across the original source checkout, whole per-UID review namespace, real HOME, `/proc`, and `/dev`, then re-opens only the current detached workspace and private Git view; it also removes authentication variables and denies writes. The launch requests fail-closed native sandbox settings, but v2.1.212 does not expose effective sandbox or merged managed-permission fields; admin-managed policy remains part of the trusted ordinary CLI control plane.
- The verified control plane may use ordinary Claude Code local login and refresh behavior from real `HOME`. Explicit API-key or OAuth-token values are forwarded only according to precedence and are requested to be removed from sandboxed Bash commands. Valid `auth status --json` evidence is parsed before return-code classification, so Claude Code's nonzero `loggedIn: false` result becomes `blocked-authentication` with the carrier-specific recovery action. The model-backed launch disables Claude Code's broad subprocess scrub because v2.1.212 otherwise forces effective permission mode to `default`; credential-free probes retain it. Hooks, MCP, plugins, skills, and slash commands are separately disabled and checked. The prompt requires read-only behavior, and an exact post-attempt validation rejects any observable worktree, private-Git, diff, or prompt mutation before accepting a result. This does not claim proof against transient writes or out-of-workspace side effects, including ordinary real-HOME control-plane caches or tool-result artifacts.
- Sensitive-content and escaping-symlink checks cover the exact selected artifact, including non-ignored untracked files in WIP mode, before any provider egress.
- Claude Code 2.1.212 creates an empty `.claude/.cc-writes` directory when its native Bash sandbox first runs. The provider records exact pre-launch absence plus any existing real `.claude` parent's filesystem identity, then uses no-follow directory descriptors to verify current-user ownership, `0700` mode, empty contents, and stable parent/child identity before non-recursively removing only a staging directory newly created by that attempt. A new empty parent is atomically moved into helper-private quarantine and identity-checked before removal; a swapped candidate is retained there and rejected rather than restored through a replace-capable rename. Pre-existing WIP entries are not cleaned, disappeared or replaced parents are rejected, and the unchanged exact workspace validator still decides every remaining shape.

## Next Steps

- None for this workstream.

## Evidence

- PR: https://github.com/Joey-Tools/codex-review-workflows/pull/63
- Runtime and workspace contracts: `skills/review-orchestration-playbook/SKILL.md`, `references/helper-contract.md`, `references/claude-runtime-trust.md`, and `references/egress-consent.md`.
- Contract regressions: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Focused contract suite: `python3 -m unittest skills/review-orchestration-playbook/tests/test_contracts.py` — 22 tests passed.
- Full local suite: `python3 -m unittest discover -s skills/review-orchestration-playbook/tests` — 693 tests passed in 421.941 seconds.
- Static and repository gates: Ruff lint and focused format checks, Python byte-compilation, skill validation, project-journal validation, and `git diff --check` passed.
- Live Claude Code 2.1.212 probes verified that the model-backed scrub opt-out preserves effective `permissionMode: dontAsk`; `Read(./**)` allows an in-workspace synthetic file while an unmatched external synthetic file is denied; recognized read-only Bash `pwd` and `cat` calls run; and `touch` is denied. Absolute `/bin/...` command spellings intentionally fall outside Claude's built-in read-only classifier and are also denied.
- A retained real WIP review reproduced only the exact empty `.claude/.cc-writes` staging artifact; the provider-specific exact cleanup returned `verified-and-removed`, and the unchanged common workspace validator then passed.
- Independent focused reviews of the subprocess-scrub compatibility fix, staging-cleanup race hardening, external review-root security/portability boundary, same-UID retained-review isolation, and exact-version documentation contract: no findings after fixes.
