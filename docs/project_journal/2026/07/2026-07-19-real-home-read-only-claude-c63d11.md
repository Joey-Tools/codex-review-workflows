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
- New external review state uses schema/marker v2. Exact historical v1 state under `<canonical-source>/.codex-tmp/isolated-review-*` remains manageable in place by status/wait/final/cleanup, including the bounded cleanup worker, but cannot launch a reviewer or satisfy the v2 retained-fallback gate.
- On WSL2, `/proc/self/mountinfo` must prove both the source checkout and external review container use supported local native Linux filesystems; Windows-backed provenance is blocked and unproven provenance is inconclusive.
- Only Claude Code `2.1.212` is eligible after publisher-provenance, public-capability, and structured-output checks; other releases fail closed until the behavioral contract is revalidated and deliberately advanced. Every accepted review stream proves effective `dontAsk` mode, the exact `Read`/`Grep`/`Glob`/`Bash` tool set, the requested model, and compatible authentication evidence. `Read(./**)` authorizes detached-workspace file access and unmatched requests are denied; deny-first rules protect real-HOME secrets plus `/proc` and `/dev`. The Bash sandbox denies reads across the original source checkout, whole per-UID review namespace, real HOME, `/proc`, and `/dev`, then re-opens only the current detached workspace and private Git view; it also removes authentication variables and denies writes. The launch requests fail-closed native sandbox settings, but v2.1.212 does not expose effective sandbox or merged managed-permission fields; admin-managed policy remains part of the trusted ordinary CLI control plane.
- The verified control plane may use ordinary Claude Code local login and refresh behavior from real `HOME`. Explicit API-key or OAuth-token values are forwarded only according to precedence and are requested to be removed from sandboxed Bash commands. Valid `auth status --json` evidence is parsed before return-code classification, so Claude Code's nonzero `loggedIn: false` result becomes `blocked-authentication` with the carrier-specific recovery action. The model-backed launch disables Claude Code's broad subprocess scrub because v2.1.212 otherwise forces effective permission mode to `default`; credential-free probes retain it. Hooks, MCP, plugins, skills, and slash commands are separately disabled and checked. The prompt requires read-only behavior, and an exact post-attempt validation rejects any observable worktree, private-Git, diff, or prompt mutation before accepting a result. This does not claim proof against transient writes or out-of-workspace side effects, including ordinary real-HOME control-plane caches or tool-result artifacts.
- The real-HOME resolver clears inherited `XDG_CONFIG_HOME`, preventing alternate Claude configuration discovery outside the authorized home. Output redaction covers both explicit authentication values and complete credential-bearing proxy URLs, while routing-only proxy endpoints and `NO_PROXY` values are excluded from unsafe global byte replacement; all proxy variables remain denied to sandboxed Bash.
- Strict Claude JSONL output is consumed as a single-pass stream that retains only the required init/result events and aggregate error state, avoiding Python-object amplification from a bounded file containing many small records.
- Sensitive-content and escaping-symlink checks cover the exact selected artifact, including non-ignored untracked files in WIP mode, before any provider egress.
- WIP validation also scans the original source `HEAD`-to-snapshot delta paths and original-`HEAD`-side raw blobs from the helper-private Git database. The complete snapshot scan covers the current side, so deleting or reverting a sensitive committed file in the WIP snapshot cannot leave it review-readable through `git show` without blocking egress.
- WIP capture distinguishes deleted tracked endpoints from paths whose content must be read. This prevents a case-insensitive filesystem from resolving the deleted side of a case-only rename to the new path and materializing both spellings.
- Clean/WIP source status preserves the user's ignore boundary without reopening the broader Git configuration surface. A bounded config-only query resolves the effective `core.excludesFile` (or Git's default XDG/HOME ignore path), then the ordinary isolated status command receives only that path; files ignored by the user are neither classified as WIP nor copied, scanned, or sent to a reviewer.
- WIP regular-file contents and symlink-target bytes now consume the same 512 MiB aggregate capture budget. Blob creation uses one bounded `fast-import` session with exact SHA-1/SHA-256 digest verification, and all raw-path removals/additions use one NUL-delimited `update-index --index-info` session. This preserves non-UTF-8, newline, tab, directory/file-transition, duplicate-blob, deletion-only, and source-race semantics while removing the previous per-path subprocess amplification.
- Linux/WSL2 preflight now requires and identity-verifies both native `bubblewrap` and `socat`. The selected tool directories are bound ahead of other host-tool directories in the final Claude `PATH`, and exact name resolution is rechecked before launch so the native sandbox cannot consume an earlier shadow executable.
- Endpoint commit and tag metadata scanning now includes both the complete joined raw Base64 body and strict decoded bytes of structured `gpgsig`, `gpgsig-sha256`, and nested `mergetag` signature blocks, closing both wrapped-raw and encoded-credential paths into the reviewer-readable private Git database.
- Range admission and legacy synthetic-provenance ancestry checks now run against a helper-owned sanitized Git view with only the source object directory attached and commit-graph acceleration disabled. Source Git configuration, replacement refs, `.git/info/grafts`, and cached commit-graph parent edges therefore cannot forge the committed graph accepted as frozen review evidence; missing objects remain no-fetch, fail-closed errors.
- Cleanup-lock creation avoids a redundant `fchmod(0600)` when the newly created file already has the exact private mode. This closes a concurrent first-open metadata race without weakening the subsequent path/descriptor identity, owner, link-count, mode, and metadata-stability checks; genuinely restrictive umasks still take the corrective path.
- Claude Code 2.1.212 creates an empty `.claude/.cc-writes` directory when its native Bash sandbox first runs. The provider records exact pre-launch absence plus any existing real `.claude` parent's filesystem identity, then uses no-follow directory descriptors to verify current-user ownership, `0700` mode, empty contents, and stable parent/child identity. The staging entry itself is atomically moved into helper-private quarantine, re-proved against the opened inode, rechecked as empty, and only then removed non-recursively. It performs the same conservative cleanup and exact workspace validation after the managed process group has completed bounded termination/I/O teardown on a supervision exception, while preserving the primary exception and recording cleanup rejection only as a secondary redacted diagnostic. A new empty parent is independently moved into helper-private quarantine and identity-checked before removal; a swapped candidate at either layer is retained there and rejected rather than restored through a replace-capable rename. Pre-existing WIP entries are not cleaned, disappeared or replaced parents are rejected, and the unchanged exact workspace validator still decides every remaining shape.

## Next Steps

- None for this workstream.

## Evidence

- PR: https://github.com/Joey-Tools/codex-review-workflows/pull/63
- Runtime and workspace contracts: `skills/review-orchestration-playbook/SKILL.md`, `references/helper-contract.md`, `references/claude-runtime-trust.md`, and `references/egress-consent.md`.
- Contract regressions: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Focused contract suite: `python3 -B skills/review-orchestration-playbook/tests/test_contracts.py` — 43 tests passed.
- Final focused suites after review fixes: provider 180 tests, workspace 135 tests, and Linux/WSL runtime 56 tests passed. These include supervision-exception staging cleanup, final-name staging swap quarantine, exact v1 state management, original-`HEAD` WIP deletion, case-only rename, raw/decoded signature metadata, global-ignore boundaries, aggregate symlink budgeting, bounded batched WIP import, raw-path/SHA-256 overlays, sanitized ancestry, stale commit-graph rejection, native `socat` identity, and exact sandbox-tool `PATH` binding.
- Final exact-tree local suite after merging the cleanup-directory identity repair from current `master`: `python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests -q` — 781 tests passed.
- Static and repository gates: Ruff lint and focused format checks, Python byte-compilation, skill validation, project-journal validation, and `git diff --check` passed.
- Live Claude Code 2.1.212 probes verified that the model-backed scrub opt-out preserves effective `permissionMode: dontAsk`; `Read(./**)` allows an in-workspace synthetic file while an unmatched external synthetic file is denied; recognized read-only Bash `pwd` and `cat` calls run; and `touch` is denied. Absolute `/bin/...` command spellings intentionally fall outside Claude's built-in read-only classifier and are also denied.
- A retained real WIP review reproduced only the exact empty `.claude/.cc-writes` staging artifact; the provider-specific exact cleanup returned `verified-and-removed`, and the unchanged common workspace validator then passed.
- Independent focused reviews of the subprocess-scrub compatibility fix, staging-cleanup race hardening, external review-root security/portability boundary, same-UID retained-review isolation, and exact-version documentation contract: no findings after fixes.
