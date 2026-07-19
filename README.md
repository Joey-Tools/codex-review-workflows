# Codex Review Workflows

Public review orchestration, synthetic fixture selection, and local delivery gate skills.

`review-orchestration-playbook` is the single entrypoint for policy-bound local Codex review, Claude-family double review, GitHub Codex triple review, and PR readiness. Claude Code model selection remains pinned, while CLI compatibility follows a publisher-verified release range and explicit macOS, Linux, and WSL2 capability contract documented in [Claude Runtime Trust And Platform Capabilities](skills/review-orchestration-playbook/references/claude-runtime-trust.md).

## Review Workspace

Every local lane runs from a helper-owned detached Git worktree backed by a private minimal Git database. That database contains the scanned base/head endpoint commits and their tree/blob closures; WIP mode additionally contains the helper-generated snapshot tree/blob closure. Intermediate commit history and history-only objects are unavailable. The worktree is bound to the resolved review head without registering anything in the source repository's common Git directory, so it cannot collide with the user's branches or other worktrees.

The default mode requires the source checkout to be clean and reviews the exact head commit. `--include-source-wip` is an explicit review-only option that overlays staged changes, unstaged changes, and non-ignored untracked files into a digest-bound snapshot. The helper scans that complete snapshot before egress. WIP evidence is reproducible by its recorded digest, but it is not exact-commit evidence and cannot satisfy PR-readiness or merge-ready gates.

## Claude Runtime

Claude Code runs in the detached worktree with the current user's real `HOME`. The verified CLI control plane may use ordinary local login and refresh it through Claude Code's own supported behavior. For an explicit API key or OAuth token, the helper selects one non-empty environment value and opaque-forwards it to that CLI; it never parses, logs, writes to disk, stages, brokers, or persists the value. Keychain entries, credential files, and refresh state remain owned by Claude Code.

Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login; only the winning explicit variable is forwarded. Before any review prompt enters the child process, the same verified CLI must return a compatible `auth status --json` provider/method/source tuple. Claude Code `>=2.1.212,<3.0.0` must pass publisher-provenance and capability checks before receiving review content or authentication.

The model runs in plan mode with `Read`, `Grep`, and `Glob` exposed for detached-workspace review, plus Claude Code's built-in read-only `Bash` set. The review prompt forbids reads outside that workspace, and explicit file-tool deny rules protect common credential/configuration paths in real `HOME`; `--allowedTools` is not treated as a filesystem allowlist. Every accepted stream must begin with one `system/init` event proving the effective plan mode, exact tool set, model, and authentication indicator, then end with one matching terminal result. The launch requests `failIfUnavailable`, disabled sandbox auto-approval, HOME/worktree write denials, and no unsandbox escape, but Claude Code 2.1.212 does not expose effective sandbox settings or merged admin-managed permission arrays in `system/init`; reports therefore record those settings as requested, not independently proven. Admin-managed policy remains part of the trusted ordinary CLI control plane, so the helper does not claim a non-interactive run can never receive a preapproval. The prompt and verified plan/tool surface require read-only model behavior, and exact post-attempt validation rejects any observable detached-workspace, private-Git, diff, or prompt mutation before accepting a result or model fallback. That validation does not prove that no transient write or out-of-workspace side effect occurred.

## Test

The helper requires Python 3.10 or later; CI pins the minimum supported runtime.

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -m unittest discover -s skills/review-orchestration-playbook/tests
```
