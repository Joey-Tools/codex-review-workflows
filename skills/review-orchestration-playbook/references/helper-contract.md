# Isolated Review Helper Contract

The canonical helper is:

```bash
$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review
```

It runs exactly one logical local reviewer against one frozen Git range. The parent skill composes multiple logical lanes.

## CLI

Foreground:

```bash
isolated_review \
  --repo /path/to/repo \
  --reviewer codex \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

Stateful:

```bash
isolated_review stateful start \
  --repo /path/to/repo \
  --reviewer claude \
  --egress-consent double-review \
  --base-ref <base_sha> \
  --head-ref <head_sha>

isolated_review stateful status --state-dir <state_dir>
isolated_review stateful wait --state-dir <state_dir>
isolated_review stateful final --state-dir <state_dir>
```

Always pass `--state-dir`; it is not positional. `stateful wait --timeout-seconds` bounds the caller's wait but does not kill or downgrade a healthy reviewer.

## Logical Reviewers

`--reviewer codex`:

1. `gpt-5.6-sol`, `xhigh`
2. `gpt-5.5`, `xhigh`, only after explicit model entitlement/policy denial

`--reviewer claude`:

1. Claude Code `claude-opus-4-8`, `max`
2. Claude Code `claude-opus-4-7`, `max`, entitlement-only fallback
3. Copilot CLI `claude-opus-4.8`, `max`, only when Claude Code is absent or both Claude Code models are entitlement-blocked
4. Copilot CLI `claude-opus-4.7`, `max`, entitlement-only fallback

The Claude-family lane requires one of `--egress-consent explicit-claude-review`, `--egress-consent double-review`, or `--egress-consent triple-review`. The helper saves this value in state and writes `egress.json`; it refuses to start the external lane without it.

Capacity, overload, rate limits, timeouts, network/5xx errors, missing artifacts, silent model substitution, and review findings never trigger a model downgrade. The helper records every attempt and reports transient failures without switching models.

## Snapshot And Safety

- The helper requires `--base-ref` and `--head-ref` and resolves both to commits before launch.
- It creates a detached worktree at the frozen head under source-repo `.codex-tmp/` and generates a binary `--submodule=diff` artifact for the exact range.
- Initialized submodules are materialized without fetching. Missing local objects block the lane instead of causing hidden network access.
- Every reviewer receives the same bounded findings-only prompt and primary diff file inside a helper-owned `.codex-review/` directory in the detached worktree.
- The helper installs the fixed `git_readonly_shim`, passes the real Git path separately, and executes the reviewer inside the detached workspace.
- The reviewer prompt and environment do not name the live source checkout as an additional context root. Claude Code receives only read/search tools, with slash commands, Chrome integration, inherited MCP configuration, and repository/user setting sources disabled. Copilot runs in plan mode and disables custom instructions, built-in MCPs, bash environment loading, experimental features, and remote session export; secret-like environment variables are withheld from its shell and MCP tools.
- Source files are never edited. The detached workspace is removed after `stateful wait` unless `--keep-workspace` is set.
- Logs, attempts metadata, and `final.txt` remain in the state directory after workspace cleanup.

## Terminal States

- exit `0`: a non-empty terminal final artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if the parent policy permits
- other nonzero: blocked or failed; inspect `stateful status`, `attempts.json`, and bounded logs
- `stateful final` prints only the saved terminal artifact on success

Each attempt records runtime, requested model, effective model when observable, category, exit status, and log paths. A successful CLI response that silently substituted another model is `model-mismatch` and stops the lane; it is not evidence of account entitlement and never enters the fallback path.

## Deliberate Omissions

The helper no longer supports generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, live working-tree snapshots, arbitrary child argv, report sinks, or legacy helper names. These surfaces caused ambiguous review counting and model drift.
