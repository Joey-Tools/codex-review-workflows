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

The parent acquires an exclusive runner lock before spawn and passes its file descriptor to the child for the child's full lifetime. Cross-process `status` / `wait` trusts that lock, not PID existence, so a reused PID cannot masquerade as the review runner.

## Logical Reviewers

`--reviewer codex`:

1. `gpt-5.6-sol`, `xhigh`
2. `gpt-5.5`, `xhigh`, only after explicit model entitlement/policy denial

`--reviewer claude`:

1. Claude Code `claude-opus-4-8`, `max`
2. Claude Code `claude-opus-4-7`, `max`, entitlement-only fallback
3. Copilot CLI `claude-opus-4.8`, `max`, only when Claude Code is absent or both Claude Code models are entitlement-blocked
4. Copilot CLI `claude-opus-4.7`, `max`, entitlement-only fallback

The Claude-family lane requires one of `--egress-consent explicit-claude-review`, `--egress-consent double-review`, or `--egress-consent triple-review`. The helper saves this value in state and writes `egress.json`; it refuses to start the external lane without it. `explicit-claude-review` authorizes Anthropic only, while `double-review` and `triple-review` also authorize the entitlement-only GitHub Copilot fallback.

Model verification normalizes punctuation only and then requires exact equality. A requested `gpt-5.5` never accepts `gpt-5.5-mini`, `gpt-5.5-codex`, or any other suffix as the same model.

Capacity, overload, rate limits, timeouts, network/5xx errors, missing artifacts, silent model substitution, and review findings never trigger a model downgrade. The helper records every attempt and reports transient failures without switching models.

Fallback classification uses stderr plus explicit structured CLI error events only. Reviewer tool output and repository text on stdout are never scanned for entitlement or transient substrings.

## Snapshot And Safety

- The helper requires `--base-ref` and `--head-ref` and resolves both to commits before launch.
- It creates a `.git`-free frozen snapshot by streaming raw tree blobs from the head under source-repo `.codex-tmp/`; Git archive attributes, checkout filters, hooks, and repository config cannot rewrite that snapshot. It also streams a binary `--submodule=diff` artifact for the exact range to disk.
- `.codex-tmp` must be a real in-repository directory, never a symlink. Each random review container is created relative to a no-follow directory descriptor with owner-only `0700` permissions.
- The helper rejects a range when either base or head uses its reserved top-level `.codex-review` control path.
- Snapshot preparation runs Git with a cleaned environment, disabled hooks/fsmonitor/external diff, and explicit `--no-ext-diff --no-textconv`. It does not checkout files through repository filters.
- Submodules remain uninitialized and unfetched; their gitlink changes are represented in the frozen diff.
- Every reviewer receives the same bounded findings-only prompt and primary diff file inside a helper-owned `.codex-review/` directory in the frozen snapshot.
- The helper installs the fixed `git_readonly_shim`, passes the real Git path separately, and executes the reviewer inside the detached workspace.
- Every child receives a runtime-specific minimal environment allowlist instead of the parent's complete environment. Claude and Copilot authentication variables are never present in each other's process. Codex may receive `OPENAI_API_KEY` for headless authentication, but model-proposed shell commands cannot inherit it.
- Codex runs with a custom permission profile: only platform-minimal paths and the frozen workspace are readable; `.git`, `.codex`, `.agents`, and environment-file globs are denied; network and writes are unavailable. It ignores user config and execpolicy rules, uses `approval_policy=never`, and gives model-proposed shell commands a fresh environment with an empty helper-owned `HOME`.
- Claude Code runs in safe mode with `dontAsk` permissions and only `Read`, `Grep`, and `Glob`; no additional directory is allowed, so its permission root is the frozen workspace. Explicit deny rules cover common credential/config homes. Slash commands, Chrome integration, inherited MCP configuration, repository/user setting sources, and nonessential traffic are disabled.
- Copilot runs in plan mode with its built-in current-working-directory path boundary, explicit shell/write denial, temp-directory denial, and disabled custom instructions, built-in MCPs, bash environment loading, experimental features, and remote session export. Secret-like auth variables are withheld from its tools.
- Before a Claude-family run, the helper rejects any symlink in the frozen workspace that resolves outside that workspace and blocks credential-like paths or high-confidence secret patterns found across base-to-head changed paths, the head snapshot, frozen diff, or prompt. The complete changed-path list streams to a NUL-delimited control file and is scanned incrementally, including deleted credentials and credential filenames nested under fixtures or copied home directories. Findings record only bounded path/rule metadata, never matched secret values.
- Reviewer stdout/stderr stream directly to complete per-attempt files. Only a bounded head/tail capture is retained in memory for error classification and runtime metadata parsing; the middle is never buffered in the runner.
- Executable discovery validates `--version` identity and never trusts arbitrary repository `PATH` entries. It checks Homebrew/system locations plus NVM, `NVM_BIN`, `~/.local/bin`, Volta, asdf, Bun, npm-global, and `~/bin`. Explicit absolute overrides are `CODEX_REVIEW_CODEX_PATH`, `CODEX_REVIEW_CLAUDE_PATH`, and `CODEX_REVIEW_COPILOT_PATH`; invalid paths or CLI identities block the lane.
- Source files are never edited. The detached workspace is removed after `stateful wait` unless `--keep-workspace` is set.
- Logs, attempts metadata, and `final.txt` remain in the state directory after workspace cleanup.

## Terminal States

- exit `0`: a non-empty terminal final artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if the parent policy permits
- other nonzero: blocked or failed; inspect `stateful status`, `attempts.json`, and bounded logs
- `stateful final` prints only the saved terminal artifact on success
- workspace cleanup failure is terminal nonzero even when the reviewer produced a clean artifact; the error and retained state directory remain visible for recovery

Each attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, and log paths. For Codex, the helper resolves the emitted thread ID to its persisted rollout and requires matching `turn_context` model and effort before accepting the final artifact. Missing verification is `runtime-unverified`; mismatches stop the lane. Neither condition is entitlement evidence, so neither enters the fallback path.

## Deliberate Omissions

The helper no longer supports generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, live working-tree snapshots, arbitrary child argv, report sinks, or legacy helper names. These surfaces caused ambiguous review counting and model drift.
