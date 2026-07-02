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
isolated_review stateful cleanup --state-dir <state_dir>
```

Always pass `--state-dir`; it is not positional. `stateful wait --timeout-seconds` accepts only a non-negative finite value, bounds the caller's wait, and does not kill or downgrade a healthy reviewer. `stateful cleanup` explicitly removes a workspace retained by `--keep-workspace` or for a clean-context fallback while preserving state artifacts.

The parent acquires an exclusive runner lock before spawn and passes its file descriptor to the child for the child's full lifetime. Cross-process `status` / `wait` trusts that lock, not PID existence, so a reused PID cannot masquerade as the review runner.

## Logical Reviewers

`--reviewer codex`:

1. `gpt-5.6-sol`, `xhigh`
2. `gpt-5.5`, `xhigh`, only after explicit model entitlement/policy denial

`--reviewer claude`:

1. Claude Code `claude-sonnet-5`, `max`
2. Claude Code `claude-opus-4-8`, `max`, entitlement-only fallback
3. Claude Code `claude-opus-4-7`, `max`, entitlement-only fallback
4. Copilot CLI `claude-sonnet-5`, `max`, only when Claude Code is absent, lacks bare-mode API-key authentication, or all Claude Code models are entitlement-blocked
5. Copilot CLI `claude-opus-4.8`, `max`, entitlement-only fallback
6. Copilot CLI `claude-opus-4.7`, `max`, entitlement-only fallback

The Copilot IDs follow GitHub's authoritative [supported models matrix](https://docs.github.com/en/copilot/reference/ai-models/supported-models), which lists Sonnet 5, Opus 4.8, and Opus 4.7 for Copilot CLI. The shorter command-reference example table can lag product availability and is not treated as a runtime allowlist; exact model verification still fails closed if the installed CLI rejects or substitutes any ID.

The Claude-family lane requires one of `--egress-consent explicit-claude-review`, `--egress-consent double-review`, or `--egress-consent triple-review`. The helper saves this value in state and writes `egress.json`; it refuses to start the external lane without it. `explicit-claude-review` authorizes Anthropic only, while `double-review` and `triple-review` also authorize GitHub Copilot fallback when Claude Code is unavailable, lacks bare-mode API-key authentication, or all pinned Claude models are entitlement-blocked.

Model verification normalizes punctuation only and then requires exact equality. A requested `gpt-5.5` never accepts `gpt-5.5-mini`, `gpt-5.5-codex`, or any other suffix as the same model.

Capacity, overload, rate limits, timeouts, network/5xx errors, missing artifacts, silent model substitution, and review findings never trigger a model downgrade. The helper records every attempt and reports transient failures without switching models.

Fallback classification uses stderr plus explicit structured CLI error events and error-schema fields only. Partial `result`/`data` payloads, reviewer tool output, and repository text on stdout are never scanned for entitlement or transient substrings.

## Snapshot And Safety

- The helper requires `--base-ref` and `--head-ref`, resolves both to commits before launch, and rejects the range unless base is an ancestor of head. A diverged range reports the merge base to use instead of silently reviewing a two-endpoint diff with unrelated target-branch changes.
- It creates a `.git`-free frozen snapshot by streaming raw tree blobs from the head under source-repo `.codex-tmp/`; Git archive attributes, checkout filters, hooks, and repository config cannot rewrite that snapshot. Before writing each regular blob, it enforces a 64 MiB per-file limit plus a 512 MiB/100,000-entry total snapshot budget, and caps streamed tree metadata at 128 MiB. It also limits changed-path and raw-diff metadata to 128 MiB and 100,000 changes, streams a binary `--submodule=diff` artifact for the exact range through a 128 MiB output cap, and bounds changed-blob secret scanning to 512 MiB total. Exceeding any budget fails closed and removes the partial container.
- `.codex-tmp` must be a real in-repository directory owned by the current user, never a symlink or group/other writable. Each random review container is created relative to a verified no-follow directory descriptor with owner-only `0700` permissions.
- The helper rejects a range when either base or head uses its reserved top-level `.codex-review` control path.
- The rendered review prompt is capped at 64 KiB before any reviewer starts. This keeps Copilot's required `--prompt` argument below per-argument execution limits and prevents an oversized override from reaching any external lane.
- Snapshot preparation runs Git with a cleaned environment, replacement objects disabled, disabled hooks/fsmonitor/external diff, and explicit `--no-ext-diff --no-textconv`. It does not checkout files through repository filters, redacts secret-shaped paths from materialization diagnostics, and removes a partial review container on ordinary errors, forwarded signals, or `KeyboardInterrupt`. Completed snapshot ownership is handed to the caller while forwarded signals are blocked, before preparation returns. If removal fails before the state path is published, the terminal error names the retained container and cleanup failure instead of silently losing recovery evidence.
- Submodules remain uninitialized and unfetched; their gitlink changes are represented in the frozen diff.
- Every reviewer receives the same bounded findings-only prompt and primary diff file inside a helper-owned `.codex-review/` directory in the frozen snapshot. Custom prompt placeholders are expanded in one pass so placeholder-shaped text inside generated paths is never interpreted again.
- The frozen workspace contains no `.git` metadata. Codex receives only that workspace under a verified read-only filesystem profile; parent paths are not readable, writes and network are unavailable, and the supplied diff is the primary evidence surface. The runtime does not copy a Git shim or any other helper source into any reviewer-visible workspace. A Git command that cannot operate without repository metadata is expected lane context, not a reason to broaden permissions. Snapshot Git commands disable lazy fetching, terminal prompts, and askpass helpers, so a partial clone with missing objects fails closed instead of contacting a promisor remote or waiting for authentication.
- Every child receives a runtime-specific minimal environment allowlist instead of the parent's complete environment. Proxy and standard/custom CA bundle pointers are preserved so configured TLS trust still works. Claude and Copilot authentication variables are never present in each other's process. Codex may receive `OPENAI_API_KEY` for headless authentication, but model-proposed shell commands cannot inherit it.
- Codex runs with a custom permission profile: only platform-minimal paths and the frozen workspace are readable; `.git`, `.codex`, `.agents`, and environment-file globs are denied; network and writes are unavailable. It ignores user config and execpolicy rules, sets `project_doc_max_bytes=0` so the reviewed head cannot inject `AGENTS.md` instructions, uses `approval_policy=never`, and gives model-proposed shell commands a fresh environment with an empty helper-owned `HOME`. The helper-owned review prompt is the only project-level review contract. The terminal artifact is rejected unless the persisted Codex turn context exactly matches the expected restricted filesystem entries, at most one direct `codex-arg0*` transport file under `$CODEX_HOME/tmp/arg0`, denied control paths, restricted network, and never-approve policy; extra read paths/globs and legacy or managed `sandbox_mode` overrides fail closed as `permission-mismatch`.
- Claude Code runs in bare mode with `dontAsk` permissions, exposes only `Read`, `Grep`, and `Glob`, and pre-approves only the cwd-relative `Read(./**)` rule. Claude applies scoped `Read` rules to its built-in Grep and Glob tools, while `dontAsk` denies any path that does not match; no additional directory is allowed, so the permission root is the frozen workspace. Executable identity and help probes enter bare mode before `--version` or `--help`; the help probe also uses a fresh helper-owned `HOME` and receives neither the API key nor review-path environment variables. Before every attempt, the helper parses the unique local `--bare` option block and requires an exact Claude Code 2.1.187 help whitelist confirming that hooks, `CLAUDE.md` auto-discovery, plugins, keychain reads, and other customizations are skipped; duplicate, mutated, or contradictory `--bare` text fails closed. The inline settings also request `disableAllHooks`, but bare mode is the security boundary because lower-precedence settings cannot disable managed hooks. Bare mode accepts `ANTHROPIC_API_KEY` and intentionally excludes OAuth/keychain authentication; without that key, an authorized double/triple review falls back to Copilot rather than starting a hook-capable Claude session. The review attempt keeps the fresh `HOME` but receives the API key only after both probes pass. Explicit deny rules cover common credential/config homes. Slash commands, Chrome integration, inherited MCP configuration, repository/user setting sources, nonessential traffic, and subprocess credential inheritance are disabled.
- Copilot runs with a fresh helper-owned `COPILOT_HOME`, so persisted permission grants and configuration cannot broaden the lane. It uses plan mode with `-C` pinned to the frozen workspace, a model-visible tool allowlist limited to `view`, `glob`, and `grep`, no `--add-dir` or `--allow-all-paths`, explicit shell/write/URL denial, temp-directory denial, and disabled custom instructions, built-in MCPs, bash environment loading, experimental features, and remote session export. Excluding the `skill` and delegation tools prevents project skills or agents from injecting reviewed-head instructions. Before every attempt, the helper requires `copilot help permissions` to confirm that availability filters control which tools the model can see, default file access is cwd-only, `--disallow-temp-dir` removes the implicit temp root, and deny rules override `--allow-all-tools`; otherwise the fallback fails closed. Secret-like auth variables are withheld from its tools.
- Before any network-backed Codex, Claude Code, or Copilot run, the helper rejects any symlink in the frozen workspace that resolves outside that workspace and blocks credential-like paths or high-confidence secret patterns found across base-to-head changed paths, both sides of changed raw blobs, every head-snapshot path name, symlink target, and file, the frozen diff, or prompt. Changed paths and raw-blob findings stream to NUL-delimited control files and are scanned incrementally, including deleted binary credentials and credential filenames nested under fixtures or copied home directories. Sensitive-content findings plus symlink materialization/escape diagnostics secret-check paths and targets before display; secret-bearing values use typed redaction markers, while control characters and undecodable bytes are escaped. Findings record only bounded side/path/rule metadata, never matched secret values. A successful check writes retained `preflight.json` before executable discovery or model launch so a parent PR-readiness workflow can prove that preflight preceded its separate independent Codex lane.
- Reviewer stdout/stderr stream directly to complete per-attempt files. Only a bounded head/tail capture is retained in memory for error classification and runtime metadata parsing; the middle is never buffered in the runner. Stateful status tails seek and decode only a bounded suffix instead of loading complete logs.
- Logged reviewer processes run in their own process groups. The helper forwards `SIGTERM`, `SIGINT`, `SIGHUP`, and `SIGQUIT`, reaps the reviewer, and terminates leftover descendants before restoring signal handlers; a stateful runner persists `128 + signal` as its terminal exit code. Foreground mode installs the same cancellation boundary before snapshot preparation and blocks signals across final cleanup, so preparation/preflight cancellation cannot strand a tracked-tree container.
- `stateful start` remains cancellable during workspace preparation. It defers a termination signal only across the narrow `Popen` handoff, checks it before publishing, and stops plus cleans any unpublished runner. The state becomes published only after the caller successfully flushes its path. The background runner keeps signal handling installed across preflight, executable discovery, model-attempt gaps, and child execution, then records `128 + signal` under a blocked finalization step.
- Claude/Copilot structured output is accepted only when no explicit `error`, `failed`, or `failure` state is present; partial text attached to an error result cannot become a clean final artifact.
- If Claude reports auxiliary model usage, effective-model verification selects the explicitly requested model entry rather than treating the first auxiliary entry as the reviewer model.
- Executable discovery validates `--version` identity and never trusts arbitrary repository `PATH` entries. It checks Homebrew/system locations plus NVM, `NVM_BIN`, `~/.local/bin`, Volta, asdf, Bun, npm-global, and `~/bin`. For `/usr/bin/env` shebang CLIs, it resolves the named interpreter from those same bounded user/system locations and uses the same constructed `PATH` for identity validation and the review attempt. Explicit absolute overrides are `CODEX_REVIEW_CODEX_PATH`, `CODEX_REVIEW_CLAUDE_PATH`, and `CODEX_REVIEW_COPILOT_PATH`; invalid paths or CLI identities block the lane.
- Source files are never edited. The detached workspace is removed after `stateful wait` unless `--keep-workspace` is set or the Codex runtime exits `127` after a matching successful preflight. That deterministic-unavailability state retains the immutable frozen workspace for the clean-context fallback and is machine-visible in `stateful status`; run `stateful cleanup` after the fallback decision and artifact are complete. A finite wait deadline covers runner completion, cleanup-lock acquisition, and workspace removal; `stateful final` applies its own bounded cleanup deadline. Timed cleanup runs in an independent worker that inherits the held cleanup-lock descriptor; lock ownership is handed off while forwarded signals are blocked, so a timeout or interrupted parent cannot let another waiter start a concurrent `rmtree`. A daemon reaper collects the worker while long-lived callers continue. A successful worker clears any stale cleanup-error artifact while it still owns the cleanup lock.
- Logs, preflight evidence, attempts metadata, and `final.txt` remain in the state directory after workspace cleanup. `attempts.json` is atomically rewritten after every completed model attempt, so cancellation during a later entitlement fallback preserves the earlier model/category/effective-runtime evidence.

## Terminal States

- exit `0`: a non-empty terminal final artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if the parent policy permits
- other nonzero: blocked or failed; inspect `stateful status`, `attempts.json`, and bounded logs
- `stateful final` prints only the saved terminal artifact on success
- exit `127` with `fallback_workspace_retained: true` means preflight succeeded but the Codex executable was deterministically unavailable; use only that retained scope for the clean-context fallback, then run `stateful cleanup`
- workspace cleanup failure is terminal nonzero even when the reviewer produced a clean artifact; the error and retained state directory remain visible for recovery

Each attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, and log paths. For Codex, the helper resolves the emitted thread ID to its persisted rollout and requires matching `turn_context` model and effort before accepting the final artifact. Missing verification on a successful result is `runtime-unverified`; any observed model, effort, or permission mismatch overrides even an otherwise entitlement-shaped failed attempt and stops the lane. None of those conditions is entitlement evidence, so none enters the fallback path.

## Deliberate Omissions

The helper no longer supports generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, live working-tree snapshots, reviewer-visible Git shims, arbitrary child argv, report sinks, or legacy helper names. These surfaces caused ambiguous review counting, model drift, or unnecessary runtime code exposure.
