# Isolated Review Helper

Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review` when bounded review orchestration needs:

- a detached review workspace instead of the live repo checkout
- a single stable executable prefix for approval reuse
- recursive submodule content that matches the current source worktree, not only `HEAD`
- a frozen `base_sha..head_sha` review range on a `wip/<topic>` branch instead of a live uncommitted diff
- a root read-only Codex review session that does not inherit writable runtime overrides from the current parent thread

## Snapshot Semantics

- The helper creates `git worktree add --detach --no-checkout` under repo-local `.codex-tmp/`. In the normal path it keeps that no-checkout baseline and overlays the live working-tree snapshot by file copy; the conditional `git checkout --detach <source-head>` guard only matters when a later materialization sees a reused workspace whose `HEAD` no longer matches the source repo.
- It syncs the current final working-tree snapshot, not the staged/unstaged boundary.
- When both `--base-ref` and `--head-ref` are provided, the helper switches modes: it creates the isolated workspace directly at the frozen `head_ref` commit instead of overlaying the live working tree, and it exposes `{base_ref}`, `{head_ref}`, and `{review_range}` placeholders to child args and prompt templates.
- In that frozen-range mode, if you do not pass `--diff-file`, the helper auto-generates one from `git diff --binary --submodule=diff <base_ref> <head_ref>` inside the isolated workspace checkout.
- Repository content is then materialized into that detached worktree by preferring GNU `cp -a --reflink=always`, falling back to macOS `/bin/cp -cRp` (clonefile attempt; on copy-strategy mismatch the helper then falls back to plain `cp -Rp`), and only then falling back to plain `cp -Rp`.
- Untracked non-ignored files are copied into the isolated workspace as part of that materialized snapshot.
- Recursive initialized submodules are synced the same way.
- Files under generic `.codex-tmp/` are excluded from the automatic untracked copy, but explicit `--prompt-file`, `--diff-file`, and `--copy-path` inputs are copied in.
- Unresolved conflicts abort the helper.
- Existing submodule content is supported; uncommitted submodule topology changes remain best-effort.
- Use `--prepare-only` to build that isolated workspace once and print its path without launching the reviewer.
- When prepare is already cheap on the current repo, do not keep or reuse isolated workspaces by default; let the helper clean them after each bounded attempt.
- Use `--reuse-workspace <path>` only when you intentionally want to compare different reviewer flags or models against the exact same prepared snapshot, or when repo bootstrap remains expensive enough that reuse is worth the cleanup tradeoff.
- On the `HDR-streaming` test repo, this backend change reduced `--prepare-only` from about `42s` to about `0.73s`, which makes later timing much more representative of reviewer behavior instead of submodule bootstrap cost. Treat those timings as one measured example, not a universal wait budget for every repo.

## Entrypoints

- `--entrypoint auto`: follow the priority order implied by `--lane`.
- `--entrypoint codex-parallel`: start helper-managed internal Codex dual-lane review. This launches `codex-readonly` and `codex-review` in parallel against the same scope and aggregates them under one manager state dir. Treat it as explicit opt-in coverage, not the default.
- `--entrypoint codex-readonly`: force the helper-managed diff-fed readonly Codex lane. Treat it as the deterministic fallback when the default agentic lane is unavailable or inconclusive, or when the caller explicitly wants a diff-fed findings baseline. Default to the helper's `stateful start|status|wait|final` lifecycle for this lane; reserve plain one-shot runs for narrow smoke/debug cases.
- `--entrypoint codex-review`: force a root read-only Codex review lane inside the isolated workspace. This is the default internal agentic lane. On Linux, the helper may first probe the default sandbox backend and inject helper-managed feature flags before `-s read-only` when the known bubblewrap loopback failure appears.
- `--entrypoint opencode`: force direct `opencode`.
- `--entrypoint agent`: force direct `agent`.
- `--entrypoint copilot`: force direct `copilot`.
- `--entrypoint gh-copilot`: force `gh copilot -- ...`.

`auto` continues to mean external-review lane selection only. The helper does not silently choose `codex-review` as part of external auto priorities.

## Lanes

- `--lane custom`: preserve the legacy helper behavior. `auto` still prefers `agent`, then `copilot`, then `gh copilot`.
- `--lane bounded-semantic`: prefer `opencode` when its narrow preflight confirms the exact model that will be launched after helper defaults and any explicit `--model` override are applied, package `report sink`-friendly placeholders, and disable OpenCode auto-compaction by default; otherwise fall back to the next lane candidate.
- `--lane deep-semantic`: prefer Cursor `agent` first when deeper semantic review matters more than speed.
- `--lane baseline`: prefer legacy Copilot lanes for a more conservative baseline run.
- `--lane super-large`: prefer `opencode` and generate a persistent review contract plus `auto-hardened` compaction config for very large diffs.

The helper now supports `opencode`, `agent`, `copilot`, and `gh-copilot`.

## Child Command Contract

Pass the real review CLI arguments after `--`.

GPT-family model overrides belong only on Codex CLI entrypoints. Direct external runtimes (`opencode`, Cursor `agent`, `copilot`, and `gh-copilot`) must use their non-GPT provider defaults or an explicit non-GPT comparison model; if a caller passes a GPT model such as `gpt-*` or `openai/gpt-*` directly to one of those lanes, including as a later duplicate `-m/--model` value, the helper rejects that lane in explicit mode or strips the stale override during `auto` fallback before candidate preflight and launch.

When the resolved entrypoint is `codex-parallel`, the helper does not forward caller-supplied child args or prompt-contract flags. Instead it starts one helper-managed `codex-readonly` child state and one helper-managed `codex-review` child state in parallel, then exposes a single aggregate `stateful status` / `wait` / `final` view. `codex-readonly` is the primary findings lane; `codex-review` remains advisory. The advisory lane no longer uses a fixed `300s` wall-clock kill. The helper now derives an agentic total budget from the same helper-generated diff that the readonly lane already materialized, starting at `20min` and scaling up to `60min` for larger repos or diffs. That keeps frozen `--submodule=diff` ranges and live working-tree snapshots aligned with the actual review payload, while avoiding an extra full-file scan over every untracked artifact just to estimate the tier. The helper also separates initial-quiet and no-new-output leases so a lane that is still reading files can continue while a genuinely stalled lane still times out; those leases now key off non-empty reviewer output timestamps rather than empty log-file creation or the caller's first polling time. If the advisory lane fails or times out after that helper-managed wait budget, the aggregate review still passes as long as `codex-readonly` completed successfully, and `stateful final` emits a helper-assembled internal review report that preserves both lanes instead of pretending to be a raw single-lane final message. Treat this lane as opt-in dual-lane coverage, not as the default path for callers that still expect a machine-comparable single-lane final artifact.

When the resolved entrypoint is `codex-readonly`, the helper defaults the child command to `codex -s read-only --add-dir <state-dir>/codex-readonly-tmp ... exec -o <state-dir>/final.txt -` and writes a helper-generated findings-only prompt over stdin. When helper-managed inputs such as `{diff_file}` or `final.txt` live outside the isolated workspace, the helper also injects their parent directories as extra `--add-dir` entries so the readonly sandbox can still read or write those files. For frozen ranges it auto-generates `{diff_file}` from `base_ref..head_ref`; for live working-tree review it auto-generates a composite primary diff file containing `git status --short --untracked-files=all` plus `git diff --no-ext-diff --binary --submodule=diff HEAD`, with untracked files rendered through `git diff --no-index --no-ext-diff`. This lane is intentionally helper-managed: it rejects caller-supplied prompt contracts, report sinks, extra copied inputs, and child args after `--`. Use it as the deterministic fallback when the default agentic lane is unavailable or inconclusive, or when you intentionally need a predictable diff-fed readonly findings baseline instead of builtin agentic review behavior. In normal review work, prefer `stateful start|status|wait|final` so the lane keeps a pollable state dir and durable `final.txt`; reserve plain one-shot `codex-readonly` for quick smoke/debug probes where an eventual manual interrupt would be acceptable.

When the resolved entrypoint is `codex-review`, the helper defaults the child command to `codex -s read-only --add-dir <state-dir>/codex-review-tmp exec ... review ...`. On Linux, the helper first probes `codex sandbox linux /usr/bin/true`; if that probe fails with the known `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` signature, it retries the probe with helper-managed `--disable use_linux_sandbox_bwrap --enable use_legacy_landlock` and injects those same feature flags into the real `codex-review` command only when the retry succeeds. It injects helper-managed `--base <base_ref>` when the review range is frozen, otherwise falls back to helper-managed `--uncommitted`; it always enables `--json`, writes the last assistant message to a helper-managed `final.txt`, and points `TMPDIR` / `TMP` / `TEMP` / `TMPPREFIX` at that task-scoped temp area. Native scoped `codex exec review --base` / `--uncommitted` does not accept a custom positional prompt, so this lane cannot carry the default evidence-budget prompt contract; move to `codex-readonly` when that exact prompt contract is required. This lane does not support `--report-path`; use the saved `final.txt` / `stateful final` artifact instead of a report sink. Caller-supplied prompt contracts such as `--prompt-file`, `--diff-file`, `--final-reply`, non-default `--prompt-delivery`, or prompt stdin injection still fail closed for the builtin `codex-review` lane so the helper does not silently drop them. Frozen `codex-review` runs also require a linear range where `base_ref` is an ancestor of `head_ref`; builtin `codex exec review --base` uses merge-base semantics, so non-ancestor target-branch comparisons must fail closed and move to a diff-fed direct read-only fallback instead of silently widening scope. Treat this lane as the default internal agentic reviewer path when callers still expect the historical single-lane final artifact. If this lane is unavailable or inconclusive, or if the workflow intentionally wants an exact diff-fed baseline, move to `codex-readonly`; if you intentionally want dual-lane coverage, opt into `codex-parallel`.

On Linux or Ubuntu hosts, repeated helper stderr like `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` after helper-managed backend selection is a lane failure, not harmless noise. Once that signature still appears for helper-backed `codex-review`, stop extending waits on the same lane shape and switch to an explicit fallback reviewer path.

For `codex-review`, keep the child args narrow: pass only safe `codex exec` options before the helper-managed `review` subcommand such as `-C/--cd`, `-p/--profile`, `--color`, `--oss`, and `--local-provider`; safe `codex exec review` options such as `-m/--model`, `-o/--output-last-message`, `--json`, `--ephemeral`, `--skip-git-repo-check`, and `--title`; and no explicit prompt positional on the builtin review lane. The helper intentionally rejects caller-supplied runtime-override flags such as `-s/--sandbox`, `--add-dir`, `--full-auto`, and `--dangerously-bypass-approvals-and-sandbox`; it also rejects helper-managed review selectors such as `--base`, `--commit`, and `--uncommitted`, rejects nested subcommands such as `review`, and rejects `-c/--config`, `-i/--image`, `--enable`, `--disable`, and `--output-schema` so the helper remains the only place that controls the reviewer runtime contract.

When the resolved entrypoint is `agent`, the helper defaults the child command to `--mode ask --model claude-opus-4-7-thinking-high --print --trust`. If that exact thinking alias is not exposed but the current 4.7 high alias is available, the helper falls back compatibly to `claude-opus-4-7-high`; it no longer treats 4.6 Opus aliases as supported helper defaults. Pass explicit child args after `--` when you need to override or extend those defaults, but still pass the prompt payload itself there as `"{prompt_text}"` or an equivalent prompt input, and do not pass GPT-family models through `agent`. The helper now uses `agent models` as a best-effort preflight: a successful catalog that omits the effective model fails that lane or triggers fallback, while only explicitly recognized false negatives such as `SecItemCopyMatching failed -50` stay inconclusive. When the catalog was authoritative, the selected default model is reused at launch so later probes cannot silently drift the helper onto a different alias; when the first probe was only inconclusive, the launch path is still allowed one late resolve so hosts with a transient Keychain false negative can recover onto a supported 4.7 alias, but if that retry still cannot produce a trustworthy catalog the helper now fails or falls back instead of silently launching `agent` without any explicit `--model`. If you compare against another non-GPT model, run that as a separate lane or explicit override, but keep one primary pass on the helper defaults.

When `--prompt-file` is present, the helper now defaults to `--prompt-delivery auto`. Short rendered prompts stay inline, but long prompts on agentic entrypoints (`agent`, `opencode`) switch to a tiny bootstrap prompt that tells the reviewer to read `{prompt_file}` from inside the isolated workspace. That keeps real review contracts out of long argv/env payloads and avoids shell-metachar drift in the outer caller. If you explicitly need the previous behavior, force `--prompt-delivery inline`; if you want to force the file-reading bootstrap on an agentic lane, use `--prompt-delivery bootstrap`.

When the resolved entrypoint is `opencode`, the helper defaults the child command to `run -m github-copilot/claude-opus-4.7 --format json`. If `opencode models` does not list that model on the current machine, the helper treats the OpenCode lane as unavailable and falls back to the next configured lane instead of pinning an older Opus baseline. It injects an OpenCode-native `--` delimiter before the message payload, and if `{diff_file}` exists it also injects `--file {diff_file}` unless you already supplied one. The helper additionally creates a task-scoped OpenCode config under the isolated workspace, and maps lane defaults to compaction mode:

- `bounded-semantic` -> `no-auto`
- `super-large` -> `auto-hardened`
- everything else -> plain `auto`

Only the `super-large` / `auto-hardened` shape forces a task-local `XDG_DATA_HOME`; bounded semantic lanes intentionally keep the normal OpenCode data home so existing provider/model metadata stays available.
When `--report-path` is set on non-`codex-review` lanes, the helper also grants the exact `mkdir -p <report-parent>` bash shape needed for the report sink directory inside the isolated workspace so the reviewer can materialize `.codex-tmp/external-review/report.md` without widening shell access further.

When the resolved entrypoint is `copilot` or `gh-copilot`, the helper preserves explicit `-p` / `--prompt` / `-i` / `--interactive` child args, but if you only pass a bare `"{prompt_text}"` payload it will normalize that to `--prompt <rendered prompt>` to satisfy the current non-interactive Copilot contract. That keeps the small child argv shape stable while avoiding the CLI's `Invalid command format` startup failure.

On the user's current machine, direct `copilot -p --model claude-opus-4.7` works on the authenticated host path, while sandboxed probes can fail early with `SecItemCopyMatching failed -50`. Do not confuse that with the current ACP caveat: GitHub documents Copilot CLI ACP as public preview, and public issue `github/copilot-cli#2782` reports `session.create` still rejecting `claude-opus-4.7` even when the direct interactive/programmatic path supports it. Treat that as an ACP-specific workaround boundary; if a separate ACP client needs Copilot today, pin its ACP model explicitly instead of changing the helper's direct `copilot` lane defaults.

When `--entrypoint auto` starts on an OpenCode-first lane and later falls back to another runtime, the helper now sanitizes primary-only or GPT-family model overrides before launching the fallback. Concretely:

- `copilot` and `gh-copilot` drop inherited `-m` / `--model` args entirely.
- `agent` drops inherited provider-scoped model overrides such as `openai/gpt-5.3-codex` so it can fall back to its own default model instead of inheriting an OpenCode-specific override.
- `opencode`, `agent`, `copilot`, and `gh-copilot` reject direct GPT-family model overrides; in `auto` mode the helper strips those stale overrides before candidate preflight so the selected lane can use its non-GPT default.

Treat that sanitization as part of the helper contract rather than as optional prompt shaping. Real replay evidence showed that reusing the primary lane's invalid `--model` could make a healthy fallback lane fail before it had a chance to answer.

`gh-copilot` also has a companion runtime contract: the helper requires both `gh` and a usable `copilot` companion binary. In the normal path it resolves `gh` from `PATH`, resolves the companion from `CODEX_GH_COPILOT_COMPANION_PATH` or the known Homebrew/macOS locations, and then injects the companion directory into the child `PATH` immediately after the readonly git shim. That keeps `gh-copilot` usable even in constrained PATH shapes that intentionally expose `gh` but not direct `copilot` as an auto-lane candidate.

When a findings-only OpenCode lane keeps drifting into process-summary output or project journals, keep the helper but pair it with a dedicated review-only OpenCode agent or command in the isolated workspace. Disable skill/task/todo/question helpers there, deny `docs/PROJECT_STATE.md` / `docs/PROJECT_TODO.md` unless they are explicitly in scope, and keep writes limited to the report path.

When you launch this helper from Codex `exec_command` and need the final reviewer message, prefer a pollable `tty=true` session over one-shot plain pipes. The helper can successfully hand work off to `agent`, yet a plain pipe session may stop surfacing new stdout while the child reviewer is still running.

If a prior helper invocation is still alive according to `ps`, do not start another reviewer on top of it. Reattach or keep polling the same session when possible, or stop the stale process first before retrying with a different prompt/model/session shape.

Do not assume you can safely add `--force` as a universal helper default just to unblock agentic `git diff` / `git status`. Current Cursor CLI only exposes broad unblock knobs such as `--force` / `--yolo`, not a narrower "read-only git only" mode, and org-managed accounts may disable `Run Everything` entirely. When that happens, keep the helper on its normal defaults and steer the reviewer to read `{diff_file}` directly instead of running git.

If the user explicitly configures user-level Cursor CLI permissions in `~/.cursor/cli-config.json`, the normal headless helper path can sometimes keep agentic file reads and `git status` / `git diff` probes without falling back to the no-git prompt. The relevant shape on the user's current machine is `Read(**)` plus `Shell(git)`, but keep the permission caveat explicit: `Shell(git)` is command-base scoped, so Cursor's built-in allow/deny model cannot reliably express "allow `git diff` but deny `git commit`" by subcommand name alone.

To narrow git access back down in helper-managed lanes, the helper resolves a trusted absolute `git` path for its own internal worktree operations, then installs the fixed script `scripts/git_readonly_shim` into the isolated container's `tool-shims/git`, prepends that directory to the child review process `PATH`, and verifies before launch that `git --version` resolves through the shim. The installed shim rewrites its shebang to the helper process's absolute Python executable instead of keeping `#!/usr/bin/env python3`; on macOS read-only review sandboxes, resolving `python3` through `/usr/bin/env` can itself trigger Apple `xcrun_db-*` cache writes before real Git ever runs. On macOS, prefer Homebrew Git before Apple's `/usr/bin/git`; repeated readonly review sessions showed the Apple wrapper can trigger `xcrun_db-*` cache writes that are denied inside Codex read-only sandboxes. The shim allows common inspection commands such as `git status`, `git diff`, `git show`, `git log`, `git rev-parse`, `git ls-files`, `git blame`, and related diff/log readers, while rejecting mutating subcommands such as `git commit`, arbitrary global config overrides through `-c` except exact helper-equivalent hardening values, dangerous global options such as `--config-env` and `--exec-path`, and explicit reader flags that would re-enable external helpers such as `--ext-diff`, `--textconv`, `--filters`, and `--open-files-in-pager` including the short `git grep -O` form. It also strips inherited `GIT_CONFIG_*`, `GIT_CONFIG_SYSTEM`, repo-routing `GIT_DIR` / `GIT_WORK_TREE` / `GIT_COMMON_DIR` / `GIT_CEILING_DIRECTORIES`, object-dir/index overrides, `GIT_EXEC_PATH`, `GIT_EXTERNAL_DIFF`, and pager env overrides before delegating to real git. The delegated call itself is additionally hardened with `--no-pager`, fixed safe config overrides for `core.hooksPath`, `diff.external`, `core.fsmonitor`, and repo-local GPG program settings, a trusted subprocess `PATH` rooted at the resolved real git, `--no-ext-diff --no-textconv` on diff-like readers, a graceful skip of repo-local filter preflight when the target is not actually a git repo such as `git diff --no-index`, and per-target-repo overrides that neutralize discovered `filter.<driver>.clean` / `smudge` / `process` hooks for worktree-reading commands such as `status`, `diff`, and `blame` through `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` injection so unusual driver names such as `a=b` are still neutralized. That keeps cross-repo history inspection usable without trusting the target repo's local diff config, diff drivers, textconv, clean-filter hooks, repo-local hooks/GPG program settings, repo-routing env overrides, or an outer wrapper that shadowed `git`. If the reviewer trips that guardrail, treat it as a prompt-shaping signal, not as a reason to widen git access immediately.

If this helper already has an approved recurring prefix, call it directly. In public docs and prompts, use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review` as the stable installed-helper shape; do not hard-code account-specific paths such as `/Users/<name>/.codex/...`, and do not use repo-local `skills/...` helper paths for normal workflows. Do not wrap it in `/usr/bin/time`, `bash -lc`, or another outer executable just to add timing or shell syntax, because the approval match is against the real argv prefix; once the outer argv changes, sandbox policy can block the helper's writes to the source repo's shared git dir.

Treat this helper as the standard entrypoint for helper-supported bounded reviews. Do not hand-assemble raw `opencode ...`, `agent ...`, `copilot ...`, or `gh copilot ...` review commands in the normal workflow unless you are doing a narrow preflight or debugging the helper itself, because that creates approval drift and makes it easier to miss the recurring helper prefix in `~/.codex/rules`.

Supported placeholders in child args and prompt-file content:

- `{workspace}`: isolated repo root
- `{repo}`: alias of `{workspace}`
- `{source_repo}`: original source repo root
- `{prompt_file}`: copied prompt file path inside the isolated workspace
- `{diff_file}`: copied diff file path inside the isolated workspace
- `{prompt_text}`: rendered prompt text after placeholder substitution
- `{report_file}`: report file path inside the isolated workspace, when `--report-path` is set
- `{final_reply}`: final reply contract, either explicit or derived from `--report-path`
- `{base_ref}`: frozen base commit SHA, when `--base-ref` is set
- `{head_ref}`: frozen head commit SHA, when `--head-ref` is set
- `{review_range}`: frozen range label `<base_ref>..<head_ref>`

Environment variables exported to the child command:

- `CODEX_ISOLATED_REVIEW_ROOT`
- `CODEX_ISOLATED_SOURCE_REPO`
- `CODEX_ISOLATED_REVIEW_ENTRYPOINT`
- `CODEX_ISOLATED_REVIEW_PROMPT_DELIVERY`
- `CODEX_ISOLATED_REVIEW_PROMPT_FILE`
- `CODEX_ISOLATED_REVIEW_DIFF_FILE`
- `CODEX_ISOLATED_REVIEW_PROMPT_TEXT` (`bootstrap` mode omits this on purpose to keep oversized prompts out of the child env)
- `CODEX_ISOLATED_REVIEW_REPORT_FILE`
- `CODEX_ISOLATED_REVIEW_FINAL_REPLY`
- `CODEX_ISOLATED_REVIEW_FINAL_FILE`
- `CODEX_ISOLATED_REVIEW_BASE_REF`
- `CODEX_ISOLATED_REVIEW_HEAD_REF`
- `CODEX_ISOLATED_REVIEW_RANGE`

## Stateful Control

When the review lane needs subagent-like lifecycle control without sharing the parent runtime, the helper also supports an explicit `stateful` control namespace:

- `stateful start`: prepare the isolated workspace, launch the reviewer in the background, and print the state dir.
- `stateful status --state-dir <dir>`: report whether that review is still running plus recent stdout/stderr tails.
- `stateful wait --state-dir <dir>`: block until the background review exits, then clean the workspace unless the keep flags say otherwise.
- `stateful final --state-dir <dir>`: print the saved final reviewer artifact. For `codex-review` and `codex-readonly` this is the assistant's final message from `final.txt`. For `codex-parallel` it is the helper-assembled aggregate internal review report. For other lanes it falls back to the last non-empty stdout line when available.

Prefer this namespace by default for `codex-readonly`, not only for `codex-review`. A direct one-shot readonly run can still be useful for a tiny local smoke, but it has no pollable state dir and is more likely to end in a manual interrupt when stdout stays quiet for a long time.

The explicit namespace avoids argv ambiguity with real reviewer commands whose first positional token happens to be `start`, `status`, `wait`, or `final`.

The background review state lives beside the isolated workspace under the same task-scoped `.codex-tmp/isolated-review-*` container. After `wait`, the helper may remove `workspace/` while preserving the state dir, logs, and saved final artifact for audit/debug use. For `codex-review`, the background child now writes its own PID as soon as it starts; during the tiny window after `runner-spec.json` is written but before that PID lands, `status` may report `launching` instead of `running`, and `start --reuse-workspace` will still refuse to reuse that recent-launch state.

## Examples

Smallest normal-path invocation, using the helper defaults:

```bash
"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  --repo /path/to/repo \
  --lane bounded-semantic \
  --prompt-file /path/to/repo/.codex-tmp/review.prompt \
  --diff-file /path/to/repo/.codex-tmp/review.diff \
  --report-path .codex-tmp/external-review/report.md \
  -- \
  "{prompt_text}"
```

This keeps the helper on bounded semantic defaults, creates a fresh isolated workspace for the attempt, lets the helper clean that workspace afterward, and prefers `opencode` with `no-auto` compaction when it is available.

If the rendered prompt in `review.prompt` grows too large for a comfortable inline argv/env payload, leave the command shape alone and let `--prompt-delivery auto` switch the child prompt to a small bootstrap instruction. The reviewer still receives the full instructions through `{prompt_file}` inside the isolated workspace.

Frozen commit-range example for a reviewable `wip/<topic>` slice:

```bash
"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  --repo /path/to/repo \
  --lane bounded-semantic \
  --base-ref 2c4f... \
  --head-ref 9a7b... \
  --prompt-file /path/to/repo/.codex-tmp/review.prompt \
  --report-path .codex-tmp/external-review/report.md \
  -- \
  "{prompt_text}"
```

This freezes the reviewer onto the exact `2c4f.....9a7b...` range, checks out the isolated workspace at `head_ref`, auto-generates `{diff_file}` from that range when you did not prebuild one, and keeps later live worktree drift out of scope.

Internal readonly Codex review with background lifecycle control:

```bash
state_dir="$(
  "$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
    stateful start \
    --repo /path/to/repo \
    --entrypoint codex-readonly \
    --base-ref 2c4f... \
    --head-ref 9a7b...
)"

"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  stateful status \
  --state-dir "$state_dir"

"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  stateful wait \
  --state-dir "$state_dir"

"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  stateful final \
  --state-dir "$state_dir"
```

This keeps the internal reviewer on a fresh root `read-only` Codex `exec` session, while still preserving the isolated snapshot, submodule handling, and reusable helper prefix. For frozen `codex-review` runs, do not pass helper-managed prompt contracts such as `--prompt-file`, `--diff-file`, `--report-path`, or `--final-reply`; builtin `codex exec review --base` cannot honor them, so the helper now rejects those flags instead of silently dropping them.

For the historical agentic lane, keep the same `stateful start|status|wait|final` shape and switch only `--entrypoint codex-readonly` to `--entrypoint codex-review`. Do this only for narrow scopes where builtin `codex exec review` is acceptable: that builtin prompt cannot receive the helper-managed evidence budget and may tell the child to run `git diff <base>` directly. For large, generated-heavy, or evidence-budget-sensitive scopes, keep `--entrypoint codex-readonly`.

Progress-visible example when you want `stream-json` timing or ingest traces:

```bash
"$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review" \
  --repo /path/to/repo \
  --lane deep-semantic \
  --entrypoint agent \
  --prompt-file /path/to/repo/.codex-tmp/review.prompt \
  --diff-file /path/to/repo/.codex-tmp/review.diff \
  -- \
  --output-format stream-json \
  --stream-partial-output \
  "{prompt_text}"
```

Legacy compatibility alias:

```bash
"$HOME/.codex/skills/external-review-playbook/scripts/isolated_copilot_review" ...
```

The old script name is still kept as a thin wrapper to the new helper so existing approved prefixes and muscle memory do not break immediately.

Deprecated old-skill-path approval shim:

```bash
"$HOME/.codex/skills/copilot-review-playbook/scripts/isolated_copilot_review" ...
```

This path is kept only as a runtime compatibility wrapper for older approved prefixes. Treat `review-orchestration-playbook` plus `scripts/isolated_review` as the canonical skill and helper path; `external-review-playbook` and `isolated_external_review` remain compatibility wrappers.

Use `--keep-on-failure` to retain the isolated workspace for debugging, or `--keep-workspace` to always keep it.
