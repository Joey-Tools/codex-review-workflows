# Isolated Review Helper Contract

The canonical helper is:

```bash
$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review
```

It runs exactly one logical local reviewer against one immutable review artifact. The parent skill composes multiple logical lanes.

## CLI

Clean foreground review:

```bash
isolated_review \
  --repo /path/to/repo \
  --reviewer codex \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

Stateful Claude review:

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

Explicit WIP review adds one flag to the review invocation:

```bash
isolated_review stateful start \
  --repo /path/to/repo \
  --reviewer claude \
  --egress-consent explicit-claude-review \
  --include-source-wip \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

`--include-source-wip` is review-only consent, not a way to satisfy PR-readiness gates. All review commands otherwise default to clean mode and reject a dirty source checkout.

Synthetic-token catalog inspection remains read-only:

```bash
isolated_review synthetic-tokens validate
isolated_review synthetic-tokens list --json
isolated_review synthetic-tokens get <id> --json
isolated_review synthetic-tokens list-exemptions --json
isolated_review synthetic-tokens audit-master --repo <path> --ref <sha> --exemption <id>
```

`stateful start` returns the helper-generated external per-run container as `state_dir`. Always pass that exact path with `--state-dir`; it is not positional. `stateful wait --timeout-seconds` accepts only a non-negative finite value, bounds the caller's wait, and does not kill or downgrade a healthy reviewer. `stateful cleanup` explicitly removes a retained review worktree while preserving state artifacts in that container.

The parent acquires an exclusive runner lock before spawn and passes its file descriptor to the child for the child's full lifetime. Cross-process `status` / `wait` trusts that lock, not PID existence, so a reused PID cannot masquerade as the review runner.

## Logical Reviewers

`--reviewer codex`:

1. `gpt-5.6-sol`, `xhigh`
2. `gpt-5.5`, `xhigh`, only after explicit model entitlement/policy denial

`--reviewer claude`:

1. Claude Code `claude-opus-4-8`, `max`
2. Claude Code `claude-opus-4-7`, `max`, only after explicit model entitlement/policy denial for Opus 4.8
3. Copilot CLI `claude-opus-4.8`, `max`, only when the verified Claude runtime is deterministically unavailable or both Claude models are entitlement-blocked and consent authorizes fallback
4. Copilot CLI `claude-opus-4.7`, `max`, only after the same explicit model entitlement/policy denial

The Claude-family lane requires `--egress-consent explicit-claude-review`, `--egress-consent double-review`, or `--egress-consent triple-review`. `explicit-claude-review` authorizes Anthropic only; the other two may authorize the narrow Copilot fallback above. Authentication failure never becomes fallback eligibility.

Model verification normalizes punctuation only and requires exact equality. Capacity, overload, rate limits, timeouts, network/5xx errors, missing artifacts, silent substitution, and findings never trigger a model downgrade.

## Detached Review Worktree

Clean and WIP are two content variants of the same review workspace and runtime boundary.

The helper places the detached worktree, private Git database, control artifacts, logs, and state outside the source checkout. Its fixed base is `/tmp`, resolved to a canonical real directory that must be root-owned with exact mode `01777`. Beneath that base it creates current-user-owned exact-`0700` namespaces for `codex-isolated-review-uid-<effective-uid>` and the SHA-256 of the canonical source path, then an exact generated per-run container. Short-lived pre-container ancestry/source-inspection directories and bounded spill files also use the same verified canonical base and are removed before the operation that creates them returns. No caller-controlled `TMPDIR` or source path selects another root, and layout validation recomputes the same external namespace. Claude's publisher-verified executable snapshot is also run from this container during credential-free safe-mode preflight, so a `noexec` temporary mount fails before authentication or review content is exposed.

### Clean Content

- Resolve `--base-ref` and `--head-ref` to commits and require base to be an ancestor of head. Both range admission and legacy-provenance ancestry queries run through a helper-owned sanitized Git view that reads only the source object directory with commit-graph acceleration disabled; source configuration, replacement refs, `.git/info/grafts`, and cached commit-graph parent edges cannot rewrite the accepted graph. Before a false ancestry result is classified as a legitimate merge-base outcome, a bounded zero-output `rev-list --quiet --missing=error` commit walk must prove that both endpoint histories are traversable; Git-version-specific status `1` behavior cannot turn missing parent objects into an ordinary unrelated-history diagnosis.
- Require the source checkout to have no staged changes, unstaged changes, conflicts, or non-ignored untracked files. Inspect the actual source `HEAD`, object directory, and exact per-worktree index through a short-lived helper-owned Git database; source `status`, `diff`, `ls-files`, and `ls-tree` must not load source-local hooks, filters, diff drivers, aliases, or other repository configuration.
- Reject every gitlink found in either the actual source `HEAD` tree or the active source index before running source `status` or `diff`. This includes staged deletion or replacement of a committed gitlink; the source-inspection path never recurses into a source submodule or consumes its local Git configuration.
- Create a helper-owned literal detached Git worktree at the exact head commit.
- Back it with a helper-owned minimal Git database. Never run `git worktree add` against the source repository/common Git directory, register there, update a source ref, execute a source hook/filter, or write review objects into the source object database. A detached worktree owned solely by the helper-private Git database is required.
- Record the exact base SHA, head SHA, tree SHA, worktree mode, and control-artifact digests in helper-private state.

### WIP Content

- `--include-source-wip` requires the source `HEAD` to equal the resolved head and rejects conflicts, gitlinks in the actual source `HEAD` tree or active index, or capture races.
- Capture staged changes, unstaged changes, deletions, mode changes, symlinks, and every non-ignored untracked file into the helper-owned worktree.
- Charge regular-file contents and symlink-target bytes against one aggregate snapshot budget. Import all captured blobs through one bounded object-format-aware Git process, verify every returned object ID against a helper-computed digest, and apply all removals/additions through one NUL-delimited raw-path index update. Per-path Git subprocess loops are not an acceptable WIP capture implementation.
- Exclude ignored files. Copy the source `info/exclude` into the helper-owned inspection database with a 1 MiB bound, resolve only user-global `core.excludesFile` through `git config --global --includes` under the operating-system account home and source branch context, and pass that path as one command-line override while source-inspection commands suppress source-local, system, and global Git configuration. This preserves tracked repository ignores, the frozen source `info/exclude`, configured user-global excludes, and the default `$XDG_CONFIG_HOME/git/ignore` or `$HOME/.config/git/ignore` without enabling unrelated hooks, aliases, filters, or diff commands.
- Apply the same file, entry-count, byte, symlink, and secret-scan budgets used for clean evidence.
- Bind the result to a deterministic WIP digest plus the base/head/tree identity and source-state observations before and after capture.
- Drive the rendered diff, changed-path inventory, blob scan, prompt, and reviewer-visible files from that same captured artifact. Never scan one tree while reviewing another.
- Preserve the original source `HEAD` in the helper-private Git database and additionally scan its `HEAD`-to-snapshot delta paths and original-`HEAD`-side raw blobs. The current snapshot side is already covered by the complete snapshot scan. Together these checks supplement the base-to-snapshot diff so a WIP deletion or reversion cannot hide sensitive content that remains reachable from the original source `HEAD`.
- Treat the WIP digest as fixed review-only artifact evidence. It is not an authored Git commit and cannot count for formal PR-readiness or merge-ready review.

The detached worktree contains Git metadata sufficient for read-only `git` inspection, but its database and administrative files stay helper-owned and immutable to model tools. Reviewer-visible control artifacts live outside tracked content and are independently identity/digest checked. Cleanup is idempotent and removes only helper-owned external workspace content; it never prunes or mutates the source repository or another worktree.

Source `.codex-tmp` content has no helper-status filter. Ordinary Git ignore/status semantics apply, any reported record makes clean mode dirty, and WIP capture rejects `.codex-tmp` as a reserved helper path. Stateful artifacts retained under `/tmp` can survive helper workspace cleanup, but they are not durable across reboot or host temporary-file cleanup; harvest required evidence before relying on either event boundary.

Gitlinks present only in the selected review artifact remain uninitialized and unfetched. A source checkout whose actual `HEAD` tree or active index contains a gitlink is unsupported and fails closed before source status inspection. A partial clone with missing required objects fails closed instead of contacting a promisor remote or prompting for authentication.

## Sensitive-Content And Egress Preflight

Before any network-backed Codex, Claude Code, or Copilot run, the helper checks the complete selected artifact, exact diff, changed paths, raw changed blobs, symlink targets, reviewer controls, and prompt. It rejects escaping symlinks, credential-like paths, and high-confidence secret patterns. The endpoint commit/tag metadata check scans human metadata plus both the complete joined raw Base64 body and strict decoded bytes of structured `gpgsig`, `gpgsig-sha256`, and nested `mergetag` signature blocks; line wrapping or encoding therefore cannot hide a credential in reviewer-readable raw Git objects. WIP mode includes non-ignored untracked files in both capture and scanning, plus the original source `HEAD`-to-snapshot delta paths and original-`HEAD`-side raw blobs from the helper-private Git database; the complete snapshot scan covers the current side.

The scanner reports only side/path/rule metadata, never the matched value. Exact helper-catalog synthetic fixtures may suppress only their declared finding. A successful check writes retained `preflight.json` before executable discovery or model launch.

## Claude Combined Runtime

Only Claude Code `2.1.212` is eligible, and only after the fixed Anthropic signing-key fingerprint verifies that release's signed per-version manifest and the manifest checksum matches the native platform binary. Credential-free version/help probes validate the invoked public flags and the v2.1.212 `dontAsk`/safe-mode contract before authentication or review data is exposed. Native sandbox availability and inline settings are then requested fail-closed on the actual review launch; because the init schema does not expose effective sandbox fields, evidence labels them requested rather than independently verified. A different release remains blocked until its read-only permission, path-rule, sandbox, and output semantics receive equivalent evidence and the exact supported-version contract is deliberately updated.

Every Claude review then uses one combined runtime:

- on WSL2, mount provenance must prove both the source checkout and external review container use supported local native Linux filesystems; Windows-backed provenance is blocked and unprovable provenance is inconclusive;
- on Linux and WSL2, both `bubblewrap` and `socat` must pass fixed-path ownership, mode, native-ELF, architecture, and bounded identity validation; the selected directories are then placed before all other host-tool directories in Claude's final `PATH`, and resolution of both names must reproduce the exact selected executables before authentication or review launch;
- cwd is the helper-owned detached review worktree;
- `HOME` is the current account's real home resolved from the operating-system account database, not a caller-controlled override;
- helper-owned temporary paths are used for CLI scratch and bounded artifacts;
- the trusted ordinary Claude control plane may use its supported authentication/configuration paths in real `HOME`, including admin-managed policy;
- `dontAsk` mode exposes `Read`, `Grep`, and `Glob` for detached-workspace review, explicitly allows `Read(./**)`, automatically denies unmatched permission requests, and uses deny-first rules for sensitive HOME paths, `/proc`, and `/dev`;
- `Bash` is exposed only through Claude Code's non-prompting read-only command policy; recognized Bash file readers inherit workspace Read rules, arbitrary interpreters are outside that non-prompting set, and `sandbox.autoAllowBashIfSandboxed` is requested false; the init schema cannot expose merged admin-managed permission arrays or prove the requested sandbox settings;
- every accepted stream has one first `system/init` that proves effective `dontAsk` mode, exact tools, requested model, and authentication indicator, followed by one matching last result;
- the native-sandbox request sets `failIfUnavailable`, denies unsandboxed-command escape, requests authentication/proxy removal from sandboxed commands, denies Bash reads across the original source checkout, per-UID review namespace, real `HOME`, `/proc`, and `/dev`, re-opens only the current detached workspace and private Git view, and requests write denials for the worktree and real `HOME`.
- credential-free probes use Claude Code's broad subprocess scrub, while the model-backed launch disables it because v2.1.212 otherwise forces effective permission mode to `default`; sandboxed-Bash credential deny rules and the separately disabled hook/MCP/plugin/skill/slash surfaces form the compatible runtime boundary.
- immediately before launch, the Claude provider records whether the exact `.claude/.cc-writes` entry is absent and binds any already-existing real `.claude` parent's filesystem identity; after normal return or bounded teardown of the managed process group, it may use no-follow directory descriptors to verify only an exact empty, current-user-owned `0700` staging directory newly created by that attempt. It atomically moves that exact entry into helper-private quarantine, re-proves the opened inode and emptiness there, and only then removes it non-recursively before common validation. Pre-existing entries are not cleaned; a newly created empty parent is independently quarantined and identity-checked before removal, a swapped candidate at either layer is retained in quarantine and rejected, and all other topology remains subject to the unchanged validator. An exception-path cleanup or validation rejection is only a secondary redacted diagnostic and never replaces the primary supervision or forwarded-signal exception.
- after every completed Claude attempt, exact external-workspace validation must confirm the worktree snapshot, private Git state, diff, and prompt are unchanged before a result or model fallback is accepted.

The helper does not make a separate model-backed behavioral request before every review. It relies on the publisher-verified exact-version pin, the validated CLI contract, the documented `dontAsk` baseline, the workspace file allowlist, explicit tool/path denials, strict effective init/result evidence, the requested `failIfUnavailable` launch behavior, and post-attempt exact state validation. Admin-managed policy is part of the trusted ordinary CLI control plane. Observable init or workspace changes fail closed, but prompt instructions, merged managed permissions, and requested sandbox settings are not reported as independently observed OS enforcement. Post-attempt validation rejects observable review-workspace or private-Git mutation as terminal `permission-mismatch`; it does not prove that no transient write or out-of-workspace side effect occurred.

Authentication precedence is:

1. `ANTHROPIC_API_KEY`
2. `CLAUDE_CODE_OAUTH_TOKEN`
3. ordinary local login

The helper strips both explicit variables, tests them only for non-emptiness, and opaque-forwards only the winning value. It never parses, logs, writes to disk, projects into a temporary HOME, stages, brokers, replaces, or persists that value. Ordinary Keychain/credential-file lookup and refresh are Claude Code control-plane behavior. Before any review prompt enters the child process, bounded redacted `auth status --json` evidence must match the selected first-party provider/method/API-key-source contract. Valid JSON is parsed before process-status classification because Claude Code 2.1.212 uses a nonzero exit for `loggedIn: false`; that outcome is blocked authentication with the carrier-specific recovery action. The actual init event cross-checks its authentication indicator. Requested carrier and effective CLI fields are recorded separately.

A rejected explicit carrier or ordinary login is `blocked-authentication`. The operator action is respectively: unset/replace `ANTHROPIC_API_KEY`, unset/replace `CLAUDE_CODE_OAUTH_TOKEN`, or run `claude auth login`. Authentication failure never authorizes Copilot fallback.

Read [claude-runtime-trust.md](claude-runtime-trust.md) for provenance, native sandbox, HOME/tool separation, platform, network, and output details.

## Reviewer Output And State

Reviewer stdout/stderr stream to complete per-attempt files with finite deadlines and byte ceilings. Only bounded heads/tails are retained for classification. Timeouts, overflow, drain failure, or retained descendants terminate the containment unit and produce `inconclusive`.

Only a validated non-empty terminal artifact counts. Every attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, workspace content mode, exact range or WIP digest, and bounded log paths. Repository-controlled partial result text never authorizes authentication, entitlement, or fallback classification.

Stateful final artifacts survive helper workspace cleanup inside the external per-run container, subject to the `/tmp` reboot and host-cleanup lifetime above. A retained fallback worktree is valid only when its preflight, mode, exact range, and clean-tree or WIP digest match the requested fallback evidence.

New external state uses an exact v2 marker/schema pair. Management-only legacy compatibility accepts v1 only at the historical exact `<canonical-source>/.codex-tmp/<generated-container>` layout with every serialized workspace path bound to that state directory. Such v1 state can be inspected, waited, finalized, or cleaned in place, including through the bounded cleanup worker, but it cannot enter `run-state`, launch another reviewer, migrate into `/tmp`, or satisfy v2 retained-fallback trust. The source-local root and exact-mode-`0700` state directory are opened and revalidated through no-follow descriptors. Cleanup state-directory identity binds path and open descriptor with stable device, inode, mode, and owner metadata; entry churn beneath the same directory must not invalidate that binding, while path replacement must still fail closed. Only this authenticated v1 path may migrate a safe legacy lock, including an empty owner-owned mode-`0664` `cleanup.lock`: after the exclusive lock is acquired, the helper revalidates both directories and the lock identity/mode before `fchmod(0600)`, `fsync`, and exact mode-`0600` validation. V2 requires a private mode-`0600` lock from the start; every unsafe, nonempty writable, linked, or replaced legacy lock fails closed without workspace removal.

## Terminal States

- exit `0`: a non-empty validated terminal artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if policy permits
- other nonzero: blocked or failed; inspect bounded state/log evidence
- `stateful final` prints only the saved terminal artifact on success
- deterministic Codex-runtime absence after matching preflight may retain the worktree for the clean-context reviewer fallback
- workspace cleanup failure is terminal nonzero even when a clean artifact exists

## Deliberate Omissions

The helper does not support generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, reviewer-visible Git shims, arbitrary child argv, report sinks, legacy helper names, source-common-dir worktree registration, or helper-managed Claude credential transport. WIP capture is available only through the explicit `--include-source-wip` boundary.
