# Isolated Review Helper Contract

The supported low-level helper is:

```bash
$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review
```

It runs one diagnostic supplied-diff reviewer against one immutable artifact in a helper-owned private-minimal-Git worktree. It is retained for compatibility, helper-security maintenance, and targeted runtime debugging. It is not the canonical implementation of single, double, or triple review; no result from this helper satisfies a named review lane. New state is machine-labeled `review_contract: supplied-diff-private-git` and `named_lane_eligible: false`.

## CLI

Legacy helper Codex foreground invocation:

```bash
isolated_review \
  --repo /path/to/repo \
  --reviewer codex \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

Stateful Claude diagnostic:

```bash
isolated_review stateful start \
  --repo /path/to/repo \
  --reviewer claude \
  --egress-consent explicit-claude-review \
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

Review commands accept repeatable `--synthetic-secret-exemption <id>` selections for helper-owned historical migration envelopes. Read [synthetic-token-fixtures.md](synthetic-token-fixtures.md) before changing the catalog or selecting an exemption.

`stateful start` returns the helper-generated external per-run container as `state_dir`. Always pass that exact path with `--state-dir`; it is not positional. `stateful wait --timeout-seconds` accepts only a non-negative finite value, bounds the caller's wait, and does not kill or downgrade a healthy reviewer. `stateful cleanup` explicitly removes a retained review worktree while preserving state artifacts in that container.

The parent acquires an exclusive runner lock before spawn and passes its file descriptor to the child for the child's full lifetime. Cross-process `status` / `wait` trusts that lock, not PID existence, so a reused PID cannot masquerade as the review runner.

## Low-Level Helper Reviewers

`--reviewer codex`:

1. `gpt-5.6-sol`, `xhigh`
2. `gpt-5.5`, `xhigh`, only after explicit model entitlement/policy denial

This legacy supplied-diff Codex runtime does not load the normal instruction stack or provide the separate clean Git worktree required by canonical single review. Its result is diagnostic-only.

`--reviewer claude`:

1. Claude Code `claude-opus-4-8`, `max`
2. Claude Code `claude-opus-4-7`, `max`, only after explicit organization-policy or model-entitlement denial for Opus 4.8
3. Copilot CLI `claude-opus-4-8`, `max`, only when the verified Claude runtime is deterministically unavailable or both Claude models are entitlement-blocked and separate consent authorizes fallback
4. Copilot CLI `claude-opus-4-7`, `max`, only after the same explicit organization-policy or model-entitlement denial

The low-level Claude helper requires either `--egress-consent explicit-claude-review` or `--egress-consent explicit-claude-with-copilot-fallback`. `explicit-claude-review` authorizes Anthropic only. `explicit-claude-with-copilot-fallback` is valid only after the user separately requests and authorizes both Anthropic review and this compatibility Copilot fallback. Named single/double/triple phrases are not helper consent markers. Authentication failure never becomes fallback eligibility, and no Copilot artifact counts as Claude Code.

Every new state and `egress.json` record exposes `review_contract: supplied-diff-private-git` and `named_lane_eligible: false`; `stateful status` returns both fields. `attempts[].runtime` remains the authoritative actual backend. Consumers must not infer a named lane from the requested helper reviewer or exit `0`. The foreground compatibility command likewise prints only the raw helper artifact, and `stateful final` prints the saved artifact rather than a named-lane envelope. Automation that needs machine-readable contract metadata must use `stateful status`; it must never ingest foreground stdout or `stateful final` as named-review evidence.

Model verification normalizes punctuation only and requires exact equality. Capacity, overload, rate limits, timeouts, network/5xx errors, missing artifacts, silent substitution, and findings never trigger a model downgrade. Fallback classification uses stderr plus explicit structured CLI error events and error-schema fields only; repository-controlled partial result text never authorizes authentication, entitlement, or fallback classification.

## Detached Review Worktree

Clean and WIP are two content variants of the same low-level review workspace and runtime boundary.

The helper places the detached worktree, private Git database, control artifacts, logs, and state outside the source checkout. Its fixed base is `/tmp`, resolved to a canonical real directory that must be root-owned with exact mode `01777`. Beneath that base it creates current-user-owned exact-`0700` namespaces for `codex-isolated-review-uid-<effective-uid>` and the SHA-256 of the canonical source path, then an exact generated per-run container. Short-lived pre-container ancestry/source-inspection directories and bounded spill files use the same verified canonical base and are removed before the operation that creates them returns. No caller-controlled `TMPDIR` or source path selects another root. Claude's publisher-verified executable snapshot is also run from this container during credential-free safe-mode preflight, so a `noexec` temporary mount fails before authentication or review content is exposed.

### Clean Content

- Resolve `--base-ref` and `--head-ref` to commits and require base to be an ancestor of head. Range admission runs through a helper-owned sanitized Git view that reads only the source object directory with commit-graph acceleration disabled; source configuration, replacement refs, `.git/info/grafts`, and cached commit-graph parent edges cannot rewrite the accepted graph. Before a false ancestry result is accepted, a bounded zero-output `rev-list --quiet --missing=error` walk must prove both endpoint histories traversable.
- Require no staged changes, unstaged changes, conflicts, or non-ignored untracked files. Inspect actual source `HEAD`, the object directory, and exact per-worktree index through a short-lived helper-owned Git database; operational `status`, `diff`, `ls-files`, and `ls-tree` must not load source-local hooks, filters, diff drivers, aliases, or other repository configuration.
- Reject every gitlink found in either actual source `HEAD` or the active index before source status inspection, including a staged deletion or replacement of a committed gitlink.
- Create a helper-owned literal detached Git worktree at the exact head commit.
- Back it with a helper-owned private minimal Git database. Never run `git worktree add` against the source common directory, register there, update a source ref, execute a source hook/filter, or write review objects into the source object database.
- Record exact base SHA, head SHA, tree SHA, workspace mode, and control-artifact digests in helper-private state.

### WIP Content

- `--include-source-wip` requires source `HEAD` to equal the resolved head and rejects conflicts, source/index gitlinks, and capture races.
- Capture staged changes, unstaged changes, deletions, mode changes, symlinks, and every non-ignored untracked file into the helper-owned worktree.
- Charge regular-file contents and symlink-target bytes against one aggregate snapshot budget. Import captured blobs through one bounded object-format-aware Git process, verify every returned object ID against a helper digest, and apply the complete NUL-delimited raw-path overlay through one index update.
- Exclude ignored files according to the source worktree's effective path semantics without letting source configuration execute during operational inspection. A bounded config-only `git config --includes` query under the operating-system account home and actual worktree context selects only the final `core.excludesFile` plus typed `core.ignoreCase` and `core.precomposeUnicode` values. The helper secure-reads and freezes the selected excludes bytes, then gives operational Git only those validated path-semantics settings. Source hooks, aliases, filters, and diff commands remain disabled; `core.filemode=true` remains hardening so source configuration cannot hide a real mode-only WIP change.
- Apply the clean-mode file, entry-count, byte, symlink, and secret-scan budgets.
- Bind the snapshot to a deterministic WIP digest plus base/head/tree identity and source-state observations before and after capture.
- Drive rendered diff, changed-path inventory, blob scan, prompt, and reviewer-visible files from that same captured artifact.
- Preserve original source `HEAD` in the helper-private database and scan its `HEAD`-to-snapshot paths and original-`HEAD` raw blobs so a WIP deletion or reversion cannot hide sensitive content.
- Treat the WIP digest as fixed review-only artifact evidence. It is not an authored commit and cannot count for PR-readiness or merge-ready review.

The worktree contains Git metadata sufficient for read-only inspection, but its database and administrative files remain helper-owned and immutable to model tools. Reviewer-visible control artifacts live outside tracked content and are independently identity/digest checked. Cleanup is idempotent, removes only helper-owned external workspace content, and never prunes or mutates the source repository or another worktree.

Source `.codex-tmp` content has no helper-status exemption. Ordinary Git ignore/status semantics apply, any reported record makes clean mode dirty, and WIP capture rejects `.codex-tmp` as reserved. Stateful artifacts retained under `/tmp` are operational evidence, not durable storage.

Gitlinks present only in the selected artifact remain uninitialized and unfetched. A partial clone with missing required objects fails closed instead of contacting a promisor remote or prompting for authentication.

## Sensitive-Content And Egress Preflight

Before any network-backed Codex, Claude Code, or Copilot run, the helper checks the complete selected artifact, exact diff, changed paths, raw changed blobs, symlink targets, reviewer controls, and prompt. It rejects escaping symlinks, credential-like paths, and high-confidence secret patterns. Endpoint commit/tag metadata scanning covers human metadata plus joined raw Base64 and strict decoded bytes of structured signature blocks. WIP mode includes non-ignored untracked files and the original-source-HEAD delta evidence.

The scanner reports only side/path/rule metadata, never the matched value. Exact helper-catalog synthetic fixtures may suppress only their declared finding. A successful check writes retained `preflight.json` before executable discovery or model launch.

## Claude Combined Runtime

This section applies only to the diagnostic helper. The named Claude lane is a separate direct launch governed by [canonical-claude-lane.md](canonical-claude-lane.md).

Only Claude Code `2.1.212` is eligible, and only after the fixed Anthropic signing-key fingerprint verifies that release's signed per-version manifest and the manifest checksum matches the native platform binary. Credential-free version/help probes validate the invoked public flags and the exact `dontAsk`/safe-mode contract before authentication or review data is exposed. Native sandbox availability and inline settings are requested fail-closed on the actual review launch. A different release remains blocked until its read-only permission, path-rule, sandbox, and output semantics receive equivalent evidence and the exact supported-version contract is deliberately updated.

Every helper Claude review uses one combined runtime:

- on WSL2, mount provenance must prove both source checkout and external review container use supported local native Linux filesystems;
- on Linux and WSL2, `bubblewrap` and `socat` must pass fixed-path ownership, mode, native-ELF, architecture, and bounded identity validation; their selected directories lead Claude's final `PATH`, and exact resolution is rechecked before launch;
- cwd is the helper-owned detached review worktree and `HOME` is the current account's real home resolved from the operating-system account database, not a caller-controlled override;
- helper-owned temporary paths hold CLI scratch and bounded artifacts;
- the trusted ordinary Claude control plane may use supported authentication/configuration paths in real `HOME`, including admin-managed policy;
- `dontAsk` exposes `Read`, `Grep`, and `Glob`, explicitly allows `Read(./**)`, and automatically denies unmatched permission requests; sensitive real-HOME roots, `/proc`, and `/dev` have deny-first rules;
- `Bash` is exposed only through Claude Code's non-prompting read-only command policy; recognized Bash file readers inherit workspace rules, arbitrary interpreters are outside that set, and sandboxed Bash auto-approval is requested disabled;
- every accepted stream begins with one `system/init` proving effective `dontAsk`, exact tools, requested model, and authentication indicator, then ends with one matching terminal result;
- the native-sandbox request sets `failIfUnavailable`, forbids unsandboxed-command escape, removes authentication/proxy variables from sandboxed commands, requests global write denial, denies reads of the original source checkout, other review state, sensitive real-HOME roots, `/proc`, and `/dev`, and lists only the current worktree and private Git view in `allowRead`;
- after every completed attempt, exact external-workspace validation confirms the snapshot, private Git state, diff, and prompt are unchanged before accepting a result or model fallback.

This is a selected-deny native-sandbox boundary, not a global host-read whitelist. `allowRead` records the intended review scope but does not prove every other host path unreadable; sandboxed Bash can technically read a path outside the worktree when no `denyRead` covers it. The prompt/model contract therefore forbids all outside-workspace reads. Claude Code 2.1.212 `system/init` and capability output do not prove the final merged sandbox, merged admin-managed permission arrays, or path-rule evaluation. Persist those controls only as requested configuration. Post-attempt validation proves the inspected state at validation time; it cannot prove no transient write or outside-workspace read/side effect occurred.

Absolute workspace and diff-file paths in an operator-supplied Claude prompt are projected only when they appear as standalone path tokens; lexically bounded workspace descendants without empty or upward-traversal segments are also projected. URI-embedded, suffix-extended, traversing, or otherwise ambiguous occurrences fail closed.

Authentication precedence is:

1. `ANTHROPIC_API_KEY`
2. `CLAUDE_CODE_OAUTH_TOKEN`
3. ordinary local login

The helper strips both explicit variables, tests them only for non-emptiness, and opaque-forwards only the winning value. It never parses, logs, writes to disk, projects into a temporary HOME, stages, brokers, replaces, persists, or writes back that value. Ordinary Keychain/credential-file lookup and refresh are Claude Code control-plane behavior. Before any review prompt enters the child process, bounded redacted `auth status --json` evidence must match the selected first-party provider/method/API-key-source contract. The init event cross-checks its authentication indicator; requested carrier and effective CLI fields are recorded separately.

A rejected explicit carrier or ordinary login is `blocked-authentication`. The operator action is respectively to unset/replace `ANTHROPIC_API_KEY`, unset/replace `CLAUDE_CODE_OAUTH_TOKEN`, or run `claude auth login`. Authentication failure never authorizes Copilot fallback.

Read [claude-runtime-trust.md](claude-runtime-trust.md) for provenance, selected-deny sandbox, real-HOME/tool separation, platform, network, and output details.

## Reviewer Output And State

Reviewer stdout/stderr stream to complete per-attempt files with finite deadlines and byte ceilings. Only bounded heads/tails are retained for classification. Timeouts, overflow, drain failure, or retained descendants terminate the containment unit and produce `inconclusive`.

Only a validated non-empty terminal artifact counts as a low-level result. Every attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, workspace content mode, exact range or WIP digest, and bounded log paths. Repository-controlled partial result text never authorizes authentication, entitlement, or fallback classification.

Stateful final artifacts survive workspace cleanup inside the external per-run container, subject to `/tmp` lifetime. A retained worktree is diagnostic-only and cannot be handed to, satisfy, or supply a canonical named lane.

New external state uses an exact v2 marker/schema pair. Management-only legacy compatibility accepts v1 only at the historical exact `<canonical-source>/.codex-tmp/<generated-container>` layout with every serialized workspace path bound to that state directory. Such v1 state can be inspected, waited, finalized, or cleaned in place, including through the bounded cleanup worker, but it cannot enter `run-state`, launch another reviewer, migrate into `/tmp`, or satisfy v2 retained-workspace trust. The source-local root and exact-mode-`0700` state directory are opened and revalidated through no-follow descriptors. Cleanup state-directory identity binds path and open descriptor with stable device, inode, mode, and owner metadata; entry churn beneath the same directory inode does not invalidate that binding, while path replacement fails closed. Only this authenticated v1 path may migrate a safe legacy lock, including an empty owner-owned mode-`0664` `cleanup.lock`: after the exclusive lock is acquired, the helper revalidates both directories and the lock identity/mode before `fchmod(0600)`, `fsync`, and exact mode-`0600` validation. V2 requires a private mode-`0600` lock from the start; every unsafe, nonempty writable, linked, or replaced legacy lock fails closed without workspace removal.

## Terminal States

- exit `0`: a non-empty validated low-level artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if policy permits
- other nonzero: blocked or failed; inspect bounded state/log evidence
- `stateful final` prints only the saved low-level artifact on success
- deterministic helper runtime absence may retain the worktree only for bounded diagnosis; it never supplies named-lane evidence
- workspace cleanup failure is terminal nonzero even when a low-level artifact exists

## Deliberate Omissions

The helper does not support generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, reviewer-visible Git shims, arbitrary child argv, report sinks, legacy helper names, source-common-dir worktree registration, or helper-managed Claude credential transport. WIP capture is available only through explicit `--include-source-wip`.
