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

Always pass `--state-dir`; it is not positional. `stateful wait --timeout-seconds` accepts only a non-negative finite value, bounds the caller's wait, and does not kill or downgrade a healthy reviewer. `stateful cleanup` explicitly removes a retained review worktree while preserving state artifacts.

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

### Clean Content

- Resolve `--base-ref` and `--head-ref` to commits and require base to be an ancestor of head.
- Require the source checkout to have no staged changes, unstaged changes, conflicts, dirty submodules, or non-ignored untracked files.
- Create a helper-owned literal detached Git worktree at the exact head commit.
- Back it with a helper-owned minimal Git database. Never run `git worktree add` against the source repository/common Git directory, register there, update a source ref, execute a source hook/filter, or write review objects into the source object database. A detached worktree owned solely by the helper-private Git database is required.
- Record the exact base SHA, head SHA, tree SHA, worktree mode, and control-artifact digests in helper-private state.

### WIP Content

- `--include-source-wip` requires the source `HEAD` to equal the resolved head and rejects conflicts, unsafe submodule state, or capture races.
- Capture staged changes, unstaged changes, deletions, mode changes, symlinks, and every non-ignored untracked file into the helper-owned worktree.
- Exclude ignored files. Apply the same file, entry-count, byte, symlink, and secret-scan budgets used for clean evidence.
- Bind the result to a deterministic WIP digest plus the base/head/tree identity and source-state observations before and after capture.
- Drive the rendered diff, changed-path inventory, blob scan, prompt, and reviewer-visible files from that same captured artifact. Never scan one tree while reviewing another.
- Treat the WIP digest as fixed review-only artifact evidence. It is not an authored Git commit and cannot count for formal PR-readiness or merge-ready review.

The detached worktree contains Git metadata sufficient for read-only `git` inspection, but its database and administrative files stay helper-owned and immutable to model tools. Reviewer-visible control artifacts live outside tracked content and are independently identity/digest checked. Cleanup is idempotent and removes only the helper-owned container; it never prunes or mutates the source repository or another worktree.

Submodules remain uninitialized and unfetched. A partial clone with missing required objects fails closed instead of contacting a promisor remote or prompting for authentication.

## Sensitive-Content And Egress Preflight

Before any network-backed Codex, Claude Code, or Copilot run, the helper checks the complete selected artifact, exact diff, changed paths, raw changed blobs, symlink targets, reviewer controls, and prompt. It rejects escaping symlinks, credential-like paths, and high-confidence secret patterns. WIP mode includes non-ignored untracked files in both capture and scanning.

The scanner reports only side/path/rule metadata, never the matched value. Exact helper-catalog synthetic fixtures may suppress only their declared finding. A successful check writes retained `preflight.json` before executable discovery or model launch.

## Claude Combined Runtime

Claude Code `>=2.1.212,<3.0.0` is eligible only after the fixed Anthropic signing-key fingerprint verifies the release's signed per-version manifest and the manifest checksum matches the native platform binary. Credential-free version/help probes validate the invoked public flags and the v2.1.212 plan/safe-mode contract before authentication or review data is exposed. Native sandbox availability and inline settings are then requested fail-closed on the actual review launch; because the init schema does not expose effective sandbox fields, evidence labels them requested rather than independently verified.

Every Claude review then uses one combined runtime:

- cwd is the helper-owned detached review worktree;
- `HOME` is the current account's real home resolved from the operating-system account database, not a caller-controlled override;
- helper-owned temporary paths are used for CLI scratch and bounded artifacts;
- the trusted ordinary Claude control plane may use its supported authentication/configuration paths in real `HOME`, including admin-managed policy;
- plan-mode `Read`, `Grep`, and `Glob` are exposed for detached-workspace review; the prompt forbids out-of-workspace reads and explicit file-tool rules deny sensitive HOME paths, but `--allowedTools` is not claimed as a filesystem allowlist;
- `sandbox.autoAllowBashIfSandboxed` is requested false; the model prompt and verified effective plan/tool surface require read-only behavior, but the init schema cannot expose merged admin-managed permission arrays or prove that no preapproval exists;
- every accepted stream has one first `system/init` that proves effective plan mode, exact tools, requested model, and authentication indicator, followed by one matching last result;
- the native-sandbox request sets `failIfUnavailable`, denies unsandboxed-command escape, requests authentication/proxy removal from sandboxed commands, re-opens only the detached workspace and private Git view inside the broader real-`HOME` Bash read denial, and requests write denials for the worktree and real `HOME`.
- credential-free probes use Claude Code's broad subprocess scrub, while the model-backed launch disables it because v2.1.212 otherwise forces effective permission mode to `default`; sandboxed-Bash credential deny rules and the separately disabled hook/MCP/plugin/skill/slash surfaces form the compatible runtime boundary.
- immediately before launch, the Claude provider records whether the exact `.claude/.cc-writes` entry is absent and binds any already-existing real `.claude` parent's filesystem identity; immediately before common validation, it may use no-follow directory descriptors to verify and non-recursively remove only an exact empty, current-user-owned `0700` staging directory newly created by that attempt, while pre-existing entries are not cleaned; a newly created empty parent is atomically quarantined and identity-checked before removal, a swapped candidate is retained in quarantine and rejected, and all other topology remains subject to the unchanged validator.
- after every completed Claude attempt, exact external-workspace validation must confirm the worktree snapshot, private Git state, diff, and prompt are unchanged before a result or model fallback is accepted.

The helper does not make a separate model-backed behavioral request before every review. It relies on the publisher-verified version floor, the validated CLI contract, the documented plan-mode baseline, explicit tool denials, strict effective init/result evidence, the requested `failIfUnavailable` launch behavior, and post-attempt exact state validation. Admin-managed policy is part of the trusted ordinary CLI control plane. Observable init or workspace changes fail closed, but prompt instructions, merged managed permissions, and requested sandbox settings are not reported as independently observed OS enforcement. Post-attempt validation rejects observable review-workspace or private-Git mutation as terminal `permission-mismatch`; it does not prove that no transient write or out-of-workspace side effect occurred.

Authentication precedence is:

1. `ANTHROPIC_API_KEY`
2. `CLAUDE_CODE_OAUTH_TOKEN`
3. ordinary local login

The helper strips both explicit variables, tests them only for non-emptiness, and opaque-forwards only the winning value. It never parses, logs, writes to disk, projects into a temporary HOME, stages, brokers, replaces, or persists that value. Ordinary Keychain/credential-file lookup and refresh are Claude Code control-plane behavior. Before any review prompt enters the child process, bounded redacted `auth status --json` evidence must match the selected first-party provider/method/API-key-source contract; the actual init event cross-checks its authentication indicator. Requested carrier and effective CLI fields are recorded separately.

A rejected explicit carrier or ordinary login is `blocked-authentication`. The operator action is respectively: unset/replace `ANTHROPIC_API_KEY`, unset/replace `CLAUDE_CODE_OAUTH_TOKEN`, or run `claude auth login`. Authentication failure never authorizes Copilot fallback.

Read [claude-runtime-trust.md](claude-runtime-trust.md) for provenance, native sandbox, HOME/tool separation, platform, network, and output details.

## Reviewer Output And State

Reviewer stdout/stderr stream to complete per-attempt files with finite deadlines and byte ceilings. Only bounded heads/tails are retained for classification. Timeouts, overflow, drain failure, or retained descendants terminate the containment unit and produce `inconclusive`.

Only a validated non-empty terminal artifact counts. Every attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, workspace content mode, exact range or WIP digest, and bounded log paths. Repository-controlled partial result text never authorizes authentication, entitlement, or fallback classification.

Stateful final artifacts survive workspace cleanup. A retained fallback worktree is valid only when its preflight, mode, exact range, and clean-tree or WIP digest match the requested fallback evidence.

## Terminal States

- exit `0`: a non-empty validated terminal artifact exists
- exit `75`: transient/capacity failure; retry only the same runtime/model if policy permits
- other nonzero: blocked or failed; inspect bounded state/log evidence
- `stateful final` prints only the saved terminal artifact on success
- deterministic Codex-runtime absence after matching preflight may retain the worktree for the clean-context reviewer fallback
- workspace cleanup failure is terminal nonzero even when a clean artifact exists

## Deliberate Omissions

The helper does not support generic `auto` lanes, OpenCode, Cursor Agent, `gh-copilot`, `codex-parallel`, reviewer-visible Git shims, arbitrary child argv, report sinks, legacy helper names, source-common-dir worktree registration, or helper-managed Claude credential transport. WIP capture is available only through the explicit `--include-source-wip` boundary.
