# Isolated Review Helper Contract

The canonical helper is:

```bash
$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review
```

It runs one low-level supplied-diff reviewer against one frozen Git range. It is retained for compatibility, helper-security maintenance, and targeted runtime debugging. It is diagnostic and never satisfies a named single, double, or triple review lane.

## CLI

Foreground compatibility mode:

```bash
isolated_review \
  --repo /path/to/repo \
  --reviewer codex \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

Stateful mode:

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
isolated_review stateful admission --state-dir <state_dir>
isolated_review stateful cleanup --state-dir <state_dir>
```

Add `--include-source-wip` only with separate explicit consent to include staged, unstaged, and non-ignored untracked source state. Clean committed-head content is the default.

Synthetic-token catalog inspection remains read-only:

```bash
isolated_review synthetic-tokens validate
isolated_review synthetic-tokens list --json
isolated_review synthetic-tokens get <id> --json
isolated_review synthetic-tokens list-exemptions --json
isolated_review synthetic-tokens audit-master --repo <path> --ref <sha> --exemption <id>
```

Always pass `--state-dir`; it is not positional. `stateful wait --timeout-seconds` accepts only a non-negative finite value, bounds the caller's wait, and does not kill or downgrade a healthy reviewer. `stateful cleanup` removes a retained helper workspace while preserving the state artifacts needed to explain the terminal result.

Canonical PR/master admission uses the separate direct `isolated_review secret-admission` command, which starts no reviewer. This helper's `stateful final` / `stateful admission` pair is retained only for an independently requested low-level helper run: collect `stateful final` first, then query `stateful admission` against that same state and current head. A head change invalidates both results.

## Low-Level Helper Reviewers

`--reviewer codex` uses:

1. `gpt-5.6-sol`, `xhigh`;
2. `gpt-5.5`, `xhigh`, only after explicit model-entitlement or organization-policy denial.

`--reviewer claude` uses:

1. Claude Code `claude-opus-4-8`, `max`;
2. Claude Code `claude-opus-4-7`, `max`, only after explicit model-entitlement or organization-policy denial for Opus 4.8;
3. Copilot CLI `claude-opus-4.8`, `max`, only when separately authorized and Claude Code is deterministically unavailable or both Claude models are entitlement-blocked;
4. Copilot CLI `claude-opus-4.7`, `max`, only after the same strict denial for Copilot Opus 4.8.

Authentication failure, capacity, overload, rate limit, timeout, network/5xx failure, malformed output, silent model substitution, or findings never authorize a downgrade. Copilot is an independently consented helper-only fallback and never counts as Claude Code in a named review shape.

Every new state and `egress.json` record is machine-labeled:

```text
review_contract: supplied-diff-private-git
named_lane_eligible: false
```

`stateful status` exposes those fields, while `attempts[].runtime` remains the authoritative actual backend. Consumers must not infer named-lane completion from the requested helper reviewer, exit `0`, or findings-only output. The foreground compatibility command likewise prints only the raw helper artifact and does not emit a machine envelope. Automation that needs machine-readable contract metadata must use `stateful status`; it must never ingest foreground stdout or `stateful final` as named-review evidence.

## Private Git Workspace

The helper requires `--base-ref` and `--head-ref`, resolves both to commits, and requires base to be an ancestor of head. It materializes a helper-owned detached worktree backed by a private minimal Git database. This `private-minimal-Git` scope contains the supplied diff plus only the endpoint tree/blob closure needed for bounded inspection; it is deliberately narrower than the complete clean Git worktree used by named lanes.

The modern review root lives under the system temporary root `/tmp`, outside the source checkout, in a private namespace owned by the current effective UID and bound to the canonical source path. The source checkout is read-only input and is never edited. The helper removes remote URLs, disables networked Git behavior, rejects unsafe symlinks and reserved control paths, and exposes only bounded read-only Git/source operations to the reviewer.

Without `--include-source-wip`, preparation requires the clean committed endpoint. With that explicit flag, the helper creates a helper-private composite from original source `HEAD` plus staged, unstaged, and non-ignored untracked state. It records the original source `HEAD`, exact private snapshot tree, WIP digest, and source-to-snapshot path evidence. A source mutation, WIP deletion or reversion, digest mismatch, unsupported special file, or ambiguous source state fails closed. WIP evidence is diagnostic only and cannot satisfy PR-readiness or merge-ready exact-commit gates.

Every reviewer receives a bounded findings-only prompt and supplied-diff control artifacts inside the helper workspace. Within that consented scope, tracked `.codex`, `.agents`, and environment files are intentionally readable, including tracked repository secrets. The helper does not initialize or fetch submodules; gitlink changes expose only the path, mode, and endpoint object IDs.

## Claude Runtime And Authentication

The direct named lane and this low-level helper accept only publisher-verified strict stable Claude Code releases `>=2.1.211,<3.0.0`. For the exact selected version, verification binds the fixed Anthropic release-signing key, signed per-version manifest, platform artifact size, and SHA-256 before any credential or review content reaches Claude. Native-format and platform checks reject scripts, interpreter wrappers, prereleases, unsupported platforms, and future major versions.

The helper materializes one private digest-verified executable snapshot after signed-artifact verification. Mandatory bounded credential-free `--version` and `--help` capability probes run against that same snapshot with empty stdin, fixed `/` cwd, and no prompt, credential, repository, range, PR, or workspace input. The observed version must match the manifest-selected version, and help must advertise each invoked option plus the reviewed safe-mode contract. The helper rechecks snapshot digest and mutable-source identity before acceptance. It never downloads or installs Claude and never changes an active symlink.

Authentication uses the publisher-verified ordinary CLI in real `HOME` with exact precedence `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. The parent opaque-forwards only the winning explicit value, removes lower-priority explicit sources, and checks `auth status --json` for the selected source without inspecting credential contents. The CLI may update ordinary CLI-owned authentication and runtime state in its trusted control plane, including credential refresh and possible cache or tool-result artifacts. Those side effects are not model-authorized review mutations. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable, and the helper does not take or verify a complete real-`HOME` diff.

A rejected API key yields `blocked-authentication` and asks the operator to unset or replace `ANTHROPIC_API_KEY`. A rejected OAuth token asks the operator to unset or replace `CLAUDE_CODE_OAUTH_TOKEN`. An expired or rejected ordinary login asks the operator to run `claude auth login`. Authentication is a pause boundary and never authorizes Copilot fallback. Capacity, quota, rate-limit, generic token-usage, ambiguous credential I/O, or a bare exit code is inconclusive rather than authentication evidence.

## Sandbox And Platform Boundary

Claude exposes exactly `Read`, `Grep`, `Glob`, and `Bash` under the helper's platform guard and native sandbox; Bash is sandboxed. Launch requests global write denial, critical sensitive-root read denial, no unsandboxed commands, and removal of secret environment variables from sandboxed tools. This is a selected-deny policy, not a global host-read whitelist. Sandboxed Bash can technically read a host path that is not covered by a selected deny; the prompt/model scope therefore forbids every read outside the detached helper workspace and its private Git scope. Record these controls as requested configuration. Capability or init output does not prove the final merged sandbox, managed permission arrays, or path-rule evaluation.

On macOS, the helper requires the reviewed native sandbox and a validated read-only launch profile. On Linux and positively identified WSL2, it requires the reviewed outer isolation runtime and rejects known DrvFS/Windows-backed runtime or workspace paths. Unknown platform, mount, namespace, filesystem, dependency, probe, process-containment, or cleanup evidence fails closed as blocked or inconclusive; it is never guessed safe.

For Claude, runtime preparation accepts only the same version range, signed-artifact evidence, same-snapshot version/help capability contract, requested model, and safe-mode/tool surface. Deterministic automatic absence or a cleanly missing non-security capability may reach an already-authorized helper fallback. Publisher-verification, explicit-override, sandbox, authentication, identity-race, or ambiguous-probe failures do not.

## Structured Output And Attempts

The helper records bounded stdout/stderr and complete per-attempt metadata outside reviewer-visible scope. It accepts findings only from the documented successful structured terminal shape with a nonempty result and verified requested/effective model. Explicit error states, malformed or partial output, permission denials, unexpected model usage, or nonzero ambiguous termination never become findings.

Each attempt records runtime, requested/effective model, requested/effective effort when observable, category, exit status, and bounded log paths. Model fallback requires strict machine-classified entitlement or organization-policy denial. Auxiliary model usage never replaces exact verification of the requested reviewer model.

`claude-runtime.json` records non-secret source discovery, selected version, signed-manifest and checksum state, capability evidence, authentication-source label, runtime phase, requested/effective model, terminal category, and bounded diagnostics. It never records credential values or bearer-capable metadata and does not claim future token validity.

## Secret Admission

Secret admission is independent of reviewer launch. Secret admission never delays, suppresses, redacts, or gates reviewer launch; a trusted reviewer receives the original consented tracked scope. The separate direct command is:

```bash
isolated_review secret-admission \
  --repo <repo> \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

It reports `review_contract: admission-only-no-reviewer`, starts no reviewer, and scans immutable Git trees without materializing a review workspace, diff, or prompt. Exit `0` means clean only with `temporary_cleanup_status: complete`; exit `1` means proved violations; exit `75` means inconclusive scan or otherwise-clean scan with incomplete temporary cleanup.

For each exact raw secret byte value, count occurrences globally in the complete tracked base and head trees and require `head_count <= base_count`. A first appearance or any growth blocks. Unchanged occurrences are omitted; deletions and moves pass. No unembedded counter is accepted as proof. Do not derive Base64, hex, URL-encoded, escaped, hashed, or other transformed values. Report only head-side added locations for positive-delta candidates, and classify incomplete count or location evidence as inconclusive.

For an independently requested stateful helper run, `stateful final` remains the reviewer-artifact operation and `stateful admission` remains an optional second query against the same state after the runner lock is released. A runner-sealed schema-v5 preflight receipt binds exact byte length and SHA-256; mutation, replacement, malformed receipt, missing seal, or a legacy schema without a receipt makes admission inconclusive without invalidating an independently valid reviewer final.

## State, Retention, And Cleanup

The parent acquires the runner lock before helper-private bytes are published and holds the same lease for the child lifetime. State markers bind the canonical source, review container, reviewer, egress consent, workspace identities, runtime artifacts, and cleanup ownership. `status`, `wait`, `final`, and cleanup validate those bindings with bounded no-follow reads.

New preparation publishes schema-v5 state in the external `/tmp` review root and binds a runner-sealed preflight receipt. Management-only compatibility never resumes an old reviewer: v1 is the source-local legacy workspace without private Git metadata and requires manual recovery; v2 through v4 are source-local compatibility records for the private-Git workspace shape. V2 and v3 remain readable but require manual recovery, while v4 permits bounded `status`, `final`, and cleanup; v4 admission is inconclusive because it has no v5 receipt.

Cleanup-only compatibility for the recorded `<canonical-source>/.codex-tmp/<generated-container>` layout cannot enter `run-state`. The legacy migration first proves a private source-local root, an exact-mode-`0700` state directory, and an empty owner-owned mode-`0664` `cleanup.lock`. Only after the exclusive lock is acquired, cleanup revalidates both directories and the lock identity/mode, performs `fchmod(0600)`, calls `fsync`, and requires exact mode-`0600` validation. Modern state requires a private mode-`0600` lock from creation. Any other legacy lock fails closed without workspace removal.

Workspace and control artifacts are identity-bound, owner-private, no-follow, size-bounded, and durably published before another phase trusts them. Schema-v4 state remains readable for status/final/cleanup but cannot supply schema-v5 admission evidence. Same-effective-UID hostile mutation remains part of the host trust boundary; the helper does not overclaim portable isolation from a peer process with the same account.

Source files are never edited. The detached workspace is removed after `stateful wait` unless `--keep-workspace` or a documented helper-only diagnostic condition retains it. `stateful cleanup` removes that workspace after diagnosis. Logs, preflight evidence, attempts metadata, `final.txt`, and cleanup errors remain in the state directory. Cleanup timeout, identity mismatch, or path replacement fails closed and leaves exact retained state for controlled diagnosis.

## Terminal States

### Reviewer Final

- exit `0`: a nonempty terminal final artifact exists;
- exit `75`: transient or capacity failure; retry only the same runtime/model when parent policy permits;
- other nonzero: blocked or failed; inspect `stateful status`, attempts, and bounded logs;
- `stateful final` prints only the saved terminal artifact on success;
- cleanup failure remains terminal nonzero even when a reviewer produced an artifact.

### Helper-State Secret Admission

- exit `0`: the sealed bounded summary is valid and clean;
- exit `1`: the valid summary reports one or more violations;
- exit `3`: the runner lock is still held and no terminal admission evidence exists;
- exit `75`: the audit, receipt, state, or cleanup evidence is inconclusive.

A successful reviewer final remains valid review evidence when helper-state admission exits `1` or `75`. Neither helper result is a hidden PR-readiness lane.

Claude Code publisher provenance is anchored to Anthropic's release-signing primary-key fingerprint `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`. For the exact selected version, the helper verifies `manifest.json.sig` over `manifest.json` from `downloads.claude.ai`, then requires the installed platform binary to match the manifest size and checksum. Platform signing and notarization may provide defense in depth but never substitute for the signed manifest.

## Deliberate Omissions

The helper does not implement a generic `auto` named lane, provider substitution for named review, implicit live-working-tree capture, arbitrary child argv, reviewer-visible Git shims, automatic installation, active-version switching, or unconsented Copilot egress. Its private-Git and explicit-WIP modes remain low-level diagnostic mechanisms only.
