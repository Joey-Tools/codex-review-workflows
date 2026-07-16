---
name: review-orchestration-playbook
description: Orchestrate Joey's single, double, and triple code reviews plus PR readiness through one policy-bound workflow, and govern Claude Code runtime trust across macOS, Linux, and WSL2. Use for helper-backed or clean-context Codex review, Claude-family review, GitHub `@codex review`, review-only child prompts, PR comment/CI fix loops, merge-readiness, or Claude Code CLI provenance, version-policy, platform-capability, and upgrade-compatibility changes. Local double review means one Codex lane plus one Claude-family lane; triple review adds the current-head GitHub Codex PR review. Review-only children that forbid orchestration should inspect directly and return findings only.
---

# Review Orchestration Playbook

## Review Shapes

Count independent reviewer families, not retries, helper implementations, or fallback attempts.

- Single/local internal review: one clean-context Codex lane.
- Local double review / `本地双重 review`: the Codex lane plus one Claude-family lane.
- Triple review / `三重 review`: local double review plus GitHub Codex review on the current PR head, triggered automatically by the repository or with the exact `@codex review` comment.
- PR readiness: the requested review shape plus required CI, PR comments/conversation resolution, and branch/base checks. Those delivery gates do not increase the review count.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user consent for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. That consent covers any necessary tracked code in the named repository at the frozen head, the generated diff, and the review prompt/result sent to OpenAI Codex, Anthropic Claude Code, and, only under the pinned fallback policy, Microsoft/GitHub Copilot. Triple review additionally authorizes current-head GitHub Codex review. It never covers credentials, untracked files, unrelated repositories, broad workspace dumps, or home-directory content. Read [egress-consent.md](references/egress-consent.md) before starting those lanes.

## Reviewer And Runtime Policy

The helper and the clean-context `reviewer` agent use explicit models; they do not inherit a possibly older parent or global default. Model selection remains pinned, while Claude Code CLI compatibility is version-range and capability based.

- Codex CLI: `gpt-5.6-sol` with `xhigh`; fall back to `gpt-5.5` with `xhigh` only after an explicit account, plan, organization-policy, or model-entitlement denial.
- Claude Code: accept publisher-verified release versions `>=2.1.187,<3.0.0` that pass the required capability probes inside a helper-owned outer sandbox; do not pin the CLI to `latest` or one current patch. Support macOS through Seatbelt and an official thin arm64 or x64 Mach-O artifact; x64 may run through Rosetta on Apple Silicon, so the manifest artifact is selected from the binary architecture rather than requiring exact host-CPU equality. Support Linux/WSL2 through `bubblewrap`, `socat`, and a native ELF matching the host architecture and libc. WSL1 and native Windows are unsupported. Positive WSL2 classification requires an explicit WSL2 or Microsoft-standard kernel identity marker plus bounded mount-table provenance for every executable, credential, review-state, and runtime path. `/run/WSL`, `WSL_INTEROP`, distro environment, and binfmt evidence are weak WSL-presence signals because they do not distinguish WSL1 from WSL2; a custom kernel without a recognizable WSL2 identity marker is unsupported when any such signal remains. A guest that removes both the marker and every WSL-presence signal is indistinguishable from native Linux and follows that classification, so the common Linux/WSL mount guard independently rejects positive Windows-backed DrvFS provenance reached through custom automounts, bind mounts, or aliases. Positively identified WSL2 also keeps the fast literal `/mnt/<drive>` rejection and accepts only a conservative set of local native Linux filesystem types, while layered/shared/loop-backed or unknown filesystems remain inspection-inconclusive. Unreadable, malformed, oversized, non-canonical, or non-covering mount information also fails closed. Use ordinary local Claude login by default with `claude-opus-4-8` and `max`; macOS refreshes only when the credential cannot cover the current model attempt, using that attempt's model in the restricted no-tools warmup before re-reading and validating the Keychain item. Linux/WSL2 never refreshes local login: every model attempt independently validates the current user's exact-mode-`0600` credential and mounts only a new helper-owned read-only private copy for runtime authentication. Its model-visible file-tool boundary uses `dontAsk`, exposes only `Read`, allows only `Read(./**)`, rejects prompt file mentions, denies every other synthetic-root mount, and rechecks immediately before sandbox serialization that no workspace symlink resolves outside the frozen workspace. An explicitly exported `ANTHROPIC_API_KEY` remains an optional authentication override, with `/proc` denied to file tools. Fall back to `claude-opus-4-7` with `max` only after an explicit account, plan, organization-policy, or model-entitlement denial for Opus 4.8. Read [claude-runtime-trust.md](references/claude-runtime-trust.md) before changing version, provenance, platform, sandbox, capability-probe, or credential behavior.
- Copilot CLI: use only after Claude Code is unavailable, has no usable local/API authentication, or both Claude Code Opus models are entitlement-blocked; use `claude-opus-4.8` with `max`, then fall back to `claude-opus-4.7` with `max` only after the same explicit account, plan, organization-policy, or model-entitlement denial for Opus 4.8.

On macOS, every Claude model attempt revalidates the publisher-verified executable snapshot, re-exports authoritative user/admin/system trust settings, rebuilds a certificate-only helper bundle, and rechecks the current-account Keychain credential immediately before launch. The helper does not read or bridge `~/.claude.json`; Keychain is the only local-login source. A nonzero Claude process never supplies a final artifact, but `attempts.json` retains a bounded sanitized structural `reason` so an empty stderr cannot collapse into an unactionable `other` result.

Codex CLI and Copilot CLI are not pinned to exact executable versions; their acceptance remains identity-, capability-, and output-contract based. Claude Code was the only exact-version CLI pin. After its signed manifest and SHA-256 match the source candidate, the helper materializes a current-user-only verified executable snapshot; the same snapshot is captured before the model chain and runs every `--help`, post-provenance dependency inspection, authentication preparation, and final model attempt. The mutable source installation is never rediscovered between Opus attempts.

The fixed-path native GPG source is validated only as a host dependency and is recorded separately from Anthropic publisher provenance. Verification retains a stable source descriptor, copies the main executable into a fresh private GPG home below an explicit helper-owned `0700` root, publishes the copy as mode `0500`, and runs all three GPG operations through that private execution snapshot. The main-file snapshot is not treated as a dynamic-library snapshot. macOS uses fixed root-owned `/usr/bin/otool` to inspect a bounded Mach-O closure, requires the main executable to select exactly `/usr/lib/dyld`, rejects loader commands in dependencies, rejects relative/rpath or non-sealed/non-Homebrew dependencies, treats sealed endpoints as platform TCB, recursively captures every non-sealed Homebrew branch, treats only the current user, root, and Homebrew `admin` group as the host-tool TCB, and revalidates every captured path before each GPG call. Linux/WSL2 defaults only to root-owned `/usr/bin/gpg{,2}` and uses stable-descriptor ELF parsing to prove that the loader-visible `PT_DYNAMIC` range maps consistently through exactly one file-backed `PT_LOAD` at byte and loader-page granularity, rejects other page-rounded load mappings over that table, then rejects `DT_RPATH`/`DT_RUNPATH` and `DT_AUDIT`/`DT_DEPAUDIT` in the snapshot before any dependency query. It validates the architecture-specific canonical glibc loader, invokes that loader directly with `--list` instead of executing an implementation-variable `ldd` script, post-checks every returned dependency, captures each loader-visible lexical symlink chain and resolved root-owned endpoint, revalidates the old identities, then rebuilds and requires an exactly equal closure before every GPG call. On WSL2, each old and refreshed closure batch-validates the snapshot, canonical loader, and every lexical/resolved runtime path against bounded mountinfo; DrvFS is rejected and missing or malformed mount evidence is inconclusive. Before publisher verification, the candidate version probe receives a fixed credential-free environment rather than a filtered copy of the caller environment; in particular, proxy URLs, custom CA paths, authentication material, and review metadata are absent. GPG and Linux host-tool probes likewise run with fixed minimal environments that omit inherited dynamic-loader, shell-startup, compiler, and toolchain override variables.

Capacity, overload, rate limits, timeouts, network errors, 5xx responses, missing final artifacts, silent model substitution, or reviewer findings are not model-fallback reasons. Retry the same runtime/model only within a bounded transient retry policy; otherwise report `inconclusive`. Authentication, invalid configuration, an unexpected effective model/effort, or missing runtime-verification metadata is `blocked`, not a reason to downgrade models.

## Workflow

1. Classify the request.
- Review-only child: if the prompt says `independent code reviewer`, `review-only`, `不要启动其他 reviewer`, `不要等待 CI`, or equivalent, inspect the supplied scope directly and return findings only. Do not start this workflow, another reviewer, PR actions, fixes, or CI waiting.
- Local single/double review: freeze the exact `base_sha..head_sha`, then run the requested local lanes through the helper.
- Triple review: establish the PR/current head, run the local double review, then require final current-head GitHub Codex evidence.
- PR readiness/full workflow: follow [pr-readiness.md](references/pr-readiness.md) after the local delivery commit exists.
  Full PR readiness retains separate required `independent-codex-pr-review` and helper-backed `offline-frozen-diff-review` evidence; those delivery gates do not alter the standalone double/triple definitions above.

2. Freeze scope.
- Prefer a `wip/<topic>` branch and an exact `base_sha..head_sha` range.
- If the target branch moved, compute the merge base and review `<merge_base>..<head_sha>`.
- Do not use a live working tree as formal review evidence. For truly uncommitted review, use a direct review-only child or create an explicit review anchor first.

3. Run local lanes.
- Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`.
- When source or tests need credential-shaped fixtures, use `$synthetic-token-fixtures` to select an exact authoring token from the helper-owned catalog. Canonical tokens suppress only their declared scanner rule; credential-like paths and every other rule remain blocking.
- Start one stateful helper run per logical reviewer: `--reviewer codex` and, for double/triple review, `--reviewer claude`.
- A Claude-family run must also pass `--egress-consent double-review`, `--egress-consent triple-review`, or `--egress-consent explicit-claude-review`, matching the user's request. This makes the authorization visible in the command and saved state.
- `explicit-claude-review` authorizes only Anthropic Claude Code. Only `double-review` and `triple-review` authorize GitHub Copilot fallback when Claude Code is unavailable, has no usable local/API authentication, or all pinned Claude models are entitlement-blocked.
- Before any Codex or Claude-family egress, require the helper's escaping-symlink and sensitive-content preflight to pass. A blocked credential path or high-confidence secret pattern is a hard stop; remove the secret or narrow the review content instead of overriding the scan.
- When the Claude-family helper needs approval, the escalation justification must repeat the explicit user request, exact repository, frozen `base_sha..head_sha`, Anthropic destination plus GitHub Copilot fallback when Claude Code is unavailable, has no usable local/API authentication, or all pinned models are entitlement-blocked, included tracked-code/diff/prompt scope, and exclusions. Use the template in [egress-consent.md](references/egress-consent.md); a generic `run external reviewer` justification is insufficient.
- Use `stateful start`, then bounded `stateful status` / `stateful wait`, and finally `stateful final --state-dir <dir>`.
- Treat only the terminal final artifact as review evidence. Intermediate reasoning, tool traces, stdout tails, and keepalives are not findings.
- If the Codex runtime is deterministically unavailable after successful preflight, use the helper-retained frozen workspace with the clean-context `reviewer` agent and the same diff/evidence and output contracts. After collecting that fallback artifact, run `stateful cleanup --state-dir <dir>`. Do not use inherited-context/default coding agents or bypass a failed preflight.

4. Apply evidence budgets.
- Read [review-lane-contracts.md](references/review-lane-contracts.md) for the exact bounded-read contract.
- Start from counts, diff headers, `--stat` / `--numstat`, `rg -l`, `rg --count`, one hunk, or one exact symbol window.
- Do not begin with whole-file reads, broad `rg -n`, wide diffs, or large untracked inventories.
- If a broad single-file sample is unavoidable, use `rg -n --max-count 80 --max-columns 200 <exact-file>` and then narrow further. Do not combine ripgrep's only-matching mode with a per-line match cap; one matching line can still emit an unbounded number of matches.
- After any 800+ line or 10k+ token result, narrow the next read.

5. Handle findings and failures.
- `No findings.` / `LGTM`: clean terminal result.
- Actionable findings: fix in the parent workflow, rerun affected tests, freeze the new head, and rerun every requested lane affected by the change.
- `blocked`: deterministic auth, policy, permission, configuration, or missing-runtime problem.
- `inconclusive`: transient/capacity/timeout/network failure or no trustworthy final artifact.
- Never report a requested double/triple review as clean when one requested logical lane is blocked, missing, or inconclusive.

6. Report precisely.
- Name the logical lane, runtime, requested/effective model, effort, frozen range, and terminal status.
- Keep model fallback attempts within the same logical lane; they do not increase the review count.
- For triple review, bind GitHub Codex evidence to the current PR head and distinguish automatic review from `@codex review`.
- If the user names a Codex app-server thread for review handoff, verify that exact thread with read-only thread checks before sending anything; never probe or notify a different thread as a substitute.

## Helper Contract

Read [helper-contract.md](references/helper-contract.md) before modifying or debugging the helper. For Claude Code CLI upgrades or platform support, also read [claude-runtime-trust.md](references/claude-runtime-trust.md). The helper intentionally exposes only `codex` and `claude` logical reviewers, requires a `.git`-free frozen range, avoids reviewer-visible helper shims, and preserves stateful final artifacts.

## References

- [helper-contract.md](references/helper-contract.md): helper CLI, model policy, state lifecycle, and safety boundaries.
- [claude-runtime-trust.md](references/claude-runtime-trust.md): Claude Code version range, signed-manifest provenance, platform sandbox, capability, credential, and failure-classification contract.
- [review-lane-contracts.md](references/review-lane-contracts.md): evidence budget, output contract, and PR reply note.
- [review-prompt-templates.md](references/review-prompt-templates.md): bounded prompt variants.
- [pr-readiness.md](references/pr-readiness.md): PR authorization, GitHub review, CI/comments, fix loop, and merge-ready reporting.
- [github-pr-probes.md](references/github-pr-probes.md): bounded `gh` probes.
- [egress-consent.md](references/egress-consent.md): scoped review egress rules.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): long-running task recovery.
- [synthetic-token-fixtures.md](references/synthetic-token-fixtures.md): catalog authority, threat model, legacy migration, and bounded evidence.

## Guardrails

- Do not count fallback attempts or multiple Codex helper implementations as additional reviews.
- Do not silently replace Claude-family review with OpenCode, Cursor Agent, or another model family.
- Do not downgrade on capacity or other transient failures.
- Do not infer account entitlement from silent model substitution.
- Do not accept a Codex result unless the persisted rollout verifies both the effective model and effort.
- Do not let model aliases or global defaults override the pinned policy.
- Do not treat a Claude Code version string, native file format, executable bit, or install path as publisher provenance; require the signed-manifest trust contract before credential or review access.
- Do not run the mutable source Claude executable after publisher verification; capability, dependency, credential-bearing, and final review execution must use the helper-owned verified snapshot.
- Do not execute the fixed-path GPG source directly after inspection; all release-key and signature operations must use the stable-descriptor copy in the private GPG home.
- Do not repair an existing Claude Linux runtime directory with `chmod` or follow a symlink. Create a missing directory once, otherwise validate its owner, exact private mode where required, no-follow file identity, and stability without side effects.
- Do not accept WSL2 runtime paths from spelling alone. Require bounded mount-table provenance, and reject Windows-backed filesystems even when an alias or bind mount hides `/mnt/<drive>`.
- Do not treat overlay, FUSE, 9p, virtiofs, loop-backed, or unknown WSL2 filesystems as proven local Linux storage from mountinfo strings alone. Preserve these as inspection-inconclusive unless a future design can prove the backing objects without path-string races.
- Do not add a Linux/WSL2 synthetic-root mount unless command construction also proves that the file-tool deny policy covers its top-level root. Never add a separate mount below the allowed `/workspace` tree.
- Do not expose `Grep`, `Glob`, LSP, or prompt file mentions on Linux/WSL2 while the supported range includes releases below `2.1.208`; those releases do not reliably propagate `Read` path rules to those surfaces.
- Do not run Claude Code on WSL1, native Windows, or any host where the helper-owned outer sandbox is unavailable.
- Do not start another reviewer from a findings-only review child.
- Do not claim a clean result without a terminal artifact for every requested logical lane.
- Do not invent token variants or use a legacy exemption for new fixtures. `--synthetic-secret-exemption` is an explicit, count-monotonic migration bridge for master-proven historical values only.
- Do not restore compatibility skill aliases. This migration intentionally removes the old skill entrypoints; update repository and release call sites to `review-orchestration-playbook` instead of relying on discovery-time redirection.
