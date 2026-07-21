# Claude Code Runtime Trust

This document defines the shared executable, capability, platform, authentication, sandbox, and failure policy for both Claude Code paths:

- the canonical direct Claude lane used by named double and triple review; and
- the low-level `isolated_review` Claude helper, which remains diagnostic and never satisfies a named lane.

Workspace shape remains path-specific. The named lane runs directly in a lane-unique clean Git worktree. The helper runs from a supplied diff in a helper-owned detached worktree backed by private-minimal-Git metadata and may include source WIP only after explicit `--include-source-wip` consent.

## Current Acceptance Policy

Both paths accept only strict stable Claude Code releases `>=2.1.211,<3.0.0`. A version is eligible only when all of these gates succeed before any credential, prompt, repository, range, PR, or review-workspace input reaches Claude:

1. choose a candidate from a controlled absolute path, never caller `PATH`;
2. require a supported native artifact and strict stable version;
3. verify the fixed Anthropic release-signing key and the selected release's signed per-version manifest;
4. bind the exact platform artifact size and SHA-256 to the selected file;
5. capture descriptor-bound source identity, including `ctime`;
6. materialize one private digest-verified executable snapshot while that identity remains stable;
7. run mandatory bounded credential-free `--version` and `--help` capability probes against that same snapshot;
8. reverify the snapshot and freshly hash/revalidate the mutable source before acceptance.

Any version, provenance, capability, snapshot, or source-identity drift fails closed. Probes receive empty stdin, fixed `/` cwd, fixed credential-free environment, bounded time/output, and no review input. Capability output attests only the advertised CLI surface; it does not attest the actual review launch, final merged sandbox, admin-managed settings, or path-rule evaluation.

The preflight may fetch signed metadata but never downloads or installs a Claude executable, switches the active version, or repairs an active symlink. Installation is a separate host mutation requiring explicit authorization through the official installer/version manager.

## Publisher Provenance

Anthropic publisher provenance is anchored to primary-key fingerprint:

```text
31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE
```

For the exact selected version, verification checks `manifest.json.sig` over `manifest.json` from `downloads.claude.ai`, selects the exact platform entry, then validates both size and SHA-256. A stable filename, symlink target, native format, notarization, or package-manager origin never substitutes for the signed manifest. Scripts, interpreter wrappers, prereleases, development builds, unsupported platforms, and future major versions are rejected.

GPG is a host-trust dependency rather than publisher evidence. Its executable path and behavior must satisfy the reviewed dependency contract. Missing dependencies, network uncertainty, malformed metadata, source races, probe timeout, or filesystem ambiguity are inconclusive unless the evidence proves a deterministic unsupported or invalid state.

### Direct named lane

`named_claude_preflight` returns one exact resolved path plus non-secret version, artifact, capability, and identity evidence. Its private snapshot is probe-only and is erased before return. Immediately before launch, the parent revalidates that same installed path, size, digest, and identity, launches it directly, then revalidates it again after process completion.

For the direct lane, do not create a helper snapshot for the actual review launch and do not call `snapshot_verified_claude_executable`. The before/after path checks detect drift but do not claim the stronger immutability of a private runtime copy.

### Low-level helper

For the low-level helper, after the signed manifest, size, SHA-256, and same-snapshot capability probes pass, the helper may retain its helper-owned digest-keyed executable snapshot for the isolated runtime. The snapshot identity and digest remain bound to the runtime report. That stronger helper runtime copy does not make its supplied-diff/private-Git review eligible for a named lane.

## Capability Contract

The mandatory `--version` probe must report the exact manifest-selected release. The mandatory `--help` probe must uniquely advertise every public option used by the reviewed command plus the reviewed safe-mode and permission-mode behavior. Both probes execute the same verified snapshot in the same credential-free setup.

Missing required options, contradictory safe-mode claims, duplicate or ambiguous option evidence, unexpected version output, excessive output, timeout, or probe-launch uncertainty prevents review launch. A deterministic unsupported capability is blocked; uncertain probe evidence is inconclusive.

`--help` remains advertised-surface evidence only. Neither it nor `system/init` proves the final merged sandbox, managed permission arrays, actual path-rule evaluation, absence of host-side CLI state changes, or behavior of an unreported upstream feature.

## Authentication And Trusted Real HOME

Both Claude paths use ordinary Claude CLI authentication in real `HOME`. Source precedence is exact:

```text
ANTHROPIC_API_KEY > CLAUDE_CODE_OAUTH_TOKEN > ordinary local login
```

The parent opaque-forwards only the winning explicit value and removes the lower-priority explicit source from the child environment. The same publisher-verified CLI runs `auth status --json` without review input to confirm that its effective source matches the parent-selected `api-key`, `oauth-token`, or `local-login` mode. The orchestrator never parses, copies, prints, or persists credential contents.

Real `HOME` is the trusted CLI control plane. The CLI may update ordinary CLI-owned authentication and runtime state, including credential refresh and possible cache or tool-result artifacts. Those accepted side effects are not model-authorized review mutations and do not authorize model/tool writes or deliberate host changes. The canonical lane does not enumerate or attest every CLI-owned `HOME` write. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable. Neither path takes or verifies a complete real-`HOME` diff.

Authentication failures are source-specific pause boundaries:

- rejected API key: `blocked-authentication`; ask the operator to unset or replace `ANTHROPIC_API_KEY`;
- rejected OAuth token: `blocked-authentication`; ask the operator to unset or replace `CLAUDE_CODE_OAUTH_TOKEN`;
- expired or rejected ordinary login: `blocked-authentication`; ask the operator to run `claude auth login` and explicitly retry.

Recognized structured `Login expired`, explicit HTTP/status 401, OAuth/login/authentication/token-refresh denial, or directly adjacent expired/invalid/unauthorized state may support that classification. Generic token counting, usage, quota, capacity, rate limits, ambiguous credential I/O, non-authentication refresh failure, or a bare exit code is inconclusive. Authentication failure never authorizes a provider substitution.

## Selected-Deny Sandbox Contract

The named lane's detached worktree and the helper's detached private-Git workspace are the model-visible review scopes. Both launch policies request:

- global write denial;
- read denial for critical sensitive roots, authentication/configuration roots, implementation checkouts, unrelated state, `/proc`, and `/dev` as applicable;
- only reviewed `Read`, `Grep`, `Glob`, and sandboxed `Bash` surfaces;
- no unsandboxed commands, edits, web tools, browser tools, delegation tools, or unapproved external mutations;
- removal or denial of secret environment variables from sandboxed tools.

This is selected-deny, not a global host-read whitelist. `allowRead` records the intended review and Git scopes but does not prove that every other host path is unreadable. Sandboxed Bash can technically read another host path that is not covered by a selected deny. The prompt/model scope therefore explicitly forbids all outside-workspace reads, including direct reads of real `HOME`, another checkout, parent state, or another reviewer workspace; do not describe the selected-deny policy as re-opening only the current workspace.

Global write denial and critical sensitive-root exclusions are recorded as requested configuration. Capability and init evidence cannot prove the final merged sandbox, admin-managed arrays, or real path evaluation. A read-only filesystem result also does not prove that state-changing connector or remote tool surfaces were absent; the prompt and tool configuration must forbid them.

## Platform Boundary

### macOS

Require the reviewed native sandbox with fail-if-unavailable behavior, exact inline safe-mode/tool settings, global write denial, and selected critical-root denies. Resolve every path before constructing settings. A denied root must not overlap required private Git metadata; create a non-overlapping lane layout rather than relying on allow/deny precedence.

### Linux and WSL2

The low-level helper additionally requires its reviewed outer isolation runtime and private runtime directories. Positively identified WSL2 paths must reside on approved Linux-backed filesystems; known DrvFS/Windows provenance is blocked. Ambiguous WSL identity, mountinfo, namespace, filesystem backing, dependency identity, or containment is inconclusive. The named direct lane follows its canonical native-sandbox contract and never inherits helper workspace semantics merely because it runs on the same platform.

Across platforms, process-group publication, signal forwarding, bounded output, descendant cleanup, and post-run workspace verification are part of the terminal evidence. Timeout, output overflow, retained process, or cleanup uncertainty prevents a clean claim.

## Structured Direct-Lane Evidence

Canonical direct review captures bounded raw `stream-json` stdout outside the model-visible worktree. The stream must contain exactly one leading `system/init` as its first nonblank record and one trailing terminal `result` as its last nonblank record. Duplicate, malformed, misordered, missing, unknown, or trailing contract evidence must fail closed.

`validate_claude_stream.py` requires all of these parent arguments:

```text
--cwd <resolved-clean-worktree>
--model <requested-model>
--claude-code-version <preflight-version>
--authentication-source <api-key|oauth-token|local-login>
--process-returncode <child-returncode>
--input <bounded-stream-jsonl>
```

The validator requires exact init version equality and maps authentication source to `apiKeySource`: `api-key` maps to `ANTHROPIC_API_KEY`; `oauth-token` and `local-login` map to `none`.

The closed legacy base init profile covers `>=2.1.211,<2.1.216`. The closed extended 2.x profile covers `>=2.1.216,<3.0.0`; current 2.1.216 evidence requires exact `output_style: default`, ordered agents `claude`/`Explore`/`general-purpose`/`Plan`, ordered capabilities `interrupt_receipt_v1`/`msg_lifecycle_v1`, `analytics_disabled: true`, boolean `product_feedback_disabled`, nonempty `uuid`, and `fast_mode_state: off`. Added, missing, malformed, reordered, unknown, or fixed-value-drifted fields are inconclusive.

Every intermediate event is selected by version profile, closed over its reviewed fields and nested shape, and bound to the init/result session. The extended profile accepts only reviewed `system/thinking_tokens`, assistant-message, user-tool-result, and `rate_limit_event` events. Unknown type, subtype, field, session binding, or shape is inconclusive.

Extended-2x success requires `fast_mode_state: off`, `terminal_reason: completed`, and nonnegative integer `time_to_request_ms`, `ttft_ms`, and `ttft_stream_ms`. Legacy success forbids those five fields. Extended failure permits them only as optional fields with the same strict known values and types until a reviewed failure sample supports a required-field contract. Every other unknown terminal field remains inconclusive.

Only `classification: accepted` with a zero child return code supplies findings. Deterministic structured blockers retain `blocked` or `blocked-authentication`; malformed evidence, ambiguous errors, or a success-looking stream with missing/nonzero return code remains inconclusive. Validator acceptance attests reported invocation and terminal fields only, never sandbox enforcement.

## Failure Vocabulary

- `blocked`: deterministic unsupported release/platform, invalid provenance, missing required capability, configuration/policy mismatch, permission denial, model substitution, or missing required provider;
- `blocked-authentication`: recognized source-specific authentication rejection with the corresponding operator action;
- `inconclusive`: dependency/network/probe uncertainty, candidate inspection ambiguity, identity or digest race, timeout/capacity, malformed or contradictory structured evidence, unclassified error, nonzero ambiguous return code, process leak, or cleanup uncertainty;
- `accepted`: every path-specific provenance, capability, authentication-source, sandbox-request, structured-output, return-code, and cleanup gate required for that artifact passed.

These classifications preserve the requested review shape. A failed Claude lane does not become a completed single review, and an independently unavailable GitHub Codex lane cannot make an incomplete Claude double clean.

## Historical Evidence

Earlier journals may record an exact release used for a point-in-time probe or a now-superseded helper design. Those entries remain historical evidence only. They do not override the current stable range, per-version signed-manifest binding, same-snapshot version/help probes, ordinary real-`HOME` CLI authentication, selected-deny policy, version-selected init profiles, or private-Git helper contract.

## Official Sources

- [Claude Code sandboxing](https://docs.anthropic.com/en/docs/claude-code/sandboxing)
- [Claude Code settings](https://docs.anthropic.com/en/docs/claude-code/settings)
- [Claude Code authentication](https://docs.anthropic.com/en/docs/claude-code/authentication)
- [Claude Code CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-reference)
