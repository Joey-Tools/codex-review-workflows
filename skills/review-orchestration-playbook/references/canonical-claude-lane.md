# Canonical Claude Code Lane

Use this contract for the actual Anthropic Claude Code lane in named double and triple review. Do not route this lane through `isolated_review`: that helper materializes a supplied diff in a `.git`-free workspace and is diagnostic-only.

The trusted guard is non-executable Python source and loads only its manifest-bound runtime source bytes, without ordinary bundle-path import resolution. Every shorter guard spelling below is an argv-tail placeholder and must actually be launched through the recorded, revalidated absolute Python interpreter as `<trusted-python-absolute-path> -I -B -S <trusted-bundle-absolute-path>/scripts/named_lane_guard ...` under the fixed clean parent environment in [review-lane-contracts.md](review-lane-contracts.md); never execute the guard path directly, resolve Python through ambient `PATH`, load global or user site initialization, or accept bytecode/native-extension substitutes.

The default `validate-worktree` / `run-claude` profile keeps the exact eager three-module closure `review_runtime`, `review_runtime.common`, and `review_runtime.named_lane`. The formal `preflight-claude` and `validate-claude-stream` subcommands select separate manifest-bound raw-source profiles for only their declared implementation dependencies and, for stream validation, the exact schema bytes. They do not widen the default closure or use ordinary package import resolution. Direct execution of the env-shebang compatibility wrappers is not a formal named-lane control path.

The `preflight-claude` profile raw-loads exactly `review_runtime`, `review_runtime.common`, `review_runtime.claude_refresh_lock`, `review_runtime.claude_linux`, `review_runtime.claude_provenance`, and `review_runtime.named_claude_preflight`, then binds and revalidates `review_runtime/claude_code_release.asc`. Companion revalidation repeats no-follow descriptor/type safety checks and compares the complete bounded bytes, so a safe ordinary-file replacement with identical content is harmless; it does not require persistent `dev`/`ino` identity across the two reads. The provenance consumer verifies signatures with the immutable release-key bytes captured by the guard's initial validated read; it never reopens the key path after final validation and never reads or executes the `scripts/named_claude_preflight` wrapper. The `validate-claude-stream` profile raw-compiles only the standalone `scripts/validate_claude_stream.py` source, binds/revalidates `references/claude-2.1.212-stream-schema.json`, and injects the immutable schema bytes from its initial validated read for parsing without a later path reopen; it never executes that source through its env shebang. Neither profile needs or accepts an extra `--` before its own arguments.

## Workspace And Process

1. Create a lane-unique clean Git working tree at the same frozen `head_sha` used by the Codex lane. Prefer a lane-private local clone or private bare object store plus worktree under the task's temporary root, so required Git metadata does not live under the denied implementation checkout. This is a local Git setup step, not a network clone or prepared-diff materialization. With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, prove that the exact range and both endpoint trees are locally complete without rendering a full diff; if a parent-owned preflight must render a diff before the final guard, pass both `--no-ext-diff` and `--no-textconv`. Hydrate missing objects before freezing or block the lane. Remove remote URLs before model launch. Verify clean status, exact `HEAD`, both commits, and bounded read-only range queries. As the final parent-owned preflight immediately before launch, invoke `<trusted-bundle-absolute-path>/scripts/named_lane_guard validate-worktree` on that exact clean worktree/head under [review-lane-contracts.md](review-lane-contracts.md); record the trusted bundle's absolute source, version, and SHA-256 digest, and never resolve a repository-relative guard. In addition to forced file-mode-aware ordinary/staged dirt checks and tracked-symlink or guidance safety, the guard rejects `assume-unchanged` and `skip-worktree` index bits, ignored artifacts, and every materialized or initialized submodule. Any repository-visible direct `include.path` or `includeIf.*.path` key is `blocked-safety`; included values are not accepted as safety configuration, and the guard blocks before status or reviewer execution. Initial bounded Git repository-identity probes may still parse the configured target before the block and therefore fail closed; this is not a no-read guarantee. Every other safety-relevant value is evaluated from direct local/per-worktree configuration with includes disabled. Every direct `alias.*` key and direct executable clean/process filter or external/driver/textconv diff command is rejected. Before any status or reviewer Git command, direct `core.fsmonitor` must be unset or parse as Git-false; built-in daemon (`true`), no-value, and path hook values are rejected without execution, while worktree `false` may override a local path. Direct submodule configuration follows path mapping even without `.gitmodules`, per-name boolean precedence, and repeated `submodule.active` pathspec semantics; every raw gitlink is matched against those global pathspecs even without a name/path mapping, and explicit per-name `active=false` is not treated as initialization. An absent or empty uninitialized gitlink is allowed; only an exact deletion record for a frozen-tree gitlink whose path is independently proven absent may be removed from the otherwise-empty status result. Frozen symlink targets use one aggregate 30-second `git cat-file --batch` read with at most 4,096 entries, 16 KiB per target, and 64 MiB total output. The guard deliberately does not compare `mtime`/`ctime` or snapshot ordinary file contents. Every bounded preflight failure is `blocked-safety` and forbids process launch.
2. Start a new actual `claude` process with its working directory set to that worktree. Do not use `--continue`, `--resume`, `--from-pr`, `--fork-session`, or `--worktree`.
3. Preserve the real user `HOME` as Claude's trusted authentication and CLI control plane. The model-visible review scope is the detached working tree plus only its lane-private Git metadata/object paths that read-only Git needs for the frozen refs.
4. Send the small control prompt through stdin. Do not create a prompt or diff file in the worktree, and do not send a prepared diff, changed-file contents, Codex findings, or parent suspicions.

The canonical launch uses the same parent-recorded absolute trusted guard's `run-claude` process-only supervisor, not any helper reviewer. Send the bounded control prompt on stdin, use distinct private stdout/stderr artifact paths outside the real worktree, and pass the exact revalidated absolute, non-symlink actual Claude executable after `--`. The supervisor must make that executable its direct child `argv[0]` without a shell:

```text
<trusted-python-absolute-path> -I -B -S <trusted-bundle-absolute-path>/scripts/named_lane_guard run-claude
  --worktree <absolute-clean-worktree>
  --stdout-path <private-stdout-path-outside-worktree>
  --stderr-path <private-stderr-path-outside-worktree>
  --
  <resolved-exact-claude-path>
  --print
  --model <claude-opus-4-8-or-authorized-4-7>
  --effort max
  --permission-mode dontAsk
  --output-format stream-json
  --verbose
  --no-session-persistence
  --safe-mode
  --no-chrome
  --disable-slash-commands
  --strict-mcp-config
  --mcp-config {"mcpServers":{}}
  --setting-sources ""
  --settings <inline-native-sandbox-json>
  --tools Read,Grep,Glob,Bash
  --allowedTools Read(./**),Grep,Glob,Bash
  --disallowedTools Edit,Write,NotebookEdit,WebFetch,WebSearch,Task
```

Run the exact-version selection preflight below before the parent revalidates the selected CLI's provenance and constructs the fixed reviewed launch. Pass settings inline; do not write them into the review workspace. `--safe-mode` disables automatic customizations and slash-skill loading, not the built-in `Read` tool. The prompt therefore tells Claude to read applicable tracked `AGENTS.md`, repo-local skill documents, and project guidance from the worktree explicitly. It must not read an installed skill or guidance file outside the worktree.

The inline settings must also set `disableBundledSkills: true`. `--safe-mode` alone is not evidence that bundled skills are absent; the explicit setting is required before the init `skills` field can be expected to be empty.

## Exact-Version Selection Preflight

Before any prompt, credential, authentication, repository, range, PR, or review-workspace input is exposed to Claude, invoke the trusted guard's manifest-bound `preflight-claude` profile through the same revalidated absolute Python launcher used above:

```text
<trusted-python-absolute-path> -I -B -S <trusted-bundle-absolute-path>/scripts/named_lane_guard preflight-claude
  [--claude-path <explicit-absolute-override>]
```

That profile raw-loads the implementation behind [`named_claude_preflight`](../scripts/named_claude_preflight) from the trusted bundle without ordinary package import resolution. The env-shebang `named_claude_preflight` wrapper is a low-level compatibility entrypoint only; executing it directly cannot satisfy a formal named lane or a self-policy-migration control-plane bound. The formal guard ignores ambient `HOME`, resolves the current POSIX account through `pwd.getpwuid(os.getuid())`, and requires its nonempty absolute home to resolve to an accessible directory. In the ordered paths below, `$HOME` means that canonical account home; inability to establish it fails closed before selection. The machine helper hardcodes required version `2.1.212` and considers candidates in this exact order:

1. an explicit absolute `--claude-path` override, when supplied;
2. the side-by-side install at `$HOME/.local/share/claude/versions/2.1.212`, when present; then
3. the first present controlled active-install path from `$HOME/.local/bin/claude`, `/opt/homebrew/bin/claude`, and `/usr/local/bin/claude`.

An explicit override is authoritative: missing, unusable, or wrong-version explicit input fails closed and never falls through to another candidate. Candidate presence is tri-state: only exact absence may advance to the next candidate; I/O, path-resolution, or filesystem-identity uncertainty stops priority fallback as `candidate-inspection-inconclusive`. A present side-by-side path is likewise selected rather than bypassed. Caller `PATH` entries are ignored, so a repository or task cannot inject the active candidate. If a resolved native-installer symlink target itself declares `versions/<semver>` other than `2.1.212`, the helper blocks the mismatch without executing it. Otherwise, before any version probe, the helper requires a native executable for the current supported platform, verifies its size and SHA-256 against the fixed-key signed Anthropic manifest for required version `2.1.212`, and captures the descriptor-bound strong source identity including `ctime`. Before creating the private GPG directory, it resolves the configured system temporary parent to its canonical path and passes the verifier a real private child path; aliases such as macOS `/tmp -> /private/tmp` therefore do not weaken or falsely fail the existing requested-path-equals-resolved-path check. While the source identity remains stable, the helper materializes a private digest-verified executable snapshot and runs only `<private-snapshot> --version`, with empty stdin, fixed `/` cwd, bounded output/time, and a fixed credential-free environment; it receives no prompt, credential, repository, range, PR, or workspace input. The helper re-verifies the snapshot, then performs a fresh descriptor-bound hash of the mutable source against the signed size and SHA-256 before acceptance and rechecks its identity; stat identity alone is not sufficient. It erases the temporary snapshot before returning and never executes the mutable installation path. Scripts, interpreter wrappers, wrong signed artifacts, and caller-`PATH` candidates are never executed. The helper may fetch signed release metadata needed for verification, but never downloads or installs a Claude executable and never creates, changes, or repairs an active symlink.

If exact `2.1.212` is absent, the named-review workflow stops at the blocked result. Acquiring that binary is a separate host-mutation workflow that requires explicit authorization and must use the official installer/version manager to create a side-by-side exact-version installation before retrying preflight. A named double/triple request by itself does not authorize installation, an active-version switch, or symlink repair, and the preflight never performs those actions.

The helper emits exactly one bounded JSON object. Missing or deterministically unusable exact-version selection is `classification: blocked` with `reason: exact-version-unavailable`; a declared or probed version other than `2.1.212`, including an active `2.1.216`, is `classification: blocked` with `reason: exact-version-mismatch` only after source-identity stability is proved. Deterministically invalid signed metadata, signer identity, signature, manifest, or artifact provenance is `classification: blocked` with `reason: publisher-verification-failed`; it is a provenance failure, not proof of another installed version. A transient native-format, candidate-presence, path-resolution, or filesystem-identity inspection failure is `classification: inconclusive` with `reason: candidate-inspection-inconclusive`; a publisher-verification dependency/network failure, snapshot failure, probe failure, or later identity race that cannot support a deterministic result is also `inconclusive`. Source drift takes precedence over an observed wrong-version result. Never collapse inspection uncertainty into deterministic unavailability or continue to a lower-priority candidate after uncertain inspection. Success alone returns the fixed resolved absolute path for the source plus non-secret source, signed-artifact, version, and descriptor-bound filesystem-identity metadata; the temporary probe snapshot is not a returned launch path. Do not record candidate output, environment contents, credentials, or repository data.

Only after `classification: accepted` may the parent pass the selected `resolved_path` and signed-artifact identity to the canonical provenance revalidation and guarded direct-child launch below. Failure never authorizes use of `2.1.216`, the broader low-level helper version range, `isolated_review`, another provider, or a downgrade to single review. A requested double remains a double review whose Claude lane is blocked. A requested triple remains blocked when its Claude lane is blocked; if the GitHub Codex lane is independently unavailable, its effective shape may be double, but that effective double is still incomplete and blocked because Claude did not complete.

For each complete stdout/stderr path, the caller must create and supply its lexical parent as a lane-unique, current-user-owned, exact-mode-`0700`, already-canonical real directory and cooperatively exclude every other same-UID writer for the run. The parent must be outside the review worktree, exist, be a non-symlink directory, and equal its own strict resolution. Each argument must name a distinct direct leaf in that parent; the leaf must be absent and non-symlink before launch and remain protected by no-follow, exclusive publication. The guard must not infer authority from a symlink-resolved parent or follow a pre-existing leaf symlink, including a dangling one. Before launch it binds the validated parent identity and safety mode/owner to an open directory descriptor. Temporary creation, hard-link publication, cleanup, and rollback remain relative to that descriptor, and the lexical path must still name the same `(st_dev, st_ino)` with the same owner and mode before and after publication. The complete pair publication and every rollback run under a forwarded-signal mask with a temporary handler and explicit commit point; a signal observed before commit removes both leaves before it is propagated, while a signal after commit may leave only the complete validated pair. Each temporary and published leaf carries the creating write's `(st_dev, st_ino)` identity token. Identity drift already observed by the final cleanup check is preserved and makes the result inconclusive. POSIX/Python has no portable conditional unlink, so a non-cooperative same-UID replacement in the final check-to-unlink window is outside this lightweight lane's guarantee. A failure to remove a temporary hard-link name rolls back every still-matching leaf already published by that write before returning inconclusive. Parent `mtime`, `ctime`, `nlink`, and child-count churn are not identity checks.

`run-claude` constructs the child environment from an allowlist instead of copying the ambient process environment:

- derive real `HOME`, `USER`, `LOGNAME`, and account `SHELL` from `pwd.getpwuid(os.getuid())`, and use the shipped trusted `PATH`;
- pass through only locale/UI keys `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `COLORTERM`, and `NO_COLOR`;
- pass through only proxy keys `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lowercase equivalents;
- pass through only CA keys `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO`; this is host control-plane compatibility, not a copied or attested CA bundle. Ambient `NODE_EXTRA_CA_CERTS` is not inherited unless the caller supplies the value-free `--inherit-node-extra-ca-certs` opt-in. The guard then reads the value from its own environment, requires the configured lexical path to be an exact absolute readable non-symlink regular file under a stable no-follow identity check, and passes the original path only to the final Claude child without exposing it in the guard's argv. This direct-lane interface does not parse, copy, attest, or inherit the helper's stronger CA staging guarantees;
- force Git no-lazy/no-prompt/no-replace/no-global-or-system-config/no-optional-lock behavior with `GIT_ASKPASS=/usr/bin/false`, `GIT_ATTR_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, `GIT_PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, and `PAGER=cat`; and
- inherit no ambient Claude/Anthropic, cloud-provider, dynamic-loader, or other tool-control variables. In particular, an ambient Claude or Anthropic API/config variable is not an explicitly authorized credential input.

Do not print the inherited allowlisted values: proxy and CA configuration may itself be sensitive, and the native-sandbox credential deny must include every forwarded or explicitly supplied proxy/CA key, including explicit `NODE_EXTRA_CA_CERTS`. Local login never inherits `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, or another `CLAUDE_*`/`ANTHROPIC_*` variable. The allowlist also excludes all other ambient `GIT_*`, `TMPDIR`, `XDG_CONFIG_HOME`, cloud-provider variables, `LD_*`/`DYLD_*`, `NODE_OPTIONS`/`NODE_PATH`/`NODE_EXTRA_CA_CERTS`, language/package-manager controls, shell startup controls, agent sockets, and similar tool-control state. If a non-login credential or another control variable is required, add a separate explicit, reviewed input contract rather than widening ambient inheritance.

## Canonical Executable Provenance

The canonical direct lane uses the user's installed actual Claude Code executable at the one exact resolved path accepted by the selection preflight. Before exposing credentials, review metadata, or repository content, the parent must:

1. resolve the selected executable without later `PATH` lookup and reject a missing, non-regular, non-executable, script/interpreter-wrapper, prerelease, development, unsupported-platform, or future-major candidate;
2. verify the fixed Anthropic release-signing key, signed per-version manifest for exact `2.1.212`, expected platform artifact, exact size, and SHA-256 of the stable resolved installed file, using `verify_claude_release` or equivalent checks before executing the candidate;
3. require exactly Claude Code `2.1.212` from the accepted preflight's snapshot-bound version evidence and construct the exact reviewed argv above; and
4. immediately before launch, revalidate the same path identity, signed artifact size, and SHA-256, pass that exact resolved path after `--` to the parent-recorded absolute trusted guard's `run-claude` subcommand for direct-child launch, then revalidate it again after process completion. Any drift or uncertainty makes the lane inconclusive.

This provenance contract rejects npm/NVM shebang shims and all other scripts or interpreter wrappers. Do not add a user-writable npm/NVM directory to trusted `PATH` to make such a candidate resolve. `run-claude` inherits only the fixed trusted path and does not establish publisher provenance merely by supervising a process.

The named lane intentionally has no separate mandatory `--help` or advertised-capability probe. Exact signed version selection, the fixed argv above, and the strict leading-init/terminal validator below are its machine-verifiable observable contract. A help probe would only report an advertised CLI surface; it cannot prove the actual launch argv, final merged sandbox, managed permission arrays, or path evaluation. If a diagnostic non-review help probe is run, it must use a new private digest-verified snapshot after repeated publisher verification and while the descriptor-bound source identity remains stable, and it must receive no credential, repository, range, PR, or review-workspace input. Its result is diagnostic only and does not add or replace a named-lane gate.

The accepted preflight's private executable snapshot is temporary evidence for its credential-free version probe; it is erased before return and is never the later review-launch path. The direct review launch does not reuse that snapshot and does not call `snapshot_verified_claude_executable`; it also does not inherit the low-level helper's dependency-closure, outer-sandbox, credential-carrier, catalog, guarded-writeback, or recovery contracts. It intentionally uses the revalidated host-installed executable path for the actual ordinary real-`HOME` CLI process; the before/after identity and digest checks detect drift but do not claim the stronger immutability of the helper snapshot. The broader publisher-verified `>=2.1.211,<3.0.0` range in `claude-runtime-trust.md` belongs to the low-level helper and does not make another CLI version eligible for this named direct lane. Record only non-secret provenance metadata such as resolved path, version, platform, artifact digest, and verification state.

## Process Supervisor Contract

The trusted guard's `run-claude` subcommand accepts only a bounded control prompt and launches the exact revalidated Claude path with direct argv/no shell. Reading the prompt through EOF is part of the same fixed 1,800-second monotonic deadline as process supervision; a writer that sends a short prompt but withholds EOF therefore terminates as inconclusive instead of blocking the lane before its timer starts. The same outer forwarded-signal scope covers prompt reading and the handoff to process supervision, so SIGTERM, SIGINT, SIGHUP, or SIGQUIT during the EOF wait returns structured `inconclusive` / `forwarded-signal` evidence rather than a traceback or unstructured process exit. Retain the 64 MiB limit for each of stdout and stderr (128 MiB aggregate) and the 256 KiB prompt cap. Test-oriented CLI overrides may equal or tighten the 1,800-second timeout, per-stream, and prompt caps but may never raise them; direct Python API callers are subject to the same ceilings. The supervisor applies the shipped runtime's TERM/KILL/drain/reap cleanup to the initial supervisor process group and inherited streams, and normal leader exit does not bypass those bounded checks.

Only complete structured terminal output collected after successful cleanup and reaping may become review evidence, but `run-claude` supplies only the bounded raw bytes and exact child return code for the later validator. Every `run-claude` supervision failure is `inconclusive`: timeout, either-stream overflow, drain or reap failure, residual members of the initial supervisor process group, or an inherited-stream leak prevents validation. Malformed or partial terminal output is instead a fail-closed validator result after successful supervision; the validator never retroactively proves process cleanup. Never accept a partial tail, silently downgrade the model, or fall back to another provider. By contrast, every bounded failure while running `validate-worktree` is terminal `blocked-safety` because worktree safety was not proved.

This is bounded process supervision, not a process-tree sandbox. A descendant that deliberately calls `setsid()` or `setpgid()` to escape the initial supervisor process group and closes every inherited output stream is outside the supervisor's observable cleanup boundary. The lane must not claim whole-process-tree quiescence; a product requirement to contain arbitrary descendants needs platform containment such as cgroups, macOS-specific process tracking, or Windows Job Objects rather than a process-group check.

This guard is deliberately narrow. `validate-worktree` checks clean/safety properties without timestamp or ordinary-content snapshots, and `run-claude` is the launch guard and process supervisor. The separate stream validator classifies only already-captured output. Neither prepares a diff, performs review logic, establishes executable provenance, configures or attests the sandbox, authenticates Claude, scans general content/secrets, or provides `isolated_review` helper guarantees; neither can replace the other.

## Authentication Control Plane

The canonical direct lane uses ordinary local Claude CLI login in real `HOME` as its only authentication interface. It accepts no API key, OAuth-token environment interface, or helper credential carrier. It does not use the low-level helper's credential broker, staged carrier, credential-lock catalog, guarded writeback, or recovery journal, and it must not claim those helper-only guarantees.

Real `HOME` is a trusted control plane. The publisher-verified Claude CLI may update ordinary CLI-owned authentication and runtime state there, including credential refresh and possible cache or tool-result artifacts. These are accepted CLI control-plane side effects, not model-authorized review mutations; they do not authorize model/tool writes or deliberate host mutations. This contract does not enumerate or attest every CLI-owned `HOME` write. The model prompt still forbids direct reads of real-`HOME` content, and the native sandbox must deny model-visible credential/configuration roots. Do not inspect, copy, print, or place credential contents in review state.

If organization policy forbids ordinary CLI control-plane writes, or the host has only API-key/OAuth-token credentials, report `blocked-authentication`; do not widen ambient inheritance or silently introduce an API-key interface or the helper credential wrapper. A structurally valid reported `Login expired`, explicit HTTP/status 401, explicit OAuth/credential/login/authentication/token refresh failure, or directly adjacent authentication state of expired, invalid, or unauthorized is `blocked-authentication`: ask Joey to run `claude auth login` on that host and wait for an explicit retry. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit failures are not authentication evidence and remain `inconclusive`; an authentication word separated from `error`/`failure` by one of those resource terms does not change that result. A bare child exit code 401, credential-file or other ambiguous credential I/O, a generic non-authentication refresh failure, or uncertain persistence state is also `inconclusive`. Neither condition authorizes provider fallback. `--no-session-persistence` disables resumable session persistence; it does not make the CLI process or real `HOME` immutable. The lane does not take or verify a complete real-`HOME` diff, so cache or tool-result artifacts may retain review-derived data according to upstream CLI behavior. Post-run worktree cleanliness does not attest what the trusted control plane changed or prove that no transient control-plane write occurred.

Accordingly, when organization policy forbids ordinary CLI credential refresh, the outcome is `blocked-authentication`, never an API-key fallback.

## Native Sandbox Contract

The inline settings request all of the following:

- hooks disabled;
- bundled skills disabled explicitly;
- native sandbox enabled with fail-if-unavailable;
- sandboxed Bash never auto-approved and unsandboxed commands forbidden;
- global write denial for model-visible tools and sandboxed commands;
- read denial for critical sensitive roots such as authentication, credential, SSH, GPG, cloud, Codex, Claude, and other private configuration roots;
- explicit read entries for the clean worktree and its registered Git metadata/object store;
- credential-file and secret-environment denial;
- no MCP, browser, editing, web, task, or other state-changing tool surface.

Construct the inline JSON from resolved absolute paths with this shape; never interpolate credentials or repository content into it:

```json
{
  "disableAllHooks": true,
  "disableBundledSkills": true,
  "permissions": {
    "deny": ["Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Task"]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "autoAllowBashIfSandboxed": false,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": [
        "<credential-and-private-config-root>",
        "<implementation-checkout>",
        "<other-review-state-root>",
        "/proc",
        "/dev"
      ],
      "allowRead": ["<clean-worktree>", "<registered-git-metadata-or-object-root>"],
      "denyWrite": ["/"]
    },
    "credentials": {
      "files": [{"path": "<sensitive-file-or-root>", "mode": "deny"}],
      "envVars": [{"name": "<secret-environment-name>", "mode": "deny"}]
    }
  }
}
```

Enumerate every applicable sensitive root and every Git metadata/object root rather than leaving placeholder values in a real invocation. If a protected root would contain required Git metadata, create the worktree layout so those scopes do not overlap; do not rely on `allowRead` to override a broader `denyRead`.

Treat this as a selected-deny native sandbox, not a global host-read whitelist. `allowRead` records the intended review scope but does not prove every other host path is unreadable; sandboxed Bash may technically read another path not covered by `denyRead`. The prompt/model contract therefore forbids direct reads outside the worktree. Read-only Git may internally access only the worktree's registered Git metadata/object paths for the frozen range; that logical Git metadata is part of the review workspace and is not permission to inspect the source checkout, parent directory, real `HOME`, or another review.

Claude Code 2.1.212 `system/init` or capability output cannot attest the final merged sandbox, managed permission arrays, or path-rule evaluation. Record the settings as requested configuration. Do not promote init output into independent proof of effective enforcement, and do not restore the retired complex outer global-read-isolation design.

If the required native sandbox, global write deny, sensitive-root denies, tool restrictions, actual Claude executable, or structured-output verification cannot be established, report the lane as `blocked` or `inconclusive` under the failure contract. Never weaken the boundary or substitute Copilot.

## Structured Init And Terminal Evidence

Parse `stream-json` as bounded strict UTF-8 JSONL. Every nonblank line must be one JSON object; reject duplicate keys, nonstandard constants, undecodable text, or non-JSON output. The first nonblank record must be the sole event with `type: system` and `subtype: init`; the last nonblank record must be the sole event with `type: result`. A missing, duplicate, malformed, out-of-order, or trailing contract event makes the lane `inconclusive`; partial findings do not count. A structurally valid terminal event that fails the success acceptance schema is passed to the failure classifier below rather than being classified by this envelope rule.

Capture bounded raw stdout in parent-owned state outside the model-visible
worktree. After successful `run-claude` supervision, the canonical lane must pass
those captured bytes through the trusted guard's manifest-bound
`validate-claude-stream` profile. That profile raw-loads
[`validate_claude_stream.py`](../scripts/validate_claude_stream.py) and its exact
versioned schema from the trusted bundle without ordinary package import
resolution; the script's env-shebang CLI remains a low-level compatibility
entrypoint and cannot satisfy a formal named lane. Prose-only inspection or an
ad hoc parser does not satisfy this gate. Keep stderr separate and give the
validator the same resolved cwd and concrete model used for the supervised
Claude argv, with the current lane's fixed local-login authentication source:

```text
<trusted-python-absolute-path> -I -B -S <trusted-bundle-absolute-path>/scripts/named_lane_guard validate-claude-stream
  --cwd <resolved-clean-worktree>
  --model <claude-opus-4-8-or-authorized-4-7>
  --api-key-source none
  --process-returncode <exact-child-returncode>
  --input <bounded-raw-stream-jsonl>
```

The executable/importable validator applies the versioned machine contract and
fixed upper bounds of 8 MiB total input, 10,000 raw lines, 1 MiB per line,
and 128 decimal digits per JSON integer. JSON floating-point tokens are parsed
exactly as decimal values, with at most 256 characters, 128 significand digits,
and an absolute explicit exponent no greater than 308. These parser bounds do
not depend on Python's process-global integer-string conversion limit and prevent
binary floating-point overflow or negative underflow from changing a metric's
sign.
It emits one JSON object with `classification: accepted` and the verbatim
`findings` only after the exact child process return code is integer zero and
every envelope, init, and terminal-success check passes. A nonzero child return
code, including `401`, is `inconclusive` by itself; authentication classification
requires recognized structured authentication evidence rather than an exit-code
guess. When the fully validated stream instead supplies deterministic structured
`blocked` or `blocked-authentication` evidence, preserve that classification even
with a nonzero child return code; the return code never turns such a failure into
success. An invalid or missing child return code is always `inconclusive`.
Every failure emits a fail-closed `blocked`, `blocked-authentication`, or
`inconclusive` classification without a `findings` field. Validator acceptance
attests only the reported invocation fields and terminal artifact; it never
claims proof of the final merged sandbox, managed permission arrays, or path-rule
evaluation.

The validator is a machine interface, not a help-text interface. `-h`, `--help`,
missing or unknown arguments, and invalid choices all return nonzero, emit exactly
one `inconclusive` JSON object on stdout, and leave stderr empty. Exit status zero is reserved for `accepted` output.

Before accepting the result, compare the leading init against a reviewed, version-specific expected-init contract for the publisher-verified installed CLI. For Claude Code 2.1.212, require all of these observable fields:

- `cwd` equals the resolved lane-unique clean worktree exactly;
- `permissionMode` equals `dontAsk`;
- `tools` is a duplicate-free set exactly equal to `Read`, `Grep`, `Glob`, and `Bash`;
- `mcp_servers`, `slash_commands`, `skills`, and `plugins` are present and exactly empty arrays;
- `model` equals the requested concrete model string exactly, without alias normalization or silent substitution;
- `claude_code_version` equals the publisher-verified preflight version; and
- `apiKeySource` is exactly the string `none`, matching ordinary local login in Claude Code 2.1.212. The validator/schema compatibility surface can represent `ANTHROPIC_API_KEY` for explicit API-key mode and `none` for ordinary local login, but the current `run-claude` launcher exposes no API-key input; `ANTHROPIC_API_KEY` therefore cannot satisfy this canonical lane.

Missing, malformed, or conflicting required fields fail closed as `inconclusive` and cannot count as the Claude lane. A well-formed required field that mismatches the frozen launch is a deterministic `blocked` configuration/policy mismatch. A CLI version other than exact `2.1.212` is blocked before review input is exposed; adding another version requires its own reviewed init and terminal schema. The init top-level field set is closed for this version: only the required fields above plus an optional nonempty string `session_id` are accepted. `hooks`, `agents`, or any other unknown init field is `inconclusive` until a reviewed version-specific schema update permits it. These observable init fields still do not prove the final merged sandbox, managed permission arrays, or path-rule evaluation.

For the Claude Code 2.1.212 terminal `result`, require this exact acceptance schema:

- `type` is the string `result`, `subtype` is the string `success`, and `is_error` is the boolean `false`;
- `result` is a required string whose `strip()` value is nonempty; preserve the original string verbatim as the findings payload;
- `modelUsage` is a required nonempty object; every key is a nonempty model-ID string and every value is an object. For Claude Code 2.1.212, the only reviewed terminal aliases for requested `claude-opus-4-8` are `claude-opus-4-8` and `claude-opus-4.8`; the only aliases for requested fallback `claude-opus-4-7` are `claude-opus-4-7` and `claude-opus-4.7`. At least one key must belong to the exact requested model's set. The only reviewed auxiliary key is `claude-haiku-4-5-20251001`. A key from the other supported primary-model set is a deterministic blocked model substitution even when a requested-model key is also present; any other model-usage key is `inconclusive` until a reviewed schema update permits it. Thus a `claude-opus-4-8` request with only or with both a `claude-opus-4-7` key is never accepted;
- `duration_ms` and `duration_api_ms`, when present, are nonnegative integers; `num_turns` is a positive integer; `total_cost_usd` is a nonnegative finite exact-decimal number within the stream parser's lexical and exponent bounds; `session_id` and `uuid` are nonempty strings; and `usage` is an object. When both init and terminal events report `session_id`, the values must match exactly or the stream is `inconclusive`. A missing optional metric is acceptable, but a present value with the wrong type or range is `inconclusive`;
- `stop_reason`, when present, is exactly `null` or `end_turn`. Any other value—including `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, or `refusal`—is a deterministic blocked incomplete or abnormal terminal result and cannot supply findings;
- `structured_output`, when present, is exactly `null` because the canonical launch does not request a structured-output schema. A non-null value is contradictory evidence and makes the lane `inconclusive`;
- `error` and `errors`, when present, are explicitly empty: `null`, a whitespace-only string, an empty array, or an empty object;
- `api_error_status`, when present, is `null` or a whitespace-only string; and
- `permission_denials`, when present, is an empty array.

A non-success subtype, `is_error: true`, blank/non-string `result`, missing or malformed `modelUsage`, no requested-model match, unaccepted `stop_reason`, non-null `structured_output`, nonempty `error`/`errors`, nonempty `api_error_status`, or nonempty/malformed `permission_denials` fails closed and cannot supply findings. Classify a structurally valid permission denial, output truncation/abnormal stop, exact-model mismatch, or configuration/policy mismatch as `blocked`. When a non-success terminal follows any deterministic init or terminal blocker, absence of error prose preserves `blocked` and does not add a generic unclassified reason. Classify only a structurally valid recognized `Login expired`, explicit HTTP/status 401, explicit OAuth/credential/login/authentication/token refresh error, or directly adjacent expired/invalid/unauthorized authentication state as `blocked-authentication`. Generic token counting, usage, budget, quota, capacity, rate-limit, or limit errors, credential-file/I/O errors, a bare child exit code 401, non-authentication refresh failure, malformed evidence, contradictory evidence, or mixed-category evidence are `inconclusive`.

The only non-authentication error prose that authorizes the pinned-model fallback is a strict recognized model-entitlement or organization-policy denial, including exact account/plan model-access denials and reviewed structured model-entitlement codes. The validator emits `classification: blocked` with machine reason `terminal.model-entitlement-denial` or `terminal.organization-policy-denial`; a parent may advance from `claude-opus-4-8` to `claude-opus-4-7` only when every classified message belongs to those two categories. Mixed, extended, authentication, resource/quota/capacity/rate-limit, unclassified, or ambiguous evidence is `inconclusive`, and prose inspection outside the validator never authorizes fallback.

The machine-readable Claude Code 2.1.212 contract is [claude-2.1.212-stream-schema.json](claude-2.1.212-stream-schema.json). Its required and optional terminal-field lists form a closed top-level allowlist. Any other terminal field, including an unknown error-bearing field, makes the lane `inconclusive` until a reviewed schema update explicitly adds it. Do not infer a model alias or harmless metadata field from punctuation, provider convention, or a later CLI version.

This evidence verifies only what the CLI reports about that invocation. It does not prove the final merged native sandbox, merged admin-managed permission arrays, path-rule evaluation, or absence of unreported CLI control-plane side effects. Capability output and init evidence must never be promoted into such proof.

## Guidance And Evidence

The control prompt must require Claude to:

1. read repo-wide tracked guidance;
2. obtain changed-path metadata only;
3. read applicable path-scoped `AGENTS.md`, repo-local domain skills, and tracked project guidance;
4. inspect the exact range incrementally with bounded Git, `Read`, `Grep`, `Glob`, and sandboxed read-only Bash;
5. never run `fetch`, `pull`, or another networked Git operation because the parent already proved the frozen scope locally complete;
6. avoid direct reads outside the logical review workspace and every mutation;
7. return findings only, or exactly `No findings.` when clean.

After `run-claude` has completed inherited-stream drain, initial-process-group cleanup, direct-child reap, and complete bounded-output publication, pass the raw stdout and exact child return code to the strict validator. Accept only its strict init/result evidence from the actual Claude process, extract the terminal findings verbatim, and bind them to the frozen range in the parent-owned lane record. The supervisor's success cannot replace validator acceptance, and validator acceptance cannot replace successful supervision and cleanup. Progress, tool traces, stdout/stderr tails, partial JSON, silent model substitution, and helper output do not count.
