# Local Codex Lane

The named local Codex lane is one logical, fresh-context review of the frozen committed range. A subagent and a CLI process are peer adapters for that lane.

## Lane Identity

One requested lane has one parent-owned lane record:

- `base_sha` and `head_sha`;
- independent workspace and successful preparation/validation evidence;
- authoritative review-policy bundle identity;
- selected adapter;
- requested and effective model and Codex mode;
- parent-owned `sanitized_git_argv_prefix` profile/digest, fixed Git
  path/version, workspace validation-receipt identity, prompt-delivery and
  read-only-boundary evidence, plus the Git-argv observation level the adapter
  actually exposes;
- terminal result and cleanup status.

Retries, switching adapters, or Codex Ultra's internal delegation do not increment the lane count. Never describe internal workers as a double or triple review.

## Peer Adapters

Neither adapter has a standing priority.

| Adapter | Use when | Operational trade-off |
| --- | --- | --- |
| Fresh `reviewer` subagent | The host can launch the installed role with zero inherited turns and enforce a read-only workspace. | Direct orchestration, mailbox lifecycle, and role reuse; the effective role profile may be partly controlled by the host. |
| Fresh Codex CLI review process | The CLI can explicitly bind the workspace, fresh session, model/mode, and read-only execution. | Explicit binary/version/profile evidence and little parent-context coupling; the parent owns process, output, and sandbox supervision. |

Choose from observed capability, effective reviewer strength, orchestration simplicity, expected latency, and parent-context cost. Do not claim one adapter produces intrinsically better findings without evidence.

### Subagent adapter

- Launch the installed `reviewer` role with `fork_turns="none"` or the platform's exact zero-inherited-context equivalent.
- Do not use a default coding child, a resumed child, or the parent conversation.
- Give it only the control metadata and review prompt described below.
- Include the exact parent-owned `sanitized_git_argv_prefix` token array and
  digest. Require every Git tool call to copy it verbatim. Record available host
  tool-call evidence; when the collaboration runtime does not expose complete
  argv, record `unobservable` rather than treating that absence as deviation.
- Require a read-only sandbox and no state-changing external tools.

### CLI adapter

- Start a new, non-resumed Codex review process in the validated workspace. Never reuse a parent or earlier reviewer session.
- Deliver the complete parent-constructed control metadata and shared review prompt through the CLI's initial-prompt channel. Do not assume a specialized review subcommand accepts, preserves, or combines a custom prompt with its range selector.
- Include the same exact parent-owned `sanitized_git_argv_prefix` token array
  and digest used by the subagent adapter. The CLI process `-C` selects the
  model workspace but does not replace the prefix required for every
  model-issued Git call. Retain structured tool-event argv when the CLI exposes
  it; otherwise record the observation level as `partial` or `unobservable`.
- Explicitly bind the intended model/mode, read-only sandbox, workspace, and fresh-session controls.
- Preflight the effective instruction surface. `--ignore-user-config` suppresses `$CODEX_HOME/config.toml`; it does not by itself suppress global `AGENTS.md`, skill instructions, or other ambient guidance. Bind every admitted external guidance file by resolved path and digest, or use a version-proven instruction-isolation control. Any unallowlisted external model/tool read invalidates the attempt.
- Capture the effective CLI version, model, mode, exit status, and bounded final output.
- Treat an output or process limit, interactive prompt, sandbox failure, or ambiguous profile selection as inconclusive rather than clean.

For the currently supported CLI surface, the normalized direct-argv shape is:

```text
<absolute-codex> exec
  --ephemeral
  --ignore-user-config
  --strict-config
  -s read-only
  -m gpt-5.6-sol
  -c model_reasoning_effort="ultra"
  -C <absolute-validated-workspace>
  --json
  -
```

Keep every Codex argument literal. Write the exact UTF-8 prompt bytes to the child's stdin descriptor and then close it; `-` is the explicit stdin-prompt selector. The prompt carries the full `base_sha` and `head_sha`, while the validated detached `HEAD` is the same full `head_sha`.

Prefer a direct parent-process stdin write. When the orchestrator exposes only a shell command interface, one fixed single-command `< <absolute-parent-owned-prompt-file>` redirection is also valid after the parent records the regular file's identity, byte length, and SHA-256 digest and revalidates them after process exit. The command must use a resolved shell and literal absolute paths; never embed prompt content in the command, use a pipeline, command substitution, heredoc, environment expansion, or interactive PTY injection. PTY bulk writes can drop or transform bytes and are not a prompt-integrity transport.

As observed on Codex CLI 0.149.0, the specialized `review --base` surface rejects a positional custom prompt and does not provide a receipt proving that an stdin prompt was preserved. It is therefore not the normalized adapter for that version. A future review entrypoint may replace general `exec -` only after a credential-free capability probe proves that it accepts the complete shared prompt, binds the exact frozen range, and exposes enough evidence to verify both properties. An equivalent future spelling must preserve fresh non-resumed execution, explicit config selection, a digest-bound or capability-isolated instruction surface, read-only sandboxing, exact cwd/range, and structured bounded output.

The CLI lane receipt binds the resolved binary/version, exact argv projection, prompt transport (`direct-stdin` or `hashed-file-redirection`), prompt file identity when applicable, prompt byte length and SHA-256 digest before and after launch, workspace prepare/validate receipt digests, base/head, process exit, output digest, and any runtime-reported effective model/mode. It also records the `sanitized-git-argv-prefix-v1` digest, fixed Git path/version, canonical workspace and validation-receipt identity, verified prompt delivery, established read-only adapter boundary, actual tool-event coverage (`complete`, `partial`, or `unobservable`), and any observed prefix deviation. Strict accepted argv plus the requested profile and absence of a substitution/error is direct intent evidence; if the runtime exposes no effective-profile field, record the effective value as `unknown`. An observed mismatch or downgrade is inconclusive. A resume/fork/session selector, unsupported flag, prompt mismatch, cwd/range mismatch, absent terminal result, changed prompt-file identity/digest, unavailable required boundary, or observed prefix deviation is also inconclusive. Partial or unobservable Git-argv telemetry remains a reported limitation but is not by itself a failure.

## Reviewer Profile

The intended installed profile is:

- model: `gpt-5.6-sol`;
- Codex profile/mode: `ultra`;
- context: fresh;
- access: read-only;
- output: findings only.

`ultra` is a Codex profile/mode that may use internal delegation. It is not documented here as an OpenAI API `reasoning.effort` enum value. Regardless of implementation, one Ultra invocation remains one logical lane.

Record both requested and effective values. A configuration file proves intent, not runtime effect. Prefer a host/runtime receipt when available; otherwise record the strongest direct observation and mark unobservable fields as `unknown`.

## Avoid Routine Model Discovery

Do not query the network or enumerate model catalogs for every review. The installed skill and role are the normal source of the intended profile.

Check current official OpenAI model guidance only when either condition holds:

1. the parent session's effective model family or Codex mode is clearly stronger than the configured reviewer; or
2. the runtime rejects, silently downgrades, or reports a mismatch for the intended reviewer profile.

If neither condition holds, do not perform a latest-model lookup. This reduces latency, tokens, and unnecessary external reads.

## Fallback Order

When the first adapter cannot realize the intended profile:

1. Try the peer adapter with the same model and `ultra` mode.
2. If both adapters cannot realize `ultra` on the same model, use the highest supported lower mode only when the review can still be meaningfully completed; record the downgrade prominently.
3. Do not move to an older model family without explicit user confirmation.

A transient adapter or service failure is retryable. A stable rejected profile with no authorized fallback is blocked. An unproved effective profile is inconclusive; never report it as the requested profile.

## Launch Sequence

1. Freeze the committed range and choose one adapter.
2. Prepare a lane-unique workspace through [review-workspace.md](review-workspace.md).
3. Validate the same workspace and endpoints immediately before launch.
4. For a self-policy migration, bind the prior trusted installed bundle as described in [review-lane-contracts.md](review-lane-contracts.md).
5. Launch the reviewer with [review-prompt-templates.md](review-prompt-templates.md).
6. Let the reviewer load applicable guidance and inspect the diff itself.
7. Classify the bounded terminal output.
8. Clean up the workspace by default and record the cleanup result.

Do not give the reviewer a prebuilt full diff, parent findings, another reviewer's output, or untracked/private files.

## Review Behavior

The reviewer should:

- verify the supplied endpoints before reading hunks;
- use only the exact supplied `sanitized_git_argv_prefix` for every Git call;
- treat `base_sha..head_sha` as the complete DAG range, retaining merge commits and side history rather than substituting a first-parent or ancestry-path projection;
- inspect changed-path metadata, stats, and the diff in bounded chunks;
- load repository-wide and path-scoped `AGENTS.md` plus applicable project guidance before judging affected code;
- inspect only the necessary tracked surrounding context;
- prioritize correctness, security, regressions, missing tests, and concrete performance or operability risks;
- remain read-only and avoid GitHub, messaging, PR, or other state-changing actions.

Bare or alternate Git, a reconstructed or modified prefix, an additional `-C`,
a global `--git-dir` / `--work-tree`, and an overriding environment assignment
or `-c` are forbidden. Every diff-producing Git command appends
`--no-ext-diff` and `--no-textconv`. Missing objects must surface as
`range-incomplete`; the reviewer never fetches.

For either peer adapter, the prefix is a prompt/tool-observation contract rather
than an operating-system guarantee. Missing/altered prefix delivery, inability
to establish the required read-only boundary, or any observed deviation makes
the lane inconclusive; a clean-looking terminal answer cannot repair it. When
the runtime exposes no complete Git argv, record `unobservable` as a limitation,
not as proof of either compliance or deviation.

## Result Contract

Order findings by severity. Each finding contains:

- concise title;
- path and line or the narrowest stable location;
- impact and triggering condition;
- concrete evidence;
- remediation direction.

If there are no findings, return exactly:

`No findings.`

Narrative summaries without a clean sentinel or actionable finding are inconclusive. The parent, not the reviewer, decides whether all requested lanes and PR-readiness gates pass.
