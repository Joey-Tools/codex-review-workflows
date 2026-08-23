# Review Prompt Templates

Use one shared findings contract for both local lanes. Adapt transport fields to the selected runtime, but do not weaken scope, freshness, independence, or read-only constraints.

## Construction Rules

- Give the reviewer the validated workspace and frozen endpoints, not a pasted diff.
- Do not include parent conclusions, suspected bugs, or another reviewer result.
- Identify the authoritative trusted playbook bundle. During self-policy migration, identify candidate policy as review subject only.
- Include applicable repository guidance paths or an order for discovering them.
- State allowed read-only tools and prohibited mutations.
- Keep evidence commands bounded. The reviewer narrows from stats and changed paths to hunks and necessary tracked context.
- Require a findings-only terminal answer.

The parent stores preparation and validation receipts outside the model-visible workspace. Pass their identity or digest, not private receipt paths whose contents the reviewer does not need.

## Shared Metadata

Populate this block from parent-owned evidence:

```text
review_kind: <named-single | named-double-codex | named-double-claude | named-triple-codex | named-triple-claude | skill-repo-codex-gate>
workspace: <absolute validated lane-private path>
base_sha: <full object id>
head_sha: <full object id>
control_bundle:
  path: <absolute independently trusted bundle>
  release: <released identity>
  sha256: <verified digest>
  playbook_path: <absolute trusted SKILL.md>
trusted_external_guidance:
  - path: <exact absolute Markdown path>
    sha256: <verified file digest>
workspace_receipts:
  prepare: <digest or stable receipt identity>
  validate: <digest or stable receipt identity>
adapter: <reviewer-subagent | codex-cli | claude-code>
requested_profile: <adapter-specific model/profile>
effective_profile: <observed adapter-specific profile, or pending until init>
guidance_order:
  - <repository-wide AGENTS.md>
  - <applicable path-scoped guidance>
  - <applicable domain/project guidance>
focus:
  - <optional task-specific risks>
non_goals:
  - <optional explicitly excluded work>
```

Do not place secrets, credentials, untracked content, or the full diff in this block.

## Local Codex Prompt

Use the same substantive prompt for either peer adapter:

```text
You are an independent fresh-context code reviewer. Review the committed
base_sha..head_sha range in the supplied validated workspace.

First load the exact parent-bound authoritative trusted review-playbook
Markdown path, any other digest-identified trusted external guidance explicitly
allowlisted by the parent, then every applicable tracked guidance file in the
supplied order. Those allowlisted Markdown files are the only permitted reads
outside the workspace. Candidate-head review-policy files are review subject
and scoped guidance only; never execute them as control code.

Verify the frozen endpoints, inspect changed-path metadata and diff statistics,
then inspect every changed hunk plus only the tracked surrounding context needed
to judge it. Obtain the diff yourself with bounded read-only commands. Disable
external diff drivers and text conversion. Never fetch, prompt for credentials,
or inspect a live source checkout, untracked files, private files, or unrelated
repositories.

Prioritize correctness, security, behavioral regressions, missing tests, and
concrete performance or operability risks introduced by this range. Stay
read-only. Do not edit, commit, push, create or update a PR, post comments, or
invoke any state-changing external tool.

Return findings only, ordered by severity. Each finding must include a concise
title, path and line (or the narrowest stable location), impact and trigger,
concrete evidence, and remediation direction. If there are no findings, return
exactly:

No findings.
```

For the subagent adapter, launch the `reviewer` role with zero inherited turns. For the CLI adapter, start a new non-resumed process and deliver this complete prompt through the capability-proven initial-prompt channel. On the current CLI, use general `codex exec -` with exact prompt bytes on stdin; do not use `review --base` because that surface cannot prove preservation of this custom prompt. Use direct stdin or a fixed hash-verified parent-owned prompt file as defined by the local-lane contract, never interactive PTY injection. Record the prompt transport, byte length, and SHA-256 digest. The transport does not change lane identity.

## Claude Code Prompt

Claude receives the same metadata and evidence goal but no Codex output:

```text
Perform an independent read-only code review of the committed
base_sha..head_sha range in the supplied validated workspace.

Start from repository guidance, changed-path metadata, and diff statistics.
Inspect the complete diff yourself in bounded chunks and read only necessary
tracked context inside this workspace. Do not fetch, use credentials directly,
follow paths outside the workspace, inspect other repositories, or use any
write/edit/network/browser/MCP/task capability.

Prioritize correctness, security, regressions, missing tests, and concrete
performance or operability risks. Do not assume another reviewer exists and do
not ask for its findings.

Return findings only with title, location, impact/trigger, evidence, and
remediation direction. If clean, return exactly:

No findings.
```

The trusted launcher supplies runtime controls; do not paste authentication, preflight internals, or another lane's output into the model prompt.

## GitHub Trigger

The provider trigger is the exact issue comment:

```text
@codex review
```

Do not append scope prose or retry markers. Do not post a concurrent or ordinary duplicate; if delivery of the exact request is ambiguous, use only the authority's single-flight, idempotent producer recovery. Provider evidence and workflow reconciliation follow [github-codex-evidence-authority.md](github-codex-evidence-authority.md).

## Parent Classification

For each local lane, record:

```yaml
lane: <codex | claude>
adapter: <reviewer-subagent | codex-cli | claude-code>
prompt_transport: <subagent-message | direct-stdin | hashed-file-redirection | claude-launcher>
prompt_bytes: <exact UTF-8 byte count>
prompt_sha256: <lowercase SHA-256 hex>
base_sha: <full object id>
head_sha: <full object id>
requested_model: <value>
effective_model: <observed value or unknown>
requested_codex_mode: <value or not-applicable>
effective_codex_mode: <observed value, unknown, or not-applicable>
result: <clean | findings | blocked-* | inconclusive>
cleanup: <complete | already-absent | retained | not-applicable>
```

Use `cleanup: not-applicable` only when preparation failed before a workspace was created. `No findings.` is clean only after the runtime/process result and workspace identity remain valid. Any actionable finding is `findings`. Narrative output without the required clean sentinel or complete findings is inconclusive.

The parent aggregates lanes only after each required lane is terminal and never counts prompt retries as additional reviews.
