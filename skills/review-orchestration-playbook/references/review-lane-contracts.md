# Review Lane Contracts

This file defines shared scope, independence, counting, outcomes, and rerun rules. Adapter mechanics live in the lane-specific references.

## Canonical Shapes

| Shape | Completion requirement |
| --- | --- |
| Named single | One clean logical local Codex lane. |
| Named double | Named single plus one clean actual Claude Code lane. |
| Named triple | Named double plus a passing current-head GitHub Codex lane. |
| `skill-repo-codex-gate` | One clean logical local Codex lane plus a passing current-head GitHub Codex lane. This is an unnamed repository default, not a named shape. |

Count logical independent judgments. Do not count:

- retries or adapter switches;
- Ultra's internal delegation;
- preparation, validation, admission, CI, or PR-readiness gates;
- a Claude simulation, another Codex process, or GitHub Copilot in place of actual Claude Code;
- service-start checks without a review result.

## Frozen Range

Every local lane uses the same exact full-object-ID `base_sha..head_sha` range.

- Both endpoints are committed and locally complete for the comparison.
- `base_sha` is an ancestor of `head_sha`.
- The comparison is the complete reachable DAG set `reachable(head_sha) - reachable(base_sha)`. Merge commits and every in-range side-history commit belong to the range.
- No lane may substitute `--first-parent`, `--ancestry-path`, a single-parent walk, or a linear-history requirement for that set.
- The range is immutable for the lane attempt.
- Reviewers inspect only committed tracked state. Untracked files and live working-tree changes are outside the lane.
- The parent provides endpoints and control metadata, not a prepared full diff.

A selected PR is a separate selector. For whole-PR readiness or triple coverage, authenticated PR state must show an open, unmerged PR whose current `headRefOid` equals `head_sha` and whose unique current merge base equals `base_sha`. A caller-supplied range is never silently rewritten to make it fit a PR.

An explicit range-only single or double needs no PR probe. A report-only request with no resolvable committed range is `blocked-input`. Intended dirty state that would require an unauthorized commit is `blocked-authorization`.

## Independent Local Workspaces

Each local lane gets a different workspace prepared and validated under [review-workspace.md](review-workspace.md).

The required properties are:

- detached exact `head_sha` checkout;
- clean index and worktree;
- no source checkout, config, hooks, untracked state, or initialized submodules;
- independent Git directory, common directory, and object storage;
- no hardlinks, alternates, borrowed object store, or linked-worktree back-pointer;
- an exact reviewer-visible
  `git rev-list --parents --full-history base_sha..head_sha` DAG matching the
  frozen raw range and raw parent tuples, with synthetic shallow boundaries only
  at safely representable missing-parent frontiers and no suppressed locally
  known parent edge;
- one fixed absolute Git executable, preflighted as normal or Apple Git
  `>=2.45.0` before any repository command and reused for every bounded,
  pack/index, and direct-process Git invocation in that operation;
- no reviewer fetch or credential prompt;
- read-only reviewer execution.

The source may itself be shallow, partial/promisor, or alternate-backed when the
complete scoped snapshots and every required direct-parent snapshot are local.
A missing pre-base parent frontier is representable only when marking its
present child shallow suppresses no locally known edge; otherwise preparation is
`range-incomplete`. The destination imports every required object and retains
none of the source's storage dependencies.

The current helper writes one range manifest and one disjoint
`review-parent-support-objects` manifest, then normalizes their sorted union into
one exact pack. Preparation and validation receipts type-preservingly bind both
`range_object_count` / `range_object_sha256` and
`parent_support_object_count` / `parent_support_object_sha256`. The object-count,
logical-byte, compressed-pack, pack-index, and preparation-deadline caps apply to
the complete imported union. For a complete source the destination shallow
receipt binding is empty and `.git/shallow` is absent; a fixed `base_sha`
shallow boundary is forbidden.

A future copy-on-write strategy is eligible only when it starts from a validated
immutable seed and proves separate directory entries/inodes. Extra committed
base-history support objects are allowed by the public workspace contract; exact
total-object inventory is not a portable lane requirement.

## Self-Policy Migration Trust Boundary

When the frozen range changes any review-control material—including this skill, `agents/reviewer.toml`, prompt templates, workspace helper, Claude launcher, model policy, or result validator—the candidate cannot bootstrap its own approval.

The parent must:

1. select an independently trusted installed bundle outside the candidate range;
2. record its absolute path, released identity, and complete control-bundle digest;
3. revalidate that identity before and after each formal lane;
4. use its role, helper, prompts, launchers, and validators as the control plane;
5. treat candidate-head Markdown as review subject and applicable repository guidance only;
6. never execute candidate-head Python, shell, or machine schema to approve the candidate.

For the Codex CLI adapter, self-policy isolation additionally requires:

- automatic `AGENTS.md`, skills-catalogue, plugin, hook, and user/project-rule
  loading to be absent through version-proven controls plus isolated roots;
- an owner-private empty neutral launch root outside the candidate and source
  checkout when the CLI cannot disable every project-config layer before read;
- a fresh owner-private temporary auth-only `CODEX_HOME`, because the ordinary
  home remains a global-`AGENTS.md` source even when the other controls are
  active;
- a fixed shell-environment policy that hides `CODEX_HOME` and ordinary
  key/secret/token variables from model-issued subprocess environments, plus a
  prompt prohibition on authentication credential discovery or model-tool
  access to `auth.json`; this reduces discoverability but does not prove
  filesystem deny-read separation from the Codex runtime that must authenticate
  with that file;
- pre/post neutral-root, auth-home, and version-bound instruction-surface
  receipts; and
- every candidate Markdown file consumed as guidance to be explicitly listed
  by the trusted parent prompt with its workspace-relative path, digest, and
  purpose (`review-subject`, `scoped-convention`, or `both`).

Candidate text cannot opt into another skill, rule, plugin, hook, agent, config
layer, or external file. Any automatic candidate/user guidance injection makes
the attempt inconclusive. Built-in/runtime platform instructions may remain as
a recorded version-bound CLI baseline; do not misdescribe this boundary as
total prompt isolation.

If the prior bundle does not expose the new workspace interface, review the migration under the prior trusted policy, merge and release it, then activate and smoke-test the new interface from that trusted release. Do not mix old and candidate control components into a synthetic policy.

## Common Prompt Contract

Every local reviewer receives:

- absolute validated workspace;
- frozen base and head;
- authoritative control-bundle identity;
- workspace preparation and validation receipt identity;
- selected adapter/runtime identity;
- applicable guidance-loading order;
- review focus and explicit non-goals;
- read-only and external-action prohibitions;
- findings-only output contract.

Every local Codex reviewer also receives the parent-owned
`sanitized_git_argv_prefix` exact token sequence plus its identity metadata as
defined below. The prefix is opaque to the reviewer: it is copied, not rebuilt
from prose.

The reviewer must obtain stats, changed paths, hunks, and necessary nearby tracked context itself with bounded commands. Do not inject the full diff, parent conclusions, or another lane's findings.

For a process adapter, the parent serializes this metadata and the substantive prompt into exact UTF-8 bytes, delivers those bytes through a capability-proven initial-prompt channel, and records their byte length and SHA-256 digest. A runtime's default review prompt or range selector never substitutes for this control prompt. If the parent cannot prove that the selected entrypoint accepts both the complete prompt and the frozen range, use another verified entrypoint or classify the launch as inconclusive.

Use [review-prompt-templates.md](review-prompt-templates.md) to construct the prompt.

### Parent-Owned Reviewer Git Prefix

After the final successful workspace validation, the parent materializes one
ordered `sanitized_git_argv_prefix` for that exact Codex lane. It binds:

- the fixed absolute Git executable and the exact accepted `git --version`
  result used for the lane;
- the canonical validated workspace and its validation-receipt identity;
- the closed environment-key allowlist and fixed safe Git options below; and
- `sanitized_git_argv_prefix_sha256`, the lowercase SHA-256 of the exact UTF-8
  JSON token-array bytes placed in the control metadata.

The ordered token profile is `sanitized-git-argv-prefix-v1`:

```text
/usr/bin/env
-i
PATH=<parent-recorded-trusted-path>
LANG=<parent-fixed-locale>
LC_ALL=<parent-fixed-locale>
GIT_ASKPASS=/usr/bin/false
GIT_ATTR_NOSYSTEM=1
GIT_CEILING_DIRECTORIES=<absolute-clean-workspace-parent>
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_GRAFT_FILE=/dev/null
GIT_NO_LAZY_FETCH=1
GIT_NO_REPLACE_OBJECTS=1
GIT_OPTIONAL_LOCKS=0
GIT_TERMINAL_PROMPT=0
PAGER=cat
GIT_PAGER=cat
<fixed-absolute-git-executable>
--no-pager
--no-lazy-fetch
-c core.commitGraph=false
-c core.checkStat=default
-c core.multiPackIndex=false
-c core.fsmonitor=false
-c core.fileMode=true
-c core.ignoreStat=false
-c core.trustCtime=true
-c core.hooksPath=/dev/null
-c core.attributesFile=/dev/null
-c diff.external=
-c color.ui=false
-C <absolute-clean-workspace>
```

Each displayed `-c name=value` line represents two argv tokens. All other lines
represent one token. The parent chooses the recorded path, locale, executable,
and workspace values once; the reviewer may not substitute values, reorder
tokens, add environment assignments or `-c` overrides, or reconstruct a
semantically similar command.

For every Git invocation, both the subagent and CLI adapters require the
reviewer to copy this prefix token-for-token and append only the read-only Git
subcommand and its arguments. Bare `git`, an alternate Git executable or
wrapper, an additional `-C`, a global `--git-dir` / `--work-tree` selector, and
a different workspace are forbidden. Every diff-producing subcommand also
appends both `--no-ext-diff` and `--no-textconv`.

The lane receipt records the prefix profile and digest, fixed Git path/version,
workspace validation-receipt identity, verified prompt delivery, the established
read-only adapter boundary, and the strongest Git-argv observation the adapter
actually exposes: `complete`, `partial`, or `unobservable`. Record every observed
deviation separately.

Missing or altered prefix metadata, unproved prompt delivery, inability to
launch under the required read-only adapter boundary, or any observed deviation
makes the Codex lane `inconclusive`, never clean. `partial` or `unobservable`
argv evidence is a recorded limitation, not evidence of deviation and not by
itself a lane failure. When the prefix/digest was delivered intact, the required
adapter boundary was established, and available evidence contains no deviation,
the lane may still complete; report the observation limitation without claiming
argv-level enforcement.

This is a prompt and tool-observation boundary, not an operating-system
enforcement claim. `/usr/bin/env -i` sanitizes only a process actually launched
with the supplied argv. A prompt, prefix digest, or tool transcript does not by
itself prove that the model could not invoke another executable; the parent may
claim only the boundary and argv visibility that the adapter runtime actually
attests, and must not reinterpret `unobservable` as either compliance proof or
deviation.

## Local Codex Contract

Read [local-codex-lane.md](local-codex-lane.md).

- A zero-inherited-context `reviewer` subagent and a fresh non-resumed Codex CLI review are peer adapters.
- The intended installed profile is `gpt-5.6-sol` with Codex mode `ultra`.
- Record requested and effective adapter, model, and mode.
- Record `effective_profile_basis` as `runtime-attested`,
  `accepted-pinned-launch`, `unknown`, or `mismatch`.
- Every CLI adapter uses the temporary auth-only `CODEX_HOME` contract in
  [local-codex-lane.md](local-codex-lane.md). Each CLI process gets a fresh
  home that is destroyed rather than purged and reused. Routine gating uses the
  credential-free capability/prompt probe, forced-file `login status`, and the
  actual review exec's own structured terminal evidence—not an additional paid
  exec preflight. A non-file credential source or unsafe copy/validation blocks
  that adapter; selecting the peer subagent at the same requested profile
  remains the same logical lane.
- Switch adapters before lowering the mode. Moving to an older model family requires explicit user confirmation.
- One invocation remains one logical lane even when Ultra delegates internally.

Both peer adapters use the same effective-profile rule. An exact
`runtime-attested` match may support clean. When authoritative runtime fields are
absent, a version-proven exact CLI argv accepted through a successful complete
run, or a trusted digest-bound reviewer role accepted by the host, is
`accepted-pinned-launch` and may supply the requested pinned model/mode as
execution-level effective values. This does not attest provider backend aliases,
routing, or weights. `unknown` and `mismatch` are always inconclusive; a clean
sentinel never repairs either state.

## Claude Code Contract

Read [canonical-claude-lane.md](canonical-claude-lane.md).

- Start one actual supported Claude Code process in its own independently prepared workspace.
- Give it the same frozen range and an independent prompt; never give it Codex findings.
- Use the trusted runtime preflight, direct launcher, and strict output validator.
- The named direct lane uses ordinary local login in trusted real `HOME`. It exposes no API-key or OAuth-token launch interface.
- Only validator-accepted terminal output can be clean or findings.

## GitHub Codex Contract

Read [github-codex-evidence-authority.md](github-codex-evidence-authority.md) before producer or consumer work.

- The lane is current-head and PR-scoped.
- Base/merge-base coverage is established locally; do not infer it from provider output.
- A trustworthy terminal clean provider comment/review at the latest head plus
  no applicable unresolved provider finding passes. The compatibility shorthand
  `latest head plus no unresolved provider finding passes` always means this
  applicability-filtered rule.
- Prefer a trustworthy associated merge-commit/provider status when present,
  while still checking applicable unresolved findings.
- A complete exact-provider `+1` reaction basis is a fallback, not the preferred artifact.
- Only applicable unresolved provider findings block. On the same head, an
  exact typed GraphQL thread resolution or a later trustworthy provider
  correction accepted by the evidence authority clears the corresponding
  finding after a complete stable reread. A service-start check alone never
  passes.
- Automatic recovery is only for a machine-decidable transient pending or
  infrastructure reason. A stable malformed snapshot, scope contradiction, or
  other non-retryable inconclusive state stops recovery; code findings, test
  failures, and policy failures are never reconciled as infrastructure.
- A workflow rerun or dispatch requires both a repository-predeclared
  idempotent or reentrant contract for that exact frozen-scope operation and
  current authorization for the external mutation. Otherwise recovery remains
  read-only status polling.

The evidence authority owns exact identities, pagination, terminal selection, reaction fallback, retry state, and report fields.

## Egress And Independence

Before launching any reviewer, apply [egress-consent.md](egress-consent.md).

Each lane starts without another lane's output. The parent may aggregate only after each lane reaches a terminal result. A reviewer must not:

- edit the workspace;
- commit, push, create or update a PR, or post a comment;
- run state-changing GitHub, connector, browser, messaging, or external-system actions;
- inspect untracked/private files or unrelated repositories;
- fetch missing Git objects.

The GitHub producer is the narrow exception for the authorized exact
`@codex review` producer operation and any separately authorized,
repository-predeclared idempotent or reentrant workflow reconciliation. An
ambiguous request delivery enters only the evidence authority's single-flight
read/reread recovery; it never authorizes another POST. The GitHub write is not
intrinsically idempotent.

## Outcome Vocabulary

Use these meanings consistently:

| Status | Meaning |
| --- | --- |
| `clean` | The lane's required authoritative evidence completed with no finding. |
| `findings` | At least one actionable finding is present. |
| `pending` | A retryable process or provider state can still make progress under the recovery policy. |
| `blocked-input` | Required scope, PR, range, or locally complete object input is absent or contradictory. |
| `blocked-authorization` | Completion requires an ungranted mutation or external action. |
| `blocked-authentication` | The required processor cannot use its authorized authentication interface. |
| `blocked-safety` | Workspace, provenance, execution, or cleanup safety cannot be established. |
| `inconclusive` | A terminal or exhausted attempt cannot prove clean or findings. |

A blocked or inconclusive lane never becomes clean because another lane passed.

## Findings And Reruns

Classify each finding before choosing a transition:

- An applicable inline provider finding may clear on the same head only through
  its exact typed GraphQL thread resolution. An applicable top-level provider
  finding may clear through a later trustworthy same-head provider correction.
  Both require the evidence authority's complete stable reread; neither alone
  changes code, creates a head, or invalidates stable local reviews.
- If resolving a finding changes code, change the implementation checkout,
  never a review workspace; run proportionate tests; create a new committed
  head; discard old-head positive evidence; prepare fresh workspaces and rerun
  every required local lane independently; and obtain new current-head GitHub
  evidence when required.
- Never create an empty commit solely to convert a resolution-only same-head
  transition into a fresh review epoch.

Do not ask a reviewer to approve a patch pasted into its existing context. Do not reuse an old workspace or resume an old reviewer session.

## Failure And Cleanup

- A reviewer process or model transport failure is retryable when the same scope and workspace identity remain valid; revalidate immediately before retry.
- A profile mismatch, malformed result, output overflow, or unproved effective runtime is inconclusive.
- A missing range object is `blocked-input` / `range-incomplete` and routes to minimal parent-owned fetching.
- A workspace identity or independence failure is `blocked-safety`.
- Cleanup runs after every terminal result. Cleanup failure cannot change findings into clean; record the retained path and safety evidence.

Never silently weaken a requested shape. Report requested shape, effective shape, each lane's adapter/runtime and outcome, frozen range, current head, cleanup state, and remaining readiness gates.

## Separate Secret Admission

Secret-delta admission is independent of review. It may block PR/master admission, but it never supplies a reviewer result and never increments a named shape.
