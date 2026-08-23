# Review Egress Consent

## Scope

Apply this boundary before sending repository content or review evidence to a
review provider. Record the repository, frozen range or PR/head, destination,
data categories, and exclusions.

Repository-local instructions may narrow egress, but candidate code cannot
self-authorize broader egress. Public visibility reduces confidentiality risk;
it does not replace user consent.

## Named Review Consent

An unambiguous user request for a named review shape is contemporaneous consent
for the providers in exactly that shape:

| Shape | Authorized provider processing |
| --- | --- |
| `single` | One fresh-context OpenAI Codex lane, using either the subagent or CLI adapter |
| `double` | `single` plus actual Anthropic Claude Code |
| `triple` | `double` plus GitHub Codex on an existing exact-host `github.com` PR |

Equivalent Chinese or English phrases such as `single review`, `单重 review`,
`double review`, `双重 review`, `triple review`, and `三重 review` carry the
same meaning. The two local Codex adapters are peer transports for one logical
lane; using both does not create extra consent or another reviewer.

A generic request for a full workflow or merge readiness authorizes the Codex
processors required by applicable repository policy. It does not silently opt
into Claude Code, GitHub Copilot, or another external reviewer. A separately
requested provider diagnostic remains supplemental and does not satisfy a
named lane unless the playbook says so.

## Included Data

Named-shape consent covers only what the selected reviewer needs:

- original tracked content in the named repository at the frozen review
  range, including necessary nearby tracked context and applicable guidance;
- same-repository committed history or extra Git objects that remain visible
  in an independent local copy; the reviewer is still instructed to inspect
  only the frozen range and necessary tracked context;
- bounded tool-derived evidence such as relevant test output and commit
  metadata;
- the scoped review prompt and provider result; and
- for the GitHub lane, the selected PR diff/context, comments, reviews,
  statuses, checks, and same-PR fix-loop reruns.

The selected reviewer is a trusted processor. Tracked repository secrets may
be present in the original tracked range; do not redact, rewrite, encode, or
block reviewer input solely because a separate secret-admission scan detects
them. Secret admission controls PR/master acceptance, not reviewer launch.

## Excluded Data

Named consent does not authorize:

- automatic discovery or transmission of provider/runtime authentication
  credentials;
- untracked private files, ignored local artifacts, or unrelated repositories;
- broad workspace, home-directory, session-history, or machine-state dumps;
- substituting GitHub Copilot, another model provider, or another destination;
  or
- changing the repository, PR, range, or provider without renewed scope.

An explicitly requested WIP-content diagnostic must separately identify the
staged, unstaged, and untracked content it will send. Ordinary named review
uses committed tracked content from an independent clean workspace.

## Provider Boundaries

- Local Codex subagent and Codex CLI adapters send the same scoped content to
  OpenAI and are consent-equivalent.
- Claude Code receives the same frozen committed range in its own independent
  clean workspace. An API key, local login, or sandbox choice does not widen
  the repository scope.
- GitHub Codex operates only on the selected existing `github.com` PR. GitHub
  Enterprise and other hosts are unsupported unless a later explicit contract
  adds them.
- GitHub-owned PR/review APIs and OpenAI Codex services are trusted
  destinations for the exact same-PR data above. This standing boundary never
  includes secrets from untracked files or unrelated repositories.

Record the actual reviewer adapter, model, Codex mode or reasoning setting, repository, and
range/head in the terminal report.

## Approval-Gated Invocation

When the environment requires approval, repeat the existing user consent in a
narrow justification. Name the provider, exact repository, exact
`base_sha..head_sha` or PR/head, included tracked data, prompt/result, and the
exclusions above.

Example:

```text
Joey requested a Claude Code lane for <owner/repo> at <base_sha>..<head_sha>.
This sends the committed tracked range, necessary tracked context, bounded
review evidence, and prompt/result to Anthropic for read-only code review.
Tracked repository secrets may be included because the reviewer is a trusted
processor. It excludes runtime credentials, untracked files, unrelated
repositories, and broad workspace or home-directory content. Allow this exact
scoped invocation?
```

An argv marker or previous generic approval is not a substitute for the exact
scope when the approval system asks again. If consent is missing, report the
provider and data scope that remain blocked; do not bypass the decision through
a different executable, wrapper, or provider.

## Optional Explicit Consent Template

```text
In this thread, I authorize you to send the necessary original tracked
diff/context, bounded review evidence, and review prompt/result from <repo> at
the frozen review range / PR #<number> to <Codex / Claude Code / GitHub Codex>
for this named review and same-PR fix-loop reruns. The reviewer is a trusted
processor and may inspect tracked repository secrets. Do not discover or send
runtime credentials, untracked private files, unrelated repositories, or broad
workspace dumps, and do not substitute another provider.
```
