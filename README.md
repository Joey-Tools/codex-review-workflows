# Codex Review Workflows

Public review orchestration, synthetic fixture selection, and local delivery gate skills.

`review-orchestration-playbook` is the single entrypoint for named single, double, and triple review plus PR readiness. The canonical direct Claude Code lane is governed by [Canonical Claude Code Lane](skills/review-orchestration-playbook/references/canonical-claude-lane.md); the diagnostic `isolated_review` helper has a separate exact-version runtime contract documented in [Claude Runtime Trust And Platform Capabilities](skills/review-orchestration-playbook/references/claude-runtime-trust.md).

## Named Review Shapes

- **Single:** exactly one clear/fresh-context Codex `reviewer` agent launched with `fork_turns="none"` or the platform-equivalent zero inherited turns, in a separate clean Git worktree. The workspace is read-only. The agent loads applicable skills, scoped `AGENTS.md` files, and project guidance, then uses bounded Git/tool calls to obtain and review the frozen `base_sha..head_sha` itself. Its prompt carries control metadata but never embeds or attaches a prebuilt full diff.
- **Double:** single plus an actual Anthropic Claude Code process launched directly in another independent read-only worktree over the same frozen range. The supplied-diff `isolated_review` helper is diagnostic-only; GitHub Copilot requires a separate explicit request and never satisfies or increases the named double-review shape.
- **Triple:** double plus exact `@codex review` on a supported GitHub Cloud PR and a trustworthy terminal GitHub Codex result bound to that PR's current head. No PR, an unsupported GitHub Codex integration, host, or identity, host `sqbu-github.cisco.com`, and operating identity in `{hoteng, hoteng_cisco}` all make that lane unavailable; report `effective double`, not triple. The request comment is not completion. An authenticated provider rejection may prove that no run started and the lane is unavailable; missing response or generic failure is inconclusive. After acknowledgement/run/review activity proves start, malformed, stale, ambiguous, or incomplete evidence is `triple-inconclusive`, not double fallback.

PR readiness layers required CI, review-conversation resolution, and branch/base checks onto the requested shape. It does not add retired extra Codex gates. The `isolated_review` helper remains low-level compatibility and diagnostic infrastructure; no helper result counts toward single, double, or triple review.

A bare named-review request is report-only. It does not authorize branch creation, push, PR creation, or PR branch/metadata changes. Bare triple may post only the scoped `@codex review` request on an already-existing supported PR; without one, run the two local lanes and report effective double. PR mutation requires a separate explicit PR or delivery-workflow request.

For the accepted real-`HOME` native-sandbox design, “read-only workspace” describes required model behavior and requested write denial, not a global host-read whitelist. Launch must request global `denyWrite` and critical-sensitive-root `denyRead`; native-sandbox `allowRead` entries do not make every other host path unreadable. The prompt/model contract therefore forbids outside-workspace reads. Claude Code 2.1.212 init/capability output does not prove the final merged sandbox, managed permission arrays, or path-rule evaluation, so reports record those controls as requested configuration.

## Low-Level `isolated_review` Helper Only

The helper is diagnostic-only and machine-labels new state `review_contract: supplied-diff-private-git` plus `named_lane_eligible: false`. It runs a supplied-diff review in a helper-owned detached worktree backed by a private minimal Git database; it never satisfies a named Codex or Claude lane.

Clean mode is the default and rejects a dirty source checkout. Explicit `--include-source-wip` overlays staged changes, unstaged changes, and non-ignored untracked files into a digest-bound review-only snapshot. The private Git database contains the scanned base/head endpoint commits and their tree/blob closures; WIP mode also contains the generated snapshot tree/blob closure. Intermediate history and history-only objects remain unavailable. The helper never registers this worktree in the source repository's common Git directory or writes review objects into the source object database.

The helper keeps its worktree, private Git database, control artifacts, logs, and state outside the source checkout under a verified system `/tmp` namespace. WIP evidence is reproducible by its recorded digest but is not exact-commit evidence and cannot satisfy PR-readiness or merge-ready gates.

The low-level Claude runtime uses the current account's real `HOME` and pins the publisher-verified CLI to exact version `2.1.212`. Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. The helper opaque-forwards only the winning explicit value; it never parses, logs, stages, brokers, persists, or writes back credentials. Keychain access, credential-file access, login refresh, and persistence remain ordinary Claude Code control-plane behavior.

The model runs in `dontAsk` mode with `Read`, `Grep`, `Glob`, and non-prompting read-only `Bash`. Editing, web, and task tools are disabled. Native sandbox settings request global write denial, critical-sensitive-root read denial, no unsandboxed-command escape, and removal of authentication variables from sandboxed commands. Post-attempt validation rejects observable worktree, private-Git, diff, or prompt mutation, but cannot prove that no transient write or outside-workspace side effect occurred.

## Test

The helper requires Python 3.10 or later; CI pins the minimum supported runtime.

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -m unittest discover -s skills/review-orchestration-playbook/tests
```
