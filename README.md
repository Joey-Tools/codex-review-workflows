# Codex Review Workflows

Public review orchestration, synthetic fixture selection, and local delivery gate skills.

`review-orchestration-playbook` is the single entrypoint for named single, double, and triple review plus PR readiness. Both the named direct Claude Code lane and the low-level helper accept only publisher-verified strict stable Claude Code releases `>=2.1.211,<3.0.0`. Each selected release is bound to its exact signed per-version manifest, platform artifact size, and SHA-256; before any credential or review input is exposed, credential-free `--version` and `--help` probes must pass from the same private verified executable snapshot.

The canonical Claude lane captures bounded raw stdout outside the model-visible worktree and must pass it through [validate_claude_stream.py](skills/review-orchestration-playbook/scripts/validate_claude_stream.py) with the exact cwd, model, preflight-selected Claude Code version, parent-selected authentication source, and child return code. Only `classification: accepted` supplies findings; prose inspection, partial output, or an ad hoc parser does not satisfy named double/triple review, and acceptance does not prove the final merged sandbox.

## Named Review Shapes

- **Single:** exactly one clear/fresh-context Codex `reviewer` agent launched with zero inherited turns in a separate clean read-only Git worktree. The agent receives control metadata and refs, then loads applicable guidance and inspects the frozen `base_sha..head_sha` itself with bounded Git/tool calls. A prepared full diff is never injected.
- **Double:** single plus an actual Anthropic Claude Code process launched directly in another independent read-only Git worktree over the same frozen range. The supplied-diff `isolated_review` helper is diagnostic-only; GitHub Copilot requires separate explicit consent and never satisfies or increases the named double-review shape.
- **Triple:** double plus exact `@codex review` on exact host `github.com` and a complete terminal provider-authored GitHub Codex findings payload bound to that PR's current head, whole-PR range, and isolated request. Other hosts and operating identities in `{hoteng, hoteng_cisco}` are unsupported and reduce an otherwise complete request to effective double.

For the third lane, allow at most one acceptable exact request per unchanged head and never post a second one. Completion requires a complete exact-bot review body plus every fully paginated associated inline comment, or an unambiguous terminal exact-bot issue-comment body. Re-read complete authenticated request history immediately before posting and accepting; an older request that might overlap makes attribution `triple-inconclusive`. Timestamps prove ordering, not request/run lineage. A `chatgpt-codex-connector` check/run with non-null `started_at` proves service start only; it never proves terminal findings or no findings. Missing, stale, ambiguous, incomplete, overlapping-request, or check-only evidence after service start is `triple-inconclusive`.

For every selected PR, including one named explicitly, require exact authenticated lifecycle `state == "open"`, `merged == false`, and `merged_at == null`; missing or contradictory evidence is `blocked-input` (`pr-lifecycle-unverified`), closed-unmerged is `selected-pr-closed`, and merged is terminal `already-merged` / `selected-pr-merged`. Revalidate at selection, before posting, before accepting a result, and before readiness/merge; these point-in-time snapshots do not prove that no intermediate close-and-reopen occurred.

Independently read `baseRefName`, `baseRefOid`, and `headRefOid`, require locally complete endpoint commits, and require `git merge-base --all pr_base_oid pr_head_oid` to produce exactly one `pr_merge_base`. PR-specific readiness or triple coverage requires `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve it, do not silently rewrite it, and never describe its result as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR needs no PR probe. A post-request base-only retarget is `base-changed-same-head`: it invalidates the old whole-PR evidence and does not authorize a replacement same-head request or an empty or anchor commit.

For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.

A bare named-review request is report-only. It does not authorize a review anchor, branch or PR mutation, push, installation, active-version switch, or symlink repair. Use `blocked-authorization` when the intended scope includes dirty or untracked state that would require an unauthorized anchor commit. PR readiness adds CI, conversation-resolution, base/head, and merge-policy checks to the effective requested shape; it does not add retired extra Codex gates. The legacy low-level helper Codex path and separately requested Copilot diagnostic never count as a named lane.

## Claude Runtime Contract

The direct Claude process uses the selected installed native executable path after publisher verification and before/after identity plus digest revalidation. The preflight accepts only strict stable `>=2.1.211,<3.0.0`; prereleases, future major releases, scripts/wrappers, unsupported platforms, missing required options, ambiguous safe-mode claims, or any source/snapshot drift fail closed. Capability output proves only the advertised public surface, never the final merged sandbox or path-rule evaluation.

The accepted real-`HOME` design treats the ordinary user `HOME` as the trusted Claude CLI authentication/runtime control plane. An explicit API key has priority over an explicit OAuth token, which has priority over ordinary local login. Claude Code owns ordinary local-login discovery and refresh state and may update ordinary CLI-owned authentication and runtime state there, including credential refresh and possible cache or tool-result artifacts; those are control-plane side effects, not model-authorized review mutations. `--no-session-persistence` does not make real `HOME` immutable.

The native sandbox is selected-deny, not a global host-read whitelist. Launch must request global `denyWrite`, critical-sensitive-root `denyRead`, and removal of authentication variables from sandboxed Bash. `allowRead` records the intended worktree/private-Git scope but does not prove all other host paths are unreadable, so the control prompt forbids every direct outside-workspace read. Record these settings as requested configuration rather than independent proof of merged policy.

The stream validator requires `--claude-code-version <preflight-version>` and `--authentication-source api-key|oauth-token|local-login`. It requires init `claude_code_version` to match exactly and maps the parent authentication winner to init `apiKeySource`: `api-key -> ANTHROPIC_API_KEY`, while `oauth-token` and `local-login` both map to `none`. The legacy base init profile covers earlier accepted 2.x releases; current Claude Code 2.1.216 uses the closed extended profile with exact `output_style`, ordered `agents`, ordered `capabilities`, analytics/feedback booleans, nonempty `uuid`, and `fast_mode_state`. Its intermediate-event contract is version-profiled, closed, and session-bound over reviewed `system/thinking_tokens`, assistant-message, user-tool-result, and `rate_limit_event` shapes. Extended-2x success requires `fast_mode_state: off`, `terminal_reason: completed`, and nonnegative integer `time_to_request_ms`, `ttft_ms`, and `ttft_stream_ms`; legacy success forbids those five fields, and extended failure permits them only with strict known values and types. Unknown intermediate or terminal fields and added, missing, malformed, reordered, or otherwise drifting profile evidence are inconclusive.

## Low-Level `isolated_review` Helper Only

The low-level helper has `review_contract: supplied-diff-private-git` and `named_lane_eligible: false`. It materializes a supplied diff and the scanned endpoint tree/blob closures in a helper-owned detached worktree backed by a private minimal Git database. Its restricted private Git view is different from the complete clean Git worktree used by named lanes and never satisfies a named Codex or Claude lane.

Clean committed-head content is the default. Explicit `--include-source-wip` consent captures a digest-bound helper-private composite of source `HEAD` plus staged, unstaged, and nonignored untracked content. The helper binds the WIP digest, original source `HEAD`, private snapshot tree, and source-to-WIP deletion or reversion evidence. WIP output is review-only diagnostic evidence and cannot satisfy PR-readiness or merge-ready exact-commit gates.

Low-level Claude uses the same publisher-verified stable range, same-snapshot credential-free `--version` and `--help` capability evidence, selected-deny boundary, and strict structured-output checks described above. Its real-`HOME` authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. It opaque-forwards only the winning explicit value and otherwise delegates authentication to the ordinary publisher-verified CLI. Its separately authorized Copilot compatibility fallback remains helper-only and never satisfies named double review.

Canonical PR/master secret admission is the separate `isolated_review secret-admission` command. It scans immutable Git trees without starting a reviewer. Optional helper-state `stateful final` / `stateful admission` evidence remains diagnostic and is not a hidden PR-readiness reviewer gate.

`synthetic-token-fixtures` selects exact authoring values from the review helper's finite catalog. The helper catalog remains the enforcement authority; skill templates contain placeholders only.

## Test

The helper requires Python 3.10 or later; CI pins the minimum supported runtime.

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -m unittest discover -s skills/review-orchestration-playbook/tests
```
