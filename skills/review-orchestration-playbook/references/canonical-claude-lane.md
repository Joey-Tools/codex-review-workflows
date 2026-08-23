# Canonical Claude Code Lane

A named double or triple adds one actual Claude Code process. It is independent of the Codex lane and runs in a different validated workspace over the same frozen range.

## Required Inputs

The parent supplies:

- frozen `base_sha` and `head_sha`;
- a lane-unique workspace prepared and validated under [review-workspace.md](review-workspace.md);
- independently trusted control-bundle identity;
- accepted Claude runtime preflight evidence;
- the Claude prompt from [review-prompt-templates.md](review-prompt-templates.md);
- parent-private output and receipt destinations outside the model-visible workspace.

Do not give Claude the Codex result, parent findings, a prebuilt diff, untracked content, or unrelated repository context.

## Trusted Control Plane

Launch review-control code only from the recorded trusted bundle through a parent-validated absolute Python interpreter:

```text
<trusted-python> -I -B -S \
  <trusted-bundle>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  <subcommand> ...
```

Do not execute the guard through its shebang, resolve Python from ambient `PATH`, import candidate-head modules, or load bytecode/native-extension substitutes.

For a self-policy migration, use the previously trusted installed bundle. Candidate Markdown remains review subject only. Follow [review-lane-contracts.md](review-lane-contracts.md#self-policy-migration-trust-boundary).

## Runtime Selection

Before exposing a prompt, credential, repository, range, or workspace to Claude, run the trusted guard's credential-free Claude preflight.

The canonical compatible range and feature gates live in `scripts/review_runtime/claude_version_policy.py`. Do not duplicate a patch pin here. A candidate must pass:

- compatible stable version selection;
- publisher/artifact provenance and executable identity checks;
- bounded credential-free `--version` and mandatory `--help` capability probes;
- compatibility-profile and stream-schema binding.

Only an accepted preflight may launch. Exact absence may advance to the next configured candidate; I/O, identity, signature, probe, or schema uncertainty fails closed. Do not install, downgrade, repair, or switch a host Claude installation without separate authorization.

Read [claude-runtime-trust.md](claude-runtime-trust.md) only when changing or diagnosing these provenance, capability, process, or stream-validation primitives.

## Authentication

The named direct lane uses ordinary Claude Code local login in trusted real `HOME`.

- Derive account identity and home from the trusted host account record, not ambient caller variables.
- Do not expose an API-key or OAuth-token launch interface for this lane.
- If ordinary local login is unavailable or refresh is forbidden, report `blocked-authentication`.
- Do not claim helper-private credential carrier, broker, lock, or guarded-writeback guarantees for this direct lane.
- Session-suppression flags do not make real `HOME` immutable; credential refresh and CLI control-plane artifacts may still occur.

An explicit helper API key or OAuth token belongs only to a separately chosen low-level helper path and does not satisfy named double/triple.

## Workspace And Launch

Prepare the Claude workspace independently from the Codex workspace. Validate it immediately before launch with the same frozen endpoints.

Launch only through the trusted guard's direct process supervisor. It must:

- bind the accepted preflight to the exact executable bytes it launches;
- use direct argv with no shell;
- set the validated workspace as the exact cwd;
- start a fresh, non-resumed session;
- supply the prompt on stdin;
- expose only bounded read/search/sandboxed-shell capabilities;
- disable edits, writes, hooks, bundled skills, MCP, browser, web, task, and other external actions;
- rebuild the environment from a narrow allowlist;
- disable Git lazy fetching and credential prompts;
- cap time and both output streams;
- forward termination, drain output, and reap the supervised process before publication;
- write raw stdout and the process receipt outside the workspace.

The process supervisor proves only the launch and process evidence it records. It does not prove compatible-version provenance by itself and is not a whole-process-tree sandbox.

## Native Sandbox Boundary

Request global `denyWrite` and `denyRead` for critical sensitive roots. Keep no write exception for the review workspace or session-control path.

Native `allowRead` is not a global host-read whitelist. The prompt/model scope forbids reads outside the validated workspace, while requested native controls enforce only the roots and operations the runtime actually supports. Record those settings as requested configuration; capability or init output does not attest the final merged sandbox or managed permission arrays.

If structured tool evidence names an external path or a symlink escape, block the lane. If Claude reports that large command output spilled to an external CLI-managed file, it must not follow that path; it should rerun a narrower bounded command within the workspace.

## Stream Validation

After successful process cleanup, validate the complete raw stdout through the trusted bundle's `validate-claude-stream` guard profile.

The validator binds:

- exact preflight-selected version and compatibility profile;
- exact validated cwd;
- requested model;
- local-login authentication source;
- process return code and launch binding;
- one leading init event, admitted intermediate events, and one terminal result;
- tool/path scope and the findings-only result contract.

Only `classification: accepted` supplies a lane result. Prose inspection, partial output, an ad hoc parser, or direct compatibility-wrapper execution never substitutes for formal validation.

Validator acceptance attests the closed observable stream contract. It still does not prove the final merged sandbox, managed permissions, host-wide read exclusion, or behavior of descendants outside the supervised process boundary.

## Result And Cleanup

Classify an accepted terminal `No findings.` as clean. Accepted actionable findings block the requested shape until fixed and rerun on a new head.

Timeout, output overflow, malformed/missing/duplicate events, version or launch mismatch, external-path evidence, process cleanup uncertainty, or validator rejection is inconclusive unless a narrower blocked status is proven.

Always run identity-bound workspace cleanup after the terminal result unless the user explicitly requests retention. Keep raw stream evidence only in its parent-private bounded destination according to the task's retention needs.
