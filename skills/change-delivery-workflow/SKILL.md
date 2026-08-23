---
name: change-delivery-workflow
description: "Run a local pre-commit delivery gate for non-trivial repo changes: implement, build, test, update docs, hand a frozen committed range to local review, then land the commit. Use when wrapping up local work, probing local gate readiness, or starting a full workflow before PR readiness."
---

# Change Delivery Workflow

## Overview

This skill owns the local `plan -> code -> test -> docs -> review -> commit`
gate. It does not define reviewer adapters, workspace isolation, GitHub evidence,
CI recovery, or PR readiness. Hand those tasks to the authoritative active
`$review-orchestration-playbook` with a frozen committed range.

A request for a full workflow or merge-ready result continues into that
playbook after the local gate. A request for only the local/pre-commit gate
stops after the checked commit and does not push.

## Workflow

1. Establish the local scope.
- Identify the intended repository, target/base, validation surface, documentation, and whether PR readiness follows.
- Limit fixes to the requested work and direct gate blockers. Stop with a clear handoff when credentials, login, device authorization, or another missing authority is required.
- For reviewable work, prefer a `wip/<topic>` branch and review checkpoint commits so a fixed `base_sha..head_sha` can represent the complete candidate without dirty or untracked state.

2. Implement the change.
- Read the relevant implementation and repository guidance before editing.
- Complete the requested behavior and correct mistakes introduced by the change before moving to validation.
- If the design premise changes materially, update the plan and documentation before continuing.

3. Build and test.
- Run the widest relevant local build, unit, integration, and end-to-end validation that the repository supports and the change warrants.
- Use one runtime/toolchain version unless the user, repo policy, or the compatibility work itself requires a finite multi-version set.
- Select a single version from the first applicable authority: explicit user instruction, repo-local instruction, repo version-selection configuration, the normal repo runner, then the highest compatible installed version. A selected source that is conflicting, ambiguous, or incompatible is a blocker; do not silently fall through to a lower-priority source.
- For a required multi-version set, use the first applicable finite authority: explicit instruction, repo policy, declared supported-version set, then CI matrix. Isolate version-sensitive checkout artifacts, caches, ports, and mutable machine state, or run serially when isolation is not proved.
- Fix failures from the earliest affected step and rerun the affected validation. Report every gate that could not run and its residual risk.

4. Update durable documentation.
- Follow the repository's project-journal, state, TODO, changelog, and user-documentation conventions.
- In a squash-merge repository, describe the stable post-merge outcome in tracked journal entries; keep transient review/merge status in the PR.

5. Freeze and hand off review.
- Ensure the candidate is represented by committed Git objects and record an immutable `base_sha..head_sha`; do not hand a live working tree or prebuilt diff to formal review.
- Load the authoritative active `$review-orchestration-playbook` and give it the repository plus frozen endpoints. That playbook alone selects the fresh local Codex adapter, prepares and validates the independent clean workspace, constructs the review prompt, and interprets the result.
- If review finds an issue, fix it in a new checkpoint commit, rerun affected tests and docs validation, freeze the new head, and repeat the required local review.

6. Land the local result.
- Only land after implementation, validation, documentation, and the requested local review are clean.
- Keep the landing commit focused and follow repository signing and attribution policy. Review checkpoint commits may be squashed into the final landing shape.
- Do not push a local-gate-only task without separate authorization.
- When PR readiness was requested and its target authorization preflight passes, continue with `$review-orchestration-playbook` for push/PR operations, CI and comment repair, the requested review shape, and the terminal readiness or merge outcome.

## Long Gates

When a test or other local gate exceeds a stable foreground turn, a repository-approved background runner such as `cbth` may keep it pollable. Persist the source thread and job identifiers, preserve asynchronous delivery, and poll rather than consuming the final delivery from a synchronous waiter. Read [cbth-agent-delivery.md](../review-orchestration-playbook/references/cbth-agent-delivery.md) when that runner is used.

## Guardrails

- This is a local delivery gate, not an independent PR or merge policy.
- Phrases such as `merge-ready` or `before merge` require the playbook handoff; they do not by themselves authorize mutation of an otherwise unauthorized PR target or a merge.
- Do not restate or reinterpret named single/double/triple composition, model selection, workspace isolation, Claude runtime, GitHub provider evidence, or retry semantics here.
- Review progress and keepalive output are not a final review artifact.
- If a required gate stays inconclusive after its owning workflow's recovery policy, stop at an evidence-backed decision point.
