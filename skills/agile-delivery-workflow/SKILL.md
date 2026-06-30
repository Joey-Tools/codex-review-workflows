---
name: agile-delivery-workflow
description: "Deliver an explicitly requested MVP or early usable product slice before the full delivery gate. Use when the user asks for MVP, early usable product, quick iteration, agile delivery, scout work, or similar first-slice delivery."
---

# Agile Delivery Workflow

## Overview

Use this skill only when the user explicitly asks to prioritize an early usable
slice over full delivery, such as `MVP`, `early usable product`, `quick
iteration`, `agile delivery`, or `scout`.

The goal is to produce the smallest useful local commit quickly, then stop at a
clear checkpoint. Do not silently continue into broad review, PR readiness, CI
waiting, release automation, or merge-readiness unless the user asks to continue.

## Workflow

1. Define the first slice.
- Read enough repo context to avoid a brittle guess.
- State the core user-visible behavior, command, artifact, or diagnostic that
  makes the slice usable.
- Cut scope aggressively: defer polish, broad docs, refactors, additional
  platforms, automation hardening, release wiring, and full review gates unless
  they are required for the slice to work.
- If a required dependency blocks the slice, stop early with the blocker evidence
  and the smallest next slice that can proceed.

2. Implement only the first slice.
- Reuse the existing repo patterns and helper APIs.
- Keep the diff focused and reversible.
- Fix low-level mistakes introduced during the slice, but do not expand into
  adjacent cleanup.

3. Run focused checks.
- Run the narrowest checks that prove the slice builds, runs, or can be inspected.
- Prefer focused tests, smoke commands, static checks, or one representative
  workflow over full test suites when full gates would delay the checkpoint.
- Report any skipped broader validation explicitly.

4. Create the MVP checkpoint.
- Use the repository's normal local commit policy for the focused slice.
- The checkpoint is not merge-ready by default.
- Do not push, open a PR, wait for CI, run external review, or merge unless the
  user explicitly asks for that next phase.

5. Report the checkpoint.
- Include the local commit SHA.
- Explain what is usable now and how to run or inspect it.
- List the focused checks actually run.
- List known gaps and the recommended next iteration.

## Handoff

- Reuse the local discipline from
  [$change-delivery-workflow](../change-delivery-workflow/SKILL.md): repo
  conventions, focused validation, commit hygiene, and truthful reporting.
- Do not invoke the full local delivery gate by default. Use
  `$change-delivery-workflow` as a full workflow only when the user asks to
  continue past the MVP checkpoint or explicitly wants the complete local gate.
- Use [$review-orchestration-playbook](../review-orchestration-playbook/SKILL.md)
  for PR readiness after the MVP commit only when the user asks to continue
  toward a PR, full gates, CI/review waiting, or merge-ready status.

## Guardrails

- This skill is opt-in. Do not treat ordinary non-trivial work as agile delivery
  unless the user explicitly requested an MVP or early usable slice.
- A checkpoint commit is a product feedback point, not a quality waiver.
- Never claim full validation when only focused checks ran.
