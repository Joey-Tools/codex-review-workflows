---
name: agile-delivery-workflow
description: "Compatibility alias for explicitly requested MVP, early usable product, quick iteration, agile delivery, or scout work. Route these requests to `$change-delivery-workflow` with the `focused-checkpoint` profile; do not run an independent agile workflow."
---

# Agile Delivery Workflow Compatibility

This skill is retired as an independent workflow. Its only active behavior is to
load [$change-delivery-workflow](../change-delivery-workflow/SKILL.md) and select
the mapped delivery profile below. The active delivery skill is authoritative
if these files ever disagree.

## Compatibility Mapping

- `MVP`, `early usable product`, `quick iteration`, `agile delivery`, `scout`,
  `先可用`, `快速迭代`, or a similar first-slice request maps to
  `focused-checkpoint`.
- A later request to complete the full local gate maps to `local-gate`.
- A later request to continue toward a PR, CI/review waiting, or merge-ready maps
  to `pr-readiness-handoff`.

Immediately announce the mapping and continue under
`$change-delivery-workflow`. Preserve the original user scope and authorization;
the alias does not authorize push, PR creation, external review, release, or
merge.

## Guardrails

- Do not duplicate or reinterpret the profile workflow here.
- Do not invoke the old standalone sequence after loading the active skill.
- Do not force first-time journal adoption for a short focused checkpoint; apply
  the active skill's journal automation threshold.
