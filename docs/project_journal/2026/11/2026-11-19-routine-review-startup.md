---
id: 20261119-routine-review-startup
title: Reusable routine review preparation and startup
status: completed
created: 2026-11-19
updated: 2026-11-19
branch: codex/routine-review-launch
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/156
supersedes: []
superseded_by:
---

# Reusable routine review preparation and startup

## Summary

Routine local review has one stdlib prepare/config/run entrypoint. Independent
local Git copies retain available committed history while materializing only
the parent's selected regular tracked context. The audited helper is unchanged.

## Current State

- Effective configuration is read without creating a model thread. The primary
  is GPT-6.1 Sol/High/Daybreak Off; the explicitly authorized GPT-6 Sol fallback
  uses High/Daybreak On. Inherited MCP and external write tools are disabled only
  for that process, preserving the user's global configuration and auth.
- A successful config record can be reused across heads in one task. Config,
  execution output and terminal records have separate paths.
- One fresh read-only review retains its complete stream without a model-output
  quota or elapsed review timeout. Selected content/mode, head/index and Git
  configuration are revalidated before and after execution.
- Supporting unchanged-unit evidence stays at its old SHA; affected-unit and
  current-head integration review remain required for new-head acceptance.
- Original human authorization stays with the review owner; delegated source
  handoff does not establish consent by assistant assertion.

## Validation

- Focused tests cover independent sparse preparation, retained Git context,
  live-source independence, content/mode revalidation and process-local profiles.
- Native review fixes cover relative CLI paths, frozen heads retained only by
  PR refs, raw-blob validation under CRLF/UTF-16 attributes, and relative output
  directories. Raw content/index checks and untracked-file detection avoid
  working-tree attribute conversion. These use the
  existing test module and do not add CI jobs or model probes.
- A real no-model configuration invocation confirms the installed Codex CLI's
  effective primary profile and MCP shutdown.
- Existing policy contracts, skill metadata, journal, whitespace and consumer
  export compatibility checks remain part of delivery. No trajectory evaluation
  or new model probe is introduced.

## Next Steps

- No further implementation is required for this slice.
