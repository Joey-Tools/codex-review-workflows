---
id: 20261102-local-codex-context
title: Separate Local Review Context From Personal Account Isolation
status: completed
created: 2026-11-02
updated: 2026-11-02
branch: codex/daily-skill-friction-2026-11-02-codex-review-workflows-local-review-default-home
pr:
supersedes: []
superseded_by:
---

# Separate Local Review Context From Personal Account Isolation

## Summary

- Prefer a clean-context Codex subagent for local review, with a fresh non-resumed Codex CLI session as fallback.
- Use the normal trusted personal Codex environment, including its default `CODEX_HOME`; remove temporary auth-only home and credential-copy requirements.
- Preserve the frozen committed range, independent clean repository workspace, read-only review, and the boundary between candidate review policy and trusted review control.

## Evidence

- The previous local lane explicitly prohibited the ordinary user `CODEX_HOME` and required separate temporary auth-only homes for login checks and review execution.
- The previous subagent contract required complete host instruction-surface receipts even for a zero-inherited-context launch, making the simpler adapter unavailable on hosts without that telemetry.
- The focused local Codex lane contract suite passes all 13 tests.
- Skill metadata validation, reviewer TOML parsing, and `git diff --check` pass.

## Next Steps

- No remaining source changes. Host-local installation and rollback evidence are retained outside Git; publication follows only when requested.
