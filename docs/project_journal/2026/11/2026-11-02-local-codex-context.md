---
id: 20261102-local-codex-context
title: Separate Local Review Context From Personal Account Isolation
status: completed
created: 2026-11-02
updated: 2026-11-02
branch: codex/daily-skill-friction-2026-11-02-codex-review-workflows-local-review-default-home
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/145
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
- The repository-wide and local Codex lane contract suites run 70 tests with 2 skips and no failures, covering generic-subagent launch/evidence, normal-home fallback, prompt transport, and final launch-boundary classification.
- Skill metadata validation, reviewer TOML parsing, and `git diff --check` pass.
- Fresh conversation context is distinct from complete host instruction-stack isolation. Known forced candidate controls require the normal-home, neutral-root CLI fallback.
- Hashed-file prompt transport protects stable file identity and exact bytes without imposing account isolation; neutral-root launch receipts use a stable identity across prelaunch and postlaunch evidence.
- Final lane records expose the actual subagent context/execution/evidence and neutral-root match/pre/post results. The CLI requests JSONL events explicitly with `codex exec --json -`.
- CLI accepted-pinned evidence binds the actual executable, version, and complete literal argv. Per-process hook and notification overrides preserve report-only execution without changing the normal account or global configuration.

## Next Steps

- No remaining source changes. Host-local installation and PR/release evidence are retained outside Git.
