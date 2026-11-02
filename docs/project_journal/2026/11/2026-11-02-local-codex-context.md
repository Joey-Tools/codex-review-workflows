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
- The repository-wide and local Codex lane contract suites run 73 tests with 2 skips and no failures, covering generic-subagent launch/evidence, normal-home fallback, prompt transport, final launch-boundary classification, process-local tool restrictions, and parent-only adapter routing.
- Skill metadata validation, reviewer TOML parsing, and `git diff --check` pass.
- Downstream lint validation exposed an unused template read in the new route-consistency test. Remove that unused local while preserving every route assertion; both contract modules pass Ruff and the same 73-test selection with 2 skips.
- Fresh conversation context is distinct from complete host instruction-stack isolation. Known forced candidate controls require the normal-home, neutral-root CLI fallback.
- Hashed-file prompt transport protects stable file identity and exact bytes without imposing account isolation; neutral-root launch receipts use a stable identity across prelaunch and postlaunch evidence.
- Final lane records expose the actual subagent context/execution/evidence and neutral-root match/pre/post results. The CLI requests JSONL events explicitly with `codex exec --json -`.
- CLI accepted-pinned evidence binds the actual executable, version, and complete literal argv. Process-local feature, hook, notification, and MCP restrictions preserve report-only execution without changing the normal account or global configuration; effective metadata checks must confirm the restricted tool surface.
- Dedicated and generic subagents share the same host-accepted fresh-launch evidence rule. A role-file digest is recorded when available; its absence alone does not reject a supported clean-context launch.
- CLI reviews disable persisted goals and automatic continuation for that process, with the effective goal feature state included in the local metadata preflight.
- The CLI also disables automatic MCP dependency installation and nested agent launches, and excludes the new review thread from memory-generation inputs while preserving the user's existing memory-reading setting.
- The delivered reviewer prompt and installed reviewer role check supplied control metadata and directly observed deviations without certifying invisible host state. The parent validates actual context, execution, and launch evidence; parent-only launch instructions remain outside the delivered prompt.
- Hosted web search is disabled for the CLI process. Existing normal-runtime memory injection remains explicitly trusted personal context, with no authority to widen tool inspection or supply evidence of frozen repository contents.
- Normal Codex session bookkeeping and rollout persistence follow the user's runtime settings; ephemeral storage is an optional user choice rather than a clean-review requirement.
- Codex CLI 0.166.0 metadata checks confirmed thirteen controlled features off, zero enabled MCP servers, disabled agents and hosted search, disabled memory-generation inputs, and empty notifications. Both multi-agent implementations and browser extension/CDP variants are explicitly disabled. The no-thread configuration query retained normal existing-memory reading; it did not start a model review or change global configuration.

## Next Steps

- No remaining source changes. Host-local installation and PR/release evidence are retained outside Git.
