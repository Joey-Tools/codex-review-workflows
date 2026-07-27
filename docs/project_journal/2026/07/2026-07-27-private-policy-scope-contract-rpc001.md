---
id: 20260727-rpc001
title: Private Policy Scope Contract
status: completed
created: 2026-07-27
updated: 2026-07-27
branch: wip/private-policy-scope-contract
pr:
supersedes: []
superseded_by:
---

# Private Policy Scope Contract

## Summary

- Resolve trusted-control manifest paths through the selected distribution policy scope.
- Keep canonical paths rooted at the repository and private-overlay paths rooted at `personal_codex/`.

## Current State

- The self-policy migration contract reads every manifest-bound control file from `policy_scope_root`.
- The private overlay can validate `personal_codex/agents/reviewer.toml` without requiring an unrelated duplicate at repository root.

## Next Steps

- Sync the corrected contract into the private overlay and publish a trusted release.

## Evidence

- The private-overlay full canonical suite exposed the incorrect repository-root read after the review-runtime bytecode gate was fixed.
- The same test already exercises canonical and private layouts in their respective repository CI profiles.
- Python 3.13 focused policy-scope regressions passed 2/2.
- The complete Python 3.13 canonical review suite passed 2,817/2,817 with six expected skips in 1,230.818 seconds.
- The macOS keychain-broker regression passed in a narrow unsandboxed rerun after the first full private-layout run proved the parent sandbox could not invoke `sandbox-exec`.
- Ruff lint and format checks, source-only compilation, the official skill validator, project-journal validation, `git diff --check`, and the bytecode inventory all passed.
- No local Python 3.10 run was performed.
