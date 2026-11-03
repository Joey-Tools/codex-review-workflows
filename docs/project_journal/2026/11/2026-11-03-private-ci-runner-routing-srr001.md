---
id: 20261103-srr001
title: Private CI Self-Hosted Runner Routing
status: completed
created: 2026-11-03
updated: 2026-11-03
branch: wip/self-hosted-routing
pr:
supersedes: []
superseded_by:
---

# Private CI Self-Hosted Runner Routing

## Summary

- Add opt-in JSON label routing for eligible private CI Linux and macOS jobs while preserving hosted defaults and existing test coverage.

## Current State

- The canonical private workflow fixture and contract tests describe the routing variables and retain the original job and matrix structure.
- Independent supervisor checks, read-only macOS installation, and Linux isolation retain hosted runners for hosted evidence or disposal-dependent side effects.
- The shared Python setup fixture preserves `setup-python` on hosted runners and downloads uv 0.11.18 into a fresh mode-700 `RUNNER_TEMP` root on self-hosted runners. It checks the fixed asset size and SHA256 before extracting the exact uv member; the uv executable, managed interpreter, uv package cache, and seeded venv remain per-job. Every uv bootstrap call disables configuration discovery, and venv creation disables project discovery. The empty-environment smoke test runs before the venv is added to `PATH`; host `curl`, `tar`, and checksum tools remain trusted runner prerequisites.
- `docs/private-ci-runners.md` records the repository-variable contract, provisioned runner pools, and platform-specific checks.
- Four Linux and two macOS runners are registered and have accepted jobs. The routing implementation slice is complete for the post-merge target state; full CI validation of its portable Python setup remains a separate gate.

## Next Steps

- Verify full CI execution with the portable Python setup.
- Keep CI timing, optimization, and removal of the three hosted dependencies in a separate follow-up PR.

## Evidence

- Canonical fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Canonical private Python setup fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/setup-private-python/action.yml`.
- Canonical contract tests: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Runner configuration and validation limits: `docs/private-ci-runners.md`.
- Official uv 0.11.18 Linux x64 archive: `https://github.com/astral-sh/uv/releases/download/0.11.18/uv-x86_64-unknown-linux-gnu.tar.gz`, 24,198,195 bytes, SHA256 `588f3e360f69ce02b6982aa99f2240e803933a6b7e176ac01617830adf955add`; official release API digest and sidecar agree, and local `shasum -a 256` recheck matched.
- Official uv 0.11.18 macOS ARM64 archive: `https://github.com/astral-sh/uv/releases/download/0.11.18/uv-aarch64-apple-darwin.tar.gz`, 20,688,438 bytes, SHA256 `1a7adf8dadae3b55853115d13a8bf564d219597ad13824b93b213706933863e5`; official release API digest and sidecar agree, and local `shasum -a 256` recheck matched.
