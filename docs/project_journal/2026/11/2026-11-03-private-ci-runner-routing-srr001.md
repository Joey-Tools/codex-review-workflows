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
- The shared Python setup fixture preserves `setup-python` on hosted runners and downloads uv 0.13.7 into a fresh mode-700 `RUNNER_TEMP` root on self-hosted runners. It checks the fixed asset size and SHA256 before extracting the exact uv member; the uv executable, managed interpreter, uv package cache, and seeded venv remain per-job. Every uv bootstrap call disables configuration discovery, and venv creation disables project discovery. Before exposing the venv, it installs hash-pinned certifi 2026.10.23, validates the bundle with Python SSL and confirms the affected emSign ECC Root CA G3 is absent, then exports that fresh bundle as `PIP_CERT` for later pip commands. The empty-environment smoke test runs before the venv is added to `PATH`; host `curl`, `tar`, and checksum tools remain trusted runner prerequisites. Version 0.13.7 includes the upstream fix for GHSA-hq85-5cpj-mr62.
- The hosted `readonly_install_supervisor_tests` job also pins setup-uv 0.13.7 because it downloads Python; its exact 3.13.13 staging layout allowlist remains intact. A non-root local install reproduced the existing `.gitignore`, empty `.lock`, empty `.temp`, versioned directory, and minor-version alias layout.
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
- Official uv 0.13.7 Linux x64 archive: `https://github.com/astral-sh/uv/releases/download/0.13.7/uv-x86_64-unknown-linux-gnu.tar.gz`, 16,671,812 bytes, SHA256 `c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83`; official release API digest and sidecar agree, and local `shasum -a 256` recheck matched.
- Official uv 0.13.7 macOS ARM64 archive: `https://github.com/astral-sh/uv/releases/download/0.13.7/uv-aarch64-apple-darwin.tar.gz`, 14,347,867 bytes, SHA256 `81b811b57e4624df7ed3aac148e0359100d9962f3d9dce00aec533dc2e086731`; official release API digest and sidecar agree, and local `shasum -a 256` recheck matched.
- Official PyPI certifi 2026.10.23 wheel: `https://files.pythonhosted.org/packages/32/d1/a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/certifi-2026.10.23-py3-none-any.whl`, 135,082 bytes, SHA256 `e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1`; PyPI metadata says `Requires-Python >=3.7`. A real uv 0.13.7 seeded CPython 3.9.25 venv had pip 26.0.1/certifi 2026.01.04 and contained the affected G3 root; after the hash-pinned update, `ssl.create_default_context` loaded 118 certificates and no longer contained that root.
- A non-root uv 0.13.7 install of Python 3.13.13 retained the exact allowlisted staging entries: `.gitignore`, `.lock`, `.temp`, versioned directory, and minor-version alias symlink; the alias pointed to the versioned directory, `.gitignore` contained `*`, `.lock` was empty, and `.temp` had no entries.
