# Private CI Runner Routing

The private CI workflow fixture in this repository mirrors `codex-private-workflows` and is covered by its contract tests. Runner routing preserves the existing jobs, test modules, shards, and matrices while adapting provider-specific runtime setup. Three jobs retain GitHub-hosted runners for their hosted checks or disposable environments.

## Repository Variables

Set these Actions variables in `Joey-Tools/codex-private-workflows` to route the corresponding jobs to its repository-registered self-hosted runners:

| Variable | Example JSON value |
| --- | --- |
| `CODEX_PRIVATE_LINUX_RUNNER_LABELS` | `["self-hosted","Linux","X64","codex-private-linux"]` |
| `CODEX_PRIVATE_MACOS_RUNNER_LABELS` | `["self-hosted","macOS","ARM64","codex-private-macos"]` |

Each value is a JSON array of labels. An empty or unset value selects the original hosted label for each dynamically routed job in that OS route; the three hosted-only jobs below are fixed exceptions. Clear both private runner variables and `CODEX_REVIEW_GATE_RUNNER_LABELS` to restore every dynamic route to its hosted default. `CODEX_REVIEW_GATE_RUNNER_LABELS` already accepts JSON labels; its existing `CODEX_REVIEW_GATE_USE_UBUNTU_LATEST` fallback remains supported.

Runner registration is repository-only. Four Linux instances on `dradar-hoteng` and two macOS instances under a dedicated runner account on `India-mac-mini-m4-hoteng` are registered and have accepted jobs. Full CI validation of the portable Python setup remains separate from runner availability.

## Platform-Specific Checks

- `independent_supervisor_tests` stays on hosted `macos-26` so its fingerprint, hosted no-child regressions, and broker byte-reproduction check all remain covered.
- `readonly_install_supervisor_tests` stays on hosted `macos-26`: failure and cancellation paths can retain local accounts and immutable root-owned trees until runner disposal.
- `linux_isolation_tests` stays on hosted `ubuntu-latest` because it changes the global AppArmor user-namespace restriction. Persistent runners retain their existing host policy.
- Dynamically routed jobs use the local `setup-private-python` composite action. Hosted runners keep `actions/setup-python@v5` with the requested version. Self-hosted runners download uv 0.11.18 for Linux x64 or macOS ARM64 into a fresh mode-700 root in `RUNNER_TEMP`, verify the official archive size and pinned SHA256 before extracting the `uv` binary, then keep uv, managed CPython, the uv package cache, and the seeded environment in that per-job root. Bootstrap calls disable uv configuration discovery, and venv creation also disables project discovery. The managed interpreter is smoke-tested with an empty environment before its venv is added to `PATH`; system `curl`, `tar`, and checksum tools remain part of the runner OS trust boundary. The `3.x` request is passed to uv as `3`; fixed minor requests such as `3.9` and `3.10` are preserved.

This routing slice does not include CI optimization. Timing-based optimization and removing the three hosted dependencies belong in a follow-up PR.
