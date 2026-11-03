# Private CI Runner Routing

The private CI workflow fixture in this repository mirrors `codex-private-workflows` and is covered by its contract tests. Runner routing preserves the existing jobs, test modules, shards, matrices, and hosted coverage while adapting provider-specific runtime setup where needed.

## Repository Variables

Set these Actions variables in `Joey-Tools/codex-private-workflows` to route the corresponding jobs to its repository-registered self-hosted runners:

| Variable | Example JSON value |
| --- | --- |
| `CODEX_PRIVATE_LINUX_RUNNER_LABELS` | `["self-hosted","Linux","X64","codex-private-linux"]` |
| `CODEX_PRIVATE_MACOS_RUNNER_LABELS` | `["self-hosted","macOS","ARM64","codex-private-macos"]` |

Each value is a JSON array of labels. An empty or unset value selects the original hosted label for every job in that OS route. Clear both private runner variables and `CODEX_REVIEW_GATE_RUNNER_LABELS` to restore every hosted route. `CODEX_REVIEW_GATE_RUNNER_LABELS` already accepts JSON labels; its existing `CODEX_REVIEW_GATE_USE_UBUNTU_LATEST` fallback remains supported.

Runner registration is repository-only. The planned Linux pool has four instances on `dradar-hoteng`. The planned macOS pool has two instances under a dedicated runner account on `India-mac-mini-m4-hoteng`. Provisioning is not complete, so these values describe the intended configuration and do not establish that either pool is live.

## Platform-Specific Checks

- Hosted macOS fingerprint reporting and hosted-only no-child probes continue to run only on GitHub-hosted runners. Functional tests and the real read-only supervisor custody and isolation checks continue on both runner types.
- The self-hosted macOS path discovers Xcode with `xcode-select -p`. When the read-only macOS job uses the self-hosted pool, workflow concurrency serializes it with `queue: max` because UID allocation is machine-global; the original hosted parallelism is retained.
- The Linux Python 3.9 compatibility job keeps `actions/setup-python` on hosted runners. On self-hosted Ubuntu 26, it uses `uv` to install Python 3.9 and create a seeded per-job virtual environment because the official setup-python artifact is unavailable there.

This routing slice does not include CI optimization. Timing-based optimization belongs in a follow-up PR, and live self-hosted validation requires completed runner provisioning.
