---
id: 20260722-pot001
title: Repair Private Overlay Test Compatibility
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/private-overlay-test-compat
pr:
supersedes: []
superseded_by:
---

# Repair Private Overlay Test Compatibility

## Summary

- Make the canonical review contract tests resolve repository policy files through the canonical/private CI profile instead of assuming the public repository layout.
- Keep canonical `README.md` assertions canonical-only because the private overlay has its own repository README.
- Build malicious bytecode fixtures at the unoptimized cache location used by the isolated `-I` guard subprocess, even when the parent test process has `PYTHONPYCACHEPREFIX` or optimization enabled.

## Current State

- The generated private overlay can run the canonical contract suite without copying private policy files into public-repository paths.
- Unchecked bytecode fixtures recursively create their isolated cache parents, fix both the cache tag and compilation level to unoptimized mode, and still exercise the path the guarded interpreter would inspect.
- Production review runtime behavior is unchanged; this repair is limited to portable integration-test setup and repository-profile resolution.

## Next Steps

- None in the target-branch post-merge state recorded here. PR, private-overlay sync, and release transition state remain in their delivery workflow rather than this completed journal.

## Evidence

- Failing integration run: https://github.com/Joey-Tools/codex-private-workflows/actions/runs/29923546683
- The five focused regressions pass with a fresh `PYTHONPYCACHEPREFIX` whose ancestor directories do not exist.
- `test_contracts.py`: 86 tests passed.
- `test_named_lane.py`: 164 tests passed with `PYTHONPYCACHEPREFIX` set and the parent interpreter running with `-O`.
