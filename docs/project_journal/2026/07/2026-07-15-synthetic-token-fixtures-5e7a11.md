---
id: 20260715-5e7a11
title: Enforce Exact Synthetic Token Fixtures
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: wip/synthetic-token-v1
pr: 44
supersedes: []
superseded_by:
---

# Enforce Exact Synthetic Token Fixtures

## Summary

- The review helper now owns a finite versioned authoring pool and monotonic legacy migration envelopes, while a thin skill selects exact values through a read-only CLI.

## Current State

- The fixed helper-relative JSON catalog is the only runtime authority; reviewed repositories, environment variables, and caller configuration cannot replace or extend it.
- Public authoring tokens cover access, refresh, ID, API-key, and bearer roles plus expired and consumed states.
- Exact complete scanner captures may suppress only `generic-secret-assignment`; provider credentials, JWTs, private keys, adjacent values, high-entropy assignments, and credential paths remain blocking.
- Named legacy envelopes store only digests, lengths, rules, and pinned master provenance. Selected entries pass only when each complete captured value has `head_count <= base_count` across the full repository.
- The helper exposes read-only validate, metadata list, single-value get, exemption list, and pinned-master audit commands.
- Successful preflight records bounded IDs, digests, rules, surfaces, and counts without raw token values.
- Accepted assignments use bounded continuation inspection, and catalog value uniqueness plus recovered legacy overlap checks are rule-independent.
- `$synthetic-token-fixtures` uses the helper CLI and placeholder-only templates rather than duplicating catalog literals.

## Next Steps

- Downstream private overlays may wholesale replace the fixed catalog through a trusted release-time regular-file override.

## Evidence

- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -v` (`345` tests passed; `2` loopback-dependent tests skipped)
- `python3 -m py_compile skills/review-orchestration-playbook/scripts/review_runtime/*.py skills/review-orchestration-playbook/tests/test_*.py`
- `ruff check --ignore F401` passed for every changed runtime and test module.
- `uv run --offline --with pyyaml python .../quick_validate.py <skill>` passed for both skills using the locally cached PyYAML runtime.
