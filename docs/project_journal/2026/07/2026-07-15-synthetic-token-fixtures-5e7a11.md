---
id: 20260715-5e7a11
title: Enforce Exact Synthetic Token Fixtures
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: codex/synthetic-token-v1
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
- Named legacy envelopes store exact values as strict canonical Base64 plus rules and pinned master provenance. Runtime decodes exact ASCII bytes in memory, while metadata and evidence expose only digests and lengths.
- Selected legacy entries pass only when both the complete-tree raw-byte count and the count not embedded inside a longer value from the same envelope are monotonic. The stateful runner recomputes both materialized-head counts before egress, while cross-envelope overlaps fail closed.
- Every complete-catalog legacy raw value and canonical Base64 storage encoding is independently forbidden in base, head, and materialized repository paths through a finite linear byte matcher; diagnostics never expose the matched path or value.
- The helper exposes read-only validate, metadata list, single-value get, exemption list, and pinned-master audit commands.
- Successful preflight records bounded IDs, digests, rules, surfaces, and counts without raw token values; the shared evidence-entry limit is enforced before each new key is inserted.
- The six reviewer-visible control files and their exact directory entry set are bound to helper-private size, digest, record-count, identity, mode, and stable-metadata evidence; added files, nested directories, symlinks, FIFOs, and post-prepare mutations fail closed.
- All six control files are created as `0600` even under permissive caller umasks, while the existing reader continues to reject group- or other-writable artifacts.
- Accepted assignments use bounded continuation inspection, and catalog value uniqueness plus exact authoring/legacy overlap checks are rule-independent.
- Canonical unquoted acceptance rejects YAML/INI indentation folding, operator continuations, quote/backslash/backtick/parameter-expansion concatenation, tabs, ambiguous inline comment/semicolon suffixes, and any next content that is not a bounded same-or-shallower named statement or explicit metadata boundary. Existing harmless placeholders may consume an inline hash comment and source/container closers, but an indented continuation still blocks.
- `$synthetic-token-fixtures` uses the helper CLI and placeholder-only templates rather than duplicating catalog literals.

## Next Steps

- Downstream private overlays may wholesale replace the fixed catalog through a trusted release-time regular-file override.

## Evidence

- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -v` (`376` tests passed; `2` loopback-dependent tests skipped)
- `python3 -m unittest skills.review-orchestration-playbook.tests.test_synthetic_tokens -q` (`74` tests passed)
- `python3 -m unittest skills.review-orchestration-playbook.tests.test_workspace -q` (`56` tests passed)
- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `ruff check` and `ruff format --check` passed for the finding-repair runtime and test files.
- `uv run --with pyyaml python /Users/hoteng/.codex/skills/.system/skill-creator/scripts/quick_validate.py <skill-path>` passed independently for both skills.
