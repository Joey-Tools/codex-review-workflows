---
id: 20260716-7f16d2
title: Retire Temporary JWT Legacy Envelope
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: codex/daily-skill-friction-20260716-codex-review-workflows-retire-temporary-jwt-envelope
pr:
supersedes: []
superseded_by:
---

# Retire Temporary JWT Legacy Envelope

## Summary

PR #52 added one narrowly scoped JWT legacy envelope so the
`codex-workflow-hygiene` historical fixture could be deleted through fixed
frozen review ranges. Those ranges have finished, so this workstream removes
the temporary envelope and restores JWT findings to an unconditional
fail-closed boundary.

## Current State

- The public synthetic-token catalog has no legacy exemptions.
- Legacy envelopes may declare only `generic-secret-assignment` or
  `github-token`; `jwt` is rejected by catalog validation for both legacy and
  authoring entries.
- JWT scanner detection remains active, while JWT-specific legacy acceptance,
  preflight, provenance-audit, and public-catalog positive tests have been
  removed.
- The synthetic-token reference and helper contract now state explicitly that
  JWT findings are never eligible for legacy suppression.
- The earlier synthetic-token journal remains unchanged as the historical
  evidence for PR #52 and its master-proven migration envelope.
- The independent `NODE_EXTRA_CA_CERTS` trust support merged in PR #54 remains
  unchanged.

## Validation Evidence

- `isolated_review synthetic-tokens validate` passed for
  `public-example-v1`.
- `isolated_review synthetic-tokens list-exemptions --json` returned an empty
  exemption list.
- JWT-focused synthetic-token regressions passed (`2` tests).
- The full review-orchestration suite passed (`705` tests; `4` skipped).
- Python compile checks passed for the helper scripts and changed test module.
- Offline `ruff check` and `ruff format --check` passed for the changed Python
  files.
- Isolated PyYAML skill validation passed for both
  `review-orchestration-playbook` and `synthetic-token-fixtures`.
- Project-journal validation and `git diff --check` passed.

## Next Steps

- None for this retirement workstream.
