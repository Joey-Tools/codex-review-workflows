---
id: 20260722-7f2201
title: Claude Compatible Version Range
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/claude-compatible-version-range
pr:
supersedes: []
superseded_by:
---

# Claude Compatible Version Range

## Summary

- The canonical named Claude Code lane uses the publisher-verified stable release range `>=2.1.211,<3.0.0` instead of a single-patch eligibility rule.
- The range has one production source of truth in `scripts/review_runtime/claude_version_policy.py`; documentation, signed per-version manifests, and stream fixtures do not redefine it.
- Publisher-first provenance, signed manifest/digest verification, nonblocking descriptor-bound candidate reads, path and artifact identity binding, TOCTOU revalidation, mandatory advertised-capability probing, and strict stream validation remain required.

## Current State

- Stable releases such as `2.1.211` and `2.1.216` are eligible candidates. An in-range later patch is not rejected because of its version number, but every selected release must pass the complete provenance, identity, capability, and stream-contract gates.
- Claude Code `2.1.212` remains the audited per-version stream-schema baseline, not a global eligibility pin. `claude-stream-compatibility.json` uses `strict-version-and-launch-profiles`: it binds that baseline and selects closed `legacy-base` (`>=2.1.211,<2.1.216`) or `extended-2x` (`>=2.1.216,<3.0.0`) init/intermediate/terminal structure for the exact preflight-selected release. Unknown fields, variants, malformed values, or session mismatches fail closed; profile compatibility is not a claim that every patch received a separate schema audit.
- The credential-free `--help` probe is mandatory and verifies only the advertised capability surface. Help and `system/init` evidence—including 2.1.212 output—do not prove launch semantics, the final merged sandbox, managed permission arrays, or path-rule evaluation.
- The accepted preflight result is retained outside the reviewer worktree as a current-user-owned, single-link parent-private regular file. The validator binds selected-version, publisher, capability, identity, compatibility-profile, audited-baseline, and capability-contract source digests before findings can count; workspace-local, linked, special-file, stale, or mismatched evidence fails closed.
- Outside-workspace read exclusion remains prompt/model scope. The native selected-deny sandbox enforces requested global write denial and critical-sensitive-root read denial, but `allowRead` is not a global host-read whitelist.
- For the named direct lane, real `HOME` remains the trusted ordinary Claude CLI control plane. Necessary authentication refresh, cache, and tool-result artifacts are accepted residual CLI writes; they are not model-authorized review mutations, and `--no-session-persistence` does not make that control plane immutable. The low-level helper instead retains its separate broker/carrier/catalog/full refresh transaction for local login; an exact catalog miss blocks only helper local login, not the named direct lane or helper explicit API-key/OAuth-token modes.
- A named review request never installs, downgrades, switches, or repairs Claude Code. In particular, the audited 2.1.212 baseline does not require installing or downgrading to that patch.

## Next Steps

- No canonical policy work remains for this correction. Downstream distributions should sync only from the corrected canonical default branch.

## Evidence

- `skills/review-orchestration-playbook/scripts/review_runtime/claude_version_policy.py`
- `skills/review-orchestration-playbook/scripts/review_runtime/named_claude_preflight.py`
- `skills/review-orchestration-playbook/scripts/review_runtime/claude_stream_contract.py`
- `skills/review-orchestration-playbook/references/claude-stream-compatibility.json`
- `skills/review-orchestration-playbook/references/claude-2.1.212-stream-schema.json`
- `skills/review-orchestration-playbook/references/canonical-claude-lane.md`
- `skills/review-orchestration-playbook/tests/test_named_claude_preflight.py`
- `skills/review-orchestration-playbook/tests/test_validate_claude_stream.py`
- `skills/review-orchestration-playbook/tests/test_contracts.py`
