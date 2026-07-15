---
name: synthetic-token-fixtures
description: Select exact helper-approved synthetic access, refresh, ID, API-key, and bearer values for source or test fixtures that must pass isolated-review secret preflight. Use when adding or revising credential-shaped fixtures, choosing distinct token roles or lifecycle states, replacing branch-only synthetic literals, or inspecting a named historical fixture exemption.
---

# Synthetic Token Fixtures

Use the installed review helper as the only source of token values. The helper-owned catalog, not this skill or a project file, defines what preflight accepts.

```bash
review_helper="${CODEX_HOME:-$HOME/.codex}/skills/review-orchestration-playbook/scripts/isolated_review"
```

## Select Authoring Tokens

1. Locate the installed helper at `$CODEX_HOME/skills/review-orchestration-playbook/scripts/isolated_review`, or under `$HOME/.codex` when `CODEX_HOME` is unset.
2. Run `"$review_helper" synthetic-tokens validate`, then `"$review_helper" synthetic-tokens list --json`. Listing returns metadata, not raw values.
3. Read `pool_version` and each token's `id`, `role`, `state`, `rule`, and `value_sha256`. Supported roles are `access`, `refresh`, `id`, `api-key`, and `bearer`; supported states are `active`, `expired`, and `consumed`.
4. Reuse token IDs already named by the project when their role and state still fit. Otherwise filter by role and state, sort by ID, and choose the first compatible entry. For distinct fixtures, choose the first distinct `N` IDs. Record the selected IDs with the fixture so later work reuses them instead of reselecting after a catalog update.
5. Run `"$review_helper" synthetic-tokens get <id> --json` for each chosen ID. Insert the returned value verbatim as the complete credential value.
6. Run the affected tests. Hand the exact frozen-range preflight and review invocation to `$review-orchestration-playbook`; a catalog match does not override another scanner rule or a credential-like path finding.

Do not append counters, change case or whitespace, escape or encode the value, use a Unicode lookalike, or embed it inside another string. If the active catalog lacks the required role, state, or count, stop and request an explicit catalog update.

Prefer a structured named fixture field or another unambiguously complete statement. If preflight cannot prove that the value is not continued by adjacent code, restructure the fixture rather than changing the token or requesting a broader exemption.

## Handle Historical Fixtures

Use `"$review_helper" synthetic-tokens list-exemptions --json` only to inspect helper-owned legacy envelopes. A selected envelope is a migration bridge for values already proven in master history, not an authoring pool. Pass its ID with repeatable `--synthetic-secret-exemption <id>` only when reviewing the affected frozen range.

Never register a pull-request-only value as legacy or run `audit-master` against a pull-request ref. Replace it with an authoring token in an ordinary forward commit by default. Rewrite already-published branch history only with explicit user authorization.

Catalog admission and pinned-master audits belong to the review helper's [focused synthetic-token reference](../review-orchestration-playbook/references/synthetic-token-fixtures.md), not this selection skill.

Read [fixture-templates.md](references/fixture-templates.md) when creating a fixture shape. The templates deliberately contain placeholders only.

## Guardrails

- Never copy token literals into this skill, templates, project instructions, or an allocator.
- Never invent IDs, suffixes, reservations, counters, or regex namespaces.
- Never treat words such as `synthetic`, `test`, `fixture`, or `sentinel` as proof that a value is safe.
- Never use a legacy exemption for prompts, new fixtures, or a net increase in repository occurrences.
