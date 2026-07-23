---
name: synthetic-token-fixtures
description: Select exact catalog-approved synthetic access, refresh, ID, API-key, and bearer values through the installed review helper's authoring CLI. Use when adding or revising credential-shaped fixtures, choosing distinct token roles or lifecycle states, or replacing invented or branch-only synthetic literals.
---

# Synthetic Token Fixtures

Use the installed review helper's catalog and CLI as the only machine authority
for authoring token IDs, metadata, and raw values. This skill is routing and
selection guidance only: it does not define a pool, copy values, allocate tokens,
or let a project override the catalog.

```bash
catalog_cli="${CODEX_HOME:-$HOME/.codex}/skills/review-orchestration-playbook/scripts/isolated_review"
```

## Authoring CLI Contract

The authoring surface has exactly three operations:

- `"$catalog_cli" synthetic-tokens validate` validates the fixed catalog and its scanner contract.
- `"$catalog_cli" synthetic-tokens list --json` returns `pool_version` plus metadata-only token records. It must not expose raw values.
- `"$catalog_cli" synthetic-tokens get <id> --json` returns the one explicitly selected record and its exact raw value. It must not bulk-return other raw values.

If any of these operations is missing, the catalog does not validate, or output
violates this boundary, stop instead of reconstructing values from documentation
or source.

## Select Authoring Tokens

1. Resolve `catalog_cli` from the installed skill root shown above; do not use a
   repository-local copy or caller-selected catalog.
2. Run `validate`, then metadata-only `list --json`.
3. Read `pool_version` and each token's `id`, `role`, `state`, `rule`, and
   `value_sha256`. Supported roles are `access`, `refresh`, `id`, `api-key`, and
   `bearer`; supported states are `active`, `expired`, and `consumed`.
4. Reuse token IDs already named by the project when their role and state still
   fit. Otherwise filter by role and state, sort by ID, and choose the first
   compatible entry. Choose distinct IDs for fixtures that model distinct
   credentials, and record those IDs with the fixture.
5. Run single-ID `get <id> --json` for each chosen ID. Insert the returned value
   verbatim as the complete credential value.
6. Run the affected tests. Hand frozen-range preflight and review work to
   `$review-orchestration-playbook`; a catalog match does not override another
   scanner rule or a credential-like path finding.

Do not append counters, change case or whitespace, escape or encode the value,
use a Unicode lookalike, or embed it inside another string. If the catalog lacks
the required role, state, or count, stop and request an explicit catalog update.

Prefer a structured named fixture field or another unambiguously complete
statement. If preflight cannot prove that the value is not continued by adjacent
code, restructure the fixture rather than changing the token.

Read [fixture-templates.md](references/fixture-templates.md) when creating a fixture shape. The templates deliberately contain placeholders only.

## Legacy Compatibility Boundary

Legacy exemption selection and pinned-master audit remain review-helper
compatibility surfaces only. They are not fixture-authoring operations, do not
extend the authoring catalog, and are intentionally not routed by this skill.
Replace new or branch-only values with an authoring token in an ordinary forward
commit; hand an unavoidable historical-range review to
`$review-orchestration-playbook`.

## Guardrails

- Never copy token literals into this skill, templates, project instructions, or an allocator.
- Never create a project-local pool, catalog override, second CLI, reservation, or fallback value.
- Never invent IDs, suffixes, reservations, counters, or regex namespaces.
- Never treat words such as `synthetic`, `test`, `fixture`, or `sentinel` as proof that a value is safe.
- Never use a legacy compatibility exemption for prompts, new fixtures, or a net increase in repository occurrences.
