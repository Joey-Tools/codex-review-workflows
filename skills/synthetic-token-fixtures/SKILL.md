---
name: synthetic-token-fixtures
description: Select exact catalog-approved synthetic access, refresh, ID, API-key, and bearer values through the active immutable macOS or Linux personal-sync review-skill release's authoring CLI. Use when adding or revising credential-shaped fixtures, choosing distinct token roles or lifecycle states, or replacing invented or branch-only synthetic literals.
---

# Synthetic Token Fixtures

Use the review helper catalog and CLI from the same active immutable release as
this loaded skill as the only machine authority for authoring token IDs,
metadata, and raw values. This skill is routing and selection guidance only: it
does not define a pool, copy values, allocate tokens, or let a project override
the catalog.

```bash
synthetic_skill_root="<absolute directory containing this loaded SKILL.md>"
binding_resolver="$synthetic_skill_root/scripts/active_catalog_binding.py"
```

## Bind The Active Source

1. Resolve one absolute Python 3 interpreter through the user or repository's
   normal runtime authority. Run that interpreter with `-E -B -s -S` against
   the skill-relative `binding_resolver`. Do not search `CODEX_HOME`, `HOME`,
   `PATH`, another checkout, or a caller-provided catalog path for the review
   skill. The resolver requires POSIX no-follow, nonblocking, close-on-exec, and
   ownership primitives; on an unsupported native runtime, stop rather than
   selecting another source.
2. Require a successful versioned-release binding. The resolver derives the
   sibling review skill from its own resolved file location, verifies that the
   release `sync-manifest.json` installs both skill sources, and returns the
   exact absolute release/root/manifest/CLI/catalog/interpreter paths, release
   ID, review-runtime tree digest, manifest/CLI/catalog/skill/interpreter
   SHA-256 digests, `pool_version`, and one canonical `binding_sha256`.
3. Stop on a non-release layout, missing sibling, symlink, bytecode/native
   import substitute, package shadow, unsafe ownership or write policy, invalid
   catalog, ambiguous source, or digest mismatch. A repository working copy is
   not an active release.
4. Before and after every authoring CLI operation, rerun the same resolver with
   `--expect-binding-sha256 <binding_sha256>`. Use only the returned exact
   `python_executable` and `catalog_cli_path`; invoke them as:

```bash
"$python_executable" -E -B -s -S "$catalog_cli" synthetic-tokens validate
```

The resolver binds source identity but is not a second token CLI. It never
accepts a catalog or review-skill path and never returns token values. The
review skill-local CLI and catalog remain the sole authoring authority.

## Authoring CLI Contract

The authoring surface has exactly three operations:

- `"$catalog_cli" synthetic-tokens validate` validates the fixed catalog and its scanner contract.
- `"$catalog_cli" synthetic-tokens list --json` returns `pool_version` plus metadata-only token records. It must not expose raw values.
- `"$catalog_cli" synthetic-tokens get <id> --json` returns the one explicitly selected record and its exact raw value. It must not bulk-return other raw values.

If any operation is missing, the catalog does not validate, the CLI response
`pool_version` differs from the bound `pool_version`, the binding changes during
selection, or output violates this boundary, stop instead of reconstructing
values from documentation or source.

## Select Authoring Tokens

1. Capture and verify the active-source binding above.
2. Run bound `validate`, then metadata-only `list --json`, revalidating
   `binding_sha256` around each operation.
3. Read `pool_version` and each token's `id`, `role`, `state`, `rule`, and
   `value_sha256`. Supported roles are `access`, `refresh`, `id`, `api-key`, and
   `bearer`; supported states are `active`, `expired`, and `consumed`.
4. Reuse token IDs already named by the project when their role and state still
   fit. Otherwise filter by role and state, sort by ID, and choose the first
   compatible entry. Choose distinct IDs for fixtures that model distinct
   credentials, and record those IDs with the fixture.
5. Run bound single-ID `get <id> --json` for each chosen ID. Revalidate the
   binding and `pool_version`, then insert the returned value verbatim as the
   complete credential value.
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
- Never create a project-local pool, catalog override, second token CLI, reservation, or fallback value.
- Never select the catalog through `CODEX_HOME`, `HOME`, `PATH`, a repository copy, or a caller-provided path.
- Never invent IDs, suffixes, reservations, counters, or regex namespaces.
- Never treat words such as `synthetic`, `test`, `fixture`, or `sentinel` as proof that a value is safe.
- Never use a legacy compatibility exemption for prompts, new fixtures, or a net increase in repository occurrences.
