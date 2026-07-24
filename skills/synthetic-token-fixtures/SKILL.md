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
   normal runtime authority. Invoke the skill-relative `binding_resolver` only
   with `-I -B -S`, the exact absolute directory containing this loaded
   `SKILL.md`, and the `bind` action:

```bash
"$python_executable" -I -B -S "$binding_resolver" \
  --loaded-skill-root "$synthetic_skill_root" bind
```

   `-I` is mandatory: `-E -B -s -S` still leaves the script directory on
   `sys.path`. The resolver checks isolated-mode flags before importing
   `argparse`, `json`, or any other non-builtin module, so a resolver-local or
   current-directory module shadow cannot execute before source admission.
   It requires POSIX no-follow, nonblocking, close-on-exec file primitives and
   fails closed when they are unavailable.
   Do not search `CODEX_HOME`, `HOME`, `PATH`, another checkout, or a
   caller-provided catalog path for the review skill.
2. Require a successful versioned-release binding. The resolver validates the
   original absolute resolver leaf before any `resolve`, rejects symlinks,
   validates every release-to-resolver parent including the `scripts`
   directory, binds the explicitly loaded skill root, and derives the sibling
   review skill from that same co-release. It verifies that the release
   `sync-manifest.json` installs both skill sources and returns release/root
   identity, review-runtime tree digest, source/interpreter snapshot digests,
   `pool_version`, and one canonical `binding_sha256`.
3. Stop on a non-release layout, loaded-skill mismatch, cross-release symlink,
   missing sibling, bytecode/native import substitute, package shadow, unsafe
   ownership or write policy, invalid catalog, ambiguous source, or digest
   mismatch. A repository working copy is not an active release.
4. Run each authoring operation through the resolver with the captured binding:

```bash
"$python_executable" -I -B -S "$binding_resolver" \
  --loaded-skill-root "$synthetic_skill_root" \
  --expect-binding-sha256 "$binding_sha256" validate
```

   `--expect-binding-sha256` is mandatory for every `validate`, `list`, and
   `get` action; only `bind` may omit it. The resolver rejects a missing,
   malformed, or changed expected digest before executing the bound catalog
   operation, including before a `get` can publish a raw credential-shaped
   value.

   Each invocation is one controlled in-process transaction. It retains the
   active interpreter, resolver, review CLI, and catalog descriptor bindings;
   executes the review CLI only from manifest-bound source snapshots through a
   closed `review_runtime` import set; captures and validates the operation
   result and `pool_version`; removes the temporary module namespace; and
   closes the bound descriptors before publishing the result envelope. It
   never executes the returned Python or CLI path, and there is no
   validate-path / execute-path / revalidate-path window.

The resolver is an execution guard, not a second token CLI. It never accepts a
catalog or review-skill path, never defines token values, and exposes raw value
output only for one explicitly requested `get` operation. The manifest-bound
review skill-local CLI and catalog remain the sole authoring authority.

## Authoring CLI Contract

The authoring surface has exactly three operations:

- Resolver action `validate` runs `synthetic-tokens validate` against the bound fixed catalog and validates its scanner contract.
- Resolver action `list` runs `synthetic-tokens list --json` and returns `pool_version` plus metadata-only token records. It must not expose raw values.
- Resolver action `get <id>` runs `synthetic-tokens get <id> --json` and returns the one explicitly selected record and its exact raw value. It must not bulk-return other raw values.

If any operation is missing, the catalog does not validate, the CLI response
`pool_version` differs from the bound `pool_version`, the binding changes during
selection, or output violates this boundary, stop instead of reconstructing
values from documentation or source.

## Select Authoring Tokens

1. Capture and verify the active-source binding above.
2. Run bound `validate`, then metadata-only `list`, requiring the same
   `binding_sha256` inside each completed transaction envelope.
3. Read `pool_version` and each token's `id`, `role`, `state`, `rule`, and
   `value_sha256`. Supported roles are `access`, `refresh`, `id`, `api-key`, and
   `bearer`; supported states are `active`, `expired`, and `consumed`.
4. Reuse token IDs already named by the project when their role and state still
   fit. Otherwise filter by role and state, sort by ID, and choose the first
   compatible entry. Choose distinct IDs for fixtures that model distinct
   credentials, and record those IDs with the fixture.
5. Run bound single-ID `get <id>` for each chosen ID. Require the same binding
   and `pool_version`, then insert the returned value verbatim as the complete
   credential value.
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
