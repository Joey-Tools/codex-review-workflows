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
trusted_bundle_root="<parent-verified bundle containing agents/ and skills/>"
catalog_guard="$trusted_bundle_root/skills/review-orchestration-playbook/scripts/named_lane_guard"
```

## Bind The Active Source

1. Resolve one absolute Python 3 interpreter through the user or repository's
   normal runtime authority. Independently bind the trusted bundle's canonical
   control manifest and record its release/version plus SHA-256 as required by
   `$review-orchestration-playbook`. Invoke only that manifest-bound guard with
   `-I -B -S`, the exact absolute directory containing this loaded `SKILL.md`,
   and its `catalog-bootstrap` profile:

```bash
"$python_executable" -I -B -S "$catalog_guard" catalog-bootstrap \
  --loaded-skill-root "$synthetic_skill_root" bind
```

   `-I` is mandatory: `-E -B -s -S` still leaves the script directory on
   `sys.path`. The guard must come from a previously trusted release or frozen
   prior-policy bundle outside any candidate range. Its exact two-source
   catalog-bootstrap closure, trusted runtime-manifest digest, and the
   co-release synthetic `SKILL.md` and resolver are records in that bundle's
   canonical control manifest. During a
   self-policy migration, keep using the prior trusted release; candidate-head
   Python and machine schemas are implementation/test subjects only and never
   bootstrap their own activation.
   Do not search `CODEX_HOME`, `HOME`, `PATH`, another checkout, or a
   caller-provided catalog path for the review skill.
2. Require a successful versioned-release binding. The guard derives the
   resolver from its own manifest-bound co-release instead of accepting a
   resolver path. Before any resolver byte executes, the trusted bootstrap
   opens every target with POSIX `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, validates
   regular-file type, current-user ownership, non-writable access policy,
   descriptor/path identity, stable complete content, the co-release
   `sync-manifest.json`, and exact equality with the control-manifest source
   bytes. It then compiles and executes those same bound resolver bytes
   in-process, retains the descriptors, and withholds stdout and raw values
   until final identity/content revalidation succeeds. A symlink, malicious
   leaf replacement, or loaded-skill root from another release therefore
   cannot run through the resolver path or publish a result.

   The resolver independently repeats the release-to-leaf binding, validates
   the explicitly loaded skill root and sibling review skill from the same
   co-release, and returns the trusted bootstrap binding, release/root
   identity, exact runtime closure, source/interpreter snapshot digests,
   `pool_version`, and one canonical `binding_sha256`.

   The trusted runtime manifest uses profile
   `synthetic-catalog-authoring-v1`. It binds the dedicated catalog entry,
   `review_runtime/__init__.py`, `common.py`, `cli.py`,
   `synthetic_tokens.py`, and `synthetic-token-catalog.json` by exact path and
   SHA-256. The resolver rejects every other module, path, profile, or import;
   it does not inventory or authorize the surrounding review scripts tree.
3. Stop on a non-release layout, loaded-skill mismatch, cross-release symlink,
   missing sibling, bytecode/native import substitute, package shadow, unsafe
   ownership or write policy, invalid catalog, ambiguous source, or digest
   mismatch. A repository working copy is not an active release.
4. Run each authoring operation through the resolver with the captured binding:

```bash
"$python_executable" -I -B -S "$catalog_guard" catalog-bootstrap \
  --loaded-skill-root "$synthetic_skill_root" \
  --expect-binding-sha256 "$binding_sha256" validate
```

   `--expect-binding-sha256` is mandatory for every `validate`, `list`, and
   `get` action; only `bind` may omit it. The resolver rejects a missing,
   malformed, or changed expected digest before executing the bound catalog
   operation, including before a `get` can publish a raw credential-shaped
   value.

   Each invocation is one controlled in-process transaction. It retains the
   active interpreter, trusted bootstrap, resolver, trusted runtime manifest,
   dedicated catalog entry, four source modules, and catalog descriptor
   bindings; executes the resolver and catalog entry only from
   manifest-bound source snapshots through closed source loaders that ignore
   `__pycache__` and never load bytecode; captures and validates the operation
   result and `pool_version`; removes the temporary module namespace; and
   closes the bound descriptors before publishing the result envelope. It
   never executes the resolver or returned CLI as a path, and there is no
   validate-path / execute-path / revalidate-path window.

The resolver is an execution guard, not a second token CLI. It never accepts a
catalog or review-skill path, never defines token values, and exposes raw value
output only for one explicitly requested `get` operation. The manifest-bound
review skill-local CLI and catalog remain the sole authoring authority.

## Runtime Manifest Rotation

The manifest cannot authorize its own first binding. Its exact SHA-256 is
provisioned in `named_lane_guard`; changing any listed byte requires an
ordinary candidate commit that updates the listed digest and that pinned guard
digest together. Review that candidate with the previous trusted release,
merge and publish it, and only then use the new release as catalog authority.
Adding a module or changing the profile also requires a versioned contract
change; merely listing another file is rejected. Candidate-head guard or
manifest bytes never bootstrap their own activation.

## Authoring CLI Contract

The authoring surface has exactly three operations:

- Resolver action `validate` runs the dedicated authoring-only catalog
  validation against the bound fixed catalog. The ordinary review-helper test
  and admission suites independently validate scanner compatibility; the
  authoring runtime does not import the review workspace or scanner.
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
- Never pass the resolver path as Python's script argv or use candidate-head
  review control to activate its own catalog bootstrap.
- Never create a project-local pool, catalog override, second token CLI, reservation, or fallback value.
- Never select the catalog through `CODEX_HOME`, `HOME`, `PATH`, a repository copy, or a caller-provided path.
- Never invent IDs, suffixes, reservations, counters, or regex namespaces.
- Never treat words such as `synthetic`, `test`, `fixture`, or `sentinel` as proof that a value is safe.
- Never use a legacy compatibility exemption for prompts, new fixtures, or a net increase in repository occurrences.
