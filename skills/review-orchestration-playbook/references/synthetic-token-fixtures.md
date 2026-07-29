# Synthetic Token Fixtures

## Contents

- [Authority And Threat Model](#authority-and-threat-model)
- [Catalog Schema](#catalog-schema)
- [Authoring Pool](#authoring-pool)
- [Historical Exact Values](#historical-exact-values)
- [Unified Exact-Secret Admission](#unified-exact-secret-admission)
- [Read-Only CLI](#read-only-cli)
- [Admission Evidence](#admission-evidence)
- [Trusted Catalog Customization](#trusted-catalog-customization)
- [Migration Procedure](#migration-procedure)

## Authority And Threat Model

The fixed helper-relative `scripts/review_runtime/synthetic-token-catalog.json` is the sole machine-readable authority for approved synthetic authoring fixtures. Runtime code does not accept a catalog path, environment override, reviewed-repository configuration, project instruction, or dynamic merge. The helper loads the file without following symlinks, requires an owner-matching single-link regular file, enforces a byte limit, parses strict JSON, and fails closed on malformed or ambiguous entries as a helper-owned catalog-integrity failure, not as a tracked secret-delta result.

The authoring facility is finite and exact. It is not a regex namespace and does not accept arbitrary suffixes, prefixes, casing changes, whitespace changes, escapes, encodings, Unicode lookalikes, or embedded matches. New authoring values require a versioned trusted catalog change and tests.

An authoring token suppresses only the scanner rule declared by its catalog entry. Version 1 authoring entries may declare only `generic-secret-assignment`. Acceptance requires one complete unambiguous right-hand side under the bounded scanner. Provider-specific credentials, real JWTs, private keys, adjacent secrets, and every other scanner rule still run. The catalog is a safe-fixture allowlist, not a way to baseline an arbitrary historical secret.

The frozen tracked diff, necessary tracked context, and rendered prompt are integrity-bound trusted reviewer input. They are sent in their original form after the review egress boundary passes, regardless of the separate secret-admission result. Catalog and secret counting never rewrite reviewer input.

## Catalog Schema

The version 1 root retains this compatibility shape:

```json
{
  "schema_version": 1,
  "authoring_pool": {
    "version": "<STABLE_POOL_VERSION>",
    "tokens": [
      {
        "id": "<STABLE_TOKEN_ID>",
        "role": "<ROLE>",
        "state": "<STATE>",
        "rule": "generic-secret-assignment",
        "value": "<EXACT_ASCII_VALUE>"
      }
    ]
  },
  "legacy_exemptions": []
}
```

Authoring roles are `access`, `refresh`, `id`, `api-key`, and `bearer`. States are `active`, `expired`, and `consumed`. IDs and values must be unique; values may not be equal, prefix-related, or substring-related. An authoring value may not occur inside public catalog metadata. Values use only the scanner-compatible ASCII byte set `A-Z`, `a-z`, `0-9`, and `-_./+=!@#$%^&*?~:;`. On every load, the helper runs each entry through the real scanner in canonical quoted and unquoted assignments and requires exactly one acceptance under its declared rule.

Existing version 1 catalogs may still contain `legacy_exemptions` records with `value_base64`, provenance, and source-count metadata. Those fields are retained only for file-format compatibility. The helper automatically decodes every valid legacy `value_base64` solely to recover its historical exact raw candidate. It must not derive or search for that Base64 storage text, another encoding, or any transformed variant. No selection or provenance-audit surface exists, and no new admission policy depends on an envelope, selected ID, containing commit, unembedded count, or provenance record.

## Authoring Pool

The public catalog carries a finite versioned authoring pool. Neither its stable
ID inventory nor its raw values are duplicated in documentation. Use the
active immutable release's manifest-bound `catalog-bootstrap` resolver action
`list` for current metadata and action `get <id>` for one explicitly selected
authoring value. Every action after `bind` requires the captured
`--expect-binding-sha256`. There is no allocator, reservation, release, counter,
suffix generator, or bulk raw-value listing.

When authoring a fixture, reuse a project-recorded compatible ID. Otherwise select by role and state, sort compatible metadata by ID, and take the first entry. For `N` distinct credentials, take the first `N` distinct compatible IDs. Insert each selected value unchanged as the complete captured credential value.

## Historical Exact Values

Historical catalog records are file-format compatibility data only. Their exact
decoded raw values automatically participate in the same complete-tree global
count as other historical secrets. The helper exposes no legacy selection,
listing, or pinned-master audit operation, and provenance metadata cannot
authorize an admission outcome.

Historical catalog values and unregistered exact secrets now use the same rule. A formerly selected legacy value does not retain:

- an unembedded counter;
- path/surface/offset provenance;
- an encoded-variant search;
- a raw-or-Base64 path-name absolute deny;
- a repository or envelope allowlist; or
- a requirement for explicit selection.

Authoring entries remain different because their values are reviewed safe fixtures and suppress only their exact declared scanner rule.

## Unified Exact-Secret Admission

For each countable exact raw secret value outside the approved authoring pool, count occurrences globally across the complete base and head Git trees. The count domain contains each actual tracked surface once:

- raw Git path bytes, including gitlink/submodule entry paths without reading submodule content;
- regular-file blob bytes, including executable blobs; and
- symlink-target bytes.

The rendered diff and prompt are reviewer input and do not add duplicate count surfaces. Require only:

```text
head_count <= base_count
```

Consequences:

- unchanged counts pass;
- deletion passes;
- a move or rename passes;
- movement across path/content, blob/symlink, mode, or byte offset passes;
- a copy passes only when another deletion keeps the global count non-growing;
- `base_count = 0` with a head occurrence is a violation; and
- any other global count growth is a violation.

The counter uses exact raw bytes only. It does not derive canonical Base64, URL encoding, hexadecimal, escaping, hashing, or another representation. An encoded or transformed secret is linked to the raw value only if those bytes independently become an exact scanner candidate. This is a deliberate limitation and must be stated in audit evidence.

A dynamic expression that cannot produce one stable exact byte value does not enter the counter and does not fail admission merely for being non-exact. This is distinct from a genuinely incomplete scan. For a scanner-recognized shape whose exact raw value cannot be extracted, admission retains bounded opaque container evidence: raw Git path bytes identify path containers, while the canonical blob OID alone identifies regular-file and symlink content independently of path and mode; blob paths are not retained. One aggregate budget shared across the base, head, and optional source-WIP endpoint maps permits at most 100,000 endpoint-local identities and 16 MiB of retained path-identity bytes. A repeated identity within one endpoint increments only its integer multiplicity, and a blob identity consumes no path-byte budget. Exact path retention, unchanged blobs, same-blob moves, balanced identical copies/removals, and deletions pass when every head identity count is no greater than base. A renamed or new opaque path, a new or changed opaque blob OID, or greater identical-blob multiplicity is ordinary opaque uncertainty and becomes `inconclusive` only when the completed exact counter has no violation; it cannot replace an independently proved exact growth. Missing or malformed identity, an incomplete bounded tree read, opaque-evidence budget exhaustion, or lost count integrity remains immediately `inconclusive`. For a source-WIP helper snapshot, exact candidate discovery also covers original source HEAD and deduplicates by raw value. Source-HEAD growth erased entirely by the private snapshot yields `inconclusive` with `source-head-exact-growth`; an exact violation still present in the snapshot remains `violations`.

A violation report lists only newly added locations for a candidate whose global count grows. Text additions use the one-based head line. New tracked paths and binary fallbacks use `line: null`; symlink targets use line `1`. Unchanged residual occurrences are omitted. If bounded diff evidence cannot map every detected local growth to an added location, `location_status` is `inconclusive` rather than inventing a line. In particular, endpoint Git trees do not record whether one of multiple identical head blobs was moved and another was copied; when local positive candidates exceed the authoritative global delta, the helper omits those ambiguous locations instead of trusting heuristic rename attribution. The secret-admission result controls only PR/master admission; a trusted Codex, Claude Code, or consent-gated Copilot reviewer still receives the original tracked diff and necessary context.

## Manifest-Bound Authoring Surface

The loaded active-release synthetic skill routes the three internal operations
through `named_lane_guard catalog-bootstrap`:

```bash
named_lane_guard catalog-bootstrap --loaded-skill-root <active-skill-root> bind
named_lane_guard catalog-bootstrap --loaded-skill-root <active-skill-root> \
  --expect-binding-sha256 <binding-sha256> validate
named_lane_guard catalog-bootstrap --loaded-skill-root <active-skill-root> \
  --expect-binding-sha256 <binding-sha256> list
named_lane_guard catalog-bootstrap --loaded-skill-root <active-skill-root> \
  --expect-binding-sha256 <binding-sha256> get <id>
```

Invoke the guard with the absolute interpreter and mandatory `-I -B -S` flags
specified by `synthetic-token-fixtures`; the shorthand above shows only the
action contract. `list` returns authoring metadata only. `get` returns the raw
value for exactly one selected authoring ID.

`isolated_review synthetic-tokens ...` and direct
`scripts/synthetic_catalog_entry` execution are unsupported and rejected before
catalog loading or output. The entry remains an internal manifest companion
whose bound snapshot is executed only by the resolver.

## Admission Evidence

Evidence is range-bound, bounded by entry count and serialized size, and separate from reviewer input. For approved authoring findings, record the catalog schema/pool version, stable token ID, scanner rule, side/surface, digest, and occurrence count without duplicating raw values.

For ordinary exact secrets, record a stable candidate digest, raw byte length, base count, head count, and admission status. Do not record unembedded counts, per-occurrence provenance commitments, derived encodings, or a complete unchanged-occurrence inventory. A violation includes only newly added `path:line` locations. An incomplete exact scan records `inconclusive` and the bounded failure class without inventing a candidate or treating a non-exact expression as scan failure.

Reviewer-visible artifacts remain owner-only, size/digest-bound, and governed by the existing no-follow, identity, cleanup, retention, and bounded-output contract. The admission result does not become a reviewer-launch gate. Evidence is audit data, not a reusable allowlist; every new frozen range must be counted again.

## Trusted Catalog Customization

Downstream users may replace the fixed authoring pool as part of a trusted installation or release build. Replacement must be wholesale, not a union with reviewed-repository data. Keep the same schema and fixed target path, preserve strict validation, add a new pool version for authoring-value changes, and run the complete scanner and catalog tests.

Do not read a replacement from the reviewed repository, caller arguments, environment variables, or project instructions. A release overlay should copy the complete public skill first, replace only the predeclared catalog target with a regular file, reject symlinks and path traversal, validate the generated skill, and verify that generated catalog bytes equal the trusted replacement source.

Existing historical records may be retained for file-format compatibility, but
new historical baselines do not require catalog entries or envelopes.

## Migration Procedure

1. New and pull-request-only fixtures must use the approved authoring pool.
2. Stop adding legacy envelopes for ordinary historical secrets; the complete base tree is their baseline.
3. Remove unsupported legacy-selection, exemption-listing, and pinned-master-audit calls from automation.
4. Delete obsolete historical records once file-format recovery no longer needs them.
5. Run scanner, catalog, admission-counter, evidence, and authoring-CLI tests.

If a branch-only secret has already been published and increases the exact global count, replace it in the repository task. Clean published branch history only after explicit user authorization; never broaden reviewer-input or admission policy to avoid that repository-local repair.
