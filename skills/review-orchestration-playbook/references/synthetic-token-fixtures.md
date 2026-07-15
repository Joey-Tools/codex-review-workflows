# Synthetic Token Fixtures

## Contents

- [Authority And Threat Model](#authority-and-threat-model)
- [Catalog Schema](#catalog-schema)
- [Authoring Pool](#authoring-pool)
- [Legacy Exemptions](#legacy-exemptions)
- [Read-Only CLI](#read-only-cli)
- [Preflight Evidence](#preflight-evidence)
- [Private Catalog Replacement](#private-catalog-replacement)
- [Migration Procedure](#migration-procedure)

## Authority And Threat Model

The fixed helper-relative `scripts/review_runtime/synthetic-token-catalog.json` is the sole machine-readable enforcement authority. Runtime code does not accept a catalog path, environment override, reviewed-repository configuration, project instruction, or dynamic merge. The helper loads the file without following symlinks, requires an owner-matching single-link regular file, enforces a byte limit, parses strict JSON, and fails closed on malformed or ambiguous entries.

The facility is intentionally finite and exact. It is not a regex namespace and does not accept arbitrary suffixes, prefixes, casing changes, whitespace changes, escapes, encodings, Unicode lookalikes, or embedded matches. New authoring values require a versioned catalog source change and tests.

An authoring token suppresses only the scanner rule declared by its catalog entry. Version 1 authoring entries may declare only `generic-secret-assignment`. Provider-specific credentials, real JWTs, private keys, high-entropy values, adjacent secrets, and any other scanner rule continue to run. Credential-like path findings are independent: a catalog value in `auth.json`, a key file, or another blocked credential path still blocks review.

The same classifier applies to changed base and head blobs, the frozen diff, the complete frozen head, and the rendered prompt. Legacy exemptions are narrower: they never apply to the prompt and do not weaken credential-path checks.

## Catalog Schema

The version 1 root has exactly these fields:

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

Authoring roles are `access`, `refresh`, `id`, `api-key`, and `bearer`. States are `active`, `expired`, and `consumed`. IDs and values must be unique; values may not be equal, prefix-related, or substring-related. The helper also bounds catalog size and entry counts.

A legacy envelope uses this illustrative shape:

```text
{
  "id": "<STABLE_EXEMPTION_ID>",
  "repository": "<CANONICAL_OWNER_AND_REPOSITORY>",
  "verified_master_tip": "<FULL_COMMIT_OID>",
  "match": "non-increasing-global-count",
  "values": [
    {
      "id": "<STABLE_VALUE_ID>",
      "rule": "<GENERIC_OR_GITHUB_TOKEN_RULE>",
      "value_sha256": "<SHA256>",
      "value_length": <EXACT_BYTE_LENGTH>,
      "containing_commit": "<FULL_COMMIT_OID>",
      "source_occurrences": <EXACT_SOURCE_OCCURRENCE_COUNT>
    }
  ]
}
```

The angle-bracket fields above are placeholders, not valid catalog data. Both counts must be positive integers backed by the audit. Legacy entries store a SHA-256 digest and exact byte length instead of duplicating a historical literal in the catalog. Runtime still matches the complete scanner-captured bytes exactly by length and digest. The raw value remains absent from catalog metadata and audit evidence.

`repository`, `containing_commit`, `verified_master_tip`, and `source_occurrences` are admission provenance. They prove why a value may enter the catalog; they are not a runtime repository or fork allowlist.

## Authoring Pool

The public catalog activates a versioned example pool covering:

| Stable ID | Role | State |
| --- | --- | --- |
| `access-a` | access | active |
| `access-b` | access | active |
| `access-expired` | access | expired |
| `refresh-a` | refresh | active |
| `refresh-b` | refresh | active |
| `refresh-consumed` | refresh | consumed |
| `id-a` | id | active |
| `id-b` | id | active |
| `api-key-a` | api-key | active |
| `bearer-a` | bearer | active |

Raw values are intentionally not duplicated in documentation. Use `synthetic-tokens list --json` for authoritative metadata and `synthetic-tokens get <id> --json` for one explicitly selected value. There is no allocator, reservation, release, counter, suffix generator, or bulk raw-value listing.

When authoring a fixture, reuse a project-recorded compatible ID. Otherwise select by role and state, sort compatible metadata by ID, and take the first entry. For `N` distinct credentials, take the first `N` distinct compatible IDs. Insert each selected value unchanged as the complete captured credential value.

## Legacy Exemptions

`--synthetic-secret-exemption <id>` explicitly selects a named helper-owned envelope and remains repeatable. Version 1 legacy entries may suppress only `generic-secret-assignment` or the existing migration need for `github-token`.

For every selected value, the helper scans the complete base tree and complete head tree and compares global occurrence counts. It permits only `head_count <= base_count`:

- unchanged counts pass;
- deletion passes;
- a move or rename with the same total count passes;
- `base_count = 0` with a head occurrence blocks;
- a copy or any net increase blocks.

The rule is global, not path-bound or blob-bound. It allows a historical fixture to move while preventing new use. Unknown IDs, duplicate selections, missing or extra provenance occurrences, malformed entries, count failures, ambiguous digest recovery, overlapping recovered values, and an entirely unused selected envelope fail closed. Multiple values in one envelope are counted independently by complete scanner capture. Review preflight and the pinned master audit transiently recover matched candidates in memory and reject equal, prefix-related, or substring-related legacy values without writing the raw bytes to evidence.

Selection never turns a legacy value into an authoring token. The value remains scanned outside the selected, count-proven review context; prompt occurrences always block. Credential-like paths and unrelated secrets in the same file remain blocking.

## Read-Only CLI

The helper exposes:

```bash
isolated_review synthetic-tokens validate
isolated_review synthetic-tokens list --json
isolated_review synthetic-tokens get <id> --json
isolated_review synthetic-tokens list-exemptions --json
isolated_review synthetic-tokens audit-master \
  --repo <path> \
  --ref <full-master-tip> \
  --exemption <id>
```

`list` returns authoring metadata only. `get` returns the raw value for exactly one selected authoring ID. `list-exemptions` exposes IDs, provenance, rules, digests, lengths, and counts without raw legacy values. `audit-master` verifies the catalog admission evidence against a local repository and pinned ref; it does not mutate either the repository or catalog.

## Preflight Evidence

Successful preflight evidence is bounded by entry count and serialized size. Accepted authoring findings record the catalog schema and pool version, stable token ID, scanner rule, path, side or surface, digest, and occurrence count. Selected legacy evidence additionally records the exemption ID plus base and head counts. Raw authoring and legacy values are never written to preflight evidence.

Evidence is audit data, not a reusable allowlist. A later scan must load and validate the active fixed catalog again.

## Private Catalog Replacement

Downstream users may replace the fixed catalog as part of a trusted installation or release build. Replacement must be wholesale, not a union with the public catalog. Keep the same schema and fixed target path, preserve strict validation, add a new pool version for value changes, and run the complete scanner and catalog tests.

Do not read a replacement from the reviewed repository, caller arguments, environment variables, or project instructions. A release overlay should copy the complete public skill first, replace only the predeclared catalog target with a regular file, reject symlinks and path traversal, validate the generated skill, and verify that generated catalog bytes equal the trusted replacement source. The private source override should not itself ship in the release archive.

## Migration Procedure

1. Classify the value. New and pull-request-only fixtures must switch to the authoring pool; they are never legacy candidates.
2. For a historical candidate, verify an exact occurrence on canonical master and pin the containing commit plus the master tip inspected.
3. Record a stable value ID, declared scanner rule, exact byte length, SHA-256 digest, and source occurrence count. Do not add the raw value to documentation.
4. Add it to one named envelope and run `synthetic-tokens audit-master` against the pinned master tip.
5. Review with the explicit `--synthetic-secret-exemption <id>` selection and confirm bounded preflight evidence contains only IDs, digests, and counts.
6. Migrate fixtures to authoring IDs over time. Delete the legacy entry once no supported review range needs it.

If a branch-only value has already been published, replace it in the repository task. Clean published branch history only after explicit user authorization; never broaden helper policy to avoid that repository-local migration.
