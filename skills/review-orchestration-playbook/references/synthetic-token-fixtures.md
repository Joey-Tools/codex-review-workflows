# Synthetic Token Fixtures

## Contents

- [Authority And Threat Model](#authority-and-threat-model)
- [Catalog Schema](#catalog-schema)
- [Authoring Pool](#authoring-pool)
- [Legacy Exemptions](#legacy-exemptions)
- [Read-Only CLI](#read-only-cli)
- [Preflight Evidence](#preflight-evidence)
- [Trusted Catalog Customization and Replacement](#trusted-catalog-customization-and-replacement)
- [Migration Procedure](#migration-procedure)

## Authority And Threat Model

The fixed helper-relative `scripts/review_runtime/synthetic-token-catalog.json` is the sole machine-readable enforcement authority. Runtime code does not accept a catalog path, environment override, reviewed-repository configuration, project instruction, or dynamic merge. The helper loads the file without following symlinks, requires an owner-matching single-link regular file, enforces a byte limit, parses strict JSON, and fails closed on malformed or ambiguous entries.

The facility is intentionally finite and exact. It is not a regex namespace and does not accept arbitrary suffixes, prefixes, casing changes, whitespace changes, escapes, encodings, Unicode lookalikes, or embedded matches. New authoring values require a versioned catalog source change and tests.

An authoring token suppresses only the scanner rule declared by its catalog entry. Version 1 authoring entries may declare only `generic-secret-assignment`. Provider-specific credentials, real JWTs, private keys, high-entropy values, adjacent secrets, and any other scanner rule continue to run. Credential-like path findings are independent: a catalog value in `auth.json`, a key file, or another blocked credential path still blocks review.

Acceptance also requires an unambiguous complete right-hand side. The language-agnostic scanner inspects only a bounded continuation window across whitespace, comments, closers, commas, and line boundaries. Quoted values are preferred. An unquoted value accepts only an unambiguous line end or end of input; format-dependent inline `#` and `;` suffixes fail closed. A quote, backslash, backtick, parameter expansion, or any other non-terminating byte immediately after an unquoted candidate is a blocking continuation rather than an invisible scanner gap. After an unquoted line end, blank and full-line-comment trivia may be skipped, but the next content must be a same-or-shallower named assignment, mapping key, document marker, or diff metadata boundary. More-indented YAML/INI plain-scalar content, operator continuation, tabs, unknown identifiers, excessive trivia, or incomplete continuation blocks. Quoted values likewise require explicit termination or a structurally clear next statement. Prefer structured fixture fields or explicit complete statements. If ordinary code immediately after an assignment is ambiguous, restructure the fixture instead of weakening the scanner.

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

Authoring roles are `access`, `refresh`, `id`, `api-key`, and `bearer`. States are `active`, `expired`, and `consumed`. IDs and values must be unique; values may not be equal, prefix-related, or substring-related. An authoring value also may not occur inside any public catalog metadata field, including token IDs, the pool version, or legacy provenance; this keeps metadata-only CLI output and preflight evidence structurally raw-free. Values use only the scanner-compatible ASCII byte set `A-Z`, `a-z`, `0-9`, and `-_./+=!@#$%^&*?~:;`. On every CLI or preflight load, the helper runs each entry through the real scanner in canonical quoted and unquoted assignments and requires exactly one acceptance under its declared rule. The helper also bounds catalog size and entry counts.

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
      "value_base64": "<CANONICAL_BASE64_OF_EXACT_ASCII_VALUE>",
      "containing_commit": "<FULL_COMMIT_OID>",
      "source_occurrences": <EXACT_SOURCE_OCCURRENCE_COUNT>
    }
  ]
}
```

The angle-bracket fields above are placeholders, not valid catalog data. Counts must be positive integers backed by the audit. The fixed helper-owned catalog stores each legacy value as strict canonical Base64 and decodes it in memory as the exact ASCII runtime authority, avoiding a raw-literal bootstrap exception when the helper's own private catalog is reviewed. The encoded form is storage only: it is never accepted as a token value and may not overlap any authoring value or public metadata. Metadata-only CLI output, manifests, and audit/preflight evidence expose only the derived SHA-256 digest, byte length, IDs, and counts; they never serialize the raw value or the storage encoding.

Authoring values use the scanner-compatible restricted byte class so new fixtures remain portable and predictable. Legacy values are a separate migration boundary: canonical Base64 must decode to exactly 16–512 printable ASCII bytes (`0x20` through `0x7e`) without single- or double-quote delimiters. This permits an already-published quoted scanner capture to contain spaces or other punctuation without turning those characters into an authoring namespace. Control bytes, newlines, non-ASCII text, quote delimiters, alternate encodings, and regex forms fail closed. Runtime suppression and `audit-master` still require the complete decoded value to match the declared scanner rule exactly.

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

For every selected value, the helper counts exact raw-byte occurrences across every blob in the complete base tree and complete head tree, including ordinary text, comments, symlink targets, and binary content. This counter is independent of scanner suppression events and continues even after another scanner rule blocks the surface. It permits only `head_count <= base_count`:

- unchanged counts pass;
- deletion passes;
- a move or rename with the same total count passes;
- `base_count = 0` with a head occurrence blocks;
- a copy or any net increase blocks.

The helper also records an unembedded count: an exact occurrence is unembedded only when no strictly longer value in the same selected envelope completely contains it. Both raw and unembedded counts must be monotonic. This prevents deleting a longer registered value and reusing one of its registered substrings as a new standalone value, even in plain text or binary content.

The rule is global, not path-bound or blob-bound. It allows a historical fixture to move while preventing new use. Unknown IDs, duplicate selections, duplicate exact values, any authoring-related or cross-envelope value overlap, malformed entries, count failures, and an entirely unused selected envelope fail closed. Historical master can contain one legacy exact value inside another, so legacy-only substring relationships are allowed only inside one envelope; every descriptor is counted independently at every start position. Complete scanner-captured equality still selects only the declared exact descriptor. Prepare keeps a raw-free authoritative count copy in helper-private container state outside the reviewer workspace. The stateful runner requires the workspace manifest to match that copy, reloads the same fixed catalog, and recomputes both materialized-head counts before egress; raw values are never copied into workspace control files or helper-private state.

The monotonic counters cover blob bytes and symlink targets, not Git path names. Every raw legacy value and its canonical Base64 catalog storage encoding is instead forbidden as a byte substring of any base or head repository path, whether or not its envelope was selected. The helper checks raw NUL-delimited Git paths before decoding or displaying them with a finite linear matcher under the existing tree metadata and entry limits. Stateful revalidation applies the same deny rule to materialized snapshot paths. Ordinary content can still move or rename between safe paths when its counts remain monotonic; a legacy value or storage encoding may never be moved, copied, or embedded into a filename or directory component.

Selection never turns a legacy value into an authoring token. The value remains scanned outside the selected, count-proven review context; legacy exemptions never apply to prompts, so any resulting prompt scanner finding blocks. Credential-like paths and unrelated secrets in the same file remain blocking.

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

`list` returns authoring metadata only. `get` returns the raw value for exactly one selected authoring ID. `list-exemptions` exposes IDs, provenance, rules, digests, lengths, and counts without raw legacy values. `audit-master` verifies all exact raw-byte occurrences at each provenance commit and requires at least one occurrence eligible under the declared scanner rule; it does not mutate either the repository or catalog. Provenance auditing exhaustively collects bounded scanner events so an unrelated earlier finding cannot hide a later eligible capture. This does not certify the tree as finding-free: ordinary preflight remains fail-fast, and every unrelated or non-exempt finding still blocks review.

## Preflight Evidence

Successful preflight evidence is bounded by entry count and serialized size, with the entry budget enforced before each new evidence key is inserted. Accepted authoring findings record the catalog schema and pool version, stable token ID, scanner rule, path, side or surface, digest, and occurrence count. Selected legacy evidence additionally records the exemption ID plus base/head raw and unembedded counts. Before writing evidence, the helper checks every string field, including dynamic path digests and the frozen review range, against every authoring value plus every selected or unselected legacy raw/storage value in the complete catalog. Raw authoring and legacy values are never written to preflight evidence.

The reviewer-visible synthetic manifest, changed-path, changed-blob, accepted-evidence, diff, and prompt artifacts are created as owner-only `0600` files independently of the caller's permissive umask and are bound to a raw-free helper-private state by exact name, byte size, SHA-256 digest, and, for NUL-delimited files, record count. The state also binds the `.codex-review` directory identity, non-group/other-writable mode, stable metadata, and exact six-entry name-set digest. Stateful preflight rejects any extra regular file, nested directory, symlink, or FIFO, then consumes each fixed artifact through the same no-follow, nonblocking, owner-matching regular-file descriptor it hashes, applies byte and record limits, and verifies stable metadata before egress. Clearing a deleted-path finding, swapping a control file, or changing the manifest, diff, or prompt therefore fails closed.

Evidence is audit data, not a reusable allowlist. A later scan must load and validate the active fixed catalog again.

## Trusted Catalog Customization and Replacement

Downstream users may customize both `authoring_pool` and `legacy_exemptions` by replacing the fixed catalog as part of a trusted installation or release build. Replacement must be wholesale, not a union with the public catalog. Keep the same schema and fixed target path, preserve strict validation, add a new pool version for value changes, and run the complete scanner and catalog tests.

Do not read a replacement from the reviewed repository, caller arguments, environment variables, or project instructions. A release overlay should copy the complete public skill first, replace only the predeclared catalog target with a regular file, reject symlinks and path traversal, validate the generated skill, and verify that generated catalog bytes equal the trusted replacement source. The private source override should not itself ship in the release archive.

## Migration Procedure

1. Classify the value. New and pull-request-only fixtures must switch to the authoring pool; they are never legacy candidates.
2. For a historical candidate, verify an exact occurrence on canonical master and pin the containing commit plus the master tip inspected.
3. Record a stable value ID, declared scanner rule, canonical `value_base64`, and the full-tree raw source occurrence count in the trusted catalog. Byte length and SHA-256 are derived for metadata and evidence. Keep both the raw value and storage encoding out of documentation and evidence.
4. Add it to one named envelope and run `synthetic-tokens audit-master` against the pinned master tip.
5. Review with the explicit `--synthetic-secret-exemption <id>` selection and confirm bounded preflight evidence contains only IDs, digests, and counts.
6. Migrate fixtures to authoring IDs over time. Delete the legacy entry once no supported review range needs it.

If a branch-only value has already been published, replace it in the repository task. Clean published branch history only after explicit user authorization; never broaden helper policy to avoid that repository-local migration.
