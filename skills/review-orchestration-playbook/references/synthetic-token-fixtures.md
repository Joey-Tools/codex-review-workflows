# Synthetic Token Fixtures

## Contents

- [Authority And Threat Model](#authority-and-threat-model)
- [Catalog Schema](#catalog-schema)
- [Authoring Pool](#authoring-pool)
- [Legacy Exemptions](#legacy-exemptions)
- [Relationship to Dynamic Secret Reduction](#relationship-to-dynamic-secret-reduction)
- [Read-Only CLI](#read-only-cli)
- [Preflight Evidence](#preflight-evidence)
- [Trusted Catalog Customization and Replacement](#trusted-catalog-customization-and-replacement)
- [Migration Procedure](#migration-procedure)

## Authority And Threat Model

The fixed helper-relative `scripts/review_runtime/synthetic-token-catalog.json` is the sole machine-readable enforcement authority. Runtime code does not accept a catalog path, environment override, reviewed-repository configuration, project instruction, or dynamic merge. The helper loads the file without following symlinks, requires an owner-matching single-link regular file, enforces a byte limit, parses strict JSON, and fails closed on malformed or ambiguous entries.

The facility is intentionally finite and exact. It is not a regex namespace and does not accept arbitrary suffixes, prefixes, casing changes, whitespace changes, escapes, encodings, Unicode lookalikes, or embedded matches. New authoring values require a versioned catalog source change and tests.

An authoring token suppresses only the scanner rule declared by its catalog entry. Version 1 authoring entries may declare only `generic-secret-assignment`. Provider-specific credentials, real JWTs, private keys, high-entropy values, adjacent secrets, and any other scanner rule continue to run. Credential-like path findings are independent: a catalog value in `auth.json`, a key file, or another blocked credential path still blocks when that sensitive path remains at head.

Acceptance also requires an unambiguous complete right-hand side. The language-agnostic scanner inspects only a bounded continuation window across whitespace, comments, closers, commas, and line boundaries. Quoted values are preferred. An unquoted value accepts only an unambiguous line end or end of input; format-dependent inline `#` and `;` suffixes fail closed. A quote, backslash, backtick, parameter expansion, or any other non-terminating byte immediately after an unquoted candidate is a blocking continuation rather than an invisible scanner gap. After an unquoted line end, blank and full-line-comment trivia may be skipped, but the next content must be a same-or-shallower named assignment, mapping key, document marker, or diff metadata boundary. More-indented YAML/INI plain-scalar content, operator continuation, tabs, unknown identifiers, excessive trivia, or incomplete continuation blocks. Quoted values likewise require explicit termination or a structurally clear next statement. Prefer structured fixture fields or explicit complete statements. If ordinary code immediately after an assignment is ambiguous, restructure the fixture instead of weakening the scanner.

The same classifier applies to changed base and head blobs and the complete frozen head. The frozen diff, necessary tracked context, and rendered prompt are intentionally integrity-bound but are not rescanned or redacted after the tracked range passes the reduction gate. Those bytes are trusted reviewer input outside catalog admission and tracked-tree reduction counting and require no additional prompt-secret authorization; this does not weaken credential-path or complete-head checks. PR/master admission remains the primary secret-introduction control.

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

Authoring roles are `access`, `refresh`, `id`, `api-key`, and `bearer`. States are `active`, `expired`, and `consumed`. IDs and values must be unique; values may not be equal, prefix-related, or substring-related. An authoring value also may not occur inside any public catalog metadata field, including token IDs, the pool version, or legacy provenance; this ensures metadata-only CLI output and preflight evidence contain no authoring value literals. Values use only the scanner-compatible ASCII byte set `A-Z`, `a-z`, `0-9`, and `-_./+=!@#$%^&*?~:;`. On every CLI or preflight load, the helper runs each entry through the real scanner in canonical quoted and unquoted assignments and requires exactly one acceptance under its declared rule. The helper also bounds catalog size and entry counts.

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
      "rule": "<GENERIC_OR_PROVIDER_RULE>",
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

`--synthetic-secret-exemption <id>` explicitly selects a named helper-owned envelope and remains repeatable. Version 1 legacy entries may suppress only `generic-secret-assignment` or the exact provider-specific `github-token` rule needed by a master-proven migration envelope. JWT findings are never eligible for a legacy exemption.

For every selected value, the helper counts exact raw-byte occurrences across every blob in the complete base tree and complete head tree, including ordinary text, comments, symlink targets, and binary content. This counter is independent of scanner suppression events and continues even after another scanner rule blocks the surface. It permits only `head_count <= base_count`:

- unchanged counts pass;
- deletion passes;
- a move or rename with the same total count passes;
- `base_count = 0` with a head occurrence blocks;
- a copy or any net increase blocks.

The helper also records an unembedded count: an exact occurrence is unembedded only when no strictly longer value in the same selected envelope completely contains it. Both raw and unembedded counts must be monotonic. This prevents deleting a longer registered value and reusing one of its registered substrings as a new standalone value, even in plain text or binary content.

The rule is global, not path-bound or blob-bound. It allows a historical fixture to move while preventing new use. Unknown IDs, duplicate selections, duplicate exact values, any authoring-related or cross-envelope value overlap, malformed entries, count failures, and an entirely unused selected envelope fail closed. Historical master can contain one legacy exact value inside another, so legacy-only substring relationships are allowed only inside one envelope; every descriptor is counted independently at every start position. Complete scanner-captured equality still selects only the declared exact descriptor. Prepare keeps catalog-legacy count evidence containing only IDs, digests, and counts in helper-private container state outside the reviewer workspace. The stateful runner requires the workspace manifest to match that evidence, reloads the same fixed catalog, and recomputes both materialized-head counts before egress; catalog legacy raw values are never copied into helper state. The separate dynamic-reduction path may retain canonical Base64 candidate bytes only in helper-private container state so exact unknown values can be reconstructed across stateful execution; reviewer-visible control evidence remains literal-free. Preflight removes this raw-bearing manifest through its preparation-time descriptor identity and records a bound per-file removal receipt before publishing success or launching a reviewer. Validation failure and later cleanup retry the same operation; a missing, moved, or replaced inode without its receipt fails closed.

The monotonic counters cover blob bytes and symlink targets, not Git path names. Every raw legacy value and its canonical Base64 catalog storage encoding is instead forbidden as a byte substring of any base or head repository path, whether or not its envelope was selected. The helper checks raw NUL-delimited Git paths before decoding or displaying them with a finite linear matcher under the existing tree metadata and entry limits. Stateful revalidation applies the same deny rule to materialized snapshot paths. Ordinary content can still move or rename between safe paths when its counts remain monotonic; a legacy value or storage encoding may never be moved, copied, or embedded into a filename or directory component.

Selection never turns a legacy value into an authoring token. The value remains scanned outside the selected, count-proven tracked-tree context. Prompt bytes remain outside catalog acceptance and reduction proof entirely: they are size- and integrity-bound trusted reviewer input, not a secret-egress filter. Credential-like paths that remain at head and unrelated tracked-tree findings outside an eligible reduction remain blocking.

## Relationship to Dynamic Secret Reduction

The automatic reduction gate for an unregistered dynamic secret is separate from this catalog. It may pass only when complete-tree exact counting proves `head_raw_count < base_raw_count` and `head_unembedded_count <= base_unembedded_count`. Occurrence provenance (the base location from which a residual head occurrence is allowed to survive) additionally requires every raw and unembedded head occurrence to match a base occurrence at the same raw Git path, normalized `blob` or `symlink-target` surface, and absolute byte offset. Regular `100644` and `100755` modes are the same `blob` surface; a transition to or from a symlink target is not. Equality, additions, moves/renames, copies, new offsets, surface transitions, net growth, substring extraction, incomplete counts or provenance, and unsafe or uncountable candidates fail closed. A dynamic candidate that equals or contains either a raw value or its canonical Base64 storage encoding from an unselected legacy envelope is not eligible for automatic reduction and requires explicit `--synthetic-secret-exemption` selection. A complete generic literal RHS remains an exact candidate when it is enclosed by balanced wrappers or triple quotes, including embedded newlines. A single- or double-quoted value may contain the opposite quote and still forms one exact identity; provider-shaped substrings do not truncate it. Any closer consumed before the candidate literal permanently invalidates the wrapper-only prefix, including when a later opener appears. Unsupported, unclosed, oversized, backtick, or ambiguous forms remain blocking. A complete provider-specific span inside a secret-key assignment does not erase the longer generic identity: the scanner proves the bounded logical right-hand side across quoting, escaping, type-aware last-in-first-out wrapper matching, expressions, comments, stream frontiers, and diff record sides, and deduplicates only an exact candidate. Missing, crossed, mismatched, extra, or externally unclosed wrappers block once the suffix is complete; a structurally valid partial wrapper remains incomplete until the next stream window can prove its suffix. Secondary RHS discovery retains an OPEN (not yet proven complete) or unknown assignment before a provider is visible and releases only a CLOSED (proven complete) RHS. Its absolute per-assignment proof cap covers the candidate, delimiters, trailing bytes, wrappers, and external source context used by that decision; incremental line and diff-context accounting keeps repeated prefixes linear or fail-closed within budget. The candidate's exact raw value and canonical Base64 encoding are also forbidden in every frozen or materialized head path. Public manifest schema version 4 exposes only fixed-size base/head provenance commitments; raw paths, offsets, occurrence identities, and candidate bytes are not published. The stateful runner recomputes the materialized head identities and requires the exact head commitment before egress. A base-only path removed by the range may remain in the trusted raw diff. Complete changed-path evidence commits to both head-present (`H`) and base-only (`B`) records through ordered, domain-separated digests, while the side-tagged raw records remain helper-private. Validation applies the freshly loaded complete-catalog legacy matcher to both sides and applies dynamic or sensitive-path checks only to `H`, so an unregistered pure deletion remains reviewable. Once that gate passes, the trusted reviewer receives the frozen tracked diff and necessary tracked context in their original form without secret scanning or redaction.

This does not change catalog behavior. Authoring entries retain their exact declared-rule acceptance semantics. Explicitly selected legacy envelopes retain their existing non-increasing raw and unembedded count rules, including the documented ability for an equal-count historical value to move between safe paths. Dynamic reduction is not a way to mint an authoring token, bypass catalog validation, select a legacy envelope implicitly, or weaken credential-path checks. PR/master protection remains the primary defense against introducing new secret material; the dynamic gate exists so a remediation range that provably removes occurrences can still receive review.

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

`list` returns authoring metadata only. `get` returns the raw value for exactly one selected authoring ID. `list-exemptions` exposes IDs, provenance, rules, digests, lengths, and counts without raw legacy values. `audit-master` verifies all exact raw-byte occurrences at each provenance commit and requires at least one occurrence eligible under the declared scanner rule; it does not mutate either the repository or catalog. Provenance auditing exhaustively collects bounded scanner events so an unrelated earlier finding cannot hide a later eligible capture. If an earlier stream window already committed a blocker and the retained suffix no longer has external prefix context, audit may count only an exact catalog legacy assignment whose bounded local RHS is complete; the original generic blocker remains, and this capture-only path never applies to authoring tokens, dynamic reductions, or ordinary preflight. This does not certify the tree as finding-free: ordinary preflight remains fail-fast, and every unrelated or non-exempt finding still blocks review.

## Preflight Evidence

Successful preflight evidence is bounded by entry count and serialized size, with the entry budget enforced before each new evidence key is inserted. Accepted authoring findings record the catalog schema and pool version, stable token ID, scanner rule, path, side or surface, digest, and occurrence count. Selected legacy evidence additionally records the exemption ID plus base/head raw and unembedded counts. Before writing evidence, the helper checks every string field, including dynamic path digests and the frozen review range, against every authoring value plus every selected or unselected legacy raw/storage value in the complete catalog. Raw authoring and legacy values are never written to preflight evidence.

The reviewer-visible synthetic manifest, changed-path digest, changed-blob finding, accepted-evidence, diff, and prompt artifacts are created as owner-only `0600` files independently of the caller's permissive umask and are bound by exact name, byte size, SHA-256 digest, and, for NUL-delimited files, record count to helper-private state that contains no catalog token literals. Complete changed paths are represented publicly only by ordered, side-bound SHA-256 commitments; their side-tagged raw byte records are held in one ephemeral helper-private `0600` file and verified lockstep against the public commitments. Changed-blob findings also use path digests. All public evidence strings, including path commitments and artifact digests, are checked against authoring, legacy raw/storage, and dynamic reduction values before publication. Runtime validation repeats that check for every verified changed-path and changed-blob path digest against the freshly reloaded complete catalog plus dynamic reduction values before egress. The complete prospective retained `preflight.json`, including its final `private_artifacts: removed` field, is assembled through the same builder used for publication and receives that check before the private artifacts are removed. The state also binds the `.codex-review` directory identity, non-group/other-writable mode, stable metadata, entry-set digest, and every file's name/size/digest/record evidence. Stateful preflight rejects any extra regular file, nested directory, symlink, or FIFO, then consumes each fixed public artifact and the private raw-path file through no-follow, nonblocking, owner-matching regular-file descriptors, applies byte and record limits, verifies stable metadata, and requires matching order, digest, count, and EOF. Preparation precreates both raw-bearing files as empty exact-`0600` slots, captures their identities from the creation descriptors, syncs both files and the container directory, and then publishes one canonical source-root-bound schema-v3 `preparing` marker carrying the complete identity set before workspace materialization or any helper-private secret byte. Payload writers reopen only those same inodes with no-follow and nonblocking flags, without create or truncate, and revalidate file/path identity after the synced write. A crash before the marker can therefore leave only empty slots, while every secret-bearing partial write has durable recovery identities. The review workspace, state marker, and control state carry the immutable binding; preflight requires them to agree with the current objects. Cleanup moves each bound fixed file to quarantine, revalidates the original identity, removes it, and persists that file's monotonic removal receipt relative to the same open container descriptor before proceeding. Failed validation and every later cleanup path retry both identities, including partial preparation, explicit keep, fallback retention, workspace layout-validation failure during cleanup, a retained surrounding state container, an already-missing workspace, or workspace-tree removal error. Missing or replacement objects without a receipt fail closed and are preserved, while a failure for one identity does not skip the other. Explicit cleanup after state/layout corruption requires the independent state-marker binding and matching control state from the resolved marked directory while the runner lock is free and the cleanup lock is held; it continues to report the corruption. A crash after unlink but before receipt persistence is deliberately ambiguous and fails closed on retry. Clearing a deleted-path finding, swapping a control file, changing a path side or commitment, or changing the manifest, diff, or prompt therefore fails closed.

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
