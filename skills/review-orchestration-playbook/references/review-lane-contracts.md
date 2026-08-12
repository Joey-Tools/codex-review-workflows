# Review Lane Contracts

This reference owns named-lane eligibility, logical lane counting, inputs, outputs, budgets, and failure behavior. It does not restate GitHub wire schemas; load [github-codex-evidence-authority.md](github-codex-evidence-authority.md) for that lane's evidence semantics and [egress-consent.md](egress-consent.md) for destination consent.

## Canonical Review-Control Manifest

This section owns deterministic review-control identity. Select a previously trusted installed release or frozen prior-policy checkout outside the candidate range. Its `version` is the publisher-provided release identifier or frozen commit ID, never a value derived from candidate-head content.

- Treat the directory that contains both `agents/` and `skills/` as the single bundle root. Resolve every manifest member as one canonical UTF-8 relative path beneath that absolute root, reject empty, absolute, dot-segment, NUL, duplicate, escaping, missing, extra, symlink-leaf, or non-regular entries, and open each member no-follow through its bound parent. Each read binds the ordinary-file `st_mode`, owner, size, descriptor identity, and complete raw bytes; mode/access-policy evidence is recorded and revalidated separately from the byte-manifest digest so the digest algorithm below remains stable.
- Build one canonical UTF-8 manifest over these exact regular, non-symlink record paths relative to that root, sorted by relative-path UTF-8 bytes. Each record is `<lowercase-file-sha256><two ASCII spaces><relative-path><LF>`: `agents/reviewer.toml`; `skills/review-orchestration-playbook/SKILL.md`; `skills/review-orchestration-playbook/references/base-only-retarget-state-machine.json`; `skills/review-orchestration-playbook/references/canonical-claude-lane.md`; `skills/review-orchestration-playbook/references/claude-2.1.212-stream-schema.json`; `skills/review-orchestration-playbook/references/claude-runtime-trust.md`; `skills/review-orchestration-playbook/references/claude-stream-compatibility.json`; `skills/review-orchestration-playbook/references/claude-stream-schema.json`; `skills/review-orchestration-playbook/references/egress-consent.md`; `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`; `skills/review-orchestration-playbook/references/github-codex-review-epoch-state-machine.json`; `skills/review-orchestration-playbook/references/github-pr-probes.md`; `skills/review-orchestration-playbook/references/pr-readiness.md`; `skills/review-orchestration-playbook/references/review-lane-contracts.md`; `skills/review-orchestration-playbook/references/review-prompt-templates.md`; `skills/review-orchestration-playbook/scripts/named_claude_preflight`; `skills/review-orchestration-playbook/scripts/named_lane_guard`; `skills/review-orchestration-playbook/scripts/review_runtime/__init__.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_capabilities.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_code_release.asc`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_linux.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_provenance.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_refresh_lock.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_stream_contract.py`; `skills/review-orchestration-playbook/scripts/review_runtime/claude_version_policy.py`; `skills/review-orchestration-playbook/scripts/review_runtime/common.py`; `skills/review-orchestration-playbook/scripts/review_runtime/fd_exec.py`; `skills/review-orchestration-playbook/scripts/review_runtime/named_claude_preflight.py`; `skills/review-orchestration-playbook/scripts/review_runtime/named_lane.py`; `skills/review-orchestration-playbook/scripts/review_runtime/review_result.py`; and `skills/review-orchestration-playbook/scripts/validate_claude_stream.py`. The recorded bundle SHA-256 is the lowercase SHA-256 of those complete manifest bytes.
- Treat the Python interpreter as separate trusted control-plane material. Resolve an absolute real Python `>=3.10` outside the candidate worktree to an ordinary non-symlink native executable whose file and ancestor chain are root- or current-user-owned and not group/world writable; reject a script, shim, relative path, unsafe ancestor, or identity drift. Record its absolute path, version, SHA-256, and `(st_dev, st_ino, st_mode, st_uid)` identity, and revalidate those fields immediately before every guard use and after each lane. The `named_lane_guard` file is source-only mode `0644` with no shebang and must never be executed directly. Launch it through direct argv as `<trusted-python-absolute-path> -I -B -S <trusted-bundle-absolute-path>/skills/review-orchestration-playbook/scripts/named_lane_guard ...` with an explicit clean environment: fixed trusted `PATH`, fixed locale, and only explicitly recorded locale/UI/proxy/CA values required by the lane plus the separately validated `NODE_EXTRA_CA_CERTS` opt-in. Do not inherit ambient `HOME`. For `preflight-claude`, the guard instead resolves the current POSIX account through `pwd.getpwuid(os.getuid())`, requires its matching UID and nonempty absolute home to resolve to an accessible directory, and binds that canonical path directly into the preflight consumer; this establishes the candidate-search root without treating directory `mtime`, `ctime`, or child churn as account-home identity. `-S` is mandatory so global site-packages, `.pth` processing, and `sitecustomize` cannot run before the guard; `-I` alone is insufficient. Omit every `PYTHON*`, `LD_*`, `DYLD_*`, virtualenv/Conda/pyenv, shell-startup, and unrelated tool-control variable. The parent process launcher must supply that environment rather than inheriting an ambient shell or repository environment. Every shorter guard spelling elsewhere in this skill is only an argv-tail placeholder for this exact launcher tuple.
- The default guard code-origin/import boundary is an exact four-source bound-source raw loader over `review_runtime`, `review_runtime.common`, `review_runtime.claude_version_policy`, and `review_runtime.named_lane`, with exact `review_runtime/fd_exec.py` companion bytes injected as `review_runtime.common.FD_EXEC_BYTES`. It adds no bundle path to ordinary import resolution and accepts no bytecode, native extension, or same-name substitute.
- `preflight-claude` has the exact nine-source closure `review_runtime`, `review_runtime.common`, `review_runtime.claude_refresh_lock`, `review_runtime.claude_linux`, `review_runtime.claude_version_policy`, `review_runtime.claude_capabilities`, `review_runtime.claude_provenance`, `review_runtime.claude_stream_contract`, and `review_runtime.named_claude_preflight`. Its exact companions are `review_runtime/claude_code_release.asc`, `references/claude-stream-compatibility.json`, `references/claude-2.1.212-stream-schema.json`, `references/claude-stream-schema.json`, the same manifest-bound `review_runtime/claude_capabilities.py` bytes, and `review_runtime/fd_exec.py`.
- `validate-claude-stream` has the exact nine-source closure `review_runtime`, `review_runtime.common`, `review_runtime.claude_refresh_lock`, `review_runtime.claude_linux`, `review_runtime.claude_version_policy`, `review_runtime.claude_capabilities`, `review_runtime.claude_provenance`, `review_runtime.claude_stream_contract`, and the standalone `validate_claude_stream` module. Its exact companions are `references/claude-stream-compatibility.json`, `references/claude-2.1.212-stream-schema.json`, `references/claude-stream-schema.json`, and the same manifest-bound `review_runtime/claude_capabilities.py` bytes.
- `classify-review-result` has the exact two-source closure `review_runtime` and `review_runtime.review_result`; the classifier source itself is the exact companion re-read immediately before the already loaded `main` executes. None of the profiles may widen into `review_runtime.workspace`, `review_runtime.prompt`, or `review_runtime.synthetic_tokens`. [Canonical Claude Code Lane](canonical-claude-lane.md#canonical-claude-code-lane) owns the detailed source-to-module and companion-to-binding names for these three formal Claude profiles; this manifest section owns which exact bytes are eligible.
- Initially bind every source and companion through a bounded no-follow regular-file read, retain those exact immutable bytes, and give the same buffers to the consumer. Immediately before consumer entry and after each lane, repeat complete bounded no-follow reads and recompute the full manifest. Compare complete bytes and protected mode/access evidence; do not replace full-byte validation with size, timestamps, or a digest supplied by the candidate. A same-content ordinary-file replacement between complete reads is harmless only when the path, type, mode, owner, and access policy remain admitted; any byte or policy drift is inconclusive. Consumers must not reopen a companion path after final validation.
- Candidate-head Python, shell, machine schemas, wrappers, manifests, or same-name files are review subject only and never control-plane input. Neither formal profile may use the candidate wrapper, ordinary bundle-path import resolution, a candidate-head source/schema, or a path re-read in place of the bound bytes. Verify the manifest and interpreter evidence immediately before each guard, Claude preflight, stream-validator, Claude-launch, and Codex-spawn use. Recompute it after each lane; failure to bind the active trusted profile is `blocked-safety`, not permission to fall back to candidate control files.

## Legacy Short-Prefix Receipt Producer

The only formal producer for parent-trusted local Git receipts that resolve
raw, non-current legacy 10-hex clean markers is the default-profile guard
subcommand `legacy-short-prefix-receipts`. It is parsed and dispatched by the
manifest-bound `review_runtime.named_lane` source already present in the
default exact four-source closure; it does not create another profile or add
an unmanifested runtime source. Invoke it only through the recorded trusted
Python and bundle launcher described above. A private workspace helper never
supplies receipt evidence. A direct import never satisfies this contract.
Neither counts as receipt authority. An ad hoc query reimplementation or a
source-Git-directory query also never counts. The manifest-bound runtime
declares the exact literal
`LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION = "named-lane-legacy-short-prefix-receipts-v1"`;
changing either side is a schema migration, not a compatible implementation
detail.

Use this exact argv shape under the fixed clean parent environment. Repeat
`--prefix` once for every unique raw-derived non-current lowercase 10-hex
prefix; zero or more are accepted:

```sh
<trusted-python-absolute-path> -I -B -S \
  <trusted-bundle-absolute-path>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  legacy-short-prefix-receipts \
  --source <absolute-exact-worktree-root> \
  --temporary-path <absolute-phase-unique-absent-child-under-owner-private-0700-parent> \
  --head <current-lowercase-full-object-id> \
  --phase initial \
  --prefix <lowercase-10-hex> \
  [--prefix <another-lowercase-10-hex> ...]
```

For the final pass, use `--phase final` and a different phase-unique absent
`--temporary-path`; do not delete and reuse the initial pathname as evidence
of an independently created view. The source is the exact worktree root, not
its `.git` path. `head` is the exact lowercase full-width commit object ID for
the repository format. Prefixes must be unique, and a prefix equal to the
first 10 hex of `head` is semantic `inconclusive`: current-head short cleans
belong only to the independent dual REST resolution path. When the complete
derived set is empty, omit `--prefix`; the producer still performs the full
source/head/view validation and cleanup and succeeds only with `receipts: []`.

Before any receipt query, the producer applies the materializer's source
repository trust boundary: bind the exact worktree root, `.git` marker,
resolved admin/common/object directories, linked-worktree forward target and
back-pointer, object format, owner, type, device/inode identity, and relevant
access policy through bounded no-follow control-file reads and repeated
storage revalidation. Object identity is `(st_dev, st_ino, file type, st_uid)`;
access policy is separate and rejects group/world-writable (`0o022`) source
worktree and `.git` marker parents, bound admin/common/object directories, and
relevant config/back-pointer files. Descriptor-relative custody revalidation
walks complete root-to-leaf chains for the source worktree, admin, common, and
objects directories and for the temporary parent. On Darwin, each custody
ancestor accepts only an empty or deny-only extended ACL; any allow entry or
unknown/uninspectable ACL is `blocked-safety`. A root-owned sticky custody
ancestor is the only group/world-writable special case; every bound source,
object-store, temporary-parent, control, or view leaf remains current-user-owned
and rejects every extended ACL. Mode bits and ACL state are separate
access-policy signals.
The source object-store policy inventory streams one entry at a time, increments
and checks
`LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT = MATERIALIZER_OBJECT_COUNT_LIMIT`
before metadata inspection or requesting another entry, and checks the same
phase-global receipt deadline before each directory and every 256 entries
without resetting it. Limit exhaustion, deadline expiry, or
incomplete inventory inspection is `blocked-safety`. These point revalidations
are point-in-time observations and do not claim continuous atomicity. Benign
`mtime`, `ctime`, `nlink`, or
object-directory child-entry churn alone is not mutation of either protected
property. Reject suffix-DWIM or replaced control paths,
`objects/info/alternates`, `objects/info/http-alternates`, common/admin shallow
state including per-worktree shallow state, promisor/partial-clone config or
pack markers, source pack bitmaps, an unsafe or ambiguous object directory,
and missing or incomplete local objects. Source configuration is inspected
only as a bounded direct no-include byte stream for the required object-format
and hostile-state checks; Git never loads source config, refs, hooks, remotes,
worktree state, or a source Git directory.

Range-scoped named-lane materialization does not alter this producer's
full-head reachable-object preflight or source-store inventory budget.
`LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT` remains the unchanged 250,000-object
materializer count limit; the separate 768 MiB exact-range pack ceiling grants
no additional legacy-prefix inventory, query, output, or deadline budget.

Create a minimal bare control view only at the exact absent temporary leaf.
It has owner-private control/config roots; empty refs, remotes, hooks, and
worktree state; no `info/grafts`, shallow file, replace ref, alternate, HTTP
alternate, or promisor dependency; and it exposes only the validated source
object directory through the fixed object-directory environment. Rebuild the
Git environment from the fixed allowlist, disable lazy fetch and prompting,
set `GIT_NO_REPLACE_OBJECTS=1`, isolate system/global configuration, and force
`core.commitGraph=false` plus `core.multiPackIndex=false` on every command.
This protects object type and ancestry from local grafts, replace refs,
shallow boundaries, ambient config, commit-graph data, and multi-pack-index
consumption without claiming that source object-store child churn is itself a
mutation. The producer does not materialize or snapshot the entire object
store. Source container identity/access policy and full-OID/type/ancestry
ordered point-query semantics are protected; continuous stability of selected
loose-object or pack bytes is not.
The exact owner-only mode-`0700` temporary/view root protects identity and
access policy, while bounded exact generated-view config and `HEAD` bytes
protect those control files' content stability. Revalidate each protected
property independently rather than treating a timestamp delta as proof that
object semantics changed. Same-current-UID concurrent object-store content
mutation, prefix-inventory churn, and intra-phase or inter-phase ABA are not
excluded. Initial/final equality is two point-in-time observations, not
atomicity.

After that non-receipt setup, run these bounded phase-level control preflights
against the same invocation-local view, in order:

```sh
git cat-file -t <head>
git rev-list --objects --missing=error --quiet <head> --
```

Require the first command to return `0` with exactly `commit` and LF, proving
the full head's exact object type. Require the second to return `0` without
unexpected output, proving the view contains the head's complete reachable
object closure. Both run even for a zero-prefix phase. Neither creates a
receipt field or counts as a per-prefix receipt query. After both phase-level
preflights pass, run exactly these three bounded read-only receipt queries, in
this order, for each sorted prefix against that same view:

```sh
git rev-parse --disambiguate=<raw_prefix>
git cat-file -t <sole_full_object_id>
git merge-base --is-ancestor <sole_full_object_id> <head>
```

The first command must return `0` and exactly one well-formed lowercase full
object ID of the repository's hash width that begins with `raw_prefix`. The
second is an exact-object, non-peeling type check and must return `0` with the
single ASCII line `commit` plus LF. The third must return `0`. A zero/multiple
or malformed disambiguation, a tag or other non-commit object, a non-ancestor,
the current-head prefix, unexpected stdout/stderr, timeout, output overflow,
process/drain uncertainty, source revalidation failure, or any other
near-miss produces no usable receipt. A complete zero/multiple-OID stdout is a
semantic rejection, but an output-limit exception does not identify whether
stdout or stderr overflowed and is therefore `blocked-safety`, never evidence
of ambiguity. Query count and aggregate subprocess output are capped; Git
subprocesses share the 120-second monotonic phase deadline and bounded process
cleanup. Synchronous filesystem identity/access-policy revalidation is
fail-closed but is not an interruptible wall-clock guarantee: a stalled
filesystem can exceed the subprocess deadline and supplies no receipt. At
most the phase's fixed temporary view and control path can require retained
cleanup evidence.

Success is a closed JSON object with exactly these top-level fields and this
schema version:

```json
{
  "status": "ok",
  "schema_version": "named-lane-legacy-short-prefix-receipts-v1",
  "phase": "initial",
  "head": "<current-lowercase-full-object-id>",
  "temporary_cleanup_status": "complete",
  "receipts": [
    {
      "raw_prefix": "<lowercase-10-hex>",
      "head": "<current-lowercase-full-object-id>",
      "disambiguate_return_code": 0,
      "disambiguated_object_ids": ["<sole-full-object-id>"],
      "commit_object_check_return_code": 0,
      "object_type": "commit",
      "ancestry_return_code": 0
    }
  ]
}
```

`receipts` is unique and sorted by `raw_prefix`; each item has exactly the
seven fields shown. The producer is success-only: it publishes `status: ok`
only after every prefix has a fully accepting seven-field receipt, the source
has passed final revalidation, all child processes are drained/reaped, and the
temporary view/control state has been removed. Semantic rejection returns a
closed structured `inconclusive` result with no partial `receipts`; source,
view, control, process, revalidation, or cleanup ambiguity returns structured
`blocked-safety`, also with no partial `receipts`. A cleanup failure can report
only its safely revalidated retained path or descriptor-bound locator; it can
never coexist with `temporary_cleanup_status: complete` or a success receipt.

Derive the complete non-current prefix set independently from each complete
initial/final raw inventory, invoke the producer independently for each phase,
and map only the successful generic `receipts` array to the corresponding
history-top-level `initial_legacy_short_commit_resolution_receipts` or
`final_legacy_short_commit_resolution_receipts`. Recompute and revalidate the
same independently trusted bundle path, version, and canonical manifest digest
before and after both invocations. Require exact head/prefix coverage and
type-preserving equality of the two seven-field arrays; a changed bundle,
failed invocation, missing/extra/duplicate/unsorted receipt, or drift is
fail-closed. These independent invocations retain only the two point-in-time
observations described above; they do not widen the protected properties or
turn the equality comparison into an atomic source-object-store transaction.

For a self-policy migration, candidate-head Python and this candidate
subcommand remain review subject, never review control. If the prior trusted
bundle lacks `legacy-short-prefix-receipts`, adjudicate the migration and run
its formal review under the prior trusted policy, merge and release it, then
bind the released bundle manifest before activating this producer. Never run
the candidate-head subcommand, a private helper, or source-directory Git
queries to bootstrap evidence for its own migration.

## Shared Frozen-Range Contract

Pack ownership is signal-atomic: acquire the forwarded-signal mask before bounded capture, retain it across runner return and caller-visible publication, and finish fixed-chunk overwrite plus `clear()` before restoring or propagating a pending signal. A cleanup-window signal never replaces a primary error, and stderr cleanup cannot bypass pack erasure.

The exact source commit set `{base_sha} ∪ (base_sha..head_sha)` must equal the source's `--ancestry-path` projection for the same endpoints. Reject an off-corridor side history before import so materialization and the source-independent formal validator enforce the same single-boundary topology.

For every local logical lane:

- Resolve the local range and PR selector independently. Preserve an explicit frozen range as local-lane scope. Explicit-range-only standalone single/double requires no PR probe or head comparison. When PR-specific or triple work needs a PR, use an explicitly named PR or exactly one authenticated open-PR candidate for the exact current head repository/branch. A frozen range never selects a PR. Multiple candidates leave the GitHub/PR-specific lane `blocked-input` because the required explicit PR selector is absent, while fully scoped local lanes may still run. A proven zero-candidate result is the no-PR path, not a range: require an explicit committed range or an explicitly named target/base before freezing `<merge_base>..HEAD`; never guess the target/base. For triple, an undiscoverable detached/unknown branch without an explicit PR is `blocked-input` / `triple-inconclusive`, not effective double. Keep this missing-selector state distinct from `blocked-authorization`, which applies when intended dirty/untracked state would require an unauthorized anchor mutation.
- For a selected PR, independently read authenticated `baseRefName`, `baseRefOid`, and `headRefOid`; with lazy fetching disabled, require both endpoint commits locally and require `git merge-base --all pr_base_oid pr_head_oid` to yield exactly one full `pr_merge_base`. At first freeze, persist immutable parent-owned `range_origin.kind`, `range_origin.base_sha`, and `range_origin.head_sha`; the kind is exactly `caller-supplied` or `pr-derived`, and original caller endpoints are never overwritten. A missing or ambiguous selected-PR origin is `blocked-input` (`range-origin-unverified`). A selected PR's explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, do not start or count PR-specific lanes from it, and never describe its local review results as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR remains unaffected.
- Resolve and record full `base_sha` and `head_sha`; verify that both commits exist and that the chosen range is correct for the target branch. Before launch, prove both endpoint trees and the frozen range are locally complete. With lazy fetching disabled, the trusted guard requires `git merge-base --all base_sha head_sha` to return exactly `base_sha` plus LF; that exact single-result check proves both that `base_sha` is the sole merge base and that it is an ancestor of `head_sha`. This is required for standalone ranges as well as selected-PR ranges: zero/multiple/different merge bases or a non-ancestor base cannot enter range materialization and fail closed. Never derive a formal named-lane range from a dirty working tree or untracked files. When implementation or delivery mutation is already authorized, uncommitted changes may first be captured in an intentional review-anchor commit on the review branch. A standalone report-only named review does not authorize that branch or commit: when its intended scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization` and request an existing committed range or explicit anchor authorization.
- Treat the resolved Git executable selected from the parent-recorded fixed-path trust root as trusted control-plane input; this guard validates its behavior/version, not its publisher or on-disk identity. Before the materializer invokes any Git configuration override, require that executable to report version 2.45.0 or newer under the same rebuilt environment and owner-private cwd fenced from ancestor repository discovery. Older Git releases can interpret `core.fsmonitor=false` as an executable hook path and do not provide the required no-lazy-fetch boundary; an old, malformed, or unverified version is `blocked-safety`.
- Invoke the parent-recorded trusted guard's `materialize-worktree` subcommand to create each lane through a **pre-status isolated exact-range object import**; never use `git worktree add`, clone/fetch/upload-pack, the implementation checkout, or another reviewer's checkout. Require an absolute real local source directory whose exact `.git` marker, resolved admin/common/object directories, and worktree root agree before import. Bind that marker by `(st_dev, st_ino, file type, st_uid)` rather than `mtime`, `ctime`, or `nlink`; benign churn in those excluded fields is accepted. For a linked-worktree gitfile, also require its parsed forward `gitdir:` target to equal the bound admin directory and that directory's parsed `gitdir` back-pointer to equal the exact source marker. Read each control file with a no-follow, nonblocking descriptor open followed by regular-file, owner, and stable-identity validation; every storage revalidation rereads both linked directions without treating timestamps or link count as identity. Reject either-direction target drift, sibling `.bundle` / `.git` suffix discovery, every source shallow state, alternate/HTTP-alternate dependencies, promisor markers/configuration, unsafe object-format state, and non-real, incomplete, or replaced control directories. The source must remain a full ordinary repository even though the private destination will receive one exact materializer-owned shallow boundary. The guard creates an empty owner-private destination plus owner-private `HOME`, `XDG_CONFIG_HOME`, template, hooks, temporary, and control directories under `GIT_CEILING_DIRECTORIES=<destination-parent>`; that ceiling also keeps every later `-C <destination>` command from falling back to an ancestor repository. Fail closed when a canonical ceiling or alternate-object path contains the platform path-list separator and therefore cannot be encoded as one entry. Invoke the fixed-path Git trust-root executable only by direct argv with an explicitly rebuilt allowlist process environment equivalent to `/usr/bin/env -i`, containing the recorded trusted `PATH`, `LANG=C`, `LC_ALL=C`, `PAGER=cat`, the private `HOME`/`XDG_CONFIG_HOME`, `GIT_ASKPASS=/usr/bin/false`, `GIT_ATTR_NOSYSTEM=1`, the destination ceiling, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_GRAFT_FILE=/dev/null`, `GIT_NO_LAZY_FETCH=1`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, `GIT_PAGER=cat`, and `GIT_TERMINAL_PROMPT=0`; no other process environment or `GIT_*` input is inherited. Initialize the destination with the exact source object format and empty template while the fixed prefix includes `-c core.commitGraph=false -c core.checkStat=default -c core.multiPackIndex=false -c core.hooksPath=<empty-private-hooks> -c core.fsmonitor=false -c core.fileMode=true -c core.ignoreStat=false -c core.trustCtime=true -c core.attributesFile=/dev/null -c submodule.recurse=false` before every subcommand and also disables filters, external diff, maintenance, and remote-helper execution. Source configuration is read only as a bounded no-include byte stream for object-format/promisor rejection; source refs/config/hooks are never loaded by Git, and no remote transport runs.
- Before checkout, expose only the validated source object directory through a temporary `GIT_ALTERNATE_OBJECT_DIRECTORIES` value on destination-repository plumbing. Require the exact merge-base result described above, derive the source commit scope exactly as `{base_sha} ∪ (base_sha..head_sha)`, and build the object manifest from every scoped commit plus that commit's complete recursive tree/blob snapshot closure. Require unique full object IDs and query exact types and uncompressed sizes. Hard limits allow at most 250,000 manifest objects, 250,000 parent-edge occurrences, 2 GiB of logical object bytes, 100,000 head entries, 2 GiB of repeated checkout blob-occurrence bytes, 64 MiB of aggregate head path bytes, and a 768 MiB compressed exact-range pack. Count every parent token occurrence, including repeated tokens, and reject an over-budget parent graph before pack/object import. Bound `rev-list --parents` output as `(commit_count + 250,000) * (object-id-width + 1)`, with object-ID width 40 for SHA-1 and 64 for SHA-256. Canonicalize the validated parent graph for `parent_graph_sha256` by sorting rows by raw commit-OID bytes while preserving every row's parent tokens in their original order, including duplicates. Hash the domain-separated byte stream `named-lane-parent-graph-v1<NUL><decimal-object-id-width><NUL>` followed by each sorted row encoded as `<commit><NUL>(<parent><NUL>)*<LF>`. Raw `rev-list` row order therefore cannot change the digest, while a changed parent, parent order, or duplicate occurrence does. The shared path-bearing Git raw-output envelope derives its byte ceiling as `64 MiB + 100,000 * (object-id-width + 16)`. Apply that path-bearing ceiling to the materializer's head `ls-tree` and the validator's frozen-tree `ls-tree`, index-flag/pathspec `ls-files`, and porcelain `status`. For the validator this is a shared producer-output bound derived from the materializer budget, not a separate claim that each parsed result independently proves both semantic limits. Reject every source pack `.bitmap` before object traversal, and feed the manifest—not refs or revisions—to bounded `pack-objects --stdout --no-reuse-delta --no-reuse-object --no-use-bitmap-index`; then import only the result through `index-pack --stdin --strict --max-input-size=<768 MiB>`. The captured pack remains one bounded in-memory bytearray; cleanup overwrites it in fixed 64 KiB chunks and then clears it, avoiding a second pack-sized zero buffer. The worst resident-memory contract is therefore bounded by the 768 MiB payload ceiling plus Git/process overhead, not by an additional same-sized wipe allocation.
  Keep the exact materializer-owned `base_sha` boundary installed while the validated alternate supplies source objects for manifest enumeration and packing, then run `index-pack` without that alternate environment; no alternate file is ever installed in the destination. Require the earlier destination-visible commit closure to equal the source commit scope exactly. This equality is also the representability proof for the single boundary: if a selected merge or any other scoped graph shape exposes an outside parent that the base boundary cannot hide, materialization fails closed rather than importing pre-base history, widening scope, or adding a second boundary. Require the destination's complete object inventory to equal the exact manifest before refs, `fsck`, completeness checks, or checkout. Revalidate source admin/common/object identity around packing; benign source object-store churn may succeed only when every manifest OID remains readable, while replacement, missing objects, or changed safety-policy state fails closed. This range-scoped import keeps the existing 250,000-object, 2 GiB logical-object, checkout, and path ceilings; it sets the bounded pack ceiling to 768 MiB and adds the separate fail-closed 250,000 parent-edge budget. It does not alter the legacy-prefix producer's full-head completeness or 250,000-entry source-store inventory cap. Same-UID external disk competition remains outside a filesystem-quota guarantee.
- Require the target `.git` to be a real private directory with one ordinary single-link owner-held `.git/config`, one owner-private real `.git/info` directory at exact mode `0700`, and no `commondir`, `config.worktree`, per-worktree config, remote, alternate, HTTP-alternate, sparse, promisor, or pack `.bitmap` state. `config.worktree` is forbidden even when its values appear benign. Within each materializer or validator invocation, bind `.git/config` object identity and access policy, read its complete bounded bytes through a no-follow descriptor, and reject identity, type, ownership, link-count, mode, size, or byte drift during that protected window. `local_config_sha256` is the lowercase SHA-256 of those exact bytes. Across the materializer/validator boundary, digest equality protects config content; the validator independently rebinds identity and access policy, so a safe same-content replacement between complete invocations is harmless even though replacement inside either protected window is not. Reject direct `core.checkStat`, `core.ignoreStat`, and `core.trustCtime` definitions—including weakening values such as `minimal`, `true`, and `false`, respectively—so only the fixed command-scope `core.checkStat=default`, `core.ignoreStat=false`, and `core.trustCtime=true` values govern formal Git calls.
  Bind `.git/info` by device, inode, directory type, current owner, and exact owner-only mode before the first topology query; reject any `info/grafts` entry regardless of type, and revalidate the same directory binding plus graft absence after graph/reachability work and immediately before materializer handoff or validator status. `GIT_GRAFT_FILE=/dev/null` is mandatory on every materializer, validator, Codex-reviewer, and direct-Claude Git environment so a transient default-path graft cannot affect a Git subprocess between point checks. Child-entry churn can change `.git/info` timestamps and link count without changing the protected properties; those metadata deltas are not graft mutation evidence. Missing, present, unreadable, identity-mismatched, and access-policy-mismatched states remain fail-closed rather than being inferred from timestamp changes.
  For both `.git/config` and `.git/info`, structured `blocked-safety` output keeps missing, inspection failure, object-identity mismatch, protected-content mismatch, and access-policy mismatch as distinct stable machine reasons; it must not collapse those states into generic `changed` or `cannot be inspected` prose. For `.git/config`, missing no-follow inspection support, a bounded config-byte read failure, the size ceiling, Git parser rejection through a completed nonzero/stderr result, and malformed config-record output are inspection failures; process timeout, output-limit, drain, and leak failures retain their existing process-level machine reasons. Content or size drift after a binding is established remains a protected-content mismatch. The `.git/info` protected-content category is specifically graft absence, not ordinary child-entry churn.
  Before the materializer creates its boundary, any destination shallow state is unexpected and rejected; afterward, require exactly one ordinary shallow file containing only full `base_sha` plus LF and reject a missing, additional, duplicated, malformed, replaced, or changed entry. Each materializer point validation binds the boundary's device/inode/type/owner identity, protects mode and link count as access-policy signals, and protects the exact `base_sha` plus LF bytes as range semantics. It deliberately ignores timestamp churn; a safe same-content ordinary-file replacement between complete validations is harmless, while replacement, content drift, or access-policy drift observed during a validation fails closed. Persist exactly one Git-false value for both `core.commitGraph` and `core.multiPackIndex`, inspect only the exact local config with includes disabled, and keep both `-c` overrides on every parent/reviewer Git prefix. Reject any include/includeIf, alias, credential/helper, unexpected `core.worktree` or repository-extension state, non-false fsmonitor, hooks path other than the parent-owned empty path, executable clean/smudge/process filter, external/driver/textconv diff command, submodule recursion, remote-helper/protocol command surface, direct fsck-policy override, or other value that can execute code or redirect the worktree/object/config boundary. Create only the private base/head refs with hooks disabled, then use non-rendering plumbing for bounded full object-validity `git fsck` under the exact shallow boundary and local completeness proofs over the inclusive frozen range; never hydrate missing content through a fetch. Any parent-owned diff rendering before the final guard must use both `--no-ext-diff` and `--no-textconv` under the same prefix.
- Materialize `head_sha` only after that audit, through the same fixed clean environment and pre-subcommand safe `-c` options, with detached checkout, `--no-recurse-submodules`, hooks disabled, fsmonitor false, system/global attributes disabled, and no configured external filter or diff commands. Candidate `.gitattributes` may select only inert drivers because no executable driver definition is admitted. Before the final guard, use only non-status plumbing to require `HEAD == head_sha`, both frozen commits to resolve, and bounded read-only range queries to work. Do not run `git status`, `diff-files`, `diff-index`, or another worktree-scanning command during import, audit, checkout, completeness, or head verification.
- Bind the created control directory and materialized worktree to their recorded device, inode, and owner for cleanup. Immediately before recursive removal, require that identity under the still-identical owner-private parent; detected replacement or incomplete removal preserves and reports the exact retained path as `blocked-safety`. A non-cooperative same-UID replacement in the final identity-check-to-removal window is outside this lightweight cleanup guarantee and requires platform containment or a descriptor-recursive remover rather than a stronger pathname claim.
- As the first worktree-status operation and the final parent-owned workspace preflight immediately before Codex spawn or Claude process launch, invoke `<trusted-bundle-absolute-path>/skills/review-orchestration-playbook/scripts/named_lane_guard validate-worktree --worktree <absolute-clean-worktree> --base <full-base-sha> --head <full-head-sha>`, adding one `--guidance <repo-relative-path>` for each applicable tracked project-guidance file. The base and head must be the same frozen endpoints passed to `materialize-worktree`; `--base` is mandatory under this contract. Before its first status, the validator revalidates `refs/named-lane/base`, `refs/named-lane/head`, exact `.git/shallow == base_sha + LF`, both endpoint commit identities, the unique-merge-base result, and the exact inclusive-range topology. It independently traverses and recounts that graph under the same parent-edge/output budget and recomputes the canonical graph and local-config digests. Both success receipts must contain `base`, `head`, `worktree`, `commit_count`, `parent_edge_count`, `parent_graph_sha256`, and `local_config_sha256`; before either reviewer starts, the parent requires type-preserving exact equality for all seven fields. Counts remain resource evidence, `parent_graph_sha256` binds the exact ordered-parent topology, and `local_config_sha256` binds the exact config bytes across the two independent guard processes. Only after that range/storage gate passes may its forced ordinary/staged status become the first status query; only its exact independently verified absent-gitlink exception may be removed from the otherwise-empty result. The lane record resolves the placeholder to the recorded absolute trusted path; never resolve a bare repository-relative guard. Any earlier status query makes the lane `blocked-safety` because the parent can no longer prove that hooks, fsmonitor, or filters were not executed before validation.
  The guard's forced ordinary/staged status is the first status query.
- Every validator Git call forces `core.commitGraph=false`, `core.checkStat=default`, `core.multiPackIndex=false`, `core.ignoreStat=false`, and `core.trustCtime=true`, sets `GIT_GRAFT_FILE=/dev/null`, and fences repository discovery at the exact worktree parent before resolving repository identity. The Claude process inherits the same discovery ceiling, graft neutralization, and the materialized lane's audited local Git-false cache settings; the Codex exact prefix repeats all of those safe options and the ceiling.

For Codex, supply the exact sanitized Git argv prefix as tokens: `/usr/bin/env -i`, only recorded trusted `PATH`, fixed `LANG`/`LC_*`, `PAGER`, and `GIT_*` allowlist entries, the resolved trusted Git executable, fixed safe `-c` flags, and `-C <absolute-clean-worktree>`.

The parent materializes that prefix once in control metadata. Its environment allowlist is exactly the recorded trusted `PATH`, fixed `LANG`/`LC_ALL`, `GIT_ASKPASS=/usr/bin/false`, `GIT_ATTR_NOSYSTEM=1`, `GIT_CEILING_DIRECTORIES=<absolute-clean-worktree-parent>`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_GRAFT_FILE=/dev/null`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, `PAGER=cat`, and `GIT_PAGER=cat`. After the resolved trusted Git executable, the fixed options are exactly `--no-pager -c core.commitGraph=false -c core.checkStat=default -c core.multiPackIndex=false -c core.fsmonitor=false -c core.fileMode=true -c core.ignoreStat=false -c core.trustCtime=true -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c diff.external= -c color.ui=false -C <absolute-clean-worktree>`. The reviewer appends only the read-only subcommand and its arguments; it may not add an earlier `-C`/`--git-dir`/`--work-tree`, an overriding `-c`, or an environment assignment.

Every Codex Git invocation copies that supplied token sequence exactly, never uses bare Git or another/reconstructed prefix, and adds `--no-ext-diff --no-textconv` to every diff-producing command.
- After the range/storage checks above, the guard forces `core.fileMode=true`, requires ordinary and staged Git status to be empty after the narrow gitlink exception, and separately rejects both `assume-unchanged` and `skip-worktree` hidden index bits plus every ignored artifact in the worktree. The frozen-tree `ls-tree`, index/pathspec `ls-files`, and porcelain `status` all use the same hash-width-derived path-bearing Git raw-output envelope defined above. It allows stable tracked source symlinks whose materialized and tracked targets agree and whose full resolution remains inside the worktree; it rejects absolute targets, lexical escape, final or transitive escape, and unstable or mismatched tracked symlinks without reading an escaping target. The frozen targets are read through one aggregate 30-second `git cat-file --batch` call with at most 4,096 tracked symlinks, a 16 KiB per-target limit, and a 64 MiB aggregate output limit. It also requires every tracked `AGENTS.md` plus every supplied guidance path to be an ordinary non-symlink regular file inside the worktree. A gitlink is valid only when its path is absent or is an empty directory representing an uninitialized submodule; any initialized submodule, populated gitlink directory, gitfile, file, or symlink at that path is materialized reviewer-visible content and is rejected. Any repository-visible direct `include.path` or `includeIf.*.path` key is terminal `blocked-safety`, even when its condition is inactive, its target is missing or benign, or a later direct value appears to override included content. The guard enumerates the raw direct keys with includes disabled, never accepts included values as safety configuration, and blocks before its first `git status` or reviewer execution. A formally materialized lane never copies source configuration, so the bounded Git repository-identity probes needed to locate the private repository must encounter only the parent-audited config; if another caller supplies a workspace whose include is unsafe, unreadable, or malformed, those probes fail closed and provide no no-read guarantee. Direct `submodule.<name>.path`, Git's per-name `submodule.<name>.active` boolean precedence, and every repeated `submodule.active` pathspec remain authoritative; global pathspecs apply to every raw gitlink even when it has no tracked `.gitmodules` or direct name/path mapping. Explicit per-name false does not become a false initialization finding, while a tracked-submodule URL remains independent registration evidence. This materialization check completes before the guard invokes its first `git status`, so a pre-existing gitfile cannot redirect that query into external repository metadata. Before that status query or any reviewer Git command, direct `core.fsmonitor` must be unset or parse as Git-false. A built-in daemon (`true`), a no-value declaration, and any path hook are rejected without execution. A formal lane has no `.git/config.worktree`, so only the independently bound local config is admitted and a per-worktree override cannot weaken the local audit. The post-materialization validator rejects every direct `alias.*` key and direct configuration that defines executable `filter.<driver>.clean`, `filter.<driver>.process`, `diff.external`, `diff.<driver>.command`, or `diff.<driver>.textconv` commands; the earlier materializer additionally rejects executable smudge filters before checkout. Smudge-only and required-only settings plus non-command diff metadata remain allowed by the validator because they cannot execute during its status/read-only phase. Because Git reports an absent gitlink as a worktree deletion, the guard may consume only that exact status record after the frozen tree proves mode `160000` and `lstat` independently proves the path absent; every other status record remains dirt. Every bounded Git, output-limit, deadline, drain, process, parse, race, or filesystem failure from `validate-worktree` is terminal `blocked` with reason `blocked-safety`; do not spawn or launch the lane.
- Keep the guard property-scoped (checking only the property that protects clean state or safety). It may compare Git state, hidden index flags, ignored-path presence, symlink target/containment, guidance type/location, gitlink materialization, bound control-file identity/content/access policy, graft absence, and the exact source marker fields or gitfile targets needed to retain repository identity. For ordinary tracked files, Git stat signals under `core.checkStat=default`, `core.ignoreStat=false`, and `core.trustCtime=true` decide when Git must reread content; a metadata delta is not itself a content mutation finding. The guard must not treat `mtime`, `ctime`, or `nlink` churn as launch identity or content evidence; benign churn in those fields is accepted. It must not snapshot or rehash the full ordinary-file tree. Do not expand that guard into a raw-object workspace or instruction snapshots, supplied/prepared diffs, immutable guidance snapshots, or a general secret/content scan. Conditional repository-required or suspicion-driven security scanning remains a separate parent-owned decision.
- Expose the workspace and Git metadata for read-only reviewer behavior. Disable writes to files, index, refs, config, hooks, remotes, PR state, and other external systems. The preflight-selected, publisher-verified canonical Claude process launched through `run-claude` may update ordinary CLI-owned authentication and runtime state in trusted real `HOME`, including credential refresh and possible cache or tool-result artifacts. Those accepted CLI control-plane side effects are not model-authorized review actions, do not authorize model/tool writes or deliberate host mutations, and do not inherit helper credential guarantees. The policy does not enumerate or attest every CLI-owned `HOME` write. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent: the reviewer policy must forbid those actions and the parent must not authorize them. This is a write/behavior contract; it is not a claim that every runtime has an OS-level global host-read whitelist.
- A CLI report that output was persisted or spilled to an outside-worktree control-plane path is not itself a model read and does not block the lane. The reviewer must not follow that path with a direct tool read; it reruns a narrower bounded worktree-scoped command instead. An observable structured outside-workspace read adds deterministic blocked evidence. The global classifier still gives concurrent malformed or otherwise inconclusive evidence precedence, returning `inconclusive` with combined reasons rather than accepting findings.
- Keep the model-visible workspace free of generated prompts, diff files, manifests, state directories, and helper control artifacts.
- If a security preflight needs private evidence, keep it outside the reviewer-visible workspace and never project a full diff into the prompt.
- Do not use a tracked secret delta as a reviewer-launch gate. The trusted reviewer may inspect the original tracked diff and necessary tracked context, including repository secrets, without redaction or rewriting. Reviewer/runtime authentication credentials, untracked files, unrelated repositories, broad workspace dumps, and home-directory content remain out of scope.
- Bind the terminal artifact to the exact workspace and range, then clean up the worktree after collection.

## Self-Policy Migration

When the candidate changes review policy or control code, use a compatible trusted bundle pinned outside the candidate range. Record its path, version, and digest. Candidate Markdown may be subject matter and scoped guidance, but materialization, validation, reviewer profile, prompt assembly, runtime preflight, launch, and stream/result validation come from the trusted prior bundle. If compatibility is unavailable, complete the migration under prior policy and activate the new control only after release.

## Named Single

Eligibility:

- one frozen committed range;
- one trusted-guard-materialized and validated clean workspace;
- one `reviewer` agent with zero inherited turns;
- applicable instructions loaded inside the lane;
- bounded read-only evidence access.

Output is either actionable findings with file/line evidence, canonical clean, or a precise lane blocker. Only one accepted Codex reviewer counts. Diagnostics, retries, and helper processes do not add lanes.

## Named Double

Double is the accepted single lane plus one actual Anthropic Claude Code process in a different independent workspace over the same range. The selected CLI must pass the trusted bundle's compatible-version, publisher-provenance, credential-free capability, executable, process, and stream checks. Capture canonical raw stdout outside the model-visible workspace and accept findings only after the manifest-bound validator returns its accepted classification.

The named-direct lane uses ordinary local login in trusted real `HOME`; it exposes no API-key or OAuth-token interface. The low-level `isolated_review` helper has separate supplied-diff, auth-selection, credential-carrier, and recovery contracts. It never counts as the actual-Claude lane, and its guarantees never transfer to the named-direct lane. Copilot never counts.

## Named Triple

Triple is accepted double plus one eligible GitHub Codex lane on exact `github.com`. A selected PR must pass lifecycle first and then exact current scope. Load authority resources in this order:

1. [github-codex-evidence-authority.md](github-codex-evidence-authority.md)
2. [github-codex-review-epoch-state-machine.json](github-codex-review-epoch-state-machine.json)
3. [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json) only for a same-head base-only retarget
4. [github-pr-probes.md](github-pr-probes.md) for endpoint capture
5. [pr-readiness.md](pr-readiness.md) for delivery gates

One immutable review epoch and all machine-authorized serial attempts count as one logical GitHub lane. Attempts are orchestration, liveness, retry, and audit history only. Request count, checks, runs, and `eyes` do not supply Action-status `PASS`; `+1` supplies neither `PASS` nor ACK. Only the sealed reduction's exact current-head required `codex/review-gate == success`, after that coordinate binds the canonical producer, final provider validation, and epoch/marker clocks, is `PASS`; noncanonical repository-side compatibility publication never qualifies. Applicable current-head or proved-ancestor findings and unresolved threads block, proved nonancestors are excluded, and unknown ancestry fails closed. Report the six independent planes exactly as `request_policy`, `provider`, `required_action_status`, `named_github_lane`, `reaction_audit`, and `readiness`; `evidence_basis` is nested only inside `provider` and is never a seventh top-level plane.

The reducer's sole input is one parent-owned sealed composite coordinate binding required-status membership, final provider validation, the immutable epoch first-attempt clock, and current marker/attempt state. The six report planes remain independent outputs, not independent reducer authorities; raw probe results, caller dictionaries, standalone status/provider projections, marker objects, or clock values cannot replace that coordinate. At or after the 7,200-second overall deadline, any still-budgeted or other incomplete acquisition reduces to overall-timeout `FAILURE` before the narrow late-`PASS` arm; only with no incomplete acquisition may an actual complete, final-stable, exact-current-head terminal clean plus canonical Action `success` become `PASS`.

The per-PR consumer caller preserves repository-owned events, permissions, and concurrency and has exactly one job using `JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`; the called workflow uses that same path. Floating `@v1` is a pre-execution trust boundary. Post-run admission requires producer receipt v1, the unique exact-attempt `referenced_workflows` repository/path/ref/sha identity, the receipt's separate called-job repository/path/ref identity, producer protocol major 1, decision schema 1, decision policy major 1, and release-provenance v2. Require receipt `job.workflow_sha`, receipt `action.ref`, and the unique entry's `sha` all to equal exact-attempt workflow value `W`; require the entry's ref to be exact `refs/tags/v1`, with missing or null failing closed.

Scheduled reconciliation is a separate repository-owned dispatcher boundary. It may provide bounded per-PR transport into the caller, but its workflow and runs are not required-Action producer evidence, `PASS`, or an alternate producer caller. Its exact trigger, cadence, and permissions remain repository-local implementation policy and do not extend the lane or epoch contracts.

Every release candidate independently proves its immutable release tag object `R`, derived `v1.minor` tag object, and historical provenance-`v1` tag object `T`: fetch each by that candidate's provenance OID, locally OpenPGP-verify its exact payload/signature, and require its direct target to be that candidate's `C`. That candidate's closed `workflow_sha_resolution` compares `W` only with historical `T` and exact commit `C`: zero matches is `proved-incompatible` only with otherwise complete valid unambiguous proof, one is runtime-resolution eligible, and more than one is malformed `ERROR`. Separately authenticate and final-stably reread the current floating alias `T_current -> C_current`; it is live audit/stability evidence and never supplies exact-attempt `W` or any historical candidate proof. If `W == T_current`, require `C_current == C`; a valid later alias move may otherwise differ.

Fetch the reusable workflow and released Action tree/critical bytes at candidate `C`. Admit a release only from complete GitHub Releases evidence when exactly one valid candidate has all three independent tag proofs and exactly one valid provenance-v2 asset; never admit `v1.5.0` or an erratum path, and treat `v1.5.1` as the first admitted release. Retain exact SemVer `policy_version` as audit evidence, require major 1 and cross-source equality, and keep caller-workflow SHA, run/event head, PR/status head, exact-attempt `W`, candidate `R/T/C`, and current alias `T_current/C_current` as separate roles. Provenance `source.commit_oid` is the distinct source-repository commit; source-to-Action subtree equality is separately authenticated and never makes it equal `C`. The generic Skill pins no patch release, commit, tag object, or workflow blob. This establishes authenticated run-level consistency and signed release admission, not cryptographic job provenance; rejected floating-`@v1` code may already have executed with caller permissions, and the contract does not guarantee online or post-publication revocation.

Release admission derives and final-stably rederives the complete ordered candidate vector as `valid`, `proved-incompatible`, or `malformed-or-incomplete-error`. Only complete, well-typed, authenticated, internally unambiguous evidence—including a valid OpenPGP signature by one unambiguous nontrusted primary signer or zero candidate-local `W` matches—that proves an admission predicate false is `proved-incompatible`. Missing, invalid, ambiguous, or unverifiable tag/signature evidence, more than one `W` match, and every integrity or cross-binding contradiction are errors that make the whole admission `ERROR`. Exclude only proved-incompatible candidates and, only when no malformed/incomplete sibling exists, require exactly one valid candidate. The independently authenticated source-repository `packages/action` subtree equality to the Action-`C` root tree is an admission proof, not audit-only. The consumer pins neither selected called-workflow bytes/digest nor the selected release's complete external Action SHA set.

## Inputs And Egress

Allowed lane input is limited to the named repository's tracked frozen range, necessary tracked context, bounded tool-derived evidence, applicable instructions, and review-control metadata. Named-shape consent determines permitted processors as specified in [egress-consent.md](egress-consent.md). Untracked files, unrelated repositories, broad host content, authentication-secret discovery, or substitute reviewers are outside scope.

Secret-delta admission is independent from reviewer input. It does not redact tracked content or create another reviewer lane.

Complete frozen endpoint discovery/count scans retain the 64 MiB per-blob limit and charge every blob occurrence, including duplicate OIDs, against the 2 GiB named-lane checkout envelope. Exact occurrence counting has a separate 68 GiB search-work budget, equivalent to 32 complete fixed-pattern passes over both the 2 GiB blob envelope and the conservatively bounded 128 MiB path-metadata envelope; the generic workspace scanner retains its 16 GiB bound. Stream at most 128 MiB of blob payload and 8,192 entries per `cat-file --batch` invocation, cap an endpoint at 64 blob-batch invocations, bind each response to the expected OID/type/size/delimiter with a 128-byte canonical header limit and exact output ceiling, and share one 900-second deadline across metadata, batches, complete per-blob context scanning, and parsing. Recheck that deadline at every blob boundary. At most one already size-bound blob is held as complete scanner context, avoiding chunk-boundary proof ambiguity without buffering an endpoint. Changed-location scanning remains independently capped at 512 MiB.

## Budgets

Each lane must have finite bounds for:

- materialized objects, paths, and bytes;
- reviewer prompt and tracked-context scope;
- command runtime and retained output;
- provider pages, records, raw bytes, graph depth, work units, and deadline where applicable;
- final result and diagnostic retention.

Charge before expensive work, preserve exit status, and fail closed on exceeded or unprovable limits. A truncated display is not complete evidence. Use `$bounded-command-output` for uncertain or verbose commands, but let stricter trusted-guard and machine limits prevail.

For GitHub evidence, type-sensitively load the epoch machine's exact `artifact_completion.evidence_resource_budget_contract.exact_config` before acquisition and create one parent-owned composed-operation budget ledger. It covers the provider and required-Action REST/GraphQL, run/attempt, artifact/archive/workflow, release/asset/tag/provenance, source/Action tree, and raw-resource graph; every carried `resource_budget` must equal that configuration. Counters, retained UTF-8 bytes, and deadline are cumulative across the operation, while the body ceiling applies independently to each body. No initial/final capture, candidate/sibling evaluation, caller, release, or test input may reset, split, refund, borrow, override, or reseal the ledger. Exhaustion follows the owning plane's canonical reducer and never authorizes partial evidence.

## Output Contract

The reviewer returns one raw findings-only terminal result. Preserve the complete raw result as its exact original UTF-8 bytes and lossless decoded text; never replace an extended clean result with a synthesized sentinel or parent summary. Actionable findings include severity, precise file/line evidence, violated property, and triggering impact. When clean, the result may contain one concise non-actionable coverage summary, but its final nonempty logical line must be exactly `No findings.`; a findings result must not contain that sentinel. Only outer ASCII whitespace may surround the canonical sentinel. A quoted, inline, repeated, or non-final `No findings.` is not a clean sentinel.

Store the raw result in a lane record with three independent layers:

- `artifact_status`: transport/schema trust such as `accepted`, `blocked`, or `inconclusive`;
- `review_outcome`: `clean`, `findings`, or `undetermined`, evaluated only after artifact acceptance; and
- `presentation`: `canonical-clean`, `extended-clean`, `findings`, `contradictory`, `ambiguous`, or `nonconforming`, evaluated only after artifact acceptance.

`canonical-clean` is sentinel-only; `extended-clean` is a concise non-actionable prefix plus the terminal sentinel; `findings` is actionable content without the sentinel; `contradictory` is actionable content with the sentinel; `ambiguous` pairs the sentinel with content whose no-findings meaning cannot be established; every other accepted form is `nonconforming`. A repeated, quoted, inline, or non-final sentinel is not a clean sentinel.

The artifact/stream validator remains the sole authority for artifact acceptance and `artifact_status`; it must preserve the terminal result unchanged. Only after acceptance may the manifest-bound `classify-review-result` profile decode the exact retained bytes once without normalization and invoke `classify_review_result(raw_result, content_assessment=...)` to derive `review_outcome` and `presentation`; classification cannot repair, replace, or bypass validation. Commands, tests, or residual risk may be added by the parent as optional metadata, but they never alter the raw result and must not be demanded from a reviewer whose raw output contract is findings-only.

Each complete lane record also returns:

- exact repository and frozen range;
- logical lane and actual runtime/provider;
- full frozen range and workspace identity plus guard evidence;
- validation or transport failures without laundering partial output into clean;
- checks actually run and important limitations.

The orchestrator reports requested and effective shape and never counts a lane whose required validator, evidence, or terminal status is missing.

## Failure And Rerun Contract

- An actionable `review_outcome: findings` requires a tracked repair and new frozen head before invalidated lanes rerun.
- A changed range or head invalidates every result bound to the old scope and permits the required lane rerun on the new frozen scope.
- A same-head runner, transport, or evidence-fetch failure remains inconclusive; any machine-authorized acquisition retry is affected-gate reconciliation, not a new reviewer rerun.
- A lifecycle or scope change follows lifecycle-first selection and retarget policy before any rerun.
- An ambiguous GitHub POST remains fenced; never retransmit blindly.
- A local named-lane auth or trust failure reports the corresponding blocker; do not silently substitute a helper, Copilot, or another model.
- Presentation is diagnostic metadata, not a retry signal. Never rerun solely because an accepted result is `extended-clean`, `contradictory`, `ambiguous`, or `nonconforming`; an independently proved findings outcome follows the finding-fix rule above.
- Rerun only after the reviewer's range/head evidence is invalidated, a finding fix creates a new head, or the user explicitly requests another run. Otherwise surface the exact ambiguous or nonconforming disposition and stop at the decision point.
- Repeated diagnostics do not increment single, double, or triple.

## Review-Only Child Contract

A child reviewer receives only review authority. It does not orchestrate PR delivery, edit files, start other reviewers, wait for CI, post requests, resolve conversations, or merge. It returns findings or clean to its parent; the parent owns fixes and all delivery state.
