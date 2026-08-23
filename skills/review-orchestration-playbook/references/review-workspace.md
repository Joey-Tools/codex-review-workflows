# Review Workspace

A named local reviewer runs in an independent, clean, detached Git workspace. This contract protects three properties:

1. the model-visible checkout is generated only from committed tracked state at `head_sha`;
2. its Git administration and objects are independent of the source and other lanes; and
3. the reviewer model/tool surface gets the strongest provable read-only and no-external-mutation enforcement boundary.

It does not require an exact-range-only object database. Additional committed objects or history may remain present.

## Public Helper Surface

Use the active trusted bundle's public guard interface:

```text
<trusted-python> -I -B -S <trusted-bundle>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  prepare-workspace --source <absolute-source> --worktree <absolute-absent-destination> \
  --base <full-base-oid> --head <full-head-oid>

<trusted-python> -I -B -S <trusted-bundle>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  validate-workspace --worktree <absolute-destination> \
  --base <full-base-oid> --head <full-head-oid>

<trusted-python> -I -B -S <trusted-bundle>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  cleanup-workspace --worktree <absolute-destination> --token <receipt-cleanup-token>

<trusted-python> -I -B -S <trusted-bundle>/skills/review-orchestration-playbook/scripts/named_lane_guard \
  recover-partial-workspace --control-file <absolute-control-file> \
  --control-sha256 <receipt-control-sha256>
```

Use absolute paths and a parent-validated absolute Python interpreter. Do not execute the guard through a shebang, ambient `PATH`, candidate-head code, or ordinary import resolution.

## Source Preconditions

The source may be a normal checkout or a linked worktree. It may be dirty, shallow, partial/promisor, or backed by alternates. Preparation never copies its live worktree, index, untracked files, config, hooks, remotes, or submodule checkout. Source storage dependencies are discovery inputs only: every required object must be imported into independent destination storage.

With lazy fetching and credential prompts disabled, require:

- both full object IDs resolve locally as commits;
- `base_sha` is an ancestor of `head_sha`;
- the base snapshot and complete raw `head_sha ^base_sha` DAG, including merge commits and merge side history, are locally available;
- every commit, tree, and blob needed for that graph, endpoint comparison, direct out-of-scope parent snapshots, and the head checkout is local;
- the source object format is supported and stable for the preparation attempt.

The helper never fetches and never prompts for credentials.
It never narrows the range through `--first-parent`, `--ancestry-path`, a
single-parent walk, or an inferred linear-history requirement.

For a complete, non-shallow, non-promisor source, `merge-base --is-ancestor`
exit `1` is stable `invalid-range` evidence: the selected base is not an ancestor
of the selected head. Before making that classification, independently traverse
both endpoint parent graphs with missing-object errors enabled. A shallow,
promisor, or actually incomplete graph remains `range-incomplete`; an operational
merge-base failure greater than `1` is `blocked-safety`, not an invalid range.

## Range-Incomplete Failure

When an endpoint, parent, tree, or blob is missing, stop with structured `status: range-incomplete` evidence, classified by the parent as blocked input. Include the known missing endpoint or a bounded sample of missing objects, whether the source is shallow, and precise parent remediation.

The parent should fetch only what the frozen range needs:

- use exact branch/ref refspecs or exact object IDs when the server supports them;
- for a promisor/partial clone with missing snapshot blobs, pass only the
  receipt's bounded `missing_objects` sample, one object ID per input line, to
  `git fetch-pack --stdin --no-progress <promisor-url>`; rerun preparation and
  repeat only when `missing_objects_truncated` remains true;
- if the server rejects exact reachable-object wants, stop for an explicitly
  approved narrow hydration choice rather than automatically refetching or
  unfiltering the whole repository;
- pass `--no-tags` and disable recursive submodule fetching;
- for a shallow source, deepen by the smallest useful increment and rerun completeness;
- avoid fetching unrelated refs, tags, submodules, or broad history;
- do not default to `--unshallow`.

The parent, not the helper or reviewer, performs any authorized fetch. A retry uses the same frozen endpoints.

A source missing-parent frontier is representable in the destination only when
marking its present boundary commit shallow would suppress no locally known
parent edge. In particular, a boundary commit that mixes a missing parent with
a locally present parent is unsafe because Git's shallow format suppresses all
of that commit's parents. Return `range-incomplete` with the boundary commit, a
bounded missing-parent sample, and smallest-useful-deepen guidance; never hide
the present edge or broaden the fetch automatically.

When head and base walks share a missing frontier, locally visible ancestry
through an arbitrary base ancestor is not enough to prove range membership: a
missing completion can still make that candidate reachable from the base. In
that case every admitted range commit must be a locally proved descendant of
the exact `base_sha`. Otherwise return `range-incomplete` and request the
smallest useful deepen operation. This conservative rule prevents redundant
merge ancestry from widening `base_sha..head_sha` across an unseen bridge.

## Preparation Strategy

The public helper currently reports strategy `exact-pack`. It creates a fresh
destination repository and feeds the sorted union of these locally available
objects to one bounded `git pack-objects` process:

- `.git/review-range-objects`: every commit in
  `{base_sha} ∪ (base_sha..head_sha)` plus each scoped commit's complete
  snapshot tree/blob closure; and
- `.git/review-parent-support-objects`: a disjoint support set containing the
  complete locally available commit DAG reachable from `base_sha`, plus the
  complete snapshot tree/blob closure of every direct parent of an in-range
  commit that lies outside the scoped set. Objects already present in the range
  manifest are omitted from this support manifest.

It indexes that stream into exactly one matching pack/index pair beneath the
fresh destination object directory. Pack generation disables reuse of source
deltas and source object representations. The destination contains no loose
objects, alternates, promisor state, remotes, or second pack whose lookup
precedence could hide a conflicting representation. The bound review manifest
contains only the scoped snapshots. The separate parent-support manifest binds
the available pre-base commit topology and the direct-parent snapshots needed
to inspect every scoped commit's patch. This support does not widen the frozen
diff. Pre-base trees/blobs that are neither scoped nor one of those
direct-parent snapshots are not required or imported.

The helper does not copy source object-store files. A future validated immutable
seed or copy-on-write optimization may replace the current producer without
changing the public independence-and-clean contract.

Never use:

- `git worktree add`;
- hardlinks;
- Git alternates, borrowed object stores, or shared common/object directories;
- a linked-worktree back-pointer to the source;
- a remote or promisor dependency;
- a copied source checkout, index, config, hooks, filters, attributes, or fsmonitor state.

Preparation initializes fresh destination control state, writes only safe local
configuration, and records the exact source shallow bytes separately. It derives
synthetic destination shallow boundaries only from real missing-parent
frontiers in the raw source graph. A safe boundary suppresses only missing
parents; every locally known parent edge, especially every edge within
`{base_sha} ∪ (base_sha..head_sha)`, remains reviewer-visible. When there is
no real missing-parent frontier, including for a complete source, the canonical
destination shallow receipt binding is empty and `.git/shallow` is absent. A
real safe frontier creates the file with exactly the sorted canonical boundary
bytes. The boundary is never fixed to `base_sha`. An unsafe mixed frontier is
`range-incomplete`, not permission to use `base_sha` or another convenient
commit as a guessed boundary.

After import, reviewer-visible
`git rev-list --parents --full-history base_sha..head_sha` must produce exactly
the raw frozen range, including merge commits and side history. The validator
also reads the scoped commits' raw parent rows with shallow interpretation
disabled and requires the visible parent tuples to match exactly. A
first-parent or ancestry-path projection cannot satisfy this check. Preparation
then creates a detached `head_sha` checkout without submodule initialization and
stable private refs for the frozen endpoints. It never copies the live source
worktree, index, configuration, hooks, filters, attributes, fsmonitor state, or
Git administration.

One 15-minute monotonic deadline covers source discovery, range freezing,
base-history enumeration, pack production, and indexing. Current ceilings are:

- 250,000 review commits;
- 1,000,000 raw parent-graph commits and 1,000,000 parent-edge occurrences;
- 1,000,000 distinct objects across the disjoint range-plus-parent-support
  import union;
- 32 GiB of canonical uncompressed payload across that complete union;
- a 768 MiB compressed pack and 256 MiB pack index for that complete union; and
- a checkout preflight of 100,000 tracked entries, 2 GiB of blob-occurrence
  bytes, 64 MiB of raw path bytes, and 96 MiB of bounded tree output.

The checkout byte limit counts each tracked blob occurrence, so repeated paths
to the same blob do not evade it. Every budget, deadline, capacity, malformed
output, or incomplete-object failure stops without publishing a formal
workspace. If a pack/output process may still exist and process-group
quiescence cannot be proved, rollback is intentionally skipped: the terminal
envelope binds the retained root, parent, external control, owner-process, and
active PID/PGID/start identities and marks ordinary cleanup unavailable until
quiescence is independently proved. When that control is durably sealed, the
envelope supplies one exact `recover-partial-workspace --control-file ...
--control-sha256 ...` route without placing a cleanup token in the control or
argv. Recovery refuses an active or unverifiable exact process identity, a
remaining process group, a replaced/moved/missing root or control, changed
control bytes, or unexpected workspace state. It never fabricates a formal
marker or cleanup token for that unsafe partial state.

Successful exceptional recovery removes workspace payload but deliberately
retains an authenticated, idempotent tombstone: a markerless partial workspace
keeps the same empty root inode, while a formal workspace keeps the same root
inode plus only `.git/review-workspace.json` with its original exact bytes. The
immutable external control is also retained. Repeating the same exact argv
returns `cleanup_status: already-clean` only after revalidating those identities
and tombstone contents; the first successful removal reports
`cleanup_status: payload-removed` and `tombstone_status: retained`. A separate
future prune or the system temporary-directory lifecycle may remove these small
tombstones. Ordinary `cleanup-workspace` refuses a workspace while a matching
partial-recovery control exists.

After import, rederive the destination-visible scoped snapshot closure and
require exact equality with the sorted range manifest. Independently rederive
the complete available base-side commit support plus the direct out-of-scope
parent snapshots, and require exact equality with the disjoint sorted
parent-support manifest. Separately prove the ordinary visible range and parent
tuples equal the frozen raw DAG. Then stream every object in the union of both
manifests and recompute its canonical Git object ID from
`type + SP + decimal-size + NUL + payload` using the repository's SHA-1 or
SHA-256 format. An object name, type lookup, pack index, or connectivity check is
not content-integrity evidence by itself. This verification must reject both a
forged loose object stored under another object's name and a loose override of a
packed range object even when ordinary `cat-file --batch-check` accepts the
requested name, type, and size.

## Independence Checks

Preparation and validation must prove the destination's:

- worktree, Git directory, common directory, and object directory resolve beneath its owner-private root;
- Git/common/object paths are distinct from the source and every other lane;
- object files are not hardlinked to source objects;
- alternates and alternate environment variables are absent;
- HTTP alternates, promisor markers, and remotes are absent;
- repository is not a linked worktree and has no source back-pointer;
- config contains no includes, aliases, executable hooks/filters/diff drivers, fsmonitor command, promisor remote, or object replacement mechanism;
- detached `HEAD` equals `head_sha`, and the frozen DAG plus every represented missing-parent frontier is locally sufficient for the required range and patch operations.

Extra committed base-history support objects in the private destination do not violate independence.

## Control-State Custody

The absent destination's parent, workspace root, `.git`, and `.git/objects` are
identity-bound directory objects owned by the current UID. The parent, root, and
Git control directories must remain mode `0700`. Configuration, `HEAD`,
exact source-shallow evidence, lane refs, private attributes, the range and
parent-support manifests, the index, and the workspace marker must be no-follow,
current-UID, mode-`0600`, single-link regular files with bounded content. The
same file contract applies to `.git/shallow` when a real frontier requires it;
an empty shallow binding instead requires that path to be absent.

Within each validation operation, open these paths with `O_NOFOLLOW`, bind object
identity and access policy with `fstat`, and bind file content by exact bytes or a
digest. Revalidate the binding immediately before and after every Git subprocess,
as well as before consuming fixed state and returning success. The protected
properties are directory object identity, file object identity and content, and
the stated access policy. Directory link count, ctime, and unrelated child-entry
churn are not mutation evidence.

For a control file, `mtime` and `ctime` are generation hints only. A timestamp
change during a read triggers at most one complete descriptor-bound reread; it
does not independently prove mutation. Accept the result when object identity,
exact content, and access policy remain unchanged. Reject same-size content
mutation and same-content inode replacement. Classify an initial read failure as
unavailable and a failed required reread as revalidation-unavailable rather than
misreporting either as content or identity drift. The external partial-recovery
control uses the same protected-property rule.

A safe atomic replacement with identical bytes, current UID, mode `0600`, and one
link may establish a fresh binding on a later validation call. It is rejected if
it occurs during an already-bound validation call. Do not persist ordinary
control-file inode identities across separate validations; do persist the
workspace root, `.git`, `.git/objects`, parent, and cleanup-target identities
where the receipt/marker contract requires them. Parse the marker only from the
same descriptor-bound snapshot used by validation, and revalidate that exact
marker/token binding immediately before cleanup custody transfer.

These checks detect stable replacement, content drift, and access-policy drift
during each helper operation. They are not an operating-system security boundary
against an arbitrary hostile same-UID process that can continually race the
helper with repeated ABA replacements or mount-namespace manipulation. The
caller must not concurrently mutate a prepared workspace; the adapter sandbox,
not this Git validator alone, owns enforcement against reviewer writes.

## Clean And Safe Checkout

Immediately before launch, validation rejects:

- staged, modified, deleted, untracked, or ignored worktree content;
- `assume-unchanged` or `skip-worktree` index bits;
- initialized or materialized submodules;
- escaping or unstable tracked symlinks;
- unsafe repository-local configuration or graft/replacement state;
- missing range or checkout objects.

`git ls-files -v -z` must consist only of complete `H SP path NUL` records.
Lowercase `h` (`assume-unchanged`) and lowercase or uppercase `s`/`S`
(`skip-worktree`) are blocking hidden-index state; every malformed record or
unknown tag is a validation failure rather than clean evidence.

An absent, uninitialized gitlink is acceptable. The reviewer loads guidance only after validation.

Symlink validation uses one bounded batch lookup rather than one Git process per
link. It admits at most 4,096 tracked symlinks, at most 16 KiB per target and
64 MiB of target bytes in aggregate, and applies one shared monotonic deadline
to index, object, and filesystem validation.

The reviewer process gets a read-only filesystem sandbox and no state-changing external tools. Workspace validation proves repository properties; the adapter launcher/lane receipt separately records the requested and observed model/tool enforcement boundary. Neither claims an operating-system guarantee that the runtime cannot attest. If the required boundary cannot be established, report `blocked-safety` instead of launching.

For the direct Claude lane, trusted real-`HOME` credential refresh or CLI control-plane artifacts are an explicitly documented runtime side effect, not a reviewer-model write authorization. Record them under [canonical-claude-lane.md](canonical-claude-lane.md); they do not permit repository or external-system mutation by the model/tool surface.

## Git Environment

The workspace helper directly enforces these properties for its own Git
subprocesses. A local Codex reviewer is required to preserve the same properties
through the parent-owned `sanitized_git_argv_prefix` defined in
[review-lane-contracts.md](review-lane-contracts.md):

- one fixed absolute Git executable resolved before any source or workspace
  repository command and reused throughout the complete prepare or validate
  operation, including pack, index, and direct `Popen` paths;
- an exact bounded `git --version` preflight before that first repository
  command, accepting the normal and Apple Git formats only and requiring Git
  `>=2.45.0`; an old, malformed, or unverifiable version is `blocked-safety`;
- system/global config disabled;
- lazy fetches and terminal prompts disabled with both `GIT_NO_LAZY_FETCH=1`
  and `--no-lazy-fetch` on every repository Git argv that accepts global options;
- hooks, fsmonitor, replacement objects, external diffs, and text conversion disabled;
- pagers and color disabled;
- repository discovery fenced to the workspace;
- no submodule recursion.

Diff-producing reviewer commands explicitly use `--no-ext-diff --no-textconv`.

Successful workspace validation does not prove that a later model-issued Git
command used this environment. The Codex prompt and lane receipt therefore bind
the exact prefix, fixed Git path/version, workspace, verified prompt delivery,
requested/established read-only adapter boundary, and the strongest tool-argv
evidence the runtime actually exposes. That is a prompt/tool-observation
boundary, not an operating-system enforcement claim. Missing or altered prefix
delivery, an unavailable required boundary, or observed argv deviation makes
the Codex lane inconclusive. `partial` or `unobservable` argv telemetry is
recorded as a limitation and is not by itself evidence of deviation.

## Receipts

Preparation and validation each emit one bounded machine-readable receipt. At minimum they bind:

- schema/status;
- exact canonical workspace path;
- `base_sha` and `head_sha`;
- parent-directory, workspace-root, `.git`, and `.git/objects` identities;
- object format;
- local-config digest;
- exact canonical synthetic shallow-boundary bytes and digest; empty bytes and
  their digest bind an absent `.git/shallow`, while nonempty bytes bind the
  present frontier file;
- source shallow-state flag and frozen review commit count (`base_sha` plus
  `base_sha..head_sha`);
- exact `range_object_count` and `range_object_sha256` for the range manifest;
- exact `parent_support_object_count` and
  `parent_support_object_sha256` for the disjoint parent-support manifest;
- preparation strategy;
- exact marker SHA-256 and cleanup-token SHA-256 bindings; and
- an unguessable plaintext cleanup token only in the preparation receipt.

Require the shared fields to match type-preservingly before launch. A path string alone is not an identity binding.

These are workspace preparation/validation receipts. The parent-owned Codex
lane receipt separately binds the reviewer Git-prefix digest, prompt delivery,
adapter boundary, observation level, and any observed deviation. It must not
infer argv-level compliance from workspace success or turn unavailable adapter
telemetry into a synthetic mismatch.

The consumer waits for the guard process to exit before adopting a receipt.
Success requires exit `0`, empty stderr, and exactly one complete schema-valid
stdout receipt. On any nonzero exit, ignore even a parseable success-looking
stdout payload. Exactly one complete schema-valid stderr failure envelope is
authoritative; empty, partial, malformed, or multiple stderr envelopes mean
`terminal-envelope-undelivered` and an inconclusive terminal outcome.

If preparation succeeds internally but publishing its stdout receipt fails, the
guard rolls the unpublished workspace back. When that rollback also cannot be
proved, it persists an owner-private mode-`0600`, single-link external recovery
control before publishing the terminal stderr envelope. The control binds its
own exact identity/content, the parent and workspace identities, formal marker
digest, and original owner-process identity. The envelope contains a complete
executable `recover-partial-workspace` argv; a token digest, plaintext token, or
placeholder cleanup argv is not a recovery capability. The parent waits for the
failed guard process to exit, then may execute that exact route. A post-write
validation failure uses the original exact marker bytes during rollback; if a
late removal failure occurs after the marker was deleted, rollback restores that
formal marker before sealing the same owner-exit recovery route.

## Cleanup

Cleanup is the default after success, findings, blocked, or inconclusive termination. Retain a workspace only when the user explicitly requests diagnostic retention.

`cleanup-workspace` requires the preparation receipt's cleanup token and validates the marker-bound workspace, parent, and owner identities. It refuses a missing marker, token mismatch, path replacement, parent replacement, owner mismatch, or unexpected target instead of deleting by path alone. Complete removal is success.

Signals forwarded by the lane runtime remain blocked from the final
prepare/validate-to-return boundary until the caller publishes and flushes the
terminal receipt. Cleanup likewise masks quarantine rename, descriptor-bound
removal, failure-location publication, and the return-to-receipt handoff. A
pending signal never replaces an already frozen preparation or cleanup failure.
Mask restoration retries once; if both
owner-mediated attempts fail, an exact direct `SIG_SETMASK` fallback is automatic
recovery: success remains success and a frozen primary failure remains authoritative.
Only failure of that exact fallback while the owner remains active is a structured
signal-mask failure and hard-terminal condition for the guard process, never an
ordinary reusable-loop error.

Cleanup first moves the bound workspace to a short, exclusive, owner-parented
`.review-cleanup-*` quarantine name and removes it by descriptor without
crossing a mount boundary. If cleanup cannot finish, report `retained_path` only
after matching the exact workspace device/inode/UID beneath the still-bound
owner-private parent. The retained directory may itself have an invalid mode or
ACL; the error reports that policy drift so the parent can restore a private
policy and retry the same token-bound cleanup command. Otherwise report an
`expected_locator` containing the parent and workspace identity. Do not rename
an unproved quarantine back onto the public path and do not use a broad recursive
deletion as a fallback.
