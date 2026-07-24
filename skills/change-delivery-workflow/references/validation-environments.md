# Validation Environment Selection

Read this reference when runtime or toolchain selection is material to the
gate, when the task may require local multi-version validation, or when build
and test results can depend on version-sensitive checkout, cache, or state.

The parent workflow's `local_mutation` ceiling applies before this reference.
When it is `forbidden`, do not create an isolated worktree, cache, generated
output, log, environment, or persistent state and do not run a versioned build
or test that may write any of them. Limit work to the parent's proven read-only
validation subset; report unavailable single- or multi-version gates instead of
materializing an environment for them.

## Select Single-Version Or Multi-Version Shape

A minimum supported version or CI matrix does not by itself require a local
multi-version gate. Select multi-version only when the user or repository policy
explicitly requires local multi-version validation, or when the change targets
cross-version compatibility. Otherwise select single-version.

Record the selected shape before resolving versions. Do not expand a
single-version gate merely because more runtimes are installed locally.

## Resolve The Highest-Priority Existing Authority

For either shape, select the highest-priority source that exists before deciding
whether its value parses, resolves, or is compatible. Once selected, resolve and
validate that source. If it is contradictory, ambiguous, open-ended, or
incompatible, fail closed; do not silently fall through to a lower-priority
source.

An instruction may explicitly delegate resolution to a named repository
mechanism such as `repo default`, a regular project runner, `all supported
versions`, or `CI matrix`. That mechanism remains part of the selected source;
it is not a fallback.

### Single-Version Authority

Use the first existing source:

1. the user's local-validation version instruction;
2. repository policy for the local-validation version;
3. a repository version-selection config or pin, where a compatibility range
   alone is not a selection pin;
4. the repository's regular runner or project-tool default resolution;
5. installed inventory.

The result must be exactly one version compatible with the project. When
installed inventory is selected, use the tool's canonical version ordering to
choose the highest compatible installed version. Include prereleases only when
the user or project constraint explicitly permits them.

### Multi-Version Authority

Use the first existing source:

1. the user's or current task's local multi-version instruction;
2. repository policy for local multi-version validation;
3. the repository's declared supported-version set;
4. the repository's CI matrix.

The result must be finite, non-empty, duplicate-free, and project-compatible.
Do not compare or merge lower-priority declarations after selecting the
authority; a different lower-priority set is not a conflict. An internal
contradiction, an open range that cannot resolve to a finite set, or an
unavailable selected version is a blocker. Never expand the set from installed
inventory.

Record the final version or set and its exact authority for the whole validation
round.

## Isolate Checkout, Cache, And State

Before running a multi-version set, identify checkout artifacts, caches, fixed
ports, and other machine-level mutable state.

- Reuse one checkout sequentially only when the suite is proven safe for that
  reuse.
- Give version-sensitive artifacts independent worktree, cache, and state roots,
  or explicitly clean and rebuild them between versions.
- Run fixed ports and other machine-shared resources concurrently only with a
  unique value or namespace for each run. Otherwise serialize them across every
  worktree.
- Clean or reset persistent machine-level state between versions only when it is
  proven task-owned and disposable. If ownership is shared, unknown, or unsafe
  to discard, report a blocker and request any additional authority explicitly.
- Run versions concurrently only after both checkout-local and machine-level
  resources are proven isolated.

Keep logs and results separately attributable to each version. Clean
task-scoped artifacts after recording results when safe, and report the exact
path of retained diagnostics.

## Evaluate And Report The Gate

Evaluate every selected environment independently. A failure in one version
does not become a pass because another succeeds. After a fix, rerun the failed
version and every version whose generated inputs or shared compatibility
behavior changed.

Report the selected shape, authoritative version or set, runtime/toolchain
identity, isolation method, checks that passed or failed, and every unavailable
or skipped gate. Never claim coverage that was not run.
