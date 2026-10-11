---
id: 20261011-proc001
title: Private Layout Report-Only Contract Compatibility
status: completed
created: 2026-10-11
updated: 2026-10-11
branch: wip/private-layout-report-only-contract-20261011
pr:
supersedes: []
superseded_by:
---

# Private Layout Report-Only Contract Compatibility

## Outcome

The report-only contract test inspects a closed noun list governed by the
negative verb in the unique bare named-review AGENTS rule. The permitted prefix
and complete suffix must match the selected layout's declared policy;
truncating at punctuation cannot hide an added grant. The private suffix is
read as literal bytes from its producer declaration using AST, without executing
the producer or copying its long policy into this suite. Its normalized prefix
and suffix additionally bind an independent SHA-256 from reviewed private PR222,
merge `b47a626b0f6e4432af466be97d52ef8b903fb451`; jointly changing the producer
and generated policy cannot silently redefine this expected boundary.

The canonical profile requires five prohibitions. The private profile separately
requires branch mutation, metadata changes, Actions reruns, dispatch,
reconciliation and unrelated mutation as well. Composite entries retain each
operation instead of collapsing private restrictions to canonical aliases.
Unrecognised entries, added predicates, exceptions and conditional grants fail
closed. Denial-list conjunctions may differ; runtime policy is unchanged.

A regression accepts both canonical and private wording. Removing any one of
the five operations from either denial remains detectable even when a later,
unrelated rule mentions that operation. Twenty adversarial grants and
exceptions also remain rejected; they reproduced the review finding before
the correction. Fifteen prefix/suffix grants and the lost private composite
denials also reproduced failure before the subsequent correction. Private
operation omissions and a canonical-only list cannot satisfy the private
expected set. Three coupled producer/policy grants reproduced the independent
baseline finding, then fail closed after boundary pinning. No existing test
method is removed.
Production controls, generated private policy, CI, and authorization rules
are unchanged.

## Validation

Python 3.13.0 passed 138 relevant canonical contract, carrier, recovery,
local-lane, and trusted-manifest tests (two private-layout-only skips).
The stock private text replacement function was independently checked against
the existing generated test, then used in memory to project this successor.
All 52 repository contracts passed against the real private layout, including
its CI matrix; no generated file was edited for this proof.
Selected Ruff, skill metadata, journal frontmatter, and whitespace checks pass.
These results do not claim remote review, platform CI, or private release
completion; PR lifecycle evidence remains in the PR body.

## Evidence

- Canonical source: review-workflows PR135, merge
  `8e29e9f50c967d5943565117384c3e5ef4920d9c`.
- The private source-sync repair exposed the sentence mismatch after the two
  newly routed documents passed its updated exact inventory and full generator.
  This canonical test fix must land before the private source pin advances.
