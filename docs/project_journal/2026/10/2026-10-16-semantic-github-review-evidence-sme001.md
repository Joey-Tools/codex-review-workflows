---
id: 20261016-sme001
title: Semantic GitHub Codex Review Evidence
status: completed
created: 2026-10-16
updated: 2026-10-16
branch: codex/semantic-github-review-evidence-20261016
pr:
supersedes: []
superseded_by:
---

# Semantic GitHub Codex Review Evidence

## Outcome

The agent-facing GitHub Codex authority uses the meaning of complete provider
evidence instead of requiring an exact comment template, clean phrase, heading,
disclosure URL, or report shape. It retains authenticated provider identity,
current-head binding, complete finding/thread acquisition, typed resolution,
finding precedence, and a stable final reread. An older running aggregate does
not alone veto a later independently bound terminal result.

The former deterministic contract remains separately available as
`github-codex-machine-evidence-v1.md`. Its carrier JSON and reference classifier
behavior are unchanged; existing machine-contract tests follow its new path.
One obsolete exact-sentence assertion on the agent's skill text was removed,
not replaced with another prose assertion. Semantic interpretation does not
alter required CI, Actions recovery authority, or an installed parser.

## Evidence And Validation

- Reference: [HDR-streaming #362](https://github.com/Joey-Project/HDR-streaming/pull/362),
  observed head `08e06e81c38b05d6aef1f99f95f30053dd77728f`. Provider comment
  `6215253329` carries the current reviewed commit and changed closing prose;
  comment `6214878659` has another closing and an older reviewed commit.
  The seven-comment API page SHA-256 is
  `c371263cc066b903782bce021c449c3cad249e4f865b7c958b44cab3b0ef4b1f`;
  reviews and inline collections were each empty. This is format evidence,
  not a merge-readiness or installation claim for that PR.
- Python 3.13.0: both GitHub reference modules passed 68 tests in 7.056s
  (log SHA-256 `92bc15b3b92803ec6f597b5139604b7ae64be06c46a77263da421bd65e405d23`).
  The repository contract module passed 52 tests in 3.897s, including two
  expected private-layout skips
  (`6b7639e8589cde9f8427097f91f998dd1c546f0cdb1400415d12ba65a965a4c7`).
  Initial failures from old document paths and the obsolete phrase assertion
  were corrected before these successful runs; no failed run is counted as pass.
- A GPT-6 Luna High support agent applied only the candidate authority to
  16 hypothetical cases without seeing expected classifications. All matched
  the parent-checked expectations, including unfamiliar clean prose, stale
  commits, wrong actors, pending/error states, unresolved findings, corrections,
  unbound short SHAs, and untrusted embedded instructions. This was a skill
  forward-use exercise, not formal local review or live GitHub acceptance.
- The installed skill-authoring wrapper returned `Skill is valid!` through its
  isolated `uv` validator path. Changed-test Ruff, source-only compilation,
  scenario JSON checks, and whitespace checks passed. The versioned carrier
  JSON has no diff from baseline `99c86dbfdf19c5e4ef8e12799f8c4aac6c1b2781`.

No full runtime suite, remote review, or CI was run for this documentation and
test-reference-path change. No GitHub writes, installed-skill changes, parser
deployment, source sync, release, or native installation is included.
