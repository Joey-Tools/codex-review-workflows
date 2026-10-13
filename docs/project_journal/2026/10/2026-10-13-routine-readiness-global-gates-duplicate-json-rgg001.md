---
id: 20261013-rgg001
title: Routine Readiness Global Gates and Duplicate JSON Keys
status: completed
created: 2026-10-13
updated: 2026-10-13
branch: wip/routine-readiness-global-gates-json-input-20261013
pr:
supersedes: []
superseded_by:
---

# Routine Readiness Global Gates and Duplicate JSON Keys

## Outcome

Queue retention now considers global scope, readiness, merge-policy, and
merge-group invalidations alongside evidence dependencies. Uncovered global-only
changes cancel/re-enroll; complete required-group coverage or a proven
non-bypassed hold is needed to retain an enrollment. Head, strict-base, and
retarget cancellation precedence remains unchanged. The planner rejects
duplicate JSON object keys for both stdin and file input instead of accepting
last-key-wins safety booleans.

## Validation

Python 3.10.19: 24 focused planner tests passed; 52 contract tests passed with
2 expected private-layout skips. Ruff, AST parsing, `git diff --check`, and
project-journal validation passed. The skill-validator wrapper exited 0, but
its dependency-resolution provenance was not captured; that result is not
treated as proof of a dependency-free environment. No full suite or remote CI
was run for this change.

Final parent validation on Python 3.10.19 passed all six related contract and
planner modules: 162 tests in 5.579 seconds, with 2 expected private-layout
skips. The bounded supervisor exited 0 with complete output; log SHA-256
`12685a91c9f78aa1621b4ef9e7e87312966a8a667aa3e7af29c4c027a8459b60`.
Actual CLI checks canceled an uncovered global-only queue change and rejected
duplicate bypass keys with exit 2. Both results remained planning-only, not
review or merge approval. Changed-source Ruff, source-only syntax, and
whitespace checks passed. Skill frontmatter remains byte-identical to the
independently trusted baseline (`7b43692a2b9da739c4a5098b35bd6a1043c87c626b34658b443ed8367eca50ae`);
this is unchanged-metadata evidence, not a fresh YAML parse.
