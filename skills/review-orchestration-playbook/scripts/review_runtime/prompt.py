from __future__ import annotations

import pathlib


def build_review_prompt(
    *,
    workspace: pathlib.Path,
    diff_file: pathlib.Path,
    base_ref: str,
    head_ref: str,
) -> str:
    return f"""Persistent isolated code-review contract:
- Workspace: {workspace}
- Primary diff file: {diff_file}
- Frozen review range: {base_ref}..{head_ref}
- The `.codex-review/` directory is helper-owned review evidence, not part of the change.

Review discipline:
- Review only the frozen range. Use the supplied diff as the primary review surface and read nearby repository files only when needed to verify a concrete concern.
- Do not read outside the detached workspace or inspect its parent directories, the source checkout, unrelated repositories, home-directory content, credentials, or untracked private files.
- Start with count-only probes, diff headers, --stat/--numstat, rg -l, rg --count, or exact symbol windows before printing changed-file lists or large hunks.
- Treat line-producing rg -n, including rg -n -C, as a second-stage read against one exact file, hunk, or symbol window after a count probe.
- Do not start with wide selected-file diffs, git diff -W, git diff --function-context, bare whole-file cat/nl/git-show reads, broad multi-file rg -n, or full untracked-file inventories.
- Before every tool call, rewrite a broad command into a count probe, one hunk, one exact symbol lookup, or a narrow sed window.
- After any 800+ line or 10k+ token result, narrow the next read instead of widening it.
- Focus on correctness, security, regressions, data loss, performance/resource risks, and missing tests.
- Skip style-only, naming-only, formatting-only, and speculative comments.
- Do not edit files, create commits, update pull requests, start other reviewers, or wait for CI.
- Do not run broad test/build/package-manager commands. A small targeted read-only probe is allowed only when necessary to validate a finding.
- A readonly-git or sandbox rejection is lane context, not a finding.

Output contract:
- Return findings only, ordered by severity, with file and line references when possible.
- If there are no actionable findings, reply exactly: No findings.
"""
