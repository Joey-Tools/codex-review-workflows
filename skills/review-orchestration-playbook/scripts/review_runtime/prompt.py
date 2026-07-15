from __future__ import annotations

import pathlib


def build_review_prompt(
    *,
    workspace: pathlib.Path,
    diff_file: pathlib.Path,
    base_ref: str,
    head_ref: str,
) -> str:
    relative_diff = diff_file.relative_to(workspace).as_posix()
    return f"""Persistent isolated code-review contract:
- Workspace: .
- Primary diff file: {relative_diff}
- Frozen review range: {base_ref}..{head_ref}
- The `.codex-review/` directory is helper-owned review evidence, not part of the change.

Review discipline:
- Review only the frozen range. Use the supplied diff as the primary review surface and read nearby repository files only when needed to verify a concrete concern.
- Do not read outside the detached workspace or inspect its parent directories, the source checkout, unrelated repositories, home-directory content, credentials, or untracked private files.
- Use only the tools exposed by the reviewer. If `Read` is the only file tool, read the primary diff and any necessary nearby file in bounded offset/limit windows; do not request unavailable search, shell, Git, or LSP tools.
- When count, search, or read-only Git tools are available, start with count-only probes, diff headers, --stat/--numstat, rg -l, rg --count, or exact symbol windows before printing changed-file lists or large hunks.
- Treat line-producing rg -n, including rg -n -C, as a second-stage read against one exact file, hunk, or symbol window after a count probe, and only when that tool is available.
- Do not start with wide selected-file diffs, git diff -W, git diff --function-context, bare whole-file cat/nl/git-show reads, broad multi-file rg -n, or full untracked-file inventories, even when those tools are available.
- Before every tool call, rewrite a broad read into a count probe, one bounded Read window, one hunk, one exact symbol lookup, or a narrow sed window supported by the current tool set.
- After any 800+ line or 10k+ token result, narrow the next read instead of widening it.
- Focus on correctness, security, regressions, data loss, performance/resource risks, and missing tests.
- Skip style-only, naming-only, formatting-only, and speculative comments.
- Do not edit files, create commits, update pull requests, start other reviewers, or wait for CI.
- Do not run broad test/build/package-manager commands. A small targeted read-only probe is allowed only when the reviewer exposes it and it is necessary to validate a finding.
- A readonly-git or sandbox rejection is lane context, not a finding.

Output contract:
- Return findings only, ordered by severity, with file and line references when possible.
- If there are no actionable findings, reply exactly: No findings.
"""
