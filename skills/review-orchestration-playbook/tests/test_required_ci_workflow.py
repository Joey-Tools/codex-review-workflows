from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
REUSABLE_HEADER = """name: Required CI

on:
  workflow_call:
    inputs:
      repository:
        description: Repository whose exact ref Required CI validates.
        required: true
        type: string
      ref:
        description: Exact commit or ref Required CI validates.
        required: true
        type: string

"""
REPOSITORY_BINDING = "repository: ${{ inputs.repository }}"
REF_BINDING = "ref: ${{ inputs.ref }}"


def bind_checkout_inputs(source: str) -> str:
    lines = source.splitlines(keepends=True)
    bound: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        bound.append(line)
        stripped = line.lstrip()
        if stripped.startswith(("- uses: actions/checkout@", "uses: actions/checkout@")):
            step_indent = line[: len(line) - len(line.lstrip())]
            with_indent = f"{step_indent}  " if stripped.startswith("- uses:") else step_indent
            with_line = f"{with_indent}with:\n"
            field_indent = f"{with_indent}  "
            bound.extend(
                [
                    with_line,
                    f"{field_indent}{REPOSITORY_BINDING}\n",
                    f"{field_indent}{REF_BINDING}\n",
                ]
            )
            if index + 1 < len(lines) and lines[index + 1] == with_line:
                index += 1
                while index + 1 < len(lines) and lines[index + 1].startswith(field_indent):
                    index += 1
                    field = lines[index]
                    key = field[len(field_indent) :].split(":", 1)[0]
                    if key not in {"repository", "ref"}:
                        bound.append(field)
        index += 1
    return "".join(bound)


def checkout_step_blocks(source: str) -> list[str]:
    lines = source.splitlines(keepends=True)
    blocks: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith(("- uses: actions/checkout@", "uses: actions/checkout@")):
            continue
        use_indent = line[: len(line) - len(line.lstrip())]
        step_indent = use_indent if stripped.startswith("- uses:") else use_indent[:-2]
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.startswith(f"{step_indent}- "):
                break
            end += 1
        blocks.append("".join(lines[index:end]))
    return blocks


class RequiredCIWorkflowTests(unittest.TestCase):
    def test_reusable_entry_preserves_the_complete_required_test_graph(self) -> None:
        source = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")

        permissions = source.index("permissions:\n")
        expected = REUSABLE_HEADER + bind_checkout_inputs(source[permissions:])

        self.assertEqual(reusable, expected)

    def test_reusable_entry_is_read_only_and_caller_only(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertIn("permissions:\n  contents: read\n", reusable)
        self.assertNotIn("contents: write", reusable)
        self.assertNotIn("statuses: write", reusable)
        self.assertNotIn("${{ secrets.", reusable)

    def test_every_checkout_is_bound_to_the_closed_caller_inputs(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")
        blocks = checkout_step_blocks(reusable)

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertEqual(len(blocks), 4)
        for block in blocks:
            self.assertEqual(block.count(REPOSITORY_BINDING), 1)
            self.assertEqual(block.count(REF_BINDING), 1)


if __name__ == "__main__":
    unittest.main()
