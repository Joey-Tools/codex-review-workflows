from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
REUSABLE_HEADER = """name: Required CI

on:
  workflow_call:

"""
EXPECTED_REPOSITORY = "Joey-Tools/codex-review-workflows"
REPOSITORY_BINDING = f"repository: {EXPECTED_REPOSITORY}"
REF_BINDING = "ref: ${{ github.sha }}"
PERSIST_CREDENTIALS_BINDING = "persist-credentials: false"
REPOSITORY_GUARD = (
    "      - name: Reject unexpected repository\n"
    f"        if: ${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}\n"
    "        run: exit 1"
)


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
                    if key not in {"repository", "ref", "persist-credentials"}:
                        bound.append(field)
            bound.append(f"{field_indent}{PERSIST_CREDENTIALS_BINDING}\n")
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


def without_repository_guards(source: str) -> str:
    return source.replace(REPOSITORY_GUARD + "\n", "")


def top_level_permissions(source: str) -> object:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("permissions:"):
            continue
        scalar = line.removeprefix("permissions:").strip()
        if scalar:
            return scalar

        permissions: dict[str, str] = {}
        for entry in lines[index + 1 :]:
            if not entry.strip():
                continue
            if not entry.startswith("  "):
                break
            key, separator, value = entry.strip().partition(":")
            if not separator or not key or not value.strip() or key in permissions:
                return None
            permissions[key] = value.strip()
        return permissions
    return None


class RequiredCIWorkflowTests(unittest.TestCase):
    def test_reusable_entry_preserves_the_complete_required_test_graph(self) -> None:
        source = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")

        permissions = source.index("permissions:\n")
        expected = REUSABLE_HEADER + bind_checkout_inputs(source[permissions:])

        self.assertEqual(without_repository_guards(reusable), expected)

    def test_reusable_entry_is_read_only_and_caller_only(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertEqual(top_level_permissions(reusable), {"contents": "read"})
        self.assertNotIn("${{ secrets.", reusable)
        self.assertNotIn("inputs.repository", reusable)
        self.assertNotIn("inputs.ref", reusable)

        near_misses = {
            "issues write": reusable.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\n  issues: write\n",
                1,
            ),
            "pull requests write": reusable.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\n  pull-requests: write\n",
                1,
            ),
            "write all": reusable.replace(
                "permissions:\n  contents: read\n", "permissions: write-all\n", 1
            ),
        }
        for label, near_miss in near_misses.items():
            with self.subTest(label=label):
                self.assertNotEqual(
                    top_level_permissions(near_miss), {"contents": "read"}
                )

    def test_every_checkout_is_guarded_and_bound_to_the_exact_repository(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")
        blocks = checkout_step_blocks(reusable)

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertEqual(len(blocks), 4)
        self.assertEqual(reusable.count(REPOSITORY_GUARD), len(blocks))
        self.assertEqual(
            reusable.count(
                REPOSITORY_GUARD + "\n      - uses: actions/checkout@"
            ),
            len(blocks),
        )
        for block in blocks:
            self.assertEqual(block.count(REPOSITORY_BINDING), 1)
            self.assertEqual(block.count(REF_BINDING), 1)
            self.assertEqual(block.count(PERSIST_CREDENTIALS_BINDING), 1)
        self.assertNotIn("repository: ${{ github.repository }}", reusable)


if __name__ == "__main__":
    unittest.main()
