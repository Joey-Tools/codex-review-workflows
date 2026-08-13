from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
REUSABLE_HEADER = "name: Required CI\n\non:\n  workflow_call:\n\n"


class RequiredCIWorkflowTests(unittest.TestCase):
    def test_reusable_entry_preserves_the_complete_required_test_graph(self) -> None:
        source = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")

        permissions = source.index("permissions:\n")
        expected = REUSABLE_HEADER + source[permissions:]

        self.assertEqual(reusable, expected)

    def test_reusable_entry_is_read_only_and_caller_only(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertIn("permissions:\n  contents: read\n", reusable)
        self.assertNotIn("contents: write", reusable)
        self.assertNotIn("statuses: write", reusable)
        self.assertNotIn("${{ secrets.", reusable)


if __name__ == "__main__":
    unittest.main()
