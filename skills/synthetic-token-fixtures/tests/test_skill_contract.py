from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SKILL_ROOT.parents[1]
SKILL = SKILL_ROOT / "SKILL.md"
TEMPLATES = SKILL_ROOT / "references" / "fixture-templates.md"
CATALOG_CLI = (
    REPOSITORY_ROOT
    / "skills"
    / "review-orchestration-playbook"
    / "scripts"
    / "isolated_review"
)


class SyntheticTokenSkillContractTest(unittest.TestCase):
    def run_catalog_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (str(CATALOG_CLI), "synthetic-tokens", *arguments),
            cwd=REPOSITORY_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )

    def test_skill_routes_only_the_authoring_catalog_surface(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        templates = TEMPLATES.read_text(encoding="utf-8")
        normalized_skill = " ".join(skill.split())
        normalized_templates = " ".join(templates.split())
        for anchor in (
            "only machine authority",
            "routing and selection guidance only",
            "validate",
            "metadata-only",
            "single-ID",
            "does not define a pool",
            "Never create a project-local pool",
            "second CLI",
        ):
            self.assertIn(anchor, normalized_skill)
        for command in (
            "synthetic-tokens validate",
            "synthetic-tokens list --json",
            "synthetic-tokens get <id> --json",
        ):
            self.assertIn(command, normalized_skill)
            self.assertIn(command, normalized_templates)
        self.assertNotIn("synthetic-tokens list-exemptions", normalized_skill)
        self.assertNotIn("synthetic-tokens audit-master", normalized_skill)
        self.assertFalse((SKILL_ROOT / "scripts").exists())
        self.assertFalse((SKILL_ROOT / "synthetic-token-catalog.json").exists())

    def test_authoritative_cli_validate_list_and_get_contract(self) -> None:
        validation = self.run_catalog_cli("validate")
        self.assertEqual(validation.returncode, 0, validation.stderr)
        self.assertEqual(json.loads(validation.stdout)["status"], "valid")

        listing = self.run_catalog_cli("list", "--json")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        listed = json.loads(listing.stdout)
        self.assertEqual(set(listed), {"pool_version", "tokens"})
        self.assertTrue(listed["tokens"])
        self.assertTrue(all("value" not in token for token in listed["tokens"]))

        selected_id = sorted(token["id"] for token in listed["tokens"])[0]
        selected = self.run_catalog_cli("get", selected_id, "--json")
        self.assertEqual(selected.returncode, 0, selected.stderr)
        payload = json.loads(selected.stdout)
        self.assertEqual(payload["token"]["id"], selected_id)
        self.assertIsInstance(payload["token"]["value"], str)
        self.assertTrue(payload["token"]["value"])
        self.assertNotIn(payload["token"]["value"], listing.stdout)


if __name__ == "__main__":
    unittest.main()
