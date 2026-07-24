from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SKILL_ROOT.parents[1]
REVIEW_SKILL_ROOT = REPOSITORY_ROOT / "skills" / "review-orchestration-playbook"
SKILL = SKILL_ROOT / "SKILL.md"
TEMPLATES = SKILL_ROOT / "references" / "fixture-templates.md"
BINDING_RESOLVER = SKILL_ROOT / "scripts" / "active_catalog_binding.py"
RELEASE_ID = "a" * 40


class SyntheticTokenSkillContractTest(unittest.TestCase):
    @contextlib.contextmanager
    def installed_release(self):
        with tempfile.TemporaryDirectory(
            prefix="synthetic-token-release-"
        ) as temporary:
            release_root = (
                Path(temporary)
                / "personal-sync"
                / "overlays"
                / "private"
                / "releases"
                / RELEASE_ID
            )
            skills_root = release_root / "personal_codex" / "skills"
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
            shutil.copytree(
                SKILL_ROOT,
                skills_root / "synthetic-token-fixtures",
                ignore=ignore,
            )
            shutil.copytree(
                REVIEW_SKILL_ROOT,
                skills_root / "review-orchestration-playbook",
                ignore=ignore,
            )
            manifest = {
                "version": 1,
                "links": [
                    {
                        "source": "personal_codex/skills/review-orchestration-playbook",
                        "target": "skills/review-orchestration-playbook",
                        "kind": "skill",
                    },
                    {
                        "source": "personal_codex/skills/synthetic-token-fixtures",
                        "target": "skills/synthetic-token-fixtures",
                        "kind": "skill",
                    },
                ],
            }
            (release_root / "personal_codex" / "sync-manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            yield release_root

    def run_binding(
        self,
        resolver: Path,
        *,
        expected: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(Path(sys.executable).resolve()),
            "-E",
            "-B",
            "-s",
            "-S",
            str(resolver),
        ]
        if expected is not None:
            arguments.extend(("--expect-binding-sha256", expected))
        environment = dict(os.environ)
        environment.update(
            {
                "CODEX_HOME": "/decoy/codex-home",
                "HOME": "/decoy/home",
                "PYTHONPATH": "/decoy/pythonpath",
            }
        )
        return subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            env=environment,
        )

    @staticmethod
    def run_bound_catalog_cli(
        binding: dict[str, object], *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (
                str(binding["python_executable"]),
                "-E",
                "-B",
                "-s",
                "-S",
                str(binding["catalog_cli_path"]),
                "synthetic-tokens",
                *arguments,
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            env={
                "HOME": "/decoy/home",
                "CODEX_HOME": "/decoy/codex-home",
                "PATH": "/usr/bin:/bin",
            },
        )

    def test_skill_routes_only_bound_authoring_catalog_surface(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        templates = TEMPLATES.read_text(encoding="utf-8")
        normalized_skill = " ".join(skill.split())
        normalized_templates = " ".join(templates.split())
        for anchor in (
            "only machine authority",
            "routing and selection guidance only",
            "same active immutable release",
            "macOS or Linux personal-sync",
            "skill-relative",
            "release `sync-manifest.json` installs both skill sources",
            "binding_sha256",
            "review-runtime tree digest",
            "metadata-only",
            "single-ID",
            "does not define a pool",
            "Never create a project-local pool",
            "second token CLI",
            "never accepts a catalog or review-skill path",
            "POSIX no-follow, nonblocking, close-on-exec",
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
        self.assertNotIn("${CODEX_HOME", skill)
        self.assertNotIn("${HOME", skill)
        self.assertTrue(BINDING_RESOLVER.is_file())
        self.assertFalse((SKILL_ROOT / "synthetic-token-catalog.json").exists())

    def test_release_binding_drives_authoritative_validate_list_and_get(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            resolver = (
                release_root
                / "personal_codex"
                / "skills"
                / "synthetic-token-fixtures"
                / "scripts"
                / "active_catalog_binding.py"
            )
            captured = self.run_binding(resolver)
            self.assertEqual(captured.returncode, 0, captured.stderr)
            binding = json.loads(captured.stdout)
            expected_fields = {
                "schema_version",
                "release_id",
                "release_root",
                "sync_manifest_path",
                "sync_manifest_sha256",
                "synthetic_skill_root",
                "synthetic_skill_sha256",
                "binding_resolver_path",
                "binding_resolver_sha256",
                "review_skill_root",
                "review_runtime_tree_sha256",
                "catalog_cli_path",
                "catalog_cli_sha256",
                "catalog_path",
                "catalog_sha256",
                "pool_version",
                "python_executable",
                "python_executable_sha256",
                "python_version",
                "binding_sha256",
            }
            self.assertEqual(set(binding), expected_fields)
            self.assertEqual(binding["schema_version"], 1)
            self.assertEqual(binding["release_id"], RELEASE_ID)
            self.assertEqual(
                Path(binding["release_root"]),
                release_root.resolve(),
            )
            self.assertEqual(
                Path(binding["review_skill_root"]).parent,
                Path(binding["synthetic_skill_root"]).parent,
            )
            for field in (
                "synthetic_skill_sha256",
                "sync_manifest_sha256",
                "binding_resolver_sha256",
                "review_runtime_tree_sha256",
                "catalog_cli_sha256",
                "catalog_sha256",
                "python_executable_sha256",
                "binding_sha256",
            ):
                self.assertRegex(binding[field], r"^[0-9a-f]{64}$")

            for arguments in (
                ("validate",),
                ("list", "--json"),
            ):
                with self.subTest(arguments=arguments):
                    before = self.run_binding(
                        resolver, expected=binding["binding_sha256"]
                    )
                    self.assertEqual(before.returncode, 0, before.stderr)
                    completed = self.run_bound_catalog_cli(binding, *arguments)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    payload = json.loads(completed.stdout)
                    self.assertEqual(
                        payload["pool_version"],
                        binding["pool_version"],
                    )
                    after = self.run_binding(
                        resolver, expected=binding["binding_sha256"]
                    )
                    self.assertEqual(after.returncode, 0, after.stderr)

            listing = json.loads(
                self.run_bound_catalog_cli(binding, "list", "--json").stdout
            )
            self.assertTrue(listing["tokens"])
            self.assertTrue(all("value" not in token for token in listing["tokens"]))
            selected_id = sorted(token["id"] for token in listing["tokens"])[0]

            before_get = self.run_binding(resolver, expected=binding["binding_sha256"])
            self.assertEqual(before_get.returncode, 0, before_get.stderr)
            selected = self.run_bound_catalog_cli(binding, "get", selected_id, "--json")
            self.assertEqual(selected.returncode, 0, selected.stderr)
            payload = json.loads(selected.stdout)
            self.assertEqual(payload["pool_version"], binding["pool_version"])
            self.assertEqual(payload["token"]["id"], selected_id)
            self.assertIsInstance(payload["token"]["value"], str)
            self.assertTrue(payload["token"]["value"])
            self.assertNotIn(payload["token"]["value"], json.dumps(listing))
            after_get = self.run_binding(resolver, expected=binding["binding_sha256"])
            self.assertEqual(after_get.returncode, 0, after_get.stderr)

    def test_binding_fails_closed_on_release_drift_or_ambiguous_layout(self) -> None:
        with self.installed_release() as release_root:
            resolver = (
                release_root
                / "personal_codex"
                / "skills"
                / "synthetic-token-fixtures"
                / "scripts"
                / "active_catalog_binding.py"
            )
            captured = self.run_binding(resolver)
            self.assertEqual(captured.returncode, 0, captured.stderr)
            binding = json.loads(captured.stdout)

            catalog = Path(binding["catalog_path"])
            catalog.write_bytes(catalog.read_bytes() + b"\n")
            changed = self.run_binding(resolver, expected=binding["binding_sha256"])
            self.assertEqual(changed.returncode, 2)
            self.assertIn("active catalog binding changed", changed.stderr)

        with self.installed_release() as release_root:
            resolver = (
                release_root
                / "personal_codex"
                / "skills"
                / "synthetic-token-fixtures"
                / "scripts"
                / "active_catalog_binding.py"
            )
            catalog = (
                release_root
                / "personal_codex"
                / "skills"
                / "review-orchestration-playbook"
                / "scripts"
                / "review_runtime"
                / "synthetic-token-catalog.json"
            )
            catalog_bytes = catalog.read_bytes()
            catalog.unlink()
            os.mkfifo(catalog)
            started = time.monotonic()
            unsafe = self.run_binding(resolver)
            elapsed = time.monotonic() - started
            self.assertEqual(unsafe.returncode, 2)
            self.assertLess(elapsed, 2.0)
            self.assertIn("not a regular file", unsafe.stderr)
            catalog.unlink()
            catalog.write_bytes(catalog_bytes)

            manifest_path = release_root / "personal_codex" / "sync-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["links"].append(
                {
                    "source": "personal_codex/skills/other-review",
                    "target": "skills/review-orchestration-playbook",
                    "kind": "skill",
                }
            )
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            ambiguous = self.run_binding(resolver)
            self.assertEqual(ambiguous.returncode, 2)
            self.assertIn("ambiguous authority link", ambiguous.stderr)

        with tempfile.TemporaryDirectory(
            prefix="synthetic-token-nonrelease-"
        ) as temporary:
            copied = Path(temporary) / "synthetic-token-fixtures"
            shutil.copytree(
                SKILL_ROOT,
                copied,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            rejected = self.run_binding(
                copied / "scripts" / "active_catalog_binding.py"
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("release payload", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
