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
                Path(temporary).resolve()
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
        action: str = "bind",
        token_id: str | None = None,
        expected: str | None = None,
        loaded_skill_root: Path | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-S",
            str(resolver),
            "--loaded-skill-root",
            str(loaded_skill_root or resolver.parents[1]),
        ]
        if expected is not None:
            arguments.extend(("--expect-binding-sha256", expected))
        arguments.append(action)
        if token_id is not None:
            arguments.append(token_id)
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
            cwd=cwd,
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
            "one controlled in-process transaction",
            "`--expect-binding-sha256` is mandatory",
            "only `bind` may omit it",
            "manifest-bound source snapshots",
            "never executes the returned Python or CLI path",
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
                "binding_resolver_identity",
                "review_skill_root",
                "review_runtime_tree_sha256",
                "catalog_cli_path",
                "catalog_cli_sha256",
                "catalog_cli_identity",
                "catalog_path",
                "catalog_sha256",
                "catalog_identity",
                "pool_version",
                "python_executable",
                "python_executable_sha256",
                "python_executable_identity",
                "python_version",
                "python_flags",
                "execution_mode",
                "import_mode",
                "binding_sha256",
            }
            self.assertEqual(set(binding), expected_fields)
            self.assertEqual(binding["schema_version"], 2)
            self.assertEqual(binding["release_id"], RELEASE_ID)
            self.assertEqual(binding["python_flags"], ["-I", "-B", "-S"])
            self.assertEqual(
                binding["execution_mode"],
                "in-process-manifest-bound-snapshot",
            )
            self.assertEqual(
                binding["import_mode"],
                "closed-review-runtime-snapshot",
            )
            for field in (
                "binding_resolver_identity",
                "catalog_cli_identity",
                "catalog_identity",
                "python_executable_identity",
            ):
                self.assertEqual(len(binding[field]), 5)
                self.assertTrue(all(isinstance(value, int) for value in binding[field]))
            self.assertEqual(
                Path(binding["release_root"]),
                release_root,
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

            for action in ("validate", "list"):
                with self.subTest(action=action):
                    completed = self.run_binding(
                        resolver,
                        action=action,
                        expected=binding["binding_sha256"],
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    transaction = json.loads(completed.stdout)
                    self.assertEqual(
                        set(transaction),
                        {
                            "schema_version",
                            "operation",
                            "binding",
                            "result",
                            "result_sha256",
                        },
                    )
                    self.assertEqual(transaction["schema_version"], 1)
                    self.assertEqual(transaction["operation"], action)
                    self.assertEqual(transaction["binding"], binding)
                    payload = transaction["result"]
                    self.assertEqual(
                        payload["pool_version"],
                        binding["pool_version"],
                    )

            listing = json.loads(
                self.run_binding(
                    resolver,
                    action="list",
                    expected=binding["binding_sha256"],
                ).stdout
            )["result"]
            self.assertTrue(listing["tokens"])
            self.assertTrue(all("value" not in token for token in listing["tokens"]))
            selected_id = sorted(token["id"] for token in listing["tokens"])[0]

            selected = self.run_binding(
                resolver,
                action="get",
                token_id=selected_id,
                expected=binding["binding_sha256"],
            )
            self.assertEqual(selected.returncode, 0, selected.stderr)
            selected_transaction = json.loads(selected.stdout)
            self.assertEqual(selected_transaction["operation"], "get")
            self.assertEqual(selected_transaction["binding"], binding)
            payload = selected_transaction["result"]
            self.assertEqual(payload["pool_version"], binding["pool_version"])
            self.assertEqual(payload["token"]["id"], selected_id)
            self.assertIsInstance(payload["token"]["value"], str)
            self.assertTrue(payload["token"]["value"])
            self.assertNotIn(payload["token"]["value"], json.dumps(listing))

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
            self.assertIn("non-symlink regular file", unsafe.stderr)
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

    def test_authoring_operations_require_the_captured_binding_digest(self) -> None:
        with self.installed_release() as release_root:
            resolver = (
                release_root
                / "personal_codex"
                / "skills"
                / "synthetic-token-fixtures"
                / "scripts"
                / "active_catalog_binding.py"
            )
            for action, token_id in (
                ("validate", None),
                ("list", None),
                ("get", "unused-token-id"),
            ):
                with self.subTest(action=action):
                    rejected = self.run_binding(
                        resolver,
                        action=action,
                        token_id=token_id,
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stdout, "")
                    self.assertIn(
                        "--expect-binding-sha256 is required for validate, list, and get",
                        rejected.stderr,
                    )

    def test_isolated_launch_blocks_stdlib_and_package_shadows(self) -> None:
        with self.installed_release() as release_root:
            synthetic_root = (
                release_root / "personal_codex" / "skills" / "synthetic-token-fixtures"
            )
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            with tempfile.TemporaryDirectory(
                prefix="synthetic-token-shadows-"
            ) as temporary:
                shadow_root = Path(temporary)
                marker = shadow_root / "executed"
                marker_literal = repr(str(marker))
                shadow_source = (
                    "from pathlib import Path\n"
                    f"Path({marker_literal}).write_text('executed', encoding='utf-8')\n"
                )
                (shadow_root / "json.py").write_text(
                    shadow_source,
                    encoding="utf-8",
                )
                (shadow_root / "argparse.py").write_text(
                    shadow_source,
                    encoding="utf-8",
                )
                (shadow_root / "review_runtime").mkdir()
                (shadow_root / "review_runtime" / "__init__.py").write_text(
                    shadow_source,
                    encoding="utf-8",
                )
                (resolver.parent / "json.py").write_text(
                    shadow_source,
                    encoding="utf-8",
                )
                (resolver.parent / "argparse.py").write_text(
                    shadow_source,
                    encoding="utf-8",
                )

                bound = self.run_binding(
                    resolver,
                    cwd=shadow_root,
                )
                self.assertEqual(bound.returncode, 0, bound.stderr)
                binding = json.loads(bound.stdout)
                captured = self.run_binding(
                    resolver,
                    action="list",
                    expected=binding["binding_sha256"],
                    cwd=shadow_root,
                )
                self.assertEqual(captured.returncode, 0, captured.stderr)
                self.assertFalse(marker.exists())

            review_scripts = (
                release_root
                / "personal_codex"
                / "skills"
                / "review-orchestration-playbook"
                / "scripts"
            )
            package_shadow = review_scripts / "review_runtime.py"
            package_shadow.write_text(
                "raise RuntimeError('package shadow executed')\n",
                encoding="utf-8",
            )
            rejected = self.run_binding(resolver)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("import shadow", rejected.stderr)
            self.assertNotIn("package shadow executed", rejected.stderr)

    def test_nonisolated_launch_stops_before_resolver_local_imports(self) -> None:
        with self.installed_release() as release_root:
            synthetic_root = (
                release_root / "personal_codex" / "skills" / "synthetic-token-fixtures"
            )
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            marker = synthetic_root / "scripts" / "argparse-shadow-executed"
            (resolver.parent / "argparse.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                (
                    str(Path(sys.executable).resolve()),
                    "-B",
                    "-S",
                    str(resolver),
                    "--loaded-skill-root",
                    str(synthetic_root),
                    "bind",
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                env=dict(os.environ),
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("requires an absolute Python interpreter", completed.stderr)
            self.assertFalse(marker.exists())

    def test_cross_release_symlinks_and_unsafe_scripts_parent_fail_closed(
        self,
    ) -> None:
        with self.installed_release() as first_release:
            with self.installed_release() as second_release:
                first_skill = (
                    first_release
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                )
                first_resolver = first_skill / "scripts" / "active_catalog_binding.py"
                second_resolver = (
                    second_release
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                    / "scripts"
                    / "active_catalog_binding.py"
                )
                second_skill = (
                    second_release
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                )
                wrong_loaded_skill = self.run_binding(
                    first_resolver,
                    loaded_skill_root=second_skill,
                )
                self.assertEqual(wrong_loaded_skill.returncode, 2)
                self.assertIn(
                    "explicitly loaded synthetic skill",
                    wrong_loaded_skill.stderr,
                )

                alias_release = first_release.parent / ("b" * 40)
                alias_release.symlink_to(first_release, target_is_directory=True)
                alias_skill = (
                    alias_release
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                )
                intermediate_symlink = self.run_binding(
                    alias_skill / "scripts" / "active_catalog_binding.py",
                    loaded_skill_root=alias_skill,
                )
                self.assertEqual(intermediate_symlink.returncode, 2)
                self.assertIn(
                    "not an ordinary non-symlink directory",
                    intermediate_symlink.stderr,
                )

                first_resolver.unlink()
                first_resolver.symlink_to(second_resolver)
                rejected = self.run_binding(
                    first_resolver,
                    loaded_skill_root=first_skill,
                )
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("non-symlink regular file", rejected.stderr)

        with self.installed_release() as release_root:
            synthetic_root = (
                release_root / "personal_codex" / "skills" / "synthetic-token-fixtures"
            )
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            scripts_root = resolver.parent
            scripts_root.chmod(0o775)
            try:
                rejected = self.run_binding(resolver)
            finally:
                scripts_root.chmod(0o755)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("scripts is group/world writable", rejected.stderr)

    def test_same_bytes_cli_path_replacement_cannot_release_a_result(self) -> None:
        with self.installed_release() as release_root:
            synthetic_root = (
                release_root / "personal_codex" / "skills" / "synthetic-token-fixtures"
            )
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            catalog_cli = (
                release_root
                / "personal_codex"
                / "skills"
                / "review-orchestration-playbook"
                / "scripts"
                / "isolated_review"
            )
            replacement = catalog_cli.with_name(f"{catalog_cli.name}.replacement")
            marker = catalog_cli.with_name("replacement-path-executed")
            wrapper = (
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n\n"
                "replacement = Path(__file__ + '.replacement')\n"
                f"marker = Path({str(marker)!r})\n"
                "if replacement.exists():\n"
                "    os.replace(replacement, __file__)\n"
                "else:\n"
                "    marker.write_text('executed', encoding='utf-8')\n\n"
                "if sys.version_info < (3, 10):\n"
                "    raise SystemExit(2)\n\n"
                "from review_runtime import main\n\n"
                "if __name__ == '__main__':\n"
                "    raise SystemExit(main())\n"
            )
            catalog_cli.write_text(wrapper, encoding="utf-8")
            replacement.write_text(wrapper, encoding="utf-8")

            bound = self.run_binding(resolver)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            binding = json.loads(bound.stdout)
            completed = self.run_binding(
                resolver,
                action="list",
                expected=binding["binding_sha256"],
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertIn("bound parent entry identity changed", completed.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
