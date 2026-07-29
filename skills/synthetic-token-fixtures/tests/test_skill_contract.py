from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
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
BINDING_GUARD = REVIEW_SKILL_ROOT / "scripts" / "named_lane_guard"
CATALOG_BOOTSTRAP = (
    REVIEW_SKILL_ROOT / "scripts" / "review_runtime" / "catalog_bootstrap.py"
)
REVIEW_REFERENCE = REVIEW_SKILL_ROOT / "references" / "synthetic-token-fixtures.md"
RELEASE_ID = "a" * 40
RUNTIME_MANIFEST_RELATIVE = (
    Path("scripts") / "review_runtime" / "synthetic-catalog-runtime-manifest.json"
)


class SyntheticTokenSkillContractTest(unittest.TestCase):
    def load_catalog_bootstrap(self):
        spec = importlib.util.spec_from_file_location(
            "_synthetic_token_test_catalog_bootstrap",
            CATALOG_BOOTSTRAP,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def literal_assignment(self, source: Path, name: str):
        syntax = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for statement in syntax.body:
            if not isinstance(statement, ast.Assign):
                continue
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in statement.targets
            ):
                return ast.literal_eval(statement.value)
        self.fail(f"{source} does not define {name}")

    def normalized_function_ast(self, source: Path, name: str) -> str:
        syntax = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        function = next(
            (
                statement
                for statement in syntax.body
                if isinstance(statement, ast.FunctionDef) and statement.name == name
            ),
            None,
        )
        self.assertIsNotNone(function, f"{source} does not define {name}")
        normalized = ast.unparse(function).replace(
            "BindingError",
            "CatalogBootstrapError",
        )
        return ast.dump(
            ast.parse(normalized).body[0],
            include_attributes=False,
        )

    def rotate_runtime_manifest(
        self,
        review_root: Path,
        *,
        changed_relative_paths: tuple[Path, ...] = (),
        mutate_manifest=None,
        provision_guard: bool = True,
    ) -> str:
        manifest_path = review_root / RUNTIME_MANIFEST_RELATIVE
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        changed = {path.as_posix() for path in changed_relative_paths}
        records = [manifest["entrypoint"], *manifest["sources"], *manifest["data"]]
        for record in records:
            if record["path"] in changed:
                record["sha256"] = hashlib.sha256(
                    (review_root / record["path"]).read_bytes()
                ).hexdigest()
                changed.remove(record["path"])
        self.assertEqual(changed, set())
        if mutate_manifest is not None:
            mutate_manifest(manifest)
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if not provision_guard:
            return manifest_sha256
        guard = review_root / "scripts" / "named_lane_guard"
        source = guard.read_text(encoding="utf-8")
        updated, count = re.subn(
            (
                r'(_CATALOG_RUNTIME_MANIFEST_SHA256 = \(\n\s*")'
                r"[0-9a-f]{64}"
                r'("\n\))'
            ),
            rf"\g<1>{manifest_sha256}\g<2>",
            source,
        )
        self.assertEqual(count, 1)
        guard.write_text(updated, encoding="utf-8")
        return manifest_sha256

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
        guard = (
            resolver.parents[2]
            / "review-orchestration-playbook"
            / "scripts"
            / "named_lane_guard"
        )
        arguments = [
            str(Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-S",
            str(guard),
            "catalog-bootstrap",
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

    def add_macos_acl(self, path: Path, rule: str) -> None:
        completed = subprocess.run(
            ("/bin/chmod", "+a", rule, str(path)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0 and "not supported" in completed.stderr.lower():
            self.skipTest(
                f"test filesystem does not support macOS ACLs: {completed.stderr}"
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def remove_macos_acl(self, path: Path) -> None:
        completed = subprocess.run(
            ("/bin/chmod", "-N", str(path)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @contextlib.contextmanager
    def macos_acl(self, path: Path, rule: str):
        self.add_macos_acl(path, rule)
        try:
            yield
        finally:
            self.remove_macos_acl(path)

    def test_skill_routes_only_bound_authoring_catalog_surface(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        templates = TEMPLATES.read_text(encoding="utf-8")
        review_reference = REVIEW_REFERENCE.read_text(encoding="utf-8")
        normalized_skill = " ".join(skill.split())
        normalized_templates = " ".join(templates.split())
        for anchor in (
            "only machine authority",
            "routing and selection guidance only",
            "same active immutable release",
            "macOS or Linux personal-sync",
            "previously trusted release",
            "canonical control manifest",
            "dedicated catalog entry",
            "trusted runtime manifest",
            "co-release `sync-manifest.json`",
            "binding_sha256",
            "exact runtime closure",
            "metadata-only",
            "single-ID",
            "does not define a pool",
            "Never create a project-local pool",
            "second token CLI",
            "never accepts a catalog or review-skill path",
            "O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC",
            "one controlled in-process transaction",
            "extended-ACL allow entry",
            "owner's UUID",
            "descriptor-scoped `fstatfs`",
            "selected security flags",
            "timestamp and directory-entry churn",
            "`--expect-binding-sha256` is mandatory",
            "only `bind` may omit it",
            "manifest-bound source snapshots",
            "ignore `__pycache__`",
            "never load bytecode",
            "never executes the resolver",
            "never executes the resolver or returned CLI as a path",
        ):
            self.assertIn(anchor, normalized_skill)
        self.assertIn("Resolver action `validate`", normalized_skill)
        self.assertIn("synthetic-tokens validate", normalized_templates)
        for command in (
            "synthetic-tokens list --json",
            "synthetic-tokens get <id> --json",
        ):
            self.assertIn(command, normalized_skill)
            self.assertIn(command, normalized_templates)
        self.assertNotIn("synthetic-tokens list-exemptions", normalized_skill)
        self.assertNotIn("synthetic-tokens audit-master", normalized_skill)
        for retired_surface in (
            "--synthetic-secret-exemption",
            "synthetic-tokens list-exemptions",
            "synthetic-tokens audit-master",
            "## Legacy Compatibility Boundary",
            "| `access-a` |",
        ):
            self.assertNotIn(retired_surface, skill)
            self.assertNotIn(retired_surface, review_reference)
        self.assertNotIn("${CODEX_HOME", skill)
        self.assertNotIn("${HOME", skill)
        self.assertTrue(BINDING_RESOLVER.is_file())
        self.assertTrue(BINDING_GUARD.is_file())
        self.assertFalse((SKILL_ROOT / "synthetic-token-catalog.json").exists())

    def test_linux_acl_filesystem_classification_is_closed_and_co_release(self) -> None:
        expected_posix = {
            0x0000EF53: "ext2/ext3/ext4",
            0x01021994: "tmpfs",
            0x58465342: "XFS",
            0x858458F6: "ramfs",
            0x9123683E: "Btrfs",
            0xF2F52010: "F2FS",
        }
        expected_unverified = {
            0x01021997: "9P",
            0x2FC12FC1: "ZFS",
            0x5346414F: "AFS",
            0x65735546: "FUSE",
            0x00006969: "NFS/NFSv4",
            0x73757245: "CODA",
            0x794C7630: "overlayfs",
            0xFF534D42: "CIFS/SMB",
        }
        for function_name in (
            "_linux_statfs_api",
            "_linux_filesystem_type",
            "_require_linux_posix_acl_filesystem",
            "_validate_access_policy",
        ):
            with self.subTest(shared_function=function_name):
                self.assertEqual(
                    self.normalized_function_ast(
                        BINDING_RESOLVER,
                        function_name,
                    ),
                    self.normalized_function_ast(
                        CATALOG_BOOTSTRAP,
                        function_name,
                    ),
                )
        for source in (BINDING_RESOLVER, CATALOG_BOOTSTRAP):
            with self.subTest(source=source.name):
                self.assertEqual(
                    self.literal_assignment(
                        source,
                        "_LINUX_POSIX_ACL_FILESYSTEMS",
                    ),
                    expected_posix,
                )
                self.assertEqual(
                    self.literal_assignment(
                        source,
                        "_LINUX_UNVERIFIED_ACL_FILESYSTEMS",
                    ),
                    expected_unverified,
                )
                syntax = ast.parse(
                    source.read_text(encoding="utf-8"),
                    filename=str(source),
                )
                access_policy = next(
                    statement
                    for statement in syntax.body
                    if isinstance(statement, ast.FunctionDef)
                    and statement.name == "_validate_access_policy"
                )
                called_names = {
                    node.func.id
                    for node in ast.walk(access_policy)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                }
                self.assertIn("_linux_filesystem_type", called_names)
                self.assertIn(
                    "_require_linux_posix_acl_filesystem",
                    called_names,
                )

        bootstrap = self.load_catalog_bootstrap()
        for filesystem_type in expected_posix:
            with self.subTest(allowed=hex(filesystem_type)):
                bootstrap._require_linux_posix_acl_filesystem(
                    filesystem_type,
                    label="release object",
                )
        for filesystem_type, filesystem_name in expected_unverified.items():
            with self.subTest(rejected=filesystem_name):
                with self.assertRaisesRegex(
                    bootstrap.CatalogBootstrapError,
                    rf"filesystem {re.escape(filesystem_name)} .*"
                    r"has unverified ACL semantics",
                ):
                    bootstrap._require_linux_posix_acl_filesystem(
                        filesystem_type,
                        label="release object",
                    )
        with self.assertRaisesRegex(
            bootstrap.CatalogBootstrapError,
            r"filesystem unknown \(0xdeadbeef\) has unverified ACL semantics",
        ):
            bootstrap._require_linux_posix_acl_filesystem(
                0xDEADBEEF,
                label="release object",
            )

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "Linux descriptor-scoped fstatfs contract",
    )
    def test_linux_descriptor_filesystem_acl_model_fails_closed(self) -> None:
        bootstrap = self.load_catalog_bootstrap()
        descriptor = os.open(
            CATALOG_BOOTSTRAP,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            filesystem_type = bootstrap._linux_filesystem_type(
                descriptor,
                label="catalog bootstrap",
            )
        finally:
            os.close(descriptor)
        if filesystem_type in bootstrap._LINUX_POSIX_ACL_FILESYSTEMS:
            bootstrap._require_linux_posix_acl_filesystem(
                filesystem_type,
                label="catalog bootstrap",
            )
        else:
            with self.assertRaisesRegex(
                bootstrap.CatalogBootstrapError,
                r"has unverified ACL semantics",
            ):
                bootstrap._require_linux_posix_acl_filesystem(
                    filesystem_type,
                    label="catalog bootstrap",
                )

    def test_catalog_values_are_not_handwritten_outside_the_catalog(self) -> None:
        catalog_path = (
            REVIEW_SKILL_ROOT
            / "scripts"
            / "review_runtime"
            / "synthetic-token-catalog.json"
        )
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        tokens = tuple(
            (item["id"], item["value"]) for item in catalog["authoring_pool"]["tokens"]
        )
        sources = (
            *REVIEW_SKILL_ROOT.rglob("*.py"),
            *REVIEW_SKILL_ROOT.rglob("*.md"),
            *SKILL_ROOT.rglob("*.py"),
            *SKILL_ROOT.rglob("*.md"),
        )
        for source in sources:
            text = source.read_text(encoding="utf-8")
            for token_id, value in tokens:
                self.assertNotIn(
                    value,
                    text,
                    f"catalog value {token_id} is duplicated in {source}",
                )

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
                "catalog_bootstrap",
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
                "catalog_runtime_profile",
                "catalog_runtime_version",
                "catalog_runtime_manifest_path",
                "catalog_runtime_manifest_sha256",
                "catalog_runtime_manifest_identity",
                "catalog_runtime_files",
                "catalog_entry_path",
                "catalog_entry_sha256",
                "catalog_entry_identity",
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
            self.assertEqual(binding["schema_version"], 4)
            self.assertEqual(binding["release_id"], RELEASE_ID)
            self.assertEqual(binding["python_flags"], ["-I", "-B", "-S"])
            self.assertEqual(
                binding["catalog_bootstrap"]["mode"],
                "trusted-guard-manifest-bound-source",
            )
            self.assertEqual(
                binding["catalog_bootstrap"]["resolver_sha256"],
                binding["binding_resolver_sha256"],
            )
            self.assertEqual(
                binding["execution_mode"],
                "trusted-manifest-bound-source-snapshot",
            )
            self.assertEqual(
                binding["import_mode"],
                "exact-closed-runtime-manifest",
            )
            self.assertEqual(
                binding["catalog_runtime_profile"],
                "synthetic-catalog-authoring-v1",
            )
            self.assertEqual(binding["catalog_runtime_version"], 1)
            for field in (
                "binding_resolver_identity",
                "catalog_runtime_manifest_identity",
                "catalog_entry_identity",
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
                "catalog_runtime_manifest_sha256",
                "catalog_entry_sha256",
                "catalog_sha256",
                "python_executable_sha256",
                "binding_sha256",
            ):
                self.assertRegex(binding[field], r"^[0-9a-f]{64}$")
            runtime_files = binding["catalog_runtime_files"]
            self.assertEqual(len(runtime_files), 6)
            self.assertEqual(
                {record["kind"] for record in runtime_files},
                {"source", "entrypoint", "data"},
            )
            self.assertEqual(
                {
                    record["module"]
                    for record in runtime_files
                    if record["kind"] == "source"
                },
                {
                    "review_runtime",
                    "review_runtime.common",
                    "review_runtime.cli",
                    "review_runtime.synthetic_tokens",
                },
            )

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

    def test_decoy_bytecode_cache_is_ignored_by_closed_authoring_loader(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            cache_root = review_root / "scripts" / "review_runtime" / "__pycache__"
            cache_root.mkdir()
            cache_file = cache_root / "cli.cpython-313.pyc"
            cache_file.write_bytes(
                b"untrusted-bytecode-must-never-be-loaded",
            )
            self.assertTrue(cache_file.is_file())

            captured = self.run_binding(resolver)
            self.assertEqual(captured.returncode, 0, captured.stderr)
            binding = json.loads(captured.stdout)
            for action in ("validate", "list"):
                with self.subTest(action=action):
                    completed = self.run_binding(
                        resolver,
                        action=action,
                        expected=binding["binding_sha256"],
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

            listing = json.loads(
                self.run_binding(
                    resolver,
                    action="list",
                    expected=binding["binding_sha256"],
                ).stdout
            )["result"]
            selected_id = sorted(token["id"] for token in listing["tokens"])[0]
            selected = self.run_binding(
                resolver,
                action="get",
                token_id=selected_id,
                expected=binding["binding_sha256"],
            )
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(
                json.loads(selected.stdout)["result"]["token"]["id"],
                selected_id,
            )

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
            self.assertIn("catalog runtime data digest changed", changed.stderr)

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
            skills_root = Path(temporary).resolve() / "skills"
            copied = skills_root / "synthetic-token-fixtures"
            shutil.copytree(
                SKILL_ROOT,
                copied,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            shutil.copytree(
                REVIEW_SKILL_ROOT,
                skills_root / "review-orchestration-playbook",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            rejected = self.run_binding(
                copied / "scripts" / "active_catalog_binding.py"
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("versioned immutable release", rejected.stderr)

    def test_runtime_manifest_requires_trusted_rotation_and_binds_source_data(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            catalog = (
                review_root
                / "scripts"
                / "review_runtime"
                / "synthetic-token-catalog.json"
            )
            catalog.write_bytes(catalog.read_bytes() + b"\n")
            self.rotate_runtime_manifest(
                review_root,
                changed_relative_paths=(
                    Path("scripts/review_runtime/synthetic-token-catalog.json"),
                ),
                provision_guard=False,
            )
            unprovisioned = self.run_binding(resolver)
            self.assertNotEqual(unprovisioned.returncode, 0)
            self.assertIn(
                "runtime manifest is not provisioned by this trusted guard",
                unprovisioned.stderr,
            )

            self.rotate_runtime_manifest(review_root)
            rotated = self.run_binding(resolver)
            self.assertEqual(rotated.returncode, 0, rotated.stderr)
            binding = json.loads(rotated.stdout)
            validated = self.run_binding(
                resolver,
                action="validate",
                expected=binding["binding_sha256"],
            )
            self.assertEqual(validated.returncode, 0, validated.stderr)

            common = review_root / "scripts" / "review_runtime" / "common.py"
            common.write_bytes(common.read_bytes() + b"\n# source drift\n")
            source_drift = self.run_binding(resolver)
            self.assertEqual(source_drift.returncode, 2)
            self.assertIn("source digest changed", source_drift.stderr)

        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            manifest_path = review_root / RUNTIME_MANIFEST_RELATIVE
            manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
            manifest_drift = self.run_binding(resolver)
            self.assertNotEqual(manifest_drift.returncode, 0)
            self.assertIn(
                "runtime manifest is not provisioned by this trusted guard",
                manifest_drift.stderr,
            )

    def test_runtime_manifest_rejects_unlisted_modules_and_import_substitution(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            runtime_root = review_root / "scripts" / "review_runtime"
            extra = runtime_root / "extra_catalog_runtime.py"
            extra.write_text("VALUE = 1\n", encoding="utf-8")

            def add_unlisted(manifest):
                manifest["sources"].append(
                    {
                        "module": "review_runtime.extra_catalog_runtime",
                        "path": ("scripts/review_runtime/extra_catalog_runtime.py"),
                        "package": False,
                        "sha256": hashlib.sha256(extra.read_bytes()).hexdigest(),
                    }
                )
                manifest["allowed_modules"].append(
                    "review_runtime.extra_catalog_runtime"
                )
                manifest["allowed_modules"].sort()

            self.rotate_runtime_manifest(
                review_root,
                mutate_manifest=add_unlisted,
            )
            unlisted = self.run_binding(resolver)
            self.assertEqual(unlisted.returncode, 2)
            self.assertIn("not the minimal closure", unlisted.stderr)

        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            runtime_root = review_root / "scripts" / "review_runtime"
            substitution = runtime_root / "catalog_import_substitution.py"
            marker = runtime_root / "catalog-import-substitution-executed"
            substitution.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            cli = runtime_root / "cli.py"
            cli.write_bytes(
                cli.read_bytes() + b"\nfrom . import catalog_import_substitution\n"
            )
            self.rotate_runtime_manifest(
                review_root,
                changed_relative_paths=(Path("scripts/review_runtime/cli.py"),),
            )
            bound = self.run_binding(resolver)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            binding = json.loads(bound.stdout)
            rejected = self.run_binding(
                resolver,
                action="list",
                expected=binding["binding_sha256"],
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("outside the closed manifest", rejected.stderr)
            self.assertFalse(marker.exists())

    def test_runtime_manifest_symlink_and_parent_replacement_fail_closed(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            manifest_path = review_root / RUNTIME_MANIFEST_RELATIVE
            copied_manifest = manifest_path.with_name("copied-manifest.json")
            copied_manifest.write_bytes(manifest_path.read_bytes())
            manifest_path.unlink()
            manifest_path.symlink_to(copied_manifest)
            rejected = self.run_binding(resolver)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("ordinary non-symlink regular file", rejected.stderr)

        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            review_root = skills_root / "review-orchestration-playbook"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            scripts_root = review_root / "scripts"
            runtime_root = scripts_root / "review_runtime"
            replacement = scripts_root / "review_runtime.replacement"
            shutil.copytree(runtime_root, replacement)
            entry = scripts_root / "synthetic_catalog_entry"
            entry.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n\n"
                "scripts = Path(__file__).parent\n"
                "runtime = scripts / 'review_runtime'\n"
                "original = scripts / 'review_runtime.original'\n"
                "replacement = scripts / 'review_runtime.replacement'\n"
                "os.rename(runtime, original)\n"
                "os.rename(replacement, runtime)\n"
                "from review_runtime.cli import catalog_main as main\n",
                encoding="utf-8",
            )
            self.rotate_runtime_manifest(
                review_root,
                changed_relative_paths=(Path("scripts/synthetic_catalog_entry"),),
            )
            bound = self.run_binding(resolver)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            binding = json.loads(bound.stdout)
            replaced = self.run_binding(
                resolver,
                action="list",
                expected=binding["binding_sha256"],
            )
            self.assertEqual(replaced.returncode, 2)
            self.assertIn("bound directory entry changed", replaced.stderr)

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
            self.assertIn("import substitute", rejected.stderr)
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
            guard = (
                synthetic_root.parent
                / "review-orchestration-playbook"
                / "scripts"
                / "named_lane_guard"
            )
            completed = subprocess.run(
                (
                    str(Path(sys.executable).resolve()),
                    "-B",
                    "-S",
                    str(guard),
                    "catalog-bootstrap",
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
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("requires a prevalidated absolute Python", completed.stderr)
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
                    "outside the trusted catalog bundle",
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
                    "outside the trusted catalog bundle",
                    intermediate_symlink.stderr,
                )

                marker = first_skill / "resolver-symlink-executed"
                second_resolver.write_text(
                    "from pathlib import Path\n"
                    f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                    encoding="utf-8",
                )
                first_resolver.unlink()
                first_resolver.symlink_to(second_resolver)
                rejected = self.run_binding(
                    first_resolver,
                    loaded_skill_root=first_skill,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("non-symlink regular file", rejected.stderr)
                self.assertFalse(marker.exists())

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
            self.assertIn(
                f"{scripts_root} is group/world writable",
                rejected.stderr,
            )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_mutating_acl_grants_fail_closed_without_mode_changes(
        self,
    ) -> None:
        cases = (
            (
                "ancestor-delete-child",
                lambda release: (
                    release
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                    / "scripts"
                ),
                "everyone allow add_file,delete_child",
                0o755,
            ),
            (
                "runtime-file-write",
                lambda release: (
                    release
                    / "personal_codex"
                    / "skills"
                    / "review-orchestration-playbook"
                    / "scripts"
                    / "review_runtime"
                    / "synthetic-token-catalog.json"
                ),
                "everyone allow write",
                0o644,
            ),
        )
        for case, target_for_release, rule, expected_mode in cases:
            with self.subTest(case=case), self.installed_release() as release_root:
                resolver = (
                    release_root
                    / "personal_codex"
                    / "skills"
                    / "synthetic-token-fixtures"
                    / "scripts"
                    / "active_catalog_binding.py"
                )
                target = target_for_release(release_root)
                self.assertEqual(target.stat().st_mode & 0o777, expected_mode)
                with self.macos_acl(target, rule):
                    self.assertEqual(target.stat().st_mode & 0o777, expected_mode)

                    rejected = self.run_binding(resolver)

                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stdout, "")
                    self.assertIn(
                        "grants non-owner mutation through an extended ACL",
                        rejected.stderr,
                    )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_nonmutating_acl_entries_remain_admissible(self) -> None:
        owner = pwd.getpwuid(os.geteuid()).pw_name
        for rule in (
            "everyone deny delete",
            "everyone allow read",
            f"user:{owner} allow write",
        ):
            with self.subTest(rule=rule), self.installed_release() as release_root:
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
                with self.macos_acl(catalog, rule):
                    completed = self.run_binding(resolver)

                    self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_acl_revalidation_is_property_scoped_at_transaction_end(
        self,
    ) -> None:
        cases = (
            ("everyone allow write", False),
            ("everyone deny delete", True),
        )
        for rule, should_succeed in cases:
            with self.subTest(rule=rule), self.installed_release() as release_root:
                skills_root = release_root / "personal_codex" / "skills"
                synthetic_root = skills_root / "synthetic-token-fixtures"
                review_root = skills_root / "review-orchestration-playbook"
                resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
                catalog = (
                    review_root
                    / "scripts"
                    / "review_runtime"
                    / "synthetic-token-catalog.json"
                )
                entry = review_root / "scripts" / "synthetic_catalog_entry"
                entry.write_text(
                    "#!/usr/bin/env python3\n"
                    "import subprocess\n\n"
                    f"target = {str(catalog)!r}\n"
                    f"rule = {rule!r}\n"
                    "completed = subprocess.run(\n"
                    "    ('/bin/chmod', '+a', rule, target),\n"
                    "    check=False,\n"
                    "    stdout=subprocess.PIPE,\n"
                    "    stderr=subprocess.PIPE,\n"
                    "    text=True,\n"
                    ")\n"
                    "if completed.returncode != 0:\n"
                    "    raise RuntimeError(completed.stderr)\n\n"
                    "from review_runtime.cli import catalog_main as main\n",
                    encoding="utf-8",
                )
                self.rotate_runtime_manifest(
                    review_root,
                    changed_relative_paths=(Path("scripts/synthetic_catalog_entry"),),
                )
                bound = self.run_binding(resolver)
                self.assertEqual(bound.returncode, 0, bound.stderr)
                binding = json.loads(bound.stdout)

                try:
                    completed = self.run_binding(
                        resolver,
                        action="list",
                        expected=binding["binding_sha256"],
                    )
                    if should_succeed:
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                    else:
                        self.assertEqual(completed.returncode, 2)
                        self.assertEqual(completed.stdout, "")
                        self.assertIn(
                            "grants non-owner mutation through an extended ACL",
                            completed.stderr,
                        )
                finally:
                    self.remove_macos_acl(catalog)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS BSD flags")
    def test_macos_security_flags_are_bound_but_metadata_flags_are_ignored(
        self,
    ) -> None:
        cases = (
            ("opaque", "noopaque", "runtime-directory", False),
            ("hidden", "nohidden", "catalog-file", True),
        )
        for flag, clear_flag, target_kind, should_succeed in cases:
            with self.subTest(flag=flag), self.installed_release() as release_root:
                skills_root = release_root / "personal_codex" / "skills"
                synthetic_root = skills_root / "synthetic-token-fixtures"
                review_root = skills_root / "review-orchestration-playbook"
                resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
                runtime_root = review_root / "scripts" / "review_runtime"
                target = (
                    runtime_root
                    if target_kind == "runtime-directory"
                    else runtime_root / "synthetic-token-catalog.json"
                )
                entry = review_root / "scripts" / "synthetic_catalog_entry"
                entry.write_text(
                    "#!/usr/bin/env python3\n"
                    "import subprocess\n\n"
                    f"target = {str(target)!r}\n"
                    f"flag = {flag!r}\n"
                    "completed = subprocess.run(\n"
                    "    ('/usr/bin/chflags', flag, target),\n"
                    "    check=False,\n"
                    "    stdout=subprocess.PIPE,\n"
                    "    stderr=subprocess.PIPE,\n"
                    "    text=True,\n"
                    ")\n"
                    "if completed.returncode != 0:\n"
                    "    raise RuntimeError(completed.stderr)\n\n"
                    "from review_runtime.cli import catalog_main as main\n",
                    encoding="utf-8",
                )
                self.rotate_runtime_manifest(
                    review_root,
                    changed_relative_paths=(Path("scripts/synthetic_catalog_entry"),),
                )
                bound = self.run_binding(resolver)
                self.assertEqual(bound.returncode, 0, bound.stderr)
                binding = json.loads(bound.stdout)

                try:
                    completed = self.run_binding(
                        resolver,
                        action="list",
                        expected=binding["binding_sha256"],
                    )
                    if should_succeed:
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                    else:
                        self.assertEqual(completed.returncode, 2)
                        self.assertEqual(completed.stdout, "")
                        self.assertIn("security flags changed", completed.stderr)
                finally:
                    cleared = subprocess.run(
                        ("/usr/bin/chflags", clear_flag, str(target)),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(cleared.returncode, 0, cleared.stderr)

    def test_resolver_leaf_replacement_after_guard_binding_is_not_executed(
        self,
    ) -> None:
        with self.installed_release() as release_root:
            skills_root = release_root / "personal_codex" / "skills"
            synthetic_root = skills_root / "synthetic-token-fixtures"
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            guard = (
                skills_root
                / "review-orchestration-playbook"
                / "scripts"
                / "named_lane_guard"
            )
            marker = synthetic_root / "resolver-replacement-executed"
            replacement = resolver.with_name("active_catalog_binding.replacement.py")
            replacement.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            probe = release_root / "catalog-bootstrap-replacement-probe.py"
            probe.write_text(
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n"
                f"guard = Path({str(guard)!r})\n"
                f"resolver = Path({str(resolver)!r})\n"
                f"replacement = Path({str(replacement)!r})\n"
                f"synthetic_root = Path({str(synthetic_root)!r})\n"
                "sys.argv = [str(guard), 'catalog-bootstrap']\n"
                "namespace = {'__name__': '_catalog_guard_probe', "
                "'__file__': str(guard)}\n"
                "source = guard.read_bytes()\n"
                "exec(compile(source, str(guard), 'exec'), namespace)\n"
                "os.replace(replacement, resolver)\n"
                "raise SystemExit(namespace['main']([\n"
                "    '--loaded-skill-root', str(synthetic_root), 'bind'\n"
                "]))\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                (
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-B",
                    "-S",
                    str(probe),
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                env=dict(os.environ),
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertIn("companion content changed", completed.stderr)
            self.assertFalse(marker.exists())

    def test_same_bytes_entry_path_replacement_cannot_release_a_result(self) -> None:
        with self.installed_release() as release_root:
            synthetic_root = (
                release_root / "personal_codex" / "skills" / "synthetic-token-fixtures"
            )
            resolver = synthetic_root / "scripts" / "active_catalog_binding.py"
            catalog_entry = (
                release_root
                / "personal_codex"
                / "skills"
                / "review-orchestration-playbook"
                / "scripts"
                / "synthetic_catalog_entry"
            )
            review_root = catalog_entry.parent.parent
            replacement = catalog_entry.with_name(f"{catalog_entry.name}.replacement")
            marker = catalog_entry.with_name("replacement-path-executed")
            wrapper = (
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n"
                "\n"
                "replacement = Path(__file__ + '.replacement')\n"
                f"marker = Path({str(marker)!r})\n"
                "if replacement.exists():\n"
                "    os.replace(replacement, __file__)\n"
                "else:\n"
                "    marker.write_text('executed', encoding='utf-8')\n\n"
                "from review_runtime.cli import catalog_main as main\n\n"
                "if __name__ == '__main__':\n"
                "    raise SystemExit(main())\n"
            )
            catalog_entry.write_text(wrapper, encoding="utf-8")
            replacement.write_text(wrapper, encoding="utf-8")
            self.rotate_runtime_manifest(
                review_root,
                changed_relative_paths=(Path("scripts/synthetic_catalog_entry"),),
            )

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
