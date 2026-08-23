from __future__ import annotations

import contextlib
import dis
import hashlib
import io
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import review_workspace as workspace_runtime  # noqa: E402
from review_runtime.named_lane import main as named_lane_main  # noqa: E402
from review_runtime.review_workspace import (  # noqa: E402
    RangeIncomplete,
    ReviewWorkspaceError,
    cleanup_workspace,
    prepare_workspace,
    validate_workspace,
)


def git(repo: pathlib.Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


class ReviewWorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="review-workspace-test-",
            dir=pathlib.Path(tempfile.gettempdir()).resolve(),
        )
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.repo = self.root / "source"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "master")
        git(self.repo, "config", "user.name", "Review Workspace Test")
        git(self.repo, "config", "user.email", "review-workspace@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")
        self.commits: list[str] = []
        for number in range(3):
            (self.repo / "tracked.txt").write_text(
                f"revision {number}\n", encoding="utf-8"
            )
            git(self.repo, "add", "tracked.txt")
            git(self.repo, "commit", "-m", f"revision {number}")
            self.commits.append(git(self.repo, "rev-parse", "HEAD"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def cleanup(self, prepared: object) -> None:
        root = prepared.root
        if root.exists():
            cleanup_workspace(root, prepared.cleanup_token)

    def retained_control(
        self,
        workspace: pathlib.Path,
        *,
        operation: str = "fixture-operation",
        pid: int = 900_101,
    ) -> tuple[pathlib.Path, str, dict[str, object]]:
        control = workspace_runtime._PartialRecoveryControl.create(workspace)
        control.bind_process(
            operation,
            workspace_runtime._RecoveryProcessIdentity(
                pid,
                pid,
                f"fixture-start-{pid}",
            ),
        )
        payload = control.recovery_payload()
        control.close(retain=True)
        control_payload = payload["partial_recovery_control"]
        assert isinstance(control_payload, dict)
        return (
            pathlib.Path(str(control_payload["path"])),
            str(control_payload["sha256"]),
            payload,
        )

    def forge_loose_object(
        self,
        root: pathlib.Path,
        oid: str,
        object_type: bytes,
        payload: bytes,
    ) -> pathlib.Path:
        loose = root / ".git/objects" / oid[:2] / oid[2:]
        loose.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if loose.exists():
            os.chmod(loose, 0o600)
        loose.write_bytes(
            zlib.compress(
                object_type + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
            )
        )
        os.chmod(loose, 0o400)
        return loose

    def assert_batch_check_accepts_object(
        self,
        root: pathlib.Path,
        oid: str,
        object_type: str,
        payload_size: int,
    ) -> None:
        observed = workspace_runtime._run_git(
            root,
            ("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
            stdin=f"{oid}\n".encode("ascii"),
        )
        self.assertEqual(
            observed,
            f"{oid} {object_type} {payload_size}\n".encode("ascii"),
        )

    def atomically_replace_private_file(
        self,
        path: pathlib.Path,
        payload: bytes,
    ) -> None:
        replacement = path.with_name(f".{path.name}.replacement")
        replacement.write_bytes(payload)
        os.chmod(replacement, 0o600)
        os.replace(replacement, path)

    def assert_independent_git_layout(self, root: pathlib.Path) -> None:
        git_dir = pathlib.Path(git(root, "rev-parse", "--absolute-git-dir"))
        common = pathlib.Path(
            git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
        )
        objects = pathlib.Path(
            git(root, "rev-parse", "--path-format=absolute", "--git-path", "objects")
        )
        self.assertEqual(git_dir, root / ".git")
        self.assertEqual(common, root / ".git")
        self.assertEqual(objects, root / ".git/objects")
        self.assertEqual(git(root, "remote"), "")
        self.assertFalse((objects / "info/alternates").exists())
        self.assertFalse((objects / "info/http-alternates").exists())
        for directory, directory_names, file_names in os.walk(objects):
            current = pathlib.Path(directory)
            for name in (*directory_names, *file_names):
                metadata = (current / name).stat(follow_symlinks=False)
                self.assertFalse(stat.S_ISLNK(metadata.st_mode))
                if stat.S_ISREG(metadata.st_mode):
                    self.assertEqual(metadata.st_nlink, 1)
                    self.assertFalse(name.endswith(".promisor"))

    def invoke(self, argv: tuple[str, ...]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_main(argv)
        return returncode, stdout.getvalue(), stderr.getvalue()

    def test_public_cli_exposes_only_the_new_workspace_lifecycle(self) -> None:
        guard = SCRIPTS / "named_lane_guard"
        completed = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-S",
                str(guard),
                "--help",
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        help_text = completed.stdout
        self.assertIn("prepare-workspace", help_text)
        self.assertIn("validate-workspace", help_text)
        self.assertIn("cleanup-workspace", help_text)
        self.assertNotIn("materialize-worktree", help_text)
        self.assertNotIn("validate-worktree", help_text)

        destination = self.root / "cli-workspace"
        returncode, stdout, stderr = self.invoke(
            (
                "prepare-workspace",
                "--source",
                str(self.repo),
                "--worktree",
                str(destination),
                "--base",
                self.commits[1],
                "--head",
                self.commits[2],
            )
        )
        self.assertEqual(returncode, 0, stderr)
        prepared = json.loads(stdout)
        self.assertEqual(prepared["command"], "prepare-workspace")

        returncode, stdout, stderr = self.invoke(
            (
                "validate-workspace",
                "--worktree",
                str(destination),
                "--base",
                self.commits[1],
                "--head",
                self.commits[2],
            )
        )
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(json.loads(stdout)["command"], "validate-workspace")

        returncode, stdout, stderr = self.invoke(
            (
                "cleanup-workspace",
                "--worktree",
                str(destination),
                "--token",
                prepared["cleanup_token"],
            )
        )
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(json.loads(stdout)["cleanup_status"], "complete")
        self.assertFalse(destination.exists())

    def test_fixed_git_version_gate_accepts_supported_normal_and_apple_output(
        self,
    ) -> None:
        for output in (
            b"git version 2.45.0\n",
            b"git version 2.50.1 (Apple Git-155)\n",
            b"git version 2.50.1 (Apple Git-155.1)\n",
        ):
            with self.subTest(output=output):
                capture = mock.Mock(
                    returncode=0,
                    stdout=bytearray(output),
                    stderr=bytearray(),
                )
                with mock.patch.object(
                    workspace_runtime,
                    "run_bounded_capture",
                    return_value=capture,
                ):
                    workspace_runtime._validate_git_executable(
                        pathlib.Path("/fixed/git")
                    )
                capture.zeroize.assert_called_once_with()

    def test_fixed_git_version_gate_rejects_old_and_malformed_output(self) -> None:
        cases = (
            (b"git version 2.44.9\n", "git-version-unsupported"),
            (b"git version 2.45\n", "git-version-unverified"),
            (b" git version 2.45.0\n", "git-version-unverified"),
            (b"git version 2.45.0\n\n", "git-version-unverified"),
            (b"git version 2.45.0 (AppleGit-155)\n", "git-version-unverified"),
        )
        for output, reason in cases:
            with self.subTest(output=output):
                capture = mock.Mock(
                    returncode=0,
                    stdout=bytearray(output),
                    stderr=bytearray(),
                )
                with (
                    mock.patch.object(
                        workspace_runtime,
                        "run_bounded_capture",
                        return_value=capture,
                    ),
                    self.assertRaises(ReviewWorkspaceError) as caught,
                ):
                    workspace_runtime._validate_git_executable(
                        pathlib.Path("/fixed/git")
                    )
                self.assertEqual(caught.exception.reason, reason)
                capture.zeroize.assert_called_once_with()

    def test_old_git_blocks_before_any_repository_command(self) -> None:
        capture = mock.Mock(
            returncode=0,
            stdout=bytearray(b"git version 2.44.9\n"),
            stderr=bytearray(),
        )
        destination = self.root / "old-git-workspace"
        with (
            mock.patch.object(
                workspace_runtime,
                "resolve_git",
                return_value=pathlib.Path("/fixed/git"),
            ),
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                return_value=capture,
            ) as runner,
            mock.patch.object(workspace_runtime, "_discover_source") as discover,
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(caught.exception.reason, "git-version-unsupported")
        runner.assert_called_once()
        discover.assert_not_called()
        self.assertFalse(destination.exists())

    def test_prepare_reuses_one_validated_git_for_every_runner(self) -> None:
        fixed_git = workspace_runtime.resolve_git()
        real_capture = workspace_runtime.run_bounded_capture
        real_run = workspace_runtime.run_process
        real_popen = workspace_runtime.subprocess.Popen
        observed: list[tuple[str, tuple[str, ...], dict[str, str] | None]] = []

        def capture(command: tuple[str, ...], **kwargs: object) -> object:
            observed.append(("capture", tuple(command), kwargs.get("env")))
            return real_capture(command, **kwargs)

        def run(command: tuple[str, ...], **kwargs: object) -> object:
            observed.append(("run", tuple(command), kwargs.get("env")))
            return real_run(command, **kwargs)

        def popen(command: tuple[str, ...], *args: object, **kwargs: object) -> object:
            observed.append(("popen", tuple(command), kwargs.get("env")))
            return real_popen(command, *args, **kwargs)

        destination = self.root / "fixed-git-workspace"
        with (
            mock.patch.object(
                workspace_runtime,
                "resolve_git",
                return_value=fixed_git,
            ) as resolve,
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                side_effect=capture,
            ),
            mock.patch.object(
                workspace_runtime,
                "run_process",
                side_effect=run,
            ),
            mock.patch.object(
                workspace_runtime.subprocess,
                "Popen",
                side_effect=popen,
            ),
        ):
            prepared = prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        try:
            self.assertEqual(resolve.call_count, 1)
            direct = [entry for entry in observed if entry[0] in {"capture", "run"}]
            version = [
                entry for entry in direct if entry[1] == (str(fixed_git), "--version")
            ]
            self.assertEqual(len(version), 1)
            repository_calls = [
                entry
                for entry in observed
                if entry[1]
                and entry[1][0] == str(fixed_git)
                and entry[1] != (str(fixed_git), "--version")
            ]
            self.assertTrue(repository_calls)
            self.assertEqual(
                {entry[0] for entry in repository_calls},
                {"capture", "run", "popen"},
            )
            direct_object_integrity_calls = [
                entry
                for entry in repository_calls
                if entry[0] == "popen" and entry[1][-2:] == ("cat-file", "--batch")
            ]
            self.assertEqual(len(direct_object_integrity_calls), 1)
            for _runner, argv, environment in repository_calls:
                self.assertEqual(argv[0], str(fixed_git))
                self.assertIn("--no-lazy-fetch", argv)
                assert environment is not None
                self.assertEqual(environment.get("GIT_NO_LAZY_FETCH"), "1")
        finally:
            self.cleanup(prepared)

    def test_prepare_ignores_dirty_source_and_creates_clean_independent_history(
        self,
    ) -> None:
        (self.repo / "tracked.txt").write_text("dirty source\n", encoding="utf-8")
        (self.repo / "untracked-secret.txt").write_text(
            "not reviewer input\n", encoding="utf-8"
        )
        destination = self.root / "workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[0], self.commits[2]
        )
        try:
            self.assertEqual(prepared.strategy, "exact-pack")
            self.assertFalse(prepared.source_shallow)
            self.assertEqual(prepared.commit_count, 3)
            self.assertGreater(prepared.range_object_count, prepared.commit_count)
            self.assertEqual(prepared.shallow_bytes, "")
            self.assertEqual(prepared.parent_identity[2], os.getuid())
            self.assertEqual(prepared.workspace_identity[2], os.getuid())
            self.assertEqual(git(prepared.root, "status", "--porcelain=v2"), "")
            self.assertEqual(
                git(prepared.root, "rev-parse", "--is-shallow-repository"), "false"
            )
            self.assertEqual(
                git(prepared.root, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD"
            )
            self.assertEqual(git(prepared.root, "rev-parse", "HEAD"), self.commits[2])
            self.assertEqual(git(prepared.root, "rev-list", "--count", "HEAD"), "3")
            self.assertEqual(
                (prepared.root / "tracked.txt").read_text(encoding="utf-8"),
                "revision 2\n",
            )
            self.assertFalse((prepared.root / "untracked-secret.txt").exists())
            self.assert_independent_git_layout(prepared.root)
            validated = validate_workspace(
                prepared.root, self.commits[0], self.commits[2]
            )
            self.assertEqual(validated.workspace_identity, prepared.workspace_identity)
        finally:
            self.cleanup(prepared)

    def test_merge_side_history_is_included_in_the_bounded_range(self) -> None:
        git(self.repo, "switch", "-c", "side", self.commits[0])
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "side.txt")
        git(self.repo, "commit", "-m", "side change")
        git(self.repo, "switch", "master")
        (self.repo / "main.txt").write_text("main\n", encoding="utf-8")
        git(self.repo, "add", "main.txt")
        git(self.repo, "commit", "-m", "main change")
        git(self.repo, "merge", "--no-ff", "side", "-m", "merge side")
        head = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "merge-workspace"
        prepared = prepare_workspace(self.repo, destination, self.commits[1], head)
        try:
            self.assertEqual(prepared.commit_count, 5)
            self.assertGreater(prepared.range_object_count, prepared.commit_count)
            self.assertTrue((prepared.root / "side.txt").is_file())
            self.assertTrue((prepared.root / "main.txt").is_file())
            validate_workspace(prepared.root, self.commits[1], head)
        finally:
            self.cleanup(prepared)

    def test_merge_updated_feature_preserves_exact_visible_base_range(self) -> None:
        base = self.commits[2]
        pre_base = self.commits[1]
        git(self.repo, "switch", "-c", "merge-updated-feature", pre_base)
        (self.repo / "feature.txt").write_text("feature\n", encoding="utf-8")
        git(self.repo, "add", "feature.txt")
        git(self.repo, "commit", "-m", "feature from pre-base parent")
        feature = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "merge", "--no-ff", "master", "-m", "merge current base")
        head = git(self.repo, "rev-parse", "HEAD")
        self.assertEqual(
            git(self.repo, "rev-list", "--parents", "-n", "1", head).split()[1:],
            [feature, base],
        )
        source_visible = set(git(self.repo, "rev-list", f"{base}..{head}").splitlines())
        self.assertEqual(source_visible, {feature, head})
        source_diff = git(self.repo, "diff", "--binary", f"{base}..{head}")

        destination = self.root / "merge-updated-feature-workspace"
        prepared = prepare_workspace(self.repo, destination, base, head)
        try:
            self.assertEqual(prepared.shallow_bytes, "")
            range_payload = (
                prepared.root / ".git" / workspace_runtime.RANGE_OBJECT_MANIFEST
            ).read_bytes()
            support_payload = (
                prepared.root
                / ".git"
                / workspace_runtime.PARENT_SUPPORT_OBJECT_MANIFEST
            ).read_bytes()
            range_ids = set(range_payload.decode("ascii").splitlines())
            support_ids = set(support_payload.decode("ascii").splitlines())
            self.assertFalse(range_ids.intersection(support_ids))
            self.assertIn(pre_base, support_ids)
            self.assertEqual(
                prepared.parent_support_object_count,
                len(support_ids),
            )
            self.assertEqual(
                prepared.parent_support_object_sha256,
                hashlib.sha256(support_payload).hexdigest(),
            )
            self.assertEqual(
                set(git(prepared.root, "rev-list", f"{base}..{head}").splitlines()),
                {feature, head},
            )
            self.assertNotIn(
                pre_base, git(prepared.root, "rev-list", f"{base}..{head}")
            )
            self.assertEqual(
                git(prepared.root, "diff", "--binary", f"{base}..{head}"),
                source_diff,
            )
            self.assertIn(
                "feature.txt", git(prepared.root, "show", "--format=", "-p", feature)
            )
            self.assertIn(
                "feature.txt", git(prepared.root, "show", "--format=", "-m", "-p", head)
            )
            self.assertIn(
                "feature.txt",
                git(prepared.root, "log", "--format=", "-p", f"{base}..{head}"),
            )
            self.assertEqual(git(prepared.root, "status", "--porcelain=v2"), "")
            self.assertEqual(git(prepared.root, "rev-parse", "HEAD"), head)
            validated = validate_workspace(prepared.root, base, head)
            self.assertEqual(
                validated.parent_support_object_count,
                prepared.parent_support_object_count,
            )
            self.assertEqual(
                validated.parent_support_object_sha256,
                prepared.parent_support_object_sha256,
            )
            for key in (
                "parent_support_object_count",
                "parent_support_object_sha256",
            ):
                self.assertEqual(prepared.receipt()[key], validated.receipt()[key])
        finally:
            self.cleanup(prepared)

    def test_octopus_merge_keeps_all_non_linear_range_parents_visible(self) -> None:
        base = self.commits[2]
        pre_base = self.commits[1]
        git(self.repo, "switch", "-c", "octopus-feature", pre_base)
        (self.repo / "feature.txt").write_text("feature\n", encoding="utf-8")
        git(self.repo, "add", "feature.txt")
        git(self.repo, "commit", "-m", "octopus feature")
        feature = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "switch", "-c", "octopus-side", pre_base)
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "side.txt")
        git(self.repo, "commit", "-m", "octopus side")
        side = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "switch", "octopus-feature")
        git(
            self.repo,
            "merge",
            "--no-ff",
            "master",
            "octopus-side",
            "-m",
            "merge base and side",
        )
        head = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "octopus-workspace"
        prepared = prepare_workspace(self.repo, destination, base, head)
        try:
            expected = {feature, side, head}
            self.assertEqual(
                set(git(prepared.root, "rev-list", f"{base}..{head}").splitlines()),
                expected,
            )
            head_row = git(
                prepared.root,
                "rev-list",
                "--parents",
                "-n",
                "1",
                head,
            ).split()
            self.assertEqual(head_row[1:], [feature, base, side])
            validate_workspace(prepared.root, base, head)
        finally:
            self.cleanup(prepared)

    def test_linked_source_still_produces_a_standalone_repository(self) -> None:
        linked = self.root / "linked-source"
        git(self.repo, "worktree", "add", "--detach", str(linked), self.commits[2])
        destination = self.root / "linked-workspace"
        prepared = prepare_workspace(
            linked, destination, self.commits[1], self.commits[2]
        )
        try:
            source_common = pathlib.Path(
                git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir")
            )
            destination_common = pathlib.Path(
                git(
                    prepared.root,
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                )
            )
            self.assertNotEqual(destination_common, source_common)
            self.assert_independent_git_layout(prepared.root)
        finally:
            self.cleanup(prepared)

    def test_local_alternate_source_is_materialized_without_destination_dependency(
        self,
    ) -> None:
        alternate = self.root / "alternate-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(self.repo),
                str(alternate),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue((alternate / ".git/objects/info/alternates").is_file())
        destination = self.root / "alternate-workspace"
        prepared = prepare_workspace(
            alternate, destination, self.commits[1], self.commits[2]
        )
        try:
            self.assert_independent_git_layout(prepared.root)
            validate_workspace(prepared.root, self.commits[1], self.commits[2])
        finally:
            self.cleanup(prepared)

    def test_shallow_source_is_accepted_when_the_range_is_complete(self) -> None:
        shallow = self.root / "shallow-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--depth=2",
                f"file://{self.repo}",
                str(shallow),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(shallow, "config", "extensions.partialClone", "origin")
        git(shallow, "config", "remote.origin.promisor", "true")
        pack = next((shallow / ".git/objects/pack").glob("*.pack"))
        pack.with_suffix(".promisor").write_text("fixture\n", encoding="utf-8")
        destination = self.root / "shallow-workspace"
        prepared = prepare_workspace(
            shallow, destination, self.commits[1], self.commits[2]
        )
        try:
            self.assertTrue(prepared.source_shallow)
            self.assertTrue((prepared.root / ".git/shallow").is_file())
            self.assertEqual(git(prepared.root, "rev-list", "--count", "HEAD"), "2")
            validate_workspace(prepared.root, self.commits[1], self.commits[2])
            source_shallow = prepared.root / ".git/review-source-shallow"
            original_source_shallow = source_shallow.read_bytes()
            self.atomically_replace_private_file(source_shallow, b"")
            with self.assertRaises(ReviewWorkspaceError) as drift:
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                )
            self.assertEqual(drift.exception.reason, "workspace-source-shallow-drift")
            self.atomically_replace_private_file(
                source_shallow,
                original_source_shallow,
            )
        finally:
            self.cleanup(prepared)

    def test_partial_source_may_omit_blob_reachable_only_before_base(self) -> None:
        old_blob = git(self.repo, "rev-parse", f"{self.commits[0]}:tracked.txt")
        old_blob_path = self.repo / ".git/objects" / old_blob[:2] / old_blob[2:]
        self.assertTrue(old_blob_path.is_file())
        old_blob_path.unlink()
        git(self.repo, "config", "extensions.partialClone", "origin")
        git(self.repo, "config", "remote.origin.promisor", "true")

        missing_code, _stdout, _stderr = workspace_runtime._run_git_raw(
            self.repo,
            ("cat-file", "-e", old_blob),
        )
        self.assertNotEqual(missing_code, 0)

        destination = self.root / "partial-history-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        try:
            self.assertEqual(prepared.strategy, "exact-pack")
            self.assertEqual(
                workspace_runtime._run_git_raw(
                    prepared.root,
                    ("cat-file", "-e", f"{self.commits[0]}^{{commit}}"),
                )[0],
                0,
            )
            self.assertNotEqual(
                workspace_runtime._run_git_raw(
                    prepared.root,
                    ("cat-file", "-e", old_blob),
                )[0],
                0,
            )
            validate_workspace(prepared.root, self.commits[1], self.commits[2])
        finally:
            self.cleanup(prepared)

    def test_private_ident_override_preserves_exact_raw_blob_bytes(self) -> None:
        (self.repo / ".gitattributes").write_text(
            "ident-*.txt ident\n",
            encoding="utf-8",
        )
        git(self.repo, "add", ".gitattributes")
        raw_payloads = {
            "ident-dollar.txt": b"$Id$\n",
            "ident-expanded.txt": b"$Id: already expanded $\n",
        }
        for path, payload in raw_payloads.items():
            returncode, output, stderr = workspace_runtime._run_git_raw(
                self.repo,
                ("hash-object", "-w", "--stdin"),
                stdin=payload,
            )
            self.assertEqual(returncode, 0, stderr)
            oid = output.strip().decode("ascii")
            git(
                self.repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{oid},{path}",
            )
        git(self.repo, "commit", "-m", "raw ident fixtures")
        head = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "ident-workspace"
        with mock.patch.object(
            workspace_runtime,
            "_run_git",
            wraps=workspace_runtime._run_git,
        ) as run_git:
            prepared = prepare_workspace(self.repo, destination, self.commits[2], head)
        try:
            for path, payload in raw_payloads.items():
                self.assertEqual((prepared.root / path).read_bytes(), payload)
                self.assertEqual(
                    git(prepared.root, "check-attr", "ident", "--", path),
                    f"{path}: ident: unset",
                )
            self.assertFalse(
                any(
                    call.args[1][:2] == ("cat-file", "blob")
                    for call in run_git.call_args_list
                )
            )
            validate_workspace(prepared.root, self.commits[2], head)
        finally:
            self.cleanup(prepared)

    def test_nonempty_post_checkout_status_fails_closed_without_rewrite(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "post-checkout-drift-workspace",
            self.commits[1],
            self.commits[2],
        )
        target = prepared.root / "tracked.txt"
        target.write_bytes(b"fixture transformed bytes\n")
        binding = workspace_runtime._bind_workspace_controls(
            prepared.root,
            include_index=True,
            include_marker=True,
        )
        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_run_git",
                    wraps=workspace_runtime._run_git,
                ) as run_git,
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._restore_checkout_transformations(
                    prepared.root,
                    binding,
                )
            self.assertEqual(
                caught.exception.reason,
                "checkout-transformation-unsupported",
            )
            self.assertEqual(target.read_bytes(), b"fixture transformed bytes\n")
            self.assertFalse(
                any(
                    call.args[1][:2] == ("cat-file", "blob")
                    for call in run_git.call_args_list
                )
            )
        finally:
            git(prepared.root, "checkout-index", "--all", "--force")
            self.cleanup(prepared)

    def test_range_incomplete_is_offline_and_gives_narrow_fetch_guidance(self) -> None:
        shallow = self.root / "incomplete-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--depth=1",
                f"file://{self.repo}",
                str(shallow),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        shallow_before = (shallow / ".git/shallow").read_bytes()
        destination = self.root / "incomplete-workspace"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            returncode = named_lane_main(
                (
                    "prepare-workspace",
                    "--source",
                    str(shallow),
                    "--worktree",
                    str(destination),
                    "--base",
                    self.commits[0],
                    "--head",
                    self.commits[2],
                )
            )
        self.assertEqual(returncode, 75)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "range-incomplete")
        self.assertEqual(payload["reason"], "base-commit-missing")
        self.assertIs(payload["source_promisor"], False)
        self.assertEqual(
            payload["remediation"]["recommended_action"],
            "fetch-exact-endpoints-or-deepen",
        )
        self.assertIn(self.commits[0], payload["remediation"]["fetch_exact_endpoints"])
        self.assertIn(self.commits[2], payload["remediation"]["fetch_exact_endpoints"])
        self.assertIn("--no-tags", payload["remediation"]["fetch_exact_endpoints"])
        self.assertIn(
            "--recurse-submodules=no",
            payload["remediation"]["fetch_exact_endpoints"],
        )
        self.assertIn(
            "Do not default to --unshallow", payload["remediation"]["shallow_history"]
        )
        self.assertEqual((shallow / ".git/shallow").read_bytes(), shallow_before)
        self.assertFalse(destination.exists())

    def test_exact_pack_normalization_is_independent_of_clonefile(self) -> None:
        destination = self.root / "exact-pack-workspace"
        with mock.patch.object(workspace_runtime, "_clonefile_function") as clonefile:
            prepared = prepare_workspace(
                self.repo, destination, self.commits[1], self.commits[2]
            )
        clonefile.assert_not_called()
        try:
            self.assertEqual(prepared.strategy, "exact-pack")
            self.assertEqual(prepared.receipt()["strategy"], "exact-pack")
            pack_files = tuple((prepared.root / ".git/objects/pack").glob("*.pack"))
            index_files = tuple((prepared.root / ".git/objects/pack").glob("*.idx"))
            self.assertEqual(len(pack_files), 1)
            self.assertEqual(len(index_files), 1)
            self.assertEqual(pack_files[0].stem, index_files[0].stem)
            self.assert_independent_git_layout(prepared.root)
        finally:
            self.cleanup(prepared)

    def test_raw_object_store_copy_is_hard_deprecated(self) -> None:
        with self.assertRaises(ReviewWorkspaceError) as caught:
            workspace_runtime._copy_object_stores(
                (),
                self.root / "unused-object-destination",
                "sha1",
                float("inf"),
            )
        self.assertEqual(caught.exception.reason, "deprecated-object-store-copy")

    def test_exact_pack_generation_failure_cleans_partial_output(
        self,
    ) -> None:
        destination = self.root / "pack-error-workspace"
        with mock.patch.object(
            workspace_runtime,
            "run_process",
            side_effect=workspace_runtime.ReviewError("fixture pack failure"),
        ):
            with self.assertRaises(ReviewWorkspaceError) as caught:
                prepare_workspace(
                    self.repo, destination, self.commits[1], self.commits[2]
                )
        self.assertEqual(caught.exception.reason, "range-pack-failed")
        self.assertFalse(destination.exists())

    def test_exact_pack_failure_mapping_preserves_common_error_semantics(
        self,
    ) -> None:
        cases = (
            (
                workspace_runtime.ReviewProcessLeakError("fixture process leak"),
                "range-pack-process-leak",
                "inconclusive",
            ),
            (
                workspace_runtime.ReviewOutputDrainError("fixture drain failure"),
                "range-pack-output-drain",
                "inconclusive",
            ),
            (
                workspace_runtime.ReviewTimeoutError("fixture timeout"),
                "range-pack-timeout",
                "inconclusive",
            ),
            (
                workspace_runtime.ReviewOutputLimitError(
                    "fixture output limit",
                    limit_kind="regular-file",
                ),
                "range-pack-limit",
                "blocked-safety",
            ),
        )
        for index, (error, reason, status) in enumerate(cases):
            with self.subTest(reason=reason):
                destination = self.root / f"mapped-pack-error-{index}"
                with mock.patch.object(
                    workspace_runtime,
                    "run_process",
                    side_effect=error,
                ):
                    with self.assertRaises(ReviewWorkspaceError) as caught:
                        prepare_workspace(
                            self.repo,
                            destination,
                            self.commits[1],
                            self.commits[2],
                        )
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.status, status)
                if reason == "range-pack-timeout":
                    self.assertIs(caught.exception.details["retryable"], True)
                if reason == "range-pack-limit":
                    self.assertEqual(
                        caught.exception.details["limit_kind"],
                        "regular-file",
                    )
                self.assertFalse(destination.exists())

    def test_exact_pack_nonzero_exit_remains_range_pack_failed(self) -> None:
        destination = self.root / "pack-nonzero-workspace"

        def fail_after_quiescence(*_args: object, **kwargs: object) -> object:
            kwargs["on_process_starting"]()
            kwargs["on_process_started"]()
            kwargs["on_process_quiescent"]()
            return mock.Mock(returncode=23, stdout=b"", stderr=b"fixture failure")

        with mock.patch.object(
            workspace_runtime,
            "run_process",
            side_effect=fail_after_quiescence,
        ):
            with self.assertRaises(ReviewWorkspaceError) as caught:
                prepare_workspace(
                    self.repo,
                    destination,
                    self.commits[1],
                    self.commits[2],
                )
        self.assertEqual(caught.exception.reason, "range-pack-failed")
        self.assertEqual(caught.exception.details["returncode"], 23)
        self.assertFalse(destination.exists())

    def test_unquiesced_exact_pack_failures_retain_partial_workspace(self) -> None:
        cases = (
            (
                workspace_runtime.ReviewProcessLeakError("fixture process leak"),
                "range-pack-process-leak",
            ),
            (
                workspace_runtime.ReviewOutputDrainError("fixture drain failure"),
                "range-pack-output-drain",
            ),
            (
                workspace_runtime.ReviewTimeoutError("fixture timeout"),
                "range-pack-timeout",
            ),
            (
                workspace_runtime.ReviewOutputLimitError(
                    "fixture output limit",
                    limit_kind="regular-file",
                ),
                "range-pack-limit",
            ),
            (
                workspace_runtime.ReviewError("fixture generic process failure"),
                "range-pack-quiescence-unproven",
            ),
        )

        for index, (error, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                destination = self.root / f"retained-pack-error-{index}"

                def fail_after_start(
                    *_args: object,
                    _error: BaseException = error,
                    **kwargs: object,
                ) -> object:
                    kwargs["on_process_starting"]()
                    kwargs["on_process_spawned"](
                        workspace_runtime._RecoveryProcessIdentity(
                            900_001 + index,
                            900_001 + index,
                            f"fixture-start-{index}",
                        )
                    )
                    kwargs["on_process_started"]()
                    raise _error

                with mock.patch.object(
                    workspace_runtime,
                    "run_process",
                    side_effect=fail_after_start,
                ):
                    with self.assertRaises(ReviewWorkspaceError) as caught:
                        prepare_workspace(
                            self.repo,
                            destination,
                            self.commits[1],
                            self.commits[2],
                        )
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.status, "inconclusive")
                self.assertEqual(
                    caught.exception.details["process_quiescence"],
                    "unproven",
                )
                self.assertEqual(
                    caught.exception.details["rollback"],
                    "skipped-process-quiescence-unproven",
                )
                self.assertEqual(
                    caught.exception.details["retained_path"],
                    str(destination),
                )
                self.assertTrue(
                    caught.exception.details["cleanup_unavailable_until_quiescent"]
                )
                self.assertEqual(
                    caught.exception.details["active_process"]["operation"],
                    "pack-objects",
                )
                self.assertEqual(
                    caught.exception.details["recovery"]["command"],
                    "recover-partial-workspace",
                )
                self.assertTrue(caught.exception.details["recovery"]["argv_ready"])
                self.assertNotIn("cleanup_token", str(caught.exception.details))
                self.assertTrue(destination.is_dir())
                pack_directory = destination / ".git/objects/pack"
                self.assertEqual(len(tuple(pack_directory.glob(".review-*.pack"))), 1)
                self.assertEqual(
                    len(tuple(pack_directory.glob(".review-*.stderr"))),
                    1,
                )

    def test_exact_pack_recovery_publish_failure_cannot_cancel_retention(
        self,
    ) -> None:
        destination = self.root / "pack-recovery-publish-failure"
        original_publish = workspace_runtime._PartialRecoveryControl._publish

        def fail_seal(control: object) -> None:
            if control.payload.get("state") == "retained-quiescence-unproven":
                raise PermissionError("fixture recovery publication failure")
            original_publish(control)

        def fail_after_start(*_args: object, **kwargs: object) -> object:
            kwargs["on_process_starting"]()
            kwargs["on_process_spawned"](
                workspace_runtime._RecoveryProcessIdentity(
                    900_301,
                    900_301,
                    "fixture-pack-publish-start",
                )
            )
            kwargs["on_process_started"]()
            raise workspace_runtime.ReviewProcessLeakError("fixture pack leak")

        with (
            mock.patch.object(
                workspace_runtime._PartialRecoveryControl,
                "_publish",
                new=fail_seal,
            ),
            mock.patch.object(
                workspace_runtime,
                "run_process",
                side_effect=fail_after_start,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(caught.exception.reason, "range-pack-process-leak")
        self.assertTrue(workspace_runtime.process_quiescence_unproven(caught.exception))
        self.assertTrue(
            workspace_runtime._partial_workspace_requires_retention(caught.exception)
        )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        assert recovery is not None
        self.assertFalse(recovery["recovery"]["argv_ready"])
        self.assertIsNone(recovery["partial_recovery_control"]["sha256"])
        self.assertEqual(
            recovery["partial_recovery_control"]["publication_status"],
            "unverified",
        )
        self.assertTrue(destination.is_dir())

    def test_partial_recovery_removes_only_the_bound_markerless_workspace(
        self,
    ) -> None:
        destination = self.root / "recoverable-markerless-workspace"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, payload = self.retained_control(destination)

        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            cleaned = workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )

        self.assertEqual(cleaned.command, "recover-partial-workspace")
        self.assertEqual(cleaned.cleanup_status, "payload-removed")
        self.assertEqual(cleaned.tombstone_status, "retained")
        self.assertTrue(destination.is_dir())
        self.assertEqual(tuple(destination.iterdir()), ())
        self.assertTrue(control_path.is_file())
        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            repeated = workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertEqual(repeated.cleanup_status, "already-clean")
        self.assertTrue(payload["cleanup_unavailable_until_quiescent"])
        self.assertNotIn("token", " ".join(payload["recovery"]["argv"]))

    def test_partial_control_rejects_parent_alias_replacement_after_lock(self) -> None:
        parent = self.root / "partial-control-parent"
        parent.mkdir(mode=0o700)
        workspace = parent / "workspace"
        workspace.mkdir(mode=0o700)
        displaced = self.root / "partial-control-parent-displaced"
        replacement_sentinel = parent / "workspace" / "sentinel.txt"
        real_flock = workspace_runtime.fcntl.flock
        replaced = False

        def flock_then_replace(descriptor: int, operation: int) -> object:
            nonlocal replaced
            result = real_flock(descriptor, operation)
            if operation == workspace_runtime.fcntl.LOCK_EX and not replaced:
                parent.rename(displaced)
                parent.mkdir(mode=0o700)
                (parent / "workspace").mkdir(mode=0o700)
                replacement_sentinel.write_text("unrelated\n", encoding="utf-8")
                replaced = True
            return result

        try:
            with (
                mock.patch.object(
                    workspace_runtime.fcntl,
                    "flock",
                    side_effect=flock_then_replace,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._PartialRecoveryControl.create(workspace)
            self.assertTrue(replaced)
            self.assertIn(
                caught.exception.reason,
                {
                    "partial-recovery-binding-drift",
                    "partial-recovery-binding-unavailable",
                },
            )
            self.assertEqual(
                replacement_sentinel.read_text(encoding="utf-8"), "unrelated\n"
            )
            self.assertEqual(
                tuple(
                    parent.glob(f"{workspace_runtime.PARTIAL_RECOVERY_PREFIX}*.json")
                ),
                (),
            )
            self.assertEqual(
                tuple(
                    displaced.glob(f"{workspace_runtime.PARTIAL_RECOVERY_PREFIX}*.json")
                ),
                (),
            )
        finally:
            if replaced:
                replacement_sentinel.unlink(missing_ok=True)
                (parent / "workspace").rmdir()
                parent.rmdir()
                displaced.rename(parent)

    def test_partial_control_rechecks_parent_alias_after_record_publish(self) -> None:
        parent = self.root / "partial-control-publish-parent"
        parent.mkdir(mode=0o700)
        workspace = parent / "workspace"
        workspace.mkdir(mode=0o700)
        displaced = self.root / "partial-control-publish-parent-displaced"
        replacement_sentinel = parent / "workspace" / "sentinel.txt"
        control = workspace_runtime._PartialRecoveryControl.create(workspace)
        real_write = workspace_runtime._write_partial_recovery_record
        replaced = False

        def write_then_replace(*args: object, **kwargs: object) -> str:
            nonlocal replaced
            digest = real_write(*args, **kwargs)
            if not replaced:
                parent.rename(displaced)
                parent.mkdir(mode=0o700)
                (parent / "workspace").mkdir(mode=0o700)
                replacement_sentinel.write_text("unrelated\n", encoding="utf-8")
                replaced = True
            return digest

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_write_partial_recovery_record",
                    side_effect=write_then_replace,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                control.owner_exit_recovery_payload()
            self.assertTrue(replaced)
            self.assertIn(
                caught.exception.reason,
                {
                    "partial-recovery-binding-drift",
                    "partial-recovery-binding-unavailable",
                },
            )
            self.assertEqual(
                replacement_sentinel.read_text(encoding="utf-8"), "unrelated\n"
            )
            self.assertFalse(control.path.exists())
        finally:
            control.close(retain=False)
            if replaced:
                replacement_sentinel.unlink(missing_ok=True)
                (parent / "workspace").rmdir()
                parent.rmdir()
                displaced.rename(parent)

    def test_partial_recovery_rejects_active_unverifiable_and_replaced_state(
        self,
    ) -> None:
        cases = ("active", "unverifiable", "workspace-replaced", "control-replaced")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                destination = self.root / f"partial-recovery-{case}"
                destination.mkdir(mode=0o700)
                (destination / ".git").mkdir(mode=0o700)
                process_pid = 901_000 + index
                control_path, control_digest, payload = self.retained_control(
                    destination,
                    pid=process_pid,
                )
                owner_pid = payload["owner_process"]["pid"]
                process_start = payload["active_process"]["start_identity"]

                if case == "workspace-replaced":
                    displaced = self.root / f"partial-recovery-{case}-original"
                    destination.rename(displaced)
                    destination.mkdir(mode=0o700)
                    (destination / ".git").mkdir(mode=0o700)
                if case == "control-replaced":
                    control_bytes = control_path.read_bytes()
                    control_path.unlink()
                    control_path.write_bytes(control_bytes)
                    control_path.chmod(0o600)

                def process_identity(pid: int) -> str:
                    if pid == owner_pid:
                        raise ProcessLookupError(pid)
                    if case == "active" and pid == process_pid:
                        return str(process_start)
                    if case == "unverifiable" and pid == process_pid:
                        raise ReviewWorkspaceError(
                            "partial-recovery-process-identity-unavailable",
                            "fixture identity probe failed",
                            status="inconclusive",
                        )
                    raise ProcessLookupError(pid)

                expected_reason = {
                    "active": "partial-recovery-process-active",
                    "unverifiable": "partial-recovery-process-identity-unavailable",
                    "workspace-replaced": (
                        "partial-recovery-workspace-identity-mismatch"
                    ),
                    "control-replaced": ("partial-recovery-control-identity-mismatch"),
                }[case]
                with (
                    mock.patch.object(
                        workspace_runtime,
                        "_process_start_identity",
                        side_effect=process_identity,
                    ),
                    mock.patch.object(
                        workspace_runtime,
                        "_process_group_exists",
                        return_value=False,
                    ),
                    self.assertRaises(ReviewWorkspaceError) as caught,
                ):
                    workspace_runtime.recover_partial_workspace(
                        control_path,
                        control_digest,
                    )
                self.assertEqual(caught.exception.reason, expected_reason)
                self.assertTrue(control_path.exists())

    def test_partial_recovery_rereads_exact_control_before_terminal_receipt(
        self,
    ) -> None:
        destination = self.root / "partial-recovery-control-content-drift"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        original_identity = control_path.stat(follow_symlinks=False)
        original_clear = workspace_runtime._clear_bound_partial_contents
        mutated = False

        def clear_then_mutate_control(*args: object, **kwargs: object) -> None:
            nonlocal mutated
            original_clear(*args, **kwargs)
            descriptor = os.open(control_path, os.O_RDWR)
            try:
                first = os.pread(descriptor, 1, 0)
                self.assertEqual(first, b"{")
                os.pwrite(descriptor, b"[", 0)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            mutated = True

        with (
            mock.patch.object(
                workspace_runtime,
                "_clear_bound_partial_contents",
                side_effect=clear_then_mutate_control,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertTrue(mutated)
        self.assertEqual(caught.exception.reason, "partial-recovery-control-drift")
        final_identity = control_path.stat(follow_symlinks=False)
        self.assertEqual(original_identity.st_ino, final_identity.st_ino)
        self.assertEqual(original_identity.st_size, final_identity.st_size)
        self.assertEqual(tuple(destination.iterdir()), ())

    def test_partial_recovery_second_pass_timestamp_drift_is_inconclusive(
        self,
    ) -> None:
        destination = self.root / "partial-recovery-second-pass-drift"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        original = control_path.read_bytes()
        original_identity = control_path.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        target_calls = 0
        mutated = False

        def rewrite_after_second_eof(descriptor: int, size: int) -> bytes:
            nonlocal target_calls, mutated
            data = real_read(descriptor, size)
            if not os.path.samestat(os.fstat(descriptor), original_identity):
                return data
            target_calls += 1
            if target_calls == 1 and data:
                observed = control_path.stat(follow_symlinks=False)
                os.utime(
                    control_path,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
            elif target_calls == 4 and not data:
                writer = os.open(control_path, os.O_WRONLY)
                try:
                    os.pwrite(writer, bytes((original[0] ^ 1,)), 0)
                    os.fsync(writer)
                finally:
                    os.close(writer)
                observed = control_path.stat(follow_symlinks=False)
                os.utime(
                    control_path,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
                mutated = True
            return data

        with (
            mock.patch.object(
                workspace_runtime.os,
                "read",
                side_effect=rewrite_after_second_eof,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertTrue(mutated)
        self.assertEqual(target_calls, 4)
        self.assertEqual(
            caught.exception.reason,
            "partial-recovery-control-revalidation-unavailable",
        )
        self.assertEqual(caught.exception.status, "inconclusive")
        observed_identity = control_path.stat(follow_symlinks=False)
        self.assertEqual(observed_identity.st_ino, original_identity.st_ino)
        self.assertEqual(observed_identity.st_size, original_identity.st_size)

    def test_partial_recovery_accepts_utime_between_post_read_snapshots(
        self,
    ) -> None:
        destination = self.root / "partial-recovery-between-snapshot-utime"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        initial = control_path.stat(follow_symlinks=False)
        real_stat = workspace_runtime.os.stat
        touched = False

        def touch_before_first_path_snapshot(
            candidate: object,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal touched
            if (
                candidate == control_path.name
                and kwargs.get("dir_fd") is not None
                and not touched
            ):
                os.utime(
                    control_path,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                )
                touched = True
            return real_stat(candidate, *args, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "stat",
                side_effect=touch_before_first_path_snapshot,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            recovered = workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertTrue(touched)
        self.assertEqual(recovered.cleanup_status, "payload-removed")

    def test_partial_recovery_ignores_control_utime_during_cleanup(self) -> None:
        destination = self.root / "partial-recovery-control-utime"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        real_clear = workspace_runtime._clear_bound_partial_contents

        def clear_then_touch_control(*args: object, **kwargs: object) -> None:
            real_clear(*args, **kwargs)
            observed = control_path.stat(follow_symlinks=False)
            os.utime(
                control_path,
                ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000_000),
            )

        with (
            mock.patch.object(
                workspace_runtime,
                "_clear_bound_partial_contents",
                side_effect=clear_then_touch_control,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            recovered = workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertEqual(recovered.cleanup_status, "payload-removed")

    def test_partial_recovery_rejects_same_content_control_inode_replacement(
        self,
    ) -> None:
        destination = self.root / "partial-recovery-control-replacement"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        real_clear = workspace_runtime._clear_bound_partial_contents

        def clear_then_replace_control(*args: object, **kwargs: object) -> None:
            real_clear(*args, **kwargs)
            self.atomically_replace_private_file(
                control_path,
                control_path.read_bytes(),
            )

        with (
            mock.patch.object(
                workspace_runtime,
                "_clear_bound_partial_contents",
                side_effect=clear_then_replace_control,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertEqual(caught.exception.reason, "partial-recovery-control-drift")

    def test_partial_recovery_tombstone_finish_rechecks_late_children(self) -> None:
        cases: list[tuple[str, object]] = []
        markerless = self.root / "markerless-late-child-tombstone"
        markerless.mkdir(mode=0o700)
        (markerless / ".git").mkdir(mode=0o700)
        markerless_control = self.retained_control(markerless, pid=901_301)
        cases.append(("markerless", (markerless, *markerless_control[:2])))

        formal = prepare_workspace(
            self.repo,
            self.root / "formal-late-child-tombstone",
            self.commits[1],
            self.commits[2],
        )
        formal_control = self.retained_control(formal.root, pid=901_302)
        cases.append(("formal", (formal.root, *formal_control[:2])))

        for name, fixture in cases:
            with self.subTest(name=name):
                root, control_path, control_digest = fixture
                with (
                    mock.patch.object(
                        workspace_runtime,
                        "_process_start_identity",
                        side_effect=ProcessLookupError,
                    ),
                    mock.patch.object(
                        workspace_runtime,
                        "_process_group_exists",
                        return_value=False,
                    ),
                ):
                    workspace_runtime.recover_partial_workspace(
                        control_path,
                        control_digest,
                    )
                root_identity = root.stat(follow_symlinks=False)
                real_fstat = workspace_runtime.os.fstat
                matching_calls = 0
                injected = False

                def inject_after_second_root_fstat(descriptor: int):
                    nonlocal matching_calls, injected
                    metadata = real_fstat(descriptor)
                    if (
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_uid,
                    ) == (
                        root_identity.st_dev,
                        root_identity.st_ino,
                        root_identity.st_uid,
                    ):
                        matching_calls += 1
                        if matching_calls == 2:
                            (root / "late-child").write_text(
                                "late\n",
                                encoding="utf-8",
                            )
                            injected = True
                    return metadata

                with (
                    mock.patch.object(
                        workspace_runtime.os,
                        "fstat",
                        side_effect=inject_after_second_root_fstat,
                    ),
                    mock.patch.object(
                        workspace_runtime,
                        "_process_start_identity",
                        side_effect=ProcessLookupError,
                    ),
                    mock.patch.object(
                        workspace_runtime,
                        "_process_group_exists",
                        return_value=False,
                    ),
                ):
                    repeated = workspace_runtime.recover_partial_workspace(
                        control_path,
                        control_digest,
                    )
                self.assertTrue(injected)
                self.assertEqual(repeated.cleanup_status, "payload-removed")
                self.assertFalse((root / "late-child").exists())

    def test_formal_tombstone_rechecks_git_entries_after_marker_reread(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "formal-marker-reread-late-child",
            self.commits[1],
            self.commits[2],
        )
        control_path, control_digest, _payload = self.retained_control(
            prepared.root,
            pid=901_303,
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        marker_path = prepared.root / ".git" / workspace_runtime.WORKSPACE_MARKER
        marker_payload = marker_path.read_bytes()
        marker_identity = marker_path.stat(follow_symlinks=False)
        root_descriptor = os.open(
            prepared.root,
            workspace_runtime._nofollow_flags(directory=True),
        )
        original_read = workspace_runtime._read_descriptor_payload
        marker_reads = 0

        def inject_after_second_marker_read(
            descriptor: int,
            limit: int,
        ) -> bytes:
            nonlocal marker_reads
            observed = original_read(descriptor, limit)
            metadata = os.fstat(descriptor)
            if (
                metadata.st_dev,
                metadata.st_ino,
            ) == (
                marker_identity.st_dev,
                marker_identity.st_ino,
            ):
                marker_reads += 1
                if marker_reads == 2:
                    (prepared.root / ".git" / "late-child").write_text(
                        "late\n",
                        encoding="utf-8",
                    )
            return observed

        try:
            with mock.patch.object(
                workspace_runtime,
                "_read_descriptor_payload",
                side_effect=inject_after_second_marker_read,
            ):
                matched = workspace_runtime._partial_recovery_tombstone_matches(
                    prepared.root,
                    root_descriptor,
                    prepared.workspace_identity,
                    marker_payload,
                )
        finally:
            os.close(root_descriptor)
        self.assertEqual(marker_reads, 2)
        self.assertFalse(matched)
        self.assertTrue((prepared.root / ".git" / "late-child").is_file())

    def test_formal_validator_leak_emits_executable_recovery_and_roundtrips(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "formal-validator-recovery",
            self.commits[1],
            self.commits[2],
        )
        process_pid = 902_001
        fixed_git = workspace_runtime.resolve_git()
        real_capture = workspace_runtime.run_bounded_capture

        def fail_after_binding(command: tuple[str, ...], **kwargs: object) -> object:
            if command == (str(fixed_git), "--version"):
                return real_capture(command, **kwargs)
            kwargs["on_process_starting"]()
            kwargs["on_process_spawned"](
                workspace_runtime._RecoveryProcessIdentity(
                    process_pid,
                    process_pid,
                    "fixture-formal-validator-start",
                )
            )
            kwargs["on_process_started"]()
            raise workspace_runtime.ReviewProcessLeakError(
                "fixture formal validator leak"
            )

        with mock.patch.object(
            workspace_runtime,
            "run_bounded_capture",
            side_effect=fail_after_binding,
        ):
            with self.assertRaises(workspace_runtime.ReviewProcessLeakError) as caught:
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        self.assertIsNotNone(recovery)
        assert recovery is not None
        self.assertEqual(recovery["workspace_state"]["kind"], "formal-marked")
        self.assertEqual(
            recovery["active_process"]["process_state"],
            "quiescence-unproven",
        )
        self.assertEqual(
            recovery["recovery"]["command"],
            "recover-partial-workspace",
        )
        control = recovery["partial_recovery_control"]
        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            workspace_runtime.recover_partial_workspace(
                pathlib.Path(control["path"]),
                control["sha256"],
            )
        self.assertEqual(
            tuple(path.name for path in prepared.root.iterdir()),
            (".git",),
        )
        self.assertEqual(
            tuple(path.name for path in (prepared.root / ".git").iterdir()),
            (workspace_runtime.WORKSPACE_MARKER,),
        )
        self.assertTrue(pathlib.Path(control["path"]).is_file())

    def test_post_validate_late_rollback_restores_marker_and_executable_recovery(
        self,
    ) -> None:
        destination = self.root / "post-validate-late-rollback"

        def fail_validation(*_args: object, **_kwargs: object) -> object:
            raise ReviewWorkspaceError(
                "fixture-post-validate-failure",
                "fixture post-validate failure",
            )

        def fail_after_marker_removal(*_args: object, **_kwargs: object) -> None:
            raise OSError("fixture late directory removal failure")

        with (
            mock.patch.object(
                workspace_runtime,
                "validate_workspace",
                side_effect=fail_validation,
            ),
            mock.patch.object(
                workspace_runtime,
                "_finish_bound_directory_removal",
                side_effect=fail_after_marker_removal,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(
            caught.exception.reason,
            "workspace-publication-rollback-incomplete",
        )
        marker = destination / ".git" / workspace_runtime.WORKSPACE_MARKER
        self.assertTrue(marker.is_file())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(marker.parent.stat().st_mode), 0o700)
        self.assertEqual(tuple(path.name for path in destination.iterdir()), (".git",))
        self.assertEqual(
            tuple(path.name for path in marker.parent.iterdir()),
            (workspace_runtime.WORKSPACE_MARKER,),
        )
        details = caught.exception.details
        self.assertEqual(details["workspace_state"]["kind"], "formal-marked")
        recovery = details["recovery"]
        self.assertTrue(recovery["argv_ready"])
        self.assertEqual(recovery["argv"][0], "recover-partial-workspace")
        control = details["partial_recovery_control"]
        with mock.patch.object(
            workspace_runtime,
            "_process_start_identity",
            side_effect=ProcessLookupError,
        ):
            recovered = workspace_runtime.recover_partial_workspace(
                pathlib.Path(control["path"]),
                control["sha256"],
            )
        self.assertEqual(recovered.cleanup_status, "already-clean")

    def test_marker_write_failure_does_not_fabricate_formal_recovery_marker(
        self,
    ) -> None:
        destination = self.root / "marker-write-late-rollback"
        real_write = workspace_runtime._write_bytes

        def fail_marker_write(
            path: pathlib.Path,
            payload: bytes,
            mode: int,
        ) -> None:
            if path.name == workspace_runtime.WORKSPACE_MARKER:
                raise OSError("fixture marker write failure")
            real_write(path, payload, mode)

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_bytes",
                side_effect=fail_marker_write,
            ),
            mock.patch.object(
                workspace_runtime,
                "_finish_bound_directory_removal",
                side_effect=OSError("fixture late directory removal failure"),
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(
            caught.exception.reason,
            "workspace-publication-rollback-incomplete",
        )
        self.assertEqual(tuple(destination.iterdir()), ())
        self.assertEqual(
            caught.exception.details["workspace_state"]["kind"],
            "unpublished-markerless",
        )
        self.assertFalse(
            (destination / ".git" / workspace_runtime.WORKSPACE_MARKER).exists()
        )

    def test_partial_recovery_cli_emits_terminal_receipt(self) -> None:
        destination = self.root / "partial-recovery-cli"
        destination.mkdir(mode=0o700)
        (destination / ".git").mkdir(mode=0o700)
        control_path, control_digest, _payload = self.retained_control(destination)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_main(
                (
                    "recover-partial-workspace",
                    "--control-file",
                    str(control_path),
                    "--control-sha256",
                    control_digest,
                )
            )
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt["command"], "recover-partial-workspace")
        self.assertEqual(receipt["cleanup_status"], "payload-removed")
        self.assertEqual(receipt["tombstone_status"], "retained")
        self.assertTrue(destination.is_dir())
        self.assertEqual(tuple(destination.iterdir()), ())
        self.assertTrue(control_path.is_file())

    def test_validate_detects_config_and_object_hardlink_drift(self) -> None:
        destination = self.root / "drift-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        try:
            config = prepared.root / ".git/config"
            config.write_bytes(config.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(
                ReviewWorkspaceError, "config changed"
            ) as caught:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(caught.exception.reason, "workspace-config-drift")
            config.write_bytes(workspace_runtime._config_payload("sha1"))

            shallow = prepared.root / ".git/shallow"
            shallow.write_text(f"{self.commits[0]}\n", encoding="ascii")
            shallow.chmod(0o600)
            with self.assertRaises(ReviewWorkspaceError) as shallow_drift:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(shallow_drift.exception.reason, "workspace-shallow-drift")
            shallow.unlink()

            object_file = next(
                path
                for path in (prepared.root / ".git/objects").rglob("*")
                if path.is_file()
            )
            outside_link = self.root / "object-hardlink"
            os.link(object_file, outside_link)
            with self.assertRaises(ReviewWorkspaceError) as hardlink:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(hardlink.exception.reason, "workspace-object-hardlink")
            outside_link.unlink()
        finally:
            self.cleanup(prepared)

    def test_validate_rejects_unexpected_loose_range_object_layout(self) -> None:
        destination = self.root / "loose-corruption-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        try:
            blob = git(self.repo, "rev-parse", f"{self.commits[2]}:tracked.txt")
            forged_payload = b"Revision 2\n"
            loose = self.forge_loose_object(
                prepared.root,
                blob,
                b"blob",
                forged_payload,
            )
            self.assertTrue(loose.is_file())
            self.assert_batch_check_accepts_object(
                prepared.root,
                blob,
                "blob",
                len(forged_payload),
            )
            with self.assertRaises(ReviewWorkspaceError) as caught:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                caught.exception.reason,
                "workspace-object-layout",
            )
        finally:
            self.cleanup(prepared)

    def test_validate_rejects_loose_override_before_object_resolution(
        self,
    ) -> None:
        git(self.repo, "gc", "--prune=now")
        destination = self.root / "packed-corruption-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        try:
            blob = git(self.repo, "rev-parse", f"{self.commits[2]}:tracked.txt")
            loose = prepared.root / ".git/objects" / blob[:2] / blob[2:]
            self.assertFalse(loose.exists())
            forged_payload = b"Revision 2\n"
            self.forge_loose_object(
                prepared.root,
                blob,
                b"blob",
                forged_payload,
            )
            self.assert_batch_check_accepts_object(
                prepared.root,
                blob,
                "blob",
                len(forged_payload),
            )
            with self.assertRaises(ReviewWorkspaceError) as caught:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                caught.exception.reason,
                "workspace-object-layout",
            )
        finally:
            self.cleanup(prepared)

    def test_control_custody_rejects_permission_hardlink_and_symlink_drift(
        self,
    ) -> None:
        destination = self.root / "control-custody-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        config = prepared.root / ".git/config"
        try:
            os.chmod(self.root, 0o755)
            try:
                with self.assertRaises(ReviewWorkspaceError) as parent_permission:
                    validate_workspace(prepared.root, self.commits[1], self.commits[2])
                self.assertEqual(
                    parent_permission.exception.reason,
                    "workspace-parent-policy",
                )
            finally:
                os.chmod(self.root, 0o700)

            os.chmod(prepared.root, 0o755)
            try:
                with self.assertRaises(ReviewWorkspaceError) as permission:
                    validate_workspace(prepared.root, self.commits[1], self.commits[2])
                self.assertEqual(
                    permission.exception.reason,
                    "workspace-control-directory-policy",
                )
            finally:
                os.chmod(prepared.root, 0o700)

            config_payload = config.read_bytes()
            self.atomically_replace_private_file(config, config_payload)
            validate_workspace(prepared.root, self.commits[1], self.commits[2])

            index = prepared.root / ".git/index"
            os.chmod(index, 0o644)
            try:
                with self.assertRaises(ReviewWorkspaceError) as index_permission:
                    validate_workspace(prepared.root, self.commits[1], self.commits[2])
                self.assertEqual(
                    index_permission.exception.reason,
                    "workspace-control-file-policy",
                )
            finally:
                os.chmod(index, 0o600)

            outside_link = self.root / "config-hardlink"
            os.link(config, outside_link)
            with self.assertRaises(ReviewWorkspaceError) as hardlink:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                hardlink.exception.reason,
                "workspace-control-file-policy",
            )
            outside_link.unlink()

            original = prepared.root / ".git/config.original"
            config.rename(original)
            config.symlink_to(original)
            with self.assertRaises(ReviewWorkspaceError) as symlink:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                symlink.exception.reason,
                "workspace-control-state-unavailable",
            )
            config.unlink()
            original.rename(config)
        finally:
            self.cleanup(prepared)

    def test_control_binding_ignores_utime_but_protects_content_and_identity(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-binding-properties",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        original = config.read_bytes()
        binding = workspace_runtime._bind_workspace_controls(
            prepared.root,
            include_index=True,
            include_marker=True,
        )
        try:
            before = config.stat(follow_symlinks=False)
            os.utime(
                config,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
            binding.revalidate()

            descriptor = os.open(config, os.O_RDWR)
            try:
                os.pwrite(descriptor, bytes((original[0] ^ 1,)), 0)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            with self.assertRaises(ReviewWorkspaceError) as content_drift:
                binding.revalidate()
            self.assertEqual(
                content_drift.exception.reason,
                "workspace-control-file-drift",
            )

            descriptor = os.open(config, os.O_RDWR)
            try:
                os.pwrite(descriptor, original, 0)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            restored_binding = workspace_runtime._bind_workspace_controls(
                prepared.root,
                include_index=True,
                include_marker=True,
            )
            self.atomically_replace_private_file(config, original)
            with self.assertRaises(ReviewWorkspaceError) as identity_drift:
                restored_binding.revalidate()
            self.assertEqual(
                identity_drift.exception.reason,
                "workspace-control-file-drift",
            )
        finally:
            self.cleanup(prepared)

    def test_control_snapshot_bounded_reread_accepts_timestamp_churn(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-snapshot-timestamp-churn",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        config_identity = config.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        timestamp_updates = 0

        def read_with_timestamp_churn(descriptor: int, size: int) -> bytes:
            nonlocal timestamp_updates
            data = real_read(descriptor, size)
            try:
                same_file = os.path.samestat(
                    os.fstat(descriptor),
                    config_identity,
                )
            except OSError:
                same_file = False
            if data and same_file and timestamp_updates < 1:
                observed = config.stat(follow_symlinks=False)
                timestamp_updates += 1
                os.utime(
                    config,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
            return data

        root_descriptor = os.open(
            prepared.root, workspace_runtime._nofollow_flags(directory=True)
        )
        try:
            with mock.patch.object(
                workspace_runtime.os,
                "read",
                side_effect=read_with_timestamp_churn,
            ):
                snapshot = workspace_runtime._snapshot_control_file(
                    root_descriptor,
                    (".git", "config"),
                    capture_payload=True,
                )
            self.assertEqual(snapshot.payload, config.read_bytes())
            self.assertEqual(timestamp_updates, 1)
        finally:
            os.close(root_descriptor)
            self.cleanup(prepared)

    def test_control_snapshot_accepts_utime_between_post_read_snapshots(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-snapshot-between-snapshot-utime",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        initial = config.stat(follow_symlinks=False)
        original = config.read_bytes()
        real_stat = workspace_runtime.os.stat
        touched = False

        def touch_before_first_path_snapshot(
            candidate: object,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal touched
            if (
                candidate == config.name
                and kwargs.get("dir_fd") is not None
                and not touched
            ):
                os.utime(
                    config,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                )
                touched = True
            return real_stat(candidate, *args, **kwargs)

        root_descriptor = os.open(
            prepared.root, workspace_runtime._nofollow_flags(directory=True)
        )
        try:
            with mock.patch.object(
                workspace_runtime.os,
                "stat",
                side_effect=touch_before_first_path_snapshot,
            ):
                snapshot = workspace_runtime._snapshot_control_file(
                    root_descriptor,
                    (".git", "config"),
                    capture_payload=True,
                )
            self.assertTrue(touched)
            self.assertEqual(snapshot.payload, original)
            self.assertEqual(
                snapshot.mtime_ns,
                config.stat(follow_symlinks=False).st_mtime_ns,
            )
        finally:
            os.close(root_descriptor)
            self.cleanup(prepared)

    def test_control_snapshot_second_pass_timestamp_drift_is_inconclusive(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-snapshot-second-pass-drift",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        original = config.read_bytes()
        config_identity = config.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        target_calls = 0
        mutated = False

        def rewrite_after_second_eof(descriptor: int, size: int) -> bytes:
            nonlocal target_calls, mutated
            data = real_read(descriptor, size)
            if not os.path.samestat(os.fstat(descriptor), config_identity):
                return data
            target_calls += 1
            if target_calls == 1 and data:
                observed = config.stat(follow_symlinks=False)
                os.utime(
                    config,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
            elif target_calls == 4 and not data:
                writer = os.open(config, os.O_WRONLY)
                try:
                    os.pwrite(writer, bytes((original[0] ^ 1,)), 0)
                    os.fsync(writer)
                finally:
                    os.close(writer)
                observed = config.stat(follow_symlinks=False)
                os.utime(
                    config,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
                mutated = True
            return data

        root_descriptor = os.open(
            prepared.root, workspace_runtime._nofollow_flags(directory=True)
        )
        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "read",
                    side_effect=rewrite_after_second_eof,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._snapshot_control_file(
                    root_descriptor,
                    (".git", "config"),
                    capture_payload=True,
                )
            self.assertTrue(mutated)
            self.assertEqual(target_calls, 4)
            self.assertEqual(
                caught.exception.reason,
                "workspace-control-file-revalidation-unavailable",
            )
            self.assertEqual(caught.exception.status, "inconclusive")
            observed_identity = config.stat(follow_symlinks=False)
            self.assertEqual(observed_identity.st_ino, config_identity.st_ino)
            self.assertEqual(observed_identity.st_size, config_identity.st_size)
        finally:
            writer = os.open(config, os.O_WRONLY)
            try:
                os.pwrite(writer, original, 0)
                os.fsync(writer)
            finally:
                os.close(writer)
            os.close(root_descriptor)
            self.cleanup(prepared)

    def test_control_snapshot_failed_bounded_reread_is_unavailable_not_drift(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-snapshot-reread-unavailable",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        config_identity = config.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        target_calls = 0

        def fail_second_pass(descriptor: int, size: int) -> bytes:
            nonlocal target_calls
            if os.path.samestat(os.fstat(descriptor), config_identity):
                target_calls += 1
                if target_calls == 3:
                    raise OSError("fixture reread failure")
            data = real_read(descriptor, size)
            if target_calls == 1 and data:
                observed = config.stat(follow_symlinks=False)
                os.utime(
                    config,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
            return data

        root_descriptor = os.open(
            prepared.root, workspace_runtime._nofollow_flags(directory=True)
        )
        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "read",
                    side_effect=fail_second_pass,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._snapshot_control_file(
                    root_descriptor,
                    (".git", "config"),
                    capture_payload=True,
                )
            self.assertEqual(
                caught.exception.reason,
                "workspace-control-file-revalidation-unavailable",
            )
        finally:
            os.close(root_descriptor)
            self.cleanup(prepared)

    def test_control_snapshot_initial_read_failure_is_unavailable(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "control-snapshot-initial-unavailable",
            self.commits[1],
            self.commits[2],
        )
        config = prepared.root / ".git/config"
        config_identity = config.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read

        def fail_initial_read(descriptor: int, size: int) -> bytes:
            if os.path.samestat(os.fstat(descriptor), config_identity):
                raise OSError("fixture initial read failure")
            return real_read(descriptor, size)

        root_descriptor = os.open(
            prepared.root,
            workspace_runtime._nofollow_flags(directory=True),
        )
        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "read",
                    side_effect=fail_initial_read,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._snapshot_control_file(
                    root_descriptor,
                    (".git", "config"),
                    capture_payload=True,
                )
            self.assertEqual(
                caught.exception.reason,
                "workspace-control-file-unavailable",
            )
        finally:
            os.close(root_descriptor)
            self.cleanup(prepared)

    def test_skip_worktree_uppercase_s_and_malformed_flag_output_are_rejected(
        self,
    ) -> None:
        destination = self.root / "skip-worktree-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        try:
            git(prepared.root, "update-index", "--skip-worktree", "tracked.txt")
            os.chmod(prepared.root / ".git/index", 0o600)
            binding = workspace_runtime._bind_workspace_controls(
                prepared.root,
                include_index=True,
                include_marker=True,
            )
            raw_flags = workspace_runtime._run_git(
                prepared.root,
                ("ls-files", "-v", "-z"),
                control_binding=binding,
            )
            self.assertTrue(raw_flags.startswith(b"S tracked.txt\0"))
            with self.assertRaises(ReviewWorkspaceError) as skip:
                workspace_runtime._validate_clean(prepared.root, binding)
            self.assertEqual(skip.exception.reason, "workspace-index-flags")

            git(prepared.root, "update-index", "--no-skip-worktree", "tracked.txt")
            os.chmod(prepared.root / ".git/index", 0o600)
            git(prepared.root, "update-index", "--assume-unchanged", "tracked.txt")
            os.chmod(prepared.root / ".git/index", 0o600)
            binding = workspace_runtime._bind_workspace_controls(
                prepared.root,
                include_index=True,
                include_marker=True,
            )
            raw_flags = workspace_runtime._run_git(
                prepared.root,
                ("ls-files", "-v", "-z"),
                control_binding=binding,
            )
            self.assertTrue(raw_flags.startswith(b"h tracked.txt\0"))
            with self.assertRaises(ReviewWorkspaceError) as assume_unchanged:
                workspace_runtime._validate_clean(prepared.root, binding)
            self.assertEqual(
                assume_unchanged.exception.reason,
                "workspace-index-flags",
            )

            git(prepared.root, "update-index", "--no-assume-unchanged", "tracked.txt")
            os.chmod(prepared.root / ".git/index", 0o600)
            binding = workspace_runtime._bind_workspace_controls(
                prepared.root,
                include_index=True,
                include_marker=True,
            )
            original_run_git = workspace_runtime._run_git

            def malformed_flags(
                root: pathlib.Path,
                arguments: tuple[str, ...],
                **kwargs: object,
            ) -> bytes:
                if arguments == ("ls-files", "-v", "-z"):
                    return b"H\0"
                return original_run_git(root, arguments, **kwargs)

            with (
                mock.patch.object(
                    workspace_runtime,
                    "_run_git",
                    side_effect=malformed_flags,
                ),
                self.assertRaises(ReviewWorkspaceError) as malformed,
            ):
                workspace_runtime._validate_clean(prepared.root, binding)
            self.assertEqual(
                malformed.exception.reason,
                "index-flags-output-invalid",
            )
        finally:
            self.cleanup(prepared)

    def test_source_file_timestamp_churn_rechecks_bytes_on_the_same_fd(self) -> None:
        source_state = self.root / "source-state"
        source_state.write_bytes(b"stable source bytes\n")
        real_read = workspace_runtime.os.read
        touched = False
        descriptors: list[int] = []

        def read_then_touch(descriptor: int, size: int) -> bytes:
            nonlocal touched
            payload = real_read(descriptor, size)
            descriptors.append(descriptor)
            if payload and not touched:
                observed = source_state.stat(follow_symlinks=False)
                os.utime(
                    source_state,
                    ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000_000),
                )
                touched = True
            return payload

        with mock.patch.object(
            workspace_runtime.os,
            "read",
            side_effect=read_then_touch,
        ):
            payload = workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertTrue(touched)
        self.assertEqual(payload, b"stable source bytes\n")
        self.assertEqual(len(set(descriptors)), 1)
        self.assertGreaterEqual(len(descriptors), 4)

    def test_source_file_accepts_utime_between_post_read_snapshots(self) -> None:
        source_state = self.root / "source-state-between-snapshot-utime"
        original = b"stable source bytes\n"
        source_state.write_bytes(original)
        initial = source_state.stat(follow_symlinks=False)
        real_stat = pathlib.Path.stat
        touched = False

        def touch_before_first_path_snapshot(
            candidate: pathlib.Path,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal touched
            if candidate == source_state and not touched:
                os.utime(
                    source_state,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                )
                touched = True
            return real_stat(candidate, *args, **kwargs)

        with mock.patch.object(
            pathlib.Path,
            "stat",
            new=touch_before_first_path_snapshot,
        ):
            payload = workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertTrue(touched)
        self.assertEqual(payload, original)

    def test_source_file_second_pass_timestamp_drift_is_inconclusive(self) -> None:
        source_state = self.root / "source-state-second-pass-drift"
        original = b"stable source bytes\n"
        source_state.write_bytes(original)
        original_identity = source_state.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        target_calls = 0
        mutated = False

        def rewrite_after_second_eof(descriptor: int, size: int) -> bytes:
            nonlocal target_calls, mutated
            data = real_read(descriptor, size)
            target_calls += 1
            if target_calls == 1 and data:
                observed = source_state.stat(follow_symlinks=False)
                os.utime(
                    source_state,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
            elif target_calls == 4 and not data:
                writer = os.open(source_state, os.O_WRONLY)
                try:
                    os.pwrite(writer, bytes((original[0] ^ 1,)), 0)
                    os.fsync(writer)
                finally:
                    os.close(writer)
                observed = source_state.stat(follow_symlinks=False)
                os.utime(
                    source_state,
                    ns=(
                        observed.st_atime_ns,
                        observed.st_mtime_ns + 1_000_000_000,
                    ),
                )
                mutated = True
            return data

        with (
            mock.patch.object(
                workspace_runtime.os,
                "read",
                side_effect=rewrite_after_second_eof,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertTrue(mutated)
        self.assertEqual(target_calls, 4)
        self.assertEqual(
            caught.exception.reason,
            "fixture-revalidation-unavailable",
        )
        self.assertEqual(caught.exception.status, "inconclusive")
        observed_identity = source_state.stat(follow_symlinks=False)
        self.assertEqual(observed_identity.st_ino, original_identity.st_ino)
        self.assertEqual(observed_identity.st_size, original_identity.st_size)

    def test_source_file_reread_distinguishes_unavailable_and_real_drift(self) -> None:
        source_state = self.root / "source-state-drift"
        source_state.write_bytes(b"stable source bytes\n")
        real_read = workspace_runtime.os.read
        mutated = False

        def read_then_mutate(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            payload = real_read(descriptor, size)
            if payload and not mutated:
                writer = os.open(source_state, os.O_WRONLY)
                try:
                    os.pwrite(writer, b"X", 0)
                    os.fsync(writer)
                finally:
                    os.close(writer)
                mutated = True
            return payload

        with (
            mock.patch.object(
                workspace_runtime.os,
                "read",
                side_effect=read_then_mutate,
            ),
            self.assertRaises(ReviewWorkspaceError) as drift,
        ):
            workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertEqual(drift.exception.reason, "fixture-drift")

        with (
            mock.patch.object(
                workspace_runtime.os,
                "open",
                side_effect=PermissionError("fixture unavailable"),
            ),
            self.assertRaises(ReviewWorkspaceError) as unavailable,
        ):
            workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertEqual(unavailable.exception.reason, "fixture-unavailable")

    def test_source_file_timestamp_revalidation_unavailable_is_distinct(self) -> None:
        source_state = self.root / "source-state-revalidation"
        source_state.write_bytes(b"stable source bytes\n")
        initial = source_state.stat(follow_symlinks=False)
        real_read = workspace_runtime.os.read
        real_stat = pathlib.Path.stat
        touched = False
        lexical_stats = 0

        def read_then_touch(descriptor: int, size: int) -> bytes:
            nonlocal touched
            payload = real_read(descriptor, size)
            if payload and not touched:
                os.utime(
                    source_state,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                )
                touched = True
            return payload

        def fail_second_lexical_stat(
            candidate: pathlib.Path,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal lexical_stats
            if candidate == source_state:
                lexical_stats += 1
                if lexical_stats == 2:
                    raise PermissionError("fixture revalidation unavailable")
            return real_stat(candidate, *args, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "read",
                side_effect=read_then_touch,
            ),
            mock.patch.object(
                pathlib.Path,
                "stat",
                new=fail_second_lexical_stat,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime._read_bounded_regular_file(
                source_state,
                limit=1024,
                deadline=float("inf"),
                reason="fixture-invalid",
                label="fixture source state",
                unavailable_reason="fixture-unavailable",
                revalidation_unavailable_reason="fixture-revalidation-unavailable",
                drift_reason="fixture-drift",
            )
        self.assertEqual(
            caught.exception.reason,
            "fixture-revalidation-unavailable",
        )

    def test_source_shallow_alias_is_read_only_once(self) -> None:
        shallow = self.repo / ".git/shallow"
        shallow.write_text(f"{self.commits[0]}\n", encoding="ascii")
        try:
            with mock.patch.object(
                workspace_runtime,
                "_read_bounded_regular_file",
                wraps=workspace_runtime._read_bounded_regular_file,
            ) as reader:
                discovered = workspace_runtime._discover_source(
                    self.repo,
                    float("inf"),
                )
            self.assertEqual(discovered.shallow_path, shallow)
            shallow_calls = [
                call
                for call in reader.call_args_list
                if call.args and call.args[0] == shallow
            ]
            self.assertEqual(len(shallow_calls), 1)
        finally:
            shallow.unlink(missing_ok=True)

    def test_checkout_occurrence_budgets_fail_before_materialization(self) -> None:
        blob = b"x" * 1024
        (self.repo / "repeat-a.bin").write_bytes(blob)
        (self.repo / "repeat-b.bin").write_bytes(blob)
        git(self.repo, "add", "repeat-a.bin", "repeat-b.bin")
        git(self.repo, "commit", "-m", "repeat blob")
        head = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "checkout-budget-workspace"
        with (
            mock.patch.object(
                workspace_runtime,
                "CHECKOUT_LOGICAL_BYTES_LIMIT",
                len(blob) + 1,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(self.repo, destination, self.commits[2], head)
        self.assertEqual(caught.exception.reason, "checkout-logical-byte-limit")
        self.assertEqual(caught.exception.details["limit"], len(blob) + 1)
        self.assertFalse(destination.exists())

    def test_preparation_deadline_and_checkout_capacity_fail_closed(self) -> None:
        deadline_destination = self.root / "deadline-workspace"
        with mock.patch.object(
            workspace_runtime,
            "WORKSPACE_PREPARATION_DEADLINE_SECONDS",
            0.0,
        ):
            with self.assertRaises(ReviewWorkspaceError) as deadline:
                prepare_workspace(
                    self.repo,
                    deadline_destination,
                    self.commits[1],
                    self.commits[2],
                )
        self.assertEqual(deadline.exception.reason, "workspace-preparation-deadline")
        self.assertFalse(deadline_destination.exists())

        capacity_destination = self.root / "capacity-workspace"
        with (
            mock.patch.object(
                workspace_runtime.shutil,
                "disk_usage",
                return_value=mock.Mock(free=0),
            ),
            self.assertRaises(ReviewWorkspaceError) as capacity,
        ):
            prepare_workspace(
                self.repo,
                capacity_destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(
            capacity.exception.reason,
            "checkout-capacity-insufficient",
        )
        self.assertFalse(capacity_destination.exists())

    def test_root_open_failure_after_mkdir_removes_unbound_partial(self) -> None:
        destination = self.root / "root-open-failure-workspace"
        original_open = os.open
        failed = False

        def fail_created_root_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal failed
            if path == destination.name and dir_fd is not None and not failed:
                failed = True
                raise PermissionError("fixture root-open failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "open",
                side_effect=fail_created_root_open,
            ),
            self.assertRaises(PermissionError),
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertTrue(failed)
        self.assertFalse(destination.exists())

    def test_unbound_partial_rollback_failure_reports_expected_locator(self) -> None:
        destination = self.root / "unbound-rollback-failure-workspace"
        original_open = os.open

        def fail_created_root_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == destination.name and dir_fd is not None:
                raise PermissionError("fixture root-open failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "open",
                    side_effect=fail_created_root_open,
                ),
                mock.patch.object(
                    workspace_runtime.os,
                    "rmdir",
                    side_effect=PermissionError("fixture rmdir failure"),
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                prepare_workspace(
                    self.repo,
                    destination,
                    self.commits[1],
                    self.commits[2],
                )
            self.assertEqual(
                caught.exception.reason,
                "workspace-publication-rollback-incomplete",
            )
            self.assertEqual(
                caught.exception.details["retained_path"],
                str(destination),
            )
            self.assertTrue(destination.is_dir())
        finally:
            if destination.exists():
                destination.rmdir()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "signal-mask custody requires POSIX pthread masks",
    )
    def test_signal_after_creation_unmask_rolls_back_and_propagates(self) -> None:
        destination = self.root / "creation-unmask-signal-workspace"
        original_finish = workspace_runtime._finish_forwarded_signal_mask
        finish_calls = 0

        def interrupt_after_creation_unmask(
            owner: workspace_runtime.ForwardedSignalMaskOwner,
            *,
            primary_error: BaseException | None,
        ) -> None:
            nonlocal finish_calls
            finish_calls += 1
            original_finish(owner, primary_error=primary_error)
            if finish_calls == 1:
                self.assertFalse(owner.active)
                raise workspace_runtime.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                workspace_runtime,
                "_finish_forwarded_signal_mask",
                side_effect=interrupt_after_creation_unmask,
            ),
            self.assertRaises(workspace_runtime.ForwardedSignal) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(caught.exception.signum, signal.SIGTERM)
        self.assertEqual(finish_calls, 2)
        self.assertFalse(destination.exists())

    def test_complete_unrelated_range_is_invalid_not_incomplete(self) -> None:
        git(self.repo, "switch", "-c", "unrelated", self.commits[0])
        (self.repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
        git(self.repo, "add", "unrelated.txt")
        git(self.repo, "commit", "-m", "unrelated change")
        unrelated = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "invalid-range-workspace"
        with self.assertRaises(ReviewWorkspaceError) as caught:
            prepare_workspace(
                self.repo,
                destination,
                self.commits[2],
                unrelated,
            )
        self.assertEqual(caught.exception.status, "invalid-range")
        self.assertEqual(caught.exception.reason, "base-not-ancestor")
        self.assertFalse(destination.exists())

    def test_raw_parent_graph_operational_failure_is_not_an_invalid_range(self) -> None:
        destination = self.root / "raw-graph-failure-workspace"
        original_run_git_raw = workspace_runtime._run_git_raw

        def fail_raw_graph(
            root: pathlib.Path,
            arguments: tuple[str, ...],
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            if arguments == (
                "rev-list",
                "--parents",
                "--missing=print",
                self.commits[2],
            ):
                return 2, b"", b"fixture operational failure\n"
            return original_run_git_raw(root, arguments, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                side_effect=fail_raw_graph,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(caught.exception.status, "blocked-safety")
        self.assertEqual(caught.exception.reason, "range-parent-graph-check-failed")
        self.assertFalse(destination.exists())

    def test_shallow_or_promisor_raw_graph_operational_failure_is_blocked(
        self,
    ) -> None:
        original_run_git_raw = workspace_runtime._run_git_raw

        def fail_raw_graph(
            root: pathlib.Path,
            arguments: tuple[str, ...],
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            if arguments == (
                "rev-list",
                "--parents",
                "--missing=print",
                self.commits[2],
            ):
                return 2, b"", b"fixture operational failure\n"
            return original_run_git_raw(root, arguments, **kwargs)

        for shallow, promisor in ((True, False), (False, True)):
            with (
                self.subTest(shallow=shallow, promisor=promisor),
                mock.patch.object(
                    workspace_runtime,
                    "_run_git_raw",
                    side_effect=fail_raw_graph,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._freeze_range(
                    self.repo,
                    "sha1",
                    self.commits[1],
                    self.commits[2],
                    shallow=shallow,
                    promisor=promisor,
                    shallow_boundaries=(self.commits[0],) if shallow else (),
                )
            self.assertNotIsInstance(caught.exception, RangeIncomplete)
            self.assertEqual(caught.exception.status, "blocked-safety")
            self.assertEqual(
                caught.exception.reason,
                "range-parent-graph-check-failed",
            )

    def test_shared_missing_frontier_without_known_overlap_proof_is_incomplete(
        self,
    ) -> None:
        head = self.commits[2]
        base = self.commits[1]
        side = "a" * 40
        missing_parent = "b" * 40
        probe = workspace_runtime._RawCommitGraphProbe(
            parents={
                head: (base, side),
                base: (missing_parent,),
                side: (self.commits[0],),
                self.commits[0]: (),
            },
            missing=frozenset({missing_parent}),
            returncode=0,
            stderr_preview="",
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "_read_raw_commit_graph",
                return_value=probe,
            ),
            self.assertRaises(RangeIncomplete) as caught,
        ):
            workspace_runtime._select_raw_commit_scope(
                self.repo,
                base,
                head,
                deadline=float("inf"),
                source_shallow=True,
            )
        self.assertEqual(caught.exception.reason, "range-parent-graph-missing")
        self.assertEqual(
            caught.exception.details["missing_objects"],
            [missing_parent],
        )

    def test_shared_missing_frontier_does_not_widen_redundant_merge_range(
        self,
    ) -> None:
        known_root = "1" * 40
        shared_ancestor = "2" * 40
        missing_bridge = "3" * 40
        side = "4" * 40
        base = "5" * 40
        head = "6" * 40

        # The complete DAG is C->K, M->C, Q->M, B->(K,Q), H->(B,C).
        # With M absent, the observable raw graph cannot prove that C is
        # already in Reach(B); C->K alone is not evidence that C belongs to
        # B..H.
        probe = workspace_runtime._RawCommitGraphProbe(
            parents={
                head: (base, shared_ancestor),
                base: (known_root, side),
                side: (missing_bridge,),
                shared_ancestor: (known_root,),
                known_root: (),
            },
            missing=frozenset({missing_bridge}),
            returncode=0,
            stderr_preview="",
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "_read_raw_commit_graph",
                return_value=probe,
            ),
            self.assertRaises(RangeIncomplete) as caught,
        ):
            workspace_runtime._select_raw_commit_scope(
                self.repo,
                base,
                head,
                deadline=float("inf"),
                source_shallow=True,
            )
        self.assertEqual(caught.exception.reason, "range-parent-graph-missing")
        self.assertEqual(
            caught.exception.details["missing_objects"],
            [missing_bridge],
        )

    def test_real_missing_frontier_is_safe_but_mixed_frontier_requires_deepen(
        self,
    ) -> None:
        head = self.commits[2]
        base = self.commits[1]
        old = self.commits[0]
        missing_parent = "b" * 40
        missing_only = workspace_runtime._RawCommitGraphProbe(
            parents={head: (base,), base: (missing_parent,)},
            missing=frozenset({missing_parent}),
            returncode=0,
            stderr_preview="",
        )
        with mock.patch.object(
            workspace_runtime,
            "_read_raw_commit_graph",
            return_value=missing_only,
        ):
            scope = workspace_runtime._select_raw_commit_scope(
                self.repo,
                base,
                head,
                deadline=float("inf"),
                source_shallow=True,
            )
        self.assertEqual(scope.range_commits, (head,))
        self.assertEqual(scope.base_support_commits, (base,))
        self.assertEqual(scope.shallow_boundaries, (base,))

        mixed = workspace_runtime._RawCommitGraphProbe(
            parents={
                head: (base,),
                base: (old, missing_parent),
                old: (),
            },
            missing=frozenset({missing_parent}),
            returncode=0,
            stderr_preview="",
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "_read_raw_commit_graph",
                return_value=mixed,
            ),
            self.assertRaises(RangeIncomplete) as caught,
        ):
            workspace_runtime._select_raw_commit_scope(
                self.repo,
                base,
                head,
                deadline=float("inf"),
                source_shallow=True,
            )
        self.assertEqual(caught.exception.reason, "range-parent-graph-missing")
        self.assertEqual(caught.exception.details["missing_objects"], [missing_parent])

    def test_range_completeness_operational_failure_is_blocked(self) -> None:
        original_run_git_raw = workspace_runtime._run_git_raw
        command = (
            "rev-list",
            "--objects",
            "--missing=print",
            "--no-object-names",
            "--no-walk=unsorted",
            "--stdin",
        )

        def fail_completeness(
            root: pathlib.Path,
            arguments: tuple[str, ...],
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            if arguments == command:
                return 2, b"", b"x" * 8192
            return original_run_git_raw(root, arguments, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                side_effect=fail_completeness,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime._freeze_range(
                self.repo,
                "sha1",
                self.commits[1],
                self.commits[2],
                shallow=False,
                promisor=False,
            )
        self.assertNotIsInstance(caught.exception, RangeIncomplete)
        self.assertEqual(caught.exception.status, "blocked-safety")
        self.assertEqual(caught.exception.reason, "range-object-check-failed")
        failures = caught.exception.details["failures"]
        self.assertIsInstance(failures, list)
        assert isinstance(failures, list)
        self.assertEqual(failures[0]["returncode"], 2)
        self.assertEqual(len(failures[0]["stderr_preview"]), 4096)

    def test_range_completeness_requires_a_valid_missing_oid(self) -> None:
        original_run_git_raw = workspace_runtime._run_git_raw
        command = (
            "rev-list",
            "--objects",
            "--missing=print",
            "--no-object-names",
            "--no-walk=unsorted",
            "--stdin",
        )

        def freeze_with_snapshot_output(payload: bytes) -> None:
            def replace_snapshot(
                root: pathlib.Path,
                arguments: tuple[str, ...],
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                if arguments == command:
                    return 2, payload, b"fixture snapshot failure"
                return original_run_git_raw(root, arguments, **kwargs)

            with mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                side_effect=replace_snapshot,
            ):
                workspace_runtime._freeze_range(
                    self.repo,
                    "sha1",
                    self.commits[1],
                    self.commits[2],
                    shallow=False,
                    promisor=False,
                )

        missing_oid = "e" * 40
        with self.assertRaises(RangeIncomplete) as missing:
            freeze_with_snapshot_output(f"?{missing_oid}\n".encode("ascii"))
        self.assertEqual(missing.exception.reason, "range-object-missing")
        self.assertEqual(missing.exception.details["missing_objects"], [missing_oid])

        with self.assertRaises(ReviewWorkspaceError) as malformed:
            freeze_with_snapshot_output(b"?not-an-object-id\n")
        self.assertNotIsInstance(malformed.exception, RangeIncomplete)
        self.assertEqual(
            malformed.exception.reason,
            "range-object-output-invalid",
        )

    def test_base_support_probe_has_missing_and_operational_states(self) -> None:
        missing_oid = "f" * 40
        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                return_value=(
                    2,
                    (f"{self.commits[2]} {missing_oid}\n?{missing_oid}\n").encode(
                        "ascii"
                    ),
                    b"missing",
                ),
            ),
            self.assertRaises(RangeIncomplete) as missing,
        ):
            workspace_runtime._base_ancestry_support_objects(
                self.repo,
                self.commits[1],
                self.commits[2],
                deadline=float("inf"),
                source_shallow=False,
            )
        self.assertEqual(missing.exception.reason, "base-parent-graph-missing")
        self.assertEqual(missing.exception.details["missing_objects"], [missing_oid])

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                return_value=(2, b"", b"y" * 8192),
            ),
            self.assertRaises(ReviewWorkspaceError) as operational,
        ):
            workspace_runtime._base_ancestry_support_objects(
                self.repo,
                self.commits[1],
                self.commits[2],
                deadline=float("inf"),
                source_shallow=False,
            )
        self.assertNotIsInstance(operational.exception, RangeIncomplete)
        self.assertEqual(
            operational.exception.reason,
            "base-parent-graph-check-failed",
        )
        self.assertEqual(operational.exception.details["returncode"], 2)
        self.assertEqual(len(operational.exception.details["stderr_preview"]), 4096)

    def test_promisor_unrelated_complete_range_is_invalid(self) -> None:
        git(self.repo, "switch", "-c", "unrelated", self.commits[0])
        (self.repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
        git(self.repo, "add", "unrelated.txt")
        git(self.repo, "commit", "-m", "unrelated change")
        unrelated = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "config", "extensions.partialClone", "origin")
        git(self.repo, "config", "remote.origin.promisor", "true")
        destination = self.root / "promisor-range-workspace"
        with self.assertRaises(ReviewWorkspaceError) as caught:
            prepare_workspace(
                self.repo,
                destination,
                self.commits[2],
                unrelated,
            )
        self.assertNotIsInstance(caught.exception, RangeIncomplete)
        self.assertEqual(caught.exception.status, "invalid-range")
        self.assertEqual(caught.exception.reason, "base-not-ancestor")
        self.assertFalse(destination.exists())

    def test_prepare_and_cleanup_can_defer_signal_handoff(self) -> None:
        destination = self.root / "signal-handoff-workspace"
        prepared = prepare_workspace(
            self.repo,
            destination,
            self.commits[1],
            self.commits[2],
            defer_signal_handoff=True,
        )
        self.assertIsNotNone(prepared._handoff_signal_mask)
        assert prepared._handoff_signal_mask is not None
        self.assertTrue(prepared._handoff_signal_mask.active)
        prepared._handoff_signal_mask.restore()
        cleaned = cleanup_workspace(
            prepared.root,
            prepared.cleanup_token,
            defer_signal_handoff=True,
        )
        self.assertIsNotNone(cleaned._handoff_signal_mask)
        assert cleaned._handoff_signal_mask is not None
        self.assertTrue(cleaned._handoff_signal_mask.active)
        self.assertFalse(prepared.root.exists())
        cleaned._handoff_signal_mask.restore()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "exact signal-mask fallback requires POSIX pthread masks",
    )
    def test_exact_signal_mask_fallback_preserves_the_primary_outcome(
        self,
    ) -> None:
        owner = workspace_runtime.ForwardedSignalMaskOwner()
        previous_mask = {signal.SIGTERM}
        owner.publish(previous_mask)
        primary = ReviewWorkspaceError(
            "workspace-cleanup-incomplete",
            "fixture cleanup failure",
            details={
                "retained_path": "/private/fixture/workspace",
                "cleanup_token": "fixture-token",
            },
        )
        with (
            mock.patch.object(
                owner,
                "restore",
                side_effect=(OSError("first"), OSError("second")),
            ) as restore,
            mock.patch.object(
                workspace_runtime,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(
                workspace_runtime.signal,
                "pthread_sigmask",
                return_value=set(),
            ) as direct_restore,
        ):
            workspace_runtime._finish_forwarded_signal_mask(
                owner,
                primary_error=primary,
            )
        self.assertEqual(restore.call_count, 2)
        direct_restore.assert_called_once_with(signal.SIG_SETMASK, previous_mask)
        self.assertFalse(owner.active)
        self.assertEqual(
            primary.details["retained_path"],
            "/private/fixture/workspace",
        )
        self.assertEqual(
            primary.details["cleanup_token"],
            "fixture-token",
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "exact signal-mask fallback requires POSIX pthread masks",
    )
    def test_signal_mask_restore_failure_is_fatal_when_exact_fallback_fails(
        self,
    ) -> None:
        owner = workspace_runtime.ForwardedSignalMaskOwner()
        previous_mask = {signal.SIGTERM}
        owner.publish(previous_mask)
        primary = ReviewWorkspaceError(
            "workspace-cleanup-incomplete",
            "fixture cleanup failure",
            details={
                "retained_path": "/private/fixture/workspace",
                "cleanup_token": "fixture-token",
            },
        )
        with (
            mock.patch.object(
                owner,
                "restore",
                side_effect=(OSError("first"), OSError("second")),
            ) as restore,
            mock.patch.object(
                workspace_runtime,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(
                workspace_runtime.signal,
                "pthread_sigmask",
                side_effect=OSError("direct fallback failed"),
            ) as direct_restore,
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime._finish_forwarded_signal_mask(
                owner,
                primary_error=primary,
            )
        self.assertEqual(restore.call_count, 2)
        direct_restore.assert_called_once_with(signal.SIG_SETMASK, previous_mask)
        self.assertTrue(owner.active)
        self.assertEqual(
            caught.exception.reason,
            "workspace-signal-mask-restore-failed",
        )
        self.assertEqual(
            caught.exception.details["direct_exact_mask_fallback"],
            "failed",
        )
        self.assertTrue(caught.exception.details["signal_mask_owner_active"])
        self.assertEqual(
            caught.exception.details["retained_path"],
            "/private/fixture/workspace",
        )
        self.assertEqual(
            caught.exception.details["cleanup_token"],
            "fixture-token",
        )

    def test_transient_signal_mask_restore_failure_does_not_change_success(
        self,
    ) -> None:
        owner = workspace_runtime.ForwardedSignalMaskOwner()
        owner.publish(set())
        attempts = 0

        def restore_on_retry() -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("fixture transient restore failure")
            owner.active = False

        with (
            mock.patch.object(owner, "restore", side_effect=restore_on_retry),
            mock.patch.object(
                workspace_runtime,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
        ):
            workspace_runtime._finish_forwarded_signal_mask(
                owner,
                primary_error=None,
            )
        self.assertEqual(attempts, 2)
        self.assertFalse(owner.active)

    def test_secondary_signal_diagnostic_is_visible_without_add_note(self) -> None:
        class LegacyError(Exception):
            add_note = None

        primary = LegacyError("primary")
        workspace_runtime._attach_workspace_diagnostic(primary, "secondary")
        self.assertIsInstance(
            primary.__cause__,
            workspace_runtime._WorkspaceSecondaryDiagnostic,
        )
        self.assertEqual(str(primary.__cause__), "secondary")

    def test_validate_uses_the_marker_from_its_control_binding(self) -> None:
        destination = self.root / "marker-binding-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        marker_path = prepared.root / ".git/review-workspace.json"
        original_payload = marker_path.read_bytes()
        replacement = json.loads(original_payload)
        replacement["cleanup_token_sha256"] = "0" * 64
        replacement_payload = (json.dumps(replacement, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        original_validate_parent = workspace_runtime._validate_parent_identity
        replaced = False

        def replace_after_marker_parse(
            root: pathlib.Path,
            marker: dict[str, object],
        ) -> tuple[int, int, int]:
            nonlocal replaced
            identity = original_validate_parent(root, marker)
            if not replaced:
                replaced = True
                self.atomically_replace_private_file(marker_path, replacement_payload)
            return identity

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_validate_parent_identity",
                    side_effect=replace_after_marker_parse,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                caught.exception.reason,
                "workspace-control-file-drift",
            )
        finally:
            if prepared.root.exists():
                self.atomically_replace_private_file(marker_path, original_payload)
                self.cleanup(prepared)

    def test_cleanup_revalidates_marker_before_custody_transfer(self) -> None:
        destination = self.root / "cleanup-marker-binding-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        marker_path = prepared.root / ".git/review-workspace.json"
        original_payload = marker_path.read_bytes()
        replacement = json.loads(original_payload)
        replacement["cleanup_token_sha256"] = "0" * 64
        replacement_payload = (json.dumps(replacement, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        original_begin_mask = workspace_runtime._begin_forwarded_signal_mask

        def replace_before_custody() -> object:
            self.atomically_replace_private_file(marker_path, replacement_payload)
            return original_begin_mask()

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_begin_forwarded_signal_mask",
                    side_effect=replace_before_custody,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                cleanup_workspace(prepared.root, prepared.cleanup_token)
            self.assertEqual(caught.exception.reason, "workspace-cleanup-incomplete")
            self.assertEqual(
                caught.exception.details["primary_reason"],
                "workspace-control-file-drift",
            )
            self.assertTrue(prepared.root.is_dir())
        finally:
            if prepared.root.exists():
                self.atomically_replace_private_file(marker_path, original_payload)
                self.cleanup(prepared)

    def test_cleanup_parent_replacement_preserves_unrelated_same_name_object(
        self,
    ) -> None:
        parent = self.root / "cleanup-parent-replacement"
        parent.mkdir(mode=0o700)
        destination = parent / "workspace"
        prepared = prepare_workspace(
            self.repo,
            destination,
            self.commits[1],
            self.commits[2],
        )
        displaced = self.root / "cleanup-parent-replacement-displaced"
        replacement = parent / destination.name
        sentinel = replacement / "sentinel.txt"
        original_rename = workspace_runtime._rename_exclusive
        replacement_identity: tuple[int, int] | None = None
        replaced = False

        def replace_parent_then_rename(*args: object, **kwargs: object) -> None:
            nonlocal replaced, replacement_identity
            if not replaced:
                parent.rename(displaced)
                parent.mkdir(mode=0o700)
                replacement.mkdir(mode=0o700)
                sentinel.write_text("unrelated sentinel\n", encoding="utf-8")
                metadata = replacement.stat(follow_symlinks=False)
                replacement_identity = (metadata.st_dev, metadata.st_ino)
                replaced = True
            original_rename(*args, **kwargs)

        try:
            with mock.patch.object(
                workspace_runtime,
                "_rename_exclusive",
                side_effect=replace_parent_then_rename,
            ):
                cleaned = cleanup_workspace(prepared.root, prepared.cleanup_token)
            self.assertEqual(cleaned.cleanup_status, "complete")
            self.assertTrue(replaced)
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "unrelated sentinel\n"
            )
            final_metadata = replacement.stat(follow_symlinks=False)
            self.assertEqual(
                (final_metadata.st_dev, final_metadata.st_ino),
                replacement_identity,
            )
            self.assertEqual(tuple(parent.glob(".review-cleanup-*")), ())
            self.assertEqual(tuple(displaced.iterdir()), ())
        finally:
            if sentinel.exists():
                sentinel.unlink()
            if replacement.exists():
                replacement.rmdir()
            if parent.exists():
                parent.rmdir()
            if displaced.exists():
                displaced.rmdir()

    @unittest.skipUnless(
        os.name == "posix",
        "descriptor-bound cleanup requires POSIX directory descriptors",
    )
    def test_bound_cleanup_does_not_report_success_after_target_replacement(
        self,
    ) -> None:
        target = self.root / "cleanup-race-target"
        retained = self.root / "cleanup-race-retained"
        target.mkdir(mode=0o700)
        metadata = target.stat(follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
        original_rmdir = os.rmdir
        replaced = False

        def replace_before_final_rmdir(
            path: object,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal replaced
            if path == target.name and dir_fd is not None and not replaced:
                replaced = True
                os.rename(
                    target.name,
                    retained.name,
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
                os.mkdir(target.name, mode=0o700, dir_fd=dir_fd)
            original_rmdir(path, dir_fd=dir_fd)

        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "rmdir",
                    side_effect=replace_before_final_rmdir,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                workspace_runtime._remove_bound_directory(target, identity)
            self.assertTrue(replaced)
            self.assertEqual(
                caught.exception.reason,
                "workspace-cleanup-identity-retained",
            )
            self.assertEqual(
                caught.exception.details["retained_path"],
                str(retained),
            )
            self.assertFalse(target.exists())
            self.assertTrue(retained.is_dir())
        finally:
            if retained.exists():
                workspace_runtime._remove_bound_directory(retained, identity)
            if target.exists():
                target.rmdir()

    def test_cleanup_requires_the_bound_token_and_root_identity(self) -> None:
        destination = self.root / "cleanup-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        with self.assertRaises(ReviewWorkspaceError) as wrong_token:
            cleanup_workspace(prepared.root, "not-the-token")
        self.assertEqual(wrong_token.exception.reason, "cleanup-token-mismatch")
        self.assertTrue(prepared.root.is_dir())

        marker_path = prepared.root / ".git/review-workspace.json"
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["parent_identity"]["inode"] += 1
        marker_path.write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaises(ReviewWorkspaceError) as wrong_parent:
            cleanup_workspace(prepared.root, prepared.cleanup_token)
        self.assertEqual(
            wrong_parent.exception.reason, "workspace-parent-identity-mismatch"
        )
        marker["parent_identity"]["inode"] -= 1
        marker["workspace_identity"]["inode"] += 1
        marker_path.write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaises(ReviewWorkspaceError) as wrong_identity:
            cleanup_workspace(prepared.root, prepared.cleanup_token)
        self.assertEqual(wrong_identity.exception.reason, "workspace-identity-mismatch")
        self.assertTrue(prepared.root.is_dir())
        marker["workspace_identity"]["inode"] -= 1
        marker_path.write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
        )
        cleaned = cleanup_workspace(prepared.root, prepared.cleanup_token)
        self.assertEqual(cleaned.receipt()["cleanup_status"], "complete")
        self.assertFalse(prepared.root.exists())

    def test_real_split_index_and_external_shared_index_are_rejected(self) -> None:
        destination = self.root / "split-index-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        outside = self.root / "external-shared-index"
        try:
            git(prepared.root, "update-index", "--split-index")
            index = prepared.root / ".git/index"
            os.chmod(index, 0o600)
            shared = next((prepared.root / ".git").glob("sharedindex.*"))
            shared.rename(outside)
            shared.symlink_to(outside)
            with self.assertRaises(ReviewWorkspaceError) as caught:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(caught.exception.reason, "workspace-split-index")
            shared.unlink()
            outside.rename(shared)
            git(prepared.root, "update-index", "--no-split-index")
            os.chmod(index, 0o600)
            for candidate in (prepared.root / ".git").glob("sharedindex.*"):
                candidate.unlink()
        finally:
            outside.unlink(missing_ok=True)
            self.cleanup(prepared)

    def test_marker_count_token_and_receipt_identity_bindings_are_exact(self) -> None:
        destination = self.root / "marker-binding-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        marker_path = prepared.root / ".git/review-workspace.json"
        original = marker_path.read_bytes()
        receipt = prepared.receipt()
        try:
            self.assertEqual(receipt["git_identity"]["inode"], prepared.git_identity[1])
            self.assertEqual(
                receipt["objects_identity"]["inode"], prepared.objects_identity[1]
            )
            self.assertEqual(
                receipt["marker_sha256"], hashlib.sha256(original).hexdigest()
            )
            self.assertEqual(
                receipt["cleanup_token_sha256"],
                hashlib.sha256(prepared.cleanup_token.encode("utf-8")).hexdigest(),
            )
            marker = json.loads(original)
            support_payload = (
                prepared.root
                / ".git"
                / workspace_runtime.PARENT_SUPPORT_OBJECT_MANIFEST
            ).read_bytes()
            self.assertEqual(
                marker["parent_support_object_count"],
                prepared.parent_support_object_count,
            )
            self.assertEqual(
                marker["parent_support_object_sha256"],
                hashlib.sha256(support_payload).hexdigest(),
            )
            self.assertNotIn("cleanup_token", marker)
            self.assertNotIn(prepared.cleanup_token, original.decode("utf-8"))
            self.assertEqual(
                marker["cleanup_token_sha256"],
                receipt["cleanup_token_sha256"],
            )
            marker["cleanup_token"] = prepared.cleanup_token
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as plaintext_token:
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                    expected_cleanup_token=prepared.cleanup_token,
                )
            self.assertEqual(
                plaintext_token.exception.reason,
                "workspace-marker-invalid",
            )
            del marker["cleanup_token"]
            marker["commit_count"] = True
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as boolean_count:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(boolean_count.exception.reason, "workspace-marker-invalid")

            marker["commit_count"] = json.loads(original)["commit_count"]
            marker["parent_support_object_count"] = True
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as boolean_support_count:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                boolean_support_count.exception.reason,
                "workspace-marker-invalid",
            )

            marker["parent_support_object_count"] = json.loads(original)[
                "parent_support_object_count"
            ]
            marker["commit_count"] = 1
            marker["cleanup_token_sha256"] = hashlib.sha256(
                b"different-cleanup-token"
            ).hexdigest()
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as token_drift:
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                    expected_cleanup_token=prepared.cleanup_token,
                )
            self.assertEqual(
                token_drift.exception.reason,
                "workspace-cleanup-token-drift",
            )
        finally:
            self.atomically_replace_private_file(marker_path, original)
            self.cleanup(prepared)

    def test_marker_commit_count_is_rederived_from_range_objects(self) -> None:
        destination = self.root / "commit-count-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[0], self.commits[2]
        )
        marker_path = prepared.root / ".git/review-workspace.json"
        original = marker_path.read_bytes()
        try:
            marker = json.loads(original)
            marker["commit_count"] = 2
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as caught:
                validate_workspace(prepared.root, self.commits[0], self.commits[2])
            self.assertEqual(
                caught.exception.reason,
                "workspace-range-commit-count-mismatch",
            )
        finally:
            self.atomically_replace_private_file(marker_path, original)
            self.cleanup(prepared)

    def test_parent_support_manifest_rejects_overlap_and_missing_state(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "support-manifest-workspace",
            self.commits[1],
            self.commits[2],
        )
        marker_path = prepared.root / ".git/review-workspace.json"
        support_path = (
            prepared.root / ".git" / workspace_runtime.PARENT_SUPPORT_OBJECT_MANIFEST
        )
        range_path = prepared.root / ".git" / workspace_runtime.RANGE_OBJECT_MANIFEST
        original_marker = marker_path.read_bytes()
        original_support = support_path.read_bytes()
        try:
            overlap_oid = range_path.read_text(encoding="ascii").splitlines()[0]
            overlap_payload = original_support + f"{overlap_oid}\n".encode("ascii")
            overlap_ids = sorted(set(overlap_payload.decode("ascii").splitlines()))
            overlap_payload = b"".join(
                f"{oid}\n".encode("ascii") for oid in overlap_ids
            )
            marker = json.loads(original_marker)
            marker["parent_support_object_count"] = len(overlap_ids)
            marker["parent_support_object_sha256"] = hashlib.sha256(
                overlap_payload
            ).hexdigest()
            self.atomically_replace_private_file(support_path, overlap_payload)
            self.atomically_replace_private_file(
                marker_path,
                (json.dumps(marker, sort_keys=True) + "\n").encode("utf-8"),
            )
            with self.assertRaises(ReviewWorkspaceError) as overlap:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                overlap.exception.reason,
                "workspace-parent-support-manifest-invalid",
            )

            self.atomically_replace_private_file(marker_path, original_marker)
            support_path.unlink()
            with self.assertRaises(ReviewWorkspaceError) as missing:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                missing.exception.reason,
                "workspace-control-state-unavailable",
            )
        finally:
            self.atomically_replace_private_file(marker_path, original_marker)
            self.atomically_replace_private_file(support_path, original_support)
            self.cleanup(prepared)

    def test_destination_git_commands_do_not_discover_an_ancestor_repository(
        self,
    ) -> None:
        parent = self.repo / ".review-parent"
        parent.mkdir(mode=0o700)
        destination = parent / "workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        outer_index = self.repo / ".git/index"
        before = hashlib.sha256(outer_index.read_bytes()).hexdigest()
        binding = workspace_runtime._bind_workspace_controls(
            prepared.root,
            include_index=True,
            include_marker=True,
        )
        real_capture = workspace_runtime.run_bounded_capture

        def hide_git_then_run(*args: object, **kwargs: object) -> object:
            hidden = prepared.root / ".git-hidden"
            (prepared.root / ".git").rename(hidden)
            try:
                return real_capture(*args, **kwargs)
            finally:
                hidden.rename(prepared.root / ".git")

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "run_bounded_capture",
                    side_effect=hide_git_then_run,
                ),
                self.assertRaises(ReviewWorkspaceError),
            ):
                workspace_runtime._run_git(
                    prepared.root,
                    ("read-tree", self.commits[2]),
                    control_binding=binding,
                )
            self.assertEqual(
                hashlib.sha256(outer_index.read_bytes()).hexdigest(),
                before,
            )
        finally:
            self.cleanup(prepared)
            parent.rmdir()

    def test_final_validation_rechecks_normalized_object_store_layout(self) -> None:
        destination = self.root / "late-alternate-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        real_validate_clean = workspace_runtime._validate_clean

        def inject_alternate(*args: object, **kwargs: object) -> None:
            real_validate_clean(*args, **kwargs)
            info = prepared.root / ".git/objects/info"
            info.mkdir(mode=0o700)
            alternate = info / "alternates"
            alternate.write_text(str(self.repo / ".git/objects") + "\n")
            os.chmod(alternate, 0o600)

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_validate_clean",
                    side_effect=inject_alternate,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(caught.exception.reason, "workspace-object-dependency")
        finally:
            self.cleanup(prepared)

    def test_shallow_pre_base_fork_merge_requires_deepen(self) -> None:
        git(self.repo, "switch", "-c", "side", self.commits[1])
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "side.txt")
        git(self.repo, "commit", "-m", "side from pre-base ancestor")
        git(self.repo, "switch", "master")
        git(self.repo, "merge", "--no-ff", "side", "-m", "merge shallow side")
        head = git(self.repo, "rev-parse", "HEAD")
        shallow = self.root / "shallow-merge-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--depth=3",
                f"file://{self.repo}",
                str(shallow),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue((shallow / ".git/shallow").is_file())
        destination = self.root / "shallow-merge-workspace"
        with self.assertRaises(RangeIncomplete) as caught:
            prepare_workspace(shallow, destination, self.commits[2], head)
        self.assertEqual(caught.exception.reason, "range-parent-graph-missing")
        self.assertEqual(
            caught.exception.details["missing_objects"],
            [self.commits[0]],
        )
        self.assertFalse(destination.exists())

    def test_asymmetric_base_shallow_diamond_uses_raw_parent_reachability(
        self,
    ) -> None:
        base = self.commits[2]
        git(self.repo, "switch", "-c", "diamond-side", self.commits[1])
        side_commits: list[str] = []
        for number in range(2):
            (self.repo / "diamond-side.txt").write_text(
                f"diamond side {number}\n",
                encoding="utf-8",
            )
            git(self.repo, "add", "diamond-side.txt")
            git(self.repo, "commit", "-m", f"diamond side {number}")
            side_commits.append(git(self.repo, "rev-parse", "HEAD"))
        git(self.repo, "switch", "master")
        git(
            self.repo,
            "merge",
            "--no-ff",
            "diamond-side",
            "-m",
            "merge asymmetric shallow diamond",
        )
        head = git(self.repo, "rev-parse", "HEAD")

        shallow = self.root / "asymmetric-shallow-diamond-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                f"file://{self.repo}",
                str(shallow),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (shallow / ".git/shallow").write_text(f"{base}\n", encoding="ascii")
        shallow_visible = set(git(shallow, "rev-list", f"{base}..{head}").splitlines())
        self.assertIn(self.commits[0], shallow_visible)
        self.assertIn(self.commits[1], shallow_visible)

        destination = self.root / "asymmetric-shallow-diamond-workspace"
        prepared = prepare_workspace(shallow, destination, base, head)
        try:
            self.assertTrue(prepared.source_shallow)
            self.assertEqual(prepared.commit_count, 4)
            manifest = set(
                (prepared.root / ".git/review-range-objects")
                .read_text(encoding="ascii")
                .splitlines()
            )
            self.assertTrue({base, head, *side_commits}.issubset(manifest))
            self.assertNotIn(self.commits[0], manifest)
            self.assertNotIn(self.commits[1], manifest)
            validated = validate_workspace(prepared.root, base, head)
            self.assertEqual(validated.commit_count, 4)
            self.assertEqual(validated.range_object_count, len(manifest))
        finally:
            self.cleanup(prepared)

    def test_shallow_boundary_inside_long_merge_side_is_incomplete(self) -> None:
        git(self.repo, "switch", "-c", "long-side", self.commits[1])
        for number in range(5):
            (self.repo / "long-side.txt").write_text(
                f"side revision {number}\n",
                encoding="utf-8",
            )
            git(self.repo, "add", "long-side.txt")
            git(self.repo, "commit", "-m", f"long side revision {number}")
        git(self.repo, "switch", "master")
        git(self.repo, "merge", "--no-ff", "long-side", "-m", "merge long side")
        head = git(self.repo, "rev-parse", "HEAD")
        shallow = self.root / "shallow-long-side-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--depth=3",
                f"file://{self.repo}",
                str(shallow),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        boundaries = set(
            (shallow / ".git/shallow").read_text(encoding="ascii").splitlines()
        )
        visible_range = set(
            git(shallow, "rev-list", f"{self.commits[2]}..{head}").splitlines()
        )
        self.assertTrue(boundaries.intersection(visible_range))
        self.assertEqual(
            git(shallow, "merge-base", "--is-ancestor", self.commits[2], head),
            "",
        )

        destination = self.root / "shallow-long-side-workspace"
        with self.assertRaises(RangeIncomplete) as caught:
            prepare_workspace(shallow, destination, self.commits[2], head)
        self.assertEqual(
            caught.exception.reason,
            "range-parent-graph-missing",
        )
        self.assertFalse(destination.exists())

    def test_wrong_endpoint_type_and_operational_failure_are_not_incomplete(
        self,
    ) -> None:
        blob = git(self.repo, "rev-parse", f"{self.commits[2]}:tracked.txt")
        destination = self.root / "blob-endpoint-workspace"
        with self.assertRaises(ReviewWorkspaceError) as wrong_type:
            prepare_workspace(self.repo, destination, blob, self.commits[2])
        self.assertEqual(wrong_type.exception.status, "invalid-range")
        self.assertEqual(wrong_type.exception.reason, "base-not-commit")

        git(self.repo, "tag", "-a", "review-tag", "-m", "review tag", self.commits[1])
        tag_object = git(self.repo, "rev-parse", "review-tag^{tag}")
        with self.assertRaises(ReviewWorkspaceError) as tag_type:
            prepare_workspace(self.repo, destination, tag_object, self.commits[2])
        self.assertEqual(tag_type.exception.status, "invalid-range")
        self.assertEqual(tag_type.exception.reason, "base-not-commit")

        original_run = workspace_runtime._run_git_raw

        def fail_endpoint(
            root: pathlib.Path,
            arguments: tuple[str, ...],
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            if arguments == ("cat-file", "--batch-check=%(objectname) %(objecttype)"):
                return 2, b"", b"fixture operational failure"
            return original_run(root, arguments, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git_raw",
                side_effect=fail_endpoint,
            ),
            self.assertRaises(ReviewWorkspaceError) as operational,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertEqual(
            operational.exception.reason,
            "base-object-check-failed",
        )

    def test_object_integrity_process_group_must_quiesce(self) -> None:
        destination = self.root / "process-leak-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        recovery: dict[str, object] | None = None
        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_process_group_exists",
                    return_value=True,
                ),
                mock.patch.object(workspace_runtime, "terminate_process_group"),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(
                caught.exception.reason,
                "workspace-range-object-process-leak",
            )
            self.assertEqual(caught.exception.status, "inconclusive")
            recovery = workspace_runtime._partial_workspace_recovery_payload(
                caught.exception
            )
            self.assertIsNotNone(recovery)
            assert recovery is not None
            self.assertEqual(
                recovery["active_process"]["operation"],
                "object-integrity-verifier",
            )
            control = recovery["partial_recovery_control"]
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_process_start_identity",
                    side_effect=ProcessLookupError,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "_process_group_exists",
                    return_value=False,
                ),
            ):
                workspace_runtime.recover_partial_workspace(
                    pathlib.Path(control["path"]),
                    control["sha256"],
                )
        finally:
            pass

    def test_object_integrity_recovery_publish_failure_retains_real_child_root(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "object-publish-failure-workspace",
            self.commits[1],
            self.commits[2],
        )
        original_publish = workspace_runtime._PartialRecoveryControl._publish

        def fail_seal(control: object) -> None:
            if control.payload.get("state") == "retained-quiescence-unproven":
                raise PermissionError("fixture recovery publication failure")
            original_publish(control)

        try:
            with (
                mock.patch.object(
                    workspace_runtime._PartialRecoveryControl,
                    "_publish",
                    new=fail_seal,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "_process_group_exists",
                    return_value=True,
                ),
                mock.patch.object(workspace_runtime, "terminate_process_group"),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                )
            self.assertEqual(
                caught.exception.reason,
                "workspace-range-object-process-leak",
            )
            self.assertTrue(
                workspace_runtime.process_quiescence_unproven(caught.exception)
            )
            self.assertTrue(
                workspace_runtime._partial_workspace_requires_retention(
                    caught.exception
                )
            )
            recovery = workspace_runtime._partial_workspace_recovery_payload(
                caught.exception
            )
            assert recovery is not None
            self.assertFalse(recovery["recovery"]["argv_ready"])
            self.assertIsNone(recovery["partial_recovery_control"]["sha256"])
            self.assertTrue(prepared.root.is_dir())
        finally:
            pass

    def test_object_integrity_release_publish_failure_preserves_primary(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "object-release-publish-failure",
            self.commits[1],
            self.commits[2],
        )
        original_publish = workspace_runtime._PartialRecoveryControl._publish
        selector_failed = False
        primary = ReviewWorkspaceError(
            "fixture-object-verification-failure",
            "fixture object verification failure",
        )

        def fail_release(control: object) -> None:
            if selector_failed and control.payload.get("state") == "armed":
                raise PermissionError("fixture process release publication failure")
            original_publish(control)

        def fail_select(*_args: object, **_kwargs: object) -> object:
            nonlocal selector_failed
            selector_failed = True
            raise primary

        try:
            with (
                mock.patch.object(
                    workspace_runtime._PartialRecoveryControl,
                    "_publish",
                    new=fail_release,
                ),
                mock.patch.object(
                    workspace_runtime.selectors.DefaultSelector,
                    "select",
                    side_effect=fail_select,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(
                    prepared.root,
                    self.commits[1],
                    self.commits[2],
                )
            self.assertIs(caught.exception, primary)
            self.assertEqual(
                caught.exception.reason,
                "fixture-object-verification-failure",
            )
            self.assertFalse(
                tuple(
                    prepared.root.parent.glob(
                        f"{workspace_runtime.PARTIAL_RECOVERY_PREFIX}*.json"
                    )
                )
            )
        finally:
            if prepared.root.exists():
                self.cleanup(prepared)

    def test_post_root_git_process_leak_retains_partial_workspace(self) -> None:
        destination = self.root / "post-root-git-process-leak-workspace"
        real_capture = workspace_runtime.run_bounded_capture

        def fail_index_pack(command: tuple[str, ...], **kwargs: object):
            if "index-pack" in command:
                kwargs["on_process_starting"]()
                kwargs["on_process_spawned"](
                    workspace_runtime._RecoveryProcessIdentity(
                        903_001,
                        903_001,
                        "fixture-index-pack-start",
                    )
                )
                kwargs["on_process_started"]()
                raise workspace_runtime.ReviewProcessLeakError(
                    "fixture index-pack process group is not quiescent"
                )
            return real_capture(command, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                side_effect=fail_index_pack,
            ),
            self.assertRaises(workspace_runtime.ReviewProcessLeakError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertTrue(
            workspace_runtime._partial_workspace_requires_retention(caught.exception)
        )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        self.assertIsNotNone(recovery)
        assert recovery is not None
        self.assertEqual(recovery["retained_path"], str(destination))
        self.assertTrue(recovery["cleanup_unavailable_until_quiescent"])
        self.assertEqual(recovery["active_process"]["operation"], "index-pack")
        self.assertEqual(
            recovery["recovery"]["command"],
            "recover-partial-workspace",
        )
        self.assertTrue(destination.is_dir())

    def test_post_root_git_recovery_publish_failure_retains_workspace(self) -> None:
        destination = self.root / "post-root-publish-failure-workspace"
        real_capture = workspace_runtime.run_bounded_capture
        original_publish = workspace_runtime._PartialRecoveryControl._publish

        def fail_seal(control: object) -> None:
            if control.payload.get("state") == "retained-quiescence-unproven":
                raise PermissionError("fixture recovery publication failure")
            original_publish(control)

        def fail_index_pack(command: tuple[str, ...], **kwargs: object):
            if "index-pack" in command:
                kwargs["on_process_starting"]()
                kwargs["on_process_spawned"](
                    workspace_runtime._RecoveryProcessIdentity(
                        903_051,
                        903_051,
                        "fixture-index-publish-start",
                    )
                )
                kwargs["on_process_started"]()
                raise workspace_runtime.ReviewProcessLeakError(
                    "fixture index-pack leak"
                )
            return real_capture(command, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime._PartialRecoveryControl,
                "_publish",
                new=fail_seal,
            ),
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                side_effect=fail_index_pack,
            ),
            self.assertRaises(workspace_runtime.ReviewProcessLeakError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertTrue(workspace_runtime.process_quiescence_unproven(caught.exception))
        self.assertTrue(
            workspace_runtime._partial_workspace_requires_retention(caught.exception)
        )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        assert recovery is not None
        self.assertFalse(recovery["recovery"]["argv_ready"])
        self.assertIsNone(recovery["partial_recovery_control"]["sha256"])
        self.assertTrue(destination.is_dir())

    def test_checkout_process_leak_has_identity_bound_recovery(self) -> None:
        destination = self.root / "checkout-process-leak-workspace"
        real_capture = workspace_runtime.run_bounded_capture

        def fail_checkout(command: tuple[str, ...], **kwargs: object):
            if "checkout-index" in command:
                kwargs["on_process_starting"]()
                kwargs["on_process_spawned"](
                    workspace_runtime._RecoveryProcessIdentity(
                        903_101,
                        903_101,
                        "fixture-checkout-start",
                    )
                )
                kwargs["on_process_started"]()
                raise workspace_runtime.ReviewProcessLeakError(
                    "fixture checkout process group is not quiescent"
                )
            return real_capture(command, **kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                side_effect=fail_checkout,
            ),
            self.assertRaises(workspace_runtime.ReviewProcessLeakError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        self.assertIsNotNone(recovery)
        assert recovery is not None
        self.assertEqual(
            recovery["active_process"]["operation"],
            "checkout-index",
        )
        self.assertEqual(recovery["workspace_state"]["kind"], "unpublished-markerless")
        self.assertTrue(destination.exists())

    def test_formal_partial_recovery_rebuilds_marker_for_exact_argv_retry(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "formal-partial-recovery-retry",
            self.commits[1],
            self.commits[2],
        )
        control_path, control_digest, _payload = self.retained_control(
            prepared.root,
            pid=903_201,
        )
        original_clear = workspace_runtime._clear_directory_descriptor
        failed = False

        def fail_after_first_clear(*args: object, **kwargs: object) -> None:
            nonlocal failed
            original_clear(*args, **kwargs)
            if not failed and kwargs.get("preserve_retained_marker") is True:
                failed = True
                marker = prepared.root / ".git" / workspace_runtime.WORKSPACE_MARKER
                marker.unlink()
                raise PermissionError("fixture retained recovery late failure")

        absent_processes = mock.patch.object(
            workspace_runtime,
            "_process_start_identity",
            side_effect=ProcessLookupError,
        )
        absent_group = mock.patch.object(
            workspace_runtime,
            "_process_group_exists",
            return_value=False,
        )
        with absent_processes, absent_group:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_clear_directory_descriptor",
                    side_effect=fail_after_first_clear,
                ),
                self.assertRaises(PermissionError),
            ):
                workspace_runtime.recover_partial_workspace(
                    control_path,
                    control_digest,
                )
            self.assertTrue(failed)
            marker = prepared.root / ".git" / workspace_runtime.WORKSPACE_MARKER
            self.assertTrue(marker.is_file())
            self.assertTrue(control_path.is_file())
            workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertEqual(
            tuple(path.name for path in prepared.root.iterdir()),
            (".git",),
        )
        self.assertEqual(
            tuple(path.name for path in (prepared.root / ".git").iterdir()),
            (workspace_runtime.WORKSPACE_MARKER,),
        )
        self.assertTrue(control_path.is_file())

    def test_ordinary_cleanup_refuses_bound_partial_recovery_control(self) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "ordinary-cleanup-refuses-partial-recovery",
            self.commits[1],
            self.commits[2],
        )
        control_path, control_digest, _payload = self.retained_control(
            prepared.root,
            pid=903_301,
        )
        with self.assertRaises(ReviewWorkspaceError) as caught:
            cleanup_workspace(prepared.root, prepared.cleanup_token)
        self.assertEqual(caught.exception.reason, "partial-recovery-required")
        self.assertTrue(caught.exception.details["cleanup_unavailable_until_quiescent"])
        self.assertTrue(prepared.root.is_dir())
        self.assertTrue(control_path.is_file())
        with (
            mock.patch.object(
                workspace_runtime,
                "_process_start_identity",
                side_effect=ProcessLookupError,
            ),
            mock.patch.object(
                workspace_runtime,
                "_process_group_exists",
                return_value=False,
            ),
        ):
            recovered = workspace_runtime.recover_partial_workspace(
                control_path,
                control_digest,
            )
        self.assertEqual(recovered.cleanup_status, "payload-removed")

    def test_ordinary_cleanup_control_read_failure_is_unverifiable_not_drift(
        self,
    ) -> None:
        prepared = prepare_workspace(
            self.repo,
            self.root / "ordinary-cleanup-control-unavailable",
            self.commits[1],
            self.commits[2],
        )
        control_path, _control_digest, _payload = self.retained_control(
            prepared.root,
            pid=903_302,
        )
        control_identity = control_path.stat(follow_symlinks=False)
        real_read = workspace_runtime._read_descriptor_payload

        def fail_control_read(descriptor: int, limit: int) -> bytes:
            if os.path.samestat(os.fstat(descriptor), control_identity):
                raise OSError("fixture retained control read failure")
            return real_read(descriptor, limit)

        with (
            mock.patch.object(
                workspace_runtime,
                "_read_descriptor_payload",
                side_effect=fail_control_read,
            ),
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            cleanup_workspace(prepared.root, prepared.cleanup_token)
        self.assertEqual(
            caught.exception.reason,
            "partial-recovery-control-unverifiable",
        )
        self.assertTrue(prepared.root.is_dir())
        self.assertTrue(control_path.is_file())

    def test_pre_root_git_process_leak_does_not_create_retained_workspace(
        self,
    ) -> None:
        destination = self.root / "pre-root-git-process-leak-workspace"
        leak = workspace_runtime.ReviewProcessLeakError(
            "fixture source-probe process group is not quiescent"
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "run_bounded_capture",
                side_effect=leak,
            ),
            self.assertRaises(workspace_runtime.ReviewProcessLeakError) as caught,
        ):
            prepare_workspace(
                self.repo,
                destination,
                self.commits[1],
                self.commits[2],
            )
        self.assertIs(caught.exception, leak)
        self.assertFalse(workspace_runtime._partial_workspace_requires_retention(leak))
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix", "process-group custody requires POSIX")
    def test_object_integrity_spawn_assignment_signal_reaps_real_child(self) -> None:
        destination = self.root / "spawn-assignment-signal-workspace"
        instructions = list(
            dis.get_instructions(workspace_runtime._verify_range_object_contents)
        )
        store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "spawn":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                result_store = instructions[candidate_index + 1]
                if (
                    result_store.opname == "STORE_FAST"
                    and result_store.argval == "process"
                ):
                    store_offsets.add(result_store.offset)
                break
        self.assertEqual(len(store_offsets), 1)
        original_popen = subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def spawn_sleep(command: object, *args: object, **kwargs: object):
            argv = tuple(os.fspath(item) for item in command)
            if argv[-2:] != ("cat-file", "--batch"):
                return original_popen(command, *args, **kwargs)
            process = original_popen(
                ("/bin/sleep", "60"),
                env=kwargs.get("env"),
                stdin=kwargs.get("stdin"),
                stdout=kwargs.get("stdout"),
                stderr=kwargs.get("stderr"),
                start_new_session=True,
            )
            spawned.append(process)
            return process

        interruption = workspace_runtime.ForwardedSignal(signal.SIGTERM)
        armed = True

        def trace(frame: object, event: str, _argument: object):
            nonlocal armed
            if frame.f_code is workspace_runtime._verify_range_object_contents.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti in store_offsets:
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        with mock.patch.object(
            workspace_runtime.subprocess,
            "Popen",
            side_effect=spawn_sleep,
        ):
            sys.settrace(trace)
            try:
                with self.assertRaises(workspace_runtime.ForwardedSignal) as caught:
                    prepare_workspace(
                        self.repo,
                        destination,
                        self.commits[1],
                        self.commits[2],
                    )
            finally:
                sys.settrace(previous_trace)
        self.assertIs(caught.exception, interruption)
        self.assertFalse(armed)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        self.assertFalse(workspace_runtime._process_group_exists(spawned[0].pid))
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix", "process-group custody requires POSIX")
    def test_object_integrity_binding_assignment_signal_retains_recoverable_root(
        self,
    ) -> None:
        destination = self.root / "binding-assignment-signal-workspace"
        instructions = list(
            dis.get_instructions(workspace_runtime._verify_range_object_contents)
        )
        store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "_bind_recovery_process":
                continue
            for candidate_index in range(index + 1, min(index + 8, len(instructions))):
                candidate = instructions[candidate_index]
                if (
                    candidate.opname == "STORE_FAST"
                    and candidate.argval == "process_binding"
                ):
                    store_offsets.add(instructions[candidate_index + 1].offset)
                    break
        self.assertGreaterEqual(len(store_offsets), 1)
        target_store_offset = min(store_offsets)
        interruption = workspace_runtime.ForwardedSignal(signal.SIGTERM)
        armed = True

        def trace(frame: object, event: str, _argument: object):
            nonlocal armed
            if frame.f_code is workspace_runtime._verify_range_object_contents.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti == target_store_offset:
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        with mock.patch.object(
            workspace_runtime,
            "_process_group_exists",
            return_value=True,
        ):
            sys.settrace(trace)
            try:
                with self.assertRaises(ReviewWorkspaceError) as caught:
                    prepare_workspace(
                        self.repo,
                        destination,
                        self.commits[1],
                        self.commits[2],
                    )
            finally:
                sys.settrace(previous_trace)
        self.assertFalse(armed)
        self.assertEqual(
            caught.exception.reason,
            "workspace-range-object-process-leak",
        )
        recovery = workspace_runtime._partial_workspace_recovery_payload(
            caught.exception
        )
        assert recovery is not None
        self.assertEqual(
            recovery["active_process"]["operation"],
            "object-integrity-verifier",
        )
        self.assertTrue(recovery["recovery"]["argv_ready"])
        self.assertTrue(destination.is_dir())

    @unittest.skipUnless(os.name == "posix", "process-group custody requires POSIX")
    def test_object_integrity_cleanup_signal_cannot_interrupt_worker_custody(
        self,
    ) -> None:
        destination = self.root / "spawn-cleanup-signal-workspace"
        instructions = list(
            dis.get_instructions(workspace_runtime._verify_range_object_contents)
        )
        store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "spawn":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                result_store = instructions[candidate_index + 1]
                if (
                    result_store.opname == "STORE_FAST"
                    and result_store.argval == "process"
                ):
                    store_offsets.add(result_store.offset)
                break
        self.assertEqual(len(store_offsets), 1)
        original_popen = subprocess.Popen
        real_terminate = workspace_runtime.terminate_process_group
        spawned: list[subprocess.Popen[bytes]] = []
        terminate_calls = 0

        def spawn_sleep(command: object, *args: object, **kwargs: object):
            argv = tuple(os.fspath(item) for item in command)
            if argv[-2:] != ("cat-file", "--batch"):
                return original_popen(command, *args, **kwargs)
            process = original_popen(
                ("/bin/sleep", "60"),
                env=kwargs.get("env"),
                stdin=kwargs.get("stdin"),
                stdout=kwargs.get("stdout"),
                stderr=kwargs.get("stderr"),
                start_new_session=True,
            )
            spawned.append(process)
            return process

        def interrupt_first_termination(
            process: subprocess.Popen[bytes],
            **kwargs: object,
        ) -> None:
            nonlocal terminate_calls
            terminate_calls += 1
            if terminate_calls == 1:
                raise workspace_runtime.ForwardedSignal(signal.SIGINT)
            real_terminate(process, **kwargs)

        first_interruption = workspace_runtime.ForwardedSignal(signal.SIGTERM)
        armed = True

        def trace(frame: object, event: str, _argument: object):
            nonlocal armed
            if frame.f_code is workspace_runtime._verify_range_object_contents.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti in store_offsets:
                    armed = False
                    raise first_interruption
            return trace

        previous_trace = sys.gettrace()
        with (
            mock.patch.object(
                workspace_runtime.subprocess,
                "Popen",
                side_effect=spawn_sleep,
            ),
            mock.patch.object(
                workspace_runtime,
                "terminate_process_group",
                side_effect=interrupt_first_termination,
            ),
        ):
            sys.settrace(trace)
            try:
                with self.assertRaises(workspace_runtime.ForwardedSignal) as caught:
                    prepare_workspace(
                        self.repo,
                        destination,
                        self.commits[1],
                        self.commits[2],
                    )
            finally:
                sys.settrace(previous_trace)
        self.assertIs(caught.exception, first_interruption)
        self.assertGreaterEqual(terminate_calls, 2)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        self.assertFalse(workspace_runtime._process_group_exists(spawned[0].pid))
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix", "process-group custody requires POSIX")
    def test_object_integrity_assignment_signal_and_failed_cleanup_retain_root(
        self,
    ) -> None:
        destination = self.root / "spawn-assignment-leak-workspace"
        instructions = list(
            dis.get_instructions(workspace_runtime._verify_range_object_contents)
        )
        store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "spawn":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                result_store = instructions[candidate_index + 1]
                if (
                    result_store.opname == "STORE_FAST"
                    and result_store.argval == "process"
                ):
                    store_offsets.add(result_store.offset)
                break
        self.assertEqual(len(store_offsets), 1)
        original_popen = subprocess.Popen
        real_terminate = workspace_runtime.terminate_process_group
        spawned: list[subprocess.Popen[bytes]] = []

        def spawn_sleep(command: object, *args: object, **kwargs: object):
            argv = tuple(os.fspath(item) for item in command)
            if argv[-2:] != ("cat-file", "--batch"):
                return original_popen(command, *args, **kwargs)
            process = original_popen(
                ("/bin/sleep", "60"),
                env=kwargs.get("env"),
                stdin=kwargs.get("stdin"),
                stdout=kwargs.get("stdout"),
                stderr=kwargs.get("stderr"),
                start_new_session=True,
            )
            spawned.append(process)
            return process

        interruption = workspace_runtime.ForwardedSignal(signal.SIGTERM)
        armed = True

        def trace(frame: object, event: str, _argument: object):
            nonlocal armed
            if frame.f_code is workspace_runtime._verify_range_object_contents.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti in store_offsets:
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        try:
            with (
                mock.patch.object(
                    workspace_runtime.subprocess,
                    "Popen",
                    side_effect=spawn_sleep,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "terminate_process_group",
                ) as terminate,
                mock.patch.object(
                    workspace_runtime,
                    "_process_group_exists",
                    return_value=True,
                ),
            ):
                sys.settrace(trace)
                try:
                    with self.assertRaises(ReviewWorkspaceError) as caught:
                        prepare_workspace(
                            self.repo,
                            destination,
                            self.commits[1],
                            self.commits[2],
                        )
                finally:
                    sys.settrace(previous_trace)
            self.assertEqual(
                caught.exception.reason,
                "workspace-range-object-process-leak",
            )
            self.assertEqual(caught.exception.status, "inconclusive")
            self.assertTrue(
                workspace_runtime.process_quiescence_unproven(caught.exception)
            )
            self.assertTrue(
                workspace_runtime._partial_workspace_requires_retention(
                    caught.exception
                )
            )
            self.assertFalse(armed)
            self.assertEqual(len(spawned), 1)
            self.assertGreaterEqual(terminate.call_count, 2)
            self.assertIsNone(spawned[0].poll())
            self.assertEqual(caught.exception.details["pid"], spawned[0].pid)
            self.assertEqual(
                caught.exception.details["process_handle"],
                "lease-published",
            )
            self.assertEqual(
                caught.exception.details["process_identity_status"],
                "bound",
            )
            self.assertEqual(
                caught.exception.details["process_identity"]["pid"],
                spawned[0].pid,
            )
            self.assertEqual(
                caught.exception.details["retained_path"],
                str(destination),
            )
            self.assertTrue(destination.is_dir())
        finally:
            sys.settrace(previous_trace)
            for child in spawned:
                if child.poll() is None or workspace_runtime._process_group_exists(
                    child.pid
                ):
                    real_terminate(
                        child,
                        initial_signal=signal.SIGKILL,
                        grace_seconds=5.0,
                    )

    def test_cleanup_detects_access_policy_drift_and_retains_recoverable_path(
        self,
    ) -> None:
        destination = self.root / "cleanup-mode-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        real_clear = workspace_runtime._clear_directory_descriptor

        def relax_before_clear(
            descriptor: int,
            display_path: pathlib.Path,
            root_device: int,
            **kwargs: object,
        ) -> None:
            if display_path.name.startswith(".review-cleanup-"):
                os.fchmod(descriptor, 0o777)
                raise ReviewWorkspaceError(
                    "fixture-cleanup-access-policy-drift",
                    "fixture changed the cleanup root access policy",
                )
            real_clear(descriptor, display_path, root_device, **kwargs)

        retained: pathlib.Path | None = None
        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_clear_directory_descriptor",
                    side_effect=relax_before_clear,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                cleanup_workspace(prepared.root, prepared.cleanup_token)
            self.assertEqual(caught.exception.reason, "workspace-cleanup-incomplete")
            retained_value = caught.exception.details.get("retained_path")
            self.assertIsInstance(retained_value, str)
            retained = pathlib.Path(retained_value)
            self.assertTrue((retained / ".git/review-workspace.json").is_file())
            recovery_argv = caught.exception.details["recovery_command_argv"]
            self.assertEqual(recovery_argv[2], str(retained))
            self.assertNotIn(prepared.cleanup_token, recovery_argv)
            os.chmod(retained, 0o700)
            cleanup_workspace(retained, prepared.cleanup_token)
            retained = None
        finally:
            if retained is not None and retained.exists():
                os.chmod(retained, 0o700)
                cleanup_workspace(retained, prepared.cleanup_token)

    def test_cleanup_refuses_mount_boundary_and_preserves_token_recovery(
        self,
    ) -> None:
        destination = self.root / "cleanup-mount-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )

        def fixture_mount(path: object) -> bool:
            return pathlib.Path(os.fspath(path)).name == ".git"

        retained: pathlib.Path | None = None
        try:
            with (
                mock.patch.object(
                    workspace_runtime.os.path,
                    "ismount",
                    side_effect=fixture_mount,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                cleanup_workspace(prepared.root, prepared.cleanup_token)
            self.assertEqual(caught.exception.reason, "workspace-cleanup-incomplete")
            self.assertEqual(
                caught.exception.details["primary_reason"],
                "workspace-cleanup-mount-boundary",
            )
            retained_value = caught.exception.details.get("retained_path")
            self.assertIsInstance(retained_value, str)
            retained = pathlib.Path(retained_value)
            self.assertTrue((retained / ".git/review-workspace.json").is_file())
            recovery_argv = caught.exception.details["recovery_command_argv"]
            self.assertEqual(recovery_argv[2], str(retained))
            self.assertNotIn(prepared.cleanup_token, recovery_argv)
            cleanup_workspace(retained, prepared.cleanup_token)
            retained = None
        finally:
            if retained is not None and retained.exists():
                cleanup_workspace(retained, prepared.cleanup_token)

    def test_cleanup_recreates_marker_after_late_partial_removal_and_retries(
        self,
    ) -> None:
        destination = self.root / "cleanup-late-failure-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        original_rmdir = workspace_runtime.os.rmdir
        failed = False

        def fail_first_git_removal(
            path: object,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal failed
            if path == ".git" and dir_fd is not None and not failed:
                failed = True
                raise PermissionError("fixture late Git-directory removal failure")
            original_rmdir(path, dir_fd=dir_fd)

        retained: pathlib.Path | None = None
        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "rmdir",
                    side_effect=fail_first_git_removal,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                cleanup_workspace(prepared.root, prepared.cleanup_token)
            self.assertTrue(failed)
            self.assertEqual(caught.exception.reason, "workspace-cleanup-incomplete")
            retained_value = caught.exception.details.get("retained_path")
            self.assertIsInstance(retained_value, str)
            retained = pathlib.Path(retained_value)
            marker_path = retained / ".git/review-workspace.json"
            self.assertTrue(marker_path.is_file())
            marker_payload = json.loads(marker_path.read_bytes())
            self.assertNotIn("cleanup_token", marker_payload)
            self.assertEqual(
                marker_payload["cleanup_token_sha256"],
                hashlib.sha256(prepared.cleanup_token.encode("utf-8")).hexdigest(),
            )
            recovery_argv = caught.exception.details["recovery_command_argv"]
            self.assertEqual(recovery_argv[2], str(retained))
            self.assertNotIn(prepared.cleanup_token, recovery_argv)
            cleanup_workspace(retained, prepared.cleanup_token)
            retained = None
        finally:
            if retained is not None and retained.exists():
                cleanup_workspace(retained, prepared.cleanup_token)

    @unittest.skipUnless(
        sys.platform == "darwin", "extended ACL probe is macOS-specific"
    )
    def test_extended_acl_is_rejected_even_with_private_mode_bits(self) -> None:
        destination = self.root / "acl-workspace"
        prepared = prepare_workspace(
            self.repo, destination, self.commits[1], self.commits[2]
        )
        subprocess.run(
            ("chmod", "+a", "everyone allow read", str(prepared.root)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertEqual(stat.S_IMODE(prepared.root.stat().st_mode), 0o700)
            with self.assertRaises(ReviewWorkspaceError) as caught:
                validate_workspace(prepared.root, self.commits[1], self.commits[2])
            self.assertEqual(caught.exception.reason, "workspace-extended-acl")
        finally:
            subprocess.run(
                ("chmod", "-N", str(prepared.root)),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.cleanup(prepared)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "signal-mask custody requires POSIX pthread masks",
    )
    def test_signal_drain_control_flow_restores_mask_and_cannot_be_swallowed(
        self,
    ) -> None:
        owner = workspace_runtime.ForwardedSignalMaskOwner()
        owner.publish(set())
        with (
            mock.patch.object(
                workspace_runtime,
                "consume_pending_forwarded_signal",
                side_effect=workspace_runtime.ForwardedSignal(signal.SIGTERM),
            ),
            mock.patch.object(owner, "restore", wraps=owner.restore) as restore,
            self.assertRaises(workspace_runtime.ForwardedSignal),
        ):
            workspace_runtime._finish_forwarded_signal_mask(
                owner,
                primary_error=None,
            )
        restore.assert_called_once()
        self.assertFalse(owner.active)

    def test_range_incomplete_missing_object_sample_is_bounded(self) -> None:
        missing = tuple(f"{number:040x}" for number in range(100))
        error = RangeIncomplete(
            "range-object-missing",
            "fixture",
            base=self.commits[0],
            head=self.commits[2],
            source_shallow=True,
            source_promisor=True,
            missing_objects=missing,
        )
        payload = error.payload()
        self.assertIs(payload["source_promisor"], True)
        self.assertEqual(payload["missing_object_count"], 100)
        self.assertEqual(len(payload["missing_objects"]), 32)
        self.assertTrue(payload["missing_objects_truncated"])
        self.assertEqual(
            payload["remediation"]["recommended_action"],
            "batch-exact-object-fetch",
        )
        exact_fetch = payload["remediation"]["batch_exact_object_fetch"]
        self.assertIs(exact_fetch["applicable"], True)
        self.assertEqual(
            exact_fetch["command"],
            "git fetch-pack --stdin --no-progress <promisor-url>",
        )
        self.assertIn("one object ID per line", exact_fetch["stdin"])
        self.assertIn("missing_objects_truncated", exact_fetch["stdin"])
        self.assertIn("do not refetch", exact_fetch["fallback"])

    def test_symlink_validation_uses_one_binary_safe_bounded_batch(self) -> None:
        (self.repo / "target.txt").write_text("target\n", encoding="utf-8")
        (self.repo / "first-link").symlink_to("target.txt")
        (self.repo / "second-link").symlink_to("target.txt")
        git(self.repo, "add", "target.txt", "first-link", "second-link")
        git(self.repo, "commit", "-m", "safe symlinks")
        head = git(self.repo, "rev-parse", "HEAD")
        prepared = prepare_workspace(
            self.repo,
            self.root / "batched-symlink-workspace",
            self.commits[2],
            head,
        )
        try:
            with mock.patch.object(
                workspace_runtime,
                "_run_git",
                wraps=workspace_runtime._run_git,
            ) as run_git:
                validated = validate_workspace(
                    prepared.root,
                    self.commits[2],
                    head,
                )

            self.assertEqual(validated.symlink_count, 2)
            batch_calls = [
                call
                for call in run_git.call_args_list
                if call.args[1] == ("cat-file", "--batch")
            ]
            self.assertEqual(len(batch_calls), 1)
            self.assertEqual(len(batch_calls[0].kwargs["stdin"].splitlines()), 2)
            self.assertEqual(
                batch_calls[0].kwargs["output_limit_bytes"],
                workspace_runtime.SYMLINK_BATCH_OUTPUT_LIMIT_BYTES,
            )
            index_calls = [
                call
                for call in run_git.call_args_list
                if call.args[1] == ("ls-files", "--stage", "-z")
            ]
            self.assertEqual(len(index_calls), 1)
            self.assertLessEqual(
                batch_calls[0].kwargs["timeout_seconds"],
                index_calls[0].kwargs["timeout_seconds"],
            )
            self.assertFalse(
                any(
                    call.args[1][:2] == ("cat-file", "blob")
                    for call in run_git.call_args_list
                )
            )
        finally:
            self.cleanup(prepared)

    def test_staged_symlink_index_requires_strict_nul_framing(self) -> None:
        oid = b"1" * 40
        record = b"120000 " + oid + b" 0\tlink"
        malformed_payloads = (
            record,
            b"\0" + record + b"\0",
            record + b"\0\0",
            b"120000  " + oid + b" 0\tlink\0",
        )

        for payload in malformed_payloads:
            with self.subTest(payload=payload[:24]):
                with self.assertRaises(ReviewWorkspaceError) as caught:
                    workspace_runtime._parse_staged_index_for_symlinks(payload)
                self.assertEqual(caught.exception.reason, "index-output-invalid")

    def test_staged_symlink_count_limit_blocks_before_batch(self) -> None:
        oid = b"1" * 40
        payload = b"".join(
            b"120000 " + oid + b" 0\tlink-" + str(number).encode("ascii") + b"\0"
            for number in range(workspace_runtime.SYMLINK_COUNT_LIMIT + 1)
        )

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_git",
                return_value=payload,
            ) as run_git,
            self.assertRaises(ReviewWorkspaceError) as caught,
        ):
            workspace_runtime._validate_symlinks(self.repo.resolve(), mock.Mock())

        self.assertEqual(caught.exception.reason, "symlink-count-limit")
        self.assertEqual(
            caught.exception.details,
            {
                "observed": workspace_runtime.SYMLINK_COUNT_LIMIT + 1,
                "limit": workspace_runtime.SYMLINK_COUNT_LIMIT,
            },
        )
        run_git.assert_called_once()
        self.assertEqual(
            run_git.call_args.args[1],
            ("ls-files", "--stage", "-z"),
        )

    def test_symlink_batch_enforces_single_and_aggregate_byte_limits(self) -> None:
        first_oid = b"1" * 40
        oversized = b"x" * (workspace_runtime.SYMLINK_TARGET_LIMIT_BYTES + 1)
        oversized_payload = (
            first_oid
            + b" blob "
            + str(len(oversized)).encode("ascii")
            + b"\n"
            + oversized
            + b"\n"
        )
        with self.assertRaises(ReviewWorkspaceError) as single:
            workspace_runtime._parse_symlink_batch(
                oversized_payload,
                (first_oid,),
            )
        self.assertEqual(single.exception.reason, "symlink-target-limit")

        second_oid = b"2" * 40
        first_target = b"abcd"
        second_target = b"efgh"
        aggregate_payload = (
            first_oid
            + b" blob 4\n"
            + first_target
            + b"\n"
            + second_oid
            + b" blob 4\n"
            + second_target
            + b"\n"
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "SYMLINK_TARGET_AGGREGATE_LIMIT_BYTES",
                7,
            ),
            self.assertRaises(ReviewWorkspaceError) as aggregate,
        ):
            workspace_runtime._parse_symlink_batch(
                aggregate_payload,
                (first_oid, second_oid),
            )
        self.assertEqual(
            aggregate.exception.reason,
            "symlink-target-aggregate-limit",
        )

    def test_symlink_batch_rejects_malformed_or_trailing_output(self) -> None:
        oid = b"1" * 40
        malformed_payloads = (
            oid + b" blob 4\ntest",
            oid + b" blob 4\ntest\ntrailing",
            oid + b" blob 04\ntest\n",
            b"2" * 40 + b" blob 4\ntest\n",
        )

        for payload in malformed_payloads:
            with self.subTest(payload=payload[-16:]):
                with self.assertRaises(ReviewWorkspaceError) as caught:
                    workspace_runtime._parse_symlink_batch(payload, (oid,))
                self.assertEqual(
                    caught.exception.reason,
                    "symlink-batch-output-invalid",
                )

    def test_symlink_target_must_remain_stable_during_validation(self) -> None:
        (self.repo / "target.txt").write_text("target\n", encoding="utf-8")
        (self.repo / "link").symlink_to("target.txt")
        git(self.repo, "add", "target.txt", "link")
        git(self.repo, "commit", "-m", "stable symlink")
        head = git(self.repo, "rev-parse", "HEAD")
        prepared = prepare_workspace(
            self.repo,
            self.root / "symlink-stability-workspace",
            self.commits[2],
            head,
        )
        original_readlink = workspace_runtime.os.readlink
        observations = iter(("target.txt", "other.txt"))

        def drifting_readlink(path: object, *args: object, **kwargs: object) -> str:
            if pathlib.Path(path) == prepared.root / "link":
                return next(observations)
            return original_readlink(path, *args, **kwargs)

        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "readlink",
                    side_effect=drifting_readlink,
                ),
                self.assertRaises(ReviewWorkspaceError) as caught,
            ):
                validate_workspace(prepared.root, self.commits[2], head)
            self.assertEqual(caught.exception.reason, "symlink-content-drift")
        finally:
            self.cleanup(prepared)

    def test_tracked_symlink_escape_is_rejected_and_partial_workspace_removed(
        self,
    ) -> None:
        (self.repo / "escape").symlink_to("../../outside")
        git(self.repo, "add", "escape")
        git(self.repo, "commit", "-m", "escaping symlink")
        head = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "symlink-workspace"
        with self.assertRaises(ReviewWorkspaceError) as caught:
            prepare_workspace(self.repo, destination, self.commits[2], head)
        self.assertEqual(caught.exception.reason, "symlink-escape")
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
