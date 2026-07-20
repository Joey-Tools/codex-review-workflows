from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import pathlib
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import workspace as workspace_runtime  # noqa: E402
from review_runtime.common import ForwardedSignal, ReviewError  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    _file_secret_rule,
    _parse_tree_record,
    _sensitive_path_rule,
    _value_secret_rule,
    cleanup_workspace,
    prepare_workspace as _prepare_workspace,
    symlink_target_stays_within_workspace,
    validate_external_workspace,
)


def test_git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NO_LAZY_FETCH",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def git(repo: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        env=test_git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def oauth_refresh_credential() -> str:
    return "1//" + "".join(("oauth", "-refresh", "-credential", "-value"))


def aws_access_key_credential() -> str:
    return "AKIA" + "A" * 16


def prepare_workspace(**kwargs):
    captured = []
    review = _prepare_workspace(ownership_handoff=captured.append, **kwargs)
    if captured != [review]:
        raise AssertionError("workspace ownership was not handed off exactly once")
    return review


class WorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        subprocess.run(
            ("git", "init", "-b", "master", str(self.repo)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(self.repo, "config", "user.name", "Review Test")
        git(self.repo, "config", "user.email", "review@example.com")
        git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text(
            "example.txt filter=evil diff=evil\n",
            encoding="utf-8",
        )
        (self.repo / "example.txt").write_text("one\n", encoding="utf-8")
        git(self.repo, "add", ".gitignore", ".gitattributes", "example.txt")
        git(self.repo, "commit", "-m", "Initial")
        self.base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("one\ntwo\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Update")
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.reviews = []

    def tearDown(self) -> None:
        review_roots = {review.container_dir.parent for review in self.reviews}
        for review in self.reviews:
            if review.container_dir.exists():
                cleanup_workspace(review, keep_container=False)
        if self.repo.exists():
            review_roots.add(workspace_runtime._review_root_for_source(self.repo))
        for review_root in review_roots:
            try:
                root_status = os.lstat(review_root)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(root_status.st_mode) and not stat.S_ISLNK(
                root_status.st_mode
            ):
                for container in review_root.glob("isolated-review-*"):
                    shutil.rmtree(container)
                review_root.rmdir()
        self.temporary.cleanup()

    def install_raw_commit(self, raw_commit: bytes, *, previous: str) -> str:
        created = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ),
            input=raw_commit,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        commit = created.stdout.decode("ascii").strip()
        git(self.repo, "update-ref", "refs/heads/master", commit, previous)
        return commit

    def install_signature_commit(
        self,
        *,
        metadata_key: str,
        body_lines: tuple[str, ...],
    ) -> str:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        armor = (
            "-----BEGIN PGP SIGNATURE-----",
            *body_lines,
            "-----END PGP SIGNATURE-----",
        )
        if metadata_key == "mergetag":
            signature_metadata = (
                f"mergetag object {self.head}\n"
                " type commit\n"
                " tag fixture\n"
                " tagger Review Test <review@example.com> 1700000000 +0000\n"
                " \n" + "".join(f" {line}\n" for line in armor)
            )
        else:
            signature_metadata = f"{metadata_key} {armor[0]}\n" + "".join(
                f" {line}\n" for line in armor[1:]
            )
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            f"{signature_metadata}"
            "\n"
            "Signed endpoint fixture\n"
        ).encode("utf-8")
        return self.install_raw_commit(raw_commit, previous=self.head)

    def assert_no_review_containers(self, repo: pathlib.Path | None = None) -> None:
        review_root = workspace_runtime._review_root_for_source(repo or self.repo)
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_git_environment_disables_lazy_fetch_replacements_and_prompts(
        self,
    ) -> None:
        environment = workspace_runtime._git_environment()

        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_ASKPASS"], "/usr/bin/false")
        self.assertEqual(environment["SSH_ASKPASS"], "/usr/bin/false")
        self.assertNotIn("GIT_GRAFT_FILE", environment)

    def test_sanitized_git_query_uses_short_lived_view_and_source_objects(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(("git",), 0, b"", b"")
        with workspace_runtime._temporary_sanitized_git_view(
            source_root=self.repo,
        ) as (git_view, object_directory):
            temporary_root = git_view.parent
            config = (git_view / "config").read_text(encoding="utf-8")
            with (
                mock.patch.dict(
                    workspace_runtime.os.environ,
                    {
                        "GIT_CONFIG_GLOBAL": str(self.repo / "hostile-config"),
                        "GIT_DIR": str(self.repo / ".git"),
                        "GIT_GRAFT_FILE": str(self.repo / ".git" / "info" / "grafts"),
                    },
                ),
                mock.patch.object(
                    workspace_runtime,
                    "_run_bounded_git_capture",
                    return_value=completed,
                ) as bounded,
            ):
                result = workspace_runtime._run_sanitized_git_query(
                    git_view=git_view,
                    object_directory=object_directory,
                    args=("merge-base", "--is-ancestor", self.base, self.head),
                    label="sanitized ancestry Git query",
                    check=False,
                )

            self.assertIs(result, completed)
            command = bounded.call_args.args[0]
            environment = bounded.call_args.kwargs["environment"]
            self.assertIn(f"--git-dir={git_view}", command)
            self.assertNotIn("-C", command)
            self.assertIn("core.commitGraph=false", command)
            self.assertEqual(
                command[-4:],
                ("merge-base", "--is-ancestor", self.base, self.head),
            )
            self.assertEqual(
                environment["GIT_OBJECT_DIRECTORY"],
                str(object_directory),
            )
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertNotIn("GIT_DIR", environment)
            self.assertNotIn("GIT_GRAFT_FILE", environment)
            self.assertNotIn("remote", config.casefold())
            self.assertFalse((git_view / "info" / "grafts").exists())

        self.assertFalse(temporary_root.exists())

    def test_git_environment_ignores_ambient_global_config_override(self) -> None:
        with mock.patch.dict(
            workspace_runtime.os.environ,
            {"GIT_CONFIG_GLOBAL": str(self.repo / "ambient-global-config")},
        ):
            environment = workspace_runtime._git_environment()

        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_private_git_commands_and_config_disable_reflogs(self) -> None:
        command = workspace_runtime._private_git_command(
            git_dir=self.repo / "private.git",
            args=("status",),
        )
        self.assertIn("core.logAllRefUpdates=false", command)
        for object_id_length in (40, 64):
            with self.subTest(object_id_length=object_id_length):
                config = workspace_runtime._canonical_private_git_config(
                    object_id_length=object_id_length
                )
                self.assertIn(b"\tlogAllRefUpdates = false\n", config)

    def test_private_object_byte_budgets_include_endpoint_metadata(self) -> None:
        endpoint_objects = (
            ("blob", workspace_runtime.MAX_SNAPSHOT_BYTES),
            ("tree", workspace_runtime.MAX_TREE_METADATA_BYTES),
            ("commit", workspace_runtime.MAX_ENDPOINT_COMMIT_BYTES),
        ) * 2
        endpoint_bytes = sum(size for _object_type, size in endpoint_objects)
        self.assertEqual(
            workspace_runtime.MAX_PRIVATE_OBJECT_BYTES,
            endpoint_bytes,
        )
        self.assertEqual(
            workspace_runtime.MAX_PRIVATE_PACK_BYTES,
            endpoint_bytes + workspace_runtime.MAX_PRIVATE_PACK_OVERHEAD_BYTES,
        )
        self.assertEqual(
            workspace_runtime.MAX_PRIVATE_WIP_STORAGE_BYTES,
            workspace_runtime.MAX_SNAPSHOT_BYTES
            + workspace_runtime.MAX_TREE_METADATA_BYTES
            + workspace_runtime.MAX_PRIVATE_PACK_OVERHEAD_BYTES,
        )
        self.assertEqual(
            workspace_runtime.MAX_PRIVATE_STORAGE_BYTES,
            workspace_runtime.MAX_PRIVATE_PACK_BYTES
            + workspace_runtime.MAX_PRIVATE_WIP_STORAGE_BYTES
            + workspace_runtime.MAX_PRIVATE_PACK_SIDECAR_BYTES,
        )
        self.assertLess(
            workspace_runtime.MAX_PRIVATE_LOOSE_OBJECT_BYTES,
            workspace_runtime.MAX_PRIVATE_OBJECT_BYTES,
        )

        metadata = b"".join(
            f"{index:040x} {object_type} {size}\n".encode("ascii")
            for index, (object_type, size) in enumerate(endpoint_objects, start=1)
        )

        def emit_metadata(*_args, destination, **_kwargs):
            destination.write(metadata)

        for limit, error_pattern in (
            (endpoint_bytes, None),
            (endpoint_bytes - 1, "endpoint objects exceed the byte limit"),
        ):
            with (
                self.subTest(limit=limit),
                tempfile.TemporaryFile() as object_ids,
                mock.patch.object(
                    workspace_runtime,
                    "MAX_PRIVATE_OBJECT_BYTES",
                    limit,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "_run_bounded_process_to_file",
                    side_effect=emit_metadata,
                ),
            ):
                if error_pattern is None:
                    workspace_runtime._validate_private_object_sizes(
                        git_view=self.repo / "git-view",
                        source_object_directory=self.repo / "objects",
                        object_ids=object_ids,
                    )
                else:
                    with self.assertRaisesRegex(ReviewError, error_pattern):
                        workspace_runtime._validate_private_object_sizes(
                            git_view=self.repo / "git-view",
                            source_object_directory=self.repo / "objects",
                            object_ids=object_ids,
                        )

    def test_partial_clone_missing_blob_fails_without_transport(self) -> None:
        git(self.repo, "config", "uploadpack.allowFilter", "true")
        partial = pathlib.Path(self.temporary.name) / "partial"
        subprocess.run(
            (
                "git",
                "-c",
                "protocol.file.allow=always",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                self.repo.as_uri(),
                str(partial),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        blob = git(self.repo, "rev-parse", f"{self.head}:example.txt")
        missing = subprocess.run(
            ("git", "-C", str(partial), "cat-file", "-e", blob),
            check=False,
            env=workspace_runtime._git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(missing.returncode, 0)

        marker = pathlib.Path(self.temporary.name) / "transport-called"
        upload_pack = pathlib.Path(self.temporary.name) / "upload-pack"
        upload_pack.write_text(
            f"#!/bin/sh\ntouch '{marker}'\nexit 1\n",
            encoding="utf-8",
        )
        upload_pack.chmod(0o755)
        git(partial, "config", "remote.origin.uploadpack", str(upload_pack))

        transport_environment = dict(os.environ)
        transport_environment.pop("GIT_NO_LAZY_FETCH", None)
        transport_attempt = subprocess.run(
            ("git", "-C", str(partial), "cat-file", "-e", blob),
            check=False,
            env=transport_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(transport_attempt.returncode, 0)
        self.assertTrue(marker.exists())
        marker.unlink()

        with self.assertRaisesRegex(ReviewError, "private review Git objects"):
            prepare_workspace(
                repo=partial,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )

        self.assertFalse(marker.exists())
        partial_review_root = workspace_runtime._review_root_for_source(partial)
        self.assertEqual(list(partial_review_root.glob("isolated-review-*")), [])
        if partial_review_root.exists():
            partial_review_root.rmdir()

    def test_prepare_materializes_frozen_range_and_local_control_files(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)

        self.assertEqual(review.base_ref, self.base)
        self.assertEqual(review.head_ref, self.head)
        self.assertEqual(review.diff_file.parent.name, ".codex-review")
        self.assertEqual(review.prompt_file.parent, review.diff_file.parent)
        self.assertIn("+two", review.diff_file.read_text(encoding="utf-8"))
        prompt = review.prompt_file.read_text(encoding="utf-8")
        self.assertIn(f"{self.base}..{self.head}", prompt)
        self.assertIn("Primary diff file: .codex-review/review.diff", prompt)
        self.assertIn("If `Read` is the only file tool", prompt)
        self.assertNotIn(str(review.workspace_root), prompt)
        self.assertNotIn("Source repository:", prompt)
        self.assertTrue((review.workspace_root / ".git").is_file())
        self.assertEqual(review.content_variant, "head")
        self.assertRegex(review.snapshot_tree_sha, r"^[0-9a-f]{40,64}$")
        self.assertRegex(review.scope_identity, r"^[0-9a-f]{64}$")
        self.assertEqual(git(review.workspace_root, "status", "--porcelain"), "")
        self.assertEqual(git(review.workspace_root, "rev-parse", "HEAD"), self.head)
        self.assertEqual(
            review.container_dir.parent,
            workspace_runtime._review_root_for_source(self.repo),
        )
        self.assertFalse(
            review.container_dir.resolve().is_relative_to(self.repo.resolve())
        )
        for helper_state in (
            review.container_dir,
            review.workspace_root,
            review.diff_file,
            review.prompt_file,
            review.git_dir,
            review.container_dir / workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
        ):
            with self.subTest(helper_state=helper_state):
                self.assertIsNotNone(helper_state)
                self.assertFalse(
                    helper_state.resolve().is_relative_to(self.repo.resolve())
                )
        self.assertEqual(review.container_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (review.workspace_root / "example.txt").read_text(encoding="utf-8"),
            "one\ntwo\n",
        )

        cleanup_workspace(review, keep_container=False)
        self.assertFalse(review.container_dir.exists())

    def test_review_root_is_exact_stable_and_source_specific(self) -> None:
        canonical_source = self.repo.resolve(strict=True)
        digest = hashlib.sha256(os.fsencode(str(canonical_source))).hexdigest()
        expected = (
            workspace_runtime._canonical_review_root_base()
            / f"{workspace_runtime.REVIEW_USER_ROOT_PREFIX}{os.geteuid()}"
            / digest
        )
        alias = pathlib.Path(self.temporary.name) / "repo-alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        other_source = pathlib.Path(self.temporary.name) / "other-source"
        other_source.mkdir()

        self.assertEqual(
            workspace_runtime._review_root_for_source(self.repo),
            expected,
        )
        self.assertEqual(
            workspace_runtime._review_root_for_source(self.repo),
            workspace_runtime._review_root_for_source(alias),
        )
        self.assertNotEqual(
            workspace_runtime._review_root_for_source(self.repo),
            workspace_runtime._review_root_for_source(other_source),
        )

    def test_default_rejects_dirty_source_before_creating_container(self) -> None:
        (self.repo / "example.txt").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "include-source-wip"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_wip_snapshot_includes_final_tracked_deleted_and_untracked_content(
        self,
    ) -> None:
        (self.repo / "example.txt").write_text("staged\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        (self.repo / "example.txt").write_text("staged\nunstaged\n", encoding="utf-8")
        (self.repo / ".gitattributes").unlink()
        (self.repo / "new.txt").write_text("untracked\n", encoding="utf-8")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            include_source_wip=True,
        )
        self.reviews.append(review)

        self.assertEqual(review.content_variant, "source-wip")
        self.assertEqual(
            (review.workspace_root / "example.txt").read_text(encoding="utf-8"),
            "staged\nunstaged\n",
        )
        self.assertFalse((review.workspace_root / ".gitattributes").exists())
        self.assertEqual(
            (review.workspace_root / "new.txt").read_text(encoding="utf-8"),
            "untracked\n",
        )
        diff = review.diff_file.read_text(encoding="utf-8")
        self.assertIn("+unstaged", diff)
        self.assertIn("new.txt", diff)
        prompt = review.prompt_file.read_text(encoding="utf-8")
        self.assertIn("Content variant: source-wip", prompt)
        self.assertIn("not an exact committed range", prompt)

    def test_clean_and_wip_respect_user_global_git_ignores(self) -> None:
        configured_home = pathlib.Path(self.temporary.name) / "configured-home"
        configured_home.mkdir()
        configured_ignore = configured_home / "global-ignore"
        configured_ignored_name = "configured-ignored.json"
        configured_ignore.write_text(
            f"/{configured_ignored_name}\n",
            encoding="utf-8",
        )
        (configured_home / ".gitconfig").write_text(
            f"[core]\n\texcludesFile = {configured_ignore}\n",
            encoding="utf-8",
        )

        default_home = pathlib.Path(self.temporary.name) / "default-home"
        default_ignore = default_home / ".config" / "git" / "ignore"
        default_ignore.parent.mkdir(parents=True)
        default_ignored_name = "default-ignored.json"
        default_ignore.write_text(
            f"/{default_ignored_name}\n",
            encoding="utf-8",
        )

        xdg_home = pathlib.Path(self.temporary.name) / "xdg-home"
        xdg_home.mkdir()
        xdg_config_home = pathlib.Path(self.temporary.name) / "xdg-config"
        xdg_ignore = xdg_config_home / "git" / "ignore"
        xdg_ignore.parent.mkdir(parents=True)
        xdg_ignored_name = "xdg-ignored.json"
        xdg_ignore.write_text(
            f"/{xdg_ignored_name}\n",
            encoding="utf-8",
        )

        ambient_ignore = pathlib.Path(self.temporary.name) / "ambient-ignore"
        ambient_ignore.write_text("/ambient-only-*.txt\n", encoding="utf-8")
        ambient_global_config = (
            pathlib.Path(self.temporary.name) / "ambient-global-config"
        )
        ambient_global_config.write_text(
            f"[core]\n\texcludesFile = {ambient_ignore}\n",
            encoding="utf-8",
        )
        ignored_payload = (
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n"
        )

        scenarios = (
            (
                "configured-core-excludes-file",
                configured_home,
                "",
                configured_ignored_name,
            ),
            ("default-home-ignore", default_home, "", default_ignored_name),
            (
                "default-xdg-ignore",
                xdg_home,
                str(xdg_config_home),
                xdg_ignored_name,
            ),
        )
        for label, source_home, xdg_value, ignored_name in scenarios:
            ignored_path = self.repo / ignored_name
            visible_name = f"ambient-only-{label}.txt"
            visible_path = self.repo / visible_name
            try:
                ignored_path.write_text(ignored_payload, encoding="utf-8")
                with (
                    self.subTest(ignore_source=label),
                    mock.patch.object(
                        workspace_runtime,
                        "_source_git_home",
                        return_value=source_home,
                    ),
                    mock.patch.dict(
                        workspace_runtime.os.environ,
                        {
                            "GIT_CONFIG_GLOBAL": str(ambient_global_config),
                            "XDG_CONFIG_HOME": xdg_value,
                        },
                    ),
                ):
                    clean_review = prepare_workspace(
                        repo=self.repo,
                        base_ref=self.base,
                        head_ref=self.head,
                    )
                    self.reviews.append(clean_review)
                    self.assertFalse(
                        (clean_review.workspace_root / ignored_name).exists()
                    )

                    visible_path.write_text("capture this WIP file\n", encoding="utf-8")
                    with self.assertRaisesRegex(
                        ReviewError,
                        "nonignored untracked changes",
                    ):
                        prepare_workspace(
                            repo=self.repo,
                            base_ref=self.base,
                            head_ref=self.head,
                        )

                    wip_review = prepare_workspace(
                        repo=self.repo,
                        base_ref=self.base,
                        head_ref=self.head,
                        include_source_wip=True,
                    )
                    self.reviews.append(wip_review)
                    self.assertEqual(
                        (wip_review.workspace_root / visible_name).read_text(
                            encoding="utf-8"
                        ),
                        "capture this WIP file\n",
                    )
                    self.assertFalse(
                        (wip_review.workspace_root / ignored_name).exists()
                    )
                    diff = wip_review.diff_file.read_text(encoding="utf-8")
                    self.assertIn(visible_name, diff)
                    self.assertNotIn(ignored_name, diff)
                    self.assertNotIn(oauth_refresh_credential(), diff)
                    validate_external_workspace(wip_review)
            finally:
                ignored_path.unlink(missing_ok=True)
                visible_path.unlink(missing_ok=True)

    def test_wip_case_only_rename_does_not_capture_deleted_alias(self) -> None:
        original_path = pathlib.PurePosixPath("example.txt")
        renamed_path = pathlib.PurePosixPath("EXAMPLE.txt")
        git(self.repo, "mv", original_path.as_posix(), renamed_path.as_posix())
        (self.repo / renamed_path).write_text("case-only rename\n", encoding="utf-8")
        original_read = workspace_runtime._read_wip_entry
        aliased_source_reads = 0

        def emulate_case_insensitive_source(**kwargs):
            nonlocal aliased_source_reads
            if (
                kwargs["source_root"] == self.repo
                and kwargs["relative"] == original_path
            ):
                aliased_source_reads += 1
                kwargs["relative"] = renamed_path
            return original_read(**kwargs)

        with mock.patch.object(
            workspace_runtime,
            "_read_wip_entry",
            side_effect=emulate_case_insensitive_source,
        ):
            review = prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )
        self.reviews.append(review)

        tree_paths = set(
            git(
                review.workspace_root,
                "ls-tree",
                "-r",
                "--name-only",
                review.snapshot_tree_sha,
            ).splitlines()
        )
        self.assertEqual(aliased_source_reads, 0)
        self.assertNotIn(original_path.as_posix(), tree_paths)
        self.assertIn(renamed_path.as_posix(), tree_paths)
        self.assertEqual(
            (review.workspace_root / renamed_path).read_text(encoding="utf-8"),
            "case-only rename\n",
        )
        validate_external_workspace(review)

    def test_wip_requires_source_head_to_match_review_head(self) -> None:
        (self.repo / "example.txt").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "source HEAD"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.base,
                include_source_wip=True,
            )

        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_wip_symlink_targets_share_aggregate_snapshot_budget(self) -> None:
        first = pathlib.PurePosixPath("alpha-link")
        second = pathlib.PurePosixPath("beta-link")
        (self.repo / first).symlink_to("one")
        (self.repo / second).symlink_to("two")

        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_BYTES", 5),
            self.assertRaisesRegex(
                ReviewError,
                "symlink exceeds the review snapshot limit",
            ),
        ):
            workspace_runtime._capture_source_wip_entries(
                source_root=self.repo,
                paths={first, second},
            )

    def test_wip_overlay_batches_raw_paths_without_per_path_git_processes(
        self,
    ) -> None:
        raw_name = (
            b"raw-\n-\t.txt" if sys.platform == "darwin" else b"raw-\xff-\n-\t.txt"
        )
        relative = pathlib.PurePosixPath(os.fsdecode(raw_name))
        payload = b"raw WIP path content\n"
        self.repo.joinpath(*relative.parts).write_bytes(payload)
        (self.repo / "second-wip.txt").write_text("second\n", encoding="utf-8")
        original_run = workspace_runtime._run_worktree_git
        commands: list[tuple[str, ...]] = []

        def record_worktree_git(workspace_root, *args, **kwargs):
            commands.append(tuple(args))
            return original_run(workspace_root, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime,
            "_run_worktree_git",
            side_effect=record_worktree_git,
        ):
            review = prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )
        self.reviews.append(review)

        self.assertEqual(
            review.workspace_root.joinpath(*relative.parts).read_bytes(), payload
        )
        tree = subprocess.run(
            (
                "git",
                "-C",
                str(review.workspace_root),
                "ls-tree",
                "-rz",
                "--name-only",
                review.snapshot_tree_sha,
            ),
            check=True,
            env=test_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
        self.assertIn(raw_name + b"\0", tree)
        self.assertEqual(
            [command for command in commands if command[:1] == ("fast-import",)],
            [("fast-import", "--quiet", "--done")],
        )
        self.assertEqual(
            [command for command in commands if command[:1] == ("update-index",)],
            [("update-index", "-z", "--index-info")],
        )
        self.assertFalse(any(command[:1] == ("hash-object",) for command in commands))
        validate_external_workspace(review)

    def test_wip_blob_import_batches_duplicate_payloads_to_same_object(self) -> None:
        payload = b"shared WIP content\n"
        entries = {
            pathlib.PurePosixPath("first.txt"): ("100644", payload),
            pathlib.PurePosixPath("second.txt"): ("100755", payload),
        }
        original_run = workspace_runtime._run_worktree_git
        commands: list[tuple[str, ...]] = []

        def record_worktree_git(workspace_root, *args, **kwargs):
            commands.append(tuple(args))
            return original_run(workspace_root, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime,
            "_run_worktree_git",
            side_effect=record_worktree_git,
        ):
            object_format, object_ids = workspace_runtime._import_source_wip_blobs(
                workspace_root=self.repo,
                entries=entries,
            )

        digest = hashlib.new(object_format)
        digest.update(f"blob {len(payload)}\0".encode("ascii"))
        digest.update(payload)
        expected_id = digest.hexdigest()
        self.assertEqual(
            object_ids,
            {relative: expected_id for relative in entries},
        )
        self.assertEqual(
            [command for command in commands if command[:1] == ("fast-import",)],
            [("fast-import", "--quiet", "--done")],
        )

    def test_deletion_only_wip_uses_one_nul_index_batch_without_fast_import(
        self,
    ) -> None:
        (self.repo / "example.txt").unlink()
        object_format = git(self.repo, "rev-parse", "--show-object-format")
        object_id_length = {"sha1": 40, "sha256": 64}[object_format]
        original_run = workspace_runtime._run_worktree_git
        commands: list[tuple[str, ...]] = []
        index_batches: list[bytes] = []

        def record_worktree_git(workspace_root, *args, **kwargs):
            commands.append(tuple(args))
            if args == ("update-index", "-z", "--index-info"):
                input_handle = kwargs["input_handle"]
                position = input_handle.tell()
                index_batches.append(input_handle.read())
                input_handle.seek(position)
            return original_run(workspace_root, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime,
            "_run_worktree_git",
            side_effect=record_worktree_git,
        ):
            review = prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )
        self.reviews.append(review)

        self.assertFalse((review.workspace_root / "example.txt").exists())
        self.assertFalse(any(command[:1] == ("fast-import",) for command in commands))
        self.assertEqual(
            [command for command in commands if command[:1] == ("update-index",)],
            [("update-index", "-z", "--index-info")],
        )
        self.assertEqual(
            index_batches,
            [b"0 " + b"0" * object_id_length + b"\texample.txt\0"],
        )
        validate_external_workspace(review)

    def test_wip_blob_import_rejects_mismatched_fast_import_mark(self) -> None:
        relative = pathlib.PurePosixPath("mismatch.txt")

        def fake_worktree_git(_workspace_root, *args, **kwargs):
            if args == ("rev-parse", "--show-object-format"):
                return subprocess.CompletedProcess(args, 0, b"sha1\n", b"")
            self.assertEqual(args, ("fast-import", "--quiet", "--done"))
            self.assertIsNotNone(kwargs.get("input_handle"))
            self.assertEqual(kwargs.get("record_limit"), 1)
            return subprocess.CompletedProcess(args, 0, b"0" * 40 + b"\n", b"")

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_worktree_git",
                side_effect=fake_worktree_git,
            ),
            self.assertRaisesRegex(ReviewError, "mismatched object metadata"),
        ):
            workspace_runtime._import_source_wip_blobs(
                workspace_root=self.repo,
                entries={relative: ("100644", b"captured WIP\n")},
            )

    def test_wip_blob_import_rejects_malformed_fast_import_metadata(self) -> None:
        cases = (
            (
                "truncated",
                {pathlib.PurePosixPath("truncated.txt"): ("100644", b"one\n")},
                b"0" * 40,
                "truncated object metadata",
            ),
            (
                "incomplete",
                {
                    pathlib.PurePosixPath("first.txt"): ("100644", b"one\n"),
                    pathlib.PurePosixPath("second.txt"): ("100644", b"two\n"),
                },
                b"0" * 40 + b"\n",
                "incomplete object metadata",
            ),
            (
                "invalid-hex",
                {pathlib.PurePosixPath("invalid.txt"): ("100644", b"one\n")},
                b"g" * 40 + b"\n",
                "invalid object metadata",
            ),
        )

        for name, entries, output, error_pattern in cases:
            with self.subTest(name=name):

                def fake_worktree_git(_workspace_root, *args, **kwargs):
                    if args == ("rev-parse", "--show-object-format"):
                        return subprocess.CompletedProcess(args, 0, b"sha1\n", b"")
                    self.assertEqual(args, ("fast-import", "--quiet", "--done"))
                    self.assertIsNotNone(kwargs.get("input_handle"))
                    self.assertEqual(kwargs.get("record_limit"), len(entries))
                    return subprocess.CompletedProcess(args, 0, output, b"")

                with (
                    mock.patch.object(
                        workspace_runtime,
                        "_run_worktree_git",
                        side_effect=fake_worktree_git,
                    ),
                    self.assertRaisesRegex(ReviewError, error_pattern),
                ):
                    workspace_runtime._import_source_wip_blobs(
                        workspace_root=self.repo,
                        entries=entries,
                    )

    def test_wip_symlink_to_directory_transition_preserves_aliased_content(
        self,
    ) -> None:
        target = self.repo / "target"
        target.mkdir()
        (target / "child.txt").write_text("tracked target\n", encoding="utf-8")
        (self.repo / "alias").symlink_to("target", target_is_directory=True)
        git(self.repo, "add", "target/child.txt", "alias")
        git(self.repo, "commit", "-m", "Add tracked alias")
        head = git(self.repo, "rev-parse", "HEAD")

        (self.repo / "alias").unlink()
        (self.repo / "alias").mkdir()
        (self.repo / "alias/child.txt").write_text("reviewed WIP\n", encoding="utf-8")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
            include_source_wip=True,
        )
        self.reviews.append(review)

        self.assertEqual(
            (review.workspace_root / "target/child.txt").read_text(encoding="utf-8"),
            "tracked target\n",
        )
        self.assertEqual(
            (review.workspace_root / "alias/child.txt").read_text(encoding="utf-8"),
            "reviewed WIP\n",
        )
        self.assertEqual(
            git(review.workspace_root, "write-tree"), review.snapshot_tree_sha
        )
        validate_external_workspace(review)

    def test_wip_directory_to_file_transition_matches_snapshot_tree(self) -> None:
        (self.repo / "node").mkdir()
        (self.repo / "node/child.txt").write_text("tracked child\n", encoding="utf-8")
        git(self.repo, "add", "node/child.txt")
        git(self.repo, "commit", "-m", "Add tracked directory")
        head = git(self.repo, "rev-parse", "HEAD")

        (self.repo / "node/child.txt").unlink()
        (self.repo / "node").rmdir()
        (self.repo / "node").write_text("replacement file\n", encoding="utf-8")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
            include_source_wip=True,
        )
        self.reviews.append(review)

        self.assertTrue((review.workspace_root / "node").is_file())
        self.assertEqual(
            (review.workspace_root / "node").read_text(encoding="utf-8"),
            "replacement file\n",
        )
        self.assertEqual(
            git(review.workspace_root, "write-tree"), review.snapshot_tree_sha
        )
        validate_external_workspace(review)

    def test_wip_directory_to_external_symlink_never_reads_external_bytes(
        self,
    ) -> None:
        (self.repo / "node").mkdir()
        (self.repo / "node/child.txt").write_text("tracked child\n", encoding="utf-8")
        git(self.repo, "add", "node/child.txt")
        git(self.repo, "commit", "-m", "Add tracked directory")
        head = git(self.repo, "rev-parse", "HEAD")
        outside = pathlib.Path(self.temporary.name) / "outside-wip"
        outside.mkdir()
        marker = b"MUST_NOT_ENTER_REVIEW_SNAPSHOT\n"
        (outside / "child.txt").write_bytes(marker)

        (self.repo / "node/child.txt").unlink()
        (self.repo / "node").rmdir()
        (self.repo / "node").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ReviewError, "symlink escapes") as raised:
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
                include_source_wip=True,
            )

        self.assertNotIn(marker.decode().strip(), str(raised.exception))
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_external_preflight_rejects_post_prepare_workspace_mutation(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        (review.workspace_root / "example.txt").write_text(
            "post-prepare mutation\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(ReviewError, "does not match snapshot"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_forged_scope_identity(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        forged = review.to_json()
        forged["scope_identity"] = "0" * 64

        with self.assertRaisesRegex(ReviewError, "scope identity"):
            validate_external_workspace(
                workspace_runtime.ReviewWorkspace.from_json(forged)
            )

    def test_external_preflight_rejects_detached_head_retargeting(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        (worktree_admin / "HEAD").write_text(
            f"{review.base_ref}\n",
            encoding="ascii",
        )

        with self.assertRaisesRegex(ReviewError, "HEAD no longer matches"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_attached_head_at_expected_commit(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        (worktree_admin / "HEAD").write_text(
            "ref: refs/heads/reviewer-mutation\n",
            encoding="ascii",
        )

        with self.assertRaisesRegex(ReviewError, "no longer detached"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_private_shallow_endpoint_mutation(
        self,
    ) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        shallow = review.git_dir / "shallow"
        shallow.write_text(f"{review.head_ref}\n", encoding="ascii")

        with self.assertRaisesRegex(ReviewError, "shallow endpoints"):
            validate_external_workspace(review)

    def test_external_preflight_bounds_head_before_running_git(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        (worktree_admin / "HEAD").write_bytes(b"0" * 4097)

        with (
            mock.patch.object(workspace_runtime, "_run_worktree_git") as worktree_git,
            mock.patch.object(workspace_runtime, "_run_private_git") as private_git,
            self.assertRaisesRegex(ReviewError, "HEAD exceeds its review size limit"),
        ):
            validate_external_workspace(review)

        worktree_git.assert_not_called()
        private_git.assert_not_called()

    def test_external_preflight_bounds_shallow_before_running_git(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        (review.git_dir / "shallow").write_bytes(b"0" * (2 * 65 + 1))

        with (
            mock.patch.object(workspace_runtime, "_run_worktree_git") as worktree_git,
            mock.patch.object(workspace_runtime, "_run_private_git") as private_git,
            self.assertRaisesRegex(ReviewError, "shallow.*review size limit"),
        ):
            validate_external_workspace(review)

        worktree_git.assert_not_called()
        private_git.assert_not_called()

    def test_external_preflight_rejects_worktree_commondir_retargeting(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        (worktree_admin / "commondir").write_text(
            f"{self.repo / '.git'}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ReviewError, "commondir"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_private_object_alternates(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        alternates = review.git_dir / "objects/info/alternates"
        alternates.write_text(f"{self.repo / '.git/objects'}\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "object alternates"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_private_config_comment(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        with (review.git_dir / "config").open("ab") as handle:
            handle.write(b"# unexpected private comment\n")

        with self.assertRaisesRegex(ReviewError, "config"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_private_locked_payload(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        (worktree_admin / "locked").write_bytes(b"unexpected private data\n")

        with self.assertRaisesRegex(ReviewError, "locked"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_worktree_reflog_and_cleanup_succeeds(
        self,
    ) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        self.assertFalse((review.git_dir / "logs").exists())
        self.assertFalse((worktree_admin / "logs").exists())
        validate_external_workspace(review)

        reflog = worktree_admin / "logs" / "HEAD"
        reflog.parent.mkdir()
        reflog.write_bytes(b"unexpected private reflog\n")
        with self.assertRaisesRegex(ReviewError, "unexpected entry"):
            validate_external_workspace(review)

        container = review.container_dir
        self.assertIsNone(cleanup_workspace(review, keep_container=False))
        self.reviews.remove(review)
        self.assertFalse(container.exists())

    def test_external_preflight_rejects_unexpected_private_root_file(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        (review.git_dir / "note").write_bytes(b"unexpected private data\n")

        with self.assertRaisesRegex(ReviewError, "root inventory"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_unexpected_private_object(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        subprocess.run(
            (
                "git",
                f"--git-dir={review.git_dir}",
                "hash-object",
                "-w",
                "--stdin",
            ),
            input=b"unexpected private object\n",
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        with self.assertRaisesRegex(ReviewError, "object set"):
            validate_external_workspace(review)

    def test_wip_private_object_limit_includes_snapshot_closure(self) -> None:
        (self.repo / "fresh-wip.txt").write_text("fresh WIP blob\n", encoding="utf-8")
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            include_source_wip=True,
        )
        self.reviews.append(review)
        object_id_length = len(review.head_ref)
        endpoint_objects = workspace_runtime._private_object_id_set(
            git_dir=review.git_dir,
            args=(
                "rev-list",
                "--objects",
                "--no-object-names",
                f"{review.base_ref}^{{tree}}",
                f"{review.head_ref}^{{tree}}",
            ),
            label="scaled endpoint objects",
            object_id_length=object_id_length,
        )
        snapshot_objects = workspace_runtime._private_object_id_set(
            git_dir=review.git_dir,
            args=(
                "rev-list",
                "--objects",
                "--no-object-names",
                review.snapshot_tree_sha,
            ),
            label="scaled WIP snapshot objects",
            object_id_length=object_id_length,
        )
        self.assertGreaterEqual(len(snapshot_objects - endpoint_objects), 2)
        actual_objects = workspace_runtime._private_object_id_set(
            git_dir=review.git_dir,
            args=(
                "cat-file",
                "--batch-check=%(objectname)",
                "--batch-all-objects",
            ),
            label="scaled actual objects",
            object_id_length=object_id_length,
        )
        self.assertEqual(
            workspace_runtime.MAX_PRIVATE_OBJECT_ENTRIES,
            6 * workspace_runtime.MAX_SNAPSHOT_ENTRIES + 16,
        )
        scaled_limit = len(actual_objects)
        with mock.patch.object(
            workspace_runtime,
            "MAX_PRIVATE_OBJECT_ENTRIES",
            scaled_limit,
        ):
            validate_external_workspace(review)

        subprocess.run(
            (
                "git",
                f"--git-dir={review.git_dir}",
                "hash-object",
                "-w",
                "--stdin",
            ),
            input=b"unexpected scaled private object\n",
            check=True,
            env=test_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "MAX_PRIVATE_OBJECT_ENTRIES",
                scaled_limit,
            ),
            self.assertRaisesRegex(ReviewError, "actual objects exceeds"),
        ):
            validate_external_workspace(review)

    def test_private_object_storage_category_limits_accept_exact_sizes(self) -> None:
        wip_directory = self.repo / "wip-budget"
        wip_directory.mkdir()
        (wip_directory / "entry.txt").write_text(
            "WIP private object budget\n",
            encoding="utf-8",
        )
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            include_source_wip=True,
        )
        self.reviews.append(review)

        objects = review.git_dir / "objects"
        pack_files = list((objects / "pack").glob("*.pack"))
        sidecar_files = [
            *list((objects / "pack").glob("*.idx")),
            *list((objects / "pack").glob("*.rev")),
        ]
        loose_files = [
            path for path in objects.glob("[0-9a-f][0-9a-f]/*") if path.is_file()
        ]
        self.assertTrue(pack_files)
        self.assertTrue(sidecar_files)
        self.assertTrue(loose_files)

        pack_limit = max(path.stat().st_size for path in pack_files)
        sidecar_limit = max(path.stat().st_size for path in sidecar_files)
        loose_limit = max(path.stat().st_size for path in loose_files)
        storage_limit = sum(
            path.stat().st_size for path in (*pack_files, *sidecar_files, *loose_files)
        )

        def validate_limits(
            *,
            pack: int = pack_limit,
            sidecar: int = sidecar_limit,
            loose: int = loose_limit,
            storage: int = storage_limit,
        ) -> None:
            with (
                mock.patch.object(workspace_runtime, "MAX_PRIVATE_PACK_BYTES", pack),
                mock.patch.object(
                    workspace_runtime,
                    "MAX_PRIVATE_OBJECT_LIST_BYTES",
                    sidecar,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "MAX_PRIVATE_LOOSE_OBJECT_BYTES",
                    loose,
                ),
                mock.patch.object(
                    workspace_runtime,
                    "MAX_PRIVATE_STORAGE_BYTES",
                    storage,
                ),
            ):
                workspace_runtime._validate_private_object_storage_topology(
                    review.git_dir,
                    object_id_length=len(review.head_ref),
                )

        validate_limits()
        for label, overrides, error_pattern in (
            ("pack", {"pack": pack_limit - 1}, "pack file exceeds"),
            ("sidecar", {"sidecar": sidecar_limit - 1}, "pack file exceeds"),
            ("loose", {"loose": loose_limit - 1}, "loose object exceeds"),
            (
                "aggregate",
                {"storage": storage_limit - 1},
                "object storage exceeds",
            ),
        ):
            with (
                self.subTest(limit=label),
                self.assertRaisesRegex(ReviewError, error_pattern),
            ):
                validate_limits(**overrides)

    def test_external_preflight_rejects_unexpected_private_ref(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        subprocess.run(
            (
                "git",
                f"--git-dir={review.git_dir}",
                "update-ref",
                "refs/heads/injected",
                review.head_ref,
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        with self.assertRaisesRegex(ReviewError, "unexpected ref"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_corrupt_loose_object_shadow(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        blob = git(review.workspace_root, "rev-parse", "HEAD:example.txt")
        loose = review.git_dir / "objects" / blob[:2] / blob[2:]
        loose.parent.mkdir(exist_ok=True)
        loose.write_bytes(zlib.compress(b"blob 7\0mutated"))

        with self.assertRaisesRegex(ReviewError, "integrity check"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_oversized_private_pack(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pack_path = next((review.git_dir / "objects/pack").glob("*.pack"))
        pack_path.chmod(0o600)
        with pack_path.open("r+b") as handle:
            handle.truncate(workspace_runtime.MAX_PRIVATE_PACK_BYTES + 1)

        with self.assertRaisesRegex(ReviewError, "size limit"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_index_stat_cache_payload(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        pointer = (review.workspace_root / ".git").read_text(encoding="utf-8")
        worktree_admin = pathlib.Path(pointer.removeprefix("gitdir: ").strip())
        index_path = worktree_admin / "index"
        encoded = bytearray(index_path.read_bytes())
        token = aws_access_key_credential().encode("ascii")
        encoded[12 : 12 + len(token)] = token
        encoded[-20:] = hashlib.sha1(encoded[:-20]).digest()
        index_path.write_bytes(encoded)
        self.assertEqual(
            git(review.workspace_root, "write-tree"),
            review.snapshot_tree_sha,
        )

        with self.assertRaisesRegex(ReviewError, "noncanonical metadata"):
            validate_external_workspace(review)

    def test_external_preflight_rejects_gitlink_replaced_by_file(self) -> None:
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},module",
        )
        git(self.repo, "commit", "-m", "Add gitlink fixture")
        head = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "module").mkdir()

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
        )
        self.reviews.append(review)
        (review.workspace_root / "module").rmdir()
        (review.workspace_root / "module").write_text(
            "not a gitlink\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(ReviewError, "gitlink"):
            validate_external_workspace(review)

    def test_private_git_database_excludes_intermediate_reverted_objects(self) -> None:
        base = self.head
        marker = b"INTERMEDIATE_ONLY_PRIVATE_OBJECT\n"
        (self.repo / "intermediate.txt").write_bytes(marker)
        git(self.repo, "add", "intermediate.txt")
        git(self.repo, "commit", "-m", "Intermediate content")
        intermediate = git(self.repo, "rev-parse", "HEAD")
        intermediate_blob = git(self.repo, "rev-parse", "HEAD:intermediate.txt")
        (self.repo / "intermediate.txt").unlink()
        git(self.repo, "add", "-u")
        git(self.repo, "commit", "-m", "Revert intermediate content")
        head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=base,
            head_ref=head,
        )
        self.reviews.append(review)

        for object_id in (intermediate, intermediate_blob):
            unavailable = subprocess.run(
                ("git", "-C", str(review.workspace_root), "cat-file", "-e", object_id),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(unavailable.returncode, 0)
        self.assertEqual(git(review.workspace_root, "rev-parse", "HEAD"), head)
        self.assertEqual(
            git(review.workspace_root, "rev-parse", "--is-shallow-repository"),
            "true",
        )
        self.assertEqual(git(review.workspace_root, "rev-list", "HEAD"), head)
        self.assertEqual(
            git(review.workspace_root, "diff", "--exit-code", base, head), ""
        )
        self.assertNotIn(marker, review.diff_file.read_bytes())

    def test_endpoint_commit_message_with_secret_is_rejected(self) -> None:
        message = json.dumps({"refresh_token": oauth_refresh_credential()})
        git(self.repo, "commit", "--allow-empty", "-m", message)
        head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_endpoint_commit_signature_block_is_not_scanned_as_human_metadata(
        self,
    ) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n"
            " QUJD\n"
            " =AAAA\n"
            " -----END PGP SIGNATURE-----\n"
            "\n"
            "Signed endpoint fixture\n"
        ).encode("utf-8")
        created = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ),
            input=raw_commit,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = created.stdout.decode("ascii").strip()
        git(self.repo, "update-ref", "refs/heads/master", head, self.head)

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
        )
        self.reviews.append(review)
        validate_external_workspace(review)

    def test_endpoint_commit_accepts_real_wrapped_ssh_signature_armor(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        # Generated once with `ssh-keygen -Y sign`; preserve 70/70/70/22 wrapping.
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "gpgsig -----BEGIN SSH SIGNATURE-----\n"
            " U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg62o+hpYZCWU2AhVqtlt3CSqisN\n"
            " cS4G3tNI/RO0pKfRYAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\n"
            " OQAAAEDNCoSaeGCiFs0XiXJYiHX6JRXRBMdy+ZKMy3SsQQtzETgnNrBz3f+Wqt929WJ73C\n"
            " pG/h6O5BSY3TPrdHKKxTMA\n"
            " -----END SSH SIGNATURE-----\n"
            "\n"
            "SSH-signed endpoint fixture\n"
        ).encode("utf-8")
        head = self.install_raw_commit(raw_commit, previous=self.head)

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
        )
        self.reviews.append(review)
        validate_external_workspace(review)

    def test_endpoint_commit_signature_scans_joined_base64_body(self) -> None:
        credential = aws_access_key_credential()
        body_lines = (credential[:9], credential[9:])

        for metadata_key in ("gpgsig", "gpgsig-sha256", "mergetag"):
            with self.subTest(metadata_key=metadata_key):
                head = self.install_signature_commit(
                    metadata_key=metadata_key,
                    body_lines=body_lines,
                )
                try:
                    with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
                        prepare_workspace(
                            repo=self.repo,
                            base_ref=self.head,
                            head_ref=head,
                        )
                finally:
                    git(self.repo, "update-ref", "refs/heads/master", self.head, head)
                self.assert_no_review_containers()

    def test_endpoint_commit_signature_scans_strict_decoded_body(self) -> None:
        encoded = base64.b64encode(
            f"refresh_token={oauth_refresh_credential()}".encode("ascii")
        ).decode("ascii")
        midpoint = len(encoded) // 2
        body_lines = (encoded[:midpoint], encoded[midpoint:])

        for metadata_key in ("gpgsig", "gpgsig-sha256", "mergetag"):
            with self.subTest(metadata_key=metadata_key):
                head = self.install_signature_commit(
                    metadata_key=metadata_key,
                    body_lines=body_lines,
                )
                try:
                    with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
                        prepare_workspace(
                            repo=self.repo,
                            base_ref=self.head,
                            head_ref=head,
                        )
                finally:
                    git(self.repo, "update-ref", "refs/heads/master", self.head, head)
                self.assert_no_review_containers()

    def test_endpoint_commit_malformed_signature_header_fails_closed(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            f"gpgsig refresh_token={oauth_refresh_credential()}\n"
            "\n"
            "Malformed signature fixture\n"
        ).encode("utf-8")
        head = self.install_raw_commit(raw_commit, previous=self.head)

        with self.assertRaisesRegex(ReviewError, "malformed signature"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_endpoint_commit_noncanonical_signature_key_is_scanned(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        access_key = aws_access_key_credential()
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "GPGSIG -----BEGIN PGP SIGNATURE-----\n"
            f" {access_key}\n"
            " -----END PGP SIGNATURE-----\n"
            "\n"
            "Noncanonical signature key fixture\n"
        ).encode("utf-8")
        head = self.install_raw_commit(raw_commit, previous=self.head)

        with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_endpoint_commit_malformed_parent_metadata_fails_closed(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent refresh_token={oauth_refresh_credential()}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "\n"
            "Malformed parent fixture\n"
        ).encode("utf-8")

        with self.assertRaisesRegex(ReviewError, "malformed parent"):
            workspace_runtime._human_commit_metadata(
                raw_commit,
                object_id_length=len(self.head),
            )

    def test_endpoint_commit_accepts_uppercase_structural_object_ids(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree.upper()}\n"
            f"parent {self.head.upper()}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "\n"
            "Uppercase object fixture\n"
        ).encode("utf-8")
        head = self.install_raw_commit(raw_commit, previous=self.head)

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
        )
        self.reviews.append(review)
        validate_external_workspace(review)

    def test_endpoint_commit_mergetag_object_must_be_an_object_id(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            f"mergetag object refresh_token={oauth_refresh_credential()}\n"
            " type commit\n"
            " tag fixture\n"
            " tagger Review Test <review@example.com> 1700000000 +0000\n"
            " \n"
            " Mergetag fixture\n"
            "\n"
            "Endpoint fixture\n"
        ).encode("utf-8")
        head = self.install_raw_commit(raw_commit, previous=self.head)

        with self.assertRaisesRegex(ReviewError, "malformed mergetag object"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_endpoint_commit_custom_header_containing_sig_is_scanned(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            f"design-note refresh_token={oauth_refresh_credential()}\n"
            "\n"
            "Custom metadata fixture\n"
        ).encode("utf-8")
        created = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ),
            input=raw_commit,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = created.stdout.decode("ascii").strip()
        git(self.repo, "update-ref", "refs/heads/master", head, self.head)

        with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_endpoint_commit_malformed_mergetag_fails_closed(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            "mergetag malformed-without-tag-headers-or-message\n"
            "\n"
            "Malformed mergetag fixture\n"
        ).encode("utf-8")
        created = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ),
            input=raw_commit,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = created.stdout.decode("ascii").strip()
        git(self.repo, "update-ref", "refs/heads/master", head, self.head)

        with self.assertRaisesRegex(ReviewError, "malformed mergetag"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_endpoint_commit_mergetag_human_message_is_scanned(self) -> None:
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        raw_commit = (
            f"tree {tree}\n"
            f"parent {self.head}\n"
            "author Review Test <review@example.com> 1700000000 +0000\n"
            "committer Review Test <review@example.com> 1700000000 +0000\n"
            f"mergetag object {self.head}\n"
            " type commit\n"
            " tag fixture\n"
            " tagger Review Test <review@example.com> 1700000000 +0000\n"
            " \n"
            f" refresh_token={oauth_refresh_credential()}\n"
            "\n"
            "Mergetag metadata fixture\n"
        ).encode("utf-8")
        created = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ),
            input=raw_commit,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = created.stdout.decode("ascii").strip()
        git(self.repo, "update-ref", "refs/heads/master", head, self.head)

        with self.assertRaisesRegex(ReviewError, "endpoint commit object"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=head,
            )

    def test_wip_revalidates_content_even_when_porcelain_status_is_unchanged(
        self,
    ) -> None:
        (self.repo / "example.txt").write_text("first dirty value\n", encoding="utf-8")
        original_run_worktree_git = workspace_runtime._run_worktree_git
        mutated = False

        def mutate_after_snapshot(workspace_root, *args, **kwargs):
            nonlocal mutated
            result = original_run_worktree_git(workspace_root, *args, **kwargs)
            if args == ("write-tree",) and not mutated:
                mutated = True
                (self.repo / "example.txt").write_text(
                    "second dirty value\n", encoding="utf-8"
                )
            return result

        with (
            mock.patch.object(
                workspace_runtime,
                "_run_worktree_git",
                side_effect=mutate_after_snapshot,
            ),
            self.assertRaisesRegex(ReviewError, "content changed"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )

    def test_source_status_output_is_byte_bounded(self) -> None:
        (self.repo / "example.txt").write_text("dirty\n", encoding="utf-8")

        with (
            mock.patch.object(workspace_runtime, "MAX_SOURCE_STATUS_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "source WIP status metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )

    def test_source_wip_tracked_paths_are_record_bounded(self) -> None:
        (self.repo / "example.txt").write_text("dirty\n", encoding="utf-8")

        with (
            mock.patch.object(
                workspace_runtime,
                "MAX_SOURCE_TRACKED_PATH_RECORDS",
                0,
            ),
            self.assertRaisesRegex(ReviewError, "source WIP tracked paths exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )

    def test_source_index_flag_enumeration_is_record_bounded(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SOURCE_INDEX_RECORDS", 0),
            self.assertRaisesRegex(ReviewError, "source index-flag metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

    def test_source_status_timeout_terminates_git_process(self) -> None:
        fake_git = pathlib.Path(self.temporary.name) / "bounded-git"
        fake_git.write_text(
            "#!/bin/sh\nexec /bin/sleep 30\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        stop_process = workspace_runtime._stop_source_git_process

        with (
            mock.patch.object(workspace_runtime, "resolve_git", return_value=fake_git),
            mock.patch.object(
                workspace_runtime,
                "SOURCE_GIT_TIMEOUT_SECONDS",
                0.25,
            ),
            mock.patch.object(
                workspace_runtime,
                "_stop_source_git_process",
                wraps=stop_process,
            ) as stopped,
            self.assertRaisesRegex(ReviewError, "source Git time limit"),
        ):
            workspace_runtime._source_status(self.repo)

        stopped.assert_called_once()
        process = stopped.call_args.args[0]
        self.assertIsNotNone(process.returncode)
        self.assertLess(process.returncode, 0)

    def test_source_git_query_timeout_terminates_process(self) -> None:
        fake_git = pathlib.Path(self.temporary.name) / "bounded-query-git"
        fake_git.write_text(
            "#!/bin/sh\nexec /bin/sleep 30\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        stop_process = workspace_runtime._stop_bounded_process

        with (
            mock.patch.object(workspace_runtime, "resolve_git", return_value=fake_git),
            mock.patch.object(
                workspace_runtime,
                "SOURCE_GIT_TIMEOUT_SECONDS",
                0.25,
            ),
            mock.patch.object(
                workspace_runtime,
                "_stop_bounded_process",
                wraps=stop_process,
            ) as stopped,
            self.assertRaisesRegex(ReviewError, "source Git time limit"),
        ):
            workspace_runtime.resolve_commit(self.repo, "HEAD", label="query head")

        stopped.assert_called_once()
        process = stopped.call_args.args[0]
        self.assertIsNotNone(process.returncode)
        self.assertLess(process.returncode, 0)

    def test_private_git_preparation_timeout_terminates_process(self) -> None:
        fake_git = pathlib.Path(self.temporary.name) / "bounded-private-git"
        fake_git.write_text(
            "#!/bin/sh\nexec /bin/sleep 30\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        frozen_command = workspace_runtime._frozen_command
        stop_process = workspace_runtime._stop_bounded_process

        def stall_object_enumeration(*, git_view, args):
            if args[:1] == ("rev-list",):
                return (str(fake_git),)
            return frozen_command(git_view=git_view, args=args)

        with (
            mock.patch.object(
                workspace_runtime,
                "_frozen_command",
                side_effect=stall_object_enumeration,
            ),
            mock.patch.object(
                workspace_runtime,
                "PRIVATE_GIT_TIMEOUT_SECONDS",
                0.25,
            ),
            mock.patch.object(
                workspace_runtime,
                "_stop_bounded_process",
                wraps=stop_process,
            ) as stopped,
            self.assertRaisesRegex(ReviewError, "private Git time limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        stopped.assert_called_once()
        process = stopped.call_args.args[0]
        self.assertIsNotNone(process.returncode)
        self.assertLess(process.returncode, 0)
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_clean_and_wip_reject_assume_unchanged_index_entries(self) -> None:
        git(self.repo, "update-index", "--assume-unchanged", "example.txt")
        (self.repo / "example.txt").write_text("hidden dirty value\n", encoding="utf-8")

        for include_source_wip in (False, True):
            with (
                self.subTest(include_source_wip=include_source_wip),
                self.assertRaisesRegex(ReviewError, "hidden index flags"),
            ):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                    include_source_wip=include_source_wip,
                )

    def test_clean_and_wip_reject_skip_worktree_index_entries(self) -> None:
        git(self.repo, "update-index", "--skip-worktree", "example.txt")
        (self.repo / "example.txt").write_text("hidden dirty value\n", encoding="utf-8")

        for include_source_wip in (False, True):
            with (
                self.subTest(include_source_wip=include_source_wip),
                self.assertRaisesRegex(ReviewError, "hidden index flags"),
            ):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                    include_source_wip=include_source_wip,
                )

    def test_core_filemode_false_cannot_hide_mode_only_wip(self) -> None:
        git(self.repo, "config", "core.filemode", "false")
        (self.repo / "example.txt").chmod(0o755)

        with self.assertRaisesRegex(ReviewError, "source repository has"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            include_source_wip=True,
        )
        self.reviews.append(review)
        self.assertEqual(
            stat.S_IMODE((review.workspace_root / "example.txt").stat().st_mode),
            0o755,
        )

    def test_nonowner_execute_bits_follow_git_filemode_semantics(self) -> None:
        for source_mode in (0o654, 0o645):
            with self.subTest(source_mode=oct(source_mode)):
                (self.repo / "example.txt").write_text(
                    f"WIP mode {source_mode:o}\n",
                    encoding="utf-8",
                )
                (self.repo / "example.txt").chmod(source_mode)
                review = prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                    include_source_wip=True,
                )
                self.reviews.append(review)
                snapshot_entry = git(
                    review.workspace_root,
                    "ls-tree",
                    review.snapshot_tree_sha,
                    "example.txt",
                )
                self.assertEqual(snapshot_entry.split(maxsplit=1)[0], "100644")
                self.assertEqual(
                    stat.S_IMODE(
                        (review.workspace_root / "example.txt").stat().st_mode
                    ),
                    0o644,
                )

    def test_wip_rejects_collapsed_untracked_nested_repository(self) -> None:
        nested = self.repo / "nested"
        subprocess.run(
            ("git", "init", "-b", "master", str(nested)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (nested / "private.txt").write_text("nested content\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "nested repositories"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                include_source_wip=True,
            )

    def test_cleanup_keeps_state_artifacts_but_removes_private_git_database(
        self,
    ) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        marker = review.container_dir / "state-marker"
        marker.write_text("retain\n", encoding="utf-8")

        self.assertIsNone(cleanup_workspace(review, keep_container=True))
        self.assertTrue(review.container_dir.is_dir())
        self.assertTrue(marker.is_file())
        self.assertFalse(review.workspace_root.exists())
        self.assertFalse(
            (review.git_dir or review.container_dir / "review.git").exists()
        )
        self.assertIsNone(cleanup_workspace(review, keep_container=False))

    def test_retained_state_never_changes_source_git_status(self) -> None:
        git(self.repo, "rm", ".gitignore")
        git(self.repo, "commit", "-m", "Remove helper ignore")
        head = git(self.repo, "rev-parse", "HEAD")
        status_args = ("status", "--porcelain=v2", "--untracked-files=all")
        source_status = git(self.repo, *status_args)
        self.assertEqual(source_status, "")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=head,
        )
        marker = review.container_dir / "state-marker"
        marker.write_text("retain\n", encoding="utf-8")

        self.assertEqual(git(self.repo, *status_args), source_status)
        self.assertIsNone(cleanup_workspace(review, keep_container=True))
        self.assertTrue(marker.is_file())
        self.assertEqual(git(self.repo, *status_args), source_status)
        self.assertIsNone(cleanup_workspace(review, keep_container=False))
        self.assertEqual(git(self.repo, *status_args), source_status)

    def test_clean_and_wip_prepare_without_codex_tmp_ignore(self) -> None:
        plain = pathlib.Path(self.temporary.name) / "plain"
        plain.mkdir()
        subprocess.run(
            ("git", "init", "-b", "master", str(plain)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(plain, "config", "user.name", "Review Test")
        git(plain, "config", "user.email", "review@example.com")
        git(plain, "config", "commit.gpgsign", "false")
        (plain / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        git(plain, "add", "tracked.txt")
        git(plain, "commit", "-m", "Initial")
        head = git(plain, "rev-parse", "HEAD")
        review_root = workspace_runtime._review_root_for_source(plain)

        clean_review = prepare_workspace(repo=plain, base_ref=head, head_ref=head)
        self.assertEqual(clean_review.container_dir.parent, review_root)
        self.assertFalse(clean_review.container_dir.resolve().is_relative_to(plain))
        self.assertFalse((plain / ".codex-tmp").exists())
        self.assertIsNone(cleanup_workspace(clean_review, keep_container=False))

        (plain / "wip.txt").write_text("WIP\n", encoding="utf-8")
        source_status = git(plain, "status", "--porcelain=v2", "--untracked-files=all")
        wip_review = prepare_workspace(
            repo=plain,
            base_ref=head,
            head_ref=head,
            include_source_wip=True,
        )
        self.assertEqual(wip_review.container_dir.parent, review_root)
        self.assertFalse(wip_review.container_dir.resolve().is_relative_to(plain))
        self.assertEqual(
            (wip_review.workspace_root / "wip.txt").read_text(encoding="utf-8"),
            "WIP\n",
        )
        self.assertEqual(
            git(plain, "status", "--porcelain=v2", "--untracked-files=all"),
            source_status,
        )
        self.assertFalse((plain / ".codex-tmp").exists())
        self.assertIsNone(cleanup_workspace(wip_review, keep_container=False))
        review_root.rmdir()

    def test_cleanup_of_detached_worktree_is_idempotent(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )

        self.assertIsNone(cleanup_workspace(review, keep_container=False))
        self.assertIsNone(cleanup_workspace(review, keep_container=False))

    def test_prepare_rejects_lfs_pointer_after_attributes_are_deleted(self) -> None:
        git(self.repo, "rm", ".gitattributes")
        oid = "a" * 64
        (self.repo / "asset.bin").write_text(
            f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 1\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "asset.bin")
        git(self.repo, "commit", "-m", "Add direct LFS pointer")
        self.head = git(self.repo, "rev-parse", "HEAD")
        handoffs = []

        with self.assertRaisesRegex(
            ReviewError,
            r"blocked-checkout-lfs-pointer: review_status=not-run: .*asset\.bin",
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=handoffs.append,
            )

        self.assertEqual(handoffs, [])
        self.assert_no_review_containers()

    def test_prepare_materializes_blob_at_lfs_pointer_cutoff(self) -> None:
        git(self.repo, "rm", ".gitattributes")
        oid = "a" * 64
        canonical = (
            f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 1\n"
        ).encode("ascii")
        payload = canonical + (b" " * (1024 - len(canonical)))
        self.assertEqual(len(payload), workspace_runtime.GIT_LFS_POINTER_MAX_BYTES)
        (self.repo / "asset.bin").write_bytes(payload)
        git(self.repo, "add", "asset.bin")
        git(self.repo, "commit", "-m", "Add cutoff-sized pointer-like blob")
        self.head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)

        self.assertEqual((review.workspace_root / "asset.bin").read_bytes(), payload)

    def test_prepare_uses_private_control_modes_under_permissive_umask(self) -> None:
        for mask in (0o002, 0o000):
            with self.subTest(mask=oct(mask)):
                previous = os.umask(mask)
                try:
                    review = prepare_workspace(
                        repo=self.repo,
                        base_ref=self.base,
                        head_ref=self.head,
                    )
                finally:
                    os.umask(previous)
                self.reviews.append(review)

                control_dir = review.workspace_root / ".codex-review"
                self.assertEqual(review.container_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(control_dir.stat().st_mode & 0o777, 0o700)
                for name in workspace_runtime.CONTROL_ARTIFACT_SPECS:
                    self.assertEqual(
                        (control_dir / name).stat().st_mode & 0o777,
                        0o600,
                        name,
                    )
                for name in (
                    workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME,
                    workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
                ):
                    self.assertEqual(
                        (review.container_dir / name).stat().st_mode & 0o777,
                        0o600,
                        name,
                    )
                self.assertEqual(
                    (review.workspace_root / "example.txt").stat().st_mode & 0o777,
                    0o644,
                )
                validate_external_workspace(review)

    def test_external_workspace_rejects_group_writable_control_artifact(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        changed_paths = review.workspace_root / ".codex-review/changed-paths.z"
        changed_paths.chmod(0o660)

        with self.assertRaisesRegex(ReviewError, "group or other writable"):
            validate_external_workspace(review)

    def test_external_workspace_attests_exact_primary_diff(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        diff_bytes = review.diff_file.read_bytes()

        evidence = validate_external_workspace(review)

        self.assertEqual(
            evidence["primary_diff"],
            {
                "path": ".codex-review/review.diff",
                "sha256": hashlib.sha256(diff_bytes).hexdigest(),
                "size": len(diff_bytes),
            },
        )
        encoded_evidence = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(str(review.workspace_root), encoded_evidence)
        self.assertNotIn("+two", encoded_evidence)

        tampered_diff = bytearray(diff_bytes)
        tampered_diff[0] ^= 1
        review.diff_file.write_bytes(tampered_diff)
        with self.assertRaisesRegex(
            ReviewError,
            "does not match helper-private control state",
        ):
            validate_external_workspace(review)

    def test_preflight_serialization_has_a_separate_pretty_json_bound(self) -> None:
        def exact_value(target_size: int, *, pretty: bool) -> dict[str, str]:
            value = {"padding": ""}
            if pretty:
                empty = json.dumps(value, indent=2, sort_keys=True) + "\n"
            else:
                empty = json.dumps(value, separators=(",", ":"), sort_keys=True)
            value["padding"] = "x" * (target_size - len(empty.encode("utf-8")))
            return value

        compact_limit = workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES
        compact = exact_value(compact_limit, pretty=False)
        self.assertEqual(
            len(workspace_runtime._encode_synthetic_evidence_json(compact)),
            compact_limit,
        )
        with self.assertRaisesRegex(ReviewError, "synthetic-token preflight evidence"):
            workspace_runtime._encode_synthetic_evidence_json(
                exact_value(compact_limit + 1, pretty=False)
            )

        pretty_limit = workspace_runtime.MAX_PREFLIGHT_JSON_BYTES
        pretty = exact_value(pretty_limit, pretty=True)
        self.assertEqual(
            len(workspace_runtime.encode_preflight_json(pretty).encode("utf-8")),
            pretty_limit,
        )
        with self.assertRaisesRegex(ReviewError, "serialized preflight evidence"):
            workspace_runtime.encode_preflight_json(
                exact_value(pretty_limit + 1, pretty=True)
            )

    def test_bounded_json_reader_rejects_growth_past_limit(self) -> None:
        limit = workspace_runtime.MAX_PREFLIGHT_JSON_BYTES
        path = pathlib.Path(self.temporary.name) / "growing.json"
        empty = json.dumps({"padding": ""}, sort_keys=True)
        value = {"padding": "x" * (limit - len(empty.encode("utf-8")))}
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")
        self.assertEqual(len(encoded), limit)
        path.write_bytes(encoded)
        original_read = workspace_runtime._DigestingReader.read
        grew = False

        def grow_before_first_read(reader, size=-1):
            nonlocal grew
            if not grew:
                with path.open("ab") as handle:
                    handle.write(b"x")
                grew = True
            return original_read(reader, size)

        with mock.patch.object(
            workspace_runtime._DigestingReader,
            "read",
            new=grow_before_first_read,
        ):
            with self.assertRaisesRegex(ReviewError, "exceeds its review size limit"):
                workspace_runtime._read_bounded_json(
                    path,
                    label="growing evidence",
                    max_bytes=limit,
                )

    def test_bounded_json_reader_enforces_explicit_depth_limit(self) -> None:
        path = pathlib.Path(self.temporary.name) / "nested.json"

        def nested(depth: int) -> dict[str, object]:
            value: object = None
            for _ in range(depth):
                value = [value]
            return {"padding": value}

        path.write_text(
            json.dumps(nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH)),
            encoding="utf-8",
        )
        self.assertEqual(
            workspace_runtime._read_bounded_json(path, label="nested evidence"),
            nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH),
        )

        path.write_text(
            json.dumps(nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH + 1)),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewError,
            "nested evidence exceeds the JSON nesting depth limit",
        ):
            workspace_runtime._read_bounded_json(path, label="nested evidence")

    def test_prompt_override_replaces_only_review_scope_placeholders(self) -> None:
        template = pathlib.Path(self.temporary.name) / "prompt.txt"
        template.write_text(
            "Workspace={workspace}\nDiff={diff_file}\nRange={review_range}\n",
            encoding="utf-8",
        )
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            prompt_override=template,
        )
        self.reviews.append(review)
        prompt = review.prompt_file.read_text(encoding="utf-8")
        self.assertIn(str(review.workspace_root), prompt)
        self.assertIn(str(review.diff_file), prompt)
        self.assertIn(f"{self.base}..{self.head}", prompt)

    def test_prompt_override_replacement_is_single_pass(self) -> None:
        renamed_repo = self.repo.with_name("repo-{diff_file}")
        self.repo.rename(renamed_repo)
        self.repo = renamed_repo
        template = pathlib.Path(self.temporary.name) / "single-pass-prompt.txt"
        template.write_text(
            "Workspace={workspace}\nDiff={diff_file}\n",
            encoding="utf-8",
        )

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            prompt_override=template,
        )
        self.reviews.append(review)

        self.assertEqual(
            review.prompt_file.read_text(encoding="utf-8"),
            f"Workspace={review.workspace_root}\nDiff={review.diff_file}\n",
        )

    def test_prompt_override_rejects_oversized_template(self) -> None:
        template = pathlib.Path(self.temporary.name) / "oversized-prompt.txt"
        template.write_bytes(b"x" * 9)
        with (
            mock.patch.object(workspace_runtime, "MAX_REVIEW_PROMPT_BYTES", 8),
            self.assertRaisesRegex(ReviewError, "review prompt exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                prompt_override=template,
            )
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_prompt_override_rejects_oversized_rendered_prompt(self) -> None:
        template = pathlib.Path(self.temporary.name) / "expanded-prompt.txt"
        template.write_text("{workspace}", encoding="utf-8")
        with (
            mock.patch.object(workspace_runtime, "MAX_REVIEW_PROMPT_BYTES", 32),
            self.assertRaisesRegex(ReviewError, "review prompt exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                prompt_override=template,
            )
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_prompt_override_rejects_symlink_hardlink_fifo_and_writable_file(
        self,
    ) -> None:
        root = pathlib.Path(self.temporary.name)
        target = root / "prompt-target.txt"
        target.write_text("Review {review_range}\n", encoding="utf-8")
        target.chmod(0o600)
        symlink = root / "prompt-symlink.txt"
        symlink.symlink_to(target)
        hardlink = root / "prompt-hardlink.txt"
        os.link(target, hardlink)
        fifo = root / "prompt.fifo"
        os.mkfifo(fifo, mode=0o600)
        writable = root / "prompt-writable.txt"
        writable.write_text("Review {review_range}\n", encoding="utf-8")
        writable.chmod(0o620)

        for label, candidate in (
            ("symlink", symlink),
            ("hardlink", hardlink),
            ("fifo", fifo),
            ("writable", writable),
        ):
            with self.subTest(file_type=label), self.assertRaises(ReviewError):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_override=candidate,
                )
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_tree_record_diagnostics_redact_secret_paths_and_payloads(self) -> None:
        secret = aws_access_key_credential()
        malformed = f"malformed-{secret}".encode()
        with self.assertRaises(ReviewError) as malformed_error:
            _parse_tree_record(malformed)
        self.assertNotIn(secret, str(malformed_error.exception))

        reserved = f"100644 blob {'a' * 40}\t.git/{secret}".encode()
        with self.assertRaises(ReviewError) as reserved_error:
            _parse_tree_record(reserved)
        self.assertIn("<redacted snapshot path>", str(reserved_error.exception))
        self.assertNotIn(secret, str(reserved_error.exception))

        unsafe = b"100644 blob " + b"b" * 40 + b"\tline\n\x1b\xff/.."
        with self.assertRaises(ReviewError) as unsafe_error:
            _parse_tree_record(unsafe)
        diagnostic = str(unsafe_error.exception)
        self.assertNotIn("\n", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertIn("\\x0a", diagnostic)
        self.assertIn("\\x1b", diagnostic)
        self.assertIn("\\udcff", diagnostic)
        diagnostic.encode("utf-8")

    def test_aws_secret_key_matches_nonword_terminal_characters(self) -> None:
        for terminal in b"/+=":
            with self.subTest(terminal=chr(terminal)):
                value = b"A" * 39 + bytes([terminal])
                self.assertEqual(
                    _value_secret_rule(b"aws_secret_access_key=" + value),
                    "aws-secret-key",
                )
                self.assertIsNone(
                    _value_secret_rule(b"aws_secret_access_key=" + value + b"A")
                )

    def test_pgp_private_key_marker_is_rejected(self) -> None:
        marker = b"-----BEGIN PGP PRIVATE" + b" KEY BLOCK-----"

        self.assertEqual(_value_secret_rule(marker), "pgp-private-key")

    def test_placeholder_secret_requires_a_complete_placeholder_value(self) -> None:
        self.assertIsNone(_value_secret_rule(b'password = "example-test-secret"'))
        self.assertIsNone(_value_secret_rule(b'password = "${DATABASE_PASSWORD}"'))
        self.assertIsNone(_value_secret_rule(b'password = "<DATABASE_PASSWORD>"'))
        self.assertIsNone(_value_secret_rule(b'OPENAI_API_KEY = "parent-only-secret"'))

        credential = "".join(("example-", "ProdSecret", "ABC123!"))
        self.assertEqual(
            _value_secret_rule(f'password = "{credential}"'.encode()),
            "generic-secret-assignment",
        )

    def test_unquoted_secret_accepts_common_password_punctuation(self) -> None:
        credentials = (
            "".join(("StrongPass", "123456")),
            "".join(("StrongProductionPass", "123456!")),
            "".join(("StrongProductionPass", "123456@corp")),
            "".join(("Pass1234", "#Word5678")),
            "".join(("Pass1234", ";Word5678")),
            "".join(("0123456789abcdef", "0123456789abcdef")),
            "".join(("12345678", "90123456")),
            "".join(("deadbeef", "deadbeef", "deadbeef", "deadbeef")),
            "".join(("alphabetagamma", "deltaepsilonzeta")),
        )
        for credential in credentials:
            with self.subTest(credential=credential):
                payload = b"password: " + credential.encode()
                self.assertEqual(
                    _value_secret_rule(payload),
                    "generic-secret-assignment",
                )
        placeholder = b"".join((b"example-", b"test-", b"secret"))
        self.assertIsNone(_value_secret_rule(b"password: " + placeholder))
        self.assertIsNone(
            _value_secret_rule(b"password: example-test-secret # placeholder")
        )
        self.assertEqual(
            _value_secret_rule(
                b"password: "
                + placeholder
                + b" # fixture\n  ActualOpaqueSecretA9Z8Y7\n"
            ),
            "generic-secret-assignment",
        )

    def test_oversized_secret_assignments_fail_closed(self) -> None:
        alpha_secret = b"A" * 513
        hex_secret = b"deadbeef" * 65
        numeric_secret = b"1" * 513
        payloads = (
            b'password="' + alpha_secret + b'"',
            b"password=" + alpha_secret,
            b"password=" + hex_secret,
            b"password=" + numeric_secret,
        )
        for payload in payloads:
            with self.subTest(payload_length=len(payload)):
                self.assertEqual(
                    _value_secret_rule(payload),
                    "generic-secret-assignment",
                )

    def test_snapshot_rejects_oversized_single_blob_before_materializing(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_BLOB_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "per-file review limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list(
                workspace_runtime._review_root_for_source(self.repo).glob(
                    "isolated-review-*"
                )
            ),
            [],
        )

    def test_reserved_path_preflight_rejects_oversized_tree_metadata(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_TREE_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen base tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_reserved_path_preflight_rejects_excessive_tree_entries(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "frozen base tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_recursive_tree_metadata(self) -> None:
        with (
            mock.patch.object(
                workspace_runtime,
                "_commit_uses_reserved_control_path",
                return_value=False,
            ),
            mock.patch.object(
                workspace_runtime,
                "_reject_legacy_values_in_frozen_tree_paths",
                return_value=None,
            ),
            mock.patch.object(workspace_runtime, "MAX_TREE_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen Git tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_total_before_materializing(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "total review snapshot limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_generated_diff(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_DIFF_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen review diff exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_changed_path_metadata(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen changed paths exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_excessive_changed_path_entries(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "frozen changed paths exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_changed_blob_metadata(self) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "changed blob metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_excessive_changed_blob_entries(self) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "changed blob metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_snapshot_rejects_oversized_changed_blob_scan(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_BLOB_SCAN_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "total review scan limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assert_no_review_containers()

    def test_materialization_os_error_redacts_secret_path(self) -> None:
        secret = "AKIA" + "B" * 16
        (self.repo / secret).write_text("secret-shaped path\n", encoding="utf-8")
        git(self.repo, "add", secret)
        git(self.repo, "commit", "-m", "Add secret-shaped path")
        self.head = git(self.repo, "rev-parse", "HEAD")
        materialize_blob = workspace_runtime._materialize_blob

        def fail_secret_path(**kwargs):
            if kwargs["destination"].name == secret:
                raise OSError(errno.ENAMETOOLONG, f"path too long: {secret}")
            return materialize_blob(**kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "_materialize_blob",
                side_effect=fail_secret_path,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertIn("<redacted snapshot path>", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_invalid_ref_fails_before_creating_a_review_container(self) -> None:
        review_root = workspace_runtime._review_root_for_source(self.repo)
        with self.assertRaises(ReviewError):
            prepare_workspace(
                repo=self.repo,
                base_ref="missing-ref",
                head_ref=self.head,
            )
        self.assertFalse(review_root.exists())

    def test_diverged_range_reports_merge_base_before_creating_container(self) -> None:
        git(self.repo, "switch", "-c", "diverged", self.base)
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "side.txt")
        git(self.repo, "commit", "-m", "Diverge")
        diverged = git(self.repo, "rev-parse", "HEAD")

        review_root = workspace_runtime._review_root_for_source(self.repo)
        with (
            mock.patch.object(
                workspace_runtime,
                "_new_container",
                wraps=workspace_runtime._new_container,
            ) as new_container,
            self.assertRaisesRegex(
                ReviewError,
                rf"not an ancestor.*merge base {self.base}",
            ),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=diverged,
                head_ref=self.head,
            )
        new_container.assert_not_called()
        self.assertFalse(review_root.exists())

    def test_ancestor_check_ignores_local_replace_refs(self) -> None:
        git(self.repo, "switch", "-c", "replace-diverged", self.base)
        (self.repo / "replace-side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "replace-side.txt")
        git(self.repo, "commit", "-m", "Replace diverge")
        diverged = git(self.repo, "rev-parse", "HEAD")
        head_tree = git(self.repo, "rev-parse", f"{self.head}^{{tree}}")
        replacement = git(
            self.repo,
            "commit-tree",
            head_tree,
            "-p",
            diverged,
            "-m",
            "Replacement head",
        )
        git(self.repo, "replace", self.head, replacement)

        self.assertEqual(
            git(
                self.repo,
                "merge-base",
                "--is-ancestor",
                diverged,
                self.head,
            ),
            "",
        )
        with self.assertRaisesRegex(ReviewError, "not an ancestor"):
            prepare_workspace(
                repo=self.repo,
                base_ref=diverged,
                head_ref=self.head,
            )
        self.assertFalse(workspace_runtime._review_root_for_source(self.repo).exists())

    def test_ancestor_check_ignores_local_grafts(self) -> None:
        git(self.repo, "switch", "-c", "graft-diverged", self.base)
        (self.repo / "graft-side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "graft-side.txt")
        git(self.repo, "commit", "-m", "Graft diverge")
        diverged = git(self.repo, "rev-parse", "HEAD")
        grafts = self.repo / ".git" / "info" / "grafts"
        grafts.write_text(f"{self.head} {diverged}\n", encoding="ascii")

        self.assertEqual(
            git(
                self.repo,
                "merge-base",
                "--is-ancestor",
                diverged,
                self.head,
            ),
            "",
        )
        with self.assertRaisesRegex(ReviewError, "not an ancestor"):
            prepare_workspace(
                repo=self.repo,
                base_ref=diverged,
                head_ref=self.head,
            )
        self.assertFalse(workspace_runtime._review_root_for_source(self.repo).exists())

    def test_ancestor_check_ignores_stale_commit_graph(self) -> None:
        (self.repo / "middle.txt").write_text("middle\n", encoding="utf-8")
        git(self.repo, "add", "middle.txt")
        git(self.repo, "commit", "-m", "Middle")
        middle = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "final.txt").write_text("final\n", encoding="utf-8")
        git(self.repo, "add", "final.txt")
        git(self.repo, "commit", "-m", "Final")
        final = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "commit-graph", "write", "--reachable")

        middle_object = self.repo / ".git" / "objects" / middle[:2] / middle[2:]
        self.assertTrue(middle_object.is_file())
        middle_object.unlink()
        with_graph = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "merge-base",
                "--is-ancestor",
                self.base,
                final,
            ),
            check=False,
            env=test_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Git versions differ on whether a stale graph masks the missing object
        # or makes the default ancestry query fail closed immediately.
        if with_graph.returncode == 0:
            self.assertEqual(with_graph.stdout, b"")
        else:
            self.assertNotEqual(with_graph.returncode, 1)
            self.assertTrue(with_graph.stderr)
        without_graph = subprocess.run(
            (
                "git",
                "-c",
                "core.commitGraph=false",
                "-C",
                str(self.repo),
                "merge-base",
                "--is-ancestor",
                self.base,
                final,
            ),
            check=False,
            env=test_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(without_graph.returncode, 0)

        with self.assertRaisesRegex(
            ReviewError,
            "cannot verify that the frozen base is an ancestor of head",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=final,
            )
        self.assert_no_review_containers()

    def test_ancestor_check_fails_closed_for_git_query_errors(self) -> None:
        cases = (
            (
                "ancestor-query",
                (subprocess.CompletedProcess(("git",), 128, b"", b"bad object"),),
                "cannot verify that the frozen base is an ancestor of head",
            ),
            (
                "merge-base-query",
                (
                    subprocess.CompletedProcess(("git",), 1, b"", b""),
                    subprocess.CompletedProcess(("git",), 128, b"", b"missing object"),
                ),
                "cannot determine the merge base",
            ),
        )
        for name, responses, message in cases:
            with (
                self.subTest(name=name),
                mock.patch.object(
                    workspace_runtime,
                    "_run_sanitized_git_query",
                    side_effect=responses,
                ),
                self.assertRaisesRegex(ReviewError, message),
            ):
                workspace_runtime._require_ancestor_range(
                    git_view=self.repo / ".git",
                    object_directory=self.repo / ".git" / "objects",
                    base_sha="a" * 40,
                    head_sha="b" * 40,
                )

    def test_keyboard_interrupt_cleans_partial_review_container(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_private_review_repository",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        review_root = workspace_runtime._review_root_for_source(self.repo)
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_prepare_cleanup_failure_reports_retained_container(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_private_review_repository",
                side_effect=RuntimeError("prepare failed"),
            ),
            mock.patch(
                "review_runtime.workspace._remove_partial_container",
                return_value="permission denied",
            ),
            self.assertRaisesRegex(
                ReviewError,
                r"evidence retained at .*isolated-review.*permission denied",
            ),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        review_root = workspace_runtime._review_root_for_source(self.repo)
        retained = list(review_root.glob("isolated-review-*"))
        self.assertEqual(len(retained), 1)
        shutil.rmtree(retained[0])

    def test_container_handoff_signal_cleans_private_snapshot(self) -> None:
        restore_calls = 0

        def interrupt_first_restore(_mask):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                raise ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch(
                "review_runtime.workspace.restore_signal_mask",
                side_effect=interrupt_first_restore,
            ),
            self.assertRaises(ForwardedSignal),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        review_root = workspace_runtime._review_root_for_source(self.repo)
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_completed_workspace_is_owned_before_handoff_signal(self) -> None:
        restore_calls = 0
        captured = []

        def interrupt_ownership_restore(_mask):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 2:
                raise ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch(
                "review_runtime.workspace.restore_signal_mask",
                side_effect=interrupt_ownership_restore,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
            )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0].workspace_root.exists())
        cleanup_workspace(captured[0], keep_container=False)

    def test_partial_snapshot_cleanup_reports_second_signal(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_private_review_repository",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch(
                "review_runtime.workspace.block_forwarded_signals",
                side_effect=({signal.SIGTERM}, {signal.SIGTERM}),
            ),
            mock.patch(
                "review_runtime.workspace.consume_pending_forwarded_signal",
                return_value=signal.SIGQUIT,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertEqual(raised.exception.signum, signal.SIGQUIT)
        review_root = workspace_runtime._review_root_for_source(self.repo)
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_source_codex_tmp_symlink_rejects_clean_mode_without_touching_target(
        self,
    ) -> None:
        outside = pathlib.Path(self.temporary.name) / "outside"
        outside.mkdir()
        marker = outside / "user-content.txt"
        marker.write_text("keep\n", encoding="utf-8")
        (self.repo / ".codex-tmp").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ReviewError, "source repository has"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertTrue((self.repo / ".codex-tmp").is_symlink())
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertEqual(list(outside.iterdir()), [marker])
        self.assert_no_review_containers()

    def test_source_codex_tmp_directory_is_preserved_as_user_content(self) -> None:
        source_codex_tmp = self.repo / ".codex-tmp"
        source_codex_tmp.mkdir(mode=0o700)
        source_codex_tmp.chmod(0o770)
        marker = source_codex_tmp / "user-content.txt"
        marker.write_text("keep\n", encoding="utf-8")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)

        self.assertEqual(stat.S_IMODE(source_codex_tmp.stat().st_mode), 0o770)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertEqual(list(source_codex_tmp.iterdir()), [marker])
        self.assertFalse(review.container_dir.resolve().is_relative_to(self.repo))

    def test_preexisting_external_review_root_symlink_fails_closed(self) -> None:
        review_root = workspace_runtime._review_root_for_source(self.repo)
        review_root.parent.mkdir(mode=0o700, exist_ok=True)
        outside = pathlib.Path(self.temporary.name) / "outside-review-root"
        outside.mkdir()
        review_root.symlink_to(outside, target_is_directory=True)

        try:
            with self.assertRaisesRegex(
                ReviewError,
                "current-user-owned 0700 real directory",
            ):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                )
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            review_root.unlink(missing_ok=True)

    def test_preexisting_external_review_root_wrong_mode_fails_closed(self) -> None:
        review_root = workspace_runtime._review_root_for_source(self.repo)
        review_root.parent.mkdir(mode=0o700, exist_ok=True)
        review_root.mkdir(mode=0o700)
        review_root.chmod(0o770)

        try:
            with self.assertRaisesRegex(
                ReviewError,
                "current-user-owned 0700 real directory",
            ):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                )
            self.assertEqual(stat.S_IMODE(review_root.stat().st_mode), 0o770)
            self.assertEqual(list(review_root.iterdir()), [])
        finally:
            review_root.chmod(0o700)
            review_root.rmdir()

    def test_reserved_control_path_in_base_is_rejected(self) -> None:
        control = self.repo / ".codex-review"
        control.mkdir()
        (control / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        git(self.repo, "add", ".codex-review/tracked.txt")
        git(self.repo, "commit", "-m", "Add reserved path")
        reserved_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "-r", ".codex-review")
        git(self.repo, "commit", "-m", "Remove reserved path")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(ReviewError, "frozen base uses the reserved"):
            prepare_workspace(
                repo=self.repo,
                base_ref=reserved_base,
                head_ref=clean_head,
            )

    def test_protected_review_path_symlink_is_rejected(self) -> None:
        (self.repo / ".agents").symlink_to(".codex-review")
        git(self.repo, "add", ".agents")
        git(self.repo, "commit", "-m", "Add protected path alias")
        alias_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            "symlink for protected top-level path .agents",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=alias_head,
            )

        review_root = workspace_runtime._review_root_for_source(self.repo)
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_layout_rejects_source_local_fake_container(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        fake_container = (
            self.repo / ".codex-tmp" / "isolated-review-20260720-010203-deadbeef01"
        )
        fake_workspace = fake_container / "workspace"
        fake_control = fake_workspace / ".codex-review"
        forged = review.to_json()
        forged.update(
            {
                "container_dir": str(fake_container),
                "workspace_root": str(fake_workspace),
                "diff_file": str(fake_control / "review.diff"),
                "prompt_file": str(fake_control / "review.prompt"),
                "git_dir": str(fake_container / "review.git"),
            }
        )

        with self.assertRaisesRegex(
            ReviewError,
            "outside the helper-private review root",
        ):
            workspace_runtime.validate_workspace_layout(
                workspace_runtime.ReviewWorkspace.from_json(forged)
            )

    def test_external_workspace_rejects_symlinks_that_escape_frozen_root(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        (review.workspace_root / "escape").symlink_to(self.repo / "example.txt")
        with self.assertRaises(ReviewError):
            validate_external_workspace(review)

    def test_frozen_tree_rejects_sandbox_authentication_symlink(self) -> None:
        (self.repo / "leak").symlink_to("/config/.credentials.json")
        git(self.repo, "add", "leak")
        git(self.repo, "commit", "-m", "Add sandbox authentication symlink")
        link_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            "frozen Git tree symlink escapes workspace",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=link_head,
            )

    def test_symlink_target_boundary_rejects_magic_and_transient_escape(self) -> None:
        cases = (
            (pathlib.PurePosixPath("leak"), "/proc/self/environ", False),
            (pathlib.PurePosixPath("leak"), "/proc/self/fd/3", False),
            (
                pathlib.PurePosixPath("a/x"),
                "../../workspace/file",
                False,
            ),
            (pathlib.PurePosixPath("a/x"), "../README.md", True),
            (pathlib.PurePosixPath("a/x"), "missing.md", True),
        )

        for link, target, expected in cases:
            with self.subTest(link=link, target=target):
                self.assertEqual(
                    symlink_target_stays_within_workspace(link, target),
                    expected,
                )

    def test_escaping_secret_symlink_target_is_redacted(self) -> None:
        secret = "sk-" + "A" * 40
        (self.repo / "artifact").symlink_to(pathlib.Path("../..") / secret)
        git(self.repo, "add", "artifact")
        git(self.repo, "commit", "-m", "Add escaping secret-shaped symlink")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            r"artifact -> <redacted symlink target>",
        ) as raised:
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=secret_head,
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_unchanged_sensitive_path_symlink_blocks_external_review(self) -> None:
        (self.repo / "public.txt").write_text("ordinary content\n", encoding="utf-8")
        credentials = self.repo / "fixtures"
        credentials.mkdir()
        (credentials / ".netrc").symlink_to("../public.txt")
        git(self.repo, "add", "public.txt", "fixtures/.netrc")
        git(self.repo, "commit", "-m", "Add credential-shaped symlink")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(ReviewError, r"fixtures/\.netrc.*credential-path"):
            validate_external_workspace(review)

    def test_unchanged_secret_in_path_name_blocks_external_review(self) -> None:
        secret = "sk-" + "A" * 40
        secret_path = self.repo / "fixtures" / secret
        secret_path.parent.mkdir()
        secret_path.write_text("ordinary content\n", encoding="utf-8")
        git(self.repo, "add", str(secret_path.relative_to(self.repo)))
        git(self.repo, "commit", "-m", "Add secret-shaped path")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(
            ReviewError,
            r"<redacted snapshot path>.*openai-key.*path-name",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_secret_in_sensitive_changed_path_is_redacted(self) -> None:
        secret = "sk-" + "A" * 40
        secret_path = self.repo / secret / ".netrc"
        secret_path.parent.mkdir()
        secret_path.write_text("ordinary content\n", encoding="utf-8")
        git(self.repo, "add", str(secret_path.relative_to(self.repo)))
        git(self.repo, "commit", "-m", "Add secret-bearing credential path")
        secret_head = git(self.repo, "rev-parse", "HEAD")
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=secret_head,
        )
        self.reviews.append(review)

        with self.assertRaisesRegex(
            ReviewError,
            r"<redacted changed path>.*openai-key.*changed-path-name",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_unchanged_secret_in_symlink_target_blocks_external_review(self) -> None:
        secret = "sk-" + "A" * 40
        (self.repo / "artifact").symlink_to(secret)
        git(self.repo, "add", "artifact")
        git(self.repo, "commit", "-m", "Add secret-shaped symlink target")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(
            ReviewError,
            r"artifact -> <redacted symlink target>.*openai-key.*symlink-target",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_secret_findings_escape_control_characters_in_snapshot_paths(self) -> None:
        secret = "AKIA" + "C" * 16
        file_name = "file\n\x1bname"
        symlink_name = "link\n\x1bname"
        (self.repo / file_name).write_text(secret + "\n", encoding="utf-8")
        (self.repo / symlink_name).symlink_to("sk-" + "D" * 40)
        git(self.repo, "add", file_name, symlink_name)
        git(self.repo, "commit", "-m", "Add control-character secret paths")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=secret_head,
        )
        self.reviews.append(review)

        with self.assertRaises(ReviewError) as raised:
            validate_external_workspace(review)

        diagnostic = str(raised.exception)
        self.assertNotIn("\n", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertIn("file\\x0a\\x1bname (aws-access-key)", diagnostic)
        self.assertIn(
            "link\\x0a\\x1bname -> <redacted symlink target>",
            diagnostic,
        )

    def test_deleted_binary_secret_is_detected_from_base_blob(self) -> None:
        secret = ("sk-" + "A" * 40).encode()
        binary = self.repo / "opaque.bin"
        binary.write_bytes(b"\0binary\0" + secret + b"\0")
        git(self.repo, "add", "opaque.bin")
        git(self.repo, "commit", "-m", "Add binary credential")
        secret_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "opaque.bin")
        git(self.repo, "commit", "-m", "Remove binary credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=secret_base,
            head_ref=clean_head,
        )
        self.reviews.append(review)
        findings = (
            review.workspace_root / ".codex-review/changed-blob-findings.z"
        ).read_bytes()
        self.assertNotIn(secret, findings)
        with self.assertRaisesRegex(ReviewError, "opaque.bin.*base-blob"):
            validate_external_workspace(review)

    def test_wip_deleting_secret_from_original_head_still_blocks_review(
        self,
    ) -> None:
        secret = ("sk-" + "A" * 40).encode()
        binary = self.repo / "opaque.bin"
        binary.write_bytes(b"\0binary\0" + secret + b"\0")
        git(self.repo, "add", "opaque.bin")
        git(self.repo, "commit", "-m", "Add binary credential")
        secret_head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "opaque.bin")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=secret_head,
            include_source_wip=True,
        )
        self.reviews.append(review)
        self.assertFalse((review.workspace_root / "opaque.bin").exists())

        with self.assertRaises(ReviewError) as raised:
            validate_external_workspace(review)

        diagnostic = str(raised.exception)
        self.assertIn("sensitive content preflight blocked external review", diagnostic)
        self.assertIn("opaque.bin", diagnostic)
        self.assertIn("openai-key", diagnostic)
        self.assertNotIn(secret.decode("ascii"), diagnostic)

    def test_oauth_refresh_token_is_detected_in_head_content(self) -> None:
        credential = pathlib.Path(self.temporary.name) / "oauth.json"
        credential.write_text(
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_file_secret_rule(credential), "generic-secret-assignment")

    def test_deleted_oauth_refresh_token_is_detected_from_base_blob(self) -> None:
        credential = self.repo / "oauth.json"
        credential.write_text(
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "oauth.json")
        git(self.repo, "commit", "-m", "Add OAuth credential")
        credential_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "oauth.json")
        git(self.repo, "commit", "-m", "Remove OAuth credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=credential_base,
            head_ref=clean_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(ReviewError, "oauth.json.*base-blob"):
            validate_external_workspace(review)

    def test_function_call_assignment_is_not_treated_as_literal_secret(self) -> None:
        source = pathlib.Path(self.temporary.name) / "source.py"
        source.write_text(
            "password = load_password_from_keyring()\n",
            encoding="utf-8",
        )
        self.assertIsNone(_file_secret_rule(source))

    def test_all_env_suffix_files_are_sensitive_paths(self) -> None:
        self.assertEqual(_sensitive_path_rule("config.env"), "environment-file")
        self.assertEqual(_sensitive_path_rule("deploy/prod.env"), "environment-file")
        self.assertIsNone(_sensitive_path_rule(".env.example"))

    def test_nested_oauth_token_file_is_a_sensitive_path(self) -> None:
        self.assertEqual(
            _sensitive_path_rule("fixtures/google/token.json"),
            "credential-path",
        )

    def test_snapshot_does_not_execute_repo_hooks_filters_or_external_diff(
        self,
    ) -> None:
        marker_root = pathlib.Path(self.temporary.name) / "markers"
        marker_root.mkdir()
        hooks_dir = pathlib.Path(self.temporary.name) / "hooks"
        hooks_dir.mkdir()
        hook_marker = marker_root / "hook"
        filter_marker = marker_root / "filter"
        diff_marker = marker_root / "diff"

        hook = hooks_dir / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{hook_marker}'\n", encoding="utf-8")
        hook.chmod(0o755)
        filter_script = pathlib.Path(self.temporary.name) / "filter.sh"
        filter_script.write_text(
            f"#!/bin/sh\ntouch '{filter_marker}'\ncat\n",
            encoding="utf-8",
        )
        filter_script.chmod(0o755)
        diff_script = pathlib.Path(self.temporary.name) / "diff.sh"
        diff_script.write_text(
            f"#!/bin/sh\ntouch '{diff_marker}'\n",
            encoding="utf-8",
        )
        diff_script.chmod(0o755)

        git(self.repo, "config", "core.hooksPath", str(hooks_dir))
        git(self.repo, "config", "filter.evil.smudge", str(filter_script))
        git(self.repo, "config", "diff.external", str(diff_script))
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        self.assertFalse(hook_marker.exists())
        self.assertFalse(filter_marker.exists())
        self.assertFalse(diff_marker.exists())

    def test_snapshot_uses_raw_blobs_despite_archive_export_attributes(self) -> None:
        attributes = self.repo / ".gitattributes"
        attributes.write_text(
            attributes.read_text(encoding="utf-8")
            + "hidden.txt export-ignore\n"
            + "substituted.txt export-subst\n",
            encoding="utf-8",
        )
        (self.repo / "hidden.txt").write_text("still tracked\n", encoding="utf-8")
        raw_substitution = "$Format:%H$\n"
        (self.repo / "substituted.txt").write_text(
            raw_substitution,
            encoding="utf-8",
        )
        git(
            self.repo,
            "add",
            ".gitattributes",
            "hidden.txt",
            "substituted.txt",
        )
        git(self.repo, "commit", "-m", "Add export attributes")
        export_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=export_head,
        )
        self.reviews.append(review)
        self.assertEqual(
            (review.workspace_root / "hidden.txt").read_text(encoding="utf-8"),
            "still tracked\n",
        )
        self.assertEqual(
            (review.workspace_root / "substituted.txt").read_text(encoding="utf-8"),
            raw_substitution,
        )

    def test_prepare_supports_sha256_repositories(self) -> None:
        sha256_repo = pathlib.Path(self.temporary.name) / "sha256-repo"
        subprocess.run(
            (
                "git",
                "init",
                "--object-format=sha256",
                "-b",
                "master",
                str(sha256_repo),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(sha256_repo, "config", "user.name", "Review Test")
        git(sha256_repo, "config", "user.email", "review@example.com")
        git(sha256_repo, "config", "commit.gpgsign", "false")
        (sha256_repo / ".gitignore").write_text(
            ".codex-tmp/\n",
            encoding="utf-8",
        )
        content = sha256_repo / "content.txt"
        content.write_text("base\n", encoding="utf-8")
        git(sha256_repo, "add", ".gitignore", "content.txt")
        git(sha256_repo, "commit", "-m", "Initial")
        base = git(sha256_repo, "rev-parse", "HEAD")
        content.write_text("base\nhead\n", encoding="utf-8")
        git(sha256_repo, "add", "content.txt")
        git(sha256_repo, "commit", "-m", "Update")
        head = git(sha256_repo, "rev-parse", "HEAD")
        self.assertEqual(len(head), 64)
        content.write_text("base\nhead\nwip\n", encoding="utf-8")
        (sha256_repo / "untracked.txt").write_text(
            "sha256 WIP\n",
            encoding="utf-8",
        )

        review = prepare_workspace(
            repo=sha256_repo,
            base_ref=base,
            head_ref=head,
            include_source_wip=True,
        )
        self.reviews.append(review)
        self.assertEqual(review.head_ref, head)
        self.assertEqual(
            (review.workspace_root / "content.txt").read_text(encoding="utf-8"),
            "base\nhead\nwip\n",
        )
        self.assertEqual(
            (review.workspace_root / "untracked.txt").read_text(encoding="utf-8"),
            "sha256 WIP\n",
        )
        self.assertIn("+head", review.diff_file.read_text(encoding="utf-8"))
        self.assertIn("+wip", review.diff_file.read_text(encoding="utf-8"))
        self.assertIsNone(cleanup_workspace(review, keep_container=False))
        self.reviews.remove(review)
        workspace_runtime._review_root_for_source(sha256_repo).rmdir()


if __name__ == "__main__":
    unittest.main()
