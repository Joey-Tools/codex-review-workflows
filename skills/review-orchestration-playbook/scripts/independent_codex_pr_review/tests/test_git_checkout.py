from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest import mock

import review_supervisor.gitraw as gitraw

from review_supervisor.checkout import (
    RawMaterializer,
    probe_name_semantics,
    read_and_validate_symlink_graphs,
    validate_namespaces,
)
from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    MAX_EVIDENCE_PRIMARY_BYTES,
    MAX_SYMLINK_BYTES,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.errors import SupervisorError
from review_supervisor.gitraw import (
    BOUND_GIT_DEVELOPER_DIR_ENV,
    BOUND_GIT_EXECUTABLE_ENV,
    BOUND_GIT_EXEC_PATH_ENV,
    BOUND_GIT_RECEIPT_ENV,
    BOUND_GIT_TMPDIR_ENV,
    CatFileBatch,
    GitProcessClosureUnproven,
    RepositoryInfo,
    _parse_tree_record,
    add_detached_worktree,
    authenticated_range_manifests,
    bound_git_environment,
    check_attributes,
    create_sanitized_view,
    enumerate_tree,
    enumerate_registration,
    initialize_index,
    inspect_repository,
    object_digest,
    remove_both_present_worktree,
    remove_sanitized_view,
    revalidate_git_control,
    retry_git_process_closure,
    sanitized_git_environment,
    selected_git_executable,
    verify_worktree_absent,
)
from review_supervisor.ledger import (
    acquire_retention_lease,
    open_attempt_lease,
    read_bound_attempt_state,
)
from review_supervisor.models import HelperCustody, Identity, TreeEntry
from review_supervisor.process import (
    process_start_identity,
    signal_anchored_group,
    wait_terminal,
)
from review_supervisor.runtime import _cleanup_worktree, _registration_json
from review_supervisor.secureio import (
    canonical_json,
    identity_from_stat,
    rename_exchange,
    sha256_bytes,
)

from tests.support import (
    bind_attempt_state,
    build_helper_fixture,
    owned_temporary_directory,
)


GIT = pathlib.Path(selected_git_executable())
FIXTURE_PROCESS_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
FIXTURE_PROCESS_STDERR_LIMIT_BYTES = 8 * 1024 * 1024


def _run_fixture_process(
    argv: tuple[str, ...],
    *,
    cwd: pathlib.Path,
    timeout: float,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    returncode, stdout, stderr = gitraw.run_bounded(
        argv,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        stdout_limit=FIXTURE_PROCESS_STDOUT_LIMIT_BYTES,
        stderr_limit=FIXTURE_PROCESS_STDERR_LIMIT_BYTES,
    )
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def _git(repo: pathlib.Path, *arguments: str) -> bytes:
    completed = _run_fixture_process(
        (str(GIT), "-C", str(repo), *arguments),
        cwd=repo,
        timeout=10,
        environment=bound_git_environment(),
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout.strip()


def _init_repository(
    repo: pathlib.Path,
    *,
    object_format: str,
    timeout: float = 10,
) -> subprocess.CompletedProcess[bytes]:
    arguments = [str(GIT), "init", "-q"]
    if object_format != "sha1":
        arguments.append(f"--object-format={object_format}")
    arguments.append(str(repo))
    return _run_fixture_process(
        tuple(arguments),
        cwd=repo.parent,
        timeout=timeout,
        environment=bound_git_environment(),
    )


def _build_repository(
    root: pathlib.Path,
    *,
    object_format: str = "sha1",
) -> tuple[pathlib.Path, str, str]:
    repo = root / "repo"
    repo.mkdir(mode=0o700)
    initialized = _init_repository(repo, object_format=object_format)
    if initialized.returncode != 0:
        raise AssertionError(initialized.stderr.decode("utf-8", "replace"))
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / "base.txt").write_bytes(b"base\n")
    _git(repo, "add", "--", "base.txt")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").decode("ascii")

    (repo / "nested").mkdir()
    (repo / "nested" / "data.txt").write_bytes(b"raw object bytes\n")
    executable = repo / "tool.sh"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    (repo / ".gitattributes").write_bytes(b"*.txt -filter -working-tree-encoding\n")
    os.symlink("nested/data.txt", repo / "data-link")
    _git(
        repo,
        "add",
        "--",
        ".gitattributes",
        "nested/data.txt",
        "tool.sh",
        "data-link",
    )
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD").decode("ascii")
    return repo, base, head


def _protocol_batch(response: bytes) -> tuple[CatFileBatch, int]:
    request_reader, request_writer = os.pipe()
    stdout_reader, stdout_writer = os.pipe()
    stderr_reader, stderr_writer = os.pipe()
    if os.write(stdout_writer, response) != len(response):
        raise AssertionError("protocol fixture response write was partial")
    os.close(stdout_writer)
    os.close(stderr_writer)
    batch = CatFileBatch.__new__(CatFileBatch)
    batch.info = RepositoryInfo(
        repo=pathlib.Path("/unused/repo"),
        common_git_dir=pathlib.Path("/unused/repo/.git"),
        object_directory=pathlib.Path("/unused/repo/.git/objects"),
        object_directory_identity=Identity(0, 0, 0o40700, 1, 0, 0),
        object_format="sha1",
        object_hex_length=40,
        base_sha="1" * 40,
        head_sha="2" * 40,
        git_executable=str(GIT),
    )
    batch.process = SimpleNamespace(
        stdin=os.fdopen(request_writer, "wb", buffering=0),
        stdout=os.fdopen(stdout_reader, "rb", buffering=0),
        stderr=os.fdopen(stderr_reader, "rb", buffering=0),
        poll=lambda: 0,
        returncode=0,
    )
    batch.process_group = None
    batch.group_anchor = None
    batch.requests = 0
    batch.closed = False
    batch.stderr = bytearray()
    batch._control_parent = None
    batch.control = None
    return batch, request_reader


def _close_protocol_batch(batch: CatFileBatch, request_reader: int) -> None:
    for stream in (
        batch.process.stdin,
        batch.process.stdout,
        batch.process.stderr,
    ):
        if not stream.closed:
            stream.close()
    os.close(request_reader)


def _scripted_batch(root: pathlib.Path, script: bytes) -> CatFileBatch:
    repo = root / "repo"
    repo.mkdir(mode=0o700)
    object_directory = repo / ".git" / "objects"
    object_directory.mkdir(mode=0o700, parents=True)
    executable = root / "fake-git"
    executable.write_bytes(script)
    executable.chmod(0o700)
    return CatFileBatch(
        RepositoryInfo(
            repo=repo,
            common_git_dir=repo / ".git",
            object_directory=object_directory,
            object_directory_identity=identity_from_stat(os.stat(object_directory)),
            object_format="sha1",
            object_hex_length=40,
            base_sha="1" * 40,
            head_sha="2" * 40,
            git_executable=str(executable),
        )
    )


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_exit(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_exists(pid):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _wait_for_pid_record(
    path: pathlib.Path,
    *,
    field_count: int,
    timeout: float,
) -> tuple[int, ...]:
    deadline = time.monotonic() + timeout
    while True:
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            payload = b""
        if len(payload) > 128:
            raise AssertionError("fixture PID record exceeded its byte bound")
        if payload.endswith(b"\n"):
            fields = payload[:-1].split()
            if (
                len(fields) == field_count
                and all(field.isdigit() for field in fields)
                and all(int(field) > 0 for field in fields)
            ):
                return tuple(int(field) for field in fields)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("fixture PID record was not published completely")
        time.sleep(min(0.01, remaining))


def _force_cleanup_batch(batch: CatFileBatch) -> None:
    group_anchor = getattr(batch, "group_anchor", None)
    if group_anchor is not None:
        try:
            signal_anchored_group(group_anchor, signal.SIGKILL)
        except (ChildProcessError, PermissionError):
            pass
    try:
        batch.process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    for stream in (
        batch.process.stdin,
        batch.process.stdout,
        batch.process.stderr,
    ):
        if stream is not None and not stream.closed:
            stream.close()


def _kill_verified_process(pid: int, start_identity: str) -> None:
    try:
        current_identity = process_start_identity(pid)
    except (OSError, ValueError):
        return
    if current_identity != start_identity:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class RawGitProtocolTests(unittest.TestCase):
    def test_group_cleanup_requires_stable_empty_observations(self) -> None:
        anchor = SimpleNamespace(pid=101, pgid=101)
        with (
            mock.patch.object(
                gitraw,
                "anchored_group_members",
                side_effect=((101,), (101, 202), (101,), (101,)),
            ) as group_members,
            mock.patch.object(gitraw, "signal_anchored_group") as signal_group,
            mock.patch.object(gitraw.time, "sleep"),
        ):
            gitraw._wait_anchored_group_without_other_members(
                anchor,
                deadline=time.monotonic() + 1.0,
            )

        self.assertEqual(group_members.call_count, 4)
        signal_group.assert_called_once_with(anchor, signal.SIGKILL)

    def test_repository_inspection_preserves_unproven_git_closure(self) -> None:
        process = SimpleNamespace(
            pid=123,
            returncode=0,
            stdin=None,
            stdout=None,
            stderr=None,
        )
        failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        with owned_temporary_directory("git-inspection-closure-gap-") as root:
            repo, _, _ = _build_repository(root)
            with (
                mock.patch.object(
                    gitraw,
                    "_preflight_local_git_config",
                    return_value=(repo / ".git", "sha1"),
                ),
                mock.patch.object(gitraw, "run_bounded", side_effect=failure),
                self.assertRaises(GitProcessClosureUnproven) as raised,
            ):
                inspect_repository(
                    repo=repo,
                    base_sha="a" * 40,
                    head_sha="b" * 40,
                    git_executable=str(GIT),
                    temporary_control_parent=root,
                )
            self.assertEqual(len(failure.retained_cleanup_paths), 1)
            retained_parent = failure.retained_cleanup_paths[0]
            self.assertEqual(retained_parent.parent, root)
            self.assertTrue(retained_parent.is_dir())
            self.assertTrue(retry_git_process_closure(failure))
            self.assertFalse(retained_parent.exists())
        self.assertIs(raised.exception, failure)

    def test_repository_inspection_rejects_local_includes_before_git(self) -> None:
        directives = (
            ("include.path", "../outside.config"),
            ("includeIf.gitdir:/tmp/**.path", "../outside.config"),
        )
        for key, value in directives:
            with (
                self.subTest(key=key),
                owned_temporary_directory("git-local-include-") as root,
            ):
                repo, base, head = _build_repository(root)
                outside = root / "outside.config"
                outside.write_bytes(b"[core]\n\tfsmonitor = /definitely/not/executed\n")
                outside.chmod(0o000)
                try:
                    _git(repo, "config", "--local", "--add", key, value)
                    with (
                        mock.patch.object(gitraw, "run_bounded") as run_git,
                        self.assertRaises(SupervisorError) as raised,
                    ):
                        inspect_repository(
                            repo=repo,
                            base_sha=base,
                            head_sha=head,
                            git_executable=str(GIT),
                        )
                    run_git.assert_not_called()
                    self.assertEqual(
                        raised.exception.failure.stage,
                        "git-preflight",
                    )
                    self.assertEqual(
                        raised.exception.failure.code,
                        "git-config-mismatch",
                    )
                finally:
                    outside.chmod(0o600)

        for case, relative_path, content in (
            (
                "bom-common-config",
                pathlib.Path("config"),
                b"\xef\xbb\xbf[include]\n\tpath = ../outside.config\n",
            ),
            (
                "worktree-config",
                pathlib.Path("config.worktree"),
                b'[includeIf "gitdir:/tmp/**"]\n\tpath = ../outside.config\n',
            ),
        ):
            with (
                self.subTest(case=case),
                owned_temporary_directory(f"git-local-include-{case}-") as root,
            ):
                repo, base, head = _build_repository(root)
                config_path = repo / ".git" / relative_path
                config_path.write_bytes(content)
                config_path.chmod(0o600)
                with (
                    mock.patch.object(gitraw, "run_bounded") as run_git,
                    self.assertRaises(SupervisorError) as raised,
                ):
                    inspect_repository(
                        repo=repo,
                        base_sha=base,
                        head_sha=head,
                        git_executable=str(GIT),
                    )
                run_git.assert_not_called()
                self.assertEqual(raised.exception.failure.stage, "git-preflight")
                self.assertEqual(raised.exception.failure.code, "git-config-mismatch")

    def test_source_config_injection_after_preflight_is_never_consumed(self) -> None:
        with owned_temporary_directory("git-config-private-view-") as root:
            repo, base, head = _build_repository(root)
            config = repo / ".git" / "config"
            original = config.read_bytes()
            injected = b"[include]\n\tpath = /definitely/unreadable/codex.config\n"
            original_run = gitraw.run_bounded
            injected_during_git = False

            def run_with_source_injection(
                *args: object,
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                nonlocal injected_during_git
                if not injected_during_git:
                    injected_during_git = True
                    replacement = config.with_name("config.injected")
                    replacement.write_bytes(injected)
                    replacement.chmod(0o600)
                    os.replace(replacement, config)
                return original_run(*args, **kwargs)

            try:
                with mock.patch(
                    "review_supervisor.gitraw.run_bounded",
                    side_effect=run_with_source_injection,
                ):
                    info = inspect_repository(
                        repo=repo,
                        base_sha=base,
                        head_sha=head,
                        git_executable=str(GIT),
                    )
                    manifest = enumerate_tree(info, head)
                self.assertTrue(injected_during_git)
                self.assertGreater(manifest.entry_count, 0)
            finally:
                config.write_bytes(original)
                config.chmod(0o600)

    def test_actual_linked_worktree_config_is_audited_without_git(self) -> None:
        with owned_temporary_directory("git-linked-config-") as root:
            repo, _, head = _build_repository(root)
            linked = root / "linked"
            _git(repo, "config", "extensions.worktreeConfig", "true")
            _git(
                repo,
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                str(linked),
                head,
            )
            _git(
                linked,
                "config",
                "--worktree",
                "include.path",
                "/untrusted/linked-worktree.config",
            )
            with (
                mock.patch.object(gitraw, "run_bounded") as run_git,
                self.assertRaises(SupervisorError) as raised,
            ):
                inspect_repository(
                    repo=linked,
                    base_sha=head,
                    head_sha=head,
                    git_executable=str(GIT),
                )
            run_git.assert_not_called()
            self.assertEqual(raised.exception.failure.code, "git-config-mismatch")

    def test_linked_worktree_config_aba_during_git_is_never_consumed(
        self,
    ) -> None:
        with owned_temporary_directory("git-linked-config-aba-") as root:
            repo, _, head = _build_repository(root)
            linked = root / "linked"
            _git(repo, "config", "extensions.worktreeConfig", "true")
            _git(
                repo,
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                str(linked),
                head,
            )
            _git(
                linked,
                "config",
                "--worktree",
                "core.sparseCheckout",
                "false",
            )
            git_dir = gitraw._parse_gitdir_pointer(
                (linked / ".git").read_bytes(),
                repo=linked,
            )
            config = git_dir / "config.worktree"
            original = config.read_bytes()
            original_mode = stat.S_IMODE(config.stat().st_mode)
            injected = (
                b'[includeIf "gitdir:**"]\n\tpath = /untrusted/linked-worktree.config\n'
            )
            original_run = gitraw.run_bounded
            invocation_count = 0

            def run_with_linked_config_aba(
                *args: object,
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                nonlocal invocation_count
                invocation_count += 1
                malicious = config.with_name("config.worktree.malicious")
                malicious.write_bytes(injected)
                malicious.chmod(original_mode)
                os.replace(malicious, config)
                try:
                    return original_run(*args, **kwargs)
                finally:
                    safe = config.with_name("config.worktree.safe")
                    safe.write_bytes(original)
                    safe.chmod(original_mode)
                    os.replace(safe, config)

            try:
                with mock.patch(
                    "review_supervisor.gitraw.run_bounded",
                    side_effect=run_with_linked_config_aba,
                ):
                    info = inspect_repository(
                        repo=linked,
                        base_sha=head,
                        head_sha=head,
                        git_executable=str(GIT),
                    )
                    manifest = enumerate_tree(info, head)
                self.assertGreaterEqual(invocation_count, 4)
                self.assertGreater(manifest.entry_count, 0)
            finally:
                config.write_bytes(original)
                config.chmod(original_mode)

    def test_source_config_missing_and_unreadable_are_distinct(self) -> None:
        for case, expected_code in (
            ("missing", "git-config-missing"),
            ("unreadable", "git-config-unreadable"),
        ):
            with (
                self.subTest(case=case),
                owned_temporary_directory(f"git-config-{case}-") as root,
            ):
                repo, base, head = _build_repository(root)
                config = repo / ".git" / "config"
                if case == "missing":
                    config.unlink()
                else:
                    config.chmod(0o000)
                try:
                    with self.assertRaises(SupervisorError) as raised:
                        inspect_repository(
                            repo=repo,
                            base_sha=base,
                            head_sha=head,
                            git_executable=str(GIT),
                        )
                    self.assertEqual(raised.exception.failure.code, expected_code)
                finally:
                    if case == "unreadable":
                        config.chmod(0o600)

    def test_source_config_policy_and_revalidation_mismatch_are_distinct(
        self,
    ) -> None:
        for error_number, expected_code in (
            (errno.EPERM, "git-config-policy-mismatch"),
            (errno.ESTALE, "git-config-revalidation-mismatch"),
        ):
            with (
                self.subTest(error_number=error_number),
                owned_temporary_directory("git-config-mismatch-") as root,
            ):
                repo, base, head = _build_repository(root)
                with (
                    mock.patch.object(
                        gitraw,
                        "_preflight_local_git_config",
                        side_effect=OSError(error_number, "synthetic mismatch"),
                    ),
                    self.assertRaises(SupervisorError) as raised,
                ):
                    inspect_repository(
                        repo=repo,
                        base_sha=base,
                        head_sha=head,
                        git_executable=str(GIT),
                    )
                self.assertEqual(raised.exception.failure.code, expected_code)

    def test_private_git_control_property_scoped_revalidation(self) -> None:
        with owned_temporary_directory("git-control-binding-") as root:
            repo, base, head = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base,
                head_sha=head,
                git_executable=str(GIT),
            )

            bound_info = replace(
                info,
                temporary_control_parent=root,
                temporary_control_parent_identity=identity_from_stat(os.stat(root)),
            )
            root_stat = os.stat(root)
            root_syncs = 0
            original_fsync = os.fsync

            def track_root_fsync(descriptor: int) -> None:
                nonlocal root_syncs
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_dev == root_stat.st_dev
                    and metadata.st_ino == root_stat.st_ino
                ):
                    root_syncs += 1
                original_fsync(descriptor)

            with mock.patch(
                "review_supervisor.gitraw.os.fsync",
                side_effect=track_root_fsync,
            ):
                with gitraw.temporary_git_control(bound_info) as temporary:
                    retained_parent = temporary.path.parent
                    self.assertTrue(retained_parent.is_dir())
            self.assertFalse(retained_parent.exists())
            self.assertGreaterEqual(root_syncs, 2)

            retained_after_unfsynced_delete: pathlib.Path | None = None
            deletion_sync_failed = False

            def fail_first_deletion_sync(descriptor: int) -> None:
                nonlocal deletion_sync_failed
                metadata = os.fstat(descriptor)
                is_root = (
                    metadata.st_dev == root_stat.st_dev
                    and metadata.st_ino == root_stat.st_ino
                )
                if (
                    is_root
                    and retained_after_unfsynced_delete is not None
                    and not retained_after_unfsynced_delete.exists()
                    and not deletion_sync_failed
                ):
                    deletion_sync_failed = True
                    raise OSError("synthetic deletion fsync failure")
                original_fsync(descriptor)

            with mock.patch(
                "review_supervisor.gitraw.os.fsync",
                side_effect=fail_first_deletion_sync,
            ):
                with self.assertRaises(GitProcessClosureUnproven) as raised:
                    with gitraw.temporary_git_control(bound_info) as temporary:
                        retained_after_unfsynced_delete = temporary.path.parent
                deletion_failure = raised.exception
                self.assertTrue(deletion_sync_failed)
                retained_path = retained_after_unfsynced_delete
                self.assertIsNotNone(retained_path)
                assert retained_path is not None
                self.assertFalse(retained_path.exists())
                self.assertTrue(retry_git_process_closure(deletion_failure))

            published_modes: dict[str, int] = {}
            original_publish = gitraw.publish_bytes

            def track_publication(
                path: pathlib.Path,
                data: bytes,
                *,
                mode: int = 0o600,
            ):
                published_modes[path.name] = mode
                return original_publish(path, data, mode=mode)

            with mock.patch(
                "review_supervisor.gitraw.publish_bytes",
                side_effect=track_publication,
            ):
                atomic_mode = create_sanitized_view(
                    info,
                    root / "atomic-mode-control",
                )
            self.assertEqual(published_modes["config"], 0o400)
            remove_sanitized_view(atomic_mode.path)

            benign = create_sanitized_view(info, root / "benign-control")
            config = benign.path / "config"
            metadata = config.stat()
            os.utime(
                config,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
            )
            child = benign.path / "worktrees" / "transient"
            child.mkdir(mode=0o700)
            child.rmdir()
            revalidate_git_control(info, benign)
            original_read_binding = gitraw._read_git_control_binding_once
            materialization_checks = 0

            def transient_materialization(
                checked_info: RepositoryInfo,
                checked_view: pathlib.Path,
            ):
                nonlocal materialization_checks
                materialization_checks += 1
                if materialization_checks == 1:
                    raise OSError(
                        errno.ESTALE,
                        "synthetic File Provider metadata transition",
                    )
                return original_read_binding(checked_info, checked_view)

            with mock.patch(
                "review_supervisor.gitraw._read_git_control_binding_once",
                side_effect=transient_materialization,
            ):
                revalidate_git_control(info, benign)
            self.assertEqual(materialization_checks, 2)
            remove_sanitized_view(benign.path)

            replaced = create_sanitized_view(info, root / "replaced-control")
            replacement = replaced.path / "config.replacement"
            replacement.write_bytes((replaced.path / "config").read_bytes())
            replacement.chmod(0o400)
            os.replace(replacement, replaced.path / "config")
            with self.assertRaises(OSError) as raised:
                revalidate_git_control(info, replaced)
            self.assertEqual(raised.exception.errno, errno.ESTALE)
            remove_sanitized_view(replaced.path)

            mutated = create_sanitized_view(info, root / "mutated-control")
            (mutated.path / "config").chmod(0o600)
            (mutated.path / "config").write_bytes(
                b"[include]\n\tpath = /untrusted/config\n"
            )
            (mutated.path / "config").chmod(0o400)
            with self.assertRaisesRegex(ValueError, "content mismatched"):
                revalidate_git_control(info, mutated)
            (mutated.path / "config").chmod(0o600)
            (mutated.path / "config").write_bytes(gitraw._git_control_config(info))
            (mutated.path / "config").chmod(0o400)
            remove_sanitized_view(mutated.path)

            policy = create_sanitized_view(info, root / "policy-control")
            (policy.path / "config").chmod(0o644)
            with self.assertRaises(OSError) as raised:
                revalidate_git_control(info, policy)
            self.assertEqual(raised.exception.errno, errno.EPERM)
            (policy.path / "config").chmod(0o400)
            remove_sanitized_view(policy.path)

            unreadable = create_sanitized_view(info, root / "unreadable-control")
            (unreadable.path / "config").chmod(0o000)
            with self.assertRaises(OSError) as raised:
                revalidate_git_control(info, unreadable)
            self.assertIn(raised.exception.errno, {errno.EACCES, errno.EPERM})
            (unreadable.path / "config").chmod(0o400)
            remove_sanitized_view(unreadable.path)

            missing = create_sanitized_view(info, root / "missing-control")
            (missing.path / "config").unlink()
            with self.assertRaises(FileNotFoundError):
                revalidate_git_control(info, missing)
            (missing.path / "config").write_bytes(gitraw._git_control_config(info))
            (missing.path / "config").chmod(0o400)
            remove_sanitized_view(missing.path)

    def test_object_directory_child_churn_passes_replacement_and_policy_fail(
        self,
    ) -> None:
        with owned_temporary_directory("git-object-binding-") as root:
            repo, base, head = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base,
                head_sha=head,
                git_executable=str(GIT),
            )
            transient = info.object_directory / "transient-child"
            transient.mkdir()
            transient.rmdir()
            self.assertGreater(enumerate_tree(info, head).entry_count, 0)

            original_mode = stat.S_IMODE(info.object_directory.stat().st_mode)
            changed_mode = 0o700 if original_mode != 0o700 else 0o750
            info.object_directory.chmod(changed_mode)
            try:
                with self.assertRaises(OSError) as raised:
                    enumerate_tree(info, head)
                self.assertEqual(raised.exception.errno, errno.ESTALE)
            finally:
                info.object_directory.chmod(original_mode)

            original_objects = info.object_directory.with_name("objects.original")
            info.object_directory.rename(original_objects)
            info.object_directory.mkdir(mode=original_mode)
            try:
                with self.assertRaises(OSError) as raised:
                    enumerate_tree(info, head)
                self.assertEqual(raised.exception.errno, errno.ESTALE)
            finally:
                info.object_directory.rmdir()
                original_objects.rename(info.object_directory)

    def test_worktree_add_and_remove_ignore_mid_invocation_source_include(
        self,
    ) -> None:
        with owned_temporary_directory("git-worktree-config-isolation-") as root:
            repo, base, head = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base,
                head_sha=head,
                git_executable=str(GIT),
            )
            config = repo / ".git" / "config"
            original = config.read_bytes()
            injected = b'[includeIf "gitdir:**"]\n\tpath = /untrusted/config\n'
            original_run = gitraw.run_bounded
            invocation_count = 0

            def run_with_aba(
                *args: object,
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                nonlocal invocation_count
                invocation_count += 1
                config.write_bytes(injected)
                try:
                    return original_run(*args, **kwargs)
                finally:
                    config.write_bytes(original)

            checkout = root / "checkout"
            registration = None
            try:
                with mock.patch(
                    "review_supervisor.gitraw.run_bounded",
                    side_effect=run_with_aba,
                ):
                    registration = add_detached_worktree(info, checkout)
                    initialize_index(info, registration)
                    remove_both_present_worktree(info, registration)
                self.assertGreaterEqual(invocation_count, 4)
                verify_worktree_absent(info, checkout, registration.control)
                remove_sanitized_view(registration.control.path)
            finally:
                config.write_bytes(original)
                config.chmod(0o600)
                if (
                    registration is not None
                    and checkout.exists()
                    and registration.registration.exists()
                ):
                    remove_both_present_worktree(info, registration)

    def test_local_config_content_check_ignores_timestamps_but_rejects_mutation(
        self,
    ) -> None:
        with owned_temporary_directory("git-local-config-stability-") as root:
            repo, _, _ = _build_repository(root)
            config = repo / ".git" / "config"
            expected = config.read_bytes()
            parent_fd = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
            original_read = gitraw.read_fd_exact
            touched = False

            def read_then_touch(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal touched
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                if not touched:
                    touched = True
                    metadata = config.stat()
                    os.utime(
                        config,
                        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
                    )
                return content

            try:
                with mock.patch(
                    "review_supervisor.gitraw.read_fd_exact",
                    side_effect=read_then_touch,
                ):
                    observed = gitraw._read_optional_git_file(
                        parent_fd,
                        b"config",
                        max_bytes=gitraw.LOCAL_CONFIG_BYTES_LIMIT,
                    )
            finally:
                os.close(parent_fd)
            self.assertTrue(touched)
            self.assertEqual(observed, expected)

            config.chmod(0o666)
            parent_fd = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError) as raised:
                    gitraw._read_optional_git_file(
                        parent_fd,
                        b"config",
                        max_bytes=gitraw.LOCAL_CONFIG_BYTES_LIMIT,
                    )
            finally:
                os.close(parent_fd)
                config.chmod(0o644)
            self.assertEqual(raised.exception.errno, errno.EPERM)

            parent_fd = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
            mutated = b"#" + expected[1:]
            changed = False

            def read_then_mutate(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal changed
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                if not changed:
                    changed = True
                    write_fd = os.open(config, os.O_WRONLY | os.O_NOFOLLOW)
                    try:
                        os.pwrite(write_fd, mutated, 0)
                        os.fsync(write_fd)
                    finally:
                        os.close(write_fd)
                return content

            try:
                with (
                    mock.patch(
                        "review_supervisor.gitraw.read_fd_exact",
                        side_effect=read_then_mutate,
                    ),
                    self.assertRaises(OSError) as raised,
                ):
                    gitraw._read_optional_git_file(
                        parent_fd,
                        b"config",
                        max_bytes=gitraw.LOCAL_CONFIG_BYTES_LIMIT,
                    )
            finally:
                os.close(parent_fd)
            self.assertTrue(changed)
            self.assertEqual(raised.exception.errno, errno.ESTALE)

    def test_registration_scan_accepts_child_churn_but_rejects_replacement(
        self,
    ) -> None:
        original_open = os.open
        with owned_temporary_directory("git-registration-churn-") as root:
            registration = root / "registration"
            registration.mkdir(mode=0o700)
            child = registration / "child"
            child.mkdir(mode=0o700)
            registration_fd = original_open(
                registration,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            churned = False

            def open_after_child_churn(
                path: bytes | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal churned
                if path == b"child" and not churned:
                    churned = True
                    (child / "late-entry").mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with mock.patch(
                    "review_supervisor.gitraw.os.open",
                    side_effect=open_after_child_churn,
                ):
                    self.assertEqual(
                        gitraw.enumerate_registration_fd(registration_fd)[0],
                        2,
                    )
            finally:
                os.close(registration_fd)
            self.assertTrue(churned)

        with owned_temporary_directory("git-registration-replacement-") as root:
            registration = root / "registration"
            registration.mkdir(mode=0o700)
            child = registration / "child"
            child.mkdir(mode=0o700)
            moved = root / "original-child"
            registration_fd = original_open(
                registration,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            replaced = False

            def open_after_child_replacement(
                path: bytes | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if path == b"child" and not replaced:
                    replaced = True
                    child.rename(moved)
                    child.mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with (
                    mock.patch(
                        "review_supervisor.gitraw.os.open",
                        side_effect=open_after_child_replacement,
                    ),
                    self.assertRaisesRegex(OSError, "identity changed"),
                ):
                    gitraw.enumerate_registration_fd(registration_fd)
            finally:
                os.close(registration_fd)
            self.assertTrue(replaced)

    def test_materializer_preserves_unproven_git_closure(self) -> None:
        process = SimpleNamespace(pid=124)
        failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        materializer = RawMaterializer.__new__(RawMaterializer)
        materializer.root_fd = -1
        materializer.info = SimpleNamespace()
        with (
            mock.patch(
                "review_supervisor.checkout.CatFileBatch",
                side_effect=failure,
            ),
            self.assertRaises(GitProcessClosureUnproven) as raised,
        ):
            materializer.materialize()
        self.assertIs(raised.exception, failure)

    def test_materializer_retains_view_until_git_closure_is_proven(self) -> None:
        process = SimpleNamespace(pid=125)
        failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        materializer = RawMaterializer.__new__(RawMaterializer)
        materializer.root_fd = -1
        materializer.info = SimpleNamespace()
        materializer.head = SimpleNamespace(entries=())
        materializer.semantics = SimpleNamespace()
        materializer.graph = SimpleNamespace(head_targets={})
        materializer.directories = {}
        materializer.view_path = pathlib.Path("/tmp/synthetic-sanitized-view")
        materializer.registration = SimpleNamespace(
            worktree=pathlib.Path("/tmp/synthetic-worktree"),
            registration=pathlib.Path("/tmp/synthetic-registration"),
        )
        materializer._seal_diff = mock.Mock(return_value=(SimpleNamespace(), "digest"))
        materializer._verify_final_entry_set = mock.Mock()
        batch = mock.MagicMock()
        batch.__enter__.return_value = batch
        with (
            mock.patch(
                "review_supervisor.checkout.CatFileBatch",
                return_value=batch,
            ),
            mock.patch("review_supervisor.checkout._validate_symlink_graph"),
            mock.patch("review_supervisor.checkout.create_sanitized_view"),
            mock.patch(
                "review_supervisor.checkout.check_attributes",
                side_effect=failure,
            ),
            mock.patch("review_supervisor.checkout.os.lstat") as lstat,
            mock.patch(
                "review_supervisor.checkout.remove_sanitized_view"
            ) as remove_view,
            self.assertRaises(GitProcessClosureUnproven) as raised,
        ):
            materializer.materialize()

        self.assertIs(raised.exception, failure)
        lstat.assert_not_called()
        remove_view.assert_not_called()

    def test_tree_parser_enforces_symlink_target_size_limit(self) -> None:
        object_id = b"a" * 40
        accepted = _parse_tree_record(
            b"120000 blob "
            + object_id
            + b" "
            + str(MAX_SYMLINK_BYTES).encode("ascii")
            + b"\tlink",
            object_width=40,
        )
        self.assertEqual(accepted.size, MAX_SYMLINK_BYTES)

        with self.assertRaisesRegex(ValueError, "per-object limit"):
            _parse_tree_record(
                b"120000 blob "
                + object_id
                + b" "
                + str(MAX_SYMLINK_BYTES + 1).encode("ascii")
                + b"\tlink",
                object_width=40,
            )

    def test_cat_file_accepts_exact_blob_protocol(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        response = f"{object_id} blob {len(payload)}\n".encode() + payload + b"\n"
        batch, request_reader = _protocol_batch(response)
        try:
            captured = batch.read_blob(entry, capture=True)
            request = os.read(request_reader, 4096)
        finally:
            _close_protocol_batch(batch, request_reader)

        self.assertEqual(captured, payload)
        self.assertEqual(batch.requests, 1)
        self.assertEqual(request, object_id.encode("ascii") + b"\n")

    def test_cat_file_cleanup_failure_still_releases_signal_scope(self) -> None:
        batch, request_reader = _protocol_batch(b"")
        batch.process.pid = 123
        batch._cleanup_private_control = mock.Mock(
            side_effect=[
                OSError("synthetic control cleanup failure"),
                None,
            ]
        )
        batch._finish_signal_scope = mock.Mock()
        try:
            with self.assertRaises(GitProcessClosureUnproven) as raised:
                batch.abort()
            failure = raised.exception
            self.assertEqual(
                failure.process_receipt,
                {
                    "identity_status": "unbound",
                    "pid": 123,
                    "pgid": None,
                    "start_identity": None,
                },
            )
            batch._finish_signal_scope.assert_not_called()
            self.assertTrue(retry_git_process_closure(failure))
            failure.finish_signal_deferral(deliver=False)
            batch._finish_signal_scope.assert_called_once_with(deliver=False)
        finally:
            os.close(request_reader)

        parent = pathlib.Path("/synthetic/codex-git-control-cleanup")
        binding = SimpleNamespace(path=parent / "git")
        signal_scope = mock.Mock()
        cleanup = mock.Mock(
            side_effect=[
                OSError("synthetic temporary cleanup failure"),
                None,
            ]
        )
        with (
            mock.patch(
                "review_supervisor.gitraw.begin_bound_signal_deferral",
                return_value=signal_scope,
            ),
            mock.patch(
                "review_supervisor.gitraw._create_temporary_git_control",
                return_value=(parent, binding),
            ),
            mock.patch(
                "review_supervisor.gitraw._cleanup_temporary_git_control",
                cleanup,
            ),
        ):
            with self.assertRaises(GitProcessClosureUnproven) as raised:
                with gitraw.temporary_git_control(SimpleNamespace()):
                    pass
            temporary_failure = raised.exception
            self.assertEqual(
                temporary_failure.process_receipt,
                {
                    "identity_status": "not-applicable",
                    "pid": None,
                    "pgid": None,
                    "start_identity": None,
                },
            )
            self.assertEqual(
                temporary_failure.retained_cleanup_paths,
                (parent,),
            )
            signal_scope.finish.assert_not_called()
            self.assertTrue(retry_git_process_closure(temporary_failure))
            temporary_failure.finish_signal_deferral(deliver=False)
            signal_scope.finish.assert_called_once_with(deliver=False)

        constructor_parent = pathlib.Path("/synthetic/codex-git-control-constructor")
        constructor_cleanup = mock.Mock()
        constructor_failure = GitProcessClosureUnproven(
            None,
            None,
            OSError("synthetic constructor control cleanup failure"),
        )
        constructor_failure.add_post_closure_cleanup(
            constructor_cleanup,
            retained_path=constructor_parent,
        )
        constructor_scope = mock.Mock()

        def finish_constructor_scope(*, deliver: bool = True) -> None:
            if deliver:
                raise KeyboardInterrupt

        constructor_scope.finish.side_effect = finish_constructor_scope
        with (
            mock.patch(
                "review_supervisor.gitraw.begin_bound_signal_deferral",
                return_value=constructor_scope,
            ),
            mock.patch(
                "review_supervisor.gitraw._create_temporary_git_control",
                side_effect=constructor_failure,
            ),
            self.assertRaises(GitProcessClosureUnproven) as constructor_raised,
        ):
            CatFileBatch(SimpleNamespace())
        self.assertIs(constructor_raised.exception, constructor_failure)
        constructor_scope.finish.assert_not_called()
        self.assertTrue(retry_git_process_closure(constructor_failure))
        constructor_failure.finish_signal_deferral(deliver=False)
        constructor_scope.finish.assert_called_once_with(deliver=False)

    def test_cat_file_closure_retry_finishes_control_and_signal_cleanup(self) -> None:
        with owned_temporary_directory("cat-file-closure-finalizer-") as root:
            batch = _scripted_batch(root, b"#!/bin/sh\nexec /bin/sleep 30\n")
            retained_parent = batch._control_parent
            self.assertIsNotNone(retained_parent)
            signal_scope = mock.Mock()
            batch._signal_scope = signal_scope
            try:
                with (
                    mock.patch.object(
                        gitraw,
                        "_terminate_process",
                        side_effect=TimeoutError("synthetic cleanup timeout"),
                    ),
                    self.assertRaises(GitProcessClosureUnproven) as raised,
                ):
                    batch.abort()
                failure = raised.exception
                self.assertEqual(failure.retained_cleanup_paths, (retained_parent,))
                self.assertEqual(failure.process_receipt["identity_status"], "anchored")
                self.assertEqual(failure.process_receipt["pid"], batch.process.pid)
                self.assertEqual(failure.process_receipt["pgid"], batch.process.pid)
                self.assertTrue(retained_parent.is_dir())
                self.assertTrue(retry_git_process_closure(failure))
                self.assertFalse(retained_parent.exists())
                self.assertTrue(batch.closed)
                signal_scope.finish.assert_not_called()
                failure.finish_signal_deferral(deliver=False)
                signal_scope.finish.assert_called_once_with(deliver=False)
            finally:
                if batch.process.returncode is None:
                    _force_cleanup_batch(batch)

        failed_cleanup = GitProcessClosureUnproven(
            SimpleNamespace(
                pid=123,
                returncode=0,
                stdin=None,
                stdout=None,
                stderr=None,
            ),
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        cleanup = mock.Mock(side_effect=OSError("synthetic retained residue"))
        release_signal = mock.Mock()
        release_outer_signal = mock.Mock()
        retained = pathlib.Path("/synthetic/retained-control")
        failed_cleanup.add_post_closure_cleanup(cleanup, retained_path=retained)
        failed_cleanup.bind_signal_deferral_release(release_signal)
        failed_cleanup.bind_signal_deferral_release(release_outer_signal)
        with mock.patch.object(
            gitraw,
            "checkpoint_bound_signal_interrupt",
        ) as checkpoint:
            self.assertFalse(retry_git_process_closure(failed_cleanup))
        checkpoint.assert_not_called()
        release_signal.assert_not_called()
        release_outer_signal.assert_not_called()
        failed_cleanup.finish_signal_deferral(deliver=False)
        release_signal.assert_called_once_with(False)
        release_outer_signal.assert_called_once_with(False)
        self.assertEqual(
            failed_cleanup.process_receipt,
            {
                "identity_status": "unbound",
                "pid": 123,
                "pgid": None,
                "start_identity": None,
            },
        )
        self.assertEqual(failed_cleanup.retained_cleanup_paths, (retained,))

    def test_cat_file_close_is_bounded_on_output_and_open_pipes(self) -> None:
        scripts = (
            (
                "stderr-overflow",
                b"#!/bin/sh\nexec /usr/bin/head -c 4194304 /dev/zero >&2\n",
                OverflowError,
                2.0,
            ),
            (
                "open-pipes",
                b"#!/bin/sh\nexec /bin/sleep 30\n",
                TimeoutError,
                0.25,
            ),
            ("unexpected-stdout", b"#!/bin/sh\nprintf x\n", None, 2.0),
        )
        for label, script, expected_cause, close_timeout in scripts:
            with self.subTest(shutdown_case=label):
                with owned_temporary_directory("git-cat-file-close-") as root:
                    live_batch = _scripted_batch(root, script)
                    errors: list[BaseException] = []
                    worker: threading.Thread | None = None

                    def close_batch() -> None:
                        try:
                            live_batch.close()
                        except BaseException as error:
                            errors.append(error)

                    try:
                        with mock.patch(
                            "review_supervisor.gitraw.CAT_FILE_CLOSE_TIMEOUT_SECONDS",
                            close_timeout,
                        ):
                            worker = threading.Thread(
                                target=close_batch,
                                daemon=True,
                            )
                            worker.start()
                            worker.join(timeout=4)
                        blocked = worker.is_alive()
                        self.assertFalse(
                            blocked,
                            "cat-file shutdown blocked on one pipe",
                        )
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], ValueError)
                        self.assertIsNotNone(live_batch.process.poll())
                        for stream in (
                            live_batch.process.stdin,
                            live_batch.process.stdout,
                            live_batch.process.stderr,
                        ):
                            self.assertIsNotNone(stream)
                            self.assertTrue(stream.closed)
                        if expected_cause is None:
                            self.assertIsNone(errors[0].__cause__)
                        else:
                            self.assertIsInstance(
                                errors[0].__cause__,
                                expected_cause,
                            )
                    finally:
                        _force_cleanup_batch(live_batch)
                        if worker is not None and worker.is_alive():
                            worker.join(timeout=2)

        with owned_temporary_directory("git-cat-file-anchor-failure-") as root:
            cleaned: list[subprocess.Popen[bytes]] = []
            abort_session = gitraw._abort_unanchored_fresh_session

            def record_abort(process: subprocess.Popen[bytes]) -> None:
                cleaned.append(process)
                abort_session(process)

            with (
                mock.patch.object(
                    gitraw,
                    "process_start_identity",
                    side_effect=RuntimeError("synthetic identity failure"),
                ),
                mock.patch.object(
                    gitraw,
                    "_abort_unanchored_fresh_session",
                    side_effect=record_abort,
                ),
                self.assertRaisesRegex(RuntimeError, "identity failure"),
            ):
                _scripted_batch(root, b"#!/bin/sh\nexec /bin/sleep 30\n")

            self.assertEqual(len(cleaned), 1)
            self.assertIsNotNone(cleaned[0].returncode)
            for stream in (
                cleaned[0].stdin,
                cleaned[0].stdout,
                cleaned[0].stderr,
            ):
                self.assertIsNotNone(stream)
                self.assertTrue(stream.closed)

    def test_cat_file_read_is_bounded_on_stderr_flood_and_open_pipes(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        scripts = (
            (
                "stderr-overflow",
                b"#!/bin/sh\nIFS= read -r request\n"
                b"/usr/bin/head -c 4194304 /dev/zero >&2\n",
                OverflowError,
                2.0,
            ),
            (
                "open-pipes",
                b"#!/bin/sh\nIFS= read -r request\nexec /bin/sleep 30\n",
                TimeoutError,
                0.25,
            ),
        )
        for label, script, expected_error, read_timeout in scripts:
            with self.subTest(read_case=label):
                with owned_temporary_directory("git-cat-file-read-") as root:
                    live_batch = _scripted_batch(root, script)
                    self.assertEqual(
                        os.getpgid(live_batch.process.pid),
                        live_batch.process_group,
                    )
                    self.assertEqual(
                        os.getsid(live_batch.process.pid),
                        live_batch.process.pid,
                    )
                    errors: list[BaseException] = []
                    worker: threading.Thread | None = None

                    def read_blob() -> None:
                        try:
                            live_batch.read_blob(entry, capture=True)
                        except BaseException as error:
                            errors.append(error)

                    try:
                        started = time.monotonic()
                        with mock.patch(
                            "review_supervisor.gitraw.CAT_FILE_READ_TIMEOUT_SECONDS",
                            read_timeout,
                        ):
                            worker = threading.Thread(
                                target=read_blob,
                                daemon=True,
                            )
                            worker.start()
                            worker.join(timeout=4)
                        elapsed = time.monotonic() - started
                        blocked = worker.is_alive()

                        self.assertFalse(
                            blocked,
                            "cat-file read blocked on one pipe",
                        )
                        self.assertFalse(worker.is_alive())
                        self.assertLess(elapsed, 4)
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], expected_error)
                        self.assertTrue(live_batch.closed)
                        self.assertIsNotNone(live_batch.process.poll())
                        for stream in (
                            live_batch.process.stdin,
                            live_batch.process.stdout,
                            live_batch.process.stderr,
                        ):
                            self.assertIsNotNone(stream)
                            self.assertTrue(stream.closed)
                    finally:
                        _force_cleanup_batch(live_batch)
                        if worker is not None and worker.is_alive():
                            worker.join(timeout=2)

    def test_bounded_git_settles_same_group_child_after_successful_leader_exit(
        self,
    ) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
            b'while [ ! -f "$0.release" ]; do :; done\n'
            b"printf 'bounded-output\\n'\n"
            b"exit 0\n"
        )
        with owned_temporary_directory("bounded-git-descendant-") as root:
            executable = root / "fake-git"
            executable.write_bytes(script)
            executable.chmod(0o700)
            pid_path = root / "fake-git.pids"
            release_path = root / "fake-git.release"
            result: list[tuple[int, bytes, bytes]] = []
            errors: list[BaseException] = []
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            descendant_group: int | None = None

            def invoke() -> None:
                try:
                    result.append(
                        gitraw.run_bounded(
                            (str(executable),),
                            cwd=root,
                            environment=sanitized_git_environment(),
                            timeout=3,
                            stdout_limit=8192,
                            stderr_limit=8192,
                        )
                    )
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=invoke, daemon=True)
            try:
                worker.start()
                leader_pid, descendant_pid = _wait_for_pid_record(
                    pid_path,
                    field_count=2,
                    timeout=2,
                )
                descendant_identity = process_start_identity(descendant_pid)
                descendant_group = os.getpgid(descendant_pid)
                release_path.write_bytes(b"release\n")
                worker.join(timeout=5)

                self.assertFalse(worker.is_alive(), "bounded Git settlement blocked")
                self.assertEqual(errors, [])
                self.assertEqual(result, [(0, b"bounded-output\n", b"")])
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "bounded Git same-group child survived successful settlement",
                )
                self.assertEqual(descendant_group, leader_pid)
                self.assertFalse(_process_group_exists(leader_pid))
            finally:
                release_path.touch(exist_ok=True)
                worker.join(timeout=5)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)

    def test_fixture_git_timeout_reaps_same_group_descendants(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
            b"exec /bin/sleep 30\n"
        )
        with owned_temporary_directory("fixture-git-timeout-") as root:
            executable = root / "fake-git"
            executable.write_bytes(script)
            executable.chmod(0o700)
            pid_path = root / "fake-git.pids"
            errors: list[BaseException] = []
            results: list[subprocess.CompletedProcess[bytes]] = []
            leader_pid: int | None = None
            leader_identity: str | None = None
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            descendant_group: int | None = None

            def invoke() -> None:
                try:
                    results.append(
                        _init_repository(
                            root / "repo",
                            object_format="sha1",
                            timeout=0.5,
                        )
                    )
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=invoke, daemon=True)
            try:
                with mock.patch(f"{__name__}.GIT", executable):
                    worker.start()
                    leader_pid, descendant_pid = _wait_for_pid_record(
                        pid_path,
                        field_count=2,
                        timeout=2,
                    )
                    leader_identity = process_start_identity(leader_pid)
                    descendant_identity = process_start_identity(descendant_pid)
                    descendant_group = os.getpgid(descendant_pid)
                    worker.join(timeout=5)

                self.assertFalse(worker.is_alive(), "fixture Git timeout blocked")
                self.assertEqual(results, [])
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], TimeoutError)
                self.assertIn("bounded Git command timed out", str(errors[0]))
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "fixture Git timeout left its same-group descendant alive",
                )
                self.assertEqual(descendant_group, leader_pid)
                self.assertFalse(_process_group_exists(leader_pid))
            finally:
                worker.join(timeout=5)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)
                if leader_pid is not None and leader_identity is not None:
                    _kill_verified_process(leader_pid, leader_identity)

    def test_bounded_git_overflow_terminates_same_group_child(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
            b'while [ ! -f "$0.release" ]; do :; done\n'
            b"printf xx\n"
            b"exec /bin/sleep 30\n"
        )
        with owned_temporary_directory("bounded-git-overflow-") as root:
            executable = root / "fake-git"
            executable.write_bytes(script)
            executable.chmod(0o700)
            pid_path = root / "fake-git.pids"
            release_path = root / "fake-git.release"
            errors: list[BaseException] = []
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            descendant_group: int | None = None

            def invoke() -> None:
                try:
                    gitraw.run_bounded(
                        (str(executable),),
                        cwd=root,
                        environment=sanitized_git_environment(),
                        timeout=3,
                        stdout_limit=1,
                        stderr_limit=8192,
                    )
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=invoke, daemon=True)
            try:
                worker.start()
                leader_pid, descendant_pid = _wait_for_pid_record(
                    pid_path,
                    field_count=2,
                    timeout=2,
                )
                descendant_identity = process_start_identity(descendant_pid)
                descendant_group = os.getpgid(descendant_pid)
                release_path.write_bytes(b"release\n")
                worker.join(timeout=5)

                self.assertFalse(
                    worker.is_alive(), "bounded Git overflow cleanup blocked"
                )
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], OverflowError)
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "bounded Git same-group child survived overflow cleanup",
                )
                self.assertEqual(descendant_group, leader_pid)
                self.assertFalse(_process_group_exists(leader_pid))
            finally:
                release_path.touch(exist_ok=True)
                worker.join(timeout=5)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)

    def test_bounded_git_cleanup_failure_remains_closure_unproven(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
            b"printf xx\n"
            b"exec /bin/sleep 30\n"
        )
        with owned_temporary_directory("bounded-git-cleanup-gap-") as root:
            executable = root / "fake-git"
            executable.write_bytes(script)
            executable.chmod(0o700)
            pid_path = root / "fake-git.pids"
            leader_pid: int | None = None
            descendant_pid: int | None = None

            selector_type = selectors.DefaultSelector
            signal_scope = mock.Mock()

            class CloseFailingSelector:
                def __init__(self) -> None:
                    self.inner = selector_type()

                def __getattr__(self, name: str) -> object:
                    return getattr(self.inner, name)

                def close(self) -> None:
                    self.inner.close()
                    raise OSError("synthetic selector close failure")

            try:
                with (
                    mock.patch.object(
                        gitraw.selectors,
                        "DefaultSelector",
                        CloseFailingSelector,
                    ),
                    mock.patch.object(
                        gitraw,
                        "_terminate_process",
                        side_effect=TimeoutError("synthetic cleanup timeout"),
                    ),
                    mock.patch.object(
                        gitraw,
                        "begin_bound_signal_deferral",
                        return_value=signal_scope,
                    ),
                    self.assertRaises(GitProcessClosureUnproven) as raised,
                ):
                    gitraw.run_bounded(
                        (str(executable),),
                        cwd=root,
                        environment=sanitized_git_environment(),
                        timeout=3,
                        stdout_limit=1,
                        stderr_limit=8192,
                    )

                leader_pid, descendant_pid = _wait_for_pid_record(
                    pid_path,
                    field_count=2,
                    timeout=2,
                )
                self.assertEqual(raised.exception.pid, leader_pid)
                self.assertIsNotNone(raised.exception.group_anchor)
                self.assertIsInstance(raised.exception.__cause__, OverflowError)
                self.assertTrue(retry_git_process_closure(raised.exception))
                self.assertIsNotNone(raised.exception.process.returncode)
                signal_scope.finish.assert_not_called()
                raised.exception.finish_signal_deferral(deliver=False)
                signal_scope.finish.assert_called_once_with(deliver=False)
            finally:
                if leader_pid is not None:
                    try:
                        os.killpg(leader_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        raised.exception.process.wait(timeout=2)
                    except (NameError, subprocess.TimeoutExpired):
                        pass
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_bounded_git_selector_failure_terminates_same_group_child(
        self,
    ) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
            b"exec /bin/sleep 30\n"
        )
        with owned_temporary_directory("bounded-git-selector-") as root:
            executable = root / "fake-git"
            executable.write_bytes(script)
            executable.chmod(0o700)
            pid_path = root / "fake-git.pids"
            leader_pid: int | None = None
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            descendant_group: int | None = None

            def fail_after_child_ready() -> selectors.BaseSelector:
                nonlocal leader_pid
                nonlocal descendant_pid
                nonlocal descendant_identity
                nonlocal descendant_group
                leader_pid, descendant_pid = _wait_for_pid_record(
                    pid_path,
                    field_count=2,
                    timeout=2,
                )
                descendant_identity = process_start_identity(descendant_pid)
                descendant_group = os.getpgid(descendant_pid)
                raise RuntimeError("synthetic selector failure")

            try:
                with (
                    mock.patch.object(
                        gitraw.selectors,
                        "DefaultSelector",
                        side_effect=fail_after_child_ready,
                    ),
                    self.assertRaisesRegex(RuntimeError, "selector failure"),
                ):
                    gitraw.run_bounded(
                        (str(executable),),
                        cwd=root,
                        environment=sanitized_git_environment(),
                        timeout=3,
                        stdout_limit=8192,
                        stderr_limit=8192,
                    )

                assert leader_pid is not None
                assert descendant_pid is not None
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "bounded Git same-group child survived selector failure cleanup",
                )
                self.assertEqual(descendant_group, leader_pid)
                self.assertFalse(_process_group_exists(leader_pid))
            finally:
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)

            reaped = SimpleNamespace(
                pid=424_242,
                stdin=None,
                stdout=None,
                stderr=None,
            )
            with (
                mock.patch.object(
                    gitraw,
                    "terminal_status",
                    side_effect=ChildProcessError("synthetic reaped child"),
                ),
                mock.patch.object(gitraw.os, "killpg") as kill_group,
                self.assertRaisesRegex(ChildProcessError, "reaped child"),
            ):
                gitraw._abort_unanchored_fresh_session(reaped)
            kill_group.assert_not_called()

    def test_cat_file_close_terminates_descendant_after_leader_exit(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) &\n"
            b'printf \'%s\\n\' "$!" > "$0.child-pid"\n'
            b"exit 0\n"
        )
        with owned_temporary_directory("git-cat-file-descendant-") as root:
            live_batch = _scripted_batch(root, script)
            pid_path = root / "fake-git.child-pid"
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            worker: threading.Thread | None = None
            try:
                (descendant_pid,) = _wait_for_pid_record(
                    pid_path,
                    field_count=1,
                    timeout=2,
                )
                descendant_identity = process_start_identity(descendant_pid)
                wait_terminal(
                    live_batch.process.pid,
                    deadline=time.monotonic() + 2,
                )
                self.assertEqual(
                    os.getpgid(descendant_pid),
                    live_batch.process_group,
                )
                self.assertTrue(_process_exists(descendant_pid))
                errors: list[BaseException] = []

                def close_batch() -> None:
                    try:
                        live_batch.close()
                    except BaseException as error:
                        errors.append(error)

                started = time.monotonic()
                with mock.patch(
                    "review_supervisor.gitraw.CAT_FILE_CLOSE_TIMEOUT_SECONDS",
                    0.25,
                ):
                    worker = threading.Thread(target=close_batch, daemon=True)
                    worker.start()
                    worker.join(timeout=4)
                elapsed = time.monotonic() - started
                blocked = worker.is_alive()

                self.assertFalse(blocked, "cat-file descendant kept close blocked")
                self.assertFalse(worker.is_alive())
                self.assertLess(elapsed, 4)
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ValueError)
                self.assertIsInstance(errors[0].__cause__, TimeoutError)
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "cat-file background descendant survived group termination",
                )
            finally:
                _force_cleanup_batch(live_batch)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)
                if worker is not None and worker.is_alive():
                    worker.join(timeout=2)

    def test_cat_file_close_terminates_descendant_that_closed_its_pipes(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"/bin/sleep 30 </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s\\n\' "$!" > "$0.child-pid"\n'
            b"exit 0\n"
        )
        with owned_temporary_directory("git-cat-file-detached-descendant-") as root:
            live_batch = _scripted_batch(root, script)
            pid_path = root / "fake-git.child-pid"
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            try:
                (descendant_pid,) = _wait_for_pid_record(
                    pid_path,
                    field_count=1,
                    timeout=2,
                )
                descendant_identity = process_start_identity(descendant_pid)
                wait_terminal(
                    live_batch.process.pid,
                    deadline=time.monotonic() + 2,
                )
                self.assertEqual(
                    os.getpgid(descendant_pid),
                    live_batch.process_group,
                )
                self.assertTrue(_process_exists(descendant_pid))

                started = time.monotonic()
                live_batch.close()
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "cat-file detached descendant survived normal close",
                )
                self.assertFalse(_process_group_exists(live_batch.process_group))
            finally:
                _force_cleanup_batch(live_batch)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)

    def test_cat_file_rejects_oid_type_and_length_header_mismatches(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        headers = (
            f"{'0' * 40} blob {len(payload)}",
            f"{object_id} tree {len(payload)}",
            f"{object_id} blob {len(payload) + 1}",
        )
        for header in headers:
            with self.subTest(header=header):
                batch, request_reader = _protocol_batch(
                    header.encode() + b"\n" + payload + b"\n"
                )
                try:
                    with self.assertRaisesRegex(ValueError, "header mismatch"):
                        batch.read_blob(entry, capture=True)
                finally:
                    _close_protocol_batch(batch, request_reader)

    def test_cat_file_rejects_payload_length_delimiter_and_digest_mismatches(
        self,
    ) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        header = f"{object_id} blob {len(payload)}\n".encode()
        bad_digest_id = "0" * 40
        cases = (
            (header + payload[:-1], entry, "payload ended early"),
            (header + payload + b"\0", entry, "delimiter is invalid"),
            (
                f"{bad_digest_id} blob {len(payload)}\n".encode() + payload + b"\n",
                TreeEntry(
                    0o100644,
                    "blob",
                    bad_digest_id,
                    len(payload),
                    b"file",
                ),
                "digest mismatch",
            ),
        )
        for response, candidate, message in cases:
            with self.subTest(message=message):
                batch, request_reader = _protocol_batch(response)
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        batch.read_blob(candidate, capture=True)
                finally:
                    _close_protocol_batch(batch, request_reader)

    def test_cat_file_rehashes_commit_and_tree_payloads(self) -> None:
        payloads = {
            "commit": (
                b"tree " + b"1" * 40 + b"\n"
                b"author Fixture <fixture@example.invalid> 0 +0000\n"
                b"committer Fixture <fixture@example.invalid> 0 +0000\n"
                b"\nmessage\n"
            ),
            "tree": b"100644 file\0" + bytes.fromhex("2" * 40),
        }
        for object_type, payload in payloads.items():
            with self.subTest(object_type=object_type):
                digest = hashlib.sha1(
                    f"{object_type} {len(payload)}\0".encode() + payload
                ).hexdigest()
                replacement = bytearray(payload)
                replacement[-1] ^= 1
                batch, request_reader = _protocol_batch(
                    f"{digest} {object_type} {len(payload)}\n".encode()
                    + bytes(replacement)
                    + b"\n"
                )
                try:
                    with self.assertRaisesRegex(ValueError, "digest mismatch"):
                        batch.verify_object(
                            digest,
                            allowed_types=frozenset({"commit", "tree", "tag"}),
                            maximum_size=len(payload),
                            deadline=time.monotonic() + 2,
                        )
                finally:
                    _close_protocol_batch(batch, request_reader)

    def test_private_git_commands_disable_auxiliary_object_indexes(self) -> None:
        info = SimpleNamespace(git_executable=str(GIT))
        control = SimpleNamespace(path=pathlib.Path("/private/control"))
        argv = gitraw._git_control_argv(info, control, "rev-list", "HEAD")
        self.assertIn("core.commitGraph=false", argv)
        self.assertIn("core.multiPackIndex=false", argv)
        self.assertIn("pack.useBitmaps=false", argv)


@unittest.skipUnless(GIT.is_file(), "the selected Git executable is required")
class RawGitCheckoutTests(unittest.TestCase):
    def test_authenticated_range_rejects_commit_content_mismatch(self) -> None:
        with owned_temporary_directory("git-metadata-content-mismatch-") as root:
            repo, base, head = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base,
                head_sha=head,
                git_executable=str(GIT),
            )
            original_verify = CatFileBatch.verify_object

            def reject_head_commit(
                batch: CatFileBatch,
                object_id: str,
                *,
                allowed_types: frozenset[str],
                maximum_size: int,
                deadline: float,
            ) -> tuple[str, int]:
                if object_id == head:
                    raise ValueError("raw Git object digest mismatch")
                return original_verify(
                    batch,
                    object_id,
                    allowed_types=allowed_types,
                    maximum_size=maximum_size,
                    deadline=deadline,
                )

            with (
                mock.patch.object(
                    CatFileBatch,
                    "verify_object",
                    new=reject_head_commit,
                ),
                self.assertRaises(SupervisorError) as raised,
            ):
                authenticated_range_manifests(info)
            self.assertEqual(
                raised.exception.failure.code,
                "range-object-verification-failed",
            )

    def test_authenticated_range_rejects_ls_tree_aba_view(self) -> None:
        with owned_temporary_directory("git-metadata-ls-tree-aba-") as root:
            repo, base, head = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base,
                head_sha=head,
                git_executable=str(GIT),
            )
            original_run = gitraw.run_bounded
            substituted = False

            def run_with_substituted_head_tree(
                argv: tuple[str, ...],
                **kwargs: Any,
            ) -> tuple[int, bytes, bytes]:
                nonlocal substituted
                if "ls-tree" in argv and argv[-1] == head:
                    substituted = True
                    argv = (*argv[:-1], base)
                return original_run(argv, **kwargs)

            with (
                mock.patch.object(
                    gitraw,
                    "run_bounded",
                    side_effect=run_with_substituted_head_tree,
                ),
                self.assertRaises(SupervisorError) as raised,
            ):
                authenticated_range_manifests(info)
            self.assertTrue(substituted)
            self.assertEqual(
                raised.exception.failure.code,
                "range-tree-manifest-mismatch",
            )

    def test_worktree_cleanup_does_not_write_after_unproven_git_closure(
        self,
    ) -> None:
        process = SimpleNamespace(pid=125)
        failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        state = {
            "worktree_path": "/tmp/review-worktree",
            "checkout_parent_binding": {"path": "/tmp", "identity": {}},
            "common_git_dir_binding": {
                "path": "/tmp/repository.git",
                "identity": {},
            },
        }
        attempt_lease = SimpleNamespace(
            path=pathlib.Path("/tmp/attempt"),
            revalidate=mock.Mock(),
        )
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.open_absolute_directory_chain",
                side_effect=failure,
            ),
            mock.patch(
                "review_supervisor.runtime.retry_git_process_closure",
                return_value=False,
            ) as retry,
            mock.patch(
                "review_supervisor.runtime.read_bound_attempt_state"
            ) as read_state,
            mock.patch(
                "review_supervisor.runtime._manual_worktree_recovery"
            ) as recovery,
            self.assertRaises(GitProcessClosureUnproven) as raised,
        ):
            _cleanup_worktree(
                entrypoint=pathlib.Path("/tmp/entrypoint"),
                attempt=attempt_lease,
                state=state,
                state_digest="digest",
            )
        self.assertIs(raised.exception, failure)
        retry.assert_called_once_with(failure)
        read_state.assert_not_called()
        recovery.assert_not_called()

        retried_failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic retry cleanup"),
        )
        signal_release = mock.Mock()
        retried_failure.bind_signal_deferral_release(signal_release)
        recovered_state = {**state, "worktree_status": "manual-recovery-required"}
        expected = (recovered_state, "recovered-digest")
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.open_absolute_directory_chain",
                side_effect=retried_failure,
            ),
            mock.patch(
                "review_supervisor.runtime.retry_git_process_closure",
                return_value=True,
            ),
            mock.patch(
                "review_supervisor.runtime.require_direct_process_closure_proven",
            ),
            mock.patch(
                "review_supervisor.runtime.read_bound_attempt_state",
                return_value=(state, b"state", "disk-digest"),
            ),
            mock.patch(
                "review_supervisor.runtime._manual_worktree_recovery",
                return_value=expected,
            ) as recovery,
        ):
            result = _cleanup_worktree(
                entrypoint=pathlib.Path("/tmp/entrypoint"),
                attempt=attempt_lease,
                state=state,
                state_digest="digest",
            )
        self.assertEqual(result, expected)
        signal_release.assert_called_once_with(False)
        recovery.assert_called_once()

    def test_check_attributes_accepts_many_short_unspecified_paths(self) -> None:
        paths = tuple(f"p{index:03d}".encode("ascii") for index in range(200))
        output = b"".join(
            (
                path
                + b"\0filter\0unspecified\0"
                + path
                + b"\0working-tree-encoding\0unspecified\0"
            )
            for path in paths
        )
        info = SimpleNamespace(
            git_executable=str(GIT),
            common_git_dir=pathlib.Path("/repo/.git"),
        )
        registration = SimpleNamespace(
            registration=pathlib.Path("/repo/.git/worktrees/review"),
            worktree=pathlib.Path("/repo/review"),
        )

        def run_with_limit(
            *_args: object,
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            self.assertEqual(kwargs["stdout_limit"], len(output))
            return 0, output, b""

        with (
            mock.patch(
                "review_supervisor.gitraw.run_bounded",
                side_effect=run_with_limit,
            ),
            mock.patch(
                "review_supervisor.gitraw._view_environment",
                return_value=sanitized_git_environment(),
            ),
        ):
            check_attributes(
                info,
                registration,
                pathlib.Path("/repo/sanitized-view"),
                paths,
            )

    def test_runtime_cleanup_keeps_parent_descriptors_and_settles_exactly(self) -> None:
        with owned_temporary_directory("git-cleanup-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                git_executable=str(GIT),
            )
            checkout_parent = root / "checkouts"
            checkout_parent.mkdir(mode=0o700)
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt_id = f"1-{'d' * 32}"
            attempt = retention / f"attempt-{attempt_id}"
            attempt.mkdir(mode=0o700)
            control = create_sanitized_view(info, attempt / "git-control")
            worktree = checkout_parent / "review-fixture"
            registration = add_detached_worktree(
                info,
                worktree,
                control=control,
            )
            namespace = checkout_parent / ".review-control-fixture"
            namespace.mkdir(mode=0o700)
            try:
                initialize_index(info, registration)
                post_index_count, post_index_path_bytes = enumerate_registration(
                    registration.registration
                )
                self.assertGreaterEqual(post_index_count, registration.descendant_count)
                registration_value = _registration_json(registration)
                registration_value["descendant_count"] = post_index_count
                registration_value["descendant_path_bytes"] = post_index_path_bytes
                state = {
                    "schema_version": SCHEMA_VERSION,
                    "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                    "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                    "attempt_id": attempt_id,
                    "record_generation": 1,
                    "previous_record_sha256": None,
                    "phase": "reviewed",
                    "repo": str(repo),
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "git_executable": str(GIT),
                    "worktree_path": str(worktree),
                    "control_namespace": str(namespace),
                    "registration": registration_value,
                    "git_control_binding": registration_value["control"],
                    "worktree_status": "active",
                    "checkout_settlement": "outstanding",
                    "checkout_physical_remaining_by_fs": {"fixture": 1},
                    "cleanup_status": "clean",
                    "checkout_parent_binding": {
                        "path": str(checkout_parent),
                        "identity": identity_from_stat(
                            os.stat(checkout_parent)
                        ).to_json(),
                    },
                    "common_git_dir_binding": {
                        "path": str(info.common_git_dir),
                        "identity": identity_from_stat(
                            os.stat(info.common_git_dir)
                        ).to_json(),
                    },
                }
                bind_attempt_state(
                    state,
                    retention_root=retention,
                    attempt_dir=attempt,
                )
                state_path = attempt / "state.json"
                state_path.write_bytes(canonical_json(state))
                state_path.chmod(0o600)
                with acquire_retention_lease(
                    retention,
                    deadline=time.monotonic() + 5,
                ) as lease:
                    with open_attempt_lease(lease, attempt) as attempt_lease:
                        state, _, digest = read_bound_attempt_state(attempt_lease)
                        state, _ = _cleanup_worktree(
                            entrypoint=pathlib.Path(__file__).resolve().parent.parent
                            / "independent-codex-pr-review",
                            attempt=attempt_lease,
                            state=state,
                            state_digest=digest,
                        )
                self.assertEqual(state["checkout_settlement"], "exact")
                self.assertEqual(state["worktree_status"], "removed")
                self.assertFalse(worktree.exists())
                self.assertFalse(registration.registration.exists())
                self.assertFalse(namespace.exists())
                self.assertIsNone(state["retained_worktree"])
                self.assertTrue(
                    state["checkout_cleanup_evidence"]["exact_names_absent"]
                )
                self.assertEqual(
                    state["checkout_cleanup_evidence"]["branch"],
                    "both-present",
                )
            finally:
                if worktree.exists() and registration.registration.exists():
                    remove_both_present_worktree(info, registration)

    def test_cli_preflight_authenticates_without_creating_attempt(self) -> None:
        with owned_temporary_directory("preflight-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            fixture = build_helper_fixture(
                root,
                source_repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
            )
            retention = root / "retention"
            checkouts = root / "checkouts"
            entrypoint = (
                pathlib.Path(__file__).resolve().parent.parent
                / "independent-codex-pr-review"
            )
            completed = _run_fixture_process(
                (
                    sys.executable,
                    str(entrypoint),
                    "preflight",
                    "--helper-state",
                    str(fixture["state_dir"]),
                    "--repo",
                    str(repo),
                    "--base",
                    base_sha,
                    "--head",
                    head_sha,
                    "--pr-url",
                    "https://github.example/owner/repo/pull/1",
                    "--retention-root",
                    str(retention),
                    "--checkout-parent",
                    str(checkouts),
                    "--codex",
                    "/usr/bin/true",
                ),
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                timeout=30,
                environment={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "ready")
            self.assertEqual(
                payload["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT
            )
            self.assertIs(payload["named_lane_eligible"], False)
            self.assertEqual(payload["review_status"], "not-run")
            self.assertFalse(payload["created_attempt"])
            self.assertEqual(payload["review_range"], f"{base_sha}..{head_sha}")
            self.assertEqual(tuple(checkouts.iterdir()), ())
            self.assertEqual(
                tuple(path.name for path in retention.iterdir()),
                ("retention.lock",),
            )

    def test_cli_preflight_rejects_serialized_evidence_overflow_without_attempt(
        self,
    ) -> None:
        with owned_temporary_directory("preflight-escaped-evidence-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            fixture = build_helper_fixture(
                root,
                source_repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                primary_diff="界".encode() * (MAX_EVIDENCE_PRIMARY_BYTES // 3),
            )
            retention = root / "retention"
            checkouts = root / "checkouts"
            entrypoint = (
                pathlib.Path(__file__).resolve().parent.parent
                / "independent-codex-pr-review"
            )
            completed = _run_fixture_process(
                (
                    sys.executable,
                    str(entrypoint),
                    "preflight",
                    "--helper-state",
                    str(fixture["state_dir"]),
                    "--repo",
                    str(repo),
                    "--base",
                    base_sha,
                    "--head",
                    head_sha,
                    "--pr-url",
                    "https://github.example/owner/repo/pull/1",
                    "--retention-root",
                    str(retention),
                    "--checkout-parent",
                    str(checkouts),
                    "--codex",
                    "/usr/bin/true",
                ),
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                timeout=30,
                environment={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["overall_status"], "blocked")
            self.assertEqual(payload["failure_stage"], "evidence-admission")
            self.assertEqual(
                payload["failure_code"],
                "primary-evidence-size-invalid",
            )
            self.assertEqual(tuple(checkouts.iterdir()), ())
            self.assertEqual(
                tuple(path.name for path in retention.iterdir()),
                ("retention.lock",),
            )

    def test_cli_preflight_rejects_final_turn_record_overflow_without_attempt(
        self,
    ) -> None:
        with owned_temporary_directory("preflight-turn-record-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            fixture = build_helper_fixture(
                root,
                source_repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                primary_diff=b"\\" * 2_516_582,
            )
            retention = root / "retention"
            checkouts = root / "checkouts"
            entrypoint = (
                pathlib.Path(__file__).resolve().parent.parent
                / "independent-codex-pr-review"
            )
            completed = _run_fixture_process(
                (
                    sys.executable,
                    str(entrypoint),
                    "preflight",
                    "--helper-state",
                    str(fixture["state_dir"]),
                    "--repo",
                    str(repo),
                    "--base",
                    base_sha,
                    "--head",
                    head_sha,
                    "--pr-url",
                    "https://github.example/owner/repo/pull/1",
                    "--retention-root",
                    str(retention),
                    "--checkout-parent",
                    str(checkouts),
                    "--codex",
                    "/usr/bin/true",
                ),
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                timeout=30,
                environment={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["overall_status"], "blocked")
            self.assertEqual(payload["failure_stage"], "evidence-admission")
            self.assertEqual(
                payload["failure_code"],
                "primary-evidence-size-invalid",
            )
            self.assertEqual(tuple(checkouts.iterdir()), ())
            self.assertEqual(
                tuple(path.name for path in retention.iterdir()),
                ("retention.lock",),
            )

    def _assert_raw_detached_checkout_and_sealed_diff(
        self,
        root: pathlib.Path,
        *,
        object_format: str,
    ) -> None:
        repo, base_sha, head_sha = _build_repository(
            root,
            object_format=object_format,
        )
        info = inspect_repository(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            git_executable=str(GIT),
        )
        self.assertEqual(info.object_format, object_format)
        expected_hex_length = 64 if object_format == "sha256" else 40
        self.assertEqual(len(base_sha), expected_hex_length)
        self.assertEqual(len(head_sha), expected_hex_length)
        base, head = authenticated_range_manifests(info)
        self.assertEqual(
            tuple(entry.path for entry in head.entries),
            (
                b".gitattributes",
                b"base.txt",
                b"data-link",
                b"nested/data.txt",
                b"tool.sh",
            ),
        )
        self.assertTrue(any(entry.is_symlink for entry in head.entries))

        checkout = root / "checkout"
        registration = add_detached_worktree(info, checkout)
        source = root / "source.diff"
        source_content = b"diff --git a/base.txt b/base.txt\n+head\n"
        source.write_bytes(source_content)
        source.chmod(0o600)
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        namespace = root / "name-probe"
        namespace.mkdir(mode=0o700)
        materializer: RawMaterializer | None = None
        try:
            initialize_index(info, registration)
            semantics = probe_name_semantics(namespace)
            base_entries, head_entries = validate_namespaces(
                base,
                head,
                semantics=semantics,
                checkout_root=checkout,
            )
            graph = read_and_validate_symlink_graphs(
                info,
                base,
                head,
                base_entries=base_entries,
                head_entries=head_entries,
                semantics=semantics,
            )
            source_identity = identity_from_stat(os.fstat(source_fd))
            custody = HelperCustody(
                state_dir=str(root),
                state_identity=identity_from_stat(os.stat(root)),
                workspace_root=str(root),
                source_path=str(source),
                source_identity=source_identity,
                cleanup_lock_path=str(root / "unused.lock"),
                cleanup_lock_identity=source_identity,
                review_range=f"{base_sha}..{head_sha}",
                base_sha=base_sha,
                head_sha=head_sha,
                diff_length=len(source_content),
                diff_sha256=sha256_bytes(source_content),
                preflight_sha256="0" * 64,
                control_state_sha256="1" * 64,
            )
            materializer = RawMaterializer(
                info=info,
                registration=registration,
                base=base,
                head=head,
                semantics=semantics,
                graph=graph,
                source_fd=source_fd,
                custody=custody,
                deadline=time.monotonic() + 60,
                checkout_root_bound=1024 * 1024 * 1024,
                git_admin_bound=1024 * 1024 * 1024,
                view_path=root / "sanitized-git-view",
            )
            materializer.phase1()
            with mock.patch(
                "review_supervisor.checkout.rename_exchange",
                wraps=rename_exchange,
            ) as exchange:
                evidence = materializer.materialize()
            exchange.assert_called_once()
            self.assertEqual(
                evidence.sealed_diff_sha256,
                sha256_bytes(source_content),
            )
            self.assertEqual(
                (checkout / ".codex-review" / "review.diff").read_bytes(),
                source_content,
            )
            self.assertFalse((root / "sanitized-git-view").exists())
            self.assertEqual(os.readlink(checkout / "data-link"), "nested/data.txt")
        finally:
            if materializer is not None:
                materializer.close()
            os.close(source_fd)
            if checkout.exists() and registration.registration.exists():
                remove_both_present_worktree(info, registration)
            if namespace.exists():
                namespace.rmdir()
        verify_worktree_absent(info, checkout, registration.control)
        remove_sanitized_view(registration.control.path)

    def test_raw_detached_checkout_and_sealed_diff(self) -> None:
        with owned_temporary_directory("git-checkout-") as root:
            self._assert_raw_detached_checkout_and_sealed_diff(
                root,
                object_format="sha1",
            )

    def test_sha256_raw_view_check_attr_index_and_materialization(self) -> None:
        with owned_temporary_directory("git-sha256-checkout-") as root:
            support_probe = _init_repository(
                root / "sha256-support-probe",
                object_format="sha256",
            )
            if support_probe.returncode != 0:
                self.skipTest(
                    "git init --object-format=sha256 is unsupported: "
                    + support_probe.stderr.decode("utf-8", "replace").strip()
                )
            self.assertEqual(
                _git(
                    root / "sha256-support-probe", "rev-parse", "--show-object-format"
                ),
                b"sha256",
            )
            self._assert_raw_detached_checkout_and_sealed_diff(
                root,
                object_format="sha256",
            )

    def test_git_environment_disables_network_and_filters(self) -> None:
        environment = sanitized_git_environment()
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_LFS_SKIP_SMUDGE"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_PROTOCOL_FROM_USER"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
        self.assertEqual(environment["HOME"], "/var/empty")
        self.assertNotIn("GIT_CONFIG", environment)
        self.assertNotIn("XDG_CONFIG_HOME", environment)

    def test_bound_git_environment_is_closed_and_complete(self) -> None:
        values = {
            BOUND_GIT_EXECUTABLE_ENV: "/trusted/Xcode/usr/bin/git",
            BOUND_GIT_EXEC_PATH_ENV: "/trusted/Xcode/usr/libexec/git-core",
            BOUND_GIT_DEVELOPER_DIR_ENV: "/trusted/Xcode",
            BOUND_GIT_TMPDIR_ENV: "/private/runtime",
            BOUND_GIT_RECEIPT_ENV: "a" * 64,
        }
        with mock.patch.dict(os.environ, values, clear=True):
            self.assertEqual(
                selected_git_executable(),
                "/trusted/Xcode/usr/bin/git",
            )
            environment = bound_git_environment()
        self.assertEqual(environment["DEVELOPER_DIR"], "/trusted/Xcode")
        self.assertEqual(
            environment["GIT_EXEC_PATH"],
            "/trusted/Xcode/usr/libexec/git-core",
        )
        self.assertEqual(environment["TMPDIR"], "/private/runtime")

        with mock.patch.dict(
            os.environ,
            {BOUND_GIT_EXECUTABLE_ENV: "/trusted/git"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "environment is incomplete"):
                selected_git_executable()

        invalid = dict(values)
        invalid[BOUND_GIT_TMPDIR_ENV] = "relative/runtime"
        with mock.patch.dict(os.environ, invalid, clear=True):
            with self.assertRaisesRegex(RuntimeError, "not an absolute normalized"):
                bound_git_environment()

    def test_materializer_blocks_small_lfs_pointer_content(self) -> None:
        with owned_temporary_directory("git-lfs-block-") as root:
            repo, base_sha, _ = _build_repository(root)
            pointer = (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"ext-10-!opaque/name sha256:" + b"b" * 64 + b"\n"
                b"ext-10-!opaque/name sha256:" + b"b" * 64 + b"\n"
                b"oid sha256:" + b"a" * 64 + b"\n"
                b"size +0001\n"
            )
            (repo / "pointer.bin").write_bytes(pointer)
            _git(repo, "add", "--", "pointer.bin")
            _git(repo, "commit", "-q", "-m", "pointer")
            head_sha = _git(repo, "rev-parse", "HEAD").decode("ascii")
            info = inspect_repository(
                repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                git_executable=str(GIT),
            )
            base = enumerate_tree(info, base_sha)
            head = enumerate_tree(info, head_sha)
            checkout = root / "checkout"
            registration = add_detached_worktree(info, checkout)
            namespace = root / "name-probe"
            namespace.mkdir(mode=0o700)
            source = root / "source.diff"
            source.write_bytes(b"diff\n")
            source.chmod(0o600)
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            materializer: RawMaterializer | None = None
            try:
                initialize_index(info, registration)
                semantics = probe_name_semantics(namespace)
                base_entries, head_entries = validate_namespaces(
                    base,
                    head,
                    semantics=semantics,
                    checkout_root=checkout,
                )
                graph = read_and_validate_symlink_graphs(
                    info,
                    base,
                    head,
                    base_entries=base_entries,
                    head_entries=head_entries,
                    semantics=semantics,
                )
                source_identity = identity_from_stat(os.fstat(source_fd))
                custody = HelperCustody(
                    state_dir=str(root),
                    state_identity=identity_from_stat(os.stat(root)),
                    workspace_root=str(root),
                    source_path=str(source),
                    source_identity=source_identity,
                    cleanup_lock_path=str(root / "unused.lock"),
                    cleanup_lock_identity=source_identity,
                    review_range=f"{base_sha}..{head_sha}",
                    base_sha=base_sha,
                    head_sha=head_sha,
                    diff_length=5,
                    diff_sha256=sha256_bytes(b"diff\n"),
                    preflight_sha256="0" * 64,
                    control_state_sha256="1" * 64,
                )
                materializer = RawMaterializer(
                    info=info,
                    registration=registration,
                    base=base,
                    head=head,
                    semantics=semantics,
                    graph=graph,
                    source_fd=source_fd,
                    custody=custody,
                    deadline=time.monotonic() + 60,
                    checkout_root_bound=1024 * 1024 * 1024,
                    git_admin_bound=1024 * 1024 * 1024,
                    view_path=root / "sanitized-git-view",
                )
                materializer.phase1()
                with self.assertRaises(SupervisorError) as raised:
                    materializer.materialize()
                self.assertEqual(
                    raised.exception.failure.code,
                    "blocked-checkout-lfs-pointer",
                )
            finally:
                if materializer is not None:
                    materializer.close()
                os.close(source_fd)
                if checkout.exists() and registration.registration.exists():
                    remove_both_present_worktree(info, registration)
                if namespace.exists():
                    namespace.rmdir()


if __name__ == "__main__":
    unittest.main()
