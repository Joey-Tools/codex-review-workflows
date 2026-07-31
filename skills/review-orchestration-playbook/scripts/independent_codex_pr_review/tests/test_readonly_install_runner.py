from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import unittest
from collections.abc import Iterator
from unittest import mock

from . import support
from . import run_readonly_install_deterministic_supervisor as runner
from .support import owned_temporary_directory


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    def test_runtime_parent_rejects_extended_ancestor_acl(self) -> None:
        with owned_temporary_directory("runtime-parent-acl-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)

            if sys.platform == "darwin":
                subprocess.run(
                    (
                        "/bin/chmod",
                        "+a",
                        "everyone allow read",
                        str(ancestor),
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=5,
                )
                try:
                    self.assertIsNone(
                        support._validated_private_runtime_parent(str(parent))
                    )
                finally:
                    subprocess.run(
                        ("/bin/chmod", "-N", str(ancestor)),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=5,
                    )
            else:
                with mock.patch.object(
                    support,
                    "open_absolute_directory_chain",
                    side_effect=ValueError(
                        "extended ACLs, xattrs, and quarantine are forbidden"
                    ),
                ):
                    self.assertIsNone(
                        support._validated_private_runtime_parent(str(parent))
                    )

    def test_runtime_parent_rejects_sticky_writable_ancestor(self) -> None:
        with owned_temporary_directory("runtime-parent-sticky-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)

            self.assertEqual(
                support._validated_private_runtime_parent(str(parent)),
                parent.resolve(strict=True),
            )
            ancestor.chmod(0o1777)
            try:
                self.assertIsNone(
                    support._validated_private_runtime_parent(str(parent))
                )
            finally:
                ancestor.chmod(0o700)

    def test_runtime_parent_revalidation_rejects_writable_ancestor(self) -> None:
        with owned_temporary_directory("runtime-parent-drift-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                parent,
                require_owned_private_parent=True,
            )
            try:
                ancestor.chmod(0o1777)
                with self.assertRaisesRegex(
                    OSError,
                    "group- or world-writable",
                ):
                    binding.revalidate()
            finally:
                ancestor.chmod(0o700)
                binding.close()

    def test_private_directory_creation_rejects_new_child_acl(self) -> None:
        with owned_temporary_directory("runtime-child-acl-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)

            if sys.platform == "darwin":
                original_mkdir = os.mkdir

                def mkdir_with_acl(
                    name: bytes,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    original_mkdir(name, mode, dir_fd=dir_fd)
                    child = parent / os.fsdecode(name)
                    subprocess.run(
                        (
                            "/bin/chmod",
                            "+a",
                            "everyone allow read,write,execute,"
                            "file_inherit,directory_inherit",
                            str(child),
                        ),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=5,
                    )

                validation_patch = mock.patch.object(
                    support.os,
                    "mkdir",
                    side_effect=mkdir_with_acl,
                )
            else:
                validation_patch = mock.patch.object(
                    support,
                    "open_directory_at",
                    side_effect=ValueError(
                        "private filesystem object has extended metadata"
                    ),
                )

            with (
                validation_patch,
                self.assertRaisesRegex(
                    ValueError,
                    "extended metadata",
                ),
            ):
                support._create_owned_private_directory(
                    parent,
                    ".new-child-",
                )

            self.assertEqual(tuple(parent.iterdir()), ())

    def test_private_directory_creation_normalizes_restrictive_umask(self) -> None:
        with owned_temporary_directory("runtime-child-umask-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)

            for restrictive_umask in (0o177, 0o777):
                with self.subTest(umask=oct(restrictive_umask)):
                    previous_umask = os.umask(restrictive_umask)
                    try:
                        child = support._create_owned_private_directory(
                            parent,
                            ".new-child-",
                        )
                    finally:
                        os.umask(previous_umask)

                    self.assertEqual(
                        stat.S_IMODE(child.stat(follow_symlinks=False).st_mode),
                        0o700,
                    )
                    child.rmdir()

    def test_bound_runtime_directory_allows_benign_child_churn(self) -> None:
        with owned_temporary_directory("runtime-binding-churn-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                transient = runtime_parent / "transient"
                transient.write_text("temporary", encoding="utf-8")
                transient.unlink()

                self.assertEqual(runner._list_bound_directory(binding), ())
            finally:
                binding.close()

    def test_bound_runtime_directory_rejects_path_replacement(self) -> None:
        with owned_temporary_directory("runtime-binding-replace-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)
                runtime_parent.mkdir(mode=0o700)

                with self.assertRaisesRegex(OSError, "path changed"):
                    runner._list_bound_directory(binding)
            finally:
                binding.close()

    def test_bound_runtime_cleanup_rejects_path_replacement(self) -> None:
        with owned_temporary_directory("runtime-cleanup-replace-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)
                runtime_parent.mkdir(mode=0o700)

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(original))
                self.assertEqual(failure.error_kind, "OSError")
                self.assertEqual(failure.error_errno, errno.ESTALE)
                self.assertTrue(failure.retained)
                self.assertTrue(original.is_dir())
                self.assertTrue(runtime_parent.is_dir())
            finally:
                binding.close()

    def test_bound_cleanup_retains_renamed_object_when_path_is_absent(self) -> None:
        with owned_temporary_directory("runtime-cleanup-rename-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(original))
                self.assertEqual(failure.error_kind, "FileNotFoundError")
                self.assertTrue(failure.retained)
                self.assertTrue(original.is_dir())
                self.assertFalse(runtime_parent.exists())
            finally:
                binding.close()

    def test_bound_cleanup_uses_descriptor_locator_when_path_is_unverifiable(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-locator-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)
                with mock.patch.object(
                    runner,
                    "_descriptor_path",
                    side_effect=OSError(
                        errno.ESTALE,
                        "synthetic descriptor path failure",
                    ),
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertTrue(
                    failure.path.startswith("descriptor-object://"),
                    failure.path,
                )
                self.assertNotEqual(failure.path, str(runtime_parent))
                self.assertTrue(failure.retained)
                self.assertTrue(original.is_dir())
            finally:
                binding.close()

    def test_bound_cleanup_removes_the_staged_descriptor_tree(self) -> None:
        with owned_temporary_directory("runtime-cleanup-bound-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            nested = runtime_parent / "nested"
            nested.mkdir(mode=0o700)
            payload = nested / "payload"
            payload.write_text("content", encoding="utf-8")
            nested.chmod(0o500)
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=True,
                )

                self.assertIsNone(failure)
                self.assertFalse(runtime_parent.exists())
                self.assertFalse(tuple(root.glob(".codex-cleanup-*")))
            finally:
                binding.close()

    def test_bound_cleanup_detects_final_root_replacement(self) -> None:
        with owned_temporary_directory("runtime-cleanup-final-race-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            escaped = root / "escaped"
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            real_rmdir = runner.os.rmdir

            def replace_before_final_rmdir(
                name: str,
                *,
                dir_fd: int | None = None,
            ) -> None:
                assert dir_fd is not None
                os.rename(
                    name,
                    escaped.name,
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
                os.mkdir(name, mode=0o700, dir_fd=dir_fd)
                real_rmdir(name, dir_fd=dir_fd)

            try:
                with mock.patch.object(
                    runner.os,
                    "rmdir",
                    side_effect=replace_before_final_rmdir,
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(escaped))
                self.assertEqual(failure.error_kind, "OSError")
                self.assertEqual(failure.error_errno, errno.ESTALE)
                self.assertTrue(failure.retained)
                self.assertTrue(escaped.is_dir())
                self.assertFalse(runtime_parent.exists())
            finally:
                binding.close()
                if escaped.exists():
                    escaped.rmdir()

    def test_lifecycle_signal_fence_records_without_interrupting(self) -> None:
        fence = runner._install_lifecycle_signal_fence()
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            self.assertEqual(fence.received_signal, signal.SIGTERM)
        finally:
            received_signal = runner._restore_lifecycle_signal_fence(fence)
        self.assertEqual(received_signal, signal.SIGTERM)

        with owned_temporary_directory("readonly-lifecycle-late-signal-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir(mode=0o700)
            sticky_parent.chmod(0o1777)
            late_fence = runner.LifecycleSignalFence(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
            )
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_install_lifecycle_signal_fence",
                    return_value=late_fence,
                ),
                mock.patch.object(runner, "_run_main", return_value=0),
                mock.patch.object(
                    runner,
                    "_restore_lifecycle_signal_fence",
                    return_value=signal.SIGTERM,
                ),
            ):
                self.assertEqual(runner.main(), 128 + signal.SIGTERM)

    def test_snapshot_binds_acl_and_xattr_evidence(self) -> None:
        with owned_temporary_directory("readonly-snapshot-policy-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            acl_entries: dict[pathlib.Path, tuple[bytes, ...]] = {}
            xattrs: dict[pathlib.Path, tuple[tuple[str, str], ...]] = {}

            with (
                mock.patch.object(
                    runner,
                    "_acl_entries",
                    side_effect=lambda path: acl_entries.get(path, ()),
                ),
                mock.patch.object(
                    runner,
                    "_xattr_snapshot",
                    side_effect=lambda path: xattrs.get(path, ()),
                ),
            ):
                baseline = runner._tree_snapshot(root)
                acl_entries[target] = (b" 0: user:synthetic allow write",)
                acl_changed = runner._tree_snapshot(root)
                acl_entries.clear()
                xattrs[target] = ((b"com.apple.synthetic", "digest"),)
                xattr_changed = runner._tree_snapshot(root)

            self.assertNotEqual(baseline[target.name], acl_changed[target.name])
            self.assertNotEqual(baseline[target.name], xattr_changed[target.name])

    def test_snapshot_binds_same_content_object_replacement(self) -> None:
        with owned_temporary_directory("readonly-snapshot-identity-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            target.chmod(0o444)
            before = runner._tree_snapshot(root)

            replacement = root / "replacement"
            replacement.write_text("content", encoding="utf-8")
            replacement.chmod(0o444)
            os.replace(replacement, target)
            after = runner._tree_snapshot(root)

            self.assertEqual(before[target.name].digest, after[target.name].digest)
            self.assertEqual(before[target.name].mode, after[target.name].mode)
            self.assertNotEqual(before[target.name].inode, after[target.name].inode)
            self.assertNotEqual(before[target.name], after[target.name])
            self.assertFalse(runner._tree_property_unchanged(before, after))

    def test_snapshot_rejects_regular_file_external_hardlink_alias(self) -> None:
        with (
            owned_temporary_directory("readonly-snapshot-hardlink-tree-") as root,
            owned_temporary_directory("readonly-snapshot-hardlink-alias-") as outside,
        ):
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            alias = outside / "alias"
            os.link(target, alias)
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "external hardlink alias",
                ):
                    runner._tree_snapshot(root)
            finally:
                alias.unlink()

    def test_property_comparison_ignores_benign_metadata_churn(self) -> None:
        with owned_temporary_directory("readonly-snapshot-metadata-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            with (
                mock.patch.object(runner, "_acl_entries", return_value=()),
                mock.patch.object(runner, "_xattr_snapshot", return_value=()),
            ):
                before = runner._tree_snapshot(root)
                prior_mtime_ns = target.stat().st_mtime_ns
                os.utime(
                    target,
                    ns=(prior_mtime_ns + 1_000_000_000,) * 2,
                )
                churn = root / "benign-child-churn"
                churn.write_text("temporary", encoding="utf-8")
                churn.unlink()
                after = runner._tree_snapshot(root)

            self.assertNotEqual(prior_mtime_ns, target.stat().st_mtime_ns)
            self.assertIsNone(before["."].link_count)
            self.assertEqual(before[target.name].link_count, 1)
            self.assertTrue(runner._tree_property_unchanged(before, after))

    def test_cleanup_restores_write_and_removes_tree(self) -> None:
        with owned_temporary_directory("readonly-cleanup-success-") as parent:
            root = parent / "tree"
            root.mkdir()
            nested = root / "nested"
            nested.mkdir()
            target = nested / "target"
            target.write_text("content", encoding="utf-8")
            runner._set_tree_read_only(root)
            self.assertFalse(
                stat.S_IMODE(target.stat().st_mode) & stat.S_IWUSR,
            )

            failure = runner._cleanup_tree(root, restore_owner_write=True)

            self.assertIsNone(failure)
            self.assertFalse(os.path.lexists(root))

    def test_cleanup_failure_retains_exact_machine_visible_path(self) -> None:
        with owned_temporary_directory("readonly-cleanup-failure-") as root:
            with mock.patch.object(
                runner.shutil,
                "rmtree",
                side_effect=PermissionError(
                    errno.EACCES,
                    "synthetic cleanup denial",
                    str(root),
                ),
            ):
                failure = runner._cleanup_tree(
                    root,
                    restore_owner_write=False,
                )

            self.assertIsNotNone(failure)
            assert failure is not None
            self.assertEqual(failure.path, str(root))
            self.assertEqual(failure.error_kind, "PermissionError")
            self.assertEqual(failure.error_errno, errno.EACCES)
            self.assertTrue(failure.retained)
            self.assertTrue(os.path.lexists(root))

    @staticmethod
    def _no_child_result(
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        authenticated: bool = True,
        closure_proven: bool = True,
        leader_reaped: bool = True,
        stdio_closed: bool = True,
        group_emptiness_used: bool = False,
    ) -> mock.Mock:
        closure = mock.Mock(
            authenticated_no_child_profile=authenticated,
            permitted_process_closure_proven=closure_proven,
            leader_reaped=leader_reaped,
            stdio_closed=stdio_closed,
            process_group_emptiness_used_as_descendant_proof=group_emptiness_used,
        )
        return mock.Mock(
            returncode=0,
            stdout=stdout,
            stderr=stderr,
            process_closure=closure,
        )

    @contextlib.contextmanager
    def _bound_no_child_roots(
        self,
        prefix: str,
    ) -> Iterator[
        tuple[
            pathlib.Path,
            support._DirectoryParentBinding,
            support._DirectoryParentBinding,
        ]
    ]:
        with owned_temporary_directory(prefix) as root:
            install_container = root / "install"
            install_container.mkdir(mode=0o700)
            installed_root = install_container / "independent_codex_pr_review"
            installed_root.mkdir(mode=0o700)
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            install_binding = support._open_directory_parent(
                install_container,
                require_owned_private_parent=True,
            )
            runtime_binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                with mock.patch.object(
                    runner,
                    "attest_writable_root",
                    return_value=mock.sentinel.writable_runtime,
                ):
                    yield installed_root, install_binding, runtime_binding
            finally:
                runtime_binding.close()
                install_binding.close()

    def test_no_child_runtime_profile_selection_is_exact_and_fail_closed(
        self,
    ) -> None:
        with mock.patch.dict(runner.os.environ, {}, clear=True):
            name, pin = runner._select_no_child_runtime_profile()
        self.assertEqual(name, "production-current")
        self.assertIs(pin, runner.no_child_profile.PINNED_RUNTIME)

        with (
            mock.patch.dict(
                runner.os.environ,
                {"GITHUB_ACTIONS": "true"},
                clear=True,
            ),
            self.assertRaisesRegex(RuntimeError, "missing explicit hosted"),
        ):
            runner._select_no_child_runtime_profile()

        with (
            mock.patch.dict(
                runner.os.environ,
                {
                    runner.RUNNER_ENVIRONMENT_ENV: "github-hosted",
                    runner.RUNNER_ARCH_ENV: "ARM64",
                },
                clear=True,
            ),
            mock.patch.object(runner.platform, "machine", return_value="arm64"),
            mock.patch.object(
                runner.no_child_profile,
                "_runtime_fingerprint",
                return_value=mock.sentinel.runtime,
            ),
            mock.patch.object(
                runner,
                "_select_hosted_runtime_profile",
                return_value=("github-reviewed-runtime", mock.sentinel.runtime_pin),
            ) as select_hosted,
        ):
            name, pin = runner._select_no_child_runtime_profile()
        self.assertEqual(name, "github-reviewed-runtime")
        self.assertIs(pin, mock.sentinel.runtime_pin)
        select_hosted.assert_called_once_with(mock.sentinel.runtime)

        with (
            mock.patch.dict(
                runner.os.environ,
                {runner.RUNNER_ENVIRONMENT_ENV: "github-hosted"},
                clear=True,
            ),
            self.assertRaisesRegex(RuntimeError, "incomplete or unsupported"),
        ):
            runner._select_no_child_runtime_profile()

    def test_no_child_suite_stops_after_signal_during_profile_preparation(
        self,
    ) -> None:
        with self._bound_no_child_roots("readonly-no-child-preflight-signal-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            fence = runner.LifecycleSignalFence(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
            )

            def prepare_after_signal(
                **_kwargs: object,
            ) -> object:
                fence.received_signal = signal.SIGTERM
                return mock.sentinel.prepared

            with (
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    side_effect=prepare_after_signal,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                ) as run_bounded_command,
                self.assertRaises(runner.ChildRunInterrupted) as caught,
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                    lifecycle_fence=fence,
                )

            self.assertEqual(caught.exception.signal_number, signal.SIGTERM)
            self.assertFalse(proof.launch_attempted)
            self.assertFalse(proof.proven)
            self.assertEqual(
                runner._child_process_closure_status(proof),
                "not-started",
            )
            run_bounded_command.assert_not_called()

    def test_no_child_suite_accepts_authenticated_tree_closure(self) -> None:
        with self._bound_no_child_roots("readonly-no-child-accepted-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ) as prepare_profile,
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    return_value=self._no_child_result(
                        stdout=b"selected tests passed\n",
                    ),
                ) as run_bounded_command,
            ):
                result = runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertTrue(proof.proven)
            self.assertTrue(proof.launch_attempted)
            self.assertEqual(proof.runtime_profile, "synthetic-runtime")
            prepare_profile.assert_called_once_with(
                additional_seatbelt_rules="(deny file-write*)",
                runtime_pin=mock.sentinel.runtime_pin,
                writable_roots=(mock.sentinel.writable_runtime,),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "selected tests passed\n")
            self.assertEqual(result.stderr, "")
            argv = run_bounded_command.call_args.args[0]
            self.assertIn("os.environ['TMPDIR']=sys.argv[2]", argv[3])
            self.assertIn("tempfile.tempdir=sys.argv[2]", argv[3])

    def test_no_child_suite_rejects_process_group_only_closure(self) -> None:
        with self._bound_no_child_roots("readonly-no-child-forged-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    return_value=self._no_child_result(group_emptiness_used=True),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "authenticated no-child proof",
                ),
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertFalse(proof.proven)

    def test_no_child_suite_output_overflow_keeps_closure_proof(self) -> None:
        with self._bound_no_child_roots("readonly-no-child-overflow-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    return_value=self._no_child_result(stdout=b"x" * 1025),
                ),
                self.assertRaisesRegex(OverflowError, "byte cap"),
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertTrue(proof.proven)

    def test_no_child_suite_timeout_uses_attached_settlement_proof(self) -> None:
        with self._bound_no_child_roots("readonly-no-child-timeout-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            timeout = TimeoutError("synthetic bounded timeout")
            closure = self._no_child_result(stdio_closed=False).process_closure
            with (
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    side_effect=timeout,
                ),
                mock.patch.object(
                    runner,
                    "bounded_command_process_closure",
                    return_value=closure,
                ) as process_closure,
                self.assertRaisesRegex(TimeoutError, "bounded timeout"),
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertTrue(proof.launch_attempted)
            self.assertTrue(proof.proven)
            process_closure.assert_called_once_with(timeout)

    def test_no_child_suite_output_exception_uses_attached_settlement_proof(
        self,
    ) -> None:
        with self._bound_no_child_roots("readonly-no-child-output-error-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            output_error = ValueError("command output exceeds 2048 bytes")
            closure = self._no_child_result(stdio_closed=False).process_closure
            with (
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    side_effect=output_error,
                ),
                mock.patch.object(
                    runner,
                    "bounded_command_process_closure",
                    return_value=closure,
                ) as process_closure,
                self.assertRaisesRegex(OverflowError, "byte cap"),
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertTrue(proof.launch_attempted)
            self.assertTrue(proof.proven)
            process_closure.assert_called_once_with(output_error)

    def test_no_child_suite_does_not_claim_closure_before_process_supervision(
        self,
    ) -> None:
        with self._bound_no_child_roots("readonly-no-child-pre-supervision-") as roots:
            installed_root, install_binding, runtime_binding = roots
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=mock.sentinel.interrupt,
            )
            closure_proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(
                    runner,
                    "activate_deferred_signal_interrupt",
                    side_effect=TimeoutError("synthetic activation failure"),
                ),
                mock.patch.object(runner, "_restore_child_signal_guard"),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                ) as run_bounded_command,
                self.assertRaisesRegex(TimeoutError, "activation failure"),
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=closure_proof,
                )

            self.assertFalse(closure_proof.proven)
            run_bounded_command.assert_not_called()

    def test_no_child_suite_defers_signal_until_caller_proof_is_published(
        self,
    ) -> None:
        with self._bound_no_child_roots(
            "readonly-no-child-post-return-signal-"
        ) as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            interrupt = runner.DeferredSignalInterrupt(runner.ChildRunInterrupted)
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=interrupt,
            )
            self_outer = self

            class CompletedAfterSignal:
                returncode = 0
                stdout = b""
                stderr = b""

                @property
                def process_closure(self) -> mock.Mock:
                    interrupt.request(signal.SIGTERM)
                    self_outer.assertFalse(proof.proven)
                    return ReadOnlyInstallRunnerTests._no_child_result().process_closure

            def completed_after_signal(
                *_args: object,
                **_kwargs: object,
            ) -> CompletedAfterSignal:
                return CompletedAfterSignal()

            with (
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(runner, "_restore_child_signal_guard"),
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    side_effect=completed_after_signal,
                ),
                self.assertRaises(runner.ChildRunInterrupted) as caught,
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertEqual(caught.exception.signal_number, signal.SIGTERM)
            self.assertTrue(proof.launch_attempted)
            self.assertTrue(proof.proven)

    def test_no_child_suite_retains_unproven_failure_over_pending_signal(
        self,
    ) -> None:
        with self._bound_no_child_roots("readonly-no-child-unproven-signal-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            interrupt = runner.DeferredSignalInterrupt(runner.ChildRunInterrupted)
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=interrupt,
            )
            closure_error = RuntimeError("synthetic unproven closure")

            def fail_after_signal(
                *_args: object,
                **_kwargs: object,
            ) -> None:
                interrupt.request(signal.SIGTERM)
                raise closure_error

            with (
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(runner, "_restore_child_signal_guard"),
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    side_effect=fail_after_signal,
                ),
                mock.patch.object(
                    runner,
                    "bounded_command_process_closure",
                    return_value=None,
                ),
                self.assertRaises(RuntimeError) as caught,
            ):
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=proof,
                )

            self.assertIs(caught.exception, closure_error)
            self.assertTrue(proof.launch_attempted)
            self.assertFalse(proof.proven)

    def test_main_preserves_closure_failure_across_signal_teardown(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-main-closure-gap-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            install_container.mkdir()
            runtime_home = root / "runtime-home"
            runtime_home.mkdir()
            runtime_parent = runtime_home / "runtime"
            runtime_parent.mkdir()

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            closure_error = RuntimeError("synthetic no-child closure failure")
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=mock.sentinel.interrupt,
            )
            deactivate_error = RuntimeError(
                "synthetic deferred-signal teardown failure"
            )
            restore_error = OSError(
                errno.EIO,
                "synthetic signal-guard restore failure",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_owned_private_directory",
                    side_effect=(install_container, runtime_parent),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(
                    runner,
                    "activate_deferred_signal_interrupt",
                    return_value=mock.sentinel.binding,
                ),
                mock.patch.object(
                    runner,
                    "deactivate_deferred_signal_interrupt",
                    side_effect=deactivate_error,
                ) as deactivate,
                mock.patch.object(
                    runner,
                    "_restore_child_signal_guard",
                    side_effect=restore_error,
                ) as restore,
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=mock.sentinel.prepared,
                ),
                mock.patch.object(
                    runner,
                    "attest_writable_root",
                    return_value=mock.sentinel.writable_runtime,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    side_effect=closure_error,
                ),
                mock.patch.object(runner, "_cleanup_tree") as cleanup_tree,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["primary_status"], "closure-unproven")
            self.assertEqual(summary["child_process_closure"], "unproven")
            self.assertEqual(
                summary["primary_failure"]["error_kind"],
                "RuntimeError",
            )
            self.assertEqual(
                [failure["operation"] for failure in summary["secondary_failures"]],
                [
                    "deactivate-deferred-signal-interrupt",
                    "restore-child-signal-guard",
                ],
            )
            self.assertEqual(
                [failure["error_kind"] for failure in summary["secondary_failures"]],
                ["RuntimeError", "OSError"],
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(install_container), str(runtime_parent)],
            )
            self.assertTrue(install_container.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            cleanup_tree.assert_not_called()
            deactivate.assert_called_once_with(mock.sentinel.binding)
            restore.assert_called_once_with(signal_guard)
            error_text = stderr.getvalue()
            self.assertIn("synthetic no-child closure failure", error_text)
            self.assertLess(
                error_text.index("primary failure"),
                error_text.index("secondary failures"),
            )
            self.assertLess(
                error_text.index("secondary failures"),
                error_text.index("cleanup incomplete"),
            )

    def test_main_reports_primary_and_cleanup_failures_in_order(self) -> None:
        with owned_temporary_directory("readonly-main-failures-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            install_container.mkdir()
            runtime_home = root / "runtime-home"
            runtime_home.mkdir()
            runtime_parent = runtime_home / "runtime"
            runtime_parent.mkdir()
            cleanup_failure = runner.CleanupFailure(
                path=str(install_container),
                error_kind="PermissionError",
                error_errno=errno.EACCES,
                retained=True,
                restore_error_kind=None,
                restore_error_errno=None,
            )
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="child stdout evidence",
                stderr="child stderr evidence",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_owned_private_directory",
                    side_effect=(install_container, runtime_parent),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(
                    runner,
                    "_tree_snapshot",
                    side_effect=(
                        {},
                        RuntimeError("synthetic post-snapshot failure"),
                    ),
                ),
                mock.patch.object(
                    runner,
                    "_run_no_child_test_suite",
                    return_value=completed,
                ),
                mock.patch.object(
                    runner,
                    "_cleanup_bound_tree",
                    side_effect=(cleanup_failure, None),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            error_text = stderr.getvalue()
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["returncode"], 0)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "snapshot-after",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(install_container)],
            )
            self.assertIn("child stdout evidence", error_text)
            self.assertIn("child stderr evidence", error_text)
            self.assertLess(
                error_text.index("primary failure"),
                error_text.index("cleanup incomplete"),
            )

    def test_main_rejects_replaced_install_container(self) -> None:
        with owned_temporary_directory("readonly-main-install-replace-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            install_container.mkdir()
            original_install_container = sticky_parent / "original-install"
            runtime_home = root / "runtime-home"
            runtime_home.mkdir()
            runtime_parent = runtime_home / "runtime"
            runtime_parent.mkdir()
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            def replace_install_container(
                *_args: object,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                install_container.rename(original_install_container)
                install_container.mkdir(mode=0o700)
                return completed

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_owned_private_directory",
                    side_effect=(install_container, runtime_parent),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_no_child_test_suite",
                    side_effect=replace_install_container,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "snapshot-after",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(original_install_container)],
            )
            self.assertTrue(original_install_container.is_dir())
            self.assertTrue(install_container.is_dir())
            self.assertIn("test runtime parent path changed", stderr.getvalue())

    def test_main_rejects_replaced_runtime_parent(self) -> None:
        with owned_temporary_directory("readonly-main-runtime-replace-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            install_container.mkdir()
            runtime_home = root / "runtime-home"
            runtime_home.mkdir()
            runtime_parent = runtime_home / "runtime"
            runtime_parent.mkdir()
            original_runtime_parent = runtime_home / "original-runtime"
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            def replace_runtime_parent(
                *_args: object,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                runtime_parent.rename(original_runtime_parent)
                runtime_parent.mkdir(mode=0o700)
                return completed

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_owned_private_directory",
                    side_effect=(install_container, runtime_parent),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_no_child_test_suite",
                    side_effect=replace_runtime_parent,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "runtime-residue",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(original_runtime_parent)],
            )
            self.assertTrue(original_runtime_parent.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            self.assertIn("test runtime parent path changed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
