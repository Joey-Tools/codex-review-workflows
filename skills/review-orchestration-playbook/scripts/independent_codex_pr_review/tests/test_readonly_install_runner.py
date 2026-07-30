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
import time
import unittest
from unittest import mock

from . import support
from . import run_readonly_install_deterministic_supervisor as runner
from .support import owned_temporary_directory


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    @staticmethod
    def _process_group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _require_process_group_absent(
        self,
        process_group: int,
        *,
        timeout: float = 5.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._process_group_exists(process_group):
                return
            time.sleep(0.02)
        self.assertFalse(
            self._process_group_exists(process_group),
            f"process group {process_group} remained live",
        )

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

    def test_bounded_child_settles_same_group_descendant_after_leader_exit(
        self,
    ) -> None:
        child_script = (
            "import os,pathlib,subprocess,sys\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
        )
        with owned_temporary_directory("readonly-child-descendant-") as root:
            group_file = root / "process-group"
            result = runner._run_bounded_child(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    child_script,
                    str(group_file),
                ),
                cwd=root,
                environment={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                timeout=5,
                stdout_limit=1024,
                stderr_limit=1024,
            )

            process_group = int(group_file.read_text(encoding="ascii"))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            self._require_process_group_absent(process_group)

    def test_bounded_child_output_overflow_settles_same_group_descendant(
        self,
    ) -> None:
        child_script = (
            "import os,pathlib,subprocess,sys,time\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "os.write(1,b'x'*8192)\n"
            "time.sleep(300)\n"
        )
        with owned_temporary_directory("readonly-child-overflow-") as root:
            group_file = root / "process-group"
            with self.assertRaisesRegex(OverflowError, "byte cap"):
                runner._run_bounded_child(
                    (
                        sys.executable,
                        "-B",
                        "-c",
                        child_script,
                        str(group_file),
                    ),
                    cwd=root,
                    environment={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )

            process_group = int(group_file.read_text(encoding="ascii"))
            self._require_process_group_absent(process_group)

    def test_bounded_child_sigterm_settles_group_before_interrupt_returns(
        self,
    ) -> None:
        inner_script = (
            "import os,pathlib,subprocess,sys,time\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "pathlib.Path(sys.argv[2]).write_text('ready', encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "time.sleep(300)\n"
        )
        worker_script = (
            "import os,pathlib,sys\n"
            "from tests import run_readonly_install_deterministic_supervisor as runner\n"
            "root=pathlib.Path(sys.argv[1])\n"
            "try:\n"
            " runner._run_bounded_child("
            "(sys.executable,'-B','-c',sys.argv[2],sys.argv[3],sys.argv[4]),"
            "cwd=root,environment={'LANG':'C','LC_ALL':'C',"
            "'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},"
            "timeout=30,stdout_limit=1024,stderr_limit=1024)\n"
            "except runner.ChildRunInterrupted as error:\n"
            " raise SystemExit(128+error.signal_number)\n"
            "raise SystemExit(3)\n"
        )
        with owned_temporary_directory("readonly-child-sigterm-") as root:
            group_file = root / "process-group"
            ready_file = root / "ready"
            worker = subprocess.Popen(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    worker_script,
                    str(root),
                    inner_script,
                    str(group_file),
                    str(ready_file),
                ),
                cwd=pathlib.Path(__file__).resolve().parents[1],
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready_file.is_file() and time.monotonic() < deadline:
                    if worker.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue(
                    ready_file.is_file(), "bounded child did not become ready"
                )
                process_group = int(group_file.read_text(encoding="ascii"))

                worker.send_signal(signal.SIGTERM)
                stdout, stderr = worker.communicate(timeout=10)

                self.assertEqual(worker.returncode, 128 + signal.SIGTERM)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self._require_process_group_absent(process_group)
            finally:
                if worker.poll() is None:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=5)

    def test_main_retains_trees_when_child_process_closure_is_unproven(
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

            closure_error = runner.GitProcessClosureUnproven(
                None,
                None,
                RuntimeError("synthetic closure failure"),
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
                    "_run_bounded_child",
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
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(install_container), str(runtime_parent)],
            )
            self.assertTrue(install_container.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            cleanup_tree.assert_not_called()
            self.assertIn("GitProcessClosureUnproven", stderr.getvalue())

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
                mock.patch.object(runner, "_run_bounded_child", return_value=completed),
                mock.patch.object(
                    runner,
                    "_cleanup_tree",
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
            self.assertEqual(summary["retained_paths"], [str(install_container)])
            self.assertIn("child stdout evidence", error_text)
            self.assertIn("child stderr evidence", error_text)
            self.assertLess(
                error_text.index("primary failure"),
                error_text.index("cleanup incomplete"),
            )


if __name__ == "__main__":
    unittest.main()
