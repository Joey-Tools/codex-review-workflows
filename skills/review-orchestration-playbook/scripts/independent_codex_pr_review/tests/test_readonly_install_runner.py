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
from dataclasses import asdict
from unittest import mock

from review_supervisor import recovery_cleanup

from . import run_readonly_install_deterministic_supervisor as runner
from . import support
from .support import owned_temporary_directory


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    @staticmethod
    def _bound_directory_factory(
        *paths: pathlib.Path,
    ) -> object:
        remaining = iter(paths)

        def create(
            _parent: pathlib.Path,
            _prefix: str,
            *,
            require_owned_private_parent: bool = True,
        ) -> support._DirectoryParentBinding:
            return support._open_directory_parent(
                next(remaining),
                require_owned_private_parent=require_owned_private_parent,
            )

        return create

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

    def test_darwin_process_census_rejects_zero_result_with_errno(self) -> None:
        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __call__(self, *_args: object) -> int:
                runner.ctypes.set_errno(errno.EIO)
                return 0

        class SyntheticProcPidRusage:
            argtypes: object = None
            restype: object = None

            def __call__(self, *_args: object) -> int:
                raise AssertionError("PID inspection must not start")

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.proc_pid_rusage = SyntheticProcPidRusage()

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticLibproc(),
            ),
            self.assertRaisesRegex(
                OSError,
                "cannot enumerate same-UID Darwin processes",
            ),
        ):
            runner._darwin_same_uid_processes()

    def test_darwin_process_census_retries_and_rebinds_disappearing_pid(self) -> None:
        pid = 2_147_483_647

        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __init__(self) -> None:
                self.calls = 0

            def __call__(
                self,
                _process_type: object,
                _uid: object,
                buffer: object,
                _buffer_bytes: object,
            ) -> int:
                self.calls += 1
                pid_buffer = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner.ctypes.c_int),
                )
                pid_buffer[0] = pid
                return runner.ctypes.sizeof(runner.ctypes.c_int)

        class SyntheticProcPidRusage:
            argtypes: object = None
            restype: object = None

            def __init__(self) -> None:
                self.calls = 0

            def __call__(self, _pid: int, _flavor: object, buffer: object) -> int:
                self.calls += 1
                if self.calls == 1:
                    runner.ctypes.set_errno(errno.ESRCH)
                    return -1
                value = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner._DarwinRusageInfoV0),
                ).contents
                value.ri_proc_start_abstime = 987_654
                return 0

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.proc_pid_rusage = SyntheticProcPidRusage()

        library = SyntheticLibproc()
        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=library,
            ),
        ):
            observed = runner._darwin_same_uid_processes()

        self.assertEqual(
            observed,
            (runner.DarwinProcessIdentity(pid=pid, start_abstime=987_654),),
        )
        self.assertEqual(library.proc_listpids.calls, 4)
        self.assertEqual(library.proc_pid_rusage.calls, 2)

    def test_darwin_process_census_includes_zombie_identity(self) -> None:
        pid = 90_001

        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __call__(
                self,
                _process_type: object,
                _uid: object,
                buffer: object,
                _buffer_bytes: object,
            ) -> int:
                pid_buffer = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner.ctypes.c_int),
                )
                pid_buffer[0] = pid
                return runner.ctypes.sizeof(runner.ctypes.c_int)

        class SyntheticProcPidRusage:
            argtypes: object = None
            restype: object = None

            def __call__(
                self,
                _observed_pid: int,
                _flavor: object,
                buffer: object,
            ) -> int:
                value = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner._DarwinRusageInfoV0),
                ).contents
                value.ri_proc_start_abstime = 123_456
                value.ri_proc_exit_abstime = 123_999
                return 0

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.proc_pid_rusage = SyntheticProcPidRusage()

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticLibproc(),
            ),
        ):
            observed = runner._darwin_same_uid_processes()

        self.assertEqual(
            observed,
            (
                runner.DarwinProcessIdentity(
                    pid=pid,
                    start_abstime=123_456,
                ),
            ),
        )

    def test_darwin_process_census_expires_during_pid_binding(self) -> None:
        clock = {"now": 0.0}
        pid = 90_002
        inspected: list[int] = []

        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __call__(
                self,
                _process_type: object,
                _uid: object,
                buffer: object,
                _buffer_bytes: object,
            ) -> int:
                pid_buffer = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner.ctypes.c_int),
                )
                pid_buffer[0] = pid
                return runner.ctypes.sizeof(runner.ctypes.c_int)

        class SyntheticProcPidRusage:
            argtypes: object = None
            restype: object = None

            def __call__(self, observed_pid: int, *_args: object) -> int:
                inspected.append(observed_pid)
                clock["now"] = 2.0
                return 0

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.proc_pid_rusage = SyntheticProcPidRusage()

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticLibproc(),
            ),
            mock.patch.object(
                runner.time,
                "monotonic",
                side_effect=lambda: clock["now"],
            ),
            self.assertRaisesRegex(TimeoutError, "census deadline expired"),
        ):
            runner._darwin_same_uid_processes(deadline=1.0)
        self.assertEqual(inspected, [pid])

    def test_stable_process_baseline_unions_prelaunch_identity_churn(self) -> None:
        existing = runner.DarwinProcessIdentity(pid=101, start_abstime=1_001)
        departing = runner.DarwinProcessIdentity(pid=102, start_abstime=1_002)
        arriving = runner.DarwinProcessIdentity(pid=102, start_abstime=2_002)
        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=((existing, departing), (existing, arriving)),
            ),
            mock.patch.object(runner.time, "sleep"),
        ):
            baseline = runner._stable_same_uid_processes(
                deadline=runner.time.monotonic() + 1.0
            )

        self.assertEqual(baseline, (existing, departing, arriving))

    def test_isolated_child_account_rejects_admin_membership(self) -> None:
        with (
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(runner.os, "geteuid", return_value=501),
            mock.patch.object(
                runner.grp,
                "getgrnam",
                return_value=mock.Mock(gr_gid=80),
            ),
            mock.patch.object(runner.os, "getgroups", return_value=[20, 80]),
            mock.patch.object(
                runner,
                "_require_job_creation_denied",
            ) as job_creation_denial,
            mock.patch.object(
                runner,
                "_require_sudo_exec_denied",
            ) as sudo_probe,
            self.assertRaisesRegex(PermissionError, "admin group"),
        ):
            runner._require_isolated_child_account()
        job_creation_denial.assert_not_called()
        sudo_probe.assert_not_called()

    def test_sudo_probe_requires_inherited_exec_denial(self) -> None:
        mixed_policy = subprocess.CompletedProcess(
            args=("sudo", "-n", "-l"),
            returncode=1,
            stdout=b"(root) NOPASSWD: /usr/bin/id\n",
            stderr=b"a password is required\n",
        )
        with (
            mock.patch.object(
                runner.subprocess,
                "run",
                return_value=mixed_policy,
            ),
            self.assertRaisesRegex(RuntimeError, "sudo execution was not denied"),
        ):
            runner._require_sudo_exec_denied()

        with mock.patch.object(
            runner.subprocess,
            "run",
            side_effect=PermissionError(errno.EPERM, "sandbox denied exec"),
        ):
            runner._require_sudo_exec_denied()

    def test_job_creation_probe_requires_explicit_seatbelt_denial(self) -> None:
        class SyntheticSandboxCheck:
            argtypes: object = None
            restype: object = None

            def __init__(self, result: int) -> None:
                self.result = result

            def __call__(self, *_args: object) -> int:
                return self.result

        class SyntheticSandbox:
            def __init__(self, result: int) -> None:
                self.sandbox_check = SyntheticSandboxCheck(result)

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticSandbox(1),
            ),
        ):
            runner._require_job_creation_denied()

        for result in (0, -1):
            with (
                self.subTest(result=result),
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner.ctypes,
                    "CDLL",
                    return_value=SyntheticSandbox(result),
                ),
                self.assertRaisesRegex(RuntimeError, "launchd job creation"),
            ):
                runner._require_job_creation_denied()

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

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_private_directory_creation_retains_moved_object(self) -> None:
        with owned_temporary_directory("runtime-child-binding-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            binding = support._create_bound_owned_private_directory(
                parent,
                ".new-child-",
            )
            original = binding.path
            moved = parent / "moved-child"
            try:
                original.rename(moved)
                original.mkdir(mode=0o700)

                self.assertEqual(binding.current_path(), moved)
                with self.assertRaisesRegex(OSError, "path changed"):
                    binding.revalidate()
            finally:
                binding.close()

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

    def test_unproven_closure_reports_unresolved_bound_location_as_unknown(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-binding-unresolved-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                for original_status in ("missing", "unreadable", "replaced"):
                    with (
                        self.subTest(original_path_status=original_status),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "current_path",
                            side_effect=OSError(
                                errno.ESTALE,
                                "synthetic F_GETPATH failure",
                            ),
                        ),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "original_path_identity_status",
                            return_value=original_status,
                        ),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "access_policy_status",
                            return_value="same",
                        ),
                    ):
                        evidence = runner._bound_path_evidence(binding)
                        failure = runner._retained_bound_for_unproven_child_closure(
                            binding,
                            None,
                        )

                    self.assertEqual(evidence.path, runtime_parent)
                    self.assertIsNone(evidence.retained)
                    self.assertEqual(evidence.path_status, "bound-unresolved")
                    self.assertEqual(
                        evidence.replacement_path,
                        runtime_parent if original_status == "replaced" else None,
                    )
                    self.assertEqual(
                        evidence.original_path_status,
                        original_status,
                    )
                    self.assertIsNotNone(failure)
                    assert failure is not None
                    payload = json.loads(
                        json.dumps(
                            asdict(failure),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                    self.assertEqual(
                        payload["error_kind"],
                        "ChildProcessClosureUnproven",
                    )
                    self.assertIsNone(payload["retained"])
                    self.assertEqual(
                        payload["original_path_status"],
                        original_status,
                    )
                    self.assertEqual(
                        payload["held_identity"],
                        binding.object_locator(),
                    )
                    retained_paths = [
                        item.path for item in (failure,) if item.retained is not False
                    ]
                    self.assertEqual(retained_paths, [str(runtime_parent)])
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
                self.assertEqual(failure.original_path, str(runtime_parent))
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertEqual(failure.replacement_path, str(runtime_parent))
                self.assertTrue(original.is_dir())
                self.assertTrue(runtime_parent.is_dir())
            finally:
                binding.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_runtime_cleanup_does_not_claim_unlinked_path_retained(self) -> None:
        with owned_temporary_directory("runtime-cleanup-unlinked-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rmdir()

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(runtime_parent))
                self.assertFalse(failure.retained)
                self.assertEqual(failure.original_path, str(runtime_parent))
                self.assertEqual(failure.path_status, "bound-unresolved")
                self.assertIsNone(failure.replacement_path)
            finally:
                binding.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_cleanup_reports_access_policy_drift_separately(self) -> None:
        with owned_temporary_directory("runtime-cleanup-policy-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.chmod(0o500)

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(runtime_parent))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-original")
                self.assertEqual(failure.original_path_status, "same")
                self.assertEqual(failure.access_policy_status, "changed")
                self.assertIsNone(failure.replacement_path)
                self.assertEqual(failure.held_identity, binding.object_locator())
            finally:
                runtime_parent.chmod(0o700)
                binding.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_descriptor_cleanup_retains_original_and_replacement_after_swap(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-swap-") as root:
            target = root / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload"
            payload.write_text("original", encoding="utf-8")
            moved = root / "moved-target"
            control = root / "control"
            control.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                target,
                require_owned_private_parent=True,
            )
            real_delete = runner.delete_custodied_roots

            def swap_before_delete(*args: object, **kwargs: object) -> object:
                target.rename(moved)
                target.mkdir(mode=0o700)
                (target / "sentinel").write_text("replacement", encoding="utf-8")
                return real_delete(*args, **kwargs)

            try:
                with mock.patch.object(
                    runner,
                    "delete_custodied_roots",
                    side_effect=swap_before_delete,
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=control / "manifest.bin",
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(moved))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertEqual(failure.original_path_status, "replaced")
                self.assertEqual(failure.replacement_path, str(target))
                self.assertEqual(
                    (moved / payload.name).read_text(encoding="utf-8"),
                    "original",
                )
                self.assertEqual(
                    (target / "sentinel").read_text(encoding="utf-8"),
                    "replacement",
                )
            finally:
                binding.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_descriptor_cleanup_reports_replacement_quarantined_during_rename(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-rename-race-") as root:
            target = root / "target"
            target.mkdir(mode=0o700)
            (target / "payload").write_text("original", encoding="utf-8")
            moved = root / "moved-target"
            control = root / "control"
            control.mkdir(mode=0o700)
            binding = support._open_directory_parent(
                target,
                require_owned_private_parent=True,
            )
            real_rename = os.rename
            swapped = False

            def swap_at_quarantine_rename(
                source: object,
                destination: object,
                *,
                src_dir_fd: int | None = None,
                dst_dir_fd: int | None = None,
            ) -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    real_rename(target, moved)
                    target.mkdir(mode=0o700)
                    (target / "sentinel").write_text(
                        "replacement",
                        encoding="utf-8",
                    )
                real_rename(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            try:
                with mock.patch.object(
                    recovery_cleanup.os,
                    "rename",
                    side_effect=swap_at_quarantine_rename,
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=control / "manifest.bin",
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertTrue(swapped)
                self.assertEqual(failure.path, str(moved))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertIsNotNone(failure.recovery_evidence)
                assert failure.recovery_evidence is not None
                recovery = failure.recovery_evidence
                self.assertEqual(
                    recovery["protected_property"],
                    "recovery-object-identity-and-deletion-result-ownership",
                )
                self.assertEqual(
                    recovery["deletion_result"]["published_root_count"],
                    0,
                )
                self.assertEqual(len(recovery["quarantined_roots"]), 1)
                quarantined = recovery["quarantined_roots"][0]
                self.assertEqual(
                    quarantined["stage"],
                    "post-rename-quarantine-revalidation",
                )
                self.assertEqual(
                    quarantined["quarantine_status"],
                    "different-object",
                )
                self.assertEqual(quarantined["deletion_state"], "not-published")
                self.assertTrue(quarantined["retained"])
                self.assertNotEqual(
                    quarantined["held_root_identity"],
                    quarantined["observed_quarantine_locator"],
                )
                quarantine_path = pathlib.Path(quarantined["quarantine_path"])
                self.assertTrue(quarantine_path.is_dir())
                self.assertEqual(
                    (quarantine_path / "sentinel").read_text(encoding="utf-8"),
                    "replacement",
                )
                self.assertEqual(
                    (moved / "payload").read_text(encoding="utf-8"),
                    "original",
                )
            finally:
                binding.close()

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

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin process census")
    def test_bounded_child_rejects_setsid_double_fork_escape(self) -> None:
        child_script = (
            "import os,pathlib,sys,time\n"
            "marker=pathlib.Path(sys.argv[1])\n"
            "first=os.fork()\n"
            "if first==0:\n"
            " os.setsid()\n"
            " second=os.fork()\n"
            " if second==0:\n"
            "  os.closerange(0,3)\n"
            "  marker.write_text(str(os.getpid()),encoding='ascii')\n"
            "  time.sleep(300)\n"
            "  os._exit(0)\n"
            " deadline=time.monotonic()+5\n"
            " while not marker.is_file() and time.monotonic()<deadline: time.sleep(0.01)\n"
            " os._exit(0)\n"
            "os.waitpid(first,0)\n"
        )
        with owned_temporary_directory("readonly-child-session-escape-") as root:
            marker = root / "escaped-process"
            escaped_pid: int | None = None
            try:
                started = time.monotonic()
                with self.assertRaises(
                    runner.ChildProcessTreeClosureUnproven
                ) as escaped:
                    runner._run_bounded_child(
                        (
                            sys.executable,
                            "-B",
                            "-c",
                            child_script,
                            str(marker),
                        ),
                        cwd=root,
                        environment={
                            "LANG": "C",
                            "LC_ALL": "C",
                            "PATH": "/usr/bin:/bin",
                            "PYTHONDONTWRITEBYTECODE": "1",
                        },
                        timeout=10,
                        stdout_limit=1024,
                        stderr_limit=1024,
                    )
                self.assertLess(time.monotonic() - started, 5)
                self.assertIsNone(escaped.exception.__cause__)
                escaped_pid = int(marker.read_text(encoding="ascii"))
            finally:
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

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

    def test_bounded_child_does_not_claim_closure_before_process_supervision(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-child-pre-supervision-") as root:
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
                mock.patch.object(runner, "run_bounded") as run_bounded,
                self.assertRaisesRegex(TimeoutError, "activation failure"),
            ):
                runner._run_bounded_child(
                    (sys.executable, "-B", "-c", "raise SystemExit(0)"),
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
                    closure_proof=closure_proof,
                )

            self.assertFalse(closure_proof.proven)
            self.assertFalse(closure_proof.started)
            run_bounded.assert_not_called()

    def test_bounded_child_isolation_preflight_failure_does_not_start(self) -> None:
        with owned_temporary_directory("readonly-child-preflight-") as root:
            closure_proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "_require_isolated_child_account",
                    side_effect=PermissionError(
                        errno.EPERM,
                        "synthetic account isolation failure",
                    ),
                ),
                mock.patch.object(runner, "run_bounded") as run_bounded,
                self.assertRaisesRegex(
                    PermissionError,
                    "account isolation failure",
                ),
            ):
                runner._run_bounded_child(
                    (sys.executable, "-B", "-c", "raise SystemExit(0)"),
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
                    closure_proof=closure_proof,
                    require_isolated_account=True,
                )

            self.assertFalse(closure_proof.started)
            self.assertFalse(closure_proof.proven)
            run_bounded.assert_not_called()

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

            closure_error = runner.GitProcessClosureUnproven(
                None,
                None,
                RuntimeError("synthetic closure failure"),
            )
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
            process_baseline = (
                runner.DarwinProcessIdentity(
                    pid=os.getpid(),
                    start_abstime=1,
                ),
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
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                    ),
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
                    side_effect=({}, FileNotFoundError("install path moved")),
                ),
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
                    "run_bounded",
                    side_effect=closure_error,
                ),
                mock.patch.object(
                    runner,
                    "_require_isolated_child_account",
                    return_value=process_baseline,
                ),
                mock.patch.object(runner, "_require_no_new_same_uid_processes"),
                mock.patch.object(
                    support._DirectoryParentBinding,
                    "current_path",
                    side_effect=OSError(
                        errno.ESTALE,
                        "synthetic F_GETPATH failure",
                    ),
                ),
                mock.patch.object(runner, "_cleanup_tree") as cleanup_tree,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(
                summary["primary_status"],
                "closure-unproven",
                summary,
            )
            self.assertEqual(summary["child_process_closure"], "unproven")
            self.assertEqual(
                summary["primary_failure"]["error_kind"],
                "GitProcessClosureUnproven",
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
            cleanup_failures = summary["cleanup_failures"]
            self.assertEqual(len(cleanup_failures), 2)
            self.assertEqual(
                [failure["retained"] for failure in cleanup_failures],
                [None, None],
            )
            self.assertEqual(
                [failure["path_status"] for failure in cleanup_failures],
                ["bound-unresolved", "bound-unresolved"],
            )
            self.assertEqual(
                [failure["original_path_status"] for failure in cleanup_failures],
                ["same", "same"],
            )
            self.assertEqual(
                [failure["recovery_evidence"] for failure in cleanup_failures],
                [None, None],
            )
            self.assertTrue(install_container.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            cleanup_tree.assert_not_called()
            deactivate.assert_called_once_with(mock.sentinel.binding)
            restore.assert_called_once_with(signal_guard)
            error_text = stderr.getvalue()
            self.assertIn("GitProcessClosureUnproven", error_text)
            self.assertIn('"retained":null', error_text)
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
            cleanup_control = runtime_home / "cleanup-control"
            cleanup_control.mkdir()
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
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
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
            self.assertEqual(summary["retained_paths"], [str(install_container)])
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
            cleanup_control = runtime_home / "cleanup-control"
            cleanup_control.mkdir()
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
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
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
                    side_effect=({}, FileNotFoundError("install path moved")),
                ),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
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
                "install-container-revalidation",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(original_install_container)],
            )
            cleanup = summary["cleanup_failures"][0]
            self.assertEqual(cleanup["original_path"], str(install_container))
            self.assertEqual(cleanup["path_status"], "bound-moved")
            self.assertEqual(cleanup["replacement_path"], str(install_container))
            self.assertTrue(original_install_container.is_dir())
            self.assertTrue(install_container.is_dir())

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
            cleanup_control = runtime_home / "cleanup-control"
            cleanup_control.mkdir()
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
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
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
            cleanup = summary["cleanup_failures"][0]
            self.assertEqual(cleanup["original_path"], str(runtime_parent))
            self.assertEqual(cleanup["path_status"], "bound-moved")
            self.assertEqual(cleanup["replacement_path"], str(runtime_parent))
            self.assertTrue(original_runtime_parent.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            self.assertIn("test runtime parent path changed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
