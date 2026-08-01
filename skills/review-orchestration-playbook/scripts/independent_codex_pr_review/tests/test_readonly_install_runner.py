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
from collections.abc import Iterator
from unittest import mock

from . import support
from . import run_readonly_install_deterministic_supervisor as runner
from .support import owned_temporary_directory


class _SignalInjectingStream:
    def __init__(
        self,
        wrapped: io.TextIOBase,
        *,
        inject_on: str,
    ) -> None:
        self._wrapped = wrapped
        self._inject_on = inject_on
        self._injected = False

    def write(self, value: str) -> int:
        if (
            self._inject_on == "output"
            and not self._injected
            and '"primary_status"' in value
        ):
            os.kill(os.getpid(), signal.SIGTERM)
            self._injected = True
        return self._wrapped.write(value)

    def flush(self) -> None:
        if self._inject_on == "flush" and not self._injected:
            os.kill(os.getpid(), signal.SIGTERM)
            self._injected = True
        self._wrapped.flush()

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


class _FailingFlushStream:
    def __init__(self, wrapped: io.TextIOBase, error: OSError) -> None:
        self._wrapped = wrapped
        self._error = error

    def write(self, value: str) -> int:
        return self._wrapped.write(value)

    def flush(self) -> None:
        raise self._error

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    @staticmethod
    def _bind_existing_directories(
        *paths: pathlib.Path,
    ) -> object:
        remaining = iter(paths)

        def create_binding(
            parent: pathlib.Path,
            _prefix: str,
            *,
            require_owned_private_parent: bool = True,
        ) -> support._CreatedPrivateDirectoryBinding:
            path = next(remaining)
            if path.parent.resolve(strict=True) != pathlib.Path(parent).resolve(
                strict=True
            ):
                raise AssertionError("synthetic binding parent mismatch")
            path.chmod(0o700)
            parent_binding = support._open_directory_parent(
                parent,
                require_owned_private_parent=require_owned_private_parent,
            )
            child_fd: int | None = None
            try:
                leaf_name = os.fsencode(path.name)
                child_fd, child_identity = support.open_directory_at(
                    parent_binding.fd,
                    leaf_name,
                    path_hint=path,
                    private=True,
                )
                child_policy = support.validate_directory_policy_fd(
                    child_fd,
                    path,
                    private=True,
                )
                binding = support._CreatedPrivateDirectoryBinding(
                    path=path,
                    parent_binding=parent_binding,
                    leaf_name=leaf_name,
                    fd=child_fd,
                    identity=child_identity,
                    policy=child_policy,
                    require_owned_private_parent=require_owned_private_parent,
                )
                binding.revalidate()
                child_fd = None
                return binding
            except BaseException:
                if child_fd is not None:
                    os.close(child_fd)
                parent_binding.close()
                raise

        return create_binding

    def _run_terminal_signal_scenario(
        self,
        root: pathlib.Path,
        *,
        inject_at: str,
        signal_number: signal.Signals | None,
        existing_primary: bool = False,
        terminal_process: bool = True,
    ) -> tuple[int, tuple[dict[str, object], ...], str]:
        sticky_parent = root / "sticky"
        sticky_parent.mkdir(mode=0o700)
        sticky_parent.chmod(0o1777)
        runtime_parent = root / "runtime"
        runtime_parent.mkdir(mode=0o700)
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            real_os_write = os.write
            try:
                os.close(stdout_read)
                os.close(stderr_read)
                os.dup2(stdout_write, 1)
                os.dup2(stderr_write, 2)
                os.close(stdout_write)
                os.close(stderr_write)
                child_stdout = os.fdopen(
                    os.dup(1),
                    "w",
                    encoding="utf-8",
                    buffering=1,
                )
                child_stderr = os.fdopen(
                    os.dup(2),
                    "w",
                    encoding="utf-8",
                    buffering=1,
                )
                terminal_stdout_fd = child_stdout.fileno()

                def inject_signal() -> None:
                    if signal_number is None:
                        return
                    os.kill(os.getpid(), signal_number)

                def copy_minimal_tree(
                    _source: pathlib.Path,
                    destination: pathlib.Path,
                    **_kwargs: object,
                ) -> pathlib.Path:
                    destination.mkdir(mode=0o700)
                    (destination / "fixture").write_text(
                        "fixture",
                        encoding="utf-8",
                    )
                    return destination

                snapshot_calls = 0

                def snapshot_tree(
                    _path: pathlib.Path,
                ) -> dict[str, runner.TreeEntrySnapshot]:
                    nonlocal snapshot_calls
                    snapshot_calls += 1
                    if existing_primary and snapshot_calls == 2:
                        raise OSError(
                            errno.EIO,
                            "synthetic existing primary failure",
                        )
                    return {}

                def run_no_child_suite(
                    *,
                    closure_proof: runner.ChildProcessClosureProof,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    closure_proof.launch_attempted = True
                    closure_proof.proven = True
                    closure_proof.runtime_profile = "production-current"
                    return subprocess.CompletedProcess(
                        args=("synthetic-no-child-suite",),
                        returncode=0,
                        stdout="",
                        stderr="",
                    )

                cleanup_calls = 0
                real_cleanup_created_tree = runner._cleanup_created_tree

                def cleanup_created_tree(
                    binding: support._CreatedPrivateDirectoryBinding | None,
                    *,
                    restore_owner_write: bool,
                ) -> runner.CleanupFailure | None:
                    nonlocal cleanup_calls
                    result = real_cleanup_created_tree(
                        binding,
                        restore_owner_write=restore_owner_write,
                    )
                    cleanup_calls += 1
                    if (
                        inject_at
                        in {
                            "pre-seal",
                            "pre-seal-existing-primary",
                            "signal-publication-failure",
                        }
                        and cleanup_calls == 2
                    ):
                        inject_signal()
                    return result

                def compare_tree_property(
                    _before: dict[str, runner.TreeEntrySnapshot],
                    _after: dict[str, runner.TreeEntrySnapshot],
                ) -> bool:
                    if inject_at in {"summary", "restore-pending"}:
                        inject_signal()
                    return True

                real_json_dumps = runner.json.dumps
                json_signal_injected = False

                def serialize_with_signal(
                    value: object,
                    *args: object,
                    **kwargs: object,
                ) -> str:
                    nonlocal json_signal_injected
                    if (
                        inject_at == "json"
                        and not json_signal_injected
                        and isinstance(value, dict)
                        and "primary_status" in value
                    ):
                        json_signal_injected = True
                        inject_signal()
                    return real_json_dumps(value, *args, **kwargs)

                stdout_write_injected = False

                def write_with_signal(
                    descriptor: int,
                    payload: bytes | bytearray | memoryview,
                ) -> int:
                    nonlocal stdout_write_injected
                    if (
                        inject_at == "newline-write-failure"
                        and descriptor == terminal_stdout_fd
                        and bytes(payload) == b"\n"
                    ):
                        raise OSError(
                            errno.EIO,
                            "synthetic terminal newline failure",
                        )
                    if (
                        inject_at == "stdout-write"
                        and descriptor == terminal_stdout_fd
                        and not stdout_write_injected
                        and len(payload) > 1
                    ):
                        partial = max(1, len(payload) // 2)
                        written = real_os_write(descriptor, payload[:partial])
                        stdout_write_injected = True
                        inject_signal()
                        return written
                    return real_os_write(descriptor, payload)

                def fail_terminal_stdout(_payload: bytes) -> None:
                    raise runner.TerminalPublicationError(
                        "stdout-write",
                        OSError(errno.EIO, "synthetic terminal write failure"),
                    )

                if inject_at == "stdout-flush":
                    child_stdout = _SignalInjectingStream(
                        child_stdout,
                        inject_on="flush",
                    )
                elif inject_at == "stdout-flush-failure":
                    child_stdout = _FailingFlushStream(
                        child_stdout,
                        OSError(errno.EIO, "synthetic stdout flush failure"),
                    )
                if inject_at == "stderr-flush":
                    child_stderr = _SignalInjectingStream(
                        child_stderr,
                        inject_on="flush",
                    )
                elif inject_at == "stderr-flush-failure":
                    child_stderr = _FailingFlushStream(
                        child_stderr,
                        OSError(errno.EIO, "synthetic stderr flush failure"),
                    )

                with contextlib.ExitStack() as patches:
                    patches.enter_context(
                        mock.patch.object(runner.sys, "platform", "darwin")
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner.sys,
                            "stdout",
                            child_stdout,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner.sys,
                            "stderr",
                            child_stderr,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "READONLY_INSTALL_PARENT",
                            sticky_parent,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_private_runtime_parent",
                            return_value=runtime_parent,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner.shutil,
                            "copytree",
                            side_effect=copy_minimal_tree,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_set_tree_read_only",
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_tree_snapshot",
                            side_effect=snapshot_tree,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_run_no_child_test_suite",
                            side_effect=run_no_child_suite,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_cleanup_created_tree",
                            side_effect=cleanup_created_tree,
                        )
                    )
                    patches.enter_context(
                        mock.patch.object(
                            runner,
                            "_tree_property_unchanged",
                            side_effect=compare_tree_property,
                        )
                    )
                    if inject_at == "json":
                        patches.enter_context(
                            mock.patch.object(
                                runner.json,
                                "dumps",
                                side_effect=serialize_with_signal,
                            )
                        )
                    if inject_at in {"stdout-write", "newline-write-failure"}:
                        patches.enter_context(
                            mock.patch.object(
                                runner.os,
                                "write",
                                side_effect=write_with_signal,
                            )
                        )
                    if inject_at in {
                        "stdout-write-failure",
                        "signal-publication-failure",
                    }:
                        patches.enter_context(
                            mock.patch.object(
                                runner,
                                "_write_terminal_stdout",
                                side_effect=fail_terminal_stdout,
                            )
                        )
                    exit_code = runner.main(
                        _terminal_process=terminal_process,
                    )
                os._exit(exit_code)
            except BaseException as error:
                diagnostic = (
                    "terminal signal scenario child failed: "
                    f"{type(error).__name__}: {error}\n"
                )
                try:
                    real_os_write(2, diagnostic.encode("utf-8"))
                finally:
                    os._exit(250)

        os.close(stdout_write)
        os.close(stderr_write)
        deadline = time.monotonic() + 10
        child_status: int | None = None
        while time.monotonic() < deadline:
            waited_pid, status = os.waitpid(child_pid, os.WNOHANG)
            if waited_pid == child_pid:
                child_status = status
                break
            time.sleep(0.01)
        if child_status is None:
            os.kill(child_pid, signal.SIGKILL)
            os.waitpid(child_pid, 0)
            self.fail(f"terminal signal scenario timed out: {inject_at}")

        def read_all(descriptor: int) -> bytes:
            chunks: list[bytes] = []
            try:
                while chunk := os.read(descriptor, 65_536):
                    chunks.append(chunk)
            finally:
                os.close(descriptor)
            return b"".join(chunks)

        stdout = read_all(stdout_read).decode("utf-8", errors="replace")
        stderr = read_all(stderr_read).decode("utf-8", errors="replace")
        summaries: list[dict[str, object]] = []
        for line in stdout.splitlines():
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and "primary_status" in candidate:
                summaries.append(candidate)
        self.assertEqual(tuple(sticky_parent.iterdir()), ())
        self.assertEqual(tuple(runtime_parent.iterdir()), ())
        return (
            os.waitstatus_to_exitcode(child_status),
            tuple(summaries),
            stderr,
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
                self.assertRaises(
                    support.UnprovenCreatedDirectoryError,
                ) as caught,
            ):
                support._create_owned_private_directory_binding(
                    parent,
                    ".new-child-",
                )

            self.assertIsInstance(caught.exception.error, ValueError)
            self.assertIn("extended", str(caught.exception.error))
            self.assertIn("forbidden", str(caught.exception.error))
            retained = tuple(parent.iterdir())
            self.assertEqual(len(retained), 1)
            self.assertTrue(retained[0].is_dir())
            self.assertTrue(
                caught.exception.recovery_locator.startswith("parent-directory://")
            )
            if sys.platform == "darwin":
                subprocess.run(
                    ("/bin/chmod", "-N", str(retained[0])),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=5,
                )
            retained[0].rmdir()

    def test_private_directory_creation_normalizes_restrictive_umask(self) -> None:
        with owned_temporary_directory("runtime-child-umask-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)

            previous_umask = os.umask(0o177)
            try:
                binding = support._create_owned_private_directory_binding(
                    parent,
                    ".new-child-",
                )
            finally:
                os.umask(previous_umask)

            try:
                self.assertEqual(
                    stat.S_IMODE(binding.path.stat(follow_symlinks=False).st_mode),
                    0o700,
                )
            finally:
                support._cleanup_created_private_directory_binding(binding)
                binding.close()

            previous_umask = os.umask(0o777)
            try:
                with self.assertRaises(
                    support.UnprovenCreatedDirectoryError,
                ) as caught:
                    support._create_owned_private_directory_binding(
                        parent,
                        ".new-child-",
                    )
            finally:
                os.umask(previous_umask)

            self.assertIsInstance(caught.exception.error, PermissionError)
            self.assertEqual(caught.exception.errno, errno.EACCES)
            self.assertTrue(
                caught.exception.recovery_locator.startswith("parent-directory://")
            )
            retained = caught.exception.untrusted_path_hint
            self.assertEqual(retained.parent, parent)
            retained.chmod(0o700)
            retained.rmdir()

    def test_private_directory_binding_rejects_replacement_before_open(self) -> None:
        with owned_temporary_directory("runtime-child-bind-race-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            original = parent / "original-created-directory"
            replacement: pathlib.Path | None = None
            real_open_directory_at = support.open_directory_at
            replaced = False

            def replace_before_open(
                parent_fd: int,
                name: bytes,
                *,
                path_hint: pathlib.Path,
                private: bool,
            ) -> tuple[int, object]:
                nonlocal replaced, replacement
                if replaced:
                    return real_open_directory_at(
                        parent_fd,
                        name,
                        path_hint=path_hint,
                        private=private,
                    )
                replaced = True
                replacement = parent / os.fsdecode(name)
                replacement.rename(original)
                replacement.mkdir(mode=0o700)
                (replacement / "sentinel").write_text(
                    "replacement",
                    encoding="utf-8",
                )
                return real_open_directory_at(
                    parent_fd,
                    name,
                    path_hint=path_hint,
                    private=private,
                )

            with (
                mock.patch.object(
                    support,
                    "open_directory_at",
                    side_effect=replace_before_open,
                ),
                self.assertRaises(
                    support.UnprovenCreatedDirectoryError,
                ) as caught,
            ):
                support._create_owned_private_directory_binding(
                    parent,
                    ".new-child-",
                )

            self.assertIsInstance(caught.exception.error, OSError)
            self.assertEqual(caught.exception.errno, errno.ESTALE)
            self.assertIn("not empty at first open", str(caught.exception.error))
            self.assertIsNotNone(replacement)
            assert replacement is not None
            self.assertTrue(original.is_dir())
            self.assertTrue(replacement.is_dir())
            self.assertEqual(
                (replacement / "sentinel").read_text(encoding="utf-8"),
                "replacement",
            )
            notes = getattr(caught.exception, "__notes__", ())
            self.assertTrue(
                any("recovery_locator=parent-directory://" in note for note in notes)
            )
            self.assertTrue(any("untrusted_path_hint=" in note for note in notes))
            (replacement / "sentinel").unlink()
            replacement.rmdir()
            original.rmdir()

    def test_unproven_creation_preserves_close_secondary_evidence(self) -> None:
        with owned_temporary_directory("runtime-child-close-evidence-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            child_fd: int | None = None
            close_failure_injected = False
            real_close = support.os.close

            def reject_origin(
                _parent_binding: support._DirectoryParentBinding,
                _name: bytes,
                _child_path: pathlib.Path,
                descriptor: int,
                _first_open_identity: object,
            ) -> tuple[object, object]:
                nonlocal child_fd
                child_fd = descriptor
                raise OSError(errno.ESTALE, "synthetic origin failure")

            def close_then_fail(descriptor: int) -> None:
                nonlocal close_failure_injected
                real_close(descriptor)
                if descriptor == child_fd and not close_failure_injected:
                    close_failure_injected = True
                    raise OSError(errno.EIO, "synthetic child close failure")

            with (
                mock.patch.object(
                    support,
                    "_normalize_created_private_directory_mode",
                    side_effect=reject_origin,
                ),
                mock.patch.object(
                    support.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(
                    support.UnprovenCreatedDirectoryError,
                ) as caught,
            ):
                support._create_owned_private_directory_binding(
                    parent,
                    ".new-child-",
                )

            self.assertEqual(caught.exception.errno, errno.ESTALE)
            self.assertTrue(close_failure_injected)
            self.assertTrue(
                any(
                    "created-directory child binding close failed" in note
                    and "synthetic child close failure" in note
                    for note in getattr(caught.exception, "__notes__", ())
                )
            )
            retained = caught.exception.untrusted_path_hint
            self.assertTrue(retained.is_dir())
            retained.rmdir()

    def test_retention_locators_preserve_primary_when_probes_fail(self) -> None:
        with owned_temporary_directory("runtime-locator-primary-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            parent_binding = support._open_directory_parent(
                parent,
                require_owned_private_parent=True,
            )
            try:
                with mock.patch.object(
                    support.os,
                    "fstat",
                    side_effect=OSError(
                        errno.EIO,
                        "synthetic locator fstat failure",
                    ),
                ) as fstat:
                    locator = support._unproven_created_directory_locator(
                        parent_binding,
                        b"synthetic-leaf",
                    )
                fstat.assert_not_called()
                self.assertEqual(
                    locator,
                    "parent-directory://"
                    f"{parent_binding.identity.device}/"
                    f"{parent_binding.identity.inode}/"
                    f"leaf/{b'synthetic-leaf'.hex()}",
                )
            finally:
                parent_binding.close()

            binding = support._create_owned_private_directory_binding(
                parent,
                ".new-child-",
            )
            primary = OSError(errno.ESTALE, "synthetic cleanup mismatch")
            try:
                with (
                    mock.patch.object(
                        runner,
                        "_cleanup_created_private_directory_binding",
                        side_effect=primary,
                    ),
                    mock.patch.object(
                        runner.os,
                        "fstat",
                        side_effect=OSError(
                            errno.EIO,
                            "synthetic retention probe failure",
                        ),
                    ),
                ):
                    failure = runner._cleanup_created_tree(
                        binding,
                        restore_owner_write=False,
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.error_errno, errno.ESTALE)
                self.assertEqual(
                    failure.path,
                    "descriptor-object://"
                    f"{binding.identity.device}/{binding.identity.inode}",
                )
                self.assertTrue(failure.retained)
                self.assertTrue(
                    any(
                        "retention locator fell back to recorded identity" in note
                        and "synthetic retention probe failure" in note
                        for note in getattr(primary, "__notes__", ())
                    )
                )
                support._cleanup_created_private_directory_binding(binding)
            finally:
                binding.close()

            rebound_parent = root / "rebound-parent"
            rebound_parent.mkdir(mode=0o700)
            original_parent = root / "original-parent"
            rebound_binding = support._open_directory_parent(
                rebound_parent,
                require_owned_private_parent=True,
            )
            reopened_fd: int | None = None
            real_open = support.open_absolute_directory_chain
            real_close = support.os.close

            def capture_reopened(
                *args: object,
                **kwargs: object,
            ) -> tuple[int, object]:
                nonlocal reopened_fd
                result = real_open(*args, **kwargs)
                reopened_fd = result[0]
                return result

            def close_then_fail(descriptor: int) -> None:
                real_close(descriptor)
                if descriptor == reopened_fd:
                    raise OSError(
                        errno.EIO,
                        "synthetic parent revalidation close failure",
                    )

            rebound_parent.rename(original_parent)
            rebound_parent.mkdir(mode=0o700)
            try:
                with (
                    mock.patch.object(
                        support,
                        "open_absolute_directory_chain",
                        side_effect=capture_reopened,
                    ),
                    mock.patch.object(
                        support.os,
                        "close",
                        side_effect=close_then_fail,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    rebound_binding.revalidate()
                self.assertEqual(caught.exception.errno, errno.ESTALE)
                self.assertTrue(
                    any(
                        "test runtime parent revalidation close failed" in note
                        and "synthetic parent revalidation close failure" in note
                        for note in getattr(caught.exception, "__notes__", ())
                    )
                )
            finally:
                rebound_binding.close()
                rebound_parent.rmdir()
                original_parent.rmdir()

    def test_created_cleanup_retains_observed_root_replacement(self) -> None:
        with owned_temporary_directory("runtime-created-cleanup-race-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            binding = support._create_owned_private_directory_binding(
                parent,
                ".new-child-",
            )
            escaped = parent / "escaped-created-directory"
            replacement: pathlib.Path | None = None
            real_verify = support._verify_staged_cleanup_entry
            replacement_injected = False

            def replace_after_first_verification(
                parent_fd: int,
                staged_name: str | bytes,
                descriptor: int,
                expected_path: pathlib.Path,
            ) -> None:
                nonlocal replacement, replacement_injected
                real_verify(
                    parent_fd,
                    staged_name,
                    descriptor,
                    expected_path,
                )
                if replacement_injected:
                    return
                replacement_injected = True
                os.rename(
                    staged_name,
                    escaped.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.mkdir(staged_name, mode=0o700, dir_fd=parent_fd)
                replacement = parent / os.fsdecode(staged_name)
                (replacement / "sentinel").write_text(
                    "replacement",
                    encoding="utf-8",
                )

            try:
                with (
                    mock.patch.object(
                        support,
                        "_verify_staged_cleanup_entry",
                        side_effect=replace_after_first_verification,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    support._cleanup_created_private_directory_binding(binding)

                self.assertEqual(caught.exception.errno, errno.ESTALE)
                self.assertTrue(replacement_injected)
                self.assertTrue(escaped.is_dir())
                self.assertIsNotNone(replacement)
                assert replacement is not None
                self.assertEqual(
                    (replacement / "sentinel").read_text(encoding="utf-8"),
                    "replacement",
                )
            finally:
                binding.close()
                if replacement is not None and replacement.exists():
                    (replacement / "sentinel").unlink()
                    replacement.rmdir()
                if escaped.exists():
                    escaped.rmdir()

    def test_bound_cleanup_preserves_nested_estale_over_close_failure(self) -> None:
        with owned_temporary_directory("runtime-created-nested-close-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            binding = support._create_owned_private_directory_binding(
                parent,
                ".new-child-",
            )
            (binding.path / "nested").mkdir(mode=0o700)
            entry_fd: int | None = None
            close_failure_injected = False
            real_close = support.os.close

            def reject_staged_entry(
                _parent_fd: int,
                _staged_name: str | bytes,
                descriptor: int,
                _expected_path: pathlib.Path,
            ) -> None:
                nonlocal entry_fd
                entry_fd = descriptor
                raise OSError(errno.ESTALE, "synthetic nested entry mismatch")

            def close_then_fail(descriptor: int) -> None:
                nonlocal close_failure_injected
                real_close(descriptor)
                if descriptor == entry_fd and not close_failure_injected:
                    close_failure_injected = True
                    raise OSError(errno.EIO, "synthetic nested close failure")

            try:
                with (
                    mock.patch.object(
                        support,
                        "_verify_staged_cleanup_entry",
                        side_effect=reject_staged_entry,
                    ),
                    mock.patch.object(
                        support.os,
                        "close",
                        side_effect=close_then_fail,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    support._remove_bound_directory_contents(
                        binding.fd,
                        binding.path,
                        restore_owner_write=False,
                    )

                self.assertEqual(caught.exception.errno, errno.ESTALE)
                self.assertTrue(close_failure_injected)
                self.assertTrue(
                    any(
                        "bound cleanup entry close failed" in note
                        and "synthetic nested close failure" in note
                        for note in getattr(caught.exception, "__notes__", ())
                    )
                )
                support._remove_bound_directory_contents(
                    binding.fd,
                    binding.path,
                    restore_owner_write=False,
                )
                support._cleanup_created_private_directory_binding(binding)
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

            sealed_fence = runner.LifecycleSignalFence(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                terminal_signal=signal.SIGTERM,
                terminal_selected_signal=signal.SIGTERM,
                terminal_exit_code=128 + signal.SIGTERM,
                terminal_decision_frozen=True,
            )
            publication_error = runner.TerminalPublicationError(
                "stdout-write",
                OSError(errno.EIO, "synthetic publication failure"),
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
                    return_value=sealed_fence,
                ),
                mock.patch.object(
                    runner,
                    "_run_main",
                    side_effect=publication_error,
                ),
                mock.patch.object(
                    runner,
                    "_restore_lifecycle_signal_fence",
                    side_effect=OSError(
                        errno.EIO,
                        "synthetic restore failure",
                    ),
                ),
                mock.patch.object(
                    runner,
                    "_report_terminal_publication_failure",
                ) as report_failure,
            ):
                self.assertEqual(runner.main(), 128 + signal.SIGTERM)
            self.assertEqual(report_failure.call_count, 2)

            no_signal_fence = runner.LifecycleSignalFence(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                terminal_exit_code=0,
                terminal_decision_frozen=True,
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
                    return_value=no_signal_fence,
                ),
                mock.patch.object(
                    runner,
                    "_run_main",
                    side_effect=publication_error,
                ),
                mock.patch.object(
                    runner,
                    "_restore_lifecycle_signal_fence",
                    side_effect=OSError(
                        errno.EIO,
                        "synthetic restore failure",
                    ),
                ),
                mock.patch.object(
                    runner,
                    "_report_terminal_publication_failure",
                ),
            ):
                self.assertEqual(runner.main(), 1)

    def test_terminal_signal_publication_is_linearized_in_a_real_process(
        self,
    ) -> None:
        success_scenarios = (
            (
                "pre-seal",
                signal.SIGTERM,
                False,
                True,
                "interrupted",
                signal.SIGTERM,
                128 + signal.SIGTERM,
            ),
            (
                "pre-seal-existing-primary",
                signal.SIGHUP,
                True,
                True,
                "failed",
                signal.SIGHUP,
                128 + signal.SIGHUP,
            ),
            ("summary", signal.SIGINT, False, True, "complete", None, 0),
            ("json", signal.SIGQUIT, False, True, "complete", None, 0),
            ("stdout-write", signal.SIGTERM, False, True, "complete", None, 0),
            ("stdout-flush", signal.SIGHUP, False, True, "complete", None, 0),
            ("stderr-flush", signal.SIGINT, False, True, "complete", None, 0),
            (
                "newline-write-failure",
                None,
                False,
                True,
                "complete",
                None,
                0,
            ),
            ("restore-pending", signal.SIGQUIT, False, False, "complete", None, 0),
        )
        for (
            inject_at,
            signal_number,
            existing_primary,
            terminal_process,
            primary_status,
            sealed_signal,
            expected_exit,
        ) in success_scenarios:
            with (
                self.subTest(inject_at=inject_at),
                owned_temporary_directory(f"terminal-signal-{inject_at}-") as root,
            ):
                exit_code, summaries, stderr = self._run_terminal_signal_scenario(
                    root,
                    inject_at=inject_at,
                    signal_number=signal_number,
                    existing_primary=existing_primary,
                    terminal_process=terminal_process,
                )
                self.assertEqual(exit_code, expected_exit, stderr)
                self.assertEqual(len(summaries), 1, (summaries, stderr))
                summary = summaries[0]
                self.assertEqual(summary["primary_status"], primary_status)
                self.assertEqual(summary["signal_number"], sealed_signal)
                self.assertEqual(summary["cleanup_status"], "complete")
                self.assertEqual(summary["retained_paths"], [])
                self.assertEqual(summary["runtime_residue"], [])
                self.assertEqual(summary["secondary_failures"], [])
                self.assertFalse(summary["creation_origin_proven"])
                self.assertEqual(
                    summary["creation_origin_guarantee"],
                    support.CREATION_ORIGIN_GUARANTEE,
                )
                self.assertEqual(
                    summary["cleanup_guarantee"],
                    support.CLEANUP_GUARANTEE,
                )
                if sealed_signal is None:
                    self.assertEqual(exit_code, 0)
                else:
                    self.assertEqual(exit_code, 128 + sealed_signal)
                if inject_at == "newline-write-failure":
                    self.assertIn("operation=stdout-newline", stderr)

        failure_scenarios = (
            ("stdout-write-failure", None, 1),
            ("stdout-flush-failure", None, 1),
            ("stderr-flush-failure", None, 1),
            (
                "signal-publication-failure",
                signal.SIGTERM,
                128 + signal.SIGTERM,
            ),
        )
        for inject_at, signal_number, expected_exit in failure_scenarios:
            with (
                self.subTest(inject_at=inject_at),
                owned_temporary_directory(f"terminal-failure-{inject_at}-") as root,
            ):
                exit_code, summaries, stderr = self._run_terminal_signal_scenario(
                    root,
                    inject_at=inject_at,
                    signal_number=signal_number,
                )
                self.assertEqual(exit_code, expected_exit, stderr)
                self.assertEqual(summaries, ())
                self.assertIn("terminal publication failed", stderr)

    def test_no_child_suite_python_startup_ignores_site_injection(self) -> None:
        with owned_temporary_directory("readonly-startup-isolation-") as root:
            path_payload = root / "python-path"
            path_payload.mkdir(mode=0o700)
            site_marker = root / "sitecustomize-ran"
            (path_payload / "sitecustomize.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(site_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )

            user_base = root / "user-base"
            user_site = user_base / "lib" / "python3.13" / "site-packages"
            user_site.mkdir(parents=True, mode=0o700)
            pth_marker = root / "pth-ran"
            (user_site / "startup-injection.pth").write_text(
                f"import pathlib; pathlib.Path({str(pth_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )

            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(path_payload)
            environment["PYTHONUSERBASE"] = str(user_base)
            result = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    "import sys; assert sys.flags.isolated and sys.flags.no_site",
                ),
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(site_marker.exists())
            self.assertFalse(pth_marker.exists())

    def test_snapshot_binds_acl_and_xattr_evidence(self) -> None:
        with owned_temporary_directory("readonly-snapshot-policy-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            target_inode = target.stat().st_ino
            acl_entries: dict[int, tuple[bytes, ...]] = {}
            xattrs: dict[int, tuple[tuple[bytes, str], ...]] = {}

            with (
                mock.patch.object(
                    runner,
                    "_acl_entries",
                    side_effect=lambda descriptor: acl_entries.get(
                        os.fstat(descriptor).st_ino,
                        (),
                    ),
                ),
                mock.patch.object(
                    runner,
                    "_xattr_snapshot",
                    side_effect=lambda descriptor: xattrs.get(
                        os.fstat(descriptor).st_ino,
                        (),
                    ),
                ),
            ):
                baseline = runner._tree_snapshot(root)
                acl_entries[target_inode] = (b" 0: user:synthetic allow write",)
                acl_changed = runner._tree_snapshot(root)
                acl_entries.clear()
                xattrs[target_inode] = ((b"com.apple.synthetic", "digest"),)
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

    def test_snapshot_rejects_path_replacement_during_descriptor_capture(
        self,
    ) -> None:
        with (
            owned_temporary_directory("readonly-snapshot-path-race-") as root,
            owned_temporary_directory("readonly-snapshot-replacement-") as outside,
        ):
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            target.chmod(0o444)
            target_inode = target.stat().st_ino
            replacement = outside / "replacement"
            replacement.write_text("content", encoding="utf-8")
            replacement.chmod(0o444)
            original_sample = runner._stable_regular_entry_sample
            replaced = False

            def replace_after_descriptor_read(
                descriptor: int,
            ) -> tuple[
                str,
                tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
            ]:
                nonlocal replaced
                sample = original_sample(descriptor)
                if not replaced and os.fstat(descriptor).st_ino == target_inode:
                    os.replace(replacement, target)
                    replaced = True
                return sample

            with (
                mock.patch.object(
                    runner,
                    "_stable_regular_entry_sample",
                    side_effect=replace_after_descriptor_read,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "snapshot (object changed|path no longer names)",
                ),
            ):
                runner._tree_snapshot_once(root)

            self.assertTrue(replaced)
            self.assertNotEqual(target_inode, target.stat().st_ino)

    def test_snapshot_rejects_same_inode_same_length_content_mutation(
        self,
    ) -> None:
        for mutation_point in ("after-content-read", "during-access-policy-read"):
            with (
                self.subTest(mutation_point=mutation_point),
                owned_temporary_directory("readonly-snapshot-content-race-") as root,
            ):
                target = root / "target"
                target.write_bytes(b"content")
                target_inode = target.stat().st_ino
                mutated = False
                if mutation_point == "after-content-read":
                    original_sample = runner._descriptor_digest

                    def mutate_after_sample(descriptor: int) -> str:
                        nonlocal mutated
                        sample = original_sample(descriptor)
                        if not mutated and os.fstat(descriptor).st_ino == target_inode:
                            target.write_bytes(b"changed")
                            mutated = True
                        return sample

                    patch_name = "_descriptor_digest"
                else:
                    original_sample = runner._stable_access_policy_snapshot

                    def mutate_after_sample(
                        descriptor: int,
                    ) -> tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]]:
                        nonlocal mutated
                        sample = original_sample(descriptor)
                        if not mutated and os.fstat(descriptor).st_ino == target_inode:
                            target.write_bytes(b"changed")
                            mutated = True
                        return sample

                    patch_name = "_stable_access_policy_snapshot"

                with (
                    mock.patch.object(
                        runner,
                        patch_name,
                        side_effect=mutate_after_sample,
                    ),
                    self.assertRaisesRegex(
                        OSError,
                        "regular file changed during snapshot",
                    ),
                ):
                    runner._tree_snapshot_once(root)

                self.assertTrue(mutated)
                self.assertEqual(target.stat().st_ino, target_inode)
                self.assertEqual(target.read_bytes(), b"changed")

    def test_snapshot_ignores_timestamp_churn_during_descriptor_capture(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-snapshot-timestamp-race-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            target_inode = target.stat().st_ino
            original_sample = runner._regular_entry_sample
            churned = False

            def churn_timestamp_after_descriptor_read(
                descriptor: int,
            ) -> tuple[
                str,
                tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
            ]:
                nonlocal churned
                sample = original_sample(descriptor)
                if not churned and os.fstat(descriptor).st_ino == target_inode:
                    prior = target.stat().st_mtime_ns
                    os.utime(target, ns=(prior + 1_000_000_000,) * 2)
                    churned = True
                return sample

            with mock.patch.object(
                runner,
                "_regular_entry_sample",
                side_effect=churn_timestamp_after_descriptor_read,
            ):
                snapshot = runner._tree_snapshot_once(root)

            self.assertTrue(churned)
            self.assertEqual(
                snapshot[target.name].digest,
                runner.hashlib.sha256(b"content").hexdigest(),
            )

    def test_snapshot_rejects_symlink_without_bound_target_primitive(self) -> None:
        with owned_temporary_directory("readonly-snapshot-symlink-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            (root / "alias").symlink_to(target.name)

            with self.assertRaisesRegex(
                OSError,
                "symlinks are unsupported",
            ):
                runner._tree_snapshot_once(root)

    def test_snapshot_walk_remains_bound_when_root_path_is_swapped(self) -> None:
        with owned_temporary_directory("readonly-snapshot-root-binding-") as parent:
            root = parent / "root"
            root.mkdir()
            (root / "target").write_text("original", encoding="utf-8")
            alternate = parent / "alternate"
            alternate.mkdir()
            (alternate / "target").write_text("alternate", encoding="utf-8")
            parked = parent / "parked"
            root_inode = root.stat().st_ino
            original_open = runner._open_snapshot_entry
            swapped = False

            def swap_root_around_child_open(
                parent_descriptor: int,
                name: str,
            ) -> tuple[int, os.stat_result]:
                nonlocal swapped
                if not swapped and os.fstat(parent_descriptor).st_ino == root_inode:
                    os.rename(root, parked)
                    os.rename(alternate, root)
                    try:
                        result = original_open(parent_descriptor, name)
                    finally:
                        os.rename(root, alternate)
                        os.rename(parked, root)
                    swapped = True
                    return result
                return original_open(parent_descriptor, name)

            with mock.patch.object(
                runner,
                "_open_snapshot_entry",
                side_effect=swap_root_around_child_open,
            ):
                snapshot = runner._tree_snapshot_once(root)

            self.assertTrue(swapped)
            self.assertEqual(
                snapshot["target"].digest,
                runner.hashlib.sha256(b"original").hexdigest(),
            )

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
    def _prepared_profile(
        path: str = (
            "/synthetic/Frameworks/Python.framework/Versions/3.13/"
            "Resources/Python.app/Contents/MacOS/Python"
        ),
    ) -> mock.Mock:
        return mock.Mock(sandboxed_target=mock.Mock(path=path))

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

        hosted_environments = (
            {"GITHUB_ACTIONS": "true"},
            {
                runner.RUNNER_ENVIRONMENT_ENV: "github-hosted",
                runner.RUNNER_ARCH_ENV: "ARM64",
            },
            {runner.RUNNER_ENVIRONMENT_ENV: "github-hosted"},
        )
        for environment in hosted_environments:
            with (
                self.subTest(environment=environment),
                mock.patch.dict(runner.os.environ, environment, clear=True),
                self.assertRaisesRegex(
                    RuntimeError,
                    "forbidden under GitHub Actions",
                ),
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

        with (
            self.subTest(case="missing-sandboxed-target"),
            self._bound_no_child_roots("readonly-no-child-missing-target-") as roots,
        ):
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            prepared = mock.Mock(sandboxed_target=None)
            with (
                mock.patch.object(
                    runner,
                    "_select_no_child_runtime_profile",
                    return_value=("synthetic-runtime", mock.sentinel.runtime_pin),
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=prepared,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                ) as run_bounded_command,
                self.assertRaisesRegex(
                    RuntimeError,
                    "lacks a bound Python target",
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

            self.assertFalse(proof.launch_attempted)
            self.assertFalse(proof.proven)
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
                    return_value=self._prepared_profile(),
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
            self.assertEqual(
                argv[0],
                "/synthetic/Frameworks/Python.framework/Versions/3.13/"
                "Resources/Python.app/Contents/MacOS/Python",
            )
            self.assertNotEqual(argv[0], sys.executable)
            self.assertEqual(argv[1:5], ("-I", "-S", "-B", "-c"))
            self.assertIn("not sys.flags.isolated", argv[5])
            self.assertIn("not sys.flags.no_site", argv[5])
            self.assertIn("os.environ['TMPDIR']=sys.argv[2]", argv[5])
            self.assertIn("tempfile.tempdir=sys.argv[2]", argv[5])
            self.assertEqual(
                run_bounded_command.call_args.kwargs["max_stdout_bytes"],
                1024,
            )
            self.assertEqual(
                run_bounded_command.call_args.kwargs["max_stderr_bytes"],
                1024,
            )

    def test_no_child_suite_rejects_process_group_only_closure(self) -> None:
        with self._bound_no_child_roots("readonly-no-child-forged-") as roots:
            installed_root, install_binding, runtime_binding = roots
            proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    return_value=self._prepared_profile(),
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
                    return_value=self._prepared_profile(),
                ),
                mock.patch.object(
                    runner,
                    "run_bounded_command",
                    return_value=self._no_child_result(stdout=b"x" * 1025),
                ),
                self.assertRaisesRegex(
                    runner.ChildOutputLimitExceeded,
                    "stdout output exceeded",
                ) as caught,
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
            self.assertEqual(caught.exception.scope, "stdout")
            self.assertEqual(caught.exception.limit, 1024)

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
                    return_value=self._prepared_profile(),
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
            output_error = runner.BoundedCommandOutputLimitExceeded(
                scope="stderr",
                limit=2048,
            )
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
                    return_value=self._prepared_profile(),
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
                self.assertRaisesRegex(
                    runner.ChildOutputLimitExceeded,
                    "stderr output exceeded",
                ) as caught,
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
            self.assertEqual(caught.exception.scope, "stderr")
            self.assertEqual(caught.exception.limit, 2048)
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
                    return_value=self._prepared_profile(),
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
                    return_value=self._prepared_profile(),
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
                    return_value=self._prepared_profile(),
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
                    "_create_owned_private_directory_binding",
                    side_effect=self._bind_existing_directories(
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
                    return_value=self._prepared_profile(),
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
                    "_create_owned_private_directory_binding",
                    side_effect=self._bind_existing_directories(
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
                    "_cleanup_created_tree",
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

    def test_main_retains_post_create_replacements_without_touching_them(
        self,
    ) -> None:
        for target in ("install", "runtime"):
            with (
                self.subTest(target=target),
                owned_temporary_directory(
                    f"readonly-main-post-create-{target}-"
                ) as root,
            ):
                sticky_parent = root / "sticky"
                sticky_parent.mkdir(mode=0o700)
                sticky_parent.chmod(0o1777)
                install_container = sticky_parent / "install"
                install_container.mkdir(mode=0o700)
                runtime_home = root / "runtime-home"
                runtime_home.mkdir(mode=0o700)
                runtime_parent = runtime_home / "runtime"
                runtime_parent.mkdir(mode=0o700)
                target_path = (
                    install_container if target == "install" else runtime_parent
                )
                original = target_path.parent / f"original-{target}"
                replacement_sentinel = b"replacement must survive"
                factory = self._bind_existing_directories(
                    install_container,
                    runtime_parent,
                )
                creation_index = 0
                real_binding_close = support._CreatedPrivateDirectoryBinding.close

                def create_then_replace(
                    parent: pathlib.Path,
                    prefix: str,
                    *,
                    require_owned_private_parent: bool = True,
                ) -> support._CreatedPrivateDirectoryBinding:
                    nonlocal creation_index
                    binding = factory(
                        parent,
                        prefix,
                        require_owned_private_parent=require_owned_private_parent,
                    )
                    current = "install" if creation_index == 0 else "runtime"
                    creation_index += 1
                    if current == target:
                        binding.path.rename(original)
                        binding.path.mkdir(mode=0o700)
                        (binding.path / "sentinel").write_bytes(replacement_sentinel)
                    return binding

                def fake_copytree(
                    _source: pathlib.Path,
                    destination: pathlib.Path,
                    **_kwargs: object,
                ) -> pathlib.Path:
                    pathlib.Path(destination).mkdir()
                    return pathlib.Path(destination)

                def close_with_target_failure(
                    binding: support._CreatedPrivateDirectoryBinding,
                ) -> None:
                    real_binding_close(binding)
                    if binding.path == target_path:
                        raise OSError(
                            errno.EIO,
                            "synthetic target binding close failure",
                        )

                completed = subprocess.CompletedProcess(
                    args=("python3",),
                    returncode=0,
                    stdout="",
                    stderr="",
                )

                def validate_before_completion(
                    **kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    install_binding = kwargs["install_container_binding"]
                    runtime_binding = kwargs["runtime_parent_binding"]
                    assert isinstance(
                        install_binding,
                        support._CreatedPrivateDirectoryBinding,
                    )
                    assert isinstance(
                        runtime_binding,
                        support._CreatedPrivateDirectoryBinding,
                    )
                    install_binding.revalidate()
                    runtime_binding.revalidate()
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
                        "_create_owned_private_directory_binding",
                        side_effect=create_then_replace,
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
                        side_effect=validate_before_completion,
                    ),
                    mock.patch.object(
                        support._CreatedPrivateDirectoryBinding,
                        "close",
                        autospec=True,
                        side_effect=close_with_target_failure,
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = runner.main()

                summary = json.loads(stdout.getvalue())
                self.assertEqual(returncode, 1)
                self.assertEqual(summary["primary_status"], "failed")
                self.assertEqual(
                    summary["primary_failure"]["error_errno"],
                    errno.ESTALE,
                )
                self.assertEqual(
                    summary["primary_failure"]["stage"],
                    "install-copy" if target == "install" else "child-run",
                )
                self.assertEqual(summary["cleanup_status"], "incomplete")
                self.assertEqual(summary["retained_paths"], [str(original)])
                self.assertNotIn(str(target_path), summary["retained_paths"])
                self.assertTrue(
                    any(
                        failure["error_kind"] == "OSError"
                        and failure["error_errno"] == errno.EIO
                        and failure["path"] == str(original)
                        for failure in summary["cleanup_failures"]
                    )
                )
                self.assertTrue(original.is_dir())
                self.assertEqual(
                    (target_path / "sentinel").read_bytes(),
                    replacement_sentinel,
                )
                self.assertIn(
                    "parent-relative binding changed",
                    stderr.getvalue(),
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
                    "_create_owned_private_directory_binding",
                    side_effect=self._bind_existing_directories(
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
            self.assertIn(
                "created private directory parent-relative binding changed",
                stderr.getvalue(),
            )

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
                    "_create_owned_private_directory_binding",
                    side_effect=self._bind_existing_directories(
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
            self.assertIn(
                "created private directory parent-relative binding changed",
                stderr.getvalue(),
            )


if __name__ == "__main__":
    unittest.main()
