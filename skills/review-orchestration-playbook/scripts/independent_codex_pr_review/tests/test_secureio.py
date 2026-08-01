from __future__ import annotations

import errno
import fcntl
import os
import pathlib
import signal
import stat
import unittest
from unittest import mock

import review_supervisor.ledger as ledger_module
import review_supervisor.secureio as secureio_module
from review_supervisor.codex_executable import ExtendedMetadataEvidence
from review_supervisor.errors import SupervisorError
from review_supervisor.ledger import acquire_retention_lease
from review_supervisor.models import Identity
from review_supervisor.secureio import (
    _open_darwin_boot_marker_parent,
    _require_trusted_boot_marker_metadata,
    _require_trusted_boot_parent_metadata,
    _read_darwin_boot_session_marker,
    _verify_macos_metadata,
    atomic_write_json,
    canonical_json,
    decode_json_bytes,
    directory_paths_equivalent,
    open_absolute_directory_chain,
    open_directory_at,
    open_regular_at,
    open_regular_nofollow,
    require_private_directory,
)

from tests.support import (
    _remove_exact_test_entry,
    _test_entry_object_identity,
    owned_temporary_directory,
)


class StrictJsonTests(unittest.TestCase):
    def test_canonical_json_rejects_nested_non_finite_floats(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json({"outer": [{"value": value}]})

        self.assertEqual(canonical_json({"value": 1.25}), b'{"value":1.25}\n')

        with mock.patch(
            "review_supervisor.secureio.json.loads",
            side_effect=RecursionError,
        ):
            with self.assertRaisesRegex(ValueError, "nesting is too deep"):
                decode_json_bytes(b"{}")

    def test_atomic_write_rejects_non_finite_before_publish_or_replace(self) -> None:
        with owned_temporary_directory("secureio-non-finite-") as root:
            for label, value in (
                ("nan", float("nan")),
                ("positive-infinity", float("inf")),
                ("negative-infinity", float("-inf")),
            ):
                with self.subTest(label=label):
                    target = root / f"{label}.json"
                    original = b'{"status":"original"}\n'
                    target.write_bytes(original)
                    target.chmod(0o600)

                    with self.assertRaises(ValueError):
                        atomic_write_json(
                            target,
                            {"outer": [{"value": value}]},
                            replace=True,
                        )
                    self.assertEqual(target.read_bytes(), original)

                    new_target = root / f"{label}-new.json"
                    with self.assertRaises(ValueError):
                        atomic_write_json(
                            new_target,
                            {"outer": [{"value": value}]},
                            replace=False,
                        )
                    self.assertFalse(new_target.exists())


class PrivateDirectoryAnchorTests(unittest.TestCase):
    def test_regular_openers_avoid_fifo_rendezvous_and_reject_dev_null(
        self,
    ) -> None:
        if not hasattr(signal, "setitimer"):
            self.skipTest("requires POSIX interval timers")

        class BlockingOpenTimeout(RuntimeError):
            pass

        def reject_blocking_open(_signum: int, _frame: object) -> None:
            raise BlockingOpenTimeout("regular-file opener exceeded the test deadline")

        previous_handler = signal.signal(signal.SIGALRM, reject_blocking_open)
        try:
            with owned_temporary_directory("secureio-fifo-") as root:
                parent_fd, _ = open_absolute_directory_chain(
                    root,
                    private_leaf=True,
                )
                try:
                    for name, opener in (
                        (
                            "descriptor-relative",
                            lambda: open_regular_at(
                                parent_fd,
                                b"control.fifo",
                                expected_uid=os.getuid(),
                            ),
                        ),
                        (
                            "absolute",
                            lambda: open_regular_nofollow(
                                root / "control.fifo",
                                expected_uid=os.getuid(),
                            ),
                        ),
                    ):
                        with self.subTest(opener=name):
                            fifo = root / "control.fifo"
                            if fifo.exists():
                                fifo.unlink()
                            os.mkfifo(fifo, 0o600)
                            fifo_object = _test_entry_object_identity(
                                os.stat(
                                    b"control.fifo",
                                    dir_fd=parent_fd,
                                    follow_symlinks=False,
                                )
                            )
                            try:
                                signal.setitimer(signal.ITIMER_REAL, 1.0)
                                with self.assertRaises(OSError) as caught:
                                    opener()
                            finally:
                                signal.setitimer(signal.ITIMER_REAL, 0.0)
                                _remove_exact_test_entry(
                                    parent_fd,
                                    b"control.fifo",
                                    fifo_object,
                                )
                            self.assertEqual(caught.exception.errno, errno.EINVAL)
                finally:
                    os.close(parent_fd)

            device = pathlib.Path("/dev/null")
            if device.exists():
                # This is a smoke case, not a bound on arbitrary driver latency.
                with self.subTest(opener="dev-null-smoke"):
                    signal.setitimer(signal.ITIMER_REAL, 1.0)
                    try:
                        with self.assertRaises(OSError) as caught:
                            open_regular_nofollow(
                                device,
                                require_link_one=False,
                            )
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0.0)
                    self.assertEqual(caught.exception.errno, errno.EINVAL)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)

    def test_creates_missing_private_chain_descriptor_relatively(self) -> None:
        with owned_temporary_directory("secureio-create-") as root:
            target = root / "one" / "two"
            fd, identity = open_absolute_directory_chain(
                target,
                create=True,
                private_leaf=True,
            )
            try:
                self.assertEqual(stat.S_IMODE(identity.mode), 0o700)
                self.assertEqual(identity.uid, os.getuid())
            finally:
                os.close(fd)
            self.assertEqual(stat.S_IMODE(os.stat(root / "one").st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_rejects_nonsticky_writable_ancestor(self) -> None:
        with owned_temporary_directory("secureio-writable-") as root:
            ancestor = root / "shared"
            ancestor.mkdir(mode=0o700)
            os.chmod(ancestor, 0o777)
            target = ancestor / "private"

            with self.assertRaises(OSError):
                open_absolute_directory_chain(
                    target,
                    create=True,
                    private_leaf=True,
                )
            self.assertFalse(target.exists())

    def test_allows_sticky_writable_ancestor(self) -> None:
        with owned_temporary_directory("secureio-sticky-") as root:
            ancestor = root / "sticky"
            ancestor.mkdir(mode=0o700)
            os.chmod(ancestor, 0o1777)
            target = ancestor / "private"

            fd, _ = open_absolute_directory_chain(
                target,
                create=True,
                private_leaf=True,
            )
            os.close(fd)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_private_directory_requires_exact_mode(self) -> None:
        with owned_temporary_directory("secureio-mode-") as root:
            target = root / "private"
            target.mkdir(mode=0o700)
            os.chmod(target, 0o750)

            with self.assertRaises(SupervisorError) as caught:
                require_private_directory(target)
            self.assertEqual(
                caught.exception.failure.code,
                "private-directory-unavailable",
            )

    def test_private_directory_surfaces_acl_rejection(self) -> None:
        with owned_temporary_directory("secureio-directory-acl-") as root:
            target = root / "private"
            target.mkdir(mode=0o700)

            def reject_private(
                _fd: int,
                _path: pathlib.Path,
                _kind: str,
                *,
                private: bool,
            ) -> None:
                if private:
                    raise ValueError("private ACL")

            with (
                mock.patch(
                    "review_supervisor.secureio._verify_macos_metadata",
                    side_effect=reject_private,
                ),
                self.assertRaises(SupervisorError) as caught,
            ):
                require_private_directory(target)
            self.assertIn("private ACL", caught.exception.failure.message)

    def test_directory_at_rejects_private_acl(self) -> None:
        with owned_temporary_directory("secureio-directory-at-acl-") as root:
            child = root / "child"
            child.mkdir(mode=0o700)
            parent_fd, _ = open_absolute_directory_chain(root, private_leaf=True)
            try:
                with (
                    mock.patch(
                        "review_supervisor.secureio._verify_macos_metadata",
                        side_effect=ValueError("private ACL"),
                    ),
                    self.assertRaisesRegex(ValueError, "private ACL"),
                ):
                    open_directory_at(
                        parent_fd,
                        b"child",
                        path_hint=child,
                        private=True,
                    )
            finally:
                os.close(parent_fd)

    def test_directory_at_rejects_path_replacement_during_validation(self) -> None:
        with owned_temporary_directory("secureio-directory-at-replace-") as root:
            child = root / "child"
            child.mkdir(mode=0o700)
            replacement = root / "replacement"
            replacement.mkdir(mode=0o700)
            parent_fd, _ = open_absolute_directory_chain(root, private_leaf=True)
            original_validate = secureio_module._validate_directory_fd_with_policy
            replaced = False

            def replace_path(
                fd: int,
                path: pathlib.Path,
                *,
                private: bool,
            ) -> tuple[Identity, secureio_module.DirectoryPolicyBinding]:
                nonlocal replaced
                identity = original_validate(fd, path, private=private)
                if not replaced:
                    replaced = True
                    child.rename(root / "displaced")
                    replacement.rename(child)
                return identity

            try:
                with (
                    mock.patch(
                        "review_supervisor.secureio._validate_directory_fd_with_policy",
                        side_effect=replace_path,
                    ),
                    self.assertRaisesRegex(OSError, "path identity changed"),
                ):
                    open_directory_at(
                        parent_fd,
                        b"child",
                        path_hint=child,
                        private=True,
                    )
            finally:
                os.close(parent_fd)

    def test_selected_missing_root_rejects_bound_prefix_replacement(self) -> None:
        with owned_temporary_directory("secureio-selected-prefix-replace-") as root:
            selected_parent = root / "selected-parent"
            selected_parent.mkdir(mode=0o700)
            selected = selected_parent / "retention"
            account_default = root / "account-default"
            account_default.mkdir(mode=0o700)
            replacement_parent = root / "replacement-parent"
            replacement_parent.mkdir(mode=0o700)
            displaced_parent = root / "displaced-parent"
            original_validate = secureio_module.DirectoryPathEquivalenceBinding.validate_before_selected_open
            replaced = False

            def replace_after_validation(
                binding: secureio_module.DirectoryPathEquivalenceBinding,
            ) -> None:
                nonlocal replaced
                original_validate(binding)
                if not replaced:
                    selected_parent.rename(displaced_parent)
                    replacement_parent.rename(selected_parent)
                    replaced = True

            with (
                secureio_module.bind_directory_path_equivalence(
                    selected,
                    account_default,
                ),
                mock.patch.object(
                    secureio_module.DirectoryPathEquivalenceBinding,
                    "validate_before_selected_open",
                    new=replace_after_validation,
                ),
                self.assertRaises(OSError) as caught,
            ):
                open_absolute_directory_chain(
                    selected,
                    create=True,
                    private_leaf=True,
                )

            self.assertEqual(caught.exception.errno, errno.ESTALE)
            self.assertTrue((displaced_parent / "retention").is_dir())
            self.assertFalse(selected.exists())
            self.assertFalse((selected / "retention.lock").exists())
            self.assertFalse(
                (displaced_parent / "retention" / "retention.lock").exists()
            )

    def test_selected_missing_root_allows_bound_prefix_restore(self) -> None:
        with owned_temporary_directory("secureio-selected-prefix-restore-") as root:
            selected_parent = root / "selected-parent"
            selected_parent.mkdir(mode=0o700)
            selected = selected_parent / "retention"
            account_default = root / "account-default"
            account_default.mkdir(mode=0o700)
            replacement_parent = root / "replacement-parent"
            replacement_parent.mkdir(mode=0o700)
            displaced_parent = root / "displaced-parent"
            retired_replacement = root / "retired-replacement"
            binding_type = secureio_module.DirectoryPathEquivalenceBinding
            original_validate = binding_type.validate_before_selected_open
            original_bind = binding_type.bind_selected_open
            replaced = False

            def replace_after_validation(
                binding: secureio_module.DirectoryPathEquivalenceBinding,
            ) -> None:
                nonlocal replaced
                original_validate(binding)
                if not replaced:
                    selected_parent.rename(displaced_parent)
                    replacement_parent.rename(selected_parent)
                    replaced = True

            def restore_before_binding(
                binding: secureio_module.DirectoryPathEquivalenceBinding,
                fd: int,
                identity: Identity,
            ) -> None:
                selected_parent.rename(retired_replacement)
                displaced_parent.rename(selected_parent)
                original_bind(binding, fd, identity)

            with (
                secureio_module.bind_directory_path_equivalence(
                    selected,
                    account_default,
                ),
                mock.patch.object(
                    binding_type,
                    "validate_before_selected_open",
                    new=replace_after_validation,
                ),
                mock.patch.object(
                    binding_type,
                    "bind_selected_open",
                    new=restore_before_binding,
                ),
            ):
                selected_fd, _ = open_absolute_directory_chain(
                    selected,
                    create=True,
                    private_leaf=True,
                )
                os.close(selected_fd)

            self.assertTrue(replaced)
            self.assertTrue(selected.is_dir())
            self.assertFalse((retired_replacement / "retention").exists())

    def test_directory_equivalence_rejects_missing_leaf_creation(self) -> None:
        with owned_temporary_directory("secureio-equivalence-create-") as root:
            target = root / "retention"
            original_open = secureio_module._open_directory_path_equivalence_snapshot
            calls = 0

            def open_then_create(
                path: pathlib.Path,
            ) -> secureio_module._DirectoryPathEquivalenceSnapshot:
                nonlocal calls
                snapshot = original_open(path)
                calls += 1
                if calls == 1:
                    target.mkdir(mode=0o700)
                return snapshot

            with (
                mock.patch.object(
                    secureio_module,
                    "_open_directory_path_equivalence_snapshot",
                    side_effect=open_then_create,
                ),
                self.assertRaises(OSError) as caught,
            ):
                directory_paths_equivalent(target, target)

            self.assertEqual(caught.exception.errno, errno.ESTALE)

    def test_directory_equivalence_rejects_existing_target_replacement(self) -> None:
        with owned_temporary_directory("secureio-equivalence-replace-") as root:
            target = root / "retention"
            target.mkdir(mode=0o700)
            replacement = root / "replacement"
            replacement.mkdir(mode=0o700)
            original_open = secureio_module._open_directory_path_equivalence_snapshot
            calls = 0

            def open_then_replace(
                path: pathlib.Path,
            ) -> secureio_module._DirectoryPathEquivalenceSnapshot:
                nonlocal calls
                snapshot = original_open(path)
                calls += 1
                if calls == 1:
                    target.rename(root / "displaced")
                    replacement.rename(target)
                return snapshot

            with (
                mock.patch.object(
                    secureio_module,
                    "_open_directory_path_equivalence_snapshot",
                    side_effect=open_then_replace,
                ),
                self.assertRaises(OSError) as caught,
            ):
                directory_paths_equivalent(target, target)

            self.assertEqual(caught.exception.errno, errno.ESTALE)

    def test_directory_equivalence_rejects_allowed_acl_policy_drift(self) -> None:
        with owned_temporary_directory("secureio-equivalence-acl-") as root:
            target = root / "retention"
            target.mkdir(mode=0o700)
            target_identity = os.stat(target)
            clear = ExtendedMetadataEvidence(0, (), False)
            restrictive_acl = ExtendedMetadataEvidence(
                1,
                (),
                False,
                ("group:fixture:deny:write",),
            )
            current_evidence = clear

            def metadata_for_descriptor(
                fd: int,
                _path: pathlib.Path,
                _kind: str,
                *,
                private: bool,
            ) -> ExtendedMetadataEvidence:
                del private
                if os.fstat(fd).st_ino == target_identity.st_ino:
                    return current_evidence
                return clear

            with mock.patch(
                "review_supervisor.secureio._verify_macos_metadata",
                side_effect=metadata_for_descriptor,
            ):
                snapshot = secureio_module._open_directory_path_equivalence_snapshot(
                    target
                )
                try:
                    current_evidence = restrictive_acl
                    with self.assertRaisesRegex(
                        OSError,
                        "directory path changed",
                    ) as caught:
                        secureio_module._revalidate_directory_path_equivalence_snapshot(
                            snapshot
                        )
                finally:
                    snapshot.close()

            self.assertEqual(caught.exception.errno, errno.ESTALE)

    def test_retention_lease_detects_root_replacement(self) -> None:
        cases = (
            "root-replaced",
            "lock-replaced",
            "lock-unlocked",
            "lock-reowned",
        )
        for case in cases:
            with (
                self.subTest(case=case),
                owned_temporary_directory(f"secureio-anchor-{case}-") as parent,
            ):
                retention = parent / "retention"
                lease = acquire_retention_lease(
                    retention,
                    deadline=10**12,
                )
                successor = None
                try:
                    if case == "root-replaced":
                        retention.rename(parent / "moved-retention")
                        retention.mkdir(mode=0o700)
                        message = "binding changed"
                    elif case == "lock-replaced":
                        replacement = retention / "replacement.lock"
                        replacement.write_bytes(b"")
                        replacement.chmod(0o600)
                        replacement.replace(retention / "retention.lock")
                        message = "unexpected link count|lock path identity changed"
                    elif case == "lock-unlocked":
                        fcntl.flock(lease.fd, fcntl.LOCK_UN)
                        message = "exclusive retention lock is not held"
                    else:
                        fcntl.flock(lease.fd, fcntl.LOCK_UN)
                        successor = acquire_retention_lease(
                            retention,
                            deadline=10**12,
                        )
                        message = "retention lock ownership token changed"
                    with self.assertRaisesRegex(OSError, message):
                        lease.revalidate_root()
                finally:
                    if successor is not None:
                        successor.close()
                    lease.close()

        with owned_temporary_directory("secureio-anchor-acquire-swap-") as parent:
            retention = parent / "retention"
            initial = acquire_retention_lease(retention, deadline=10**12)
            initial.close()
            original_acquire = ledger_module.acquire_flock

            def replace_after_lock(fd: int, operation: int, *, deadline: float) -> None:
                original_acquire(fd, operation, deadline=deadline)
                replacement = retention / "replacement.lock"
                replacement.write_bytes(b"")
                replacement.chmod(0o600)
                replacement.replace(retention / "retention.lock")

            with (
                mock.patch(
                    "review_supervisor.ledger.acquire_flock",
                    side_effect=replace_after_lock,
                ),
                self.assertRaisesRegex(
                    SupervisorError,
                    "cannot acquire independent-review retention lock",
                ),
            ):
                acquire_retention_lease(retention, deadline=10**12)

        with owned_temporary_directory("secureio-anchor-interrupt-") as parent:
            retention = parent / "retention"
            with (
                mock.patch(
                    "review_supervisor.ledger._write_retention_lock_token",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                acquire_retention_lease(retention, deadline=10**12)
            with acquire_retention_lease(retention, deadline=10**12) as lease:
                lease.revalidate_root()


class PrivateMetadataTests(unittest.TestCase):
    @staticmethod
    def _evidence(
        *,
        acl_entries: tuple[str, ...] = (),
        xattrs: tuple[str, ...] = (),
        quarantine: bool = False,
    ) -> ExtendedMetadataEvidence:
        return ExtendedMetadataEvidence(
            acl_entry_count=len(acl_entries),
            acl_entries=acl_entries,
            xattrs=xattrs,
            quarantine_present=quarantine,
        )

    def test_private_policy_rejects_acl_and_allows_provenance(self) -> None:
        cases = (
            (self._evidence(xattrs=("com.apple.provenance",)), False),
            (self._evidence(acl_entries=("group:fixture:allow:write",)), True),
            (self._evidence(xattrs=("com.apple.rootless",)), True),
        )
        for evidence, rejected in cases:
            with (
                self.subTest(evidence=evidence),
                mock.patch("review_supervisor.secureio.sys.platform", "darwin"),
                mock.patch(
                    "review_supervisor.codex_executable."
                    "inspect_macos_filesystem_metadata",
                    return_value=evidence,
                ),
            ):
                if rejected:
                    with self.assertRaisesRegex(ValueError, "extended metadata"):
                        _verify_macos_metadata(
                            123, pathlib.Path("/private"), "directory", private=True
                        )
                else:
                    _verify_macos_metadata(
                        123, pathlib.Path("/private"), "directory", private=True
                    )

    def test_ancestor_policy_accepts_rootless_metadata(self) -> None:
        evidence = self._evidence(xattrs=("com.apple.rootless",))
        with (
            mock.patch("review_supervisor.secureio.sys.platform", "darwin"),
            mock.patch(
                "review_supervisor.codex_executable.inspect_macos_filesystem_metadata",
                return_value=evidence,
            ),
            mock.patch(
                "review_supervisor.codex_executable.verify_macos_filesystem_metadata"
            ) as verifier,
        ):
            _verify_macos_metadata(
                123,
                pathlib.Path("/private/var/folders"),
                "directory",
                private=False,
            )
        verifier.assert_not_called()

    def test_permitted_directory_acl_uses_property_scoped_revalidation(self) -> None:
        evidence = self._evidence(acl_entries=("group:fixture:deny:write",))
        path = pathlib.Path("/Users/fixture")
        with (
            mock.patch("review_supervisor.secureio.sys.platform", "darwin"),
            mock.patch(
                "review_supervisor.codex_executable.inspect_macos_filesystem_metadata",
                return_value=evidence,
            ),
            mock.patch(
                "review_supervisor.codex_executable.verify_macos_filesystem_metadata",
                return_value=evidence,
            ) as verifier,
        ):
            _verify_macos_metadata(123, path, "directory", private=False)
        verifier.assert_called_once_with(
            123,
            path,
            "directory",
            require_directory_metadata_stability=False,
        )

    def test_atomic_write_checks_temp_and_published_file_metadata(self) -> None:
        with owned_temporary_directory("secureio-atomic-") as root:
            calls: list[pathlib.Path] = []

            def record(
                _fd: int,
                path: pathlib.Path,
                kind: str,
                *,
                private: bool,
            ) -> None:
                if kind == "file" and private:
                    calls.append(path)

            with mock.patch(
                "review_supervisor.secureio._verify_macos_metadata",
                side_effect=record,
            ):
                atomic_write_json(root / "state.json", {"value": 1}, replace=False)

            self.assertEqual(len(calls), 2)
            self.assertTrue(calls[0].name.startswith(".state.json.tmp-"))
            self.assertEqual(calls[1], root / "state.json")

    def test_atomic_write_rejects_inherited_acl_before_publish(self) -> None:
        with owned_temporary_directory("secureio-atomic-acl-") as root:
            target = root / "state.json"

            def reject_file(
                _fd: int,
                _path: pathlib.Path,
                kind: str,
                *,
                private: bool,
            ) -> None:
                if kind == "file" and private:
                    raise ValueError("private filesystem object has extended metadata")

            with (
                mock.patch(
                    "review_supervisor.secureio._verify_macos_metadata",
                    side_effect=reject_file,
                ),
                self.assertRaisesRegex(ValueError, "extended metadata"),
            ):
                atomic_write_json(target, {"value": 1}, replace=False)
            self.assertFalse(target.exists())

    def test_private_regular_reopen_rechecks_metadata(self) -> None:
        with owned_temporary_directory("secureio-reopen-") as root:
            path = root / "artifact"
            path.write_bytes(b"value")
            os.chmod(path, 0o600)
            with (
                mock.patch(
                    "review_supervisor.secureio._verify_macos_metadata",
                    side_effect=ValueError("private ACL"),
                ),
                self.assertRaisesRegex(ValueError, "private ACL"),
            ):
                open_regular_nofollow(
                    path,
                    expected_uid=os.getuid(),
                    private_metadata=True,
                )


class DarwinBootSessionMarkerTests(unittest.TestCase):
    MARKER = pathlib.Path("/synthetic/bootSessionMA.txt")
    CONTENT = b"25d4721a-7845-4f34-ae22-19e56fa8280b\n"

    @staticmethod
    def _identity(
        *,
        inode: int,
        mode: int,
        uid: int = 0,
        size: int = 0,
        link_count: int = 1,
    ) -> Identity:
        return Identity(
            device=7,
            inode=inode,
            mode=mode,
            link_count=link_count,
            uid=uid,
            size=size,
        )

    @staticmethod
    def _stat_result(
        identity: Identity,
        *,
        mtime_ns: int = 1,
        ctime_ns: int = 1,
    ) -> mock.Mock:
        return mock.Mock(
            st_dev=identity.device,
            st_ino=identity.inode,
            st_mode=identity.mode,
            st_nlink=identity.link_count,
            st_uid=identity.uid,
            st_gid=0,
            st_size=identity.size,
            st_flags=0,
            st_mtime_ns=mtime_ns,
            st_ctime_ns=ctime_ns,
        )

    def _read_with(
        self,
        *,
        file_identity: Identity | None = None,
        parent_identities: tuple[Identity, Identity] | None = None,
        reads: tuple[bytes, bytes] | None = None,
        metadata_error: BaseException | None = None,
        metadata_results: tuple[object, object, object] | None = None,
        fstat_results: tuple[mock.Mock, mock.Mock, mock.Mock, mock.Mock] | None = None,
        path_result: mock.Mock | None = None,
        events: list[str] | None = None,
    ) -> bytes:
        file_identity = file_identity or self._identity(
            inode=20,
            mode=stat.S_IFREG | 0o644,
            size=len(self.CONTENT),
        )
        parent = self._identity(
            inode=10,
            mode=stat.S_IFDIR | 0o755,
            size=128,
            link_count=2,
        )
        first_parent, second_parent = parent_identities or (parent, parent)
        parent_results = iter(((11, first_parent), (12, second_parent)))

        def open_parent(_marker: pathlib.Path) -> tuple[int, Identity]:
            descriptor, identity = next(parent_results)
            if events is not None:
                events.append(f"open:{descriptor}")
            return descriptor, identity

        def close(descriptor: int) -> None:
            if events is not None:
                events.append(f"close:{descriptor}")

        if metadata_results is not None:
            metadata_effect: object = metadata_results
        else:
            metadata_effect = metadata_error
        fstat_patch = (
            mock.patch(
                "review_supervisor.secureio.os.fstat",
                side_effect=fstat_results,
            )
            if fstat_results is not None
            else mock.patch(
                "review_supervisor.secureio.os.fstat",
                return_value=self._stat_result(file_identity),
            )
        )
        with (
            mock.patch(
                "review_supervisor.secureio.DARWIN_BOOT_SESSION_MARKER",
                self.MARKER,
            ),
            mock.patch(
                "review_supervisor.secureio._open_darwin_boot_marker_parent",
                side_effect=open_parent,
            ),
            mock.patch(
                "review_supervisor.secureio.open_regular_at",
                return_value=(21, file_identity),
            ),
            fstat_patch,
            mock.patch(
                "review_supervisor.secureio.os.stat",
                return_value=path_result or self._stat_result(file_identity),
            ),
            mock.patch(
                "review_supervisor.secureio.read_fd_exact",
                side_effect=reads or (self.CONTENT, self.CONTENT),
            ),
            mock.patch(
                "review_supervisor.secureio._verify_macos_metadata",
                side_effect=metadata_effect,
            ),
            mock.patch("review_supervisor.secureio.os.close", side_effect=close),
        ):
            return _read_darwin_boot_session_marker(self.MARKER)

    def test_marker_binds_stable_identity_content_and_parent(self) -> None:
        self.assertEqual(self._read_with(), self.CONTENT.strip())

    def test_marker_rejects_content_mutation(self) -> None:
        changed = b"54be2dd6-7659-4227-84ea-ddf64170e320\n"
        with self.assertRaisesRegex(OSError, "content changed"):
            self._read_with(reads=(self.CONTENT, changed))

    def test_marker_rejects_final_content_and_extended_metadata_drift(self) -> None:
        file_identity = self._identity(
            inode=20,
            mode=stat.S_IFREG | 0o644,
            size=len(self.CONTENT),
        )
        stable = self._stat_result(file_identity)
        changed = self._stat_result(file_identity, mtime_ns=2, ctime_ns=2)
        with self.assertRaisesRegex(OSError, "content metadata changed"):
            self._read_with(
                file_identity=file_identity,
                fstat_results=(stable, stable, changed, changed),
                path_result=changed,
            )

        clear = ExtendedMetadataEvidence(0, (), False)
        acl = ExtendedMetadataEvidence(
            1,
            (),
            False,
            ("user:fixture:allow:write",),
        )
        with self.assertRaisesRegex(OSError, "extended metadata changed"):
            self._read_with(metadata_results=(clear, clear, acl))

    def test_marker_rejects_unsafe_mode_and_extended_metadata(self) -> None:
        unsafe = self._identity(
            inode=20,
            mode=stat.S_IFREG | 0o664,
            size=len(self.CONTENT),
        )
        with self.assertRaisesRegex(ValueError, "access policy is unsafe"):
            self._read_with(file_identity=unsafe)
        with self.assertRaisesRegex(ValueError, "synthetic ACL"):
            self._read_with(metadata_error=ValueError("synthetic ACL"))

    def test_marker_rejects_parent_path_replacement(self) -> None:
        first = self._identity(
            inode=10,
            mode=stat.S_IFDIR | 0o755,
            size=128,
            link_count=2,
        )
        replacement = self._identity(
            inode=11,
            mode=stat.S_IFDIR | 0o755,
            size=128,
            link_count=2,
        )
        with self.assertRaisesRegex(OSError, "parent path changed"):
            self._read_with(parent_identities=(first, replacement))

    def test_marker_keeps_original_parent_open_through_revalidation(self) -> None:
        events: list[str] = []
        self.assertEqual(self._read_with(events=events), self.CONTENT.strip())
        self.assertLess(events.index("open:12"), events.index("close:11"))

    def test_parent_opener_rejects_replacement_and_closes_descriptors(self) -> None:
        ancestor = self._identity(
            inode=9,
            mode=stat.S_IFDIR | 0o755,
            size=128,
            link_count=2,
        )
        parent = mock.Mock(
            st_dev=7,
            st_ino=10,
            st_mode=stat.S_IFDIR | 0o775,
            st_nlink=2,
            st_uid=0,
            st_gid=1,
            st_size=128,
            st_flags=0,
        )
        replacement = mock.Mock(
            st_dev=7,
            st_ino=11,
            st_mode=stat.S_IFDIR | 0o775,
            st_nlink=2,
            st_uid=0,
            st_gid=1,
            st_size=128,
            st_flags=0,
        )
        with (
            mock.patch(
                "review_supervisor.secureio.DARWIN_BOOT_SESSION_MARKER",
                self.MARKER,
            ),
            mock.patch(
                "review_supervisor.secureio.open_absolute_directory_chain",
                return_value=(30, ancestor),
            ),
            mock.patch("review_supervisor.secureio.os.open", return_value=31),
            mock.patch("review_supervisor.secureio.os.fstat", return_value=parent),
            mock.patch("review_supervisor.secureio.os.stat", return_value=replacement),
            mock.patch(
                "review_supervisor.secureio._verify_macos_metadata",
            ) as verify_metadata,
            mock.patch("review_supervisor.secureio.os.close") as close,
            self.assertRaisesRegex(OSError, "parent identity changed"),
        ):
            _open_darwin_boot_marker_parent(self.MARKER)

        verify_metadata.assert_not_called()
        self.assertEqual(
            close.call_args_list,
            [mock.call(31), mock.call(30)],
        )

    def test_marker_and_parent_require_exact_system_access_policy(self) -> None:
        def marker_metadata(**changes: int) -> mock.Mock:
            values = {
                "st_dev": 7,
                "st_ino": 20,
                "st_mode": stat.S_IFREG | 0o644,
                "st_nlink": 1,
                "st_uid": 0,
                "st_gid": 0,
                "st_size": len(self.CONTENT),
                "st_flags": 0,
            }
            values.update(changes)
            return mock.Mock(**values)

        def parent_metadata(**changes: int) -> mock.Mock:
            values = {
                "st_mode": stat.S_IFDIR | 0o775,
                "st_uid": 0,
                "st_gid": 1,
                "st_flags": 0,
            }
            values.update(changes)
            return mock.Mock(**values)

        marker = marker_metadata()
        parent = parent_metadata()
        _require_trusted_boot_marker_metadata(marker)
        _require_trusted_boot_parent_metadata(parent)

        for field, value in (
            ("st_gid", 1),
            ("st_mode", stat.S_IFREG | 0o640),
            ("st_flags", getattr(stat, "UF_IMMUTABLE", 2)),
        ):
            with self.subTest(marker_field=field):
                changed = marker_metadata(**{field: value})
                with self.assertRaisesRegex(ValueError, "marker access policy"):
                    _require_trusted_boot_marker_metadata(changed)

        for field, value in (
            ("st_uid", 501),
            ("st_gid", 20),
            ("st_mode", stat.S_IFDIR | 0o755),
            ("st_flags", getattr(stat, "UF_IMMUTABLE", 2)),
        ):
            with self.subTest(parent_field=field):
                changed = parent_metadata(**{field: value})
                with self.assertRaisesRegex(ValueError, "parent access policy"):
                    _require_trusted_boot_parent_metadata(changed)


if __name__ == "__main__":
    unittest.main()
