from __future__ import annotations

import os
import pathlib
import stat
import unittest
from unittest import mock

from review_supervisor.codex_executable import ExtendedMetadataEvidence
from review_supervisor.errors import SupervisorError
from review_supervisor.ledger import acquire_retention_lease
from review_supervisor.secureio import (
    _verify_macos_metadata,
    atomic_write_json,
    open_absolute_directory_chain,
    open_regular_nofollow,
    require_private_directory,
)

from tests.support import owned_temporary_directory


class PrivateDirectoryAnchorTests(unittest.TestCase):
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

    def test_retention_lease_detects_root_replacement(self) -> None:
        with owned_temporary_directory("secureio-anchor-") as parent:
            retention = parent / "retention"
            moved = parent / "moved-retention"
            lease = acquire_retention_lease(
                retention,
                deadline=10**12,
            )
            try:
                retention.rename(moved)
                retention.mkdir(mode=0o700)
                with self.assertRaisesRegex(OSError, "binding changed"):
                    lease.revalidate_root()
            finally:
                lease.close()


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


if __name__ == "__main__":
    unittest.main()
