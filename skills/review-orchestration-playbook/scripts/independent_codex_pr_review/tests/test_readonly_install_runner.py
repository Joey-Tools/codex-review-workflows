from __future__ import annotations

import errno
import os
import pathlib
import stat
import unittest
from unittest import mock

from . import run_readonly_install_deterministic_supervisor as runner
from .support import owned_temporary_directory


class ReadOnlyInstallRunnerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
