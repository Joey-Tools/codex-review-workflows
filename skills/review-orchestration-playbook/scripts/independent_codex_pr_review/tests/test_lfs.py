from __future__ import annotations

import pathlib
import unittest

from review_supervisor.lfs import is_git_lfs_pointer


FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "lfs"
OID = b"sha256:" + b"a" * 64


class GitLfsPointerTests(unittest.TestCase):
    def test_accepts_canonical_fixture(self) -> None:
        self.assertTrue(is_git_lfs_pointer((FIXTURES / "canonical.ptr").read_bytes()))

    def test_accepts_reference_compatible_variants(self) -> None:
        self.assertTrue(
            is_git_lfs_pointer((FIXTURES / "interleaved-extensions.ptr").read_bytes())
        )
        crlf = b"\r\n".join(
            (
                b"version http://git-media.io/v/2",
                b"oid " + OID,
                b"size +0001",
            )
        )
        self.assertTrue(is_git_lfs_pointer(b" \t" + crlf + b"\r\n"))

    def test_rejects_near_misses(self) -> None:
        self.assertFalse(
            is_git_lfs_pointer((FIXTURES / "invalid-uppercase-oid.txt").read_bytes())
        )
        candidates = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid " + OID + b"\nsize 1\next-1-late " + OID,
            b"version https://git-lfs.github.com/spec/v1\n"
            b"ext-1-one " + OID + b"\next-1-two " + OID + b"\noid " + OID + b"\nsize 1",
            b"version https://git-lfs.github.com/spec/v1\n"
            b"ext-1-one " + OID + b"\next-1-one " + OID + b"\noid " + OID + b"\nsize 1",
            b"version https://git-lfs.github.com/spec/v1\n \noid " + OID + b"\nsize 1",
            b"version https://git-lfs.github.com/spec/v1\noid " + OID + b"\nsize -1",
            b"version https://git-lfs.github.com/spec/v1\noid "
            + OID
            + b"\nsize 9223372036854775808",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate[:48]):
                self.assertFalse(is_git_lfs_pointer(candidate))

    def test_empty_and_large_blobs_are_pass_through(self) -> None:
        self.assertFalse(is_git_lfs_pointer(b""))
        self.assertFalse(is_git_lfs_pointer(b"x" * 1024))


if __name__ == "__main__":
    unittest.main()
