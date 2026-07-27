from __future__ import annotations

import unittest

from review_supervisor.lfs import is_git_lfs_pointer


OID = b"sha256:" + b"a" * 64
# Keep samples inside a non-pointer source blob so self-review can materialize them.
CANONICAL_POINTER = (
    b"\n".join(
        (
            b"version https://git-lfs.github.com/spec/v1",
            b"oid " + OID,
            b"size 1",
        )
    )
    + b"\n"
)
INTERLEAVED_POINTER = (
    b"\n".join(
        (
            b"ext-5-alpha-with-tail sha256:" + b"b" * 64,
            b"version https://hawser.github.com/spec/v1",
            b"ext-1-beta sha256:" + b"c" * 64,
            b"oid sha256:" + b"d" * 64,
            b"size -0",
        )
    )
    + b"\n"
)
INVALID_UPPERCASE_OID = (
    b"\n".join(
        (
            b"version https://git-lfs.github.com/spec/v1",
            b"oid sha256:" + b"A" * 64,
            b"size 1",
        )
    )
    + b"\n"
)


class GitLfsPointerTests(unittest.TestCase):
    def test_accepts_canonical_fixture(self) -> None:
        self.assertTrue(is_git_lfs_pointer(CANONICAL_POINTER))

    def test_accepts_reference_compatible_variants(self) -> None:
        self.assertTrue(is_git_lfs_pointer(INTERLEAVED_POINTER))
        crlf = b"\r\n".join(
            (
                b"version http://git-media.io/v/2",
                b"oid " + OID,
                b"size +0001",
            )
        )
        self.assertTrue(is_git_lfs_pointer(b" \t" + crlf + b"\r\n"))
        repeated = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"ext-1-one "
            + OID
            + b"\next-1-one "
            + OID
            + b"\noid "
            + OID
            + b"\nsize 1\n"
        )
        self.assertTrue(is_git_lfs_pointer(repeated))

    def test_accepts_extended_priority_and_opaque_name(self) -> None:
        pointer = b"\n".join(
            (
                b"version https://git-lfs.github.com/spec/v1",
                b"ext-10-!opaque/name sha256:" + b"b" * 64,
                b"oid " + OID,
                b"size 1",
            )
        )
        self.assertTrue(is_git_lfs_pointer(pointer + b"\n"))

    def test_rejects_near_misses(self) -> None:
        self.assertFalse(is_git_lfs_pointer(INVALID_UPPERCASE_OID))
        candidates = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid " + OID + b"\nsize 1\next-1-late " + OID,
            b"version https://git-lfs.github.com/spec/v1\n"
            b"ext-1-one " + OID + b"\next-1-two " + OID + b"\noid " + OID + b"\nsize 1",
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
