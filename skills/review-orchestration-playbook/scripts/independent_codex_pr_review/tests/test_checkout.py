from __future__ import annotations

import errno
import hashlib
import pathlib
import unittest
from unittest import mock

from review_supervisor.checkout import (
    NameSemantics,
    probe_name_semantics,
    read_and_validate_symlink_graphs,
    validate_namespaces,
)
from review_supervisor.constants import MAX_RAW_BLOB_BYTES
from review_supervisor.errors import SupervisorError
from review_supervisor.gitraw import RepositoryInfo, object_digest
from review_supervisor.models import Identity, TreeEntry, TreeManifest
from review_supervisor.secureio import rename_exchange

from tests.support import owned_temporary_directory


SEMANTICS = NameSemantics(
    case_insensitive=False,
    normalization_insensitive=False,
    name_max=255,
    path_max=4096,
)


def _manifest(
    commit: str,
    *entries: TreeEntry,
    aggregate_regular_bytes: int = 0,
) -> TreeManifest:
    return TreeManifest(
        commit=commit,
        entries=entries,
        metadata_bytes=0,
        aggregate_regular_bytes=aggregate_regular_bytes,
        gitlink_count=0,
    )


def _symlink(path: bytes, target: bytes) -> TreeEntry:
    return TreeEntry(
        mode=0o120000,
        object_type="blob",
        object_id=object_digest("sha1", target),
        size=len(target),
        path=path,
    )


def _regular(path: bytes) -> TreeEntry:
    return TreeEntry(
        mode=0o100644,
        object_type="blob",
        object_id=object_digest("sha1", b""),
        size=0,
        path=path,
    )


class _RecordingCatFileBatch:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self.requests: list[str] = []

    def __enter__(self) -> _RecordingCatFileBatch:
        return self

    def __exit__(self, *unused: object) -> None:
        return None

    def read_blob(self, entry: TreeEntry, *, capture: bool) -> bytes:
        if not capture:
            raise AssertionError("symlink reads must capture their target")
        payload = self.payloads[entry.object_id]
        if len(payload) != entry.size:
            raise AssertionError("fixture size does not match its object")
        if object_digest("sha1", payload) != entry.object_id:
            raise AssertionError("fixture OID does not match its object")
        self.requests.append(entry.object_id)
        return payload


def _info() -> RepositoryInfo:
    return RepositoryInfo(
        repo=pathlib.Path("/unused/repo"),
        common_git_dir=pathlib.Path("/unused/repo/.git"),
        object_directory=pathlib.Path("/unused/repo/.git/objects"),
        object_directory_identity=Identity(0, 0, 0o40700, 1, 0, 0),
        object_format="sha1",
        object_hex_length=40,
        base_sha="1" * 40,
        head_sha="2" * 40,
        git_executable="/usr/bin/git",
    )


def _read_graphs(
    base: TreeManifest,
    head: TreeManifest,
    batch: _RecordingCatFileBatch,
    *,
    semantics: NameSemantics = SEMANTICS,
):
    base_entries, head_entries = validate_namespaces(
        base,
        head,
        semantics=semantics,
        checkout_root=pathlib.Path("/unused/checkout"),
    )
    with mock.patch(
        "review_supervisor.checkout.CatFileBatch",
        return_value=batch,
    ):
        return read_and_validate_symlink_graphs(
            _info(),
            base,
            head,
            base_entries=base_entries,
            head_entries=head_entries,
            semantics=semantics,
        )


class SymlinkGraphTests(unittest.TestCase):
    def test_unchanged_base_and_head_object_is_read_and_charged_once(self) -> None:
        target = b"target"
        base_link = _symlink(b"link", target)
        head_link = _symlink(b"link", target)
        base = _manifest("base", base_link)
        head = _manifest(
            "head",
            head_link,
            aggregate_regular_bytes=MAX_RAW_BLOB_BYTES - len(target),
        )
        batch = _RecordingCatFileBatch({base_link.object_id: target})

        graph = _read_graphs(base, head, batch)

        self.assertEqual(batch.requests, [base_link.object_id])
        self.assertEqual(graph.head_targets, {b"link": target})
        self.assertEqual(
            graph.targets,
            {
                ("base", b"link", base_link.object_id): target,
                ("head", b"link", head_link.object_id): target,
            },
        )

    def test_distinct_objects_still_enforce_the_aggregate_limit(self) -> None:
        base_target = b"base-target"
        head_target = b"head-target-longer"
        base_link = _symlink(b"link", base_target)
        head_link = _symlink(b"link", head_target)
        base = _manifest("base", base_link)
        head = _manifest(
            "head",
            head_link,
            aggregate_regular_bytes=MAX_RAW_BLOB_BYTES - len(base_target),
        )
        batch = _RecordingCatFileBatch(
            {
                base_link.object_id: base_target,
                head_link.object_id: head_target,
            }
        )

        with self.assertRaises(SupervisorError) as raised:
            _read_graphs(base, head, batch)

        self.assertEqual(
            raised.exception.failure.code, "blocked-checkout-symlink-graph"
        )
        self.assertEqual(batch.requests, [base_link.object_id])

    def test_cached_object_rejects_inconsistent_declared_size(self) -> None:
        target = b"target"
        base_link = _symlink(b"link", target)
        head_link = TreeEntry(
            mode=base_link.mode,
            object_type=base_link.object_type,
            object_id=base_link.object_id,
            size=len(target) + 1,
            path=base_link.path,
        )
        batch = _RecordingCatFileBatch({base_link.object_id: target})

        with self.assertRaises(SupervisorError) as raised:
            _read_graphs(
                _manifest("base", base_link),
                _manifest("head", head_link),
                batch,
            )

        self.assertIn("inconsistent sizes", raised.exception.failure.message)
        self.assertEqual(batch.requests, [base_link.object_id])

    def test_cached_target_is_validated_in_each_side_and_path_context(self) -> None:
        target = b"../safe"
        base_link = _symlink(b"dir/link", target)
        head_link = _symlink(b"link", target)
        batch = _RecordingCatFileBatch({base_link.object_id: target})

        with self.assertRaises(SupervisorError) as raised:
            _read_graphs(
                _manifest("base", base_link),
                _manifest("head", head_link),
                batch,
            )

        self.assertIn("transiently escapes", raised.exception.failure.message)
        self.assertEqual(batch.requests, [base_link.object_id])

    def test_rejects_symlink_loops(self) -> None:
        link_a = _symlink(b"a", b"b")
        link_b = _symlink(b"b", b"a")
        batch = _RecordingCatFileBatch({link_a.object_id: b"b", link_b.object_id: b"a"})

        with self.assertRaises(SupervisorError) as raised:
            _read_graphs(
                _manifest("base"),
                _manifest("head", link_a, link_b),
                batch,
            )

        self.assertIn("loops", raised.exception.failure.message)

    def test_rejects_staging_name_aliases(self) -> None:
        link = _symlink(b"link", b"target")
        stage = b".__codex_stage_" + hashlib.sha256(link.path).hexdigest()[:32].encode(
            "ascii"
        )
        batch = _RecordingCatFileBatch({link.object_id: b"target"})

        with self.assertRaises(SupervisorError) as raised:
            _read_graphs(
                _manifest("base"),
                _manifest("head", _regular(stage), link),
                batch,
            )

        self.assertIn("staging name aliases", raised.exception.failure.message)


class NameSemanticsTests(unittest.TestCase):
    def test_rejects_case_normalization_reserved_and_non_utf8_aliases(self) -> None:
        cases = (
            (
                NameSemantics(True, False, 255, 4096),
                (_regular(b"README"), _regular(b"Readme")),
            ),
            (
                NameSemantics(False, True, 255, 4096),
                (
                    _regular("caf\u00e9".encode()),
                    _regular("cafe\u0301".encode()),
                ),
            ),
            (
                NameSemantics(True, False, 255, 4096),
                (_regular(b".GIT/config"),),
            ),
            (
                NameSemantics(True, False, 255, 4096),
                (_regular(b"invalid-\xff"),),
            ),
        )
        for semantics, entries in cases:
            with self.subTest(entries=tuple(entry.path for entry in entries)):
                with self.assertRaises(SupervisorError) as raised:
                    validate_namespaces(
                        _manifest("base"),
                        _manifest("head", *entries),
                        semantics=semantics,
                        checkout_root=pathlib.Path("/unused/checkout"),
                    )
                self.assertEqual(
                    raised.exception.failure.code,
                    "blocked-checkout-name-semantics",
                )

    def test_probe_performs_atomic_exchange_and_cleans_up(self) -> None:
        with owned_temporary_directory("name-semantics-") as root:
            with mock.patch(
                "review_supervisor.checkout.rename_exchange",
                wraps=rename_exchange,
            ) as exchange:
                semantics = probe_name_semantics(root)

            exchange.assert_called_once()
            self.assertGreater(semantics.name_max, 0)
            self.assertGreater(semantics.path_max, 0)
            self.assertEqual(tuple(root.iterdir()), ())

    def test_probe_fails_closed_without_atomic_exchange(self) -> None:
        with owned_temporary_directory("name-semantics-failure-") as root:
            with mock.patch(
                "review_supervisor.checkout.rename_exchange",
                side_effect=OSError(errno.ENOTSUP, "unsupported"),
            ):
                with self.assertRaises(SupervisorError) as raised:
                    probe_name_semantics(root)

            self.assertEqual(
                raised.exception.failure.code,
                "blocked-checkout-atomic-symlink",
            )
            self.assertEqual(tuple(root.iterdir()), ())


if __name__ == "__main__":
    unittest.main()
