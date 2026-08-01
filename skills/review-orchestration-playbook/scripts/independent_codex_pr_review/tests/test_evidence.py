from __future__ import annotations

import json
import os
import pathlib
import unittest
from unittest import mock

from review_supervisor.evidence import (
    AuthenticatedManifest,
    EvidenceArtifact,
    EvidenceError,
    ManifestEntry,
    build_evidence_bundle,
    manifest_sha256,
)
from review_supervisor.secureio import sha256_bytes

from tests.support import (
    _remove_exact_test_entry,
    _test_entry_object_identity,
    owned_temporary_directory,
)


class EvidenceBundleTests(unittest.TestCase):
    def _entry(
        self,
        root: pathlib.Path,
        path: str,
        *,
        kind: str = "regular",
    ) -> ManifestEntry:
        value = (root / path).read_bytes() if kind == "regular" else b"target"
        return ManifestEntry(
            path=path,
            kind=kind,  # type: ignore[arg-type]
            size=len(value),
            sha256=sha256_bytes(value),
        )

    def _manifest(self, entries: list[ManifestEntry]) -> AuthenticatedManifest:
        return AuthenticatedManifest.authenticate(
            entries,
            expected_sha256=manifest_sha256(entries),
        )

    def test_builds_deterministic_opaque_bundle_from_root_descriptor(self) -> None:
        with owned_temporary_directory("evidence-success-") as root:
            control = root / ".codex-review"
            source = root / "src"
            control.mkdir()
            source.mkdir()
            primary = b"diff --git a/src/a.py b/src/a.py\n+return 2\n"
            alpha = b"def alpha():\n    return 1\n"
            beta = b"def beta():\n    return 2\n"
            (control / "review.diff").write_bytes(primary)
            (source / "a.py").write_bytes(alpha)
            (source / "b.py").write_bytes(beta)
            entries = [
                self._entry(root, "src/b.py"),
                self._entry(root, ".codex-review/review.diff"),
                self._entry(root, "src/a.py"),
            ]
            manifest = self._manifest(entries)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                first = build_evidence_bundle(
                    root_fd=root_fd,
                    manifest=manifest,
                    nearby_paths=("src/b.py", "src/a.py"),
                )
                second = build_evidence_bundle(
                    root_fd=root_fd,
                    manifest=manifest,
                    nearby_paths=("src/a.py", "src/b.py"),
                )
            finally:
                os.close(root_fd)

            self.assertEqual(first.to_bytes(), second.to_bytes())
            payload = json.loads(first.to_bytes())
            self.assertEqual(payload["schema"], "appserver-evidence-bundle-v1")
            self.assertEqual(
                [artifact["label"] for artifact in payload["artifacts"]],
                ["artifact-0000", "artifact-0001", "artifact-0002"],
            )
            self.assertEqual(payload["artifacts"][0]["role"], "primary_diff")
            self.assertEqual(payload["artifacts"][0]["content"].encode(), primary)
            self.assertEqual(payload["artifacts"][1]["content"].encode(), alpha)
            serialized = first.to_bytes()
            self.assertNotIn(str(root).encode(), serialized)
            self.assertNotIn(b"src/b.py", serialized)
            self.assertNotIn(b".codex-review/review.diff", serialized)

    def test_context_labels_follow_authenticated_raw_path_order(self) -> None:
        raw_name = os.fsdecode(b"\x80.py")
        utf8_name = os.fsdecode(b"\xe2\x82\xac.py")
        with owned_temporary_directory("evidence-raw-path-order-") as root:
            primary = b"diff --git a/a.py b/a.py\n+fixed\n"
            entries = [
                ManifestEntry(
                    path=utf8_name,
                    kind="regular",
                    size=len(b"utf8-second"),
                    sha256=sha256_bytes(b"utf8-second"),
                ),
                ManifestEntry(
                    path=".codex-review/review.diff",
                    kind="regular",
                    size=len(primary),
                    sha256=sha256_bytes(primary),
                ),
                ManifestEntry(
                    path=raw_name,
                    kind="regular",
                    size=len(b"raw-byte-first"),
                    sha256=sha256_bytes(b"raw-byte-first"),
                ),
            ]
            manifest = self._manifest(entries)
            content_by_path = {
                ".codex-review/review.diff": primary,
                raw_name: b"raw-byte-first",
                utf8_name: b"utf8-second",
            }

            def read_entry(*, entry, label, role, **_kwargs):
                content = content_by_path[entry.path]
                return EvidenceArtifact(
                    label=label,
                    role=role,
                    content=content.decode(),
                    length=len(content),
                    sha256=sha256_bytes(content),
                )

            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch(
                    "review_supervisor.evidence._read_manifest_entry",
                    side_effect=read_entry,
                ):
                    bundle = build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=manifest,
                        nearby_paths=(utf8_name, raw_name),
                    )
            finally:
                os.close(root_fd)

        self.assertEqual(
            ["raw-byte-first", "utf8-second"],
            [artifact.content for artifact in bundle.artifacts[1:]],
        )

    def test_manifest_authentication_rejects_mismatch_and_duplicate_paths(self) -> None:
        entry = ManifestEntry(
            path="a.txt",
            kind="regular",
            size=1,
            sha256=sha256_bytes(b"a"),
        )
        with self.assertRaises(EvidenceError):
            AuthenticatedManifest.authenticate(
                [entry],
                expected_sha256="0" * 64,
            )
        with self.assertRaises(EvidenceError):
            manifest_sha256([entry, entry])

    def test_rejects_unmanifested_tampered_and_wrong_sized_files(self) -> None:
        with owned_temporary_directory("evidence-auth-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff_path = control / "review.diff"
            diff_path.write_bytes(b"original\n")
            entry = self._entry(root, ".codex-review/review.diff")
            manifest = self._manifest([entry])
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=manifest,
                        nearby_paths=("missing.py",),
                    )
                diff_path.write_bytes(b"tampered\n")
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(root_fd=root_fd, manifest=manifest)
                diff_path.write_bytes(b"changed!\n")
                self.assertEqual(len(diff_path.read_bytes()), entry.size)
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(root_fd=root_fd, manifest=manifest)
            finally:
                os.close(root_fd)

    def test_rejects_symlink_gitlink_and_symlinked_parent(self) -> None:
        with owned_temporary_directory("evidence-links-") as root:
            control = root / ".codex-review"
            real = root / "real"
            control.mkdir()
            real.mkdir()
            (control / "review.diff").write_bytes(b"diff\n")
            (real / "context.txt").write_bytes(b"context\n")
            os.symlink(real, root / "linked")
            os.symlink(real / "context.txt", root / "link.txt")
            regular_primary = self._entry(root, ".codex-review/review.diff")
            linked_entry = ManifestEntry(
                path="linked/context.txt",
                kind="regular",
                size=8,
                sha256=sha256_bytes(b"context\n"),
            )
            gitlink_entry = ManifestEntry(
                path="submodule",
                kind="gitlink",
                size=6,
                sha256=sha256_bytes(b"target"),
            )
            leaf_link_entry = ManifestEntry(
                path="link.txt",
                kind="regular",
                size=8,
                sha256=sha256_bytes(b"context\n"),
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=self._manifest([regular_primary, linked_entry]),
                        nearby_paths=("linked/context.txt",),
                    )
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=self._manifest([regular_primary, gitlink_entry]),
                        nearby_paths=("submodule",),
                    )
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=self._manifest([regular_primary, leaf_link_entry]),
                        nearby_paths=("link.txt",),
                    )
            finally:
                os.close(root_fd)

    def test_rejects_hardlinked_evidence(self) -> None:
        with owned_temporary_directory("evidence-hardlink-") as root:
            control = root / ".codex-review"
            control.mkdir()
            (control / "review.diff").write_bytes(b"diff\n")
            (root / "context.txt").write_bytes(b"context\n")
            os.link(root / "context.txt", root / "alias.txt")
            entries = [
                self._entry(root, ".codex-review/review.diff"),
                self._entry(root, "context.txt"),
            ]
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            alias_object = _test_entry_object_identity(
                os.stat(
                    b"alias.txt",
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
            )
            try:
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=self._manifest(entries),
                        nearby_paths=("context.txt",),
                    )
            finally:
                try:
                    _remove_exact_test_entry(
                        root_fd,
                        b"alias.txt",
                        alias_object,
                    )
                finally:
                    os.close(root_fd)

    def test_rejects_binary_data_and_unsafe_path_syntax(self) -> None:
        for path in ("/absolute", "../escape", "a/../b", "a/*", "a\\b", "a//b"):
            with self.subTest(path=path), self.assertRaises(EvidenceError):
                ManifestEntry(
                    path=path,
                    kind="regular",
                    size=0,
                    sha256=sha256_bytes(b""),
                )

        with owned_temporary_directory("evidence-binary-") as root:
            control = root / ".codex-review"
            control.mkdir()
            binary = b"diff\x00binary\n"
            (control / "review.diff").write_bytes(binary)
            entry = self._entry(root, ".codex-review/review.diff")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(EvidenceError):
                    build_evidence_bundle(
                        root_fd=root_fd,
                        manifest=self._manifest([entry]),
                    )
            finally:
                os.close(root_fd)

    def test_enforces_primary_per_file_context_and_aggregate_caps(self) -> None:
        with owned_temporary_directory("evidence-caps-") as root:
            control = root / ".codex-review"
            control.mkdir()
            (control / "review.diff").write_bytes(b"abcd")
            (root / "one.txt").write_bytes(b"12")
            (root / "two.txt").write_bytes(b"34")
            entries = [
                self._entry(root, ".codex-review/review.diff"),
                self._entry(root, "one.txt"),
                self._entry(root, "two.txt"),
            ]
            manifest = self._manifest(entries)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch(
                    "review_supervisor.evidence.MAX_EVIDENCE_PRIMARY_BYTES", 3
                ):
                    with self.assertRaises(EvidenceError):
                        build_evidence_bundle(root_fd=root_fd, manifest=manifest)
                with mock.patch(
                    "review_supervisor.evidence.MAX_EVIDENCE_CONTEXT_FILE_BYTES", 1
                ):
                    with self.assertRaises(EvidenceError):
                        build_evidence_bundle(
                            root_fd=root_fd,
                            manifest=manifest,
                            nearby_paths=("one.txt",),
                        )
                with mock.patch(
                    "review_supervisor.evidence.MAX_EVIDENCE_CONTEXT_BYTES", 3
                ):
                    with self.assertRaises(EvidenceError):
                        build_evidence_bundle(
                            root_fd=root_fd,
                            manifest=manifest,
                            nearby_paths=("one.txt", "two.txt"),
                        )
            finally:
                os.close(root_fd)


if __name__ == "__main__":
    unittest.main()
