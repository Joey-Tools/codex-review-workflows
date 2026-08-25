from __future__ import annotations

import hashlib
import os
import pathlib
import runpy
import stat
import sys
import tempfile
import unittest
from unittest import mock


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL_ROOT = SKILL_ROOT / "scripts" / "independent_codex_pr_review"
MANIFEST_PATH = TOOL_ROOT / "trusted_mac_gate_sources.index"
CONSUMER_PATH = TOOL_ROOT / "tests" / "trusted_mac_gate.py"
MANIFEST_HEADER = b"trusted-mac-gate-source-manifest-v1\n"
SOURCE_ROOTS = ("review_supervisor", "tests")
PROHIBITED_SUFFIXES = (".pyc", ".pyo", ".so", ".dylib", ".dll", ".pyd")
SOURCE_FILE_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_TOTAL_LIMIT_BYTES = 64 * 1024 * 1024
SOURCE_ENTRY_LIMIT = 4096
SOURCE_PATH_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_DEPTH_LIMIT = 32
SOURCE_MANIFEST_LIMIT_BYTES = 1024 * 1024


def _validate_source_name(name: str, *, depth: int) -> bytes:
    if depth > SOURCE_DEPTH_LIMIT:
        raise RuntimeError("trusted gate source exceeds its depth bound")
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("trusted gate source path is not ASCII") from error
    if not encoded or any(character in encoded for character in b"\r\n\t\0"):
        raise RuntimeError("trusted gate source path is not manifest-safe")
    return encoded


def _validate_manifest_relative_path(relative: str) -> None:
    try:
        encoded = relative.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("trusted gate source manifest path is not ASCII") from error
    path = pathlib.PurePosixPath(relative)
    if (
        not relative
        or any(character in encoded for character in b"\r\n\t\0")
        or path.is_absolute()
        or path.as_posix() != relative
        or not path.parts
        or path.parts[0] not in SOURCE_ROOTS
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RuntimeError("trusted gate source manifest path is outside its scope")


def _validate_bound_directory(path: pathlib.Path) -> os.stat_result:
    initial = path.lstat()
    if (
        not stat.S_ISDIR(initial.st_mode)
        or stat.S_ISLNK(initial.st_mode)
        or initial.st_uid not in {0, os.getuid()}
    ):
        raise RuntimeError(f"trusted gate source is not a safe directory: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            initial.st_dev,
            initial.st_ino,
            stat.S_IFMT(initial.st_mode),
            initial.st_uid,
        ) != (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
            opened.st_uid,
        ):
            raise RuntimeError(f"trusted gate source directory changed: {path}")
        return opened
    finally:
        os.close(descriptor)


def _manifest_for_current_tree(tool_root: pathlib.Path = TOOL_ROOT) -> bytes:
    records: list[bytes] = []
    directories: set[tuple[str, ...]] = set()
    entries = 0
    source_bytes = 0
    path_bytes = 0

    _validate_bound_directory(tool_root)

    def observe(name: str, *, depth: int) -> None:
        nonlocal entries, path_bytes
        encoded = _validate_source_name(name, depth=depth)
        entries += 1
        path_bytes += len(encoded)
        if entries > SOURCE_ENTRY_LIMIT:
            raise RuntimeError("trusted gate source exceeds its entry bound")
        if path_bytes > SOURCE_PATH_LIMIT_BYTES:
            raise RuntimeError("trusted gate source exceeds its path byte bound")

    def walk(directory: pathlib.Path, relative: tuple[str, ...], *, depth: int) -> None:
        nonlocal source_bytes
        directories.add(relative)
        _validate_bound_directory(directory)
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in children:
            observe(entry.name, depth=depth)
            path = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if entry.is_symlink():
                raise RuntimeError(f"source manifest entry is not regular: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                if entry.name == "__pycache__":
                    raise RuntimeError(f"source-only manifest cannot include {path}")
                walk(path, (*relative, entry.name), depth=depth + 1)
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or metadata.st_nlink != 1
            ):
                raise RuntimeError(f"source manifest entry is not regular: {path}")
            if path.suffix in PROHIBITED_SUFFIXES:
                raise RuntimeError(f"source-only manifest cannot include {path}")
            if metadata.st_size < 0 or metadata.st_size > SOURCE_FILE_LIMIT_BYTES:
                raise RuntimeError("trusted gate source file exceeds its byte bound")
            # The consumer reads each source twice and charges one probe byte per read.
            source_bytes += 2 * (metadata.st_size + 1)
            if source_bytes > SOURCE_TOTAL_LIMIT_BYTES:
                raise RuntimeError("trusted gate source exceeds its total byte bound")
            relative_path = pathlib.PurePosixPath(*relative, entry.name).as_posix()
            _validate_manifest_relative_path(relative_path)
            payload = path.read_bytes()
            if len(payload) != metadata.st_size:
                raise RuntimeError("trusted gate source changed while reading")
            mode = "100755" if stat.S_IMODE(metadata.st_mode) & 0o111 else "100644"
            records.append(
                (
                    f"{mode} {len(payload)} {hashlib.sha256(payload).hexdigest()}"
                    f"\t{relative_path}\n"
                ).encode("ascii")
            )

    for source_root in SOURCE_ROOTS:
        observe(source_root, depth=0)
        walk(tool_root / source_root, (source_root,), depth=1)
    records.sort(key=lambda record: record.partition(b"\t")[2])
    if not records:
        raise RuntimeError("trusted gate source manifest is empty")
    manifest_paths = tuple(
        pathlib.PurePosixPath(record.partition(b"\t")[2][:-1].decode("ascii"))
        for record in records
    )
    expected_directories = {
        tuple(path.parts[:index])
        for path in manifest_paths
        for index in range(1, len(path.parts))
    }
    unexpected_directories = directories - expected_directories
    if unexpected_directories:
        raise RuntimeError(
            "trusted gate source contains a directory absent from the manifest"
        )
    manifest = MANIFEST_HEADER + b"".join(records)
    if len(manifest) > SOURCE_MANIFEST_LIMIT_BYTES:
        raise RuntimeError("trusted gate source manifest exceeds its byte bound")
    return manifest


class TrustedMacGateManifestTest(unittest.TestCase):
    def test_manifest_matches_the_exact_source_tree(self) -> None:
        self.assertEqual(
            MANIFEST_PATH.read_bytes(),
            _manifest_for_current_tree(),
            "trusted Mac gate source manifest is stale; regenerate every record from "
            "the current review_supervisor/ and tests/ trees",
        )

    def test_generated_manifest_is_accepted_by_the_exact_consumer_parser(self) -> None:
        consumer = runpy.run_path(
            str(CONSUMER_PATH), run_name="trusted_mac_gate_manifest_contract"
        )
        parsed = consumer["_parse_source_manifest"](_manifest_for_current_tree())
        self.assertEqual(
            set(parsed),
            {
                record.partition(b"\t")[2][:-1].decode("ascii")
                for record in MANIFEST_PATH.read_bytes()[
                    len(MANIFEST_HEADER) :
                ].splitlines(keepends=True)
            },
        )

    def test_generator_rejects_consumer_incompatible_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for source_root in SOURCE_ROOTS:
                (root / source_root).mkdir()
            (root / "review_supervisor" / "bad\nname.py").write_text(
                "pass\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "manifest-safe"):
                _manifest_for_current_tree(root)

    def test_generator_enforces_consumer_file_and_manifest_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for source_root in SOURCE_ROOTS:
                (root / source_root).mkdir()
            payload = root / "review_supervisor" / "large.py"
            (root / "tests" / "stub.py").write_text("pass\n", encoding="utf-8")
            payload.write_bytes(b"x" * 33)
            module = sys.modules[__name__]
            with mock.patch.object(module, "SOURCE_FILE_LIMIT_BYTES", 32):
                with self.assertRaisesRegex(RuntimeError, "file exceeds"):
                    _manifest_for_current_tree(root)

            payload.write_bytes(b"x")
            with mock.patch.object(
                module, "SOURCE_MANIFEST_LIMIT_BYTES", len(MANIFEST_HEADER)
            ):
                with self.assertRaisesRegex(RuntimeError, "manifest exceeds"):
                    _manifest_for_current_tree(root)


if __name__ == "__main__":
    if sys.argv[1:] == ["--regenerate"]:
        MANIFEST_PATH.write_bytes(_manifest_for_current_tree())
        print(f"Regenerated {MANIFEST_PATH}")
    else:
        unittest.main()
