from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import os
import pathlib
import pwd
import runpy
import stat
import sys
from dataclasses import dataclass
from types import CodeType, ModuleType


SOURCE_FILE_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_TOTAL_LIMIT_BYTES = 64 * 1024 * 1024
SOURCE_ENTRY_LIMIT = 4096
SOURCE_PATH_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_DEPTH_LIMIT = 32
SOURCE_MANIFEST_LIMIT_BYTES = 1024 * 1024
SOURCE_MANIFEST_HEADER = b"trusted-mac-gate-source-manifest-v1\n"
SOURCE_ROOTS = ("review_supervisor", "tests")
PROHIBITED_SUFFIXES = (".pyc", ".pyo", ".so", ".dylib", ".dll", ".pyd")
MODE_MODULES = {
    "hosted-readonly": "tests.run_readonly_install_deterministic_supervisor",
    "live": "tests.run_required_no_child_profile",
    "readonly": "tests.run_readonly_install_deterministic_supervisor",
}


@dataclass(frozen=True)
class _BoundSource:
    code: CodeType
    digest: str
    is_package: bool
    path: pathlib.Path
    payload: bytes


@dataclass(frozen=True)
class _ManifestEntry:
    git_mode: int
    size: int
    sha256: str


class _SourceOnlyLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, source: _BoundSource) -> None:
        self._fullname = fullname
        self._source = source

    def create_module(self, _spec: object) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        exec(self._source.code, module.__dict__)

    def get_code(self, fullname: str) -> CodeType:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return self._source.code

    def get_filename(self, fullname: str) -> str:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return str(self._source.path)

    def is_package(self, fullname: str) -> bool:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return self._source.is_package


class _ClosedSourceFinder(importlib.abc.MetaPathFinder):
    def __init__(self, sources: dict[str, _BoundSource]) -> None:
        self._sources = sources

    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> object:
        if not (
            fullname == "review_supervisor"
            or fullname.startswith("review_supervisor.")
            or fullname == "tests"
            or fullname.startswith("tests.")
        ):
            return None
        source = self._sources.get(fullname)
        if source is None:
            raise ImportError(f"source-only module is absent: {fullname}")
        loader = _SourceOnlyLoader(fullname, source)
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=str(source.path),
            is_package=source.is_package,
        )


@dataclass
class _SnapshotBudget:
    entries_remaining: int = SOURCE_ENTRY_LIMIT
    bytes_remaining: int = SOURCE_TOTAL_LIMIT_BYTES
    path_bytes_remaining: int = SOURCE_PATH_LIMIT_BYTES

    def observe(self, name: str, *, depth: int) -> None:
        if depth > SOURCE_DEPTH_LIMIT:
            raise RuntimeError("trusted gate source exceeds its depth bound")
        encoded = os.fsencode(name)
        if self.entries_remaining <= 0:
            raise RuntimeError("trusted gate source exceeds its entry bound")
        if len(encoded) > self.path_bytes_remaining:
            raise RuntimeError("trusted gate source exceeds its path byte bound")
        self.entries_remaining -= 1
        self.path_bytes_remaining -= len(encoded)

    def consume_source(self, size: int, *, probe_bytes: int = 0) -> None:
        if size < 0 or size > SOURCE_FILE_LIMIT_BYTES:
            raise RuntimeError("trusted gate source file exceeds its byte bound")
        charged = size + probe_bytes
        if probe_bytes < 0 or charged > self.bytes_remaining:
            raise RuntimeError("trusted gate source exceeds its total byte bound")
        self.bytes_remaining -= charged


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    path: pathlib.Path,
) -> int:
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISDIR(initial.st_mode):
        raise RuntimeError(f"trusted gate source is not a directory: {path}")
    if initial.st_uid not in {0, os.getuid()}:
        raise RuntimeError(f"trusted gate source ownership is unsafe: {path}")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if _directory_identity(initial) != _directory_identity(opened):
            raise OSError("trusted gate source directory changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _bounded_directory_names(
    descriptor: int,
    *,
    budget: _SnapshotBudget,
    depth: int,
) -> tuple[str, ...]:
    names = []
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            budget.observe(entry.name, depth=depth)
            names.append(entry.name)
    return tuple(sorted(names))


def _read_source_at(
    parent_descriptor: int,
    name: str,
    path: pathlib.Path,
    *,
    budget: _SnapshotBudget,
) -> tuple[bytes, int]:
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(initial.st_mode):
        raise RuntimeError(f"trusted gate source is not a regular file: {path}")
    if initial.st_uid not in {0, os.getuid()} or initial.st_nlink != 1:
        raise RuntimeError(f"trusted gate source ownership is unsafe: {path}")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            initial.st_nlink != 1
            or opened.st_nlink != 1
            or (
                initial.st_dev,
                initial.st_ino,
                initial.st_mode,
                initial.st_uid,
                initial.st_gid,
                initial.st_size,
                initial.st_nlink,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_size,
                opened.st_nlink,
            )
        ):
            raise OSError("trusted gate source changed while opening")
        budget.consume_source(opened.st_size, probe_bytes=1)
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise OSError("trusted gate source changed while reading")
        final = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_nlink,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_uid,
            final.st_gid,
            final.st_size,
            final.st_nlink,
        ):
            raise OSError("trusted gate source changed while reading")
        git_mode = 0o100755 if final.st_mode & 0o111 else 0o100644
        return bytes(payload), git_mode
    finally:
        os.close(descriptor)


def _read_source_manifest(
    path: pathlib.Path,
    expected_digest: str,
) -> bytes:
    if len(expected_digest) != 64 or any(
        character not in "0123456789abcdef" for character in expected_digest
    ):
        raise RuntimeError("trusted gate source manifest digest is invalid")
    if not path.is_absolute():
        raise RuntimeError("trusted gate source manifest path must be absolute")
    initial = path.lstat()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
    )

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_nlink,
        )

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid not in {0, os.getuid()}
            or opened.st_nlink != 1
            or opened.st_size < len(SOURCE_MANIFEST_HEADER)
            or opened.st_size > SOURCE_MANIFEST_LIMIT_BYTES
            or identity(initial) != identity(opened)
        ):
            raise RuntimeError("trusted gate source manifest identity is unsafe")
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(65536, opened.st_size - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise OSError("trusted gate source manifest changed while reading")
        final = os.fstat(descriptor)
        if identity(opened) != identity(final):
            raise OSError("trusted gate source manifest changed while reading")
        result = bytes(payload)
        if hashlib.sha256(result).hexdigest() != expected_digest:
            raise RuntimeError("trusted gate source manifest digest mismatch")
        return result
    finally:
        os.close(descriptor)


def _parse_source_manifest(payload: bytes) -> dict[str, _ManifestEntry]:
    if not payload.startswith(SOURCE_MANIFEST_HEADER) or not payload.endswith(b"\n"):
        raise RuntimeError("trusted gate source manifest framing is invalid")
    records = payload[len(SOURCE_MANIFEST_HEADER) :].splitlines(keepends=True)
    if not records:
        raise RuntimeError("trusted gate source manifest is empty")
    entries: dict[str, _ManifestEntry] = {}
    previous_path: bytes | None = None
    for record in records:
        if not record.endswith(b"\n") or b"\r" in record or b"\0" in record:
            raise RuntimeError("trusted gate source manifest record is malformed")
        metadata, separator, raw_path = record[:-1].partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise RuntimeError("trusted gate source manifest record is malformed")
        raw_mode, raw_size, raw_digest = fields
        if raw_mode not in {b"100644", b"100755"}:
            raise RuntimeError("trusted gate source manifest mode is unsupported")
        if (
            not raw_size
            or len(raw_size) > 10
            or any(character not in b"0123456789" for character in raw_size)
        ):
            raise RuntimeError("trusted gate source manifest size is invalid")
        size = int(raw_size)
        if size < 0 or size > SOURCE_FILE_LIMIT_BYTES:
            raise RuntimeError("trusted gate source manifest size exceeds its bound")
        if len(raw_digest) != 64 or any(
            character not in b"0123456789abcdef" for character in raw_digest
        ):
            raise RuntimeError("trusted gate source manifest digest is invalid")
        if previous_path is not None and raw_path <= previous_path:
            raise RuntimeError(
                "trusted gate source manifest paths are not unique and sorted"
            )
        previous_path = raw_path
        try:
            relative = raw_path.decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                "trusted gate source manifest path is not ASCII"
            ) from error
        path = pathlib.PurePosixPath(relative)
        if (
            not relative
            or path.is_absolute()
            or path.as_posix() != relative
            or not path.parts
            or path.parts[0] not in SOURCE_ROOTS
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise RuntimeError("trusted gate source manifest path is outside its scope")
        entries[relative] = _ManifestEntry(
            git_mode=int(raw_mode, 8),
            size=size,
            sha256=raw_digest.decode("ascii"),
        )
    return entries


def _module_name(relative: tuple[str, ...], *, is_package: bool) -> str:
    components = relative[:-1] if is_package else (*relative[:-1], relative[-1][:-3])
    if not components or any(not component.isidentifier() for component in components):
        raise RuntimeError("trusted gate source has an invalid module path")
    return ".".join(components)


def _snapshot_sources(
    tool_root: pathlib.Path,
    manifest: dict[str, _ManifestEntry],
) -> dict[str, _BoundSource]:
    budget = _SnapshotBudget()
    captured: dict[str, tuple[pathlib.Path, bytes, bool, str]] = {}
    observed: set[str] = set()
    expected_directories = {
        tuple(pathlib.PurePosixPath(path).parts[:index])
        for path in manifest
        for index in range(1, len(pathlib.PurePosixPath(path).parts))
    }
    root_initial = tool_root.lstat()
    if not stat.S_ISDIR(root_initial.st_mode):
        raise RuntimeError("trusted gate tool root is not a directory")
    if root_initial.st_uid not in {0, os.getuid()}:
        raise RuntimeError("trusted gate tool root ownership is unsafe")
    root_descriptor = os.open(
        tool_root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    root_opened = os.fstat(root_descriptor)
    if _directory_identity(root_initial) != _directory_identity(root_opened):
        os.close(root_descriptor)
        raise OSError("trusted gate tool root changed while opening")

    def walk(
        parent_descriptor: int,
        relative: tuple[str, ...],
        *,
        depth: int,
    ) -> None:
        names = _bounded_directory_names(
            parent_descriptor,
            budget=budget,
            depth=depth,
        )
        for name in names:
            path = tool_root.joinpath(*relative, name)
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(f"trusted gate source contains a symlink: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                if name == "__pycache__":
                    raise RuntimeError("trusted gate source contains __pycache__")
                directory_relative = (*relative, name)
                if directory_relative not in expected_directories:
                    raise RuntimeError(
                        f"trusted gate source contains an unexpected directory: {path}"
                    )
                child = _open_directory_at(
                    parent_descriptor,
                    name,
                    path,
                )
                try:
                    walk(child, (*relative, name), depth=depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    f"trusted gate source has an unsupported entry: {path}"
                )
            if name.endswith(PROHIBITED_SUFFIXES):
                raise RuntimeError(f"trusted gate source contains a substitute: {path}")
            manifest_path = pathlib.PurePosixPath(*relative, name).as_posix()
            expected = manifest.get(manifest_path)
            if expected is None:
                raise RuntimeError(
                    f"trusted gate source contains an unexpected file: {path}"
                )
            payload, git_mode = _read_source_at(
                parent_descriptor,
                name,
                path,
                budget=budget,
            )
            second, second_git_mode = _read_source_at(
                parent_descriptor,
                name,
                path,
                budget=budget,
            )
            if payload != second or git_mode != second_git_mode:
                raise OSError("trusted gate source changed between reads")
            if (
                git_mode != expected.git_mode
                or len(payload) != expected.size
                or hashlib.sha256(payload).hexdigest() != expected.sha256
            ):
                raise RuntimeError(
                    f"trusted gate source does not match the exact manifest: {path}"
                )
            observed.add(manifest_path)
            if not name.endswith(".py"):
                continue
            is_package = name == "__init__.py"
            module = _module_name((*relative, name), is_package=is_package)
            if module in captured:
                raise RuntimeError(
                    f"trusted gate source maps duplicate module: {module}"
                )
            captured[module] = (
                path,
                payload,
                is_package,
                hashlib.sha256(payload).hexdigest(),
            )

    try:
        for package in SOURCE_ROOTS:
            budget.observe(package, depth=0)
            package_descriptor = _open_directory_at(
                root_descriptor,
                package,
                tool_root / package,
            )
            try:
                walk(package_descriptor, (package,), depth=1)
            finally:
                os.close(package_descriptor)
    finally:
        os.close(root_descriptor)
    missing = sorted(set(manifest) - observed)
    if missing:
        raise RuntimeError(
            "trusted gate source is missing exact manifest entries: "
            + ", ".join(missing[:10])
        )
    for required in ("review_supervisor", "tests", *MODE_MODULES.values()):
        if required not in captured:
            raise RuntimeError(f"trusted gate required source is absent: {required}")
    return {
        module: _BoundSource(
            code=compile(payload, str(path), "exec", dont_inherit=True),
            digest=digest,
            is_package=is_package,
            path=path,
            payload=payload,
        )
        for module, (path, payload, is_package, digest) in captured.items()
    }


def _configure_environment(mode: str, arguments: list[str]) -> str:
    account = pwd.getpwuid(os.getuid())
    if account.pw_uid != os.getuid() or not account.pw_name or not account.pw_dir:
        raise RuntimeError("trusted gate account identity is unavailable")
    environment = {
        "HOME": account.pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "USER": account.pw_name,
    }
    if mode == "live":
        if arguments:
            raise RuntimeError("trusted live gate accepts no arguments")
        environment["CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"] = "1"
    elif mode == "readonly":
        if (
            len(arguments) != 1
            or len(arguments[0]) != 40
            or any(character not in "0123456789abcdef" for character in arguments[0])
        ):
            raise RuntimeError("trusted readonly gate requires one full SHA-1")
        environment["CODEX_REVIEW_EXPECTED_HEAD_SHA"] = arguments[0]
    elif mode == "hosted-readonly":
        if len(arguments) != 2:
            raise RuntimeError("hosted readonly gate requires runtime and home paths")
        runtime_parent = pathlib.Path(arguments[0])
        home = pathlib.Path(arguments[1])
        if not runtime_parent.is_absolute() or not home.is_absolute():
            raise RuntimeError("hosted readonly gate paths must be absolute")
        environment["CODEX_REVIEW_TEST_RUNTIME_PARENT"] = str(runtime_parent)
        environment["HOME"] = str(home)
        environment["TMPDIR"] = str(runtime_parent)
    else:
        raise RuntimeError("trusted gate mode is unsupported")
    os.environ.clear()
    os.environ.update(environment)
    return MODE_MODULES[mode]


def main() -> int:
    if (
        not sys.flags.isolated
        or not sys.flags.ignore_environment
        or not sys.flags.no_site
        or not sys.flags.no_user_site
        or not sys.flags.safe_path
        or not sys.dont_write_bytecode
    ):
        raise RuntimeError("trusted gate requires -I -B -S")
    if __file__ != "<stdin>" or sys.argv[0] != "-":
        raise RuntimeError("trusted gate must be executed from bounded trusted stdin")
    if len(sys.argv) < 5:
        raise RuntimeError(
            "trusted gate requires an absolute tool root, source manifest, "
            "manifest digest, and mode"
        )
    tool_root = pathlib.Path(sys.argv[1])
    if not tool_root.is_absolute():
        raise RuntimeError("trusted gate tool root must be absolute")
    manifest_path = pathlib.Path(sys.argv[2])
    manifest_payload = _read_source_manifest(manifest_path, sys.argv[3])
    manifest = _parse_source_manifest(manifest_payload)
    mode = sys.argv[4]
    module = _configure_environment(mode, sys.argv[5:])
    sources = _snapshot_sources(tool_root, manifest)
    sys.meta_path.insert(0, _ClosedSourceFinder(sources))
    sys.argv = [module]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
