#!/usr/bin/env python3
from __future__ import annotations

import sys


if sys.version_info < (3, 10):
    print(
        "active catalog binding requires Python 3.10 or later",
        file=sys.stderr,
    )
    raise SystemExit(2)

if not (
    sys.flags.isolated
    and sys.flags.ignore_environment
    and sys.flags.no_site
    and sys.flags.no_user_site
    and sys.flags.dont_write_bytecode
):
    print(
        "active catalog binding requires an absolute Python interpreter "
        "invoked with -I -B -S",
        file=sys.stderr,
    )
    raise SystemExit(2)

# Import only after isolated-mode admission. In particular, a resolver-local or
# current-directory json.py/argparse.py must never execute before validation.
import argparse
import contextlib
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import types
from typing import Any


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_CATALOG_BYTES = 64 * 1024
MAX_INTERPRETER_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_FILES = 512
MAX_CLI_OUTPUT_BYTES = 1024 * 1024
EXECUTABLE_CACHE_SUFFIXES = {".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll"}
RELEASE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_NAMESPACE = "review_runtime"


class BindingError(RuntimeError):
    pass


def _require_safe_file_primitives() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise BindingError("active catalog binding requires a POSIX runtime")
    for name in (
        "O_CLOEXEC",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_NONBLOCK",
    ):
        if not hasattr(os, name):
            raise BindingError(f"active catalog binding requires {name}")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _validate_directory_policy(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BindingError(f"{label} is not an ordinary non-symlink directory")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise BindingError(f"{label} has an untrusted owner")
    if metadata.st_mode & 0o022:
        shared_sticky_root = (
            metadata.st_uid == 0
            and bool(metadata.st_mode & stat.S_ISVTX)
            and bool(metadata.st_mode & 0o002)
        )
        if not shared_sticky_root:
            raise BindingError(f"{label} is group/world writable")


def _require_canonical_absolute(path: Path, *, label: str) -> None:
    raw = str(path)
    if not path.is_absolute():
        raise BindingError(f"{label} must be an absolute path")
    if raw != os.path.normpath(raw):
        raise BindingError(f"{label} must be lexically canonical")


def _require_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BindingError(f"{label} is unavailable: {error}") from error
    _validate_directory_policy(metadata, label=label)
    if metadata.st_uid != os.geteuid():
        raise BindingError(f"{label} is not owned by the current user")
    return metadata


class _BoundDirectory:
    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        identity: tuple[int, int, int, int],
        parent: _BoundDirectory | None,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.parent = parent

    def close(self, *, revalidate: bool = False) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: BindingError | None = None
        try:
            if revalidate:
                current = os.fstat(descriptor)
                _validate_directory_policy(
                    current,
                    label=f"bound directory {self.path}",
                )
                if _directory_identity(current) != self.identity:
                    raise BindingError(
                        f"bound directory identity changed for {self.path}"
                    )
                if self.parent is not None:
                    lexical = os.stat(
                        self.path.name,
                        dir_fd=self.parent.descriptor,
                        follow_symlinks=False,
                    )
                    _validate_directory_policy(
                        lexical,
                        label=f"bound parent entry {self.path}",
                    )
                    if _directory_identity(lexical) != self.identity:
                        raise BindingError(
                            f"bound parent entry identity changed for {self.path}"
                        )
        except (BindingError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, BindingError)
                else BindingError(
                    f"cannot revalidate the bound directory {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise BindingError(
                f"cannot close the bound directory {self.path}: {error}"
            ) from error
        if validation_error is not None:
            raise validation_error


class _BoundFile:
    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        identity: tuple[int, int, int, int, int],
        payload: bytes | None,
        sha256: str,
        limit: int,
        parent: _BoundDirectory | None,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.payload = payload
        self.sha256 = sha256
        self.limit = limit
        self.parent = parent

    def close(self, *, revalidate: bool = False) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: BindingError | None = None
        try:
            if revalidate:
                metadata = os.fstat(descriptor)
                if _file_identity(metadata) != self.identity:
                    raise BindingError(
                        f"bound descriptor identity changed for {self.path}"
                    )
                _payload, digest, size = _read_descriptor(
                    descriptor,
                    label=f"final descriptor revalidation for {self.path}",
                    limit=self.limit,
                    retain_payload=False,
                )
                if size != self.identity[-1] or digest != self.sha256:
                    raise BindingError(
                        f"bound descriptor content changed for {self.path}"
                    )
                if self.parent is not None:
                    lexical = os.stat(
                        self.path.name,
                        dir_fd=self.parent.descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(lexical.st_mode)
                        or stat.S_ISLNK(lexical.st_mode)
                        or _file_identity(lexical) != self.identity
                    ):
                        raise BindingError(
                            f"bound parent entry identity changed for {self.path}"
                        )
        except (BindingError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, BindingError)
                else BindingError(
                    f"cannot revalidate the bound descriptor for {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise BindingError(
                f"cannot close the bound descriptor for {self.path}: {error}"
            ) from error
        if validation_error is not None:
            raise validation_error


def _read_descriptor(
    descriptor: int,
    *,
    label: str,
    limit: int,
    retain_payload: bool,
) -> tuple[bytes | None, str, int]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise BindingError(f"{label} cannot be rewound safely: {error}") from error
    retained = bytearray() if retain_payload else None
    digest = hashlib.sha256()
    size = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - size))
        except OSError as error:
            raise BindingError(f"{label} cannot be read safely: {error}") from error
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise BindingError(f"{label} exceeds its byte limit")
        digest.update(chunk)
        if retained is not None:
            retained.extend(chunk)
    return (
        bytes(retained) if retained is not None else None,
        digest.hexdigest(),
        size,
    )


def _open_bound_file(
    path: Path,
    *,
    label: str,
    limit: int = MAX_FILE_BYTES,
    allow_root_owner: bool = False,
    retain_payload: bool = True,
    parent: _BoundDirectory | None = None,
) -> _BoundFile:
    try:
        if parent is None:
            lexical = path.lstat()
        else:
            if path.parent != parent.path:
                raise BindingError(f"{label} parent binding is inconsistent")
            lexical = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
    except OSError as error:
        raise BindingError(f"{label} cannot be inspected safely: {error}") from error
    if not stat.S_ISREG(lexical.st_mode) or stat.S_ISLNK(lexical.st_mode):
        raise BindingError(f"{label} is not an ordinary non-symlink regular file")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        if parent is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(path.name, flags, dir_fd=parent.descriptor)
    except OSError as error:
        raise BindingError(f"{label} cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise BindingError(f"{label} changed to a non-regular file")
        if _file_identity(opened) != _file_identity(lexical):
            raise BindingError(f"{label} identity changed before the validated read")
        if opened.st_uid != os.geteuid() and not (
            allow_root_owner and opened.st_uid == 0
        ):
            raise BindingError(f"{label} is not owned by an accepted user")
        if opened.st_mode & 0o022:
            raise BindingError(f"{label} is group/world writable")
        if opened.st_size > limit:
            raise BindingError(f"{label} exceeds its byte limit")

        payload, digest, size = _read_descriptor(
            descriptor,
            label=label,
            limit=limit,
            retain_payload=retain_payload,
        )
        repeated_payload, repeated_digest, repeated_size = _read_descriptor(
            descriptor,
            label=label,
            limit=limit,
            retain_payload=retain_payload,
        )
        final = os.fstat(descriptor)
        if _file_identity(final) != _file_identity(opened):
            raise BindingError(f"{label} identity changed during the validated read")
        if (
            size != opened.st_size
            or repeated_size != size
            or repeated_digest != digest
            or repeated_payload != payload
        ):
            raise BindingError(f"{label} content changed during the validated read")
        return _BoundFile(
            path=path,
            descriptor=descriptor,
            identity=_file_identity(opened),
            payload=payload,
            sha256=digest,
            limit=limit,
            parent=parent,
        )
    except BaseException:
        os.close(descriptor)
        raise


class _BindingTransaction:
    def __init__(self) -> None:
        self._retained: list[_BoundFile] = []
        self._directories: list[_BoundDirectory] = []
        self._directories_by_path: dict[Path, _BoundDirectory] = {}

    def bind_parent_chain(
        self,
        path: Path,
        *,
        label: str,
    ) -> _BoundDirectory:
        _require_canonical_absolute(path, label=label)
        existing = self._directories_by_path.get(path)
        if existing is not None:
            return existing

        root_path = Path("/")
        root = self._directories_by_path.get(root_path)
        if root is None:
            descriptor = os.open(
                root_path,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
            )
            metadata = os.fstat(descriptor)
            _validate_directory_policy(metadata, label="absolute path root")
            root = _BoundDirectory(
                path=root_path,
                descriptor=descriptor,
                identity=_directory_identity(metadata),
                parent=None,
            )
            self._directories.append(root)
            self._directories_by_path[root_path] = root

        parent = root
        current = root_path
        for component in path.parts[1:]:
            current = current / component
            existing = self._directories_by_path.get(current)
            if existing is not None:
                if existing.parent is not parent:
                    raise BindingError(
                        f"{label} has an inconsistent bound parent chain"
                    )
                parent = existing
                continue
            try:
                lexical = os.stat(
                    component,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise BindingError(
                    f"{label} component {current} cannot be inspected: {error}"
                ) from error
            _validate_directory_policy(
                lexical,
                label=f"{label} component {current}",
            )
            try:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK,
                    dir_fd=parent.descriptor,
                )
            except OSError as error:
                raise BindingError(
                    f"{label} component {current} cannot be opened: {error}"
                ) from error
            opened = os.fstat(descriptor)
            if _directory_identity(opened) != _directory_identity(lexical):
                os.close(descriptor)
                raise BindingError(
                    f"{label} component {current} changed before binding"
                )
            bound = _BoundDirectory(
                path=current,
                descriptor=descriptor,
                identity=_directory_identity(opened),
                parent=parent,
            )
            self._directories.append(bound)
            self._directories_by_path[current] = bound
            parent = bound
        return parent

    def directory(self, path: Path) -> _BoundDirectory:
        try:
            return self._directories_by_path[path]
        except KeyError as error:
            raise BindingError(f"directory was not bound: {path}") from error

    def bind(
        self,
        path: Path,
        *,
        label: str,
        limit: int = MAX_FILE_BYTES,
        allow_root_owner: bool = False,
        retain_descriptor: bool = False,
        retain_payload: bool = True,
        parent: _BoundDirectory | None = None,
    ) -> _BoundFile:
        bound = _open_bound_file(
            path,
            label=label,
            limit=limit,
            allow_root_owner=allow_root_owner,
            retain_payload=retain_payload,
            parent=parent,
        )
        if retain_descriptor:
            self._retained.append(bound)
        else:
            bound.close()
        return bound

    def close(self) -> None:
        errors: list[str] = []
        while self._retained:
            bound = self._retained.pop()
            try:
                bound.close(revalidate=True)
            except BindingError as error:
                errors.append(str(error))
        while self._directories:
            bound = self._directories.pop()
            try:
                bound.close(revalidate=True)
            except BindingError as error:
                errors.append(str(error))
        self._directories_by_path.clear()
        if errors:
            raise BindingError("; ".join(errors))


def _validate_original_layout(
    resolver: Path,
    loaded_skill_root: Path,
    transaction: _BindingTransaction,
) -> tuple[Path, Path, Path, Path, _BoundDirectory]:
    _require_canonical_absolute(resolver, label="binding resolver path")
    _require_canonical_absolute(loaded_skill_root, label="loaded skill root")
    if resolver.name != "active_catalog_binding.py":
        raise BindingError("binding resolver has an unexpected leaf name")

    scripts_root = resolver.parent
    synthetic_root = scripts_root.parent
    skills_root = synthetic_root.parent
    payload_root = skills_root.parent
    release_root = payload_root.parent
    if scripts_root.name != "scripts":
        raise BindingError("binding resolver is not inside the skill scripts directory")
    if synthetic_root.name != "synthetic-token-fixtures":
        raise BindingError("resolver is not inside synthetic-token-fixtures")
    if skills_root.name != "skills" or payload_root.name != "personal_codex":
        raise BindingError("resolver is not inside a personal Codex release payload")
    if (
        release_root.parent.name != "releases"
        or RELEASE_ID.fullmatch(release_root.name) is None
    ):
        raise BindingError("resolver is not inside a versioned immutable release")
    if loaded_skill_root != synthetic_root:
        raise BindingError(
            "binding resolver is not inside the explicitly loaded synthetic skill"
        )

    resolver_parent = transaction.bind_parent_chain(
        resolver.parent,
        label="binding resolver absolute parent chain",
    )
    for path, label in (
        (release_root, "release root"),
        (payload_root, "release payload root"),
        (skills_root, "release skills root"),
        (synthetic_root, "loaded synthetic skill root"),
        (scripts_root, "loaded synthetic skill scripts root"),
    ):
        _require_directory(path, label=label)

    return release_root, payload_root, skills_root, synthetic_root, resolver_parent


def _runtime_paths(review_root: Path) -> tuple[Path, ...]:
    scripts_root = review_root / "scripts"
    package_root = scripts_root / RUNTIME_NAMESPACE
    _require_directory(review_root, label="review skill root")
    _require_directory(scripts_root, label="review runtime scripts root")
    _require_directory(package_root, label="review runtime package")
    for suffix in EXECUTABLE_CACHE_SUFFIXES | {".py"}:
        shadow = scripts_root / f"{RUNTIME_NAMESPACE}{suffix}"
        if os.path.lexists(shadow):
            raise BindingError("review runtime package has an import shadow")

    paths = [review_root / "SKILL.md"]
    for directory, names, filenames in os.walk(scripts_root, followlinks=False):
        names.sort()
        filenames.sort()
        directory_path = Path(directory)
        _require_directory(directory_path, label="review runtime directory")
        if "__pycache__" in names:
            raise BindingError("review runtime contains executable bytecode cache")
        for name in names:
            candidate = directory_path / name
            if candidate.is_symlink():
                raise BindingError("review runtime contains a symlink directory")
        for name in filenames:
            candidate = directory_path / name
            if candidate.is_symlink():
                raise BindingError("review runtime contains a symlink file")
            if candidate.suffix.lower() in EXECUTABLE_CACHE_SUFFIXES:
                raise BindingError(
                    "review runtime contains bytecode or a native extension"
                )
            paths.append(candidate)
    if len(paths) > MAX_RUNTIME_FILES:
        raise BindingError("review runtime exceeds its file-count limit")
    return tuple(paths)


def _runtime_snapshot(
    review_root: Path,
    transaction: _BindingTransaction,
) -> tuple[str, dict[Path, bytes], dict[Path, _BoundFile]]:
    catalog_cli = review_root / "scripts" / "isolated_review"
    catalog = (
        review_root / "scripts" / RUNTIME_NAMESPACE / "synthetic-token-catalog.json"
    )
    retained_paths = {catalog_cli, catalog}
    retained_parents = {
        catalog_cli: transaction.bind_parent_chain(
            catalog_cli.parent,
            label="catalog CLI absolute parent chain",
        ),
        catalog: transaction.bind_parent_chain(
            catalog.parent,
            label="catalog absolute parent chain",
        ),
    }
    first = _runtime_paths(review_root)
    retained_files: dict[Path, _BoundFile] = {}
    runtime_files: dict[Path, bytes] = {}
    total = 0
    digest = hashlib.sha256(b"review-runtime-tree-v2\0")
    for path in first:
        relative = path.relative_to(review_root).as_posix().encode("utf-8")
        bound = transaction.bind(
            path,
            label=f"review runtime {relative!r}",
            retain_descriptor=path in retained_paths,
            parent=retained_parents.get(path),
        )
        if bound.payload is None:
            raise BindingError("review runtime snapshot unexpectedly omitted content")
        total += len(bound.payload)
        if total > MAX_RUNTIME_BYTES:
            raise BindingError("review runtime exceeds its aggregate byte limit")
        runtime_files[path] = bound.payload
        if path in retained_paths:
            retained_files[path] = bound
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(bound.payload).to_bytes(8, "big"))
        digest.update(hashlib.sha256(bound.payload).digest())
    if first != _runtime_paths(review_root):
        raise BindingError("review runtime membership changed during binding")
    if set(retained_files) != retained_paths:
        raise BindingError("review runtime omitted the catalog CLI or catalog")
    return digest.hexdigest(), runtime_files, retained_files


def _load_json_object(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BindingError(f"{label} contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BindingError(f"{label} JSON is invalid: {error}") from error
    if not isinstance(payload, dict):
        raise BindingError(f"{label} root is not an object")
    return payload


def _parse_pool_version(catalog: bytes) -> str:
    if len(catalog) > MAX_CATALOG_BYTES:
        raise BindingError("catalog exceeds the helper's byte limit")
    payload = _load_json_object(catalog, label="catalog")
    authoring_pool = payload.get("authoring_pool")
    if not isinstance(authoring_pool, dict):
        raise BindingError("catalog authoring_pool is not an object")
    pool_version = authoring_pool.get("version")
    if (
        not isinstance(pool_version, str)
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", pool_version)
        is None
    ):
        raise BindingError("catalog pool_version is not a stable identifier")
    return pool_version


def _validate_sync_manifest(content: bytes) -> None:
    manifest = _load_json_object(content, label="release sync manifest")
    if manifest.get("version") != 1:
        raise BindingError("release sync manifest version is unsupported")
    links = manifest.get("links")
    if not isinstance(links, list):
        raise BindingError("release sync manifest links are not a list")

    required = {
        (
            "personal_codex/skills/review-orchestration-playbook",
            "skills/review-orchestration-playbook",
            "skill",
        ),
        (
            "personal_codex/skills/synthetic-token-fixtures",
            "skills/synthetic-token-fixtures",
            "skill",
        ),
    }
    authority_sources = {source for source, _, _ in required}
    authority_targets = {target for _, target, _ in required}
    observed: list[tuple[object, object, object]] = []
    for entry in links:
        if not isinstance(entry, dict):
            raise BindingError("release sync manifest contains a non-object link")
        candidate = (
            entry.get("source"),
            entry.get("target"),
            entry.get("kind"),
        )
        if (
            candidate[0] in authority_sources or candidate[1] in authority_targets
        ) and candidate not in required:
            raise BindingError("release sync manifest has an ambiguous authority link")
        if candidate in required:
            observed.append(candidate)
    if len(observed) != len(set(observed)):
        raise BindingError("release sync manifest duplicates an authority link")
    if set(observed) != required:
        raise BindingError(
            "release sync manifest does not bind both co-release skill sources"
        )


def _runtime_source_specs(
    review_root: Path,
    runtime_files: dict[Path, bytes],
) -> dict[str, tuple[Path, bytes, bool]]:
    package_root = review_root / "scripts" / RUNTIME_NAMESPACE
    specs: dict[str, tuple[Path, bytes, bool]] = {}
    for path, payload in runtime_files.items():
        if path.parent == package_root and path.suffix == ".py":
            if path.name == "__init__.py":
                module_name = RUNTIME_NAMESPACE
                is_package = True
            else:
                module_name = f"{RUNTIME_NAMESPACE}.{path.stem}"
                is_package = False
            if module_name in specs:
                raise BindingError("review runtime source module is duplicated")
            specs[module_name] = (path, payload, is_package)
    if RUNTIME_NAMESPACE not in specs:
        raise BindingError("review runtime package source is missing")
    return specs


class _BoundSourceLoader:
    def __init__(
        self,
        *,
        module_name: str,
        origin: Path,
        code: types.CodeType,
    ) -> None:
        self.module_name = module_name
        self.origin = origin
        self.code = code

    def create_module(
        self,
        _spec: importlib.machinery.ModuleSpec,
    ) -> types.ModuleType | None:
        return None

    def exec_module(self, module: types.ModuleType) -> None:
        if module.__name__ != self.module_name:
            raise ImportError("bound catalog runtime module mismatch")
        exec(self.code, module.__dict__)

    def get_filename(self, fullname: str) -> str:
        if fullname != self.module_name:
            raise ImportError("bound catalog runtime module mismatch")
        return str(self.origin)


class _BoundRuntimeFinder:
    def __init__(
        self,
        specs: dict[str, tuple[Path, bytes, bool]],
    ) -> None:
        self._specs = specs
        self._loaders: dict[str, _BoundSourceLoader] = {}
        for module_name, (path, payload, _is_package) in specs.items():
            try:
                code = compile(payload, str(path), "exec", dont_inherit=True)
            except Exception as error:
                raise BindingError(
                    f"cannot compile bound review runtime source {path.name}: {error}"
                ) from error
            self._loaders[module_name] = _BoundSourceLoader(
                module_name=module_name,
                origin=path,
                code=code,
            )

    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname != RUNTIME_NAMESPACE and not fullname.startswith(
            f"{RUNTIME_NAMESPACE}."
        ):
            return None
        try:
            source_path, _payload, is_package = self._specs[fullname]
            loader = self._loaders[fullname]
        except KeyError as error:
            raise ImportError(
                f"bound catalog runtime import is outside the closed manifest: {fullname}"
            ) from error
        spec = importlib.machinery.ModuleSpec(
            fullname,
            loader,
            origin=str(source_path),
            is_package=is_package,
        )
        spec.has_location = True
        if is_package:
            spec.submodule_search_locations = []
        return spec


class _BoundTextSink:
    encoding = "utf-8"

    def __init__(self, *, label: str) -> None:
        self._label = label
        self._parts: list[str] = []
        self._size = 0

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("bound text sink accepts only text")
        encoded = value.encode("utf-8")
        self._size += len(encoded)
        if self._size > MAX_CLI_OUTPUT_BYTES:
            raise BindingError(f"{self._label} exceeds its byte limit")
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        return None

    def value(self) -> str:
        return "".join(self._parts)


def _remove_runtime_namespace() -> None:
    for module_name in tuple(sys.modules):
        if module_name == RUNTIME_NAMESPACE or module_name.startswith(
            f"{RUNTIME_NAMESPACE}."
        ):
            sys.modules.pop(module_name, None)


def _validate_catalog_result(
    *,
    action: str,
    requested_id: str | None,
    result: dict[str, Any],
    pool_version: str,
) -> None:
    if result.get("pool_version") != pool_version:
        raise BindingError("catalog CLI result has a mismatched pool_version")
    if action == "validate":
        if set(result) != {"pool_version", "schema_version", "status"}:
            raise BindingError("catalog validate result fields are not closed")
        if result["schema_version"] != 1 or result["status"] != "valid":
            raise BindingError("catalog validate result is not valid")
        return
    if action == "list":
        if set(result) != {"pool_version", "tokens"}:
            raise BindingError("catalog list result fields are not closed")
        tokens = result["tokens"]
        if not isinstance(tokens, list):
            raise BindingError("catalog list result tokens are not a list")
        for token in tokens:
            if not isinstance(token, dict) or set(token) != {
                "id",
                "role",
                "rule",
                "state",
                "value_sha256",
            }:
                raise BindingError(
                    "catalog list result exposes an invalid token record"
                )
            if "value" in token:
                raise BindingError("catalog list result exposed a raw token value")
        return
    if action == "get":
        if set(result) != {"pool_version", "token"}:
            raise BindingError("catalog get result fields are not closed")
        token = result["token"]
        if not isinstance(token, dict) or set(token) != {
            "id",
            "role",
            "rule",
            "state",
            "value",
            "value_sha256",
        }:
            raise BindingError("catalog get result token record is invalid")
        value = token["value"]
        if token["id"] != requested_id or not isinstance(value, str) or not value:
            raise BindingError("catalog get result does not match the requested token")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise BindingError("catalog get result value is not exact ASCII") from error
        if hashlib.sha256(encoded).hexdigest() != token["value_sha256"]:
            raise BindingError("catalog get result value digest is invalid")
        return
    raise BindingError("unknown catalog authoring action")


def _execute_catalog_snapshot(
    *,
    action: str,
    requested_id: str | None,
    review_root: Path,
    runtime_files: dict[Path, bytes],
    catalog_cli: Path,
    catalog_bytes: bytes,
    pool_version: str,
) -> dict[str, Any]:
    preexisting = sorted(
        name
        for name in sys.modules
        if name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
    )
    if preexisting:
        raise BindingError("a review_runtime module was loaded before catalog binding")

    specs = _runtime_source_specs(review_root, runtime_files)
    finder = _BoundRuntimeFinder(specs)
    cli_payload = runtime_files[catalog_cli]
    try:
        cli_code = compile(
            cli_payload,
            str(catalog_cli),
            "exec",
            dont_inherit=True,
        )
    except Exception as error:
        raise BindingError(f"catalog CLI snapshot cannot compile: {error}") from error

    stdout = _BoundTextSink(label="catalog CLI stdout")
    stderr = _BoundTextSink(label="catalog CLI stderr")
    sys.meta_path.insert(0, finder)
    try:
        wrapper_namespace = {
            "__builtins__": __builtins__,
            "__file__": str(catalog_cli),
            "__name__": "_active_catalog_bound_cli",
            "__package__": None,
        }
        exec(cli_code, wrapper_namespace)
        package = sys.modules.get(RUNTIME_NAMESPACE)
        importlib.import_module(f"{RUNTIME_NAMESPACE}.cli")
        cli_module = sys.modules.get(f"{RUNTIME_NAMESPACE}.cli")
        synthetic_module = sys.modules.get(f"{RUNTIME_NAMESPACE}.synthetic_tokens")
        if not all(
            isinstance(module, types.ModuleType)
            for module in (package, cli_module, synthetic_module)
        ):
            raise BindingError("bound catalog CLI did not load its required modules")
        if wrapper_namespace.get("main") is not getattr(package, "main", None):
            raise BindingError("catalog CLI wrapper entrypoint binding changed")
        if (
            "BOUND_CATALOG_BYTES" not in synthetic_module.__dict__
            or synthetic_module.__dict__["BOUND_CATALOG_BYTES"] is not None
        ):
            raise BindingError("catalog CLI bound-catalog byte hook changed")

        arguments = ["synthetic-tokens", action]
        if action == "list":
            arguments.append("--json")
        elif action == "get":
            if requested_id is None:
                raise BindingError("catalog get requires one token ID")
            arguments.extend((requested_id, "--json"))

        synthetic_module.__dict__["BOUND_CATALOG_BYTES"] = catalog_bytes
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                returncode = wrapper_namespace["main"](arguments)
        finally:
            synthetic_module.__dict__["BOUND_CATALOG_BYTES"] = None
        if returncode != 0:
            raise BindingError(f"catalog CLI snapshot returned exit {returncode}")
        if stderr.value():
            raise BindingError("catalog CLI snapshot emitted unexpected stderr")

        loaded_names = {
            name
            for name in sys.modules
            if name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
        }
        if not loaded_names <= set(specs):
            raise BindingError("catalog CLI runtime escaped its closed module manifest")
        for module_name in loaded_names:
            module = sys.modules[module_name]
            loader = getattr(module, "__loader__", None)
            if loader is not finder._loaders[module_name]:
                raise BindingError("catalog CLI runtime module loader changed")

        result = _load_json_object(
            stdout.value().encode("utf-8"),
            label="catalog CLI result",
        )
        _validate_catalog_result(
            action=action,
            requested_id=requested_id,
            result=result,
            pool_version=pool_version,
        )
        return result
    except BindingError:
        raise
    except BaseException as error:
        raise BindingError(
            f"catalog CLI snapshot execution failed: {type(error).__name__}: {error}"
        ) from error
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
        _remove_runtime_namespace()
        if any(
            name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
            for name in sys.modules
        ):
            raise BindingError("catalog CLI runtime cleanup was incomplete")


def _build_binding(
    *,
    resolver: Path,
    loaded_skill_root: Path,
    transaction: _BindingTransaction,
) -> tuple[dict[str, object], Path, dict[Path, bytes], bytes]:
    (
        release_root,
        payload_root,
        skills_root,
        synthetic_root,
        resolver_parent,
    ) = _validate_original_layout(
        resolver,
        loaded_skill_root,
        transaction,
    )
    resolver_bound = transaction.bind(
        resolver,
        label="binding resolver",
        retain_descriptor=True,
        parent=resolver_parent,
    )
    synthetic_skill = transaction.bind(
        synthetic_root / "SKILL.md",
        label="loaded synthetic skill",
        parent=transaction.directory(synthetic_root),
    )

    review_root = skills_root / "review-orchestration-playbook"
    sync_manifest = payload_root / "sync-manifest.json"
    manifest_bound = transaction.bind(
        sync_manifest,
        label="release sync manifest",
        parent=transaction.directory(payload_root),
    )
    if manifest_bound.payload is None:
        raise BindingError("release sync manifest snapshot omitted its content")
    _validate_sync_manifest(manifest_bound.payload)

    runtime_digest, runtime_files, retained_runtime = _runtime_snapshot(
        review_root,
        transaction,
    )
    catalog_cli = review_root / "scripts" / "isolated_review"
    catalog = (
        review_root / "scripts" / RUNTIME_NAMESPACE / "synthetic-token-catalog.json"
    )
    catalog_bytes = runtime_files[catalog]
    pool_version = _parse_pool_version(catalog_bytes)

    interpreter = Path(sys.executable).resolve(strict=True)
    interpreter_parent = transaction.bind_parent_chain(
        interpreter.parent,
        label="active Python interpreter absolute parent chain",
    )
    interpreter_bound = transaction.bind(
        interpreter,
        label="active Python interpreter",
        limit=MAX_INTERPRETER_BYTES,
        allow_root_owner=True,
        retain_descriptor=True,
        retain_payload=False,
        parent=interpreter_parent,
    )
    binding: dict[str, object] = {
        "schema_version": 2,
        "release_id": release_root.name,
        "release_root": str(release_root),
        "sync_manifest_path": str(sync_manifest),
        "sync_manifest_sha256": manifest_bound.sha256,
        "synthetic_skill_root": str(synthetic_root),
        "synthetic_skill_sha256": synthetic_skill.sha256,
        "binding_resolver_path": str(resolver),
        "binding_resolver_sha256": resolver_bound.sha256,
        "binding_resolver_identity": list(resolver_bound.identity),
        "review_skill_root": str(review_root),
        "review_runtime_tree_sha256": runtime_digest,
        "catalog_cli_path": str(catalog_cli),
        "catalog_cli_sha256": retained_runtime[catalog_cli].sha256,
        "catalog_cli_identity": list(retained_runtime[catalog_cli].identity),
        "catalog_path": str(catalog),
        "catalog_sha256": retained_runtime[catalog].sha256,
        "catalog_identity": list(retained_runtime[catalog].identity),
        "pool_version": pool_version,
        "python_executable": str(interpreter),
        "python_executable_sha256": interpreter_bound.sha256,
        "python_executable_identity": list(interpreter_bound.identity),
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_flags": ["-I", "-B", "-S"],
        "execution_mode": "in-process-manifest-bound-snapshot",
        "import_mode": "closed-review-runtime-snapshot",
    }
    encoded = json.dumps(
        binding,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    binding["binding_sha256"] = hashlib.sha256(encoded).hexdigest()
    return binding, review_root, runtime_files, catalog_bytes


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bind and execute synthetic-token authoring through one active-release "
            "snapshot transaction."
        )
    )
    parser.add_argument("--loaded-skill-root", required=True)
    parser.add_argument("--expect-binding-sha256")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("bind")
    actions.add_parser("validate")
    actions.add_parser("list")
    get_parser = actions.add_parser("get")
    get_parser.add_argument("id")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    transaction = _BindingTransaction()
    output: dict[str, object] | None = None
    try:
        resolver = Path(__file__)
        loaded_skill_root = Path(arguments.loaded_skill_root)
        binding, review_root, runtime_files, catalog_bytes = _build_binding(
            resolver=resolver,
            loaded_skill_root=loaded_skill_root,
            transaction=transaction,
        )
        expected = arguments.expect_binding_sha256
        if expected is not None:
            if SHA256.fullmatch(expected) is None:
                raise BindingError("expected binding digest is not canonical SHA-256")
            if expected != binding["binding_sha256"]:
                raise BindingError("active catalog binding changed")

        if arguments.action == "bind":
            output = binding
        else:
            catalog_cli = review_root / "scripts" / "isolated_review"
            result = _execute_catalog_snapshot(
                action=arguments.action,
                requested_id=getattr(arguments, "id", None),
                review_root=review_root,
                runtime_files=runtime_files,
                catalog_cli=catalog_cli,
                catalog_bytes=catalog_bytes,
                pool_version=str(binding["pool_version"]),
            )
            canonical_result = json.dumps(
                result,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            output = {
                "schema_version": 1,
                "operation": arguments.action,
                "binding": binding,
                "result": result,
                "result_sha256": hashlib.sha256(canonical_result).hexdigest(),
            }
    except (BindingError, OSError) as error:
        try:
            transaction.close()
        except BindingError as cleanup_error:
            print(
                f"active catalog binding cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
        print(f"active catalog binding failed: {error}", file=sys.stderr)
        return 2

    try:
        transaction.close()
    except BindingError as error:
        print(f"active catalog binding cleanup failed: {error}", file=sys.stderr)
        return 2
    if output is None:
        print(
            "active catalog binding failed: missing transaction output", file=sys.stderr
        )
        return 2
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
