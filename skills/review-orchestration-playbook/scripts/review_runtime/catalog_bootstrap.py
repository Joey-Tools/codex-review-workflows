"""Execute the co-release synthetic catalog resolver from trusted bound bytes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SKILL_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
RELEASE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESOLVER_LEAF = "active_catalog_binding.py"
SYNTHETIC_SKILL_NAME = "synthetic-token-fixtures"
REVIEW_SKILL_NAME = "review-orchestration-playbook"
RUNTIME_MANIFEST_LEAF = "synthetic-catalog-runtime-manifest.json"
RUNTIME_PROFILE = "synthetic-catalog-authoring-v1"


class CatalogBootstrapError(RuntimeError):
    """Reject an unsafe or inconsistent catalog resolver launch."""


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


def _require_safe_primitives() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise CatalogBootstrapError("catalog bootstrap requires a POSIX runtime")
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
        if not hasattr(os, name):
            raise CatalogBootstrapError(f"catalog bootstrap requires {name}")


def _validate_directory_policy(
    metadata: os.stat_result,
    *,
    label: str,
    require_current_user: bool = False,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise CatalogBootstrapError(f"{label} is not an ordinary non-symlink directory")
    accepted_owners = {0, os.geteuid()}
    if metadata.st_uid not in accepted_owners:
        raise CatalogBootstrapError(f"{label} has an untrusted owner")
    if require_current_user and metadata.st_uid != os.geteuid():
        raise CatalogBootstrapError(f"{label} is not owned by the current user")
    if metadata.st_mode & 0o022:
        shared_sticky_root = (
            metadata.st_uid == 0
            and bool(metadata.st_mode & stat.S_ISVTX)
            and bool(metadata.st_mode & 0o002)
        )
        if not shared_sticky_root:
            raise CatalogBootstrapError(f"{label} is group/world writable")


def _require_canonical_absolute(path: Path, *, label: str) -> None:
    raw = str(path)
    if not path.is_absolute():
        raise CatalogBootstrapError(f"{label} must be absolute")
    if raw != os.path.normpath(raw):
        raise CatalogBootstrapError(f"{label} must be lexically canonical")


def _read_descriptor(
    descriptor: int,
    *,
    label: str,
    limit: int,
) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise CatalogBootstrapError(
            f"{label} cannot be rewound safely: {error}"
        ) from error
    payload = bytearray()
    while len(payload) <= limit:
        try:
            chunk = os.read(
                descriptor,
                min(64 * 1024, limit + 1 - len(payload)),
            )
        except OSError as error:
            raise CatalogBootstrapError(
                f"{label} cannot be read safely: {error}"
            ) from error
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > limit:
        raise CatalogBootstrapError(f"{label} exceeds its byte limit")
    return bytes(payload)


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

    def close(self, *, revalidate: bool) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: CatalogBootstrapError | None = None
        try:
            if revalidate:
                current = os.fstat(descriptor)
                _validate_directory_policy(
                    current,
                    label=f"bound directory {self.path}",
                )
                if _directory_identity(current) != self.identity:
                    raise CatalogBootstrapError(
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
                        label=f"bound directory entry {self.path}",
                    )
                    if _directory_identity(lexical) != self.identity:
                        raise CatalogBootstrapError(
                            f"bound directory entry changed for {self.path}"
                        )
        except (CatalogBootstrapError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, CatalogBootstrapError)
                else CatalogBootstrapError(
                    f"cannot revalidate bound directory {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise CatalogBootstrapError(
                f"cannot close bound directory {self.path}: {error}"
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
        payload: bytes,
        limit: int,
        parent: _BoundDirectory,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.payload = payload
        self.sha256 = hashlib.sha256(payload).hexdigest()
        self.limit = limit
        self.parent = parent

    def close(self, *, revalidate: bool) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: CatalogBootstrapError | None = None
        try:
            if revalidate:
                current = os.fstat(descriptor)
                if _file_identity(current) != self.identity:
                    raise CatalogBootstrapError(
                        f"bound descriptor identity changed for {self.path}"
                    )
                payload = _read_descriptor(
                    descriptor,
                    label=f"final bound read for {self.path}",
                    limit=self.limit,
                )
                if payload != self.payload:
                    raise CatalogBootstrapError(
                        f"bound descriptor content changed for {self.path}"
                    )
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
                    raise CatalogBootstrapError(
                        f"bound parent entry identity changed for {self.path}"
                    )
        except (CatalogBootstrapError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, CatalogBootstrapError)
                else CatalogBootstrapError(
                    f"cannot revalidate bound file {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise CatalogBootstrapError(
                f"cannot close bound file {self.path}: {error}"
            ) from error
        if validation_error is not None:
            raise validation_error


class _BindingTransaction:
    def __init__(self) -> None:
        self._directories: list[_BoundDirectory] = []
        self._directories_by_path: dict[Path, _BoundDirectory] = {}
        self._files: list[_BoundFile] = []

    def bind_parent_chain(self, path: Path, *, label: str) -> _BoundDirectory:
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
                    raise CatalogBootstrapError(
                        f"{label} has an inconsistent parent chain"
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
                raise CatalogBootstrapError(
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
                raise CatalogBootstrapError(
                    f"{label} component {current} cannot be opened: {error}"
                ) from error
            opened = os.fstat(descriptor)
            if _directory_identity(opened) != _directory_identity(lexical):
                os.close(descriptor)
                raise CatalogBootstrapError(
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

    def bind_child_directory(
        self,
        path: Path,
        *,
        label: str,
        parent: _BoundDirectory,
        require_current_user: bool = False,
    ) -> _BoundDirectory:
        if path.parent != parent.path:
            raise CatalogBootstrapError(f"{label} parent binding is inconsistent")
        existing = self._directories_by_path.get(path)
        if existing is not None:
            return existing
        try:
            lexical = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise CatalogBootstrapError(
                f"{label} cannot be inspected safely: {error}"
            ) from error
        _validate_directory_policy(
            lexical,
            label=label,
            require_current_user=require_current_user,
        )
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
                dir_fd=parent.descriptor,
            )
        except OSError as error:
            raise CatalogBootstrapError(
                f"{label} cannot be opened safely: {error}"
            ) from error
        opened = os.fstat(descriptor)
        if _directory_identity(opened) != _directory_identity(lexical):
            os.close(descriptor)
            raise CatalogBootstrapError(f"{label} changed before binding")
        bound = _BoundDirectory(
            path=path,
            descriptor=descriptor,
            identity=_directory_identity(opened),
            parent=parent,
        )
        self._directories.append(bound)
        self._directories_by_path[path] = bound
        return bound

    def directory(self, path: Path) -> _BoundDirectory:
        try:
            return self._directories_by_path[path]
        except KeyError as error:
            raise CatalogBootstrapError(f"directory is not bound: {path}") from error

    def bind_file(
        self,
        path: Path,
        *,
        label: str,
        limit: int,
        parent: _BoundDirectory,
        expected_payload: bytes | None = None,
    ) -> _BoundFile:
        if path.parent != parent.path:
            raise CatalogBootstrapError(f"{label} parent binding is inconsistent")
        try:
            lexical = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise CatalogBootstrapError(
                f"{label} cannot be inspected safely: {error}"
            ) from error
        if not stat.S_ISREG(lexical.st_mode) or stat.S_ISLNK(lexical.st_mode):
            raise CatalogBootstrapError(
                f"{label} is not an ordinary non-symlink regular file"
            )
        if lexical.st_uid != os.geteuid():
            raise CatalogBootstrapError(f"{label} is not owned by the current user")
        if lexical.st_mode & 0o022:
            raise CatalogBootstrapError(f"{label} is group/world writable")
        if lexical.st_size > limit:
            raise CatalogBootstrapError(f"{label} exceeds its byte limit")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent.descriptor)
        except OSError as error:
            raise CatalogBootstrapError(
                f"{label} cannot be opened safely: {error}"
            ) from error
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _file_identity(
                opened
            ) != _file_identity(lexical):
                raise CatalogBootstrapError(f"{label} identity changed before binding")
            first = _read_descriptor(descriptor, label=label, limit=limit)
            second = _read_descriptor(descriptor, label=label, limit=limit)
            final = os.fstat(descriptor)
            if _file_identity(final) != _file_identity(opened):
                raise CatalogBootstrapError(f"{label} identity changed during binding")
            if first != second or len(first) != opened.st_size:
                raise CatalogBootstrapError(f"{label} content changed during binding")
            if expected_payload is not None and first != expected_payload:
                raise CatalogBootstrapError(
                    f"{label} does not match the trusted control manifest"
                )
            bound = _BoundFile(
                path=path,
                descriptor=descriptor,
                identity=_file_identity(opened),
                payload=first,
                limit=limit,
                parent=parent,
            )
            self._files.append(bound)
            return bound
        except BaseException:
            os.close(descriptor)
            raise

    def close(self, *, revalidate: bool) -> None:
        errors: list[str] = []
        while self._files:
            bound = self._files.pop()
            try:
                bound.close(revalidate=revalidate)
            except CatalogBootstrapError as error:
                errors.append(str(error))
        while self._directories:
            bound = self._directories.pop()
            try:
                bound.close(revalidate=revalidate)
            except CatalogBootstrapError as error:
                errors.append(str(error))
        self._directories_by_path.clear()
        if errors:
            raise CatalogBootstrapError("; ".join(errors))


class _BoundTextSink:
    encoding = "utf-8"

    def __init__(self, *, label: str) -> None:
        self._label = label
        self._parts: list[str] = []
        self._size = 0

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("catalog bootstrap output accepts text only")
        encoded = value.encode("utf-8")
        self._size += len(encoded)
        if self._size > MAX_OUTPUT_BYTES:
            raise CatalogBootstrapError(f"{self._label} exceeds its byte limit")
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        return None

    def value(self) -> str:
        return "".join(self._parts)


def _load_json_object(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CatalogBootstrapError(f"{label} contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogBootstrapError(f"{label} JSON is invalid: {error}") from error
    if not isinstance(payload, dict):
        raise CatalogBootstrapError(f"{label} root is not an object")
    return payload


def _validate_sync_manifest(content: bytes) -> None:
    manifest = _load_json_object(content, label="release sync manifest")
    if manifest.get("version") != 1:
        raise CatalogBootstrapError("release sync manifest version is unsupported")
    links = manifest.get("links")
    if not isinstance(links, list):
        raise CatalogBootstrapError("release sync manifest links are not a list")
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
            raise CatalogBootstrapError(
                "release sync manifest contains a non-object link"
            )
        candidate = (
            entry.get("source"),
            entry.get("target"),
            entry.get("kind"),
        )
        if (
            candidate[0] in authority_sources or candidate[1] in authority_targets
        ) and candidate not in required:
            raise CatalogBootstrapError(
                "release sync manifest has an ambiguous authority link"
            )
        if candidate in required:
            observed.append(candidate)
    if len(observed) != len(set(observed)):
        raise CatalogBootstrapError(
            "release sync manifest duplicates an authority link"
        )
    if set(observed) != required:
        raise CatalogBootstrapError(
            "release sync manifest does not bind both co-release skill sources"
        )


def _loaded_skill_root_from_argv(argv: tuple[str, ...]) -> Path:
    values: list[str] = []
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--loaded-skill-root":
            if index + 1 >= len(argv):
                raise CatalogBootstrapError("--loaded-skill-root is missing its value")
            values.append(argv[index + 1])
            index += 2
            continue
        if value.startswith("--loaded-skill-root="):
            values.append(value.split("=", 1)[1])
        index += 1
    if len(values) != 1 or not values[0]:
        raise CatalogBootstrapError(
            "catalog bootstrap requires exactly one --loaded-skill-root"
        )
    path = Path(values[0])
    _require_canonical_absolute(path, label="loaded synthetic skill root")
    return path


def _validate_release_layout(
    *,
    trusted_review_skill_root: Path,
    trusted_synthetic_skill_root: Path,
    resolver_path: Path,
    loaded_skill_root: Path,
) -> tuple[Path, Path, Path]:
    for path, label in (
        (trusted_review_skill_root, "trusted review skill root"),
        (trusted_synthetic_skill_root, "trusted synthetic skill root"),
        (resolver_path, "catalog resolver path"),
    ):
        _require_canonical_absolute(path, label=label)
    if loaded_skill_root != trusted_synthetic_skill_root:
        raise CatalogBootstrapError(
            "loaded synthetic skill is outside the trusted catalog bundle"
        )
    skills_root = trusted_review_skill_root.parent
    if (
        trusted_review_skill_root.name != REVIEW_SKILL_NAME
        or trusted_synthetic_skill_root.name != SYNTHETIC_SKILL_NAME
        or trusted_synthetic_skill_root.parent != skills_root
    ):
        raise CatalogBootstrapError("trusted catalog skill layout is invalid")
    expected_resolver = trusted_synthetic_skill_root / "scripts" / RESOLVER_LEAF
    if resolver_path != expected_resolver:
        raise CatalogBootstrapError("catalog resolver path is not the trusted leaf")
    payload_root = skills_root.parent
    release_root = payload_root.parent
    if (
        skills_root.name != "skills"
        or payload_root.name != "personal_codex"
        or release_root.parent.name != "releases"
        or RELEASE_ID.fullmatch(release_root.name) is None
    ):
        raise CatalogBootstrapError(
            "catalog bootstrap is not inside a versioned immutable release"
        )
    return release_root, payload_root, skills_root


def _main(
    argv: list[str] | tuple[str, ...] | None = None,
    *,
    trusted_review_skill_root: Path | None = None,
    trusted_synthetic_skill_root: Path | None = None,
    trusted_resolver_path: Path | None = None,
    trusted_resolver_bytes: bytes | None = None,
    trusted_skill_bytes: bytes | None = None,
    catalog_bootstrap_source_sha256: str | None = None,
    trusted_runtime_manifest_path: Path | None = None,
    trusted_runtime_manifest_bytes: bytes | None = None,
    trusted_runtime_manifest_sha256: str | None = None,
) -> int:
    """Bind, execute, and revalidate the trusted co-release resolver."""
    _require_safe_primitives()
    if (
        trusted_review_skill_root is None
        or trusted_synthetic_skill_root is None
        or trusted_resolver_path is None
        or trusted_resolver_bytes is None
        or trusted_skill_bytes is None
        or catalog_bootstrap_source_sha256 is None
        or trusted_runtime_manifest_path is None
        or trusted_runtime_manifest_bytes is None
        or trusted_runtime_manifest_sha256 is None
    ):
        raise CatalogBootstrapError(
            "catalog bootstrap requires manifest-bound guard inputs"
        )
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if not all(isinstance(value, str) for value in arguments):
        raise CatalogBootstrapError("catalog bootstrap arguments must be text")
    loaded_skill_root = _loaded_skill_root_from_argv(arguments)
    release_root, payload_root, skills_root = _validate_release_layout(
        trusted_review_skill_root=trusted_review_skill_root,
        trusted_synthetic_skill_root=trusted_synthetic_skill_root,
        resolver_path=trusted_resolver_path,
        loaded_skill_root=loaded_skill_root,
    )
    expected_runtime_manifest = (
        trusted_review_skill_root / "scripts" / "review_runtime" / RUNTIME_MANIFEST_LEAF
    )
    _require_canonical_absolute(
        trusted_runtime_manifest_path,
        label="trusted catalog runtime manifest",
    )
    if trusted_runtime_manifest_path != expected_runtime_manifest:
        raise CatalogBootstrapError(
            "trusted catalog runtime manifest path is not canonical"
        )
    if (
        type(trusted_runtime_manifest_bytes) is not bytes
        or len(trusted_runtime_manifest_bytes) > MAX_MANIFEST_BYTES
        or not isinstance(trusted_runtime_manifest_sha256, str)
        or SHA256.fullmatch(trusted_runtime_manifest_sha256) is None
        or hashlib.sha256(trusted_runtime_manifest_bytes).hexdigest()
        != trusted_runtime_manifest_sha256
    ):
        raise CatalogBootstrapError(
            "trusted catalog runtime manifest bytes are not guard-bound"
        )

    transaction = _BindingTransaction()
    stdout = _BoundTextSink(label="catalog resolver stdout")
    stderr = _BoundTextSink(label="catalog resolver stderr")
    returncode = 2
    try:
        resolver_parent = transaction.bind_parent_chain(
            trusted_resolver_path.parent,
            label="catalog resolver absolute parent chain",
        )
        for path, label in (
            (release_root, "release root"),
            (payload_root, "release payload root"),
            (skills_root, "release skills root"),
            (trusted_synthetic_skill_root, "loaded synthetic skill root"),
            (trusted_resolver_path.parent, "loaded synthetic scripts root"),
        ):
            bound = transaction.directory(path)
            current = os.fstat(bound.descriptor)
            _validate_directory_policy(
                current,
                label=label,
                require_current_user=True,
            )
        review_root = transaction.bind_child_directory(
            trusted_review_skill_root,
            label="trusted review skill root",
            parent=transaction.directory(skills_root),
            require_current_user=True,
        )
        if review_root.path != trusted_review_skill_root:
            raise CatalogBootstrapError("trusted review skill binding changed")

        resolver_bound = transaction.bind_file(
            trusted_resolver_path,
            label="catalog resolver",
            limit=MAX_SOURCE_BYTES,
            parent=resolver_parent,
            expected_payload=trusted_resolver_bytes,
        )
        skill_bound = transaction.bind_file(
            trusted_synthetic_skill_root / "SKILL.md",
            label="loaded synthetic skill",
            limit=MAX_SKILL_BYTES,
            parent=transaction.directory(trusted_synthetic_skill_root),
            expected_payload=trusted_skill_bytes,
        )
        manifest_bound = transaction.bind_file(
            payload_root / "sync-manifest.json",
            label="release sync manifest",
            limit=MAX_MANIFEST_BYTES,
            parent=transaction.directory(payload_root),
        )
        _validate_sync_manifest(manifest_bound.payload)
        runtime_manifest_parent = transaction.bind_parent_chain(
            trusted_runtime_manifest_path.parent,
            label="catalog runtime manifest absolute parent chain",
        )
        runtime_manifest_bound = transaction.bind_file(
            trusted_runtime_manifest_path,
            label="catalog runtime manifest",
            limit=MAX_MANIFEST_BYTES,
            parent=runtime_manifest_parent,
            expected_payload=trusted_runtime_manifest_bytes,
        )
        if runtime_manifest_bound.sha256 != trusted_runtime_manifest_sha256:
            raise CatalogBootstrapError(
                "catalog runtime manifest digest changed after guard binding"
            )
        runtime_manifest = _load_json_object(
            runtime_manifest_bound.payload,
            label="catalog runtime manifest",
        )
        if (
            runtime_manifest.get("schema_version") != 1
            or runtime_manifest.get("profile") != RUNTIME_PROFILE
        ):
            raise CatalogBootstrapError(
                "catalog runtime manifest profile is unsupported"
            )

        bootstrap_binding: dict[str, object] = {
            "schema_version": 1,
            "mode": "trusted-guard-manifest-bound-source",
            "release_id": release_root.name,
            "trusted_review_skill_root": str(trusted_review_skill_root),
            "synthetic_skill_root": str(trusted_synthetic_skill_root),
            "synthetic_skill_sha256": skill_bound.sha256,
            "resolver_path": str(trusted_resolver_path),
            "resolver_sha256": resolver_bound.sha256,
            "resolver_identity": list(resolver_bound.identity),
            "sync_manifest_path": str(manifest_bound.path),
            "sync_manifest_sha256": manifest_bound.sha256,
            "catalog_bootstrap_source_sha256": catalog_bootstrap_source_sha256,
            "runtime_manifest_path": str(runtime_manifest_bound.path),
            "runtime_manifest_sha256": runtime_manifest_bound.sha256,
            "runtime_manifest_identity": list(runtime_manifest_bound.identity),
            "runtime_profile": RUNTIME_PROFILE,
        }

        try:
            code = compile(
                resolver_bound.payload,
                str(trusted_resolver_path),
                "exec",
                dont_inherit=True,
            )
        except Exception as error:
            raise CatalogBootstrapError(
                f"catalog resolver source cannot compile: {error}"
            ) from error
        namespace = {
            "__builtins__": __builtins__,
            "__file__": str(trusted_resolver_path),
            "__name__": "_trusted_catalog_bound_resolver",
            "__package__": None,
        }
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exec(code, namespace)
            if namespace.get("BOOTSTRAP_CONTRACT_VERSION") != 1:
                raise CatalogBootstrapError(
                    "catalog resolver bootstrap contract is unsupported"
                )
            entrypoint = namespace.get("main")
            if not callable(entrypoint):
                raise CatalogBootstrapError("catalog resolver entrypoint is missing")
            result = entrypoint(
                list(arguments),
                bootstrap_binding=bootstrap_binding,
                runtime_manifest_bytes=runtime_manifest_bound.payload,
            )
        if not isinstance(result, int) or isinstance(result, bool):
            raise CatalogBootstrapError(
                "catalog resolver returned a non-integer status"
            )
        returncode = result
        transaction.close(revalidate=True)
    except (CatalogBootstrapError, OSError) as error:
        try:
            transaction.close(revalidate=True)
        except CatalogBootstrapError as cleanup_error:
            print(
                f"trusted catalog bootstrap cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
        print(f"trusted catalog bootstrap failed: {error}", file=sys.stderr)
        return 2
    except BaseException as error:
        try:
            transaction.close(revalidate=True)
        except CatalogBootstrapError as cleanup_error:
            print(
                f"trusted catalog bootstrap cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
        print(
            "trusted catalog bootstrap failed: resolver execution failed: "
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 2

    sys.stdout.write(stdout.value())
    sys.stdout.flush()
    sys.stderr.write(stderr.value())
    sys.stderr.flush()
    return returncode


def main(
    argv: list[str] | tuple[str, ...] | None = None,
    *,
    trusted_review_skill_root: Path | None = None,
    trusted_synthetic_skill_root: Path | None = None,
    trusted_resolver_path: Path | None = None,
    trusted_resolver_bytes: bytes | None = None,
    trusted_skill_bytes: bytes | None = None,
    catalog_bootstrap_source_sha256: str | None = None,
    trusted_runtime_manifest_path: Path | None = None,
    trusted_runtime_manifest_bytes: bytes | None = None,
    trusted_runtime_manifest_sha256: str | None = None,
) -> int:
    """Return a closed CLI failure for pre-transaction binding errors."""
    try:
        return _main(
            argv,
            trusted_review_skill_root=trusted_review_skill_root,
            trusted_synthetic_skill_root=trusted_synthetic_skill_root,
            trusted_resolver_path=trusted_resolver_path,
            trusted_resolver_bytes=trusted_resolver_bytes,
            trusted_skill_bytes=trusted_skill_bytes,
            catalog_bootstrap_source_sha256=catalog_bootstrap_source_sha256,
            trusted_runtime_manifest_path=trusted_runtime_manifest_path,
            trusted_runtime_manifest_bytes=trusted_runtime_manifest_bytes,
            trusted_runtime_manifest_sha256=trusted_runtime_manifest_sha256,
        )
    except (CatalogBootstrapError, OSError) as error:
        print(f"trusted catalog bootstrap failed: {error}", file=sys.stderr)
        return 2


__all__ = ["CatalogBootstrapError", "main"]
