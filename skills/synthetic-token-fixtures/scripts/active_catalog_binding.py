#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_CATALOG_BYTES = 64 * 1024
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_FILES = 512
EXECUTABLE_CACHE_SUFFIXES = {".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll"}
RELEASE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BindingError(RuntimeError):
    pass


def _require_safe_file_primitives() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise BindingError("active catalog binding requires a POSIX runtime")
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        if not hasattr(os, name):
            raise BindingError(f"active catalog binding requires {name}")


def _read_regular(
    path: Path,
    *,
    label: str,
    limit: int = MAX_FILE_BYTES,
    allow_root_owner: bool = False,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BindingError(f"{label} cannot be opened safely: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BindingError(f"{label} is not a regular file")
        if before.st_uid != os.geteuid() and not (
            allow_root_owner and before.st_uid == 0
        ):
            raise BindingError(f"{label} is not owned by the current user")
        if before.st_mode & 0o022:
            raise BindingError(f"{label} is group/world writable")
        if before.st_size > limit:
            raise BindingError(f"{label} exceeds its byte limit")
        chunks: list[bytes] = []
        retained = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - retained))
            if not chunk:
                break
            chunks.append(chunk)
            retained += len(chunk)
            if retained > limit:
                raise BindingError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_size,
        ):
            raise BindingError(f"{label} changed during the validated read")
    finally:
        os.close(descriptor)

    try:
        current = path.lstat()
    except OSError as error:
        raise BindingError(f"{label} path cannot be revalidated: {error}") from error
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_size,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_size,
    ):
        raise BindingError(f"{label} path identity changed during the read")
    return b"".join(chunks)


def _require_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BindingError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise BindingError(f"{label} is not a directory")
    if metadata.st_uid != os.geteuid():
        raise BindingError(f"{label} is not owned by the current user")
    if metadata.st_mode & 0o022:
        raise BindingError(f"{label} is group/world writable")


def _runtime_paths(review_root: Path) -> tuple[Path, ...]:
    scripts_root = review_root / "scripts"
    package_root = scripts_root / "review_runtime"
    _require_directory(review_root, label="review skill root")
    _require_directory(scripts_root, label="review runtime root")
    _require_directory(package_root, label="review runtime package")
    for suffix in EXECUTABLE_CACHE_SUFFIXES | {".py"}:
        shadow = scripts_root / f"review_runtime{suffix}"
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


def _runtime_digest(review_root: Path) -> tuple[str, dict[Path, bytes]]:
    first = _runtime_paths(review_root)
    retained: dict[Path, bytes] = {}
    total = 0
    digest = hashlib.sha256(b"review-runtime-tree-v1\0")
    for path in first:
        relative = path.relative_to(review_root).as_posix().encode("utf-8")
        content = _read_regular(path, label=f"review runtime {relative!r}")
        total += len(content)
        if total > MAX_RUNTIME_BYTES:
            raise BindingError("review runtime exceeds its aggregate byte limit")
        retained[path] = content
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    if first != _runtime_paths(review_root):
        raise BindingError("review runtime membership changed during binding")
    for path, content in retained.items():
        if _read_regular(path, label="review runtime final revalidation") != content:
            raise BindingError("review runtime content changed during binding")
    return digest.hexdigest(), retained


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


def _sha256(
    path: Path,
    *,
    label: str,
    limit: int = MAX_FILE_BYTES,
    allow_root_owner: bool = False,
) -> str:
    return hashlib.sha256(
        _read_regular(
            path,
            label=label,
            limit=limit,
            allow_root_owner=allow_root_owner,
        )
    ).hexdigest()


def build_binding() -> dict[str, object]:
    _require_safe_file_primitives()
    resolver = Path(__file__).resolve(strict=True)
    synthetic_root = resolver.parents[1]
    skills_root = synthetic_root.parent
    payload_root = skills_root.parent
    release_root = payload_root.parent

    if synthetic_root.name != "synthetic-token-fixtures":
        raise BindingError("resolver is not inside synthetic-token-fixtures")
    if skills_root.name != "skills" or payload_root.name != "personal_codex":
        raise BindingError("resolver is not inside a personal Codex release payload")
    if (
        release_root.parent.name != "releases"
        or RELEASE_ID.fullmatch(release_root.name) is None
    ):
        raise BindingError("resolver is not inside a versioned immutable release")

    for path, label in (
        (release_root, "release root"),
        (payload_root, "release payload root"),
        (skills_root, "release skills root"),
        (synthetic_root, "synthetic skill root"),
    ):
        _require_directory(path, label=label)

    review_root = skills_root / "review-orchestration-playbook"
    sync_manifest = payload_root / "sync-manifest.json"
    sync_manifest_bytes = _read_regular(sync_manifest, label="release sync manifest")
    _validate_sync_manifest(sync_manifest_bytes)
    runtime_digest, runtime_files = _runtime_digest(review_root)
    catalog_cli = review_root / "scripts" / "isolated_review"
    catalog = (
        review_root / "scripts" / "review_runtime" / "synthetic-token-catalog.json"
    )
    if catalog_cli not in runtime_files or catalog not in runtime_files:
        raise BindingError("review runtime binding omitted the catalog CLI or catalog")

    interpreter = Path(sys.executable).resolve(strict=True)
    binding: dict[str, object] = {
        "schema_version": 1,
        "release_id": release_root.name,
        "release_root": str(release_root),
        "sync_manifest_path": str(sync_manifest),
        "sync_manifest_sha256": hashlib.sha256(sync_manifest_bytes).hexdigest(),
        "synthetic_skill_root": str(synthetic_root),
        "synthetic_skill_sha256": _sha256(
            synthetic_root / "SKILL.md", label="synthetic skill"
        ),
        "binding_resolver_path": str(resolver),
        "binding_resolver_sha256": _sha256(resolver, label="binding resolver"),
        "review_skill_root": str(review_root),
        "review_runtime_tree_sha256": runtime_digest,
        "catalog_cli_path": str(catalog_cli),
        "catalog_cli_sha256": hashlib.sha256(runtime_files[catalog_cli]).hexdigest(),
        "catalog_path": str(catalog),
        "catalog_sha256": hashlib.sha256(runtime_files[catalog]).hexdigest(),
        "pool_version": _parse_pool_version(runtime_files[catalog]),
        "python_executable": str(interpreter),
        "python_executable_sha256": _sha256(
            interpreter,
            label="active Python interpreter",
            limit=128 * 1024 * 1024,
            allow_root_owner=True,
        ),
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
    }
    encoded = json.dumps(
        binding, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    binding["binding_sha256"] = hashlib.sha256(encoded).hexdigest()
    return binding


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bind synthetic-token authoring to its active review release."
    )
    parser.add_argument("--expect-binding-sha256")
    arguments = parser.parse_args(argv)
    try:
        binding = build_binding()
        expected = arguments.expect_binding_sha256
        if expected is not None:
            if SHA256.fullmatch(expected) is None:
                raise BindingError("expected binding digest is not canonical SHA-256")
            if expected != binding["binding_sha256"]:
                raise BindingError("active catalog binding changed")
    except BindingError as error:
        print(f"active catalog binding failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(binding, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
