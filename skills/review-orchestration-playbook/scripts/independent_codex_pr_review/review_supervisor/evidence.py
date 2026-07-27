from __future__ import annotations

import hmac
import os
import stat
from dataclasses import dataclass
from typing import Iterable, Literal

from .constants import (
    MAX_EVIDENCE_BUNDLE_BYTES,
    MAX_EVIDENCE_CONTEXT_BYTES,
    MAX_EVIDENCE_CONTEXT_FILE_BYTES,
    MAX_EVIDENCE_CONTEXT_FILES,
    MAX_EVIDENCE_PRIMARY_BYTES,
    PRIMARY_DIFF_RELATIVE_PATH,
)
from .secureio import canonical_json, identity_from_stat, read_fd_exact, sha256_bytes


MANIFEST_SCHEMA = "appserver-evidence-manifest-v1"
BUNDLE_SCHEMA = "appserver-evidence-bundle-v1"
_SHA256_LENGTH = 64
_PATH_BYTES_LIMIT = 4096
_GLOB_CHARACTERS = frozenset("*?[]{}")


class EvidenceError(ValueError):
    """The pre-launch evidence could not be authenticated or safely bundled."""


class EvidenceBundleSizeError(EvidenceError):
    """The canonical evidence bundle exceeds its serialized byte budget."""


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: Literal["regular", "symlink", "gitlink"]
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _validate_relative_path(self.path)
        if not isinstance(self.kind, str) or self.kind not in {
            "regular",
            "symlink",
            "gitlink",
        }:
            raise EvidenceError("manifest entry kind is invalid")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
        ):
            raise EvidenceError("manifest entry size is invalid")
        if not _is_sha256(self.sha256):
            raise EvidenceError("manifest entry digest is invalid")

    def to_json(self) -> dict[str, int | str]:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class AuthenticatedManifest:
    entries: tuple[ManifestEntry, ...]
    sha256: str

    def __post_init__(self) -> None:
        normalized = _normalize_entries(self.entries)
        if normalized != self.entries:
            raise EvidenceError("manifest entries are not in canonical order")
        actual = manifest_sha256(normalized)
        if not hmac.compare_digest(actual, self.sha256):
            raise EvidenceError("manifest authentication failed")

    @classmethod
    def authenticate(
        cls,
        entries: Iterable[ManifestEntry],
        *,
        expected_sha256: str,
    ) -> AuthenticatedManifest:
        if not _is_sha256(expected_sha256):
            raise EvidenceError("trusted manifest digest is invalid")
        normalized = _normalize_entries(entries)
        actual = manifest_sha256(normalized)
        if not hmac.compare_digest(actual, expected_sha256):
            raise EvidenceError("manifest authentication failed")
        return cls(entries=normalized, sha256=actual)

    def by_path(self) -> dict[str, ManifestEntry]:
        return {entry.path: entry for entry in self.entries}


@dataclass(frozen=True)
class EvidenceArtifact:
    label: str
    role: Literal["primary_diff", "nearby_context"]
    content: str
    length: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.label, str)
            or not isinstance(self.content, str)
            or len(self.label) != len("artifact-0000")
            or not self.label.startswith("artifact-")
            or not self.label.removeprefix("artifact-").isdigit()
        ):
            raise EvidenceError("evidence artifact label is invalid")
        if not isinstance(self.role, str) or self.role not in {
            "primary_diff",
            "nearby_context",
        }:
            raise EvidenceError("evidence artifact role is invalid")
        try:
            content = self.content.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise EvidenceError("evidence artifact text is invalid") from error
        _decode_text(content, self.label)
        if isinstance(self.length, bool) or self.length != len(content):
            raise EvidenceError("evidence artifact length is inconsistent")
        if not _is_sha256(self.sha256) or not hmac.compare_digest(
            self.sha256,
            sha256_bytes(content),
        ):
            raise EvidenceError("evidence artifact digest is inconsistent")

    def to_json(self) -> dict[str, int | str]:
        return {
            "content": self.content,
            "label": self.label,
            "length": self.length,
            "role": self.role,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class EvidenceBundle:
    artifacts: tuple[EvidenceArtifact, ...]
    manifest_sha256: str
    total_content_bytes: int

    def __post_init__(self) -> None:
        if not _is_sha256(self.manifest_sha256):
            raise EvidenceError("evidence bundle manifest digest is invalid")
        if (
            not isinstance(self.artifacts, tuple)
            or not self.artifacts
            or len(self.artifacts) > MAX_EVIDENCE_CONTEXT_FILES + 1
            or not all(
                isinstance(artifact, EvidenceArtifact) for artifact in self.artifacts
            )
        ):
            raise EvidenceError("evidence bundle artifact count is invalid")
        expected_labels = tuple(
            f"artifact-{index:04d}" for index in range(len(self.artifacts))
        )
        if tuple(artifact.label for artifact in self.artifacts) != expected_labels:
            raise EvidenceError("evidence bundle labels are not canonical")
        if self.artifacts[0].role != "primary_diff" or any(
            artifact.role != "nearby_context" for artifact in self.artifacts[1:]
        ):
            raise EvidenceError("evidence bundle roles are invalid")
        if self.artifacts[0].length > MAX_EVIDENCE_PRIMARY_BYTES:
            raise EvidenceError("primary evidence exceeds its byte limit")
        context_bytes = sum(artifact.length for artifact in self.artifacts[1:])
        if any(
            artifact.length > MAX_EVIDENCE_CONTEXT_FILE_BYTES
            for artifact in self.artifacts[1:]
        ):
            raise EvidenceError("nearby evidence file exceeds its byte limit")
        if context_bytes > MAX_EVIDENCE_CONTEXT_BYTES:
            raise EvidenceError("nearby evidence exceeds its aggregate byte limit")
        actual_total = sum(artifact.length for artifact in self.artifacts)
        if (
            isinstance(self.total_content_bytes, bool)
            or self.total_content_bytes != actual_total
        ):
            raise EvidenceError("evidence bundle byte total is inconsistent")

    def to_json(self) -> dict[str, object]:
        return {
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
            "manifest_sha256": self.manifest_sha256,
            "schema": BUNDLE_SCHEMA,
            "total_content_bytes": self.total_content_bytes,
        }

    def to_bytes(self) -> bytes:
        encoded = canonical_json(self.to_json())
        if len(encoded) > MAX_EVIDENCE_BUNDLE_BYTES:
            raise EvidenceBundleSizeError(
                "serialized evidence bundle exceeds its byte limit"
            )
        return encoded


def manifest_sha256(entries: Iterable[ManifestEntry]) -> str:
    normalized = _normalize_entries(entries)
    payload = {
        "entries": [entry.to_json() for entry in normalized],
        "schema": MANIFEST_SCHEMA,
    }
    return sha256_bytes(canonical_json(payload))


def build_evidence_bundle(
    *,
    root_fd: int,
    manifest: AuthenticatedManifest,
    primary_path: str = PRIMARY_DIFF_RELATIVE_PATH,
    nearby_paths: Iterable[str] = (),
) -> EvidenceBundle:
    if not isinstance(manifest, AuthenticatedManifest):
        raise EvidenceError("evidence manifest is not authenticated")
    if isinstance(nearby_paths, (str, bytes)):
        raise EvidenceError("nearby evidence paths must be an explicit sequence")
    root_metadata = os.fstat(root_fd)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError("evidence root descriptor is not a directory")
    if root_metadata.st_uid != os.getuid():
        raise EvidenceError("evidence root descriptor has an unexpected owner")

    _validate_relative_path(primary_path)
    requested_nearby = tuple(nearby_paths)
    if len(requested_nearby) > MAX_EVIDENCE_CONTEXT_FILES:
        raise EvidenceError("too many nearby evidence files were requested")
    for path in requested_nearby:
        _validate_relative_path(path)
    if len(set(requested_nearby)) != len(requested_nearby):
        raise EvidenceError("nearby evidence paths contain duplicates")
    if primary_path in requested_nearby:
        raise EvidenceError("the primary diff cannot also be nearby context")

    entries = manifest.by_path()
    primary_entry = entries.get(primary_path)
    if primary_entry is None:
        raise EvidenceError("the authenticated manifest omits the primary diff")

    artifacts: list[EvidenceArtifact] = []
    primary = _read_manifest_entry(
        root_fd=root_fd,
        entry=primary_entry,
        byte_limit=MAX_EVIDENCE_PRIMARY_BYTES,
        label="artifact-0000",
        role="primary_diff",
    )
    artifacts.append(primary)

    context_bytes = 0
    for index, path in enumerate(
        sorted(requested_nearby, key=os.fsencode),
        start=1,
    ):
        entry = entries.get(path)
        if entry is None:
            raise EvidenceError("requested context is absent from the manifest")
        artifact = _read_manifest_entry(
            root_fd=root_fd,
            entry=entry,
            byte_limit=MAX_EVIDENCE_CONTEXT_FILE_BYTES,
            label=f"artifact-{index:04d}",
            role="nearby_context",
        )
        context_bytes += artifact.length
        if context_bytes > MAX_EVIDENCE_CONTEXT_BYTES:
            raise EvidenceError("nearby evidence exceeds its aggregate byte limit")
        artifacts.append(artifact)

    total = sum(artifact.length for artifact in artifacts)
    bundle = EvidenceBundle(
        artifacts=tuple(artifacts),
        manifest_sha256=manifest.sha256,
        total_content_bytes=total,
    )
    bundle.to_bytes()
    return bundle


def build_primary_evidence_bundle(
    content: bytes,
    *,
    expected_sha256: str,
) -> EvidenceBundle:
    if not isinstance(content, bytes):
        raise EvidenceError("primary evidence content is not bytes")
    if not 1 <= len(content) <= MAX_EVIDENCE_PRIMARY_BYTES:
        raise EvidenceError("primary evidence exceeds its byte limit")
    actual_sha256 = sha256_bytes(content)
    if not _is_sha256(expected_sha256) or not hmac.compare_digest(
        actual_sha256,
        expected_sha256,
    ):
        raise EvidenceError("primary evidence digest is inconsistent")

    entry = ManifestEntry(
        path=PRIMARY_DIFF_RELATIVE_PATH,
        kind="regular",
        size=len(content),
        sha256=actual_sha256,
    )
    manifest = AuthenticatedManifest.authenticate(
        (entry,),
        expected_sha256=manifest_sha256((entry,)),
    )
    artifact = EvidenceArtifact(
        label="artifact-0000",
        role="primary_diff",
        content=_decode_text(content, "artifact-0000"),
        length=len(content),
        sha256=actual_sha256,
    )
    bundle = EvidenceBundle(
        artifacts=(artifact,),
        manifest_sha256=manifest.sha256,
        total_content_bytes=len(content),
    )
    bundle.to_bytes()
    return bundle


def _read_manifest_entry(
    *,
    root_fd: int,
    entry: ManifestEntry,
    byte_limit: int,
    label: str,
    role: Literal["primary_diff", "nearby_context"],
) -> EvidenceArtifact:
    if entry.kind != "regular":
        raise EvidenceError(f"{label} is not a manifest-attested regular file")
    if entry.size > byte_limit:
        raise EvidenceError(f"{label} exceeds its byte limit")

    try:
        fd = _open_regular_beneath(root_fd, entry.path)
    except OSError as error:
        raise EvidenceError(
            f"{label} cannot be opened without following links"
        ) from error
    try:
        before = os.fstat(fd)
        if before.st_uid != os.getuid():
            raise EvidenceError(f"{label} has an unexpected owner")
        if before.st_nlink != 1:
            raise EvidenceError(f"{label} has an unsafe link count")
        if before.st_size != entry.size:
            raise EvidenceError(f"{label} length differs from the manifest")
        content = read_fd_exact(fd, max_bytes=byte_limit, expected_size=entry.size)
        after = os.fstat(fd)
        if identity_from_stat(before) != identity_from_stat(after):
            raise EvidenceError(f"{label} changed while it was read")
    finally:
        os.close(fd)

    actual_sha256 = sha256_bytes(content)
    if not hmac.compare_digest(actual_sha256, entry.sha256):
        raise EvidenceError(f"{label} digest differs from the manifest")
    text = _decode_text(content, label)
    return EvidenceArtifact(
        label=label,
        role=role,
        content=text,
        length=len(content),
        sha256=actual_sha256,
    )


def _open_regular_beneath(root_fd: int, path: str) -> int:
    parts = tuple(os.fsencode(part) for part in path.split("/"))
    current_fd = os.dup(root_fd)
    os.set_inheritable(current_fd, False)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        result = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
    except BaseException:
        os.close(current_fd)
        raise
    os.close(current_fd)
    metadata = os.fstat(result)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(result)
        raise EvidenceError("manifest entry does not resolve to a regular file")
    return result


def _decode_text(value: bytes, label: str) -> str:
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} contains binary data") from error
    if any(ord(character) < 0x20 and character not in "\t\n\r" for character in text):
        raise EvidenceError(f"{label} contains binary control data")
    if "\x7f" in text:
        raise EvidenceError(f"{label} contains binary control data")
    return text


def _normalize_entries(entries: Iterable[ManifestEntry]) -> tuple[ManifestEntry, ...]:
    materialized = tuple(entries)
    if not all(isinstance(entry, ManifestEntry) for entry in materialized):
        raise EvidenceError("manifest contains a non-entry value")
    normalized = tuple(sorted(materialized, key=lambda entry: os.fsencode(entry.path)))
    paths = [entry.path for entry in normalized]
    if len(paths) != len(set(paths)):
        raise EvidenceError("manifest contains duplicate paths")
    return normalized


def _validate_relative_path(path: str) -> None:
    if not isinstance(path, str) or not path:
        raise EvidenceError("manifest path is empty")
    if "\x00" in path or "\\" in path:
        raise EvidenceError("manifest path is invalid")
    if path.startswith("/") or path.endswith("/"):
        raise EvidenceError("manifest path must be relative")
    if any(character in _GLOB_CHARACTERS for character in path):
        raise EvidenceError("manifest path contains pattern syntax")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise EvidenceError("manifest path contains a dot component")
    try:
        encoded = os.fsencode(path)
    except UnicodeEncodeError as error:
        raise EvidenceError("manifest path cannot be encoded") from error
    if len(encoded) > _PATH_BYTES_LIMIT:
        raise EvidenceError("manifest path exceeds its byte limit")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )
