from __future__ import annotations

import hashlib
import math
import os
import pathlib
import stat
import struct
import time
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .models import Identity
from .secureio import (
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_regular_at,
    publish_bytes,
    read_fd_exact,
    sha256_bytes,
)


_MANIFEST_MAGIC = b"targeted-cleanup-manifest-v1\0"
_RECORD = struct.Struct(">BBIIQQQQQ")
_KIND_DIRECTORY = 1
_KIND_ENTRY = 2
_DEFAULT_TARGETED_CLEANUP_SECONDS = 30.0
_MAX_DIRECTORY_DEPTH = 512


class CustodyLostError(RuntimeError):
    pass


@dataclass(frozen=True)
class RootSpec:
    label: str
    parent_fd: int
    parent_identity: Identity
    name: bytes
    expected_identity: Identity


@dataclass(frozen=True)
class ManifestRecord:
    root_index: int
    path: bytes
    kind: int
    identity: Identity


@dataclass
class _TraversalBudget:
    deadline: float
    remaining: int

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")

    def consume(self) -> None:
        self.check()
        if self.remaining <= 0:
            raise ValueError("targeted cleanup traversal exceeds its entry cap")
        self.remaining -= 1


def _operation_deadline(deadline: float | None) -> float:
    now = time.monotonic()
    value = now + _DEFAULT_TARGETED_CLEANUP_SECONDS if deadline is None else deadline
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError("targeted cleanup deadline is invalid")
    if value <= now:
        raise TimeoutError("targeted cleanup monotonic deadline expired")
    return float(value)


def _validate_manifest_path(path: bytes, *, root: bool) -> None:
    if not isinstance(path, bytes):
        raise ValueError("targeted cleanup manifest path is not bytes")
    if root:
        if path:
            raise ValueError("targeted cleanup root manifest path is invalid")
        return
    if (
        not path
        or path.startswith(b"/")
        or path.endswith(b"/")
        or b"\0" in path
        or any(component in {b"", b".", b".."} for component in path.split(b"/"))
    ):
        raise ValueError("targeted cleanup manifest path is invalid")


def _bounded_directory_names(
    directory_fd: int,
    *,
    entry_cap: int,
    deadline: float,
    error: str,
    sort_names: bool,
) -> tuple[bytes, ...]:
    names: list[bytes] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise TimeoutError("targeted cleanup monotonic deadline expired")
            if len(names) >= entry_cap:
                raise ValueError(error)
            names.append(os.fsencode(entry.name))
    if sort_names:
        names.sort()
    return tuple(names)


def _index_manifest_records(
    records: Sequence[ManifestRecord],
    *,
    root_count: int,
    entry_cap: int,
    deadline: float,
) -> dict[tuple[int, bytes], dict[bytes, ManifestRecord]]:
    if len(records) > entry_cap:
        raise ValueError("targeted cleanup manifest exceeds its entry cap")
    budget = _TraversalBudget(deadline=deadline, remaining=entry_cap * 2)
    directory_paths: set[tuple[int, bytes]] = set()
    seen_paths: set[tuple[int, bytes]] = set()
    root_records: set[int] = set()
    for record in records:
        budget.consume()
        if (
            type(record.root_index) is not int
            or not 0 <= record.root_index < root_count
        ):
            raise ValueError("targeted cleanup manifest root index is invalid")
        if type(record.kind) is not int or record.kind not in {
            _KIND_DIRECTORY,
            _KIND_ENTRY,
        }:
            raise ValueError("targeted cleanup manifest entry kind is invalid")
        _validate_manifest_path(record.path, root=not record.path)
        key = (record.root_index, record.path)
        if key in seen_paths:
            raise ValueError("targeted cleanup manifest contains a duplicate path")
        seen_paths.add(key)
        if not record.path:
            if record.kind != _KIND_DIRECTORY:
                raise ValueError("targeted cleanup manifest root is not a directory")
            root_records.add(record.root_index)
        if record.kind == _KIND_DIRECTORY:
            directory_paths.add(key)
    if root_records != set(range(root_count)):
        raise ValueError("targeted cleanup manifest root records are incomplete")

    children: dict[tuple[int, bytes], dict[bytes, ManifestRecord]] = {
        key: {} for key in directory_paths
    }
    for record in records:
        budget.consume()
        if not record.path:
            continue
        parent, separator, name = record.path.rpartition(b"/")
        if not separator:
            parent = b""
            name = record.path
        parent_key = (record.root_index, parent)
        expected = children.get(parent_key)
        if expected is None:
            raise ValueError("targeted cleanup manifest entry has no directory parent")
        if name in expected:
            raise ValueError("targeted cleanup manifest contains duplicate siblings")
        expected[name] = record
    return children


class CustodiedManifest:
    def __init__(
        self,
        *,
        roots: tuple[RootSpec, ...],
        root_fds: tuple[int, ...],
        records: tuple[ManifestRecord, ...],
        seal: dict[str, Any],
        children_by_parent: dict[tuple[int, bytes], dict[bytes, ManifestRecord]],
        deadline: float,
    ) -> None:
        self.roots = roots
        self.root_fds = list(root_fds)
        self.records = records
        self.seal = seal
        self.children_by_parent = children_by_parent
        self.deadline = deadline
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in self.root_fds:
            os.close(fd)
        self.root_fds.clear()

    def __enter__(self) -> CustodiedManifest:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def require_live_custody(self) -> None:
        if self._closed or len(self.root_fds) != len(self.roots):
            raise CustodyLostError("targeted cleanup root custody was lost")
        for index in range(len(self.roots)):
            self.require_root_custody(index)

    def require_root_custody(self, index: int) -> None:
        if self._closed or len(self.root_fds) != len(self.roots):
            raise CustodyLostError("targeted cleanup root custody was lost")
        spec = self.roots[index]
        root_fd = self.root_fds[index]
        _require_parent_custody(spec)
        descriptor = identity_from_stat(os.fstat(root_fd))
        path_identity = identity_from_stat(
            os.stat(spec.name, dir_fd=spec.parent_fd, follow_symlinks=False)
        )
        if not directory_identities_match(
            descriptor, spec.expected_identity
        ) or not directory_identities_match(path_identity, descriptor):
            raise CustodyLostError(f"targeted cleanup custody changed for {spec.label}")


def _require_parent_custody(spec: RootSpec) -> None:
    actual = identity_from_stat(os.fstat(spec.parent_fd))
    if not directory_identities_match(actual, spec.parent_identity):
        raise CustodyLostError(f"targeted cleanup parent changed for {spec.label}")


def _entry_kind(mode: int) -> int:
    if stat.S_ISDIR(mode):
        return _KIND_DIRECTORY
    if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        return _KIND_ENTRY
    raise ValueError("targeted cleanup tree contains an unsupported entry type")


def _enumerate_directory(
    *,
    root_index: int,
    directory_fd: int,
    prefix: bytes,
    records: list[ManifestRecord],
    budget: _TraversalBudget,
    depth: int,
) -> None:
    budget.check()
    if depth > _MAX_DIRECTORY_DEPTH:
        raise ValueError("targeted cleanup tree exceeds its depth cap")
    names = _bounded_directory_names(
        directory_fd,
        entry_cap=budget.remaining,
        deadline=budget.deadline,
        error="targeted cleanup manifest exceeds its entry cap",
        sort_names=True,
    )
    for name in names:
        budget.consume()
        if not name or name in {b".", b".."} or b"/" in name or b"\0" in name:
            raise ValueError("targeted cleanup tree returned an invalid raw name")
        relative = name if not prefix else prefix + b"/" + name
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = identity_from_stat(metadata)
        kind = _entry_kind(metadata.st_mode)
        records.append(
            ManifestRecord(
                root_index=root_index,
                path=relative,
                kind=kind,
                identity=identity,
            )
        )
        if kind != _KIND_DIRECTORY:
            continue
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            if not directory_identities_match(
                identity_from_stat(os.fstat(child_fd)), identity
            ):
                raise CustodyLostError(
                    "targeted cleanup directory changed during enumeration"
                )
            _enumerate_directory(
                root_index=root_index,
                directory_fd=child_fd,
                prefix=relative,
                records=records,
                budget=budget,
                depth=depth + 1,
            )
        finally:
            os.close(child_fd)


def _encode_manifest(
    records: Iterable[ManifestRecord],
    *,
    payload_cap: int,
    deadline: float,
) -> bytes:
    value = bytearray(_MANIFEST_MAGIC)
    for record in records:
        if time.monotonic() >= deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")
        path = record.path
        identity = record.identity
        value.extend(
            _RECORD.pack(
                record.root_index,
                record.kind,
                len(path),
                identity.mode,
                identity.device,
                identity.inode,
                identity.link_count,
                identity.uid,
                identity.size,
            )
        )
        value.extend(path)
        if len(value) > payload_cap:
            raise ValueError("targeted cleanup manifest exceeds its payload cap")
    return bytes(value)


def build_custodied_manifest(
    *,
    roots: tuple[RootSpec, ...],
    manifest_path: pathlib.Path,
    entry_cap: int,
    payload_cap: int,
    deadline: float | None = None,
) -> CustodiedManifest:
    if not roots or len(roots) > 2:
        raise ValueError("targeted cleanup requires one or two roots")
    if entry_cap <= 0 or payload_cap < len(_MANIFEST_MAGIC):
        raise ValueError("targeted cleanup manifest bounds are invalid")
    operation_deadline = _operation_deadline(deadline)
    budget = _TraversalBudget(deadline=operation_deadline, remaining=entry_cap)
    root_fds: list[int] = []
    records: list[ManifestRecord] = []
    try:
        for index, spec in enumerate(roots):
            budget.consume()
            if index > 255:
                raise ValueError("targeted cleanup has too many roots")
            _require_parent_custody(spec)
            path_metadata = os.stat(
                spec.name,
                dir_fd=spec.parent_fd,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(path_metadata.st_mode):
                raise ValueError("targeted cleanup root is not a directory")
            root_fd = os.open(
                spec.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=spec.parent_fd,
            )
            root_fds.append(root_fd)
            descriptor = identity_from_stat(os.fstat(root_fd))
            path_identity = identity_from_stat(path_metadata)
            if (
                not directory_identities_match(descriptor, spec.expected_identity)
                or not directory_identities_match(path_identity, descriptor)
                or descriptor.uid != os.getuid()
            ):
                raise CustodyLostError(
                    f"targeted cleanup root changed for {spec.label}"
                )
            records.append(
                ManifestRecord(
                    root_index=index,
                    path=b"",
                    kind=_KIND_DIRECTORY,
                    identity=descriptor,
                )
            )
            _enumerate_directory(
                root_index=index,
                directory_fd=root_fd,
                prefix=b"",
                records=records,
                budget=budget,
                depth=1,
            )

        records_tuple = tuple(records)
        children_by_parent = _index_manifest_records(
            records_tuple,
            root_count=len(roots),
            entry_cap=entry_cap,
            deadline=operation_deadline,
        )
        payload = _encode_manifest(
            records_tuple,
            payload_cap=payload_cap,
            deadline=operation_deadline,
        )
        if time.monotonic() >= operation_deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")
        manifest_identity = publish_bytes(manifest_path, payload, mode=0o600)
        seal = {
            "version": 1,
            "path": str(manifest_path),
            "identity": manifest_identity.to_json(),
            "length": len(payload),
            "sha256": sha256_bytes(payload),
            "record_count": len(records),
            "entry_cap": entry_cap,
            "payload_cap": payload_cap,
            "roots": [
                {
                    "label": spec.label,
                    "name_hex": spec.name.hex(),
                    "parent_identity": spec.parent_identity.to_json(),
                    "root_identity": spec.expected_identity.to_json(),
                }
                for spec in roots
            ],
        }
        return CustodiedManifest(
            roots=roots,
            root_fds=tuple(root_fds),
            records=records_tuple,
            seal=seal,
            children_by_parent=children_by_parent,
            deadline=operation_deadline,
        )
    except BaseException:
        for fd in root_fds:
            os.close(fd)
        raise


def _same_entry(left: Identity, right: Identity, *, directory: bool) -> bool:
    if directory:
        return directory_identities_match(left, right)
    return left == right


def _children_for(
    manifest: CustodiedManifest,
    *,
    root_index: int,
    prefix: bytes,
) -> dict[bytes, ManifestRecord]:
    try:
        return manifest.children_by_parent[(root_index, prefix)]
    except KeyError as error:
        raise CustodyLostError(
            "targeted cleanup manifest directory index is incomplete"
        ) from error


def _delete_directory_contents(
    *,
    manifest: CustodiedManifest,
    root_index: int,
    directory_fd: int,
    prefix: bytes,
    budget: _TraversalBudget,
    depth: int,
) -> int:
    budget.check()
    if depth > _MAX_DIRECTORY_DEPTH:
        raise ValueError("targeted cleanup tree exceeds its depth cap")
    expected = _children_for(
        manifest,
        root_index=root_index,
        prefix=prefix,
    )
    try:
        actual_names = _bounded_directory_names(
            directory_fd,
            entry_cap=len(expected),
            deadline=budget.deadline,
            error="targeted cleanup tree changed after manifest publication",
            sort_names=False,
        )
    except ValueError as error:
        raise CustodyLostError(str(error)) from error
    if len(actual_names) != len(expected) or set(actual_names) != set(expected):
        raise CustodyLostError(
            "targeted cleanup tree changed after manifest publication"
        )
    removed = 0
    try:
        for name in actual_names:
            budget.consume()
            record = expected[name]
            metadata = identity_from_stat(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            directory = record.kind == _KIND_DIRECTORY
            if not _same_entry(metadata, record.identity, directory=directory):
                raise CustodyLostError("targeted cleanup entry identity changed")
            relative = name if not prefix else prefix + b"/" + name
            if directory:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    if not directory_identities_match(
                        identity_from_stat(os.fstat(child_fd)), record.identity
                    ):
                        raise CustodyLostError(
                            "targeted cleanup directory descriptor changed"
                        )
                    removed += _delete_directory_contents(
                        manifest=manifest,
                        root_index=root_index,
                        directory_fd=child_fd,
                        prefix=relative,
                        budget=budget,
                        depth=depth + 1,
                    )
                finally:
                    os.close(child_fd)
                refreshed = identity_from_stat(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if not directory_identities_match(refreshed, record.identity):
                    raise CustodyLostError(
                        "targeted cleanup directory changed before removal"
                    )
                budget.check()
                os.rmdir(name, dir_fd=directory_fd)
            else:
                budget.check()
                os.unlink(name, dir_fd=directory_fd)
            removed += 1
    finally:
        if removed:
            os.fsync(directory_fd)
    budget.check()
    return removed


def delete_custodied_roots(
    manifest: CustodiedManifest,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    operation_deadline = (
        manifest.deadline
        if deadline is None
        else min(manifest.deadline, _operation_deadline(deadline))
    )
    budget = _TraversalBudget(
        deadline=operation_deadline,
        remaining=manifest.seal["record_count"],
    )
    budget.check()
    manifest.require_live_custody()
    proofs: list[dict[str, Any]] = []
    removed_entries = 0
    for index, (spec, root_fd) in enumerate(
        zip(manifest.roots, manifest.root_fds, strict=True)
    ):
        budget.consume()
        manifest.require_root_custody(index)
        removed_entries += _delete_directory_contents(
            manifest=manifest,
            root_index=index,
            directory_fd=root_fd,
            prefix=b"",
            budget=budget,
            depth=1,
        )
        budget.check()
        _require_parent_custody(spec)
        current = identity_from_stat(
            os.stat(spec.name, dir_fd=spec.parent_fd, follow_symlinks=False)
        )
        if not directory_identities_match(current, spec.expected_identity):
            raise CustodyLostError("targeted cleanup root changed before removal")
        budget.check()
        os.rmdir(spec.name, dir_fd=spec.parent_fd)
        os.fsync(spec.parent_fd)
        _require_parent_custody(spec)
        try:
            os.stat(spec.name, dir_fd=spec.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CustodyLostError("targeted cleanup root name remains present")
        proofs.append(
            {
                "label": spec.label,
                "name_hex": spec.name.hex(),
                "parent_identity": identity_from_stat(
                    os.fstat(spec.parent_fd)
                ).to_json(),
                "exact_name_absent": True,
            }
        )
        removed_entries += 1
    return {
        "manifest_sha256": manifest.seal["sha256"],
        "manifest_record_count": manifest.seal["record_count"],
        "removed_entries": removed_entries,
        "roots": proofs,
        "parent_fsync_complete": True,
        "exact_names_absent": True,
    }


def remove_published_manifest(seal: dict[str, Any]) -> None:
    path = pathlib.Path(seal["path"])
    expected_identity = Identity(**seal["identity"])
    directory_fd, _ = open_absolute_directory_chain(path.parent)
    try:
        fd, identity = open_regular_at(
            directory_fd,
            os.fsencode(path.name),
            expected_uid=os.getuid(),
        )
        try:
            if identity != expected_identity or identity.size != seal["length"]:
                raise CustodyLostError("targeted cleanup manifest identity changed")
            content = read_fd_exact(
                fd,
                max_bytes=seal["payload_cap"],
                expected_size=seal["length"],
            )
        finally:
            os.close(fd)
        if sha256_bytes(content) != seal["sha256"]:
            raise CustodyLostError("targeted cleanup manifest digest changed")
        os.unlink(os.fsencode(path.name), dir_fd=directory_fd)
        os.fsync(directory_fd)
        try:
            os.stat(
                os.fsencode(path.name),
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise CustodyLostError("targeted cleanup manifest remains present")
    finally:
        os.close(directory_fd)


def enumerate_registration_conflicts(
    *,
    common_git_dir: pathlib.Path,
    worktree: pathlib.Path,
    entry_cap: int = 100_000,
    deadline: float | None = None,
) -> dict[str, Any]:
    if type(entry_cap) is not int or entry_cap < 0:
        raise ValueError("Git worktree registration entry cap is invalid")
    operation_deadline = _operation_deadline(deadline)
    namespace = common_git_dir / "worktrees"
    try:
        parent_fd, _ = open_absolute_directory_chain(namespace)
    except FileNotFoundError:
        return {
            "namespace_present": False,
            "registration_count": 0,
            "namespace_sha256": sha256_bytes(b""),
            "exact_matches": [],
            "alias_matches": [],
        }
    try:
        names = _bounded_directory_names(
            parent_fd,
            entry_cap=entry_cap,
            deadline=operation_deadline,
            error="Git worktree registration namespace exceeds its cap",
            sort_names=True,
        )
        exact_name = os.fsencode(worktree.name)
        expected_marker = os.fsencode(worktree / ".git")
        digest = hashlib.sha256()
        exact_matches: list[str] = []
        alias_matches: list[str] = []
        for name in names:
            if time.monotonic() >= operation_deadline:
                raise TimeoutError("targeted cleanup monotonic deadline expired")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Git worktree registration entry is not a directory")
            if name == exact_name:
                exact_matches.append(os.fsdecode(name))
            registration_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                try:
                    gitdir_fd, gitdir_identity = open_regular_at(
                        registration_fd,
                        b"gitdir",
                        expected_uid=os.getuid(),
                    )
                except FileNotFoundError:
                    continue
                try:
                    if gitdir_identity.size > 4096:
                        raise ValueError("Git worktree gitdir record is oversized")
                    target = read_fd_exact(
                        gitdir_fd,
                        max_bytes=4096,
                        expected_size=gitdir_identity.size,
                    ).strip()
                finally:
                    os.close(gitdir_fd)
                digest.update(sha256_bytes(target).encode("ascii"))
                if os.path.normpath(target) == os.path.normpath(expected_marker):
                    alias_matches.append(os.fsdecode(name))
            finally:
                os.close(registration_fd)
        if len(exact_matches) > 16 or len(alias_matches) > 16:
            raise ValueError("too many conflicting Git worktree registrations")
        return {
            "namespace_present": True,
            "registration_count": len(names),
            "namespace_sha256": digest.hexdigest(),
            "exact_matches": exact_matches,
            "alias_matches": alias_matches,
        }
    finally:
        os.close(parent_fd)


def require_no_registration_conflicts(evidence: dict[str, Any]) -> None:
    if evidence["exact_matches"] or evidence["alias_matches"]:
        raise ValueError("exact or alias Git worktree registration remains present")
