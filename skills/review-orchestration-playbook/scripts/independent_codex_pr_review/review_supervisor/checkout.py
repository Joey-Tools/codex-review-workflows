from __future__ import annotations

import errno
import hashlib
import os
import pathlib
import stat
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from .constants import MAX_RAW_BLOB_BYTES, PRIMARY_DIFF_RELATIVE_PATH
from .errors import SupervisorError, blocked, inconclusive
from .gitraw import (
    CatFileBatch,
    GitProcessClosureUnproven,
    RepositoryInfo,
    WorktreeRegistration,
    check_attributes,
    create_sanitized_view,
    remove_sanitized_view,
    verify_index,
)
from .lfs import is_git_lfs_pointer
from .models import HelperCustody, Identity, TreeEntry, TreeManifest
from .secureio import (
    allocated_bytes,
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_directory,
    rename_exchange,
    stream_sha256,
    write_all,
)


@dataclass(frozen=True)
class NameSemantics:
    case_insensitive: bool
    normalization_insensitive: bool
    name_max: int
    path_max: int

    def key(self, value: bytes) -> bytes:
        if not self.case_insensitive and not self.normalization_insensitive:
            return value
        try:
            text = value.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ValueError(
                "non-UTF-8 name cannot be proven alias-free on this filesystem"
            ) from error
        if self.normalization_insensitive:
            text = unicodedata.normalize("NFC", text)
        if self.case_insensitive:
            text = text.casefold()
        return text.encode("utf-8")


@dataclass(frozen=True)
class GraphEvidence:
    targets: dict[tuple[str, bytes, str], bytes]
    head_targets: dict[bytes, bytes]
    staging_names: dict[bytes, bytes]


@dataclass(frozen=True)
class MaterializationEvidence:
    regular_identities: dict[bytes, Identity]
    symlink_identities: dict[bytes, Identity]
    directory_identities: dict[bytes, Identity]
    control_directory_identity: Identity
    sealed_diff_identity: Identity
    sealed_diff_sha256: str
    checkout_allocated_bytes: int
    git_admin_allocated_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {
            "regular_count": len(self.regular_identities),
            "symlink_count": len(self.symlink_identities),
            "directory_count": len(self.directory_identities),
            "control_directory_identity": self.control_directory_identity.to_json(),
            "sealed_diff_identity": self.sealed_diff_identity.to_json(),
            "sealed_diff_sha256": self.sealed_diff_sha256,
            "checkout_allocated_bytes": self.checkout_allocated_bytes,
            "git_admin_allocated_bytes": self.git_admin_allocated_bytes,
        }


def _exclusive_probe_file(fd: int, name: bytes) -> bool:
    try:
        probe_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=fd,
        )
    except FileExistsError:
        return False
    else:
        os.close(probe_fd)
        return True


def probe_name_semantics(checkout_parent: pathlib.Path) -> NameSemantics:
    parent_fd = open_directory(checkout_parent)
    probe_name = f".codex-name-probe-{os.getpid()}-{os.urandom(8).hex()}".encode(
        "ascii"
    )
    probe_fd: int | None = None
    try:
        os.mkdir(probe_name, 0o700, dir_fd=parent_fd)
        probe_fd = os.open(
            probe_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        prefix = os.urandom(6).hex().encode("ascii")
        lower = prefix + b"-case"
        upper = prefix + b"-CASE"
        if not _exclusive_probe_file(probe_fd, lower):
            raise ValueError("name-semantics probe collided with an existing entry")
        case_second_created = _exclusive_probe_file(probe_fd, upper)
        if case_second_created:
            os.unlink(upper, dir_fd=probe_fd)
        os.unlink(lower, dir_fd=probe_fd)

        nfc = prefix + "-\u00e9".encode("utf-8")
        nfd = prefix + "-e\u0301".encode("utf-8")
        if not _exclusive_probe_file(probe_fd, nfc):
            raise ValueError("normalization probe collided with an existing entry")
        normalization_second_created = _exclusive_probe_file(probe_fd, nfd)
        if normalization_second_created:
            os.unlink(nfd, dir_fd=probe_fd)
        os.unlink(nfc, dir_fd=probe_fd)

        placeholder = prefix + b"-placeholder"
        staged = prefix + b"-staged"
        if not _exclusive_probe_file(probe_fd, placeholder):
            raise ValueError("exchange probe placeholder collision")
        os.symlink(b"target", staged, dir_fd=probe_fd)
        rename_exchange(probe_fd, staged, probe_fd, placeholder)
        final_stat = os.stat(placeholder, dir_fd=probe_fd, follow_symlinks=False)
        displaced_stat = os.stat(staged, dir_fd=probe_fd, follow_symlinks=False)
        if not stat.S_ISLNK(final_stat.st_mode) or not stat.S_ISREG(
            displaced_stat.st_mode
        ):
            raise ValueError("atomic exchange probe returned unexpected entry types")
        if os.readlink(placeholder, dir_fd=probe_fd) != b"target":
            raise ValueError("atomic exchange probe changed the symlink target")
        os.unlink(placeholder, dir_fd=probe_fd)
        os.unlink(staged, dir_fd=probe_fd)
        return NameSemantics(
            case_insensitive=not case_second_created,
            normalization_insensitive=not normalization_second_created,
            name_max=os.fpathconf(probe_fd, "PC_NAME_MAX"),
            path_max=os.fpathconf(probe_fd, "PC_PATH_MAX"),
        )
    except (OSError, ValueError) as error:
        error_number = error.errno if isinstance(error, OSError) else None
        raise blocked(
            f"cannot prove checkout filesystem name/exchange semantics: {error}",
            stage="checkout-name-semantics",
            code=(
                "blocked-checkout-atomic-symlink"
                if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}
                else "blocked-checkout-name-semantics"
            ),
        ) from error
    finally:
        if probe_fd is not None:
            try:
                for child in os.listdir(probe_fd):
                    os.unlink(child, dir_fd=probe_fd)
            except OSError:
                pass
            os.close(probe_fd)
        try:
            os.rmdir(probe_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _path_keys(path: bytes, semantics: NameSemantics) -> tuple[bytes, ...]:
    return tuple(semantics.key(component) for component in path.split(b"/"))


def _validate_manifest_namespace(
    manifest: TreeManifest,
    *,
    semantics: NameSemantics,
    checkout_root: pathlib.Path,
) -> dict[tuple[bytes, ...], TreeEntry]:
    entries: dict[tuple[bytes, ...], TreeEntry] = {}
    sibling_names: dict[tuple[bytes, ...], dict[bytes, bytes]] = {}
    used_as_parent: set[tuple[bytes, ...]] = set()
    git_key = semantics.key(b".git")
    control_key = semantics.key(b".codex-review")
    for entry in manifest.entries:
        components = entry.path.split(b"/")
        if any(len(component) > semantics.name_max for component in components):
            raise ValueError("tracked component exceeds filesystem NAME_MAX")
        if len(os.fsencode(checkout_root)) + 1 + len(entry.path) > semantics.path_max:
            raise ValueError("tracked path exceeds filesystem PATH_MAX")
        keys = tuple(semantics.key(component) for component in components)
        if keys[0] in {git_key, control_key}:
            raise ValueError("tracked top-level path aliases a reserved namespace")
        parent: tuple[bytes, ...] = ()
        for raw, key in zip(components, keys, strict=True):
            siblings = sibling_names.setdefault(parent, {})
            old = siblings.get(key)
            if old is not None and old != raw:
                raise ValueError(
                    "tracked paths alias under target filesystem semantics"
                )
            siblings[key] = raw
            parent += (key,)
        if keys in entries:
            raise ValueError("duplicate tracked path under target filesystem semantics")
        for depth in range(1, len(keys)):
            used_as_parent.add(keys[:depth])
            parent_entry = entries.get(keys[:depth])
            if parent_entry is not None and not parent_entry.is_gitlink:
                raise ValueError("tracked leaf is also used as a parent directory")
        if keys in used_as_parent and not entry.is_gitlink:
            raise ValueError("tracked leaf aliases an already implied parent directory")
        entries[keys] = entry
    return entries


def validate_namespaces(
    base: TreeManifest,
    head: TreeManifest,
    *,
    semantics: NameSemantics,
    checkout_root: pathlib.Path,
) -> tuple[dict[tuple[bytes, ...], TreeEntry], dict[tuple[bytes, ...], TreeEntry]]:
    try:
        return (
            _validate_manifest_namespace(
                base, semantics=semantics, checkout_root=checkout_root
            ),
            _validate_manifest_namespace(
                head, semantics=semantics, checkout_root=checkout_root
            ),
        )
    except ValueError as error:
        raise blocked(
            f"checkout path/name semantics are unsafe: {error}",
            stage="checkout-name-semantics",
            code="blocked-checkout-name-semantics",
        ) from error


def _target_components(target: bytes) -> list[bytes]:
    if not target or b"\0" in target or target.startswith(b"/"):
        raise ValueError("symlink target is empty, NUL-containing, or absolute")
    return target.split(b"/")


def _resolve_symlink(
    path: bytes,
    *,
    targets: dict[bytes, bytes],
    entries: dict[tuple[bytes, ...], TreeEntry],
    semantics: NameSemantics,
) -> tuple[bytes, ...]:
    original_components = path.split(b"/")
    target = targets[path]
    pending = original_components[:-1] + _target_components(target)
    resolved: list[bytes] = []
    traversals = 0
    control_keys = {semantics.key(b".git"), semantics.key(b".codex-review")}
    while pending:
        component = pending.pop(0)
        if component in {b"", b"."}:
            continue
        if component == b"..":
            if not resolved:
                raise ValueError("symlink graph transiently escapes the checkout")
            resolved.pop()
            continue
        resolved.append(component)
        keys = tuple(semantics.key(item) for item in resolved)
        if keys and keys[0] in control_keys:
            raise ValueError("symlink graph resolves into a reserved namespace")
        linked_entry = entries.get(keys)
        if linked_entry is None or not linked_entry.is_symlink:
            continue
        linked_target = targets.get(linked_entry.path)
        if linked_target is None:
            raise ValueError("symlink graph target cache is incomplete")
        traversals += 1
        if traversals > len(targets) + 1:
            raise ValueError("symlink graph loops")
        resolved.pop()
        pending = _target_components(linked_target) + pending
    return tuple(resolved)


def _validate_symlink_graph(
    manifest: TreeManifest,
    entries: dict[tuple[bytes, ...], TreeEntry],
    targets: dict[bytes, bytes],
    semantics: NameSemantics,
) -> None:
    if set(targets) != {entry.path for entry in manifest.entries if entry.is_symlink}:
        raise ValueError("symlink target cache does not exactly cover the manifest")
    for path in targets:
        _resolve_symlink(path, targets=targets, entries=entries, semantics=semantics)


def read_and_validate_symlink_graphs(
    info: RepositoryInfo,
    base: TreeManifest,
    head: TreeManifest,
    *,
    base_entries: dict[tuple[bytes, ...], TreeEntry],
    head_entries: dict[tuple[bytes, ...], TreeEntry],
    semantics: NameSemantics,
) -> GraphEvidence:
    total = head.aggregate_regular_bytes
    targets: dict[tuple[str, bytes, str], bytes] = {}
    side_targets: dict[str, dict[bytes, bytes]] = {"base": {}, "head": {}}
    object_targets: dict[str, tuple[int, bytes]] = {}
    try:
        with CatFileBatch(info) as batch:
            for side, manifest in (("base", base), ("head", head)):
                for entry in manifest.entries:
                    if not entry.is_symlink:
                        continue
                    assert entry.size is not None
                    cached = object_targets.get(entry.object_id)
                    if cached is None:
                        total += entry.size
                        if total > MAX_RAW_BLOB_BYTES:
                            raise ValueError(
                                "aggregate scheduled raw blob bytes exceed the limit"
                            )
                        payload = batch.read_blob(entry, capture=True)
                        assert payload is not None
                        if not payload or b"\0" in payload:
                            raise ValueError("symlink target is empty or contains NUL")
                        object_targets[entry.object_id] = (entry.size, payload)
                    else:
                        cached_size, payload = cached
                        if cached_size != entry.size:
                            raise ValueError(
                                "symlink object identity has inconsistent sizes"
                            )
                    targets[(side, entry.path, entry.object_id)] = payload
                    side_targets[side][entry.path] = payload
        _validate_symlink_graph(base, base_entries, side_targets["base"], semantics)
        _validate_symlink_graph(head, head_entries, side_targets["head"], semantics)
        staging_names: dict[bytes, bytes] = {}
        sibling_keys: dict[tuple[bytes, ...], set[bytes]] = {}
        for entry in head.entries:
            components = entry.path.split(b"/")
            parent_keys = tuple(semantics.key(value) for value in components[:-1])
            sibling_keys.setdefault(parent_keys, set()).add(
                semantics.key(components[-1])
            )
        for entry in head.entries:
            if not entry.is_symlink:
                continue
            parent, _, _ = entry.path.rpartition(b"/")
            parent_keys = _path_keys(parent, semantics) if parent else ()
            name = b".__codex_stage_" + hashlib.sha256(entry.path).hexdigest()[
                :32
            ].encode("ascii")
            key = semantics.key(name)
            siblings = sibling_keys.setdefault(parent_keys, set())
            if key in siblings:
                raise ValueError(
                    "reserved symlink staging name aliases a tracked entry"
                )
            siblings.add(key)
            staging_names[entry.path] = name
        return GraphEvidence(
            targets=targets,
            head_targets=side_targets["head"],
            staging_names=staging_names,
        )
    except ValueError as error:
        raise blocked(
            f"symlink graph validation failed: {error}",
            stage="checkout-symlink-phase0",
            code="blocked-checkout-symlink-graph",
        ) from error


def _open_verified_directory(
    root_fd: int,
    path: bytes,
    identities: dict[bytes, Identity],
) -> int:
    fd = os.dup(root_fd)
    if not path:
        return fd
    current = b""
    try:
        for component in path.split(b"/"):
            current = component if not current else current + b"/" + component
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
            if not directory_identities_match(
                identity_from_stat(os.fstat(fd)),
                identities[current],
            ):
                raise ValueError("directory identity changed during component walk")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parent_and_leaf(path: bytes) -> tuple[bytes, bytes]:
    parent, separator, leaf = path.rpartition(b"/")
    return (parent if separator else b"", leaf if separator else path)


class RawMaterializer:
    def __init__(
        self,
        *,
        info: RepositoryInfo,
        registration: WorktreeRegistration,
        base: TreeManifest,
        head: TreeManifest,
        semantics: NameSemantics,
        graph: GraphEvidence,
        source_fd: int,
        custody: HelperCustody,
        deadline: float,
        checkout_root_bound: int,
        git_admin_bound: int,
        view_path: pathlib.Path,
    ) -> None:
        self.info = info
        self.registration = registration
        self.base = base
        self.head = head
        self.semantics = semantics
        self.graph = graph
        self.source_fd = source_fd
        self.custody = custody
        self.deadline = deadline
        self.checkout_root_bound = checkout_root_bound
        self.git_admin_bound = git_admin_bound
        self.view_path = view_path
        self.root_fd: int | None = None
        self.directories: dict[bytes, Identity] = {}
        self.placeholders: dict[bytes, Identity] = {}
        self.control_directory_identity: Identity | None = None
        self.diff_identity: Identity | None = None

    def _check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("checkout monotonic deadline expired")

    def _ensure_directory(self, path: bytes, *, mode: int = 0o700) -> None:
        assert self.root_fd is not None
        if path in self.directories:
            return
        parent, leaf = _parent_and_leaf(path)
        if parent:
            self._ensure_directory(parent)
        parent_fd = _open_verified_directory(self.root_fd, parent, self.directories)
        try:
            os.mkdir(leaf, mode, dir_fd=parent_fd)
            child_fd = os.open(
                leaf,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                identity = identity_from_stat(os.fstat(child_fd))
                if not stat.S_ISDIR(identity.mode) or identity.uid != os.getuid():
                    raise ValueError("created directory identity is invalid")
                self.directories[path] = identity
            finally:
                os.close(child_fd)
        finally:
            os.close(parent_fd)

    def phase1(self) -> None:
        self._check_deadline()
        self.root_fd, root_identity = open_absolute_directory_chain(
            self.registration.worktree
        )
        if not directory_identities_match(
            root_identity, self.registration.worktree_identity
        ):
            raise ValueError("worktree root identity changed before skeleton creation")
        names = tuple(os.fsencode(name) for name in os.listdir(self.root_fd))
        if names != (b".git",):
            raise ValueError("worktree root changed before skeleton creation")
        for entry in self.head.entries:
            self._check_deadline()
            parent, leaf = _parent_and_leaf(entry.path)
            if parent:
                self._ensure_directory(parent)
            if entry.is_gitlink:
                self._ensure_directory(entry.path)
                continue
            parent_fd = _open_verified_directory(self.root_fd, parent, self.directories)
            try:
                fd = os.open(
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                try:
                    identity = identity_from_stat(os.fstat(fd))
                    if (
                        not stat.S_ISREG(identity.mode)
                        or identity.link_count != 1
                        or identity.size != 0
                    ):
                        raise ValueError("leaf placeholder identity is invalid")
                    self.placeholders[entry.path] = identity
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)

        self._ensure_directory(b".codex-review", mode=0o700)
        self.control_directory_identity = self.directories[b".codex-review"]
        control_fd = _open_verified_directory(
            self.root_fd, b".codex-review", self.directories
        )
        try:
            diff_fd = os.open(
                b"review.diff",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=control_fd,
            )
            try:
                self.diff_identity = identity_from_stat(os.fstat(diff_fd))
                if (
                    not stat.S_ISREG(self.diff_identity.mode)
                    or self.diff_identity.link_count != 1
                    or self.diff_identity.size != 0
                ):
                    raise ValueError("synthetic diff placeholder is invalid")
            finally:
                os.close(diff_fd)
        finally:
            os.close(control_fd)
        self._verify_skeleton()

    def _verify_skeleton(self) -> None:
        assert self.root_fd is not None
        expected: dict[bytes, str] = {
            b".git": "file",
            b".codex-review": "directory",
            b".codex-review/review.diff": "file",
        }
        for path in self.directories:
            expected[path] = "directory"
        for path in self.placeholders:
            expected[path] = "file"
        actual: dict[bytes, str] = {}
        stack: list[tuple[int, bytes]] = [(os.dup(self.root_fd), b"")]
        try:
            while stack:
                directory_fd, prefix = stack.pop()
                try:
                    for raw_name in (
                        os.fsencode(name) for name in os.listdir(directory_fd)
                    ):
                        path = raw_name if not prefix else prefix + b"/" + raw_name
                        metadata = os.stat(
                            raw_name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        if stat.S_ISDIR(metadata.st_mode):
                            actual[path] = "directory"
                            child = os.open(
                                raw_name,
                                os.O_RDONLY
                                | os.O_DIRECTORY
                                | os.O_CLOEXEC
                                | os.O_NOFOLLOW,
                                dir_fd=directory_fd,
                            )
                            stack.append((child, path))
                        elif stat.S_ISREG(metadata.st_mode):
                            actual[path] = "file"
                        else:
                            raise ValueError(
                                "phase-1 skeleton contains an unexpected type"
                            )
                finally:
                    os.close(directory_fd)
        except BaseException:
            for fd, _ in stack:
                os.close(fd)
            raise
        if actual != expected:
            raise ValueError("phase-1 skeleton entry-name set is not exact")

    def _open_placeholder(self, path: bytes) -> tuple[int, Identity]:
        assert self.root_fd is not None
        parent, leaf = _parent_and_leaf(path)
        parent_fd = _open_verified_directory(self.root_fd, parent, self.directories)
        try:
            fd = os.open(
                leaf,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        identity = identity_from_stat(os.fstat(fd))
        if (
            identity != self.placeholders[path]
            or identity.size != 0
            or identity.link_count != 1
        ):
            os.close(fd)
            raise ValueError("leaf placeholder identity changed")
        return fd, identity

    def _install_regular(self, batch: CatFileBatch, entry: TreeEntry) -> Identity:
        assert entry.size is not None
        fd, original = self._open_placeholder(entry.path)
        try:
            if 0 < entry.size < 1024:
                payload = batch.read_blob(entry, capture=True)
                assert payload is not None
                if is_git_lfs_pointer(payload):
                    raise blocked(
                        f"raw Git LFS pointer is not reviewable: {os.fsdecode(entry.path)}",
                        stage="checkout-lfs-content",
                        code="blocked-checkout-lfs-pointer",
                    )
                write_all(fd, payload)
            elif entry.size == 0:
                payload = batch.read_blob(entry, capture=True)
                if payload != b"":
                    raise ValueError("empty blob request returned content")
            else:
                batch.read_blob(entry, consumer=lambda chunk: write_all(fd, chunk))
            mode = 0o755 if entry.mode == 0o100755 else 0o644
            os.fchmod(fd, mode)
            os.fsync(fd)
            final = identity_from_stat(os.fstat(fd))
            if (
                (final.device, final.inode) != (original.device, original.inode)
                or not stat.S_ISREG(final.mode)
                or final.link_count != 1
                or final.size != entry.size
                or stat.S_IMODE(final.mode) != mode
                or final.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
            ):
                raise ValueError(
                    "materialized regular file failed identity/mode validation"
                )
            return final
        finally:
            os.close(fd)

    def _install_symlink(self, entry: TreeEntry) -> Identity:
        assert self.root_fd is not None
        target = self.graph.head_targets[entry.path]
        stage = self.graph.staging_names[entry.path]
        parent, leaf = _parent_and_leaf(entry.path)
        parent_fd = _open_verified_directory(self.root_fd, parent, self.directories)
        try:
            os.symlink(target, stage, dir_fd=parent_fd)
            staged_stat = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
            staged_identity = identity_from_stat(staged_stat)
            if (
                not stat.S_ISLNK(staged_stat.st_mode)
                or os.fsencode(os.readlink(stage, dir_fd=parent_fd)) != target
            ):
                raise ValueError("staged symlink did not preserve exact target bytes")
            placeholder_stat = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if identity_from_stat(placeholder_stat) != self.placeholders[entry.path]:
                raise ValueError("symlink placeholder identity changed")
            rename_exchange(parent_fd, stage, parent_fd, leaf)
            final_stat = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            displaced_stat = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
            if identity_from_stat(final_stat) != staged_identity:
                raise ValueError("atomic symlink exchange changed final identity")
            if identity_from_stat(displaced_stat) != self.placeholders[entry.path]:
                raise ValueError(
                    "atomic symlink exchange lost the placeholder identity"
                )
            if os.fsencode(os.readlink(leaf, dir_fd=parent_fd)) != target:
                raise ValueError("final symlink target changed")
            os.unlink(stage, dir_fd=parent_fd)
            return staged_identity
        finally:
            try:
                os.unlink(stage, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def _seal_diff(self) -> tuple[Identity, str]:
        assert self.root_fd is not None
        assert self.diff_identity is not None
        source_identity = identity_from_stat(os.fstat(self.source_fd))
        if source_identity != self.custody.source_identity:
            raise ValueError("retained primary diff identity changed before copy")
        control_fd = _open_verified_directory(
            self.root_fd, b".codex-review", self.directories
        )
        destination_fd: int | None = None
        try:
            destination_fd = os.open(
                b"review.diff",
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=control_fd,
            )
            if identity_from_stat(os.fstat(destination_fd)) != self.diff_identity:
                raise ValueError("synthetic diff placeholder identity changed")
            digest = stream_sha256(
                self.source_fd,
                expected_size=self.custody.diff_length,
                sink_fd=destination_fd,
            )
            if digest != self.custody.diff_sha256:
                raise ValueError(
                    "retained primary diff digest does not match preflight"
                )
            os.fsync(destination_fd)
            final = identity_from_stat(os.fstat(destination_fd))
            if (
                (final.device, final.inode)
                != (self.diff_identity.device, self.diff_identity.inode)
                or final.size != self.custody.diff_length
                or final.link_count != 1
                or stat.S_IMODE(final.mode) != 0o600
            ):
                raise ValueError("sealed diff identity, mode, or length is invalid")
            read_fd = os.open(
                b"review.diff",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=control_fd,
            )
            try:
                if identity_from_stat(os.fstat(read_fd)) != final:
                    raise ValueError("sealed diff changed before readback")
                readback_digest = stream_sha256(read_fd, expected_size=final.size)
                if readback_digest != digest:
                    raise ValueError("sealed diff readback digest mismatch")
            finally:
                os.close(read_fd)
            os.fsync(control_fd)
            return final, digest
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(control_fd)

    def _verify_regular(self, entry: TreeEntry, expected: Identity) -> None:
        assert self.root_fd is not None and entry.size is not None
        parent, leaf = _parent_and_leaf(entry.path)
        parent_fd = _open_verified_directory(self.root_fd, parent, self.directories)
        try:
            fd = os.open(
                leaf, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
            )
        finally:
            os.close(parent_fd)
        try:
            actual = identity_from_stat(os.fstat(fd))
            if actual != expected:
                raise ValueError(
                    "regular file identity changed during final verification"
                )
            digest = hashlib.new(self.info.object_format)
            digest.update(f"blob {entry.size}\0".encode("ascii"))
            remaining = entry.size
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    raise ValueError("regular file readback ended early")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1) or digest.hexdigest() != entry.object_id:
                raise ValueError(
                    "regular file readback does not match the raw Git object"
                )
        finally:
            os.close(fd)

    def materialize(self) -> MaterializationEvidence:
        if self.root_fd is None:
            raise RuntimeError("phase1 must run before materialization")
        regular: dict[bytes, Identity] = {}
        symlinks: dict[bytes, Identity] = {}
        try:
            with CatFileBatch(self.info) as batch:
                for entry in self.head.entries:
                    self._check_deadline()
                    if entry.is_regular:
                        regular[entry.path] = self._install_regular(batch, entry)
                    elif entry.is_symlink:
                        symlinks[entry.path] = self._install_symlink(entry)
            sealed_identity, sealed_digest = self._seal_diff()
            for entry in self.head.entries:
                self._check_deadline()
                if entry.is_regular:
                    self._verify_regular(entry, regular[entry.path])
                elif entry.is_symlink:
                    parent, leaf = _parent_and_leaf(entry.path)
                    parent_fd = _open_verified_directory(
                        self.root_fd, parent, self.directories
                    )
                    try:
                        actual = identity_from_stat(
                            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                        )
                        target = os.fsencode(os.readlink(leaf, dir_fd=parent_fd))
                    finally:
                        os.close(parent_fd)
                    if (
                        actual != symlinks[entry.path]
                        or target != self.graph.head_targets[entry.path]
                    ):
                        raise ValueError(
                            "symlink failed final identity/target verification"
                        )
            head_entries = {
                _path_keys(entry.path, self.semantics): entry
                for entry in self.head.entries
            }
            _validate_symlink_graph(
                self.head, head_entries, self.graph.head_targets, self.semantics
            )
            self._verify_final_entry_set(regular, symlinks, sealed_identity)

            view_complete = False
            view_cleanup_allowed = True
            try:
                view_binding = create_sanitized_view(self.info, self.view_path)
                view_complete = True
                attribute_paths = tuple(entry.path for entry in self.head.entries) + (
                    PRIMARY_DIFF_RELATIVE_PATH.encode("ascii"),
                )
                check_attributes(
                    self.info,
                    self.registration,
                    view_binding,
                    attribute_paths,
                )
                verify_index(self.info, self.registration, view_binding, self.head)
            except GitProcessClosureUnproven:
                view_cleanup_allowed = False
                raise
            finally:
                if view_cleanup_allowed:
                    try:
                        os.lstat(self.view_path)
                    except FileNotFoundError:
                        pass
                    else:
                        remove_sanitized_view(
                            self.view_path,
                            allow_partial=not view_complete,
                        )
            checkout_bytes = allocated_bytes(self.registration.worktree)
            git_bytes = allocated_bytes(self.registration.control.path)
            if checkout_bytes > self.checkout_root_bound:
                raise ValueError("checkout allocation exceeds its reserved bound")
            if git_bytes > self.git_admin_bound:
                raise ValueError(
                    "Git administration allocation exceeds its reserved bound"
                )
            assert self.control_directory_identity is not None
            return MaterializationEvidence(
                regular_identities=regular,
                symlink_identities=symlinks,
                directory_identities=dict(self.directories),
                control_directory_identity=self.control_directory_identity,
                sealed_diff_identity=sealed_identity,
                sealed_diff_sha256=sealed_digest,
                checkout_allocated_bytes=checkout_bytes,
                git_admin_allocated_bytes=git_bytes,
            )
        except (SupervisorError, GitProcessClosureUnproven):
            raise
        except Exception as error:
            raise inconclusive(
                f"raw checkout validation failed: {error}",
                stage="checkout-materialization",
                code="raw-checkout-invalid",
            ) from error

    def close(self) -> None:
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None

    def _verify_final_entry_set(
        self,
        regular: dict[bytes, Identity],
        symlinks: dict[bytes, Identity],
        sealed_diff: Identity,
    ) -> None:
        assert self.root_fd is not None
        expected: dict[bytes, tuple[str, Identity | None]] = {
            b".git": ("file", self.registration.marker_identity),
            b".codex-review": ("directory", self.control_directory_identity),
            b".codex-review/review.diff": ("file", sealed_diff),
        }
        for path, identity in self.directories.items():
            expected[path] = ("directory", identity)
        for path, identity in regular.items():
            expected[path] = ("file", identity)
        for path, identity in symlinks.items():
            expected[path] = ("symlink", identity)
        actual: dict[bytes, tuple[str, Identity]] = {}
        stack: list[tuple[int, bytes]] = [(os.dup(self.root_fd), b"")]
        try:
            while stack:
                directory_fd, prefix = stack.pop()
                try:
                    for raw_name in (
                        os.fsencode(name) for name in os.listdir(directory_fd)
                    ):
                        path = raw_name if not prefix else prefix + b"/" + raw_name
                        metadata = os.stat(
                            raw_name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        identity = identity_from_stat(metadata)
                        if stat.S_ISDIR(metadata.st_mode):
                            kind = "directory"
                            child = os.open(
                                raw_name,
                                os.O_RDONLY
                                | os.O_DIRECTORY
                                | os.O_CLOEXEC
                                | os.O_NOFOLLOW,
                                dir_fd=directory_fd,
                            )
                            stack.append((child, path))
                        elif stat.S_ISREG(metadata.st_mode):
                            kind = "file"
                        elif stat.S_ISLNK(metadata.st_mode):
                            kind = "symlink"
                        else:
                            raise ValueError(
                                "final checkout contains an unsupported entry type"
                            )
                        actual[path] = (kind, identity)
                finally:
                    os.close(directory_fd)
        except BaseException:
            for fd, _ in stack:
                os.close(fd)
            raise
        if set(actual) != set(expected):
            raise ValueError("final checkout entry-name set is not exact")
        for path, (expected_kind, expected_identity) in expected.items():
            actual_kind, actual_identity = actual[path]
            identities_equal = (
                directory_identities_match(actual_identity, expected_identity)
                if expected_identity is not None and expected_kind == "directory"
                else actual_identity == expected_identity
            )
            if actual_kind != expected_kind or (
                expected_identity is not None and not identities_equal
            ):
                raise ValueError("final checkout entry identity/type set changed")
