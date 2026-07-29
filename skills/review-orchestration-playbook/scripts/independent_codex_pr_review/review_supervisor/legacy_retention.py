from __future__ import annotations

import contextlib
import fcntl
import os
import pathlib
import re
import stat
import sys
from collections.abc import Iterator
from dataclasses import dataclass

from .constants import tool_root
from .models import Identity
from .secureio import (
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_directory_at,
    open_regular_at,
    read_fd_exact,
    validate_private_directory_fd,
    validate_private_regular_fd,
)


_INSTALLED_TOOL_SUFFIX = (
    "personal_codex",
    "skills",
    "review-orchestration-playbook",
    "scripts",
    "independent_codex_pr_review",
)
_LEGACY_RETENTION_SUFFIX = tuple(
    os.fsencode(part) for part in (*_INSTALLED_TOOL_SUFFIX, "runtime", "retention")
)
_ACCOUNT_LOCAL_RETENTION_MARKER = b"ACCOUNT_LOCAL_RETENTION_V1"
_ACCOUNT_LOCAL_RETENTION_MARKER_CONTENT = b"account-local-retention-v1\n"
_MAX_INSTALLED_RELEASE_ENTRIES = 512
_MAX_REPORTED_UNFENCED_RELEASES = 8
_RELEASE_NAME_LENGTH = 40
_LOWER_HEX = frozenset(b"0123456789abcdef")
_ATTEMPT_NAME = re.compile(rb"attempt-[0-9]+-[0-9a-f]{32}\Z")
_DirectoryBinding = tuple[int, int, int, int, int]


def _binding(metadata: os.stat_result) -> _DirectoryBinding:
    """Bind object identity and access policy while ignoring child-entry churn."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _identity_binding(identity: Identity) -> _DirectoryBinding:
    return (
        identity.device,
        identity.inode,
        stat.S_IFMT(identity.mode),
        identity.uid,
        stat.S_IMODE(identity.mode),
    )


def _stable_directory_entries_fd(
    directory_fd: int,
    *,
    label: str,
) -> tuple[tuple[bytes, os.stat_result], ...]:
    root_before = identity_from_stat(os.fstat(directory_fd))
    if not stat.S_ISDIR(root_before.mode):
        raise RuntimeError(f"{label} is not a directory")

    def scan() -> tuple[tuple[bytes, os.stat_result], ...]:
        scan_fd = os.open(
            b".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        entries: list[tuple[bytes, os.stat_result]] = []
        try:
            with os.scandir(scan_fd) as iterator:
                for entry in iterator:
                    if len(entries) >= _MAX_INSTALLED_RELEASE_ENTRIES:
                        raise RuntimeError(
                            f"{label} exceeds {_MAX_INSTALLED_RELEASE_ENTRIES} entries"
                        )
                    name = os.fsencode(entry.name)
                    if not name or b"/" in name or b"\0" in name:
                        raise RuntimeError(f"{label} returned an invalid entry name")
                    entries.append(
                        (
                            name,
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            ),
                        )
                    )
        except OSError as error:
            raise RuntimeError(f"cannot enumerate {label}") from error
        finally:
            os.close(scan_fd)
        return tuple(sorted(entries, key=lambda item: item[0]))

    before = scan()
    after = scan()
    root_after = identity_from_stat(os.fstat(directory_fd))
    if not directory_identities_match(root_before, root_after) or tuple(
        (name, _binding(metadata)) for name, metadata in before
    ) != tuple((name, _binding(metadata)) for name, metadata in after):
        raise RuntimeError(f"{label} changed while being inspected")
    return after


def _installed_release_catalog(
    root: pathlib.Path,
) -> tuple[pathlib.Path, bytes] | None:
    if root.parts[-len(_INSTALLED_TOOL_SUFFIX) :] != _INSTALLED_TOOL_SUFFIX:
        return None
    release_root = root.parents[len(_INSTALLED_TOOL_SUFFIX) - 1]
    releases_root = release_root.parent
    release_name = os.fsencode(release_root.name)
    if (
        releases_root.name != "releases"
        or len(release_name) != _RELEASE_NAME_LENGTH
        or any(character not in _LOWER_HEX for character in release_name)
    ):
        return None
    return releases_root, release_name


@dataclass(slots=True)
class _LegacyRetentionRoot:
    path: pathlib.Path
    components: tuple[tuple[bytes, _DirectoryBinding, bool], ...]
    retention_fd: int
    retention_binding: _DirectoryBinding
    lock_fd: int = -1
    lock_identity: Identity | None = None

    def close(self) -> None:
        lock_fd, self.lock_fd = self.lock_fd, -1
        retention_fd, self.retention_fd = self.retention_fd, -1
        with contextlib.ExitStack() as cleanup:
            if retention_fd >= 0:
                cleanup.callback(os.close, retention_fd)
            if lock_fd >= 0:
                cleanup.callback(os.close, lock_fd)
                cleanup.callback(fcntl.flock, lock_fd, fcntl.LOCK_UN)


@dataclass(frozen=True, slots=True)
class _LegacyRetentionProbe:
    root: _LegacyRetentionRoot | None
    tool_path: pathlib.Path | None
    uses_account_local_retention: bool


def _close_inspection_fd(fd: int, *, label: str) -> None:
    primary_error = sys.exception()
    try:
        os.close(fd)
    except OSError as cleanup_error:
        if primary_error is None:
            raise
        primary_error.add_note(
            f"{label} descriptor cleanup failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )


def _release_uses_account_local_retention(
    tool_fd: int,
    tool_path: pathlib.Path,
) -> bool:
    marker_path = tool_path / os.fsdecode(_ACCOUNT_LOCAL_RETENTION_MARKER)
    try:
        marker_fd, opened_identity = open_regular_at(
            tool_fd,
            _ACCOUNT_LOCAL_RETENTION_MARKER,
            expected_uid=os.getuid(),
            private_metadata=True,
        )
    except FileNotFoundError:
        return False
    try:
        strict_identity = validate_private_regular_fd(
            marker_fd,
            marker_path,
            mode=0o644,
        )
        if strict_identity != opened_identity:
            raise RuntimeError(
                "installed retention policy marker changed while being inspected"
            )
        content = read_fd_exact(
            marker_fd,
            max_bytes=len(_ACCOUNT_LOCAL_RETENTION_MARKER_CONTENT),
            expected_size=strict_identity.size,
        )
        held_identity = validate_private_regular_fd(
            marker_fd,
            marker_path,
            mode=0o644,
        )
        probe_fd, path_identity = open_regular_at(
            tool_fd,
            _ACCOUNT_LOCAL_RETENTION_MARKER,
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            strict_path_identity = validate_private_regular_fd(
                probe_fd,
                marker_path,
                mode=0o644,
            )
            if (
                held_identity != strict_identity
                or path_identity != strict_identity
                or strict_path_identity != strict_identity
            ):
                raise RuntimeError(
                    "installed retention policy marker changed while being inspected"
                )
            final_content = read_fd_exact(
                marker_fd,
                max_bytes=len(_ACCOUNT_LOCAL_RETENTION_MARKER_CONTENT),
                expected_size=strict_identity.size,
            )
            if content != _ACCOUNT_LOCAL_RETENTION_MARKER_CONTENT:
                raise RuntimeError("installed retention policy marker is invalid")
            if final_content != content:
                raise RuntimeError(
                    "installed retention policy marker changed while being inspected"
                )
        finally:
            _close_inspection_fd(
                probe_fd,
                label="installed retention policy marker path",
            )
        return True
    finally:
        _close_inspection_fd(
            marker_fd,
            label="installed retention policy marker",
        )


def _open_legacy_retention_root(
    releases_fd: int,
    releases_root: pathlib.Path,
    release_name: bytes,
    expected_release_binding: _DirectoryBinding,
) -> _LegacyRetentionProbe:
    current_fd = releases_fd
    current_path = releases_root
    components: list[tuple[bytes, _DirectoryBinding, bool]] = []
    opened_fd = -1
    tool_path: pathlib.Path | None = None
    uses_account_local_retention = False
    try:
        for index, part in enumerate((release_name, *_LEGACY_RETENTION_SUFFIX)):
            current_path /= os.fsdecode(part)
            private = index == len(_LEGACY_RETENTION_SUFFIX)
            try:
                next_fd, identity = open_directory_at(
                    current_fd,
                    part,
                    path_hint=current_path,
                    private=private,
                )
            except FileNotFoundError:
                return _LegacyRetentionProbe(
                    root=None,
                    tool_path=tool_path,
                    uses_account_local_retention=uses_account_local_retention,
                )
            if index == 0 and _identity_binding(identity) != expected_release_binding:
                os.close(next_fd)
                raise RuntimeError("installed release changed while being inspected")
            if opened_fd >= 0:
                os.close(opened_fd)
            opened_fd = next_fd
            current_fd = opened_fd
            components.append((part, _identity_binding(identity), private))
            if index == len(_INSTALLED_TOOL_SUFFIX):
                tool_path = current_path
                uses_account_local_retention = _release_uses_account_local_retention(
                    current_fd, current_path
                )
        retention_fd = opened_fd
        opened_fd = -1
        return _LegacyRetentionProbe(
            root=_LegacyRetentionRoot(
                path=current_path,
                components=tuple(components),
                retention_fd=retention_fd,
                retention_binding=components[-1][1],
            ),
            tool_path=tool_path,
            uses_account_local_retention=uses_account_local_retention,
        )
    except (OSError, ValueError) as error:
        raise RuntimeError("cannot inspect legacy retention path safely") from error
    finally:
        if opened_fd >= 0:
            os.close(opened_fd)


def _open_current_tool_legacy_retention_root(
    current_tool_path: pathlib.Path,
) -> _LegacyRetentionRoot | None:
    retention_path = current_tool_path / "runtime" / "retention"
    try:
        retention_fd, identity = open_absolute_directory_chain(
            retention_path,
            private_leaf=True,
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot inspect current helper legacy retention path safely"
        ) from error
    return _LegacyRetentionRoot(
        path=retention_path,
        components=(),
        retention_fd=retention_fd,
        retention_binding=_identity_binding(identity),
    )


def _revalidate_current_tool_legacy_retention_root(
    root: _LegacyRetentionRoot,
) -> None:
    refreshed_fd = -1
    try:
        refreshed_fd, refreshed_identity = open_absolute_directory_chain(
            root.path,
            private_leaf=True,
        )
        held_identity = validate_private_directory_fd(root.retention_fd, root.path)
        if (
            _identity_binding(refreshed_identity) != root.retention_binding
            or _identity_binding(held_identity) != root.retention_binding
        ):
            raise RuntimeError(
                "current helper legacy retention path changed while being inspected"
            )
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot revalidate current helper legacy retention path safely"
        ) from error
    finally:
        if refreshed_fd >= 0:
            os.close(refreshed_fd)


def _revalidate_legacy_retention_root(
    releases_fd: int,
    releases_root: pathlib.Path,
    root: _LegacyRetentionRoot,
) -> None:
    current_fd = releases_fd
    current_path = releases_root
    opened_fd = -1
    try:
        for part, expected_binding, private in root.components:
            current_path /= os.fsdecode(part)
            next_fd, identity = open_directory_at(
                current_fd,
                part,
                path_hint=current_path,
                private=private,
            )
            if _identity_binding(identity) != expected_binding:
                os.close(next_fd)
                raise RuntimeError(
                    "legacy retention path changed while being inspected"
                )
            if opened_fd >= 0:
                os.close(opened_fd)
            opened_fd = next_fd
            current_fd = opened_fd
        held_identity = validate_private_directory_fd(root.retention_fd, root.path)
        if (
            _identity_binding(held_identity) != root.retention_binding
            or _identity_binding(identity_from_stat(os.fstat(opened_fd)))
            != root.retention_binding
        ):
            raise RuntimeError("legacy retention path changed while being inspected")
    except (OSError, ValueError) as error:
        raise RuntimeError("cannot revalidate legacy retention path safely") from error
    finally:
        if opened_fd >= 0:
            os.close(opened_fd)


def _acquire_legacy_retention_lock(root: _LegacyRetentionRoot) -> None:
    try:
        lock_fd, opened_identity = open_regular_at(
            root.retention_fd,
            b"retention.lock",
            expected_uid=os.getuid(),
            private_metadata=True,
        )
    except FileNotFoundError:
        return
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "legacy retention lock has unsafe identity or access policy"
        ) from error
    try:
        strict_identity = validate_private_regular_fd(
            lock_fd,
            root.path / "retention.lock",
        )
        if strict_identity != opened_identity:
            raise RuntimeError("legacy retention lock changed while being inspected")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(
                "legacy retention root has an active writer; retry after it exits"
            ) from error
        root.lock_fd = lock_fd
        root.lock_identity = strict_identity
        lock_fd = -1
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def _revalidate_legacy_retention_lock(root: _LegacyRetentionRoot) -> None:
    if root.lock_fd < 0 or root.lock_identity is None:
        return
    held_identity = validate_private_regular_fd(
        root.lock_fd,
        root.path / "retention.lock",
    )
    probe_fd, path_identity = open_regular_at(
        root.retention_fd,
        b"retention.lock",
        expected_uid=os.getuid(),
        private_metadata=True,
    )
    try:
        strict_path_identity = validate_private_regular_fd(
            probe_fd,
            root.path / "retention.lock",
        )
        if (
            held_identity != root.lock_identity
            or path_identity != root.lock_identity
            or strict_path_identity != root.lock_identity
        ):
            raise RuntimeError("legacy retention lock changed while being inspected")
        try:
            fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe_fd, fcntl.LOCK_UN)
            raise RuntimeError("legacy retention migration fence is not held")
    finally:
        os.close(probe_fd)


def _retention_root_has_attempt(root: _LegacyRetentionRoot) -> bool:
    entries = _stable_directory_entries_fd(
        root.retention_fd,
        label="legacy retention root",
    )
    retained_attempt = False
    lock_seen = False
    for entry_name, metadata in entries:
        if entry_name == b"retention.lock":
            if root.lock_identity is None:
                raise RuntimeError(
                    "legacy retention lock appeared while acquiring migration fence"
                )
            if _binding(metadata) != _identity_binding(root.lock_identity):
                raise RuntimeError(
                    "legacy retention lock changed while being inspected"
                )
            lock_seen = True
            continue
        if (
            _ATTEMPT_NAME.fullmatch(entry_name) is None
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RuntimeError("legacy retention root has an unsafe entry")
        attempt_fd = -1
        try:
            attempt_fd, identity = open_directory_at(
                root.retention_fd,
                entry_name,
                path_hint=root.path / os.fsdecode(entry_name),
                private=True,
            )
            if _identity_binding(identity) != _binding(metadata):
                raise RuntimeError(
                    "legacy retention attempt changed while being inspected"
                )
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "legacy retention attempt has unsafe identity or access policy"
            ) from error
        finally:
            if attempt_fd >= 0:
                os.close(attempt_fd)
        retained_attempt = True
    if root.lock_identity is not None and not lock_seen:
        raise RuntimeError("legacy retention lock changed while being inspected")
    if root.lock_identity is None and not retained_attempt:
        raise RuntimeError(
            "empty legacy retention root has no lock for a migration fence"
        )
    return retained_attempt


def _revalidate_releases_root(
    releases_root: pathlib.Path,
    releases_identity: Identity,
    releases_entries: tuple[tuple[bytes, os.stat_result], ...],
) -> None:
    refreshed_fd, refreshed_identity = open_absolute_directory_chain(releases_root)
    try:
        if not directory_identities_match(releases_identity, refreshed_identity):
            raise RuntimeError(
                "installed release directory changed while being inspected"
            )
        refreshed_entries = _stable_directory_entries_fd(
            refreshed_fd,
            label="installed release directory",
        )
        if tuple(
            (name, _binding(metadata)) for name, metadata in releases_entries
        ) != tuple((name, _binding(metadata)) for name, metadata in refreshed_entries):
            raise RuntimeError(
                "installed release directory changed while being inspected"
            )
    finally:
        os.close(refreshed_fd)


@contextlib.contextmanager
def installed_legacy_retention_fence() -> Iterator[tuple[pathlib.Path, ...]]:
    cleanup = contextlib.ExitStack()
    current_tool_path = tool_root()
    current_root: _LegacyRetentionRoot | None = None
    current_root_absent = False
    catalog = _installed_release_catalog(current_tool_path)
    releases_root: pathlib.Path | None = None
    current_release_name: bytes | None = None
    releases_fd = -1
    releases_identity: Identity | None = None
    releases_entries: tuple[tuple[bytes, os.stat_result], ...] = ()
    roots: list[_LegacyRetentionRoot] = []
    absent_roots: list[tuple[bytes, _DirectoryBinding]] = []
    try:
        try:
            unresolved: list[pathlib.Path] = []
            unfenced_tools: list[pathlib.Path] = []

            current_root = _open_current_tool_legacy_retention_root(current_tool_path)
            if current_root is None:
                current_root_absent = True
            else:
                cleanup.callback(current_root.close)
                _acquire_legacy_retention_lock(current_root)
                if _retention_root_has_attempt(current_root):
                    unresolved.append(current_root.path)
                _revalidate_legacy_retention_lock(current_root)
                _revalidate_current_tool_legacy_retention_root(current_root)

            if catalog is not None:
                releases_root, current_release_name = catalog
                releases_fd, releases_identity = open_absolute_directory_chain(
                    releases_root
                )
                cleanup.callback(os.close, releases_fd)
                releases_entries = _stable_directory_entries_fd(
                    releases_fd,
                    label="installed release directory",
                )
                for name, release_metadata in releases_entries:
                    if name == current_release_name:
                        continue
                    if len(name) != _RELEASE_NAME_LENGTH or any(
                        character not in _LOWER_HEX for character in name
                    ):
                        continue
                    if (
                        not stat.S_ISDIR(release_metadata.st_mode)
                        or release_metadata.st_uid != os.getuid()
                        or stat.S_IMODE(release_metadata.st_mode) & 0o022
                    ):
                        raise RuntimeError(
                            "installed release has unsafe identity or access policy"
                        )
                    release_binding = _binding(release_metadata)
                    probe = _open_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        name,
                        release_binding,
                    )
                    if probe.root is None:
                        absent_roots.append((name, release_binding))
                        if (
                            probe.tool_path is not None
                            and not probe.uses_account_local_retention
                        ):
                            unfenced_tools.append(probe.tool_path)
                        continue
                    root = probe.root
                    roots.append(root)
                    cleanup.callback(root.close)
                    _acquire_legacy_retention_lock(root)
                    if _retention_root_has_attempt(root):
                        unresolved.append(root.path)
                    _revalidate_legacy_retention_lock(root)
                    _revalidate_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        root,
                    )

                _revalidate_releases_root(
                    releases_root,
                    releases_identity,
                    releases_entries,
                )
            if unfenced_tools:
                reported = ", ".join(
                    str(path)
                    for path in unfenced_tools[:_MAX_REPORTED_UNFENCED_RELEASES]
                )
                omitted = len(unfenced_tools) - _MAX_REPORTED_UNFENCED_RELEASES
                suffix = f" (+{omitted} more)" if omitted > 0 else ""
                raise RuntimeError(
                    "installed legacy helper has no stable retention fence; "
                    "retire or disable it before using the account-local default: "
                    f"{reported}{suffix}"
                )
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "cannot inspect installed legacy retention safely"
            ) from error

        try:
            yield tuple(unresolved)
        finally:
            try:
                if current_root is not None:
                    _revalidate_legacy_retention_lock(current_root)
                    _retention_root_has_attempt(current_root)
                    _revalidate_current_tool_legacy_retention_root(current_root)
                elif current_root_absent:
                    appeared_current = _open_current_tool_legacy_retention_root(
                        current_tool_path
                    )
                    if appeared_current is not None:
                        appeared_current.close()
                        raise RuntimeError(
                            "current helper legacy retention path appeared while "
                            "migration fence was active"
                        )
                for root in roots:
                    _revalidate_legacy_retention_lock(root)
                    _retention_root_has_attempt(root)
                    _revalidate_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        root,
                    )
                if (
                    releases_root is not None
                    and releases_identity is not None
                    and releases_fd >= 0
                ):
                    for name, release_binding in absent_roots:
                        appeared = _open_legacy_retention_root(
                            releases_fd,
                            releases_root,
                            name,
                            release_binding,
                        )
                        if appeared.root is not None:
                            appeared.root.close()
                            raise RuntimeError(
                                "legacy retention path appeared while migration fence "
                                "was active"
                            )
                        if (
                            appeared.tool_path is not None
                            and not appeared.uses_account_local_retention
                        ):
                            raise RuntimeError(
                                "installed legacy helper lost its account-local "
                                "retention policy while migration fence was active"
                            )
                    _revalidate_releases_root(
                        releases_root,
                        releases_identity,
                        releases_entries,
                    )
            except (OSError, ValueError) as error:
                raise RuntimeError(
                    "cannot inspect installed legacy retention safely"
                ) from error
    finally:
        cleanup.close()
