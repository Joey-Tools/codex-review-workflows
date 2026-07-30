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
from .errors import record_secondary_error
from .models import Identity
from .secureio import (
    DirectoryPolicyBinding,
    directory_paths_equivalent,
    directory_stat_binding,
    identity_from_stat,
    open_absolute_directory_chain,
    open_directory_at,
    open_regular_at,
    read_fd_exact,
    validate_directory_policy_fd,
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
_DirectoryStatBinding = tuple[int, int, int, int, int, int, int, int]


def _binding(metadata: os.stat_result) -> _DirectoryStatBinding:
    """Bind object identity and access policy while ignoring child-entry churn."""

    return directory_stat_binding(metadata)


def _stable_directory_entries_fd(
    directory_fd: int,
    *,
    path_hint: pathlib.Path,
    private: bool,
    label: str,
) -> tuple[tuple[bytes, os.stat_result], ...]:
    root_before = validate_directory_policy_fd(
        directory_fd,
        path_hint,
        private=private,
    )

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
    root_after = validate_directory_policy_fd(
        directory_fd,
        path_hint,
        private=private,
    )
    if root_before != root_after or tuple(
        (name, _binding(metadata)) for name, metadata in before
    ) != tuple((name, _binding(metadata)) for name, metadata in after):
        raise RuntimeError(f"{label} changed while being inspected")
    return after


@dataclass(slots=True)
class _InstalledReleaseCatalog:
    releases_root: pathlib.Path
    release_root: pathlib.Path
    tool_path: pathlib.Path
    current_release_name: bytes
    releases_fd: int
    release_fd: int
    tool_fd: int
    releases_policy: DirectoryPolicyBinding
    release_policy: DirectoryPolicyBinding
    tool_policy: DirectoryPolicyBinding
    releases_entries: tuple[tuple[bytes, os.stat_result], ...]

    def close(self) -> None:
        tool_fd, self.tool_fd = self.tool_fd, -1
        release_fd, self.release_fd = self.release_fd, -1
        releases_fd, self.releases_fd = self.releases_fd, -1
        _close_inspection_fds(
            (
                (tool_fd, "installed helper"),
                (release_fd, "installed release"),
                (releases_fd, "installed release catalog"),
            )
        )


def _open_installed_tool_from_release(
    release_fd: int,
    release_root: pathlib.Path,
) -> tuple[int, DirectoryPolicyBinding]:
    current_fd = release_fd
    current_path = release_root
    opened_fd = -1
    tool_policy: DirectoryPolicyBinding | None = None
    try:
        for part_text in _INSTALLED_TOOL_SUFFIX:
            part = os.fsencode(part_text)
            current_path /= part_text
            next_fd, _ = open_directory_at(
                current_fd,
                part,
                path_hint=current_path,
                private=False,
            )
            try:
                policy = validate_directory_policy_fd(
                    next_fd,
                    current_path,
                    private=False,
                )
            except BaseException:
                _close_inspection_fd(
                    next_fd,
                    label="installed helper path component",
                )
                raise
            previous_fd = opened_fd
            opened_fd = next_fd
            if previous_fd >= 0:
                _close_inspection_fd(
                    previous_fd,
                    label="installed helper parent path component",
                )
            current_fd = opened_fd
            tool_policy = policy
        if tool_policy is None:
            raise RuntimeError("installed helper path is incomplete")
        tool_fd = opened_fd
        opened_fd = -1
        return tool_fd, tool_policy
    finally:
        if opened_fd >= 0:
            _close_inspection_fd(
                opened_fd,
                label="installed helper path",
            )


def _installed_release_catalog(
    root: pathlib.Path,
) -> _InstalledReleaseCatalog | None:
    if not root.is_absolute() or len(root.parents) < len(_INSTALLED_TOOL_SUFFIX):
        return None
    release_root = root.parents[len(_INSTALLED_TOOL_SUFFIX) - 1]
    spelled_releases_root = release_root.parent
    releases_root = spelled_releases_root.parent / "releases"
    expected_tool_root = release_root.joinpath(*_INSTALLED_TOOL_SUFFIX)
    releases_fd = -1
    release_fd = -1
    tool_fd = -1
    try:
        if not directory_paths_equivalent(spelled_releases_root, releases_root):
            return None
        if not directory_paths_equivalent(root, expected_tool_root):
            return None

        releases_fd, _ = open_absolute_directory_chain(releases_root)
        releases_policy = validate_directory_policy_fd(
            releases_fd,
            releases_root,
            private=False,
        )
        release_fd, _ = open_absolute_directory_chain(release_root)
        release_policy = validate_directory_policy_fd(
            release_fd,
            release_root,
            private=False,
        )
        tool_fd, tool_policy = _open_installed_tool_from_release(
            release_fd,
            release_root,
        )
        release_binding = release_policy.stat_binding
        releases_entries = _stable_directory_entries_fd(
            releases_fd,
            path_hint=releases_root,
            private=False,
            label="installed release directory",
        )
        matching_names = tuple(
            name
            for name, metadata in releases_entries
            if _binding(metadata) == release_binding
        )
        if len(matching_names) != 1:
            raise RuntimeError(
                "current installed release has no unique catalog identity"
            )

        release_name = matching_names[0]
        if len(release_name) != _RELEASE_NAME_LENGTH or any(
            character not in _LOWER_HEX for character in release_name
        ):
            return None
        catalog = _InstalledReleaseCatalog(
            releases_root,
            release_root,
            root,
            release_name,
            releases_fd,
            release_fd,
            tool_fd,
            releases_policy,
            release_policy,
            tool_policy,
            releases_entries,
        )
        _revalidate_installed_release_catalog(catalog)
        releases_fd = -1
        release_fd = -1
        tool_fd = -1
        return catalog
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot identify installed release catalog safely"
        ) from error
    finally:
        if tool_fd >= 0:
            _close_inspection_fd(
                tool_fd,
                label="installed helper",
            )
        if release_fd >= 0:
            _close_inspection_fd(
                release_fd,
                label="installed release",
            )
        if releases_fd >= 0:
            _close_inspection_fd(
                releases_fd,
                label="installed release catalog",
            )


@dataclass(slots=True)
class _LegacyRetentionRoot:
    path: pathlib.Path
    components: tuple[tuple[bytes, DirectoryPolicyBinding, bool], ...]
    retention_fd: int
    retention_binding: DirectoryPolicyBinding
    lock_fd: int = -1
    lock_identity: Identity | None = None
    initial_attempt_present: bool | None = None

    def close(self) -> None:
        lock_fd, self.lock_fd = self.lock_fd, -1
        retention_fd, self.retention_fd = self.retention_fd, -1
        with contextlib.ExitStack() as cleanup:
            if retention_fd >= 0:
                cleanup.callback(os.close, retention_fd)
            if lock_fd >= 0:
                cleanup.callback(os.close, lock_fd)
                cleanup.callback(fcntl.flock, lock_fd, fcntl.LOCK_UN)


@dataclass(slots=True)
class _LegacyRetentionProbe:
    root: _LegacyRetentionRoot | None
    tool_path: pathlib.Path | None
    tool_binding: DirectoryPolicyBinding | None
    uses_account_local_retention: bool
    components: tuple[tuple[bytes, DirectoryPolicyBinding, bool], ...]
    anchor_fd: int = -1
    anchor_path: pathlib.Path | None = None
    anchor_binding: DirectoryPolicyBinding | None = None
    anchor_private: bool = False

    def take_root(self) -> _LegacyRetentionRoot:
        root, self.root = self.root, None
        if root is None:
            raise RuntimeError("legacy retention probe has no root")
        return root

    def close(self) -> None:
        root, self.root = self.root, None
        anchor_fd, self.anchor_fd = self.anchor_fd, -1
        cleanup_errors: list[BaseException] = []
        if root is not None:
            try:
                root.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if anchor_fd >= 0:
            try:
                os.close(anchor_fd)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            primary_error = cleanup_errors[0]
            for secondary_error in cleanup_errors[1:]:
                _record_secondary_error(
                    primary_error,
                    label="legacy retention probe cleanup failed",
                    secondary_error=secondary_error,
                )
            raise primary_error


def _close_legacy_probe(
    probe: _LegacyRetentionProbe,
    *,
    label: str,
) -> None:
    primary_error = sys.exception()
    try:
        probe.close()
    except BaseException as cleanup_error:
        if primary_error is None:
            raise
        _record_secondary_error(
            primary_error,
            label=f"{label} cleanup failed",
            secondary_error=cleanup_error,
        )


def _record_secondary_error(
    primary_error: BaseException,
    *,
    label: str,
    secondary_error: BaseException,
) -> None:
    record_secondary_error(
        primary_error,
        label=label,
        secondary_error=secondary_error,
    )


def _close_inspection_fd(fd: int, *, label: str) -> None:
    primary_error = sys.exception()
    try:
        os.close(fd)
    except OSError as cleanup_error:
        if primary_error is None:
            raise
        _record_secondary_error(
            primary_error,
            label=f"{label} descriptor cleanup failed",
            secondary_error=cleanup_error,
        )


def _close_inspection_fds(
    descriptors: tuple[tuple[int, str], ...],
) -> None:
    primary_error = sys.exception()
    first_cleanup_error: BaseException | None = None
    for fd, label in descriptors:
        if fd < 0:
            continue
        try:
            os.close(fd)
        except BaseException as cleanup_error:
            if primary_error is not None:
                _record_secondary_error(
                    primary_error,
                    label=f"{label} descriptor cleanup failed",
                    secondary_error=cleanup_error,
                )
            elif first_cleanup_error is None:
                first_cleanup_error = cleanup_error
            else:
                _record_secondary_error(
                    first_cleanup_error,
                    label=f"{label} descriptor cleanup failed",
                    secondary_error=cleanup_error,
                )
    if primary_error is None and first_cleanup_error is not None:
        raise first_cleanup_error


def _revalidate_installed_release_catalog(
    catalog: _InstalledReleaseCatalog,
) -> None:
    refreshed_releases_fd = -1
    refreshed_release_fd = -1
    refreshed_tool_fd = -1
    try:
        held_releases_policy = validate_directory_policy_fd(
            catalog.releases_fd,
            catalog.releases_root,
            private=False,
        )
        held_release_policy = validate_directory_policy_fd(
            catalog.release_fd,
            catalog.release_root,
            private=False,
        )
        held_tool_policy = validate_directory_policy_fd(
            catalog.tool_fd,
            catalog.tool_path,
            private=False,
        )
        if (
            held_releases_policy != catalog.releases_policy
            or held_release_policy != catalog.release_policy
            or held_tool_policy != catalog.tool_policy
        ):
            raise RuntimeError("installed release changed while being inspected")

        held_entries = _stable_directory_entries_fd(
            catalog.releases_fd,
            path_hint=catalog.releases_root,
            private=False,
            label="installed release directory",
        )
        refreshed_releases_fd, _ = open_absolute_directory_chain(catalog.releases_root)
        refreshed_releases_policy = validate_directory_policy_fd(
            refreshed_releases_fd,
            catalog.releases_root,
            private=False,
        )
        refreshed_entries = _stable_directory_entries_fd(
            refreshed_releases_fd,
            path_hint=catalog.releases_root,
            private=False,
            label="installed release directory",
        )
        refreshed_release_fd, _ = open_absolute_directory_chain(catalog.release_root)
        refreshed_release_policy = validate_directory_policy_fd(
            refreshed_release_fd,
            catalog.release_root,
            private=False,
        )
        refreshed_tool_fd, _ = open_absolute_directory_chain(catalog.tool_path)
        refreshed_tool_policy = validate_directory_policy_fd(
            refreshed_tool_fd,
            catalog.tool_path,
            private=False,
        )
        if (
            refreshed_releases_policy != catalog.releases_policy
            or refreshed_release_policy != catalog.release_policy
            or refreshed_tool_policy != catalog.tool_policy
        ):
            raise RuntimeError("installed release changed while being inspected")
        expected_entries = tuple(
            (name, _binding(metadata)) for name, metadata in catalog.releases_entries
        )
        if (
            tuple((name, _binding(metadata)) for name, metadata in held_entries)
            != expected_entries
            or tuple((name, _binding(metadata)) for name, metadata in refreshed_entries)
            != expected_entries
        ):
            raise RuntimeError("installed release changed while being inspected")
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot revalidate installed release catalog safely"
        ) from error
    finally:
        _close_inspection_fds(
            (
                (refreshed_tool_fd, "revalidated installed helper"),
                (refreshed_release_fd, "revalidated installed release"),
                (
                    refreshed_releases_fd,
                    "revalidated installed release catalog",
                ),
            )
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
    expected_release_binding: _DirectoryStatBinding,
) -> _LegacyRetentionProbe:
    current_fd = releases_fd
    current_path = releases_root
    components: list[tuple[bytes, DirectoryPolicyBinding, bool]] = []
    opened_fd = -1
    tool_path: pathlib.Path | None = None
    tool_binding: DirectoryPolicyBinding | None = None
    uses_account_local_retention = False
    try:
        for index, part in enumerate((release_name, *_LEGACY_RETENTION_SUFFIX)):
            current_path /= os.fsdecode(part)
            private = index == len(_LEGACY_RETENTION_SUFFIX)
            try:
                next_fd, _ = open_directory_at(
                    current_fd,
                    part,
                    path_hint=current_path,
                    private=private,
                )
            except FileNotFoundError:
                anchor_fd = opened_fd
                opened_fd = -1
                return _LegacyRetentionProbe(
                    root=None,
                    tool_path=tool_path,
                    tool_binding=tool_binding,
                    uses_account_local_retention=uses_account_local_retention,
                    components=tuple(components),
                    anchor_fd=anchor_fd,
                    anchor_path=current_path.parent if components else None,
                    anchor_binding=components[-1][1] if components else None,
                    anchor_private=components[-1][2] if components else False,
                )
            try:
                policy = validate_directory_policy_fd(
                    next_fd,
                    current_path,
                    private=private,
                )
            except BaseException:
                _close_inspection_fd(
                    next_fd,
                    label="legacy retention path component",
                )
                raise
            if index == 0 and policy.stat_binding != expected_release_binding:
                error = RuntimeError("installed release changed while being inspected")
                try:
                    _close_inspection_fd(
                        next_fd,
                        label="installed release path component",
                    )
                except BaseException as cleanup_error:
                    _record_secondary_error(
                        error,
                        label="installed release path component cleanup failed",
                        secondary_error=cleanup_error,
                    )
                raise error
            previous_fd = opened_fd
            opened_fd = next_fd
            if previous_fd >= 0:
                _close_inspection_fd(
                    previous_fd,
                    label="legacy retention parent path component",
                )
            current_fd = opened_fd
            components.append((part, policy, private))
            if index == len(_INSTALLED_TOOL_SUFFIX):
                tool_path = current_path
                tool_binding = policy
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
            tool_binding=tool_binding,
            uses_account_local_retention=uses_account_local_retention,
            components=tuple(components),
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
    retention_fd = -1
    try:
        retention_fd, _ = open_absolute_directory_chain(
            retention_path,
            private_leaf=True,
        )
        retention_policy = validate_directory_policy_fd(
            retention_fd,
            retention_path,
            private=True,
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        if retention_fd >= 0:
            _close_inspection_fd(
                retention_fd,
                label="current helper legacy retention path",
            )
        raise RuntimeError(
            "cannot inspect current helper legacy retention path safely"
        ) from error
    return _LegacyRetentionRoot(
        path=retention_path,
        components=(),
        retention_fd=retention_fd,
        retention_binding=retention_policy,
    )


def _open_bound_current_tool_legacy_retention_root(
    catalog: _InstalledReleaseCatalog,
) -> _LegacyRetentionRoot | None:
    current_fd = catalog.tool_fd
    current_path = catalog.tool_path
    opened_fd = -1
    try:
        held_tool_policy = validate_directory_policy_fd(
            catalog.tool_fd,
            catalog.tool_path,
            private=False,
        )
        if held_tool_policy != catalog.tool_policy:
            raise RuntimeError("current installed helper changed while being inspected")
        for index, part in enumerate((b"runtime", b"retention")):
            current_path /= os.fsdecode(part)
            private = index == 1
            try:
                next_fd, _ = open_directory_at(
                    current_fd,
                    part,
                    path_hint=current_path,
                    private=private,
                )
            except FileNotFoundError:
                return None
            try:
                policy = validate_directory_policy_fd(
                    next_fd,
                    current_path,
                    private=private,
                )
            except BaseException:
                _close_inspection_fd(
                    next_fd,
                    label="current helper legacy retention path component",
                )
                raise
            previous_fd = opened_fd
            opened_fd = next_fd
            if previous_fd >= 0:
                _close_inspection_fd(
                    previous_fd,
                    label="current helper legacy retention parent",
                )
            current_fd = opened_fd
        retention_fd = opened_fd
        opened_fd = -1
        return _LegacyRetentionRoot(
            path=current_path,
            components=(),
            retention_fd=retention_fd,
            retention_binding=policy,
        )
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot inspect current helper legacy retention path safely"
        ) from error
    finally:
        if opened_fd >= 0:
            _close_inspection_fd(
                opened_fd,
                label="current helper legacy retention path",
            )


def _validate_current_release_probe(
    probe: _LegacyRetentionProbe,
    *,
    catalog: _InstalledReleaseCatalog,
    current_tool_path: pathlib.Path,
    current_root: _LegacyRetentionRoot | None,
) -> None:
    if probe.tool_path is None or probe.tool_binding is None:
        raise RuntimeError(
            "current installed helper is missing from its release catalog"
        )
    try:
        current_tool_fd, _ = open_absolute_directory_chain(current_tool_path)
        try:
            current_tool_policy = validate_directory_policy_fd(
                current_tool_fd,
                current_tool_path,
                private=False,
            )
        finally:
            _close_inspection_fd(
                current_tool_fd,
                label="current installed helper",
            )
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "cannot revalidate current installed helper safely"
        ) from error
    held_tool_policy = validate_directory_policy_fd(
        catalog.tool_fd,
        catalog.tool_path,
        private=False,
    )
    if (
        held_tool_policy != catalog.tool_policy
        or current_tool_policy != catalog.tool_policy
        or probe.tool_binding != catalog.tool_policy
    ):
        raise RuntimeError(
            "current installed helper path changed while being inspected"
        )
    if not probe.uses_account_local_retention:
        raise RuntimeError(
            "current installed helper lost its account-local retention policy"
        )
    if current_root is None:
        if probe.root is not None:
            raise RuntimeError(
                "current helper legacy retention path changed while being inspected"
            )
    elif (
        probe.root is None
        or probe.root.retention_binding != current_root.retention_binding
    ):
        raise RuntimeError(
            "current helper legacy retention path changed while being inspected"
        )


def _revalidate_legacy_probe_anchor(probe: _LegacyRetentionProbe) -> None:
    if probe.anchor_fd < 0:
        if (
            probe.anchor_path is not None
            or probe.anchor_binding is not None
            or (probe.components and probe.root is None)
        ):
            raise RuntimeError("legacy retention probe anchor is incomplete")
        return
    if probe.anchor_path is None or probe.anchor_binding is None:
        raise RuntimeError("legacy retention probe anchor is incomplete")
    held_policy = validate_directory_policy_fd(
        probe.anchor_fd,
        probe.anchor_path,
        private=probe.anchor_private,
    )
    if held_policy != probe.anchor_binding:
        raise RuntimeError(
            "installed helper path changed while migration fence was active"
        )


def _revalidate_legacy_probe_snapshot(
    initial: _LegacyRetentionProbe,
    current: _LegacyRetentionProbe,
    *,
    releases_fd: int,
    releases_root: pathlib.Path,
) -> None:
    if initial.root is None:
        _revalidate_legacy_probe_anchor(initial)
    else:
        _revalidate_legacy_retention_root(
            releases_fd,
            releases_root,
            initial.root,
        )
    if current.root is None:
        _revalidate_legacy_probe_anchor(current)
    else:
        _revalidate_legacy_retention_root(
            releases_fd,
            releases_root,
            current.root,
        )
    if initial.root is None and current.root is not None:
        raise RuntimeError(
            "legacy retention path appeared while migration fence was active"
        )
    if initial.root is not None and current.root is None:
        raise RuntimeError(
            "legacy retention path changed while migration fence was active"
        )
    if (
        initial.components != current.components
        or initial.tool_path != current.tool_path
        or initial.tool_binding != current.tool_binding
    ):
        raise RuntimeError(
            "installed helper path or retention policy changed while migration "
            "fence was active"
        )
    if initial.uses_account_local_retention != current.uses_account_local_retention:
        if (
            initial.uses_account_local_retention
            and not current.uses_account_local_retention
        ):
            raise RuntimeError(
                "installed legacy helper lost its account-local retention policy "
                "while migration fence was active"
            )
        raise RuntimeError(
            "installed helper retention policy changed while migration fence was active"
        )
    if initial.root is None:
        return
    if (
        current.root is None
        or initial.root.retention_binding != current.root.retention_binding
    ):
        raise RuntimeError(
            "legacy retention path changed while migration fence was active"
        )


def _revalidate_current_tool_legacy_retention_root(
    root: _LegacyRetentionRoot,
    *,
    catalog: _InstalledReleaseCatalog | None = None,
) -> None:
    if catalog is not None:
        refreshed_root: _LegacyRetentionRoot | None = None
        try:
            refreshed_root = _open_bound_current_tool_legacy_retention_root(catalog)
            held_policy = validate_directory_policy_fd(
                root.retention_fd,
                root.path,
                private=True,
            )
            if (
                refreshed_root is None
                or held_policy != root.retention_binding
                or refreshed_root.retention_binding != root.retention_binding
            ):
                raise RuntimeError(
                    "current helper legacy retention path changed while being inspected"
                )
        finally:
            if refreshed_root is not None:
                primary_error = sys.exception()
                try:
                    refreshed_root.close()
                except BaseException as cleanup_error:
                    if primary_error is None:
                        raise
                    _record_secondary_error(
                        primary_error,
                        label="refreshed current legacy retention cleanup failed",
                        secondary_error=cleanup_error,
                    )
        return

    refreshed_fd = -1
    try:
        refreshed_fd, _ = open_absolute_directory_chain(
            root.path,
            private_leaf=True,
        )
        refreshed_policy = validate_directory_policy_fd(
            refreshed_fd,
            root.path,
            private=True,
        )
        held_policy = validate_directory_policy_fd(
            root.retention_fd,
            root.path,
            private=True,
        )
        if (
            refreshed_policy != root.retention_binding
            or held_policy != root.retention_binding
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
            next_fd, _ = open_directory_at(
                current_fd,
                part,
                path_hint=current_path,
                private=private,
            )
            try:
                policy = validate_directory_policy_fd(
                    next_fd,
                    current_path,
                    private=private,
                )
            except BaseException:
                _close_inspection_fd(
                    next_fd,
                    label="revalidated legacy retention path component",
                )
                raise
            if policy != expected_binding:
                error = RuntimeError(
                    "legacy retention path changed while being inspected"
                )
                try:
                    _close_inspection_fd(
                        next_fd,
                        label="revalidated legacy retention path component",
                    )
                except BaseException as cleanup_error:
                    _record_secondary_error(
                        error,
                        label="legacy retention path component cleanup failed",
                        secondary_error=cleanup_error,
                    )
                raise error
            if opened_fd >= 0:
                os.close(opened_fd)
            opened_fd = next_fd
            current_fd = opened_fd
        held_policy = validate_directory_policy_fd(
            root.retention_fd,
            root.path,
            private=True,
        )
        opened_policy = validate_directory_policy_fd(
            opened_fd,
            root.path,
            private=True,
        )
        if (
            held_policy != root.retention_binding
            or opened_policy != root.retention_binding
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
        path_hint=root.path,
        private=True,
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
            if identity_from_stat(metadata) != root.lock_identity:
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
            attempt_fd, _ = open_directory_at(
                root.retention_fd,
                entry_name,
                path_hint=root.path / os.fsdecode(entry_name),
                private=True,
            )
            attempt_policy = validate_directory_policy_fd(
                attempt_fd,
                root.path / os.fsdecode(entry_name),
                private=True,
            )
            if attempt_policy.stat_binding != _binding(metadata):
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


def _record_initial_attempt_state(root: _LegacyRetentionRoot) -> bool:
    retained_attempt = _retention_root_has_attempt(root)
    root.initial_attempt_present = retained_attempt
    return retained_attempt


def _reject_new_attempt(root: _LegacyRetentionRoot) -> None:
    if root.initial_attempt_present is None:
        raise RuntimeError("legacy retention root has no initial attempt snapshot")
    retained_attempt = _retention_root_has_attempt(root)
    if retained_attempt and not root.initial_attempt_present:
        raise RuntimeError(
            "legacy retention attempts appeared while migration fence was active"
        )


def _revalidate_releases_root(
    releases_root: pathlib.Path,
    releases_policy: DirectoryPolicyBinding,
    releases_entries: tuple[tuple[bytes, os.stat_result], ...],
) -> None:
    refreshed_fd, _ = open_absolute_directory_chain(releases_root)
    try:
        refreshed_policy = validate_directory_policy_fd(
            refreshed_fd,
            releases_root,
            private=False,
        )
        if releases_policy != refreshed_policy:
            raise RuntimeError(
                "installed release directory changed while being inspected"
            )
        refreshed_entries = _stable_directory_entries_fd(
            refreshed_fd,
            path_hint=releases_root,
            private=False,
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
    current_release_binding: _DirectoryStatBinding | None = None
    current_catalog_probe: _LegacyRetentionProbe | None = None
    releases_fd = -1
    releases_policy: DirectoryPolicyBinding | None = None
    releases_entries: tuple[tuple[bytes, os.stat_result], ...] = ()
    roots: list[_LegacyRetentionRoot] = []
    absent_roots: list[tuple[bytes, _DirectoryStatBinding, _LegacyRetentionProbe]] = []
    if catalog is not None:
        cleanup.callback(catalog.close)
    try:
        try:
            unresolved: list[pathlib.Path] = []
            unfenced_tools: list[pathlib.Path] = []

            if catalog is None:
                current_root = _open_current_tool_legacy_retention_root(
                    current_tool_path
                )
            else:
                _revalidate_installed_release_catalog(catalog)
                current_root = _open_bound_current_tool_legacy_retention_root(catalog)
            if current_root is None:
                current_root_absent = True
                if catalog is None:
                    raise RuntimeError(
                        "non-catalog helper has no stable migration fence for an "
                        "absent legacy retention path; select a proven distinct "
                        "retention root"
                    )
            else:
                cleanup.callback(current_root.close)
                _acquire_legacy_retention_lock(current_root)
                if _record_initial_attempt_state(current_root):
                    unresolved.append(current_root.path)
                _revalidate_legacy_retention_lock(current_root)
                _revalidate_current_tool_legacy_retention_root(
                    current_root,
                    catalog=catalog,
                )

            if catalog is not None:
                releases_root = catalog.releases_root
                current_release_name = catalog.current_release_name
                releases_fd = catalog.releases_fd
                releases_policy = catalog.releases_policy
                releases_entries = catalog.releases_entries
                for name, release_metadata in releases_entries:
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
                    if name == current_release_name:
                        if release_binding != catalog.release_policy.stat_binding:
                            raise RuntimeError(
                                "current installed release changed while being "
                                "inspected"
                            )
                        current_release_binding = release_binding
                        current_catalog_probe = _open_legacy_retention_root(
                            releases_fd,
                            releases_root,
                            name,
                            release_binding,
                        )
                        cleanup.callback(current_catalog_probe.close)
                        _validate_current_release_probe(
                            current_catalog_probe,
                            catalog=catalog,
                            current_tool_path=current_tool_path,
                            current_root=current_root,
                        )
                        continue
                    probe = _open_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        name,
                        release_binding,
                    )
                    if probe.root is None:
                        absent_roots.append((name, release_binding, probe))
                        cleanup.callback(probe.close)
                        if (
                            probe.tool_path is not None
                            and not probe.uses_account_local_retention
                        ):
                            unfenced_tools.append(probe.tool_path)
                        continue
                    root = probe.take_root()
                    roots.append(root)
                    cleanup.callback(root.close)
                    _acquire_legacy_retention_lock(root)
                    if _record_initial_attempt_state(root):
                        unresolved.append(root.path)
                    _revalidate_legacy_retention_lock(root)
                    _revalidate_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        root,
                    )

                if current_release_binding is None:
                    raise RuntimeError(
                        "current installed release is missing from its release catalog"
                    )
                _revalidate_installed_release_catalog(catalog)
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

        body_error: BaseException | None = None
        try:
            yield tuple(unresolved)
        except BaseException as error:
            body_error = error
            raise
        finally:
            try:
                if current_root is not None:
                    _revalidate_legacy_retention_lock(current_root)
                    _reject_new_attempt(current_root)
                    _revalidate_current_tool_legacy_retention_root(
                        current_root,
                        catalog=catalog,
                    )
                elif current_root_absent:
                    if catalog is None:
                        appeared_current = _open_current_tool_legacy_retention_root(
                            current_tool_path
                        )
                    else:
                        appeared_current = (
                            _open_bound_current_tool_legacy_retention_root(catalog)
                        )
                    if appeared_current is not None:
                        appeared_current.close()
                        raise RuntimeError(
                            "current helper legacy retention path appeared while "
                            "migration fence was active"
                        )
                for root in roots:
                    _revalidate_legacy_retention_lock(root)
                    _reject_new_attempt(root)
                    _revalidate_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        root,
                    )
                if (
                    releases_root is not None
                    and current_release_name is not None
                    and current_release_binding is not None
                    and current_catalog_probe is not None
                    and releases_fd >= 0
                ):
                    refreshed_current_probe = _open_legacy_retention_root(
                        releases_fd,
                        releases_root,
                        current_release_name,
                        current_release_binding,
                    )
                    try:
                        _revalidate_legacy_probe_snapshot(
                            current_catalog_probe,
                            refreshed_current_probe,
                            releases_fd=releases_fd,
                            releases_root=releases_root,
                        )
                        _validate_current_release_probe(
                            refreshed_current_probe,
                            catalog=catalog,
                            current_tool_path=current_tool_path,
                            current_root=current_root,
                        )
                    finally:
                        _close_legacy_probe(
                            refreshed_current_probe,
                            label="refreshed current installed release probe",
                        )
                if (
                    releases_root is not None
                    and releases_policy is not None
                    and releases_fd >= 0
                ):
                    for name, release_binding, initial_probe in absent_roots:
                        appeared = _open_legacy_retention_root(
                            releases_fd,
                            releases_root,
                            name,
                            release_binding,
                        )
                        try:
                            _revalidate_legacy_probe_snapshot(
                                initial_probe,
                                appeared,
                                releases_fd=releases_fd,
                                releases_root=releases_root,
                            )
                        finally:
                            _close_legacy_probe(
                                appeared,
                                label="refreshed installed release probe",
                            )
                    if catalog is None:
                        raise RuntimeError(
                            "installed release catalog binding is missing"
                        )
                    _revalidate_installed_release_catalog(catalog)
            except (OSError, ValueError) as error:
                if body_error is None:
                    raise RuntimeError(
                        "cannot inspect installed legacy retention safely"
                    ) from error
                _record_secondary_error(
                    body_error,
                    label="legacy retention fence finalization failed",
                    secondary_error=error,
                )
            except BaseException as error:
                if body_error is None:
                    raise
                _record_secondary_error(
                    body_error,
                    label="legacy retention fence finalization failed",
                    secondary_error=error,
                )
    finally:
        primary_error = sys.exception()
        try:
            cleanup.close()
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            _record_secondary_error(
                primary_error,
                label="legacy retention fence cleanup failed",
                secondary_error=cleanup_error,
            )
