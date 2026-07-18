from __future__ import annotations

import contextlib
import math
import os
import pathlib
import stat
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterator

from .common import ForwardedSignal, ReviewError


DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
DEFAULT_RETRY_INTERVAL_SECONDS = 0.05


class ClaudeRefreshLockError(ReviewError):
    """A Claude refresh-lock operation failed closed."""


class ClaudeRefreshLockTimeout(ClaudeRefreshLockError):
    """Another process retained one of Claude's refresh locks."""


class ClaudeRefreshLockStale(ClaudeRefreshLockError):
    """A crash residue cannot be reclaimed with a conditional directory delete."""


class ClaudeRefreshLockUnsafe(ClaudeRefreshLockError):
    """The config directory or a newly created lock was unsafe."""


class ClaudeRefreshLockCompromised(ClaudeRefreshLockError):
    """A held lock was deleted, replaced, or changed."""


class ClaudeRefreshLockCleanupInconclusive(ClaudeRefreshLockError):
    """Bounded heartbeat shutdown ended without safe owned-lock cleanup."""


class ClaudeRefreshLockCleanupDiagnostic(RuntimeError):
    """Python 3.10-visible diagnostic for a secondary cleanup failure."""


@dataclass(frozen=True)
class ClaudeRefreshLockProtocol:
    identifier: str
    primary_lock_name: str
    legacy_suffix: str
    stale_seconds: float
    update_seconds: float
    mtime_tolerance_seconds: float


CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211 = ClaudeRefreshLockProtocol(
    identifier="claude-code-2.1.211-primary-plus-legacy-v1",
    primary_lock_name=".oauth_refresh.lock",
    legacy_suffix=".lock",
    stale_seconds=60.0,
    update_seconds=5.0,
    mtime_tolerance_seconds=2.0,
)

# These SHA-256 values come from Anthropic's signed 2.1.211 manifest. WSL2 uses
# the matching Linux artifact. Native Windows remains unsupported.
CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS = MappingProxyType(
    {
        (
            "2.1.211",
            "darwin-arm64",
            "5a728a76198b6eca7f3c7cdbff43bab44b77b48c2108f7a3107d889773382629",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
        (
            "2.1.211",
            "darwin-x64",
            "33049eb14cf4702b992b7eda41ec077fc6e76539f7fd046e6d32538757235da4",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
        (
            "2.1.211",
            "linux-arm64",
            "1fff7e8f947c07b19d10b1fbf714b7e547e9536253b9b58230d8adbc4624f867",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
        (
            "2.1.211",
            "linux-x64",
            "8272c8a474ac9ea1bc35f19b9f7c7e7dc4dc4eb6d5ad3e484b19335ac72446b2",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
        (
            "2.1.211",
            "linux-arm64-musl",
            "ca094a85ea464b2ebec2ecfcc9e2c056573d4ca95ebe12ffae2c7dccb722e17b",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
        (
            "2.1.211",
            "linux-x64-musl",
            "c99bd7934ac841d5be6ee7d3644cb63bccef2cd495c6c1bb982a1b1deac1b466",
        ): CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,
    }
)


def certified_claude_refresh_lock_protocol(
    *,
    version: str,
    platform_key: str,
    checksum: str,
) -> ClaudeRefreshLockProtocol | None:
    return CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS.get(
        (version, platform_key, checksum)
    )


@dataclass(frozen=True)
class ClaudeRefreshLockIdentity:
    path: pathlib.Path
    device: int
    inode: int
    uid: int
    mode: int


@dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int
    uid: int
    mode: int


@dataclass
class _DirectoryAnchor:
    path: pathlib.Path
    descriptor: int
    identity: _DirectoryIdentity
    verify_path_identity: bool = True


@dataclass
class _HeldLock:
    label: str
    path: pathlib.Path
    name: str
    parent: _DirectoryAnchor
    descriptor: int
    identity: ClaudeRefreshLockIdentity


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _lock_identity(
    path: pathlib.Path,
    metadata: os.stat_result,
) -> ClaudeRefreshLockIdentity:
    return ClaudeRefreshLockIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _matches_directory_identity(
    metadata: os.stat_result,
    identity: _DirectoryIdentity,
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_dev == identity.device
        and metadata.st_ino == identity.inode
        and metadata.st_uid == identity.uid
        and stat.S_IMODE(metadata.st_mode) == identity.mode
    )


def _matches_lock_identity(
    metadata: os.stat_result,
    identity: ClaudeRefreshLockIdentity,
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_dev == identity.device
        and metadata.st_ino == identity.inode
        and metadata.st_uid == identity.uid
        and stat.S_IMODE(metadata.st_mode) == identity.mode
    )


def _safe_filesystem_error(message: str, error: OSError) -> ClaudeRefreshLockError:
    errno_code = error.errno
    suffix = f" (errno {errno_code})" if errno_code is not None else ""
    return ClaudeRefreshLockError(message + suffix)


def _is_control_flow_error(error: BaseException) -> bool:
    return not isinstance(error, Exception) or isinstance(error, ForwardedSignal)


def _normalize_operation_error(
    message: str,
    error: BaseException,
) -> BaseException:
    if _is_control_flow_error(error):
        return error
    if isinstance(error, ClaudeRefreshLockError):
        return error
    if isinstance(error, OSError):
        return _safe_filesystem_error(message, error)
    if isinstance(error, Exception):
        return ClaudeRefreshLockError(message)
    return error


def _refresh_lock_recovery_paths(
    error: BaseException,
) -> tuple[str, ...] | None:
    pending = [error]
    seen: set[int] = set()
    while pending and len(seen) < 16:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        paths = getattr(current, "_codex_claude_refresh_lock_paths", None)
        if (
            isinstance(paths, tuple)
            and paths
            and all(isinstance(path, str) for path in paths)
        ):
            return paths
        for chained in (current.__cause__, current.__context__):
            if isinstance(chained, BaseException):
                pending.append(chained)
    return None


def _has_descriptor_bound_refresh_lock_cleanup(error: BaseException) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending and len(seen) < 16:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if getattr(
            current,
            "_codex_claude_refresh_lock_descriptor_bound",
            False,
        ) is True:
            return True
        for chained in (current.__cause__, current.__context__):
            if isinstance(chained, BaseException):
                pending.append(chained)
    return False


def _refresh_lock_recovery_diagnostic(paths: tuple[str, ...]) -> str:
    return (
        "Claude refresh-lock cleanup is inconclusive; helper-owned lock paths "
        f"may remain at {', '.join(paths)}. Pause and confirm that no Claude "
        "credential writer is active before controlled cleanup."
    )


def _descriptor_bound_refresh_lock_recovery_diagnostic() -> str:
    return (
        "Claude refresh-lock cleanup is inconclusive; descriptor-bound lock "
        "directories may remain, but no authoritative pathname is available. "
        "Pause and independently identify the retained directory tree after "
        "confirming that no Claude credential writer is active."
    )


def attach_claude_refresh_lock_recovery(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    """Make an exact retained-lock recovery diagnostic user-visible."""

    paths = _refresh_lock_recovery_paths(cleanup_error)
    if paths is None:
        if not _has_descriptor_bound_refresh_lock_cleanup(cleanup_error):
            return
        setattr(
            error,
            "_codex_claude_refresh_lock_descriptor_bound",
            True,
        )
        diagnostic = _descriptor_bound_refresh_lock_recovery_diagnostic()
    else:
        setattr(error, "_codex_claude_refresh_lock_paths", paths)
        diagnostic = _refresh_lock_recovery_diagnostic(paths)
    if isinstance(error, ForwardedSignal):
        if error.detail is None:
            error.detail = diagnostic
        elif diagnostic not in error.detail:
            error.detail = f"{error.detail}; {diagnostic}"
        return
    if isinstance(error, ReviewError):
        message = str(error)
        if diagnostic not in message:
            error.args = (f"{message}; {diagnostic}",)
        return
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)


def _attach_secondary_cleanup(
    primary: BaseException,
    _secondary: BaseException,
) -> None:
    attach_claude_refresh_lock_recovery(primary, _secondary)
    diagnostic = "Claude refresh-lock cleanup also failed"
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)
        return
    node = ClaudeRefreshLockCleanupDiagnostic(diagnostic)
    if primary.__cause__ is not None:
        node.__cause__ = primary.__cause__
    elif primary.__context__ is not None:
        node.__context__ = primary.__context__
    primary.__cause__ = node


def _attach_cleanup_or_raise(
    primary: BaseException,
    cleanup: BaseException,
    *,
    message: str,
) -> None:
    normalized = _normalize_operation_error(message, cleanup)
    if _is_control_flow_error(normalized):
        _attach_secondary_cleanup(normalized, primary)
        raise normalized
    _attach_secondary_cleanup(primary, normalized)


def _primary_error(errors: list[BaseException]) -> BaseException | None:
    if not errors:
        return None
    primary = next(
        (error for error in errors if _is_control_flow_error(error)),
        errors[0],
    )
    for error in errors:
        if error is not primary:
            _attach_secondary_cleanup(primary, error)
    return primary


def _validate_timeout(timeout_seconds: float, retry_interval_seconds: float) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise ValueError("timeout_seconds must be finite and non-negative")
    if not math.isfinite(retry_interval_seconds) or retry_interval_seconds <= 0:
        raise ValueError("retry_interval_seconds must be finite and positive")


def _validate_protocol(protocol: ClaudeRefreshLockProtocol) -> None:
    if not any(
        protocol is certified
        for certified in CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS.values()
    ):
        raise ClaudeRefreshLockUnsafe(
            "Claude refresh-lock protocol is not artifact-certified"
        )


def _open_directory_anchor(
    path: pathlib.Path,
    *,
    require_private: bool,
    label: str,
) -> _DirectoryAnchor:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise ClaudeRefreshLockUnsafe(f"Claude {label} is not a real directory")
        descriptor = os.open(path, flags)
    except ClaudeRefreshLockUnsafe:
        raise
    except OSError as error:
        raise _safe_filesystem_error(
            f"cannot inspect Claude {label}",
            error,
        ) from None
    try:
        current = os.fstat(descriptor)
        after = os.stat(path, follow_symlinks=False)
        identity = _directory_identity(current)
        if not (
            _matches_directory_identity(before, identity)
            and _matches_directory_identity(after, identity)
        ):
            raise ClaudeRefreshLockUnsafe(
                f"Claude {label} changed during inspection"
            )
        if require_private and (
            identity.uid != os.getuid() or identity.mode & 0o022
        ):
            raise ClaudeRefreshLockUnsafe(
                f"Claude {label} must be current-user-owned and not writable by others"
            )
        if not require_private:
            private_owner = identity.uid == os.getuid() and not (identity.mode & 0o022)
            sticky_system_tmp = identity.uid == 0 and identity.mode == 0o1777
            if not (private_owner or sticky_system_tmp):
                raise ClaudeRefreshLockUnsafe(f"Claude {label} is writable by others")
        return _DirectoryAnchor(path=path, descriptor=descriptor, identity=identity)
    except BaseException as primary_error:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            _attach_cleanup_or_raise(
                primary_error,
                cleanup_error,
                message="cannot close Claude directory anchor",
            )
        raise


def _open_directory_anchor_at(
    path: pathlib.Path,
    descriptor: int,
    *,
    require_private: bool,
    label: str,
) -> _DirectoryAnchor:
    """Duplicate a caller-owned directory anchor without reopening its path."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.fstat(descriptor)
        anchored_descriptor = os.open(".", flags, dir_fd=descriptor)
    except OSError as error:
        raise _safe_filesystem_error(
            f"cannot inspect anchored Claude {label}",
            error,
        ) from None
    try:
        current = os.fstat(anchored_descriptor)
        after = os.fstat(descriptor)
        identity = _directory_identity(current)
        if not (
            _matches_directory_identity(before, identity)
            and _matches_directory_identity(after, identity)
        ):
            raise ClaudeRefreshLockUnsafe(
                f"anchored Claude {label} changed during inspection"
            )
        if require_private and (
            identity.uid != os.getuid() or identity.mode & 0o022
        ):
            raise ClaudeRefreshLockUnsafe(
                f"Claude {label} must be current-user-owned and not writable by others"
            )
        if not require_private:
            private_owner = identity.uid == os.getuid() and not (identity.mode & 0o022)
            sticky_system_tmp = identity.uid == 0 and identity.mode == 0o1777
            if not (private_owner or sticky_system_tmp):
                raise ClaudeRefreshLockUnsafe(f"Claude {label} is writable by others")
        return _DirectoryAnchor(
            path=path,
            descriptor=anchored_descriptor,
            identity=identity,
            verify_path_identity=False,
        )
    except BaseException as primary_error:
        try:
            os.close(anchored_descriptor)
        except BaseException as cleanup_error:
            _attach_cleanup_or_raise(
                primary_error,
                cleanup_error,
                message="cannot close anchored Claude directory",
            )
        raise


def _assert_anchor(anchor: _DirectoryAnchor, *, label: str) -> None:
    try:
        descriptor_metadata = os.fstat(anchor.descriptor)
        path_metadata = (
            os.stat(anchor.path, follow_symlinks=False)
            if anchor.verify_path_identity
            else None
        )
    except OSError:
        raise ClaudeRefreshLockCompromised(
            f"Claude {label} is no longer stable"
        ) from None
    if not _matches_directory_identity(descriptor_metadata, anchor.identity):
        raise ClaudeRefreshLockCompromised(f"Claude {label} was replaced or changed")
    if path_metadata is not None and not _matches_directory_identity(
        path_metadata,
        anchor.identity,
    ):
        raise ClaudeRefreshLockCompromised(f"Claude {label} was replaced or changed")


def _inspect_new_lock(
    *,
    label: str,
    path: pathlib.Path,
    name: str,
    parent: _DirectoryAnchor,
) -> _HeldLock:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    identity: ClaudeRefreshLockIdentity | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
    except OSError as error:
        raise _safe_filesystem_error(
            f"cannot inspect newly created Claude {label} refresh lock; "
            "the unproven lock was left in place",
            error,
        ) from None
    assert descriptor is not None
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(
            name,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        identity = _lock_identity(path, metadata)
        if not _matches_lock_identity(path_metadata, identity):
            raise ClaudeRefreshLockUnsafe(
                f"newly created Claude {label} refresh lock changed during inspection"
            )
        if identity.uid != os.getuid() or identity.mode != 0o700:
            raise ClaudeRefreshLockUnsafe(
                f"newly created Claude {label} refresh lock is not private"
            )
        return _HeldLock(
            label=label,
            path=path,
            name=name,
            parent=parent,
            descriptor=descriptor,
            identity=identity,
        )
    except BaseException as primary_error:
        if identity is not None:
            try:
                current = os.stat(
                    name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
                descriptor_metadata = os.fstat(descriptor)
                if (
                    _matches_lock_identity(current, identity)
                    and _matches_lock_identity(descriptor_metadata, identity)
                ):
                    os.rmdir(name, dir_fd=parent.descriptor)
            except BaseException as cleanup_error:
                _attach_cleanup_or_raise(
                    primary_error,
                    cleanup_error,
                    message="cannot remove unproven Claude refresh lock",
                )
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            _attach_cleanup_or_raise(
                primary_error,
                cleanup_error,
                message="cannot close Claude refresh-lock descriptor",
            )
        raise


def _inspect_existing_lock(
    *,
    label: str,
    path: pathlib.Path,
    name: str,
    parent: _DirectoryAnchor,
    protocol: ClaudeRefreshLockProtocol,
) -> str:
    """Classify an existing lock without mutating Claude's shared lock path."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    operation_error: BaseException | None = None
    try:
        _assert_anchor(parent, label=f"{label} lock parent")
        try:
            descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        except FileNotFoundError:
            return "missing"
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect existing Claude {label} refresh lock",
                error,
            ) from None
        try:
            descriptor_metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return "missing"
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect existing Claude {label} refresh lock",
                error,
            ) from None
        identity = _lock_identity(path, descriptor_metadata)
        if not _matches_lock_identity(path_metadata, identity):
            raise ClaudeRefreshLockUnsafe(
                f"existing Claude {label} refresh lock changed during inspection"
            )
        if identity.uid != os.getuid() or identity.mode & 0o022:
            raise ClaudeRefreshLockUnsafe(
                f"existing Claude {label} refresh lock is not current-user-owned "
                "and non-writable by others"
            )
        if descriptor_metadata.st_mtime_ns != path_metadata.st_mtime_ns:
            return "live"
        stale_before_ns = time.time_ns() - int(
            protocol.stale_seconds * 1_000_000_000
        )
        if descriptor_metadata.st_mtime_ns > stale_before_ns:
            return "live"
        return "stale"
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                if operation_error is None:
                    normalized = _normalize_operation_error(
                        "cannot close existing Claude refresh-lock descriptor",
                        cleanup_error,
                    )
                    raise normalized from None
                _attach_cleanup_or_raise(
                    operation_error,
                    cleanup_error,
                    message="cannot close existing Claude refresh-lock descriptor",
                )


def _inspect_reclaimable_staged_lock(
    *,
    label: str,
    path: pathlib.Path,
    name: str,
    parent: _DirectoryAnchor,
) -> _HeldLock | None:
    """Anchor one exact helper-owned abandoned lock without mutating it."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    operation_error: BaseException | None = None
    try:
        _assert_anchor(parent, label=f"staged {label} lock parent")
        try:
            descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect abandoned staged Claude {label} refresh lock",
                error,
            ) from None
        try:
            descriptor_metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect abandoned staged Claude {label} refresh lock",
                error,
            ) from None
        identity = _lock_identity(path, descriptor_metadata)
        if not (
            _matches_lock_identity(path_metadata, identity)
            and identity.uid == os.getuid()
            and identity.mode == 0o700
        ):
            raise ClaudeRefreshLockUnsafe(
                f"abandoned staged Claude {label} refresh lock is not an "
                "unchanged current-user-owned 0700 directory"
            )
        try:
            entries = os.listdir(descriptor)
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect abandoned staged Claude {label} refresh lock contents",
                error,
            ) from None
        if entries:
            raise ClaudeRefreshLockUnsafe(
                f"abandoned staged Claude {label} refresh lock is not empty"
            )
        _assert_anchor(parent, label=f"staged {label} lock parent")
        try:
            current = os.stat(
                name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot recheck abandoned staged Claude {label} refresh lock",
                error,
            ) from None
        if not _matches_lock_identity(current, identity):
            raise ClaudeRefreshLockUnsafe(
                f"abandoned staged Claude {label} refresh lock changed during inspection"
            )
        return _HeldLock(
            label=f"staged {label}",
            path=path,
            name=name,
            parent=parent,
            descriptor=descriptor,
            identity=identity,
        )
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if descriptor is not None and operation_error is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                _attach_cleanup_or_raise(
                    operation_error,
                    cleanup_error,
                    message="cannot close abandoned staged Claude refresh-lock descriptor",
                )


def recover_abandoned_staged_claude_refresh_locks(
    carrier_root: os.PathLike[str] | str,
    config_dir: os.PathLike[str] | str,
    *,
    protocol: ClaudeRefreshLockProtocol,
    writer_quiescent: bool,
) -> tuple[pathlib.Path, ...]:
    """Remove exact helper-owned staged locks after proven writer quiescence.

    This deliberately does not share the stale-lock path used for a host Claude
    config. The caller must own the private staged carrier and must prove that
    its supervised Claude process group and credential watcher have stopped.
    """

    _validate_protocol(protocol)
    if writer_quiescent is not True:
        raise ClaudeRefreshLockUnsafe(
            "abandoned staged Claude refresh locks require proven writer quiescence"
        )
    raw_carrier = os.fspath(carrier_root)
    raw_config = os.fspath(config_dir)
    if not all(
        isinstance(value, str) and os.path.isabs(value)
        for value in (raw_carrier, raw_config)
    ):
        raise ClaudeRefreshLockUnsafe(
            "staged Claude recovery paths must be absolute"
        )
    carrier_path = pathlib.Path(raw_carrier)
    config_path = pathlib.Path(raw_config)
    if (
        config_path.parent != carrier_path
        or config_path.name != "config"
        or not carrier_path.name.startswith("claude-carrier-")
    ):
        raise ClaudeRefreshLockUnsafe(
            "Claude refresh-lock recovery is limited to an exact helper-created "
            "staged carrier"
        )

    carrier_anchor: _DirectoryAnchor | None = None
    config_anchor: _DirectoryAnchor | None = None
    locks: list[_HeldLock] = []
    operation_error: BaseException | None = None
    try:
        carrier_anchor = _open_directory_anchor(
            carrier_path,
            require_private=True,
            label="staged credential carrier",
        )
        if carrier_anchor.identity.mode != 0o700:
            raise ClaudeRefreshLockUnsafe(
                "staged Claude credential carrier must have mode 0700"
            )
        config_anchor = _open_directory_anchor(
            config_path,
            require_private=True,
            label="staged config directory",
        )
        if config_anchor.identity.mode != 0o700:
            raise ClaudeRefreshLockUnsafe(
                "staged Claude config directory must have mode 0700"
            )
        primary = _inspect_reclaimable_staged_lock(
            label="primary",
            path=config_path / protocol.primary_lock_name,
            name=protocol.primary_lock_name,
            parent=config_anchor,
        )
        if primary is not None:
            locks.append(primary)
        legacy_name = config_path.name + protocol.legacy_suffix
        legacy = _inspect_reclaimable_staged_lock(
            label="legacy",
            path=pathlib.Path(str(config_path) + protocol.legacy_suffix),
            name=legacy_name,
            parent=carrier_anchor,
        )
        if legacy is not None:
            locks.append(legacy)
        _assert_anchor(config_anchor, label="staged config directory")
        _assert_anchor(carrier_anchor, label="staged credential carrier")
        for lock in reversed(locks):
            _remove_owned_lock(lock)
        return tuple(lock.path for lock in locks)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        closed: set[int] = set()
        for descriptor in (
            *(lock.descriptor for lock in locks),
            *(
                anchor.descriptor
                for anchor in (config_anchor, carrier_anchor)
                if anchor is not None
            ),
        ):
            if descriptor in closed:
                continue
            closed.add(descriptor)
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        cleanup_error = _primary_error(cleanup_errors)
        if cleanup_error is not None:
            if operation_error is None:
                normalized = _normalize_operation_error(
                    "cannot close staged Claude recovery descriptor",
                    cleanup_error,
                )
                raise normalized from None
            _attach_cleanup_or_raise(
                operation_error,
                cleanup_error,
                message="cannot close staged Claude recovery descriptor",
            )


def _acquire_one(
    *,
    label: str,
    path: pathlib.Path,
    name: str,
    parent: _DirectoryAnchor,
    protocol: ClaudeRefreshLockProtocol,
    deadline: float,
    retry_interval_seconds: float,
) -> _HeldLock:
    while True:
        _assert_anchor(parent, label=f"{label} lock parent")
        try:
            # mkdir is the directory-lock protocol's atomic O_EXCL equivalent.
            os.mkdir(name, 0o700, dir_fd=parent.descriptor)
        except FileExistsError:
            existing_state = _inspect_existing_lock(
                label=label,
                path=path,
                name=name,
                parent=parent,
                protocol=protocol,
            )
            if existing_state == "missing":
                if time.monotonic() >= deadline:
                    raise ClaudeRefreshLockTimeout(
                        f"timed out waiting for Claude {label} refresh lock"
                    )
                continue
            if existing_state == "stale":
                raise ClaudeRefreshLockStale(
                    f"stale Claude {label} refresh lock requires controlled cleanup "
                    "after confirming that no Claude credential writer is active"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClaudeRefreshLockTimeout(
                    f"timed out waiting for Claude {label} refresh lock"
                ) from None
            time.sleep(min(retry_interval_seconds, remaining))
            continue
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot acquire Claude {label} refresh lock",
                error,
            ) from None
        return _inspect_new_lock(
            label=label,
            path=path,
            name=name,
            parent=parent,
        )


def _assert_lock(lock: _HeldLock) -> None:
    try:
        descriptor_metadata = os.fstat(lock.descriptor)
        path_metadata = os.stat(
            lock.name,
            dir_fd=lock.parent.descriptor,
            follow_symlinks=False,
        )
    except OSError:
        raise ClaudeRefreshLockCompromised(
            f"Claude {lock.label} refresh lock was deleted or became unreadable"
        ) from None
    if not (
        _matches_lock_identity(descriptor_metadata, lock.identity)
        and _matches_lock_identity(path_metadata, lock.identity)
    ):
        raise ClaudeRefreshLockCompromised(
            f"Claude {lock.label} refresh lock was replaced or changed"
        )


def _renew_lock(
    lock: _HeldLock,
    protocol: ClaudeRefreshLockProtocol,
) -> None:
    """Renew one anchored directory lock and prove the path still names it."""

    _assert_lock(lock)
    renewed_at_ns = time.time_ns()
    try:
        # Updating through the held descriptor cannot touch a replacement path.
        os.utime(
            lock.descriptor,
            ns=(renewed_at_ns, renewed_at_ns),
        )
    except OSError as error:
        raise _safe_filesystem_error(
            f"cannot renew Claude {lock.label} refresh lock",
            error,
        ) from None
    _assert_lock(lock)
    try:
        descriptor_metadata = os.fstat(lock.descriptor)
        path_metadata = os.stat(
            lock.name,
            dir_fd=lock.parent.descriptor,
            follow_symlinks=False,
        )
    except OSError:
        raise ClaudeRefreshLockCompromised(
            f"Claude {lock.label} refresh lock changed after renewal"
        ) from None
    minimum_fresh_mtime_ns = renewed_at_ns - int(
        protocol.mtime_tolerance_seconds * 1_000_000_000
    )
    if (
        descriptor_metadata.st_mtime_ns < minimum_fresh_mtime_ns
        or path_metadata.st_mtime_ns < minimum_fresh_mtime_ns
    ):
        raise ClaudeRefreshLockError(
            f"Claude {lock.label} refresh lock did not retain a fresh lease"
        )


def _remove_owned_lock(lock: _HeldLock) -> None:
    _assert_lock(lock)
    try:
        os.rmdir(lock.name, dir_fd=lock.parent.descriptor)
    except OSError as error:
        raise _safe_filesystem_error(
            f"cannot release Claude {lock.label} refresh lock",
            error,
        ) from None


class ClaudeRefreshLockLease:
    def __init__(
        self,
        *,
        protocol: ClaudeRefreshLockProtocol,
        config_anchor: _DirectoryAnchor,
        legacy_parent_anchor: _DirectoryAnchor,
        locks: tuple[_HeldLock, ...],
    ) -> None:
        self._protocol = protocol
        self._config_anchor = config_anchor
        self._legacy_parent_anchor = legacy_parent_anchor
        self._locks = locks
        self._release_started = False
        self._cleanup_started = False
        self._released = False
        self._cleanup_inconclusive: ClaudeRefreshLockCleanupInconclusive | None = None
        self._release_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_error: BaseException | None = None

    @property
    def paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(lock.path for lock in self._locks)

    @property
    def identities(self) -> tuple[ClaudeRefreshLockIdentity, ...]:
        return tuple(lock.identity for lock in self._locks)

    @property
    def released(self) -> bool:
        with self._state_lock:
            return self._released

    def _record_failure(self, error: BaseException) -> BaseException:
        normalized = _normalize_operation_error(
            "Claude refresh-lock heartbeat failed",
            error,
        )
        if self._heartbeat_error is None:
            self._heartbeat_error = normalized
        return self._heartbeat_error

    def _renew_and_assert(self) -> None:
        _assert_anchor(self._config_anchor, label="config directory")
        _assert_anchor(self._legacy_parent_anchor, label="legacy lock parent")
        for lock in self._locks:
            _renew_lock(lock, self._protocol)
        _assert_anchor(self._config_anchor, label="config directory")
        _assert_anchor(self._legacy_parent_anchor, label="legacy lock parent")
        for lock in self._locks:
            _assert_lock(lock)

    def _shutdown_timeout_seconds(self) -> float:
        return max(self._protocol.update_seconds * 2.0, 1.0)

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(
            self._protocol.update_seconds
        ):
            with self._state_lock:
                if self._release_started:
                    return
            with self._operation_lock:
                with self._state_lock:
                    if self._release_started:
                        return
                try:
                    self._renew_and_assert()
                except BaseException as error:
                    with self._state_lock:
                        self._record_failure(error)
                        self._heartbeat_stop.set()
                    return

    def _start_heartbeat(self) -> None:
        with self._state_lock:
            if self._release_started:
                raise ClaudeRefreshLockCompromised(
                    "cannot start a releasing or released Claude refresh-lock lease"
                )
            if self._heartbeat_thread is not None:
                raise ClaudeRefreshLockError(
                    "Claude refresh-lock heartbeat was already started"
                )
            thread = threading.Thread(
                target=self._heartbeat_loop,
                name="codex-claude-refresh-lock-heartbeat",
                daemon=True,
            )
            self._heartbeat_thread = thread
        try:
            thread.start()
        except BaseException as error:
            normalized = _normalize_operation_error(
                "cannot start Claude refresh-lock heartbeat",
                error,
            )
            with self._state_lock:
                self._record_failure(normalized)
                self._heartbeat_stop.set()
            raise normalized from None

    def assert_held(self) -> None:
        with self._state_lock:
            if self._release_started:
                raise ClaudeRefreshLockCompromised(
                    "Claude refresh-lock lease release already started"
                )
            if self._heartbeat_error is not None:
                raise self._heartbeat_error
        with self._operation_lock:
            with self._state_lock:
                if self._release_started:
                    raise ClaudeRefreshLockCompromised(
                        "Claude refresh-lock lease release already started"
                    )
                if self._heartbeat_error is not None:
                    raise self._heartbeat_error
            try:
                # Renew synchronously at the commit boundary. Even if earlier I/O
                # was slow, Claude's 60-second stale detector now sees a fresh lock.
                self._renew_and_assert()
            except BaseException as error:
                with self._state_lock:
                    failure = self._record_failure(error)
                    self._heartbeat_stop.set()
                raise failure from None
            with self._state_lock:
                if self._release_started:
                    raise ClaudeRefreshLockCompromised(
                        "Claude refresh-lock lease release already started"
                    )

    def release(self) -> None:
        with self._release_lock:
            with self._state_lock:
                cleanup_inconclusive = self._cleanup_inconclusive
            if cleanup_inconclusive is not None:
                raise cleanup_inconclusive
            try:
                self._release_once()
            except BaseException as first_error:
                with self._state_lock:
                    cleanup_inconclusive = self._cleanup_inconclusive
                    retry_needed = (
                        not self._released and not self._cleanup_started
                        and cleanup_inconclusive is None
                    )
                    cleanup_interrupted = cleanup_inconclusive is not None or (
                        not self._released and self._cleanup_started
                    )
                if not retry_needed:
                    if cleanup_interrupted:
                        diagnostic = self._mark_cleanup_inconclusive(
                            "Claude refresh-lock descriptor or lock cleanup "
                            "was interrupted"
                        )
                        if _is_control_flow_error(
                            first_error
                        ) or isinstance(first_error, ReviewError):
                            _attach_secondary_cleanup(first_error, diagnostic)
                            raise first_error
                        diagnostic.__cause__ = first_error
                        raise diagnostic from first_error
                    raise
                try:
                    self._release_once()
                except BaseException as retry_error:
                    with self._state_lock:
                        cleanup_inconclusive = self._cleanup_inconclusive
                        cleanup_incomplete = (
                            cleanup_inconclusive is not None
                            or (
                                not self._released
                                and not self._cleanup_started
                            )
                        )
                    if cleanup_incomplete:
                        terminal_was_published = (
                            cleanup_inconclusive is not None
                        )
                        diagnostic = self._mark_cleanup_inconclusive(
                            "Claude refresh-lock operations did not quiesce after "
                            "two bounded cleanup attempts"
                        )
                        paths = _refresh_lock_recovery_paths(diagnostic)
                        control_flow = next(
                            (
                                error
                                for error in (first_error, retry_error)
                                if _is_control_flow_error(error)
                            ),
                            None,
                        )
                        if control_flow is not None:
                            if paths is not None:
                                setattr(
                                    control_flow,
                                    "_codex_claude_refresh_lock_paths",
                                    paths,
                                )
                            if isinstance(control_flow, ForwardedSignal):
                                if control_flow.detail:
                                    control_flow.detail = (
                                        f"{control_flow.detail}; {diagnostic}"
                                    )
                                else:
                                    control_flow.detail = str(diagnostic)
                            _attach_secondary_cleanup(control_flow, diagnostic)
                            raise control_flow
                        primary = _primary_error([first_error, retry_error])
                        if terminal_was_published:
                            assert primary is not None
                            _attach_secondary_cleanup(primary, diagnostic)
                            raise primary
                        diagnostic.__cause__ = primary
                        raise diagnostic from primary
                    primary = _primary_error([first_error, retry_error])
                    if primary is not first_error:
                        assert primary is not None
                        raise primary
                raise

    def _mark_cleanup_inconclusive(
        self,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        with self._state_lock:
            if self._cleanup_inconclusive is not None:
                return self._cleanup_inconclusive
            path_diagnostics_are_authoritative = (
                self._config_anchor.verify_path_identity
                and self._legacy_parent_anchor.verify_path_identity
            )
            if path_diagnostics_are_authoritative:
                paths = tuple(str(path) for path in self.paths)
                diagnostic = ClaudeRefreshLockCleanupInconclusive(
                    f"{reason}; {_refresh_lock_recovery_diagnostic(paths)}"
                )
                setattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_paths",
                    paths,
                )
            else:
                diagnostic = ClaudeRefreshLockCleanupInconclusive(
                    f"{reason}; "
                    f"{_descriptor_bound_refresh_lock_recovery_diagnostic()}"
                )
                setattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    True,
                )
            self._cleanup_inconclusive = diagnostic
            return diagnostic

    def _release_once(self) -> None:
        with self._state_lock:
            if self._released:
                return
            if self._cleanup_started:
                raise ClaudeRefreshLockError(
                    "Claude refresh-lock cleanup already started; retrying "
                    "descriptor or lock removal is unsafe"
                )
            self._release_started = True
            self._heartbeat_stop.set()
            thread = self._heartbeat_thread
            heartbeat_error = self._heartbeat_error

        shutdown_timeout = self._shutdown_timeout_seconds()
        errors: list[BaseException] = []
        if heartbeat_error is not None:
            errors.append(heartbeat_error)
        if thread is not None:
            try:
                thread.join(timeout=shutdown_timeout)
            except BaseException as error:
                errors.append(
                    _normalize_operation_error(
                        "cannot stop Claude refresh-lock heartbeat",
                        error,
                    )
                )
            thread_alive = thread.is_alive()
            with self._state_lock:
                final_heartbeat_error = self._heartbeat_error
            if final_heartbeat_error is not None and all(
                error is not final_heartbeat_error for error in errors
            ):
                errors.append(final_heartbeat_error)
            if thread_alive:
                errors.append(
                    ClaudeRefreshLockError(
                        "Claude refresh-lock heartbeat did not stop"
                    )
                )
                primary = _primary_error(errors)
                assert primary is not None
                raise primary
        operation_acquired = False
        try:
            operation_acquired = self._operation_lock.acquire(
                timeout=shutdown_timeout
            )
        except BaseException as error:
            errors.append(
                _normalize_operation_error(
                    "cannot quiesce Claude refresh-lock operations",
                    error,
                )
            )
        if not operation_acquired:
            errors.append(
                ClaudeRefreshLockError(
                    "Claude refresh-lock operations did not quiesce"
                )
            )
            primary = _primary_error(errors)
            assert primary is not None
            raise primary
        try:
            with self._state_lock:
                final_operation_error = self._heartbeat_error
            if final_operation_error is not None and all(
                error is not final_operation_error for error in errors
            ):
                errors.append(final_operation_error)
            cleanup_diagnostic = self._mark_cleanup_inconclusive(
                "Claude refresh-lock descriptor or lock cleanup did not complete"
            )
            with self._state_lock:
                self._cleanup_started = True
            cleanup_failed = False
            for lock in reversed(self._locks):
                try:
                    _remove_owned_lock(lock)
                except BaseException as error:
                    cleanup_failed = True
                    errors.append(
                        _normalize_operation_error(
                            f"cannot release Claude {lock.label} refresh lock",
                            error,
                        )
                    )
            closed_descriptors: set[int] = set()
            for descriptor in (
                *(lock.descriptor for lock in self._locks),
                self._legacy_parent_anchor.descriptor,
                self._config_anchor.descriptor,
            ):
                if descriptor in closed_descriptors:
                    continue
                closed_descriptors.add(descriptor)
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failed = True
                    errors.append(
                        _normalize_operation_error(
                            "cannot close Claude refresh-lock descriptor",
                            error,
                        )
                    )
            with self._state_lock:
                self._released = not cleanup_failed
                if not cleanup_failed:
                    self._cleanup_inconclusive = None
            primary = _primary_error(errors)
            if cleanup_failed:
                assert primary is not None
                attach_claude_refresh_lock_recovery(
                    primary,
                    cleanup_diagnostic,
                )
            if primary is not None:
                raise primary
        finally:
            self._operation_lock.release()


def acquire_claude_refresh_lock(
    config_dir: os.PathLike[str] | str,
    *,
    protocol: ClaudeRefreshLockProtocol,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    retry_interval_seconds: float = DEFAULT_RETRY_INTERVAL_SECONDS,
    config_dir_fd: int | None = None,
    legacy_parent_dir_fd: int | None = None,
) -> ClaudeRefreshLockLease:
    """Acquire Claude's current and legacy directory locks in protocol order."""

    _validate_protocol(protocol)
    _validate_timeout(timeout_seconds, retry_interval_seconds)
    raw_path = os.fspath(config_dir)
    if not isinstance(raw_path, str) or not os.path.isabs(raw_path):
        raise ClaudeRefreshLockUnsafe("Claude config directory must be an absolute path")
    requested_path = pathlib.Path(raw_path)
    if any(part in {".", ".."} for part in requested_path.parts):
        raise ClaudeRefreshLockUnsafe(
            "Claude config directory must not contain path traversal"
        )
    anchored = config_dir_fd is not None or legacy_parent_dir_fd is not None
    if anchored and (config_dir_fd is None or legacy_parent_dir_fd is None):
        raise ClaudeRefreshLockUnsafe(
            "Claude config and legacy-parent directory anchors must be provided together"
        )
    if anchored:
        canonical_path = requested_path
    else:
        try:
            requested_metadata = os.stat(requested_path, follow_symlinks=False)
            if stat.S_ISLNK(requested_metadata.st_mode):
                raise ClaudeRefreshLockUnsafe(
                    "Claude config directory must not be a symlink"
                )
            canonical_path = pathlib.Path(os.path.realpath(raw_path))
            canonical_metadata = os.stat(canonical_path, follow_symlinks=False)
        except ClaudeRefreshLockUnsafe:
            raise
        except OSError as error:
            raise _safe_filesystem_error(
                "cannot resolve Claude config directory", error
            ) from None
        if not (
            stat.S_ISDIR(requested_metadata.st_mode)
            and requested_metadata.st_dev == canonical_metadata.st_dev
            and requested_metadata.st_ino == canonical_metadata.st_ino
        ):
            raise ClaudeRefreshLockUnsafe(
                "Claude config directory resolution is unstable"
            )

    config_anchor: _DirectoryAnchor | None = None
    parent_anchor: _DirectoryAnchor | None = None
    lease: ClaudeRefreshLockLease | None = None
    try:
        if anchored:
            assert config_dir_fd is not None
            assert legacy_parent_dir_fd is not None
            config_anchor = _open_directory_anchor_at(
                canonical_path,
                config_dir_fd,
                require_private=True,
                label="config directory",
            )
            parent_anchor = _open_directory_anchor_at(
                canonical_path.parent,
                legacy_parent_dir_fd,
                require_private=False,
                label="legacy lock parent",
            )
        else:
            config_anchor = _open_directory_anchor(
                canonical_path,
                require_private=True,
                label="config directory",
            )
            parent_anchor = _open_directory_anchor(
                canonical_path.parent,
                require_private=False,
                label="legacy lock parent",
            )
        deadline = time.monotonic() + timeout_seconds
        primary_path = canonical_path / protocol.primary_lock_name
        primary = _acquire_one(
            label="primary",
            path=primary_path,
            name=protocol.primary_lock_name,
            parent=config_anchor,
            protocol=protocol,
            deadline=deadline,
            retry_interval_seconds=retry_interval_seconds,
        )
        legacy_name = canonical_path.name + protocol.legacy_suffix
        legacy_path = pathlib.Path(str(canonical_path) + protocol.legacy_suffix)
        try:
            legacy = _acquire_one(
                label="legacy",
                path=legacy_path,
                name=legacy_name,
                parent=parent_anchor,
                protocol=protocol,
                deadline=deadline,
                retry_interval_seconds=retry_interval_seconds,
            )
        except BaseException as primary_error:
            lease = ClaudeRefreshLockLease(
                protocol=protocol,
                config_anchor=config_anchor,
                legacy_parent_anchor=parent_anchor,
                locks=(primary,),
            )
            try:
                lease.release()
            except BaseException as cleanup_error:
                selected_error = _primary_error(
                    [primary_error, cleanup_error]
                )
                if selected_error is not primary_error:
                    assert selected_error is not None
                    raise selected_error
            raise
        lease = ClaudeRefreshLockLease(
            protocol=protocol,
            config_anchor=config_anchor,
            legacy_parent_anchor=parent_anchor,
            locks=(primary, legacy),
        )
        try:
            lease._start_heartbeat()
        except BaseException as primary_error:
            try:
                lease.release()
            except BaseException as cleanup_error:
                if _is_control_flow_error(cleanup_error):
                    _attach_secondary_cleanup(cleanup_error, primary_error)
                    raise cleanup_error
                _attach_secondary_cleanup(primary_error, cleanup_error)
            raise
        return lease
    except BaseException as primary_error:
        if lease is None:
            cleanup_errors: list[BaseException] = []
            closed: set[int] = set()
            for anchor in (parent_anchor, config_anchor):
                if anchor is None or anchor.descriptor in closed:
                    continue
                closed.add(anchor.descriptor)
                try:
                    os.close(anchor.descriptor)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            selected_error = _primary_error(
                [primary_error, *cleanup_errors]
            )
            if selected_error is not primary_error:
                assert selected_error is not None
                raise selected_error
        raise


@contextlib.contextmanager
def claude_refresh_lock(
    config_dir: os.PathLike[str] | str,
    *,
    protocol: ClaudeRefreshLockProtocol,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    retry_interval_seconds: float = DEFAULT_RETRY_INTERVAL_SECONDS,
) -> Iterator[ClaudeRefreshLockLease]:
    lease = acquire_claude_refresh_lock(
        config_dir,
        protocol=protocol,
        timeout_seconds=timeout_seconds,
        retry_interval_seconds=retry_interval_seconds,
    )
    try:
        yield lease
    except BaseException as body_error:
        try:
            lease.release()
        except BaseException as cleanup_error:
            selected_error = _primary_error([body_error, cleanup_error])
            if selected_error is not body_error:
                assert selected_error is not None
                raise selected_error
        raise
    else:
        lease.release()


__all__ = (
    "CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS",
    "CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211",
    "ClaudeRefreshLockCleanupInconclusive",
    "ClaudeRefreshLockCompromised",
    "ClaudeRefreshLockError",
    "ClaudeRefreshLockIdentity",
    "ClaudeRefreshLockLease",
    "ClaudeRefreshLockProtocol",
    "ClaudeRefreshLockStale",
    "ClaudeRefreshLockTimeout",
    "ClaudeRefreshLockUnsafe",
    "acquire_claude_refresh_lock",
    "attach_claude_refresh_lock_recovery",
    "certified_claude_refresh_lock_protocol",
    "claude_refresh_lock",
    "recover_abandoned_staged_claude_refresh_locks",
)
