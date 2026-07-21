from __future__ import annotations

import contextlib
import errno
import math
import os
import pathlib
import stat
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from types import MappingProxyType
from typing import Iterator, NoReturn

from .common import (
    ForwardedSignal,
    ForwardedSignalMaskOwner,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
)


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


class _AbandonmentCleanupLifecycle(Enum):
    NOT_STARTED = auto()
    RESUMABLE = auto()
    SETTLED = auto()


class _OperationLockHandoffState(Enum):
    NOT_ACQUIRED = auto()
    UNKNOWN = auto()
    ACQUIRED = auto()
    RELEASE_UNKNOWN = auto()
    RELEASED = auto()


class ClaudeRefreshLockCompromised(ClaudeRefreshLockError):
    """A held lock was deleted, replaced, or changed."""


class ClaudeRefreshLockCleanupInconclusive(ClaudeRefreshLockError):
    """Bounded heartbeat shutdown ended without safe owned-lock cleanup."""


@dataclass(frozen=True)
class ClaudeRefreshLockRetentionSnapshot:
    """Atomic read-only state for fail-closed lock retention."""

    terminal: bool
    verified_closed: bool
    diagnostic: ClaudeRefreshLockCleanupInconclusive | None


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


@dataclass(frozen=True)
class _PendingLockAcquisition:
    label: str
    path: pathlib.Path
    name: str
    parent: _DirectoryAnchor


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
    if _has_descriptor_bound_refresh_lock_cleanup(error):
        return None
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
        linked_cleanup = getattr(
            current,
            "_codex_claude_refresh_lock_cleanup_evidence",
            None,
        )
        if isinstance(linked_cleanup, BaseException):
            pending.append(linked_cleanup)
    return None


def _has_descriptor_bound_refresh_lock_cleanup(error: BaseException) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending and len(seen) < 16:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if (
            getattr(
                current,
                "_codex_claude_refresh_lock_descriptor_bound",
                False,
            )
            is True
        ):
            return True
        for chained in (current.__cause__, current.__context__):
            if isinstance(chained, BaseException):
                pending.append(chained)
        linked_cleanup = getattr(
            current,
            "_codex_claude_refresh_lock_cleanup_evidence",
            None,
        )
        if isinstance(linked_cleanup, BaseException):
            pending.append(linked_cleanup)
    return False


def _bind_cleanup_recovery_evidence(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    """Keep prebuilt cleanup evidence live across caller bytecode boundaries."""

    setattr(
        error,
        "_codex_claude_refresh_lock_cleanup_evidence",
        cleanup_error,
    )


def _unbind_cleanup_recovery_evidence(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    if (
        getattr(
            error,
            "_codex_claude_refresh_lock_cleanup_evidence",
            None,
        )
        is cleanup_error
    ):
        delattr(error, "_codex_claude_refresh_lock_cleanup_evidence")


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


def _new_descriptor_bound_cleanup_inconclusive(
    message: str,
) -> ClaudeRefreshLockCleanupInconclusive:
    diagnostic = ClaudeRefreshLockCleanupInconclusive(message)
    setattr(
        diagnostic,
        "_codex_claude_refresh_lock_descriptor_bound",
        True,
    )
    return diagnostic


def _new_cleanup_inconclusive_fallback() -> ClaudeRefreshLockCleanupInconclusive:
    return _new_descriptor_bound_cleanup_inconclusive(
        _descriptor_bound_refresh_lock_recovery_diagnostic()
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
        return
    node = ClaudeRefreshLockCleanupDiagnostic(diagnostic)
    if error.__cause__ is not None:
        node.__cause__ = error.__cause__
    elif not error.__suppress_context__ and error.__context__ is not None:
        node.__context__ = error.__context__
    error.__cause__ = node


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
    elif not primary.__suppress_context__ and primary.__context__ is not None:
        node.__context__ = primary.__context__
    primary.__cause__ = node


def _raise_frozen_control_flow_with_cleanup(
    control_flow: BaseException,
    descriptor_bound_cleanup: ClaudeRefreshLockCleanupInconclusive,
) -> NoReturn:
    """Preserve the first control-flow winner across best-effort attachment."""

    try:
        _bind_cleanup_recovery_evidence(
            control_flow,
            descriptor_bound_cleanup,
        )
    except BaseException:
        pass
    try:
        _attach_secondary_cleanup(
            control_flow,
            descriptor_bound_cleanup,
        )
    except BaseException:
        pass
    raise control_flow


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


def _earliest_context_control_flow(
    error: BaseException,
) -> BaseException | None:
    """Recover the earliest active control flow from a bounded exception chain."""

    current: BaseException | None = error
    earliest: BaseException | None = None
    seen: set[int] = set()
    while current is not None and len(seen) < 16:
        identity = id(current)
        if identity in seen:
            break
        seen.add(identity)
        if _is_control_flow_error(current):
            earliest = current
        context = current.__context__
        if isinstance(context, BaseException):
            # An active context is authoritative. A context cycle terminates
            # recovery instead of falling through to a presentation-only cause.
            if id(context) in seen:
                break
            current = context
            continue
        cause = current.__cause__
        if not isinstance(cause, BaseException) or id(cause) in seen:
            break
        current = cause
    return earliest


class _FirstControlFlowWinner:
    """Keep the first observed control flow sticky through cleanup."""

    def __init__(
        self,
        descriptor_bound_cleanup: ClaudeRefreshLockCleanupInconclusive | None,
    ) -> None:
        self._winner: BaseException | None = None
        self._descriptor_bound_cleanup = descriptor_bound_cleanup

    @property
    def winner(self) -> BaseException | None:
        return self._winner

    def observe(self, error: BaseException) -> None:
        if self._winner is not None:
            return
        candidate = _earliest_context_control_flow(error)
        if candidate is None:
            return
        self._winner = candidate
        if self._descriptor_bound_cleanup is None:
            return
        try:
            _bind_cleanup_recovery_evidence(
                candidate,
                self._descriptor_bound_cleanup,
            )
        except BaseException:
            # The identity is already frozen. Attachment is retried before the
            # winner is raised and must never let a later signal replace it.
            pass

    def observe_all(self, errors: list[BaseException]) -> None:
        if self._winner is not None:
            return
        for error in errors:
            self.observe(error)
            if self._winner is not None:
                return

    def enforce(
        self,
        errors: list[BaseException],
        active_error: BaseException | None = None,
    ) -> None:
        """Raise the sticky winner after bounded raw-chain recovery."""

        self.observe_all(errors)
        if active_error is not None:
            self.observe(active_error)
        self.raise_if_set()

    def raise_if_set(self) -> None:
        winner = self._winner
        if winner is None:
            return
        if self._descriptor_bound_cleanup is None:
            raise winner
        try:
            _raise_frozen_control_flow_with_cleanup(
                winner,
                self._descriptor_bound_cleanup,
            )
        finally:
            raise winner


class _ControlFlowErrorLog(list[BaseException]):
    """Append-only chronology that freezes its first control flow."""

    def __init__(
        self,
        first_control_flow: _FirstControlFlowWinner,
        initial: list[BaseException] | None = None,
    ) -> None:
        super().__init__()
        self.first_control_flow = first_control_flow
        if initial is not None:
            self.extend(initial)

    def append(self, error: BaseException) -> None:
        # Persist raw chronology before the interruptible winner publication.
        super().append(error)
        self.first_control_flow.observe(error)

    def extend(self, errors: list[BaseException]) -> None:
        for error in errors:
            self.append(error)


class _OperationLockHandoff:
    """Close operation-lock ownership gaps around Python call boundaries."""

    def __init__(self, operation_lock: object) -> None:
        self._operation_lock = operation_lock
        self._owner_thread = threading.current_thread()
        self._state = _OperationLockHandoffState.NOT_ACQUIRED

    @property
    def acquired(self) -> bool:
        return self._state is _OperationLockHandoffState.ACQUIRED

    @property
    def state(self) -> _OperationLockHandoffState:
        return self._state

    @property
    def owner_thread(self) -> threading.Thread:
        return self._owner_thread

    @property
    def needs_reconciliation(self) -> bool:
        return self._state in {
            _OperationLockHandoffState.UNKNOWN,
            _OperationLockHandoffState.ACQUIRED,
            _OperationLockHandoffState.RELEASE_UNKNOWN,
        }

    @property
    def resolved(self) -> bool:
        return not self.needs_reconciliation

    def acquire(
        self,
        *,
        timeout: float,
        first_control_flow: _FirstControlFlowWinner,
    ) -> None:
        is_owned = getattr(self._operation_lock, "_is_owned", None)
        if callable(is_owned) and is_owned() is True:
            self._state = _OperationLockHandoffState.NOT_ACQUIRED
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock operation guard was already owned by the "
                "abandonment or release caller"
            )
        self._state = _OperationLockHandoffState.UNKNOWN
        try:
            acquired = self._operation_lock.acquire(timeout=timeout)
            self._state = (
                _OperationLockHandoffState.ACQUIRED
                if acquired
                else _OperationLockHandoffState.NOT_ACQUIRED
            )
        except BaseException as error:
            first_control_flow.observe(error)
            try:
                self.release()
            except BaseException as release_error:
                first_control_flow.observe(release_error)
            first_control_flow.raise_if_set()
            raise

    def release(self) -> None:
        state = self._state
        if state in {
            _OperationLockHandoffState.NOT_ACQUIRED,
            _OperationLockHandoffState.RELEASED,
        }:
            return
        if threading.current_thread() is not self._owner_thread:
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock operation handoff can only be reconciled "
                "by its original thread"
            )
        is_owned = getattr(self._operation_lock, "_is_owned", None)
        owned = is_owned() if callable(is_owned) else None
        if owned is False and state in {
            _OperationLockHandoffState.UNKNOWN,
            _OperationLockHandoffState.RELEASE_UNKNOWN,
        }:
            self._state = _OperationLockHandoffState.RELEASED
            return
        if owned is False and state is _OperationLockHandoffState.ACQUIRED:
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock operation handoff lost known ownership"
            )
        self._state = _OperationLockHandoffState.RELEASE_UNKNOWN
        try:
            self._operation_lock.release()
        except ForwardedSignal:
            owned_after = is_owned() if callable(is_owned) else None
            if owned_after is False:
                self._state = _OperationLockHandoffState.RELEASED
            raise
        except RuntimeError:
            if state is _OperationLockHandoffState.ACQUIRED:
                self._state = _OperationLockHandoffState.ACQUIRED
                raise
            # An RLock owned by another thread (or not acquired at all) cannot
            # be released here. UNKNOWN therefore resolves without touching it.
            self._state = _OperationLockHandoffState.RELEASED
        except BaseException:
            owned_after = is_owned() if callable(is_owned) else None
            if owned_after is False:
                self._state = _OperationLockHandoffState.RELEASED
            raise
        else:
            self._state = _OperationLockHandoffState.RELEASED


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
            raise ClaudeRefreshLockUnsafe(f"Claude {label} changed during inspection")
        if require_private and (identity.uid != os.getuid() or identity.mode & 0o022):
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


def _open_directory_component_at(
    *,
    parent_descriptor: int,
    name: str,
    label: str,
) -> tuple[int, _DirectoryIdentity]:
    """Open one real directory component relative to an anchored parent."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    operation_error: BaseException | None = None
    try:
        try:
            before = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect Claude {label}",
                error,
            ) from None
        if not stat.S_ISDIR(before.st_mode):
            raise ClaudeRefreshLockUnsafe(
                f"Claude {label} path contains a non-directory component"
            )
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            current = os.fstat(descriptor)
            after = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect Claude {label}",
                error,
            ) from None
        identity = _directory_identity(current)
        if not (
            _matches_directory_identity(before, identity)
            and _matches_directory_identity(after, identity)
        ):
            raise ClaudeRefreshLockUnsafe(f"Claude {label} changed during inspection")
        return descriptor, identity
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
                    message="cannot close Claude directory component anchor",
                )


def _open_absolute_directory_anchor_chain(
    path: pathlib.Path,
    *,
    require_private: bool,
    label: str,
) -> _DirectoryAnchor:
    """Anchor an absolute directory without following any path component."""

    if not path.is_absolute() or path.anchor != os.sep:
        raise ClaudeRefreshLockUnsafe(f"Claude {label} path must be absolute")
    components = path.parts[1:]
    if not components or any(
        component in ("", os.curdir, os.pardir) for component in components
    ):
        raise ClaudeRefreshLockUnsafe(
            f"Claude {label} path contains an unsafe component"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    operation_error: BaseException | None = None
    try:
        try:
            descriptor = os.open(os.sep, flags)
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot inspect Claude {label} path root",
                error,
            ) from None
        identity: _DirectoryIdentity | None = None
        for component in components:
            child_descriptor, identity = _open_directory_component_at(
                parent_descriptor=descriptor,
                name=component,
                label=label,
            )
            parent_descriptor = descriptor
            descriptor = child_descriptor
            try:
                os.close(parent_descriptor)
            except BaseException as cleanup_error:
                close_unknown = _new_descriptor_bound_cleanup_inconclusive(
                    "cannot confirm closure of a Claude directory-chain "
                    "descriptor; no authoritative pathname is available. "
                    "Pause before controlled recovery."
                )
                _attach_cleanup_or_raise(
                    close_unknown,
                    cleanup_error,
                    message="cannot close Claude directory-chain descriptor",
                )
                raise close_unknown
        assert identity is not None
        try:
            descriptor_metadata = os.fstat(descriptor)
            path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot recheck Claude {label}",
                error,
            ) from None
        if not (
            _matches_directory_identity(descriptor_metadata, identity)
            and _matches_directory_identity(path_metadata, identity)
        ):
            raise ClaudeRefreshLockUnsafe(f"Claude {label} changed during inspection")
        if require_private and (identity.uid != os.getuid() or identity.mode & 0o022):
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
                    message="cannot close Claude directory-chain anchor",
                )


def _open_child_directory_anchor(
    path: pathlib.Path,
    *,
    name: str,
    parent: _DirectoryAnchor,
    require_private: bool,
    label: str,
) -> _DirectoryAnchor:
    """Anchor one child beneath an already anchored private directory."""

    descriptor: int | None = None
    operation_error: BaseException | None = None
    try:
        _assert_anchor(parent, label=f"{label} parent")
        descriptor, identity = _open_directory_component_at(
            parent_descriptor=parent.descriptor,
            name=name,
            label=label,
        )
        _assert_anchor(parent, label=f"{label} parent")
        try:
            path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise _safe_filesystem_error(
                f"cannot recheck Claude {label}",
                error,
            ) from None
        if not _matches_directory_identity(path_metadata, identity):
            raise ClaudeRefreshLockUnsafe(f"Claude {label} changed during inspection")
        if require_private and (identity.uid != os.getuid() or identity.mode & 0o022):
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
                    message="cannot close Claude child-directory anchor",
                )


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
        if require_private and (identity.uid != os.getuid() or identity.mode & 0o022):
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
    lease: ClaudeRefreshLockLease,
    pending: _PendingLockAcquisition,
) -> _HeldLock:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    identity: ClaudeRefreshLockIdentity | None = None
    lock: _HeldLock | None = None
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
        lock = _HeldLock(
            label=label,
            path=path,
            name=name,
            parent=parent,
            descriptor=descriptor,
            identity=identity,
        )
        lease._adopt_acquired_lock(lock, pending)
        return lock
    except BaseException as primary_error:
        if lock is not None and lease._owns_acquired_lock(lock):
            raise
        removed = False
        if identity is not None:
            try:
                current = os.stat(
                    name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
                descriptor_metadata = os.fstat(descriptor)
                if _matches_lock_identity(current, identity) and _matches_lock_identity(
                    descriptor_metadata, identity
                ):
                    os.rmdir(name, dir_fd=parent.descriptor)
                    removed = True
            except BaseException as cleanup_error:
                _attach_cleanup_or_raise(
                    primary_error,
                    cleanup_error,
                    message="cannot remove unproven Claude refresh lock",
                )
        descriptor_closed = False
        try:
            os.close(descriptor)
            descriptor_closed = True
        except BaseException as cleanup_error:
            _attach_cleanup_or_raise(
                primary_error,
                cleanup_error,
                message="cannot close Claude refresh-lock descriptor",
            )
        if removed and descriptor_closed:
            try:
                lease._clear_pending_acquisition(pending)
            except BaseException as cleanup_error:
                _attach_cleanup_or_raise(
                    primary_error,
                    cleanup_error,
                    message="cannot clear cleaned Claude refresh-lock acquisition",
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
        stale_before_ns = time.time_ns() - int(protocol.stale_seconds * 1_000_000_000)
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
        raise ClaudeRefreshLockUnsafe("staged Claude recovery paths must be absolute")
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
    signal_mask_owner = ForwardedSignalMaskOwner()
    try:
        block_forwarded_signals(signal_mask_owner=signal_mask_owner)
        if not signal_mask_owner.active:
            raise ClaudeRefreshLockCleanupInconclusive(
                "cannot establish a caller-owned forwarded-signal mask before "
                "staged Claude refresh-lock recovery"
            )
        carrier_anchor = _open_absolute_directory_anchor_chain(
            carrier_path,
            require_private=True,
            label="staged credential carrier",
        )
        if carrier_anchor.identity.mode != 0o700:
            raise ClaudeRefreshLockUnsafe(
                "staged Claude credential carrier must have mode 0700"
            )
        config_anchor = _open_child_directory_anchor(
            config_path,
            name=config_path.name,
            parent=carrier_anchor,
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
        try:
            pending_signal = (
                consume_pending_forwarded_signal() if signal_mask_owner.active else None
            )
        except BaseException as error:
            cleanup_errors.append(error)
            pending_signal = None
        if pending_signal is not None:
            # Publish the first observed deferred signal before unmasking, so a
            # signal delivered by restore remains a secondary control flow.
            cleanup_errors.append(ForwardedSignal(pending_signal))
        for _attempt in range(2):
            if not signal_mask_owner.active:
                break
            try:
                signal_mask_owner.restore()
            except BaseException as error:
                cleanup_errors.append(error)
        mask_restore_inconclusive: ClaudeRefreshLockCleanupInconclusive | None = None
        if signal_mask_owner.active:
            mask_restore_inconclusive = ClaudeRefreshLockCleanupInconclusive(
                "the forwarded-signal mask remains active after two restore "
                "attempts following staged Claude refresh-lock recovery"
            )
        candidates = [
            error
            for error in (
                mask_restore_inconclusive,
                operation_error,
                *cleanup_errors,
            )
            if error is not None
        ]
        selected = _primary_error(candidates)
        mask_restore_cause_attached = False
        if (
            mask_restore_inconclusive is not None
            and selected is not None
            and selected is not mask_restore_inconclusive
        ):
            add_note = getattr(selected, "add_note", None)
            if callable(add_note):
                add_note(str(mask_restore_inconclusive))
            else:
                if selected.__cause__ is not None:
                    mask_restore_inconclusive.__cause__ = selected.__cause__
                elif (
                    not selected.__suppress_context__
                    and selected.__context__ is not None
                ):
                    mask_restore_inconclusive.__context__ = selected.__context__
                selected.__cause__ = mask_restore_inconclusive
                mask_restore_cause_attached = True
        if selected is not None and selected is not operation_error:
            normalized = _normalize_operation_error(
                "cannot finalize staged Claude refresh-lock recovery",
                selected,
            )
            if mask_restore_cause_attached:
                assert mask_restore_inconclusive is not None
                raise normalized from mask_restore_inconclusive
            raise normalized from None


def _acquire_one(
    *,
    label: str,
    path: pathlib.Path,
    name: str,
    parent: _DirectoryAnchor,
    protocol: ClaudeRefreshLockProtocol,
    deadline: float,
    retry_interval_seconds: float,
    lease: ClaudeRefreshLockLease,
) -> _HeldLock:
    while True:
        _assert_anchor(parent, label=f"{label} lock parent")
        pending = lease._begin_pending_acquisition(
            label=label,
            path=path,
            name=name,
            parent=parent,
        )
        try:
            # mkdir is the directory-lock protocol's atomic O_EXCL equivalent.
            os.mkdir(name, 0o700, dir_fd=parent.descriptor)
        except FileExistsError:
            lease._clear_pending_acquisition(pending)
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
            lease=lease,
            pending=pending,
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
        cleanup_inconclusive_fallback: ClaudeRefreshLockCleanupInconclusive,
        descriptor_bound_cleanup_fallback: ClaudeRefreshLockCleanupInconclusive,
        owner: ClaudeRefreshLockOwner | None = None,
        require_explicit_context_release: bool = False,
    ) -> None:
        self._protocol = protocol
        self._config_anchor = config_anchor
        self._legacy_parent_anchor = legacy_parent_anchor
        self._locks = locks
        self._release_started = False
        self._cleanup_started = False
        self._released = False
        self._abandoned = False
        self._deletion_prohibited = False
        self._abandonment_cleanup_completed = False
        self._abandonment_cleanup_lifecycle = _AbandonmentCleanupLifecycle.NOT_STARTED
        self._abandonment_descriptors_pending: list[int] | None = None
        self._abandonment_descriptors_unconfirmed: set[int] = set()
        self._abandonment_descriptors_residue: set[int] = set()
        self._abandonment_diagnostic_reason: str | None = None
        self._require_explicit_context_release = require_explicit_context_release
        self._cleanup_inconclusive_fallback = cleanup_inconclusive_fallback
        self._descriptor_bound_cleanup_fallback = descriptor_bound_cleanup_fallback
        # Published recovery evidence. Same-runtime consumers may read this
        # slot directly, but only the lease lifecycle may replace it.
        self._retention_recovery_evidence: (
            ClaudeRefreshLockCleanupInconclusive | None
        ) = descriptor_bound_cleanup_fallback
        self._cleanup_inconclusive: ClaudeRefreshLockCleanupInconclusive | None = None
        self._release_lock = threading.Lock()
        self._state_lock = threading.RLock()
        # RLock ownership lets an interrupted acquire handoff distinguish a
        # caller-owned guard from one still held by another thread. The handoff
        # rejects same-thread reentry so public semantics remain non-reentrant.
        self._operation_lock = threading.RLock()
        self._pending_operation_handoff: _OperationLockHandoff | None = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_error: BaseException | None = None
        self._pending_acquisition: _PendingLockAcquisition | None = None
        if owner is not None:
            owner._publish(self)

    @property
    def paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(lock.path for lock in self._locks)

    @property
    def identities(self) -> tuple[ClaudeRefreshLockIdentity, ...]:
        return tuple(lock.identity for lock in self._locks)

    @property
    def released(self) -> bool:
        """Return whether owned filesystem artifacts and descriptors closed.

        A pending operation-lock handoff is independent of this physical
        cleanup state. Consumers that require lifecycle terminality must use
        :meth:`retention_snapshot`.
        """

        with self._state_lock:
            return self._released

    def retention_snapshot(self) -> ClaudeRefreshLockRetentionSnapshot:
        """Return lifecycle state without probing or mutating descriptors."""

        with self._state_lock:
            released = self._released
            lifecycle = self._abandonment_cleanup_lifecycle
            settled = lifecycle is _AbandonmentCleanupLifecycle.SETTLED
            handoff_terminal = self._pending_operation_handoff is None
            diagnostic = self._retention_recovery_evidence
            return ClaudeRefreshLockRetentionSnapshot(
                terminal=(released or settled) and handoff_terminal,
                verified_closed=(
                    handoff_terminal
                    and (
                        released
                        or (
                            settled
                            and self._abandonment_cleanup_completed
                            and self._pending_acquisition is None
                        )
                    )
                ),
                diagnostic=diagnostic,
            )

    def _settle_descriptor_bound_retention(
        self,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        """Publish terminal retained residue without closing live descriptors."""

        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("descriptor-bound retention reason must not be empty")
        with self._state_lock:
            if self._released:
                raise ClaudeRefreshLockCompromised(
                    "cannot retain residue for a released Claude refresh-lock lease"
                )
            operation_handoff = self._pending_operation_handoff
            if operation_handoff is not None:
                if not operation_handoff.resolved:
                    raise ClaudeRefreshLockCompromised(
                        "cannot settle descriptor-bound retention with an "
                        "unresolved operation handoff"
                    )
                self._pending_operation_handoff = None
            self._deletion_prohibited = True
            self._abandoned = True
            self._release_started = True
            self._cleanup_started = True
            self._heartbeat_stop.set()
            self._abandonment_diagnostic_reason = normalized_reason
            self._cleanup_inconclusive = self._descriptor_bound_cleanup_fallback
            descriptors = {
                *(lock.descriptor for lock in self._locks),
                self._legacy_parent_anchor.descriptor,
                self._config_anchor.descriptor,
                *(self._abandonment_descriptors_pending or ()),
                *self._abandonment_descriptors_unconfirmed,
            }
            self._abandonment_descriptors_residue.update(descriptors)
            self._abandonment_descriptors_pending = []
            self._abandonment_descriptors_unconfirmed.clear()
            self._abandonment_cleanup_completed = False
            self._retention_recovery_evidence = self._descriptor_bound_cleanup_fallback
            self._abandonment_cleanup_lifecycle = _AbandonmentCleanupLifecycle.SETTLED
            return self._descriptor_bound_cleanup_fallback

    def _begin_pending_acquisition(
        self,
        *,
        label: str,
        path: pathlib.Path,
        name: str,
        parent: _DirectoryAnchor,
    ) -> _PendingLockAcquisition:
        pending = _PendingLockAcquisition(
            label=label,
            path=path,
            name=name,
            parent=parent,
        )
        with self._state_lock:
            if (
                self._pending_acquisition is not None
                or self._release_started
                or self._cleanup_started
                or self._released
                or self._heartbeat_thread is not None
            ):
                raise ClaudeRefreshLockCompromised(
                    "cannot start a Claude refresh-lock acquisition after lease "
                    "startup or cleanup"
                )
            self._pending_acquisition = pending
        return pending

    def _clear_pending_acquisition(
        self,
        pending: _PendingLockAcquisition,
    ) -> None:
        with self._state_lock:
            if self._pending_acquisition is not pending:
                raise ClaudeRefreshLockCompromised(
                    "Claude refresh-lock pending acquisition ownership changed"
                )
            self._pending_acquisition = None

    def _has_pending_acquisition(self) -> bool:
        with self._state_lock:
            return self._pending_acquisition is not None

    def _adopt_acquired_lock(
        self,
        lock: _HeldLock,
        pending: _PendingLockAcquisition,
    ) -> None:
        """Publish a newly held lock before it can cross a return boundary."""

        with self._state_lock:
            if (
                self._pending_acquisition is not pending
                or pending.label != lock.label
                or pending.path != lock.path
                or pending.name != lock.name
                or pending.parent is not lock.parent
                or self._release_started
                or self._cleanup_started
                or self._released
                or self._heartbeat_thread is not None
            ):
                raise ClaudeRefreshLockCompromised(
                    "cannot add a Claude refresh lock after lease startup or cleanup"
                )
            if len(self._locks) >= 2 or any(
                existing is lock for existing in self._locks
            ):
                raise ClaudeRefreshLockCompromised(
                    "Claude refresh-lock lease received an invalid acquired lock"
                )
            self._locks = (*self._locks, lock)
            self._pending_acquisition = None

    def _owns_acquired_lock(self, lock: _HeldLock) -> bool:
        with self._state_lock:
            return any(existing is lock for existing in self._locks)

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

    def _publish_operation_handoff(
        self,
        handoff: _OperationLockHandoff,
    ) -> None:
        """Publish an operation-lock handoff before ownership can change."""

        with self._state_lock:
            pending = self._pending_operation_handoff
            if pending is not None and not pending.resolved:
                raise ClaudeRefreshLockCompromised(
                    "cannot replace an unresolved Claude refresh-lock operation handoff"
                )
            self._pending_operation_handoff = handoff

    def _reconcile_pending_operation_handoff(self) -> None:
        """Resolve a published operation-lock handoff on its owner thread."""

        # Lifecycle callers already serialize publication with _release_lock.
        # Avoid an observable state-lock acquisition when there is no handoff.
        handoff = self._pending_operation_handoff
        if handoff is None:
            return
        with self._state_lock:
            handoff = self._pending_operation_handoff
        if handoff is None:
            return
        if handoff.resolved:
            with self._state_lock:
                if self._pending_operation_handoff is handoff:
                    self._pending_operation_handoff = None
            return
        if threading.current_thread() is not handoff.owner_thread:
            raise ClaudeRefreshLockCompromised(
                "unresolved Claude refresh-lock operation handoff must be "
                "reconciled by its original thread"
            )
        try:
            handoff.release()
        finally:
            if handoff.resolved:
                with self._state_lock:
                    if self._pending_operation_handoff is handoff:
                        self._pending_operation_handoff = None

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self._protocol.update_seconds):
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
            if len(self._locks) != 2:
                raise ClaudeRefreshLockCompromised(
                    "cannot start Claude refresh-lock heartbeat before both locks "
                    "are acquired"
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

    def commit_context_release(self) -> None:
        """Keep explicit leases retain-only; safe release requires its closure."""

        with self._state_lock:
            if (
                self._abandoned
                or self._deletion_prohibited
                or self._release_started
                or self._cleanup_started
                or self._released
            ):
                raise ClaudeRefreshLockCompromised(
                    "cannot commit context release after Claude refresh-lock "
                    "abandonment or cleanup started"
                )
            if self._require_explicit_context_release:
                raise ClaudeRefreshLockCompromised(
                    "explicit Claude refresh-lock release requires the synchronous "
                    "safe-release capability"
                )
            return

    def abandon(
        self,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        """Retain the lock directories after bounded owner shutdown."""

        if not isinstance(reason, str):
            raise TypeError("Claude refresh-lock abandonment reason must be a string")
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("Claude refresh-lock abandonment reason must not be empty")
        diagnostic = self._abandon(
            normalized_reason,
            only_if_context_release_uncommitted=False,
        )
        assert diagnostic is not None
        return diagnostic

    def _abandon(
        self,
        normalized_reason: str,
        *,
        only_if_context_release_uncommitted: bool,
    ) -> ClaudeRefreshLockCleanupInconclusive | None:
        first_control_flow = _FirstControlFlowWinner(
            self._descriptor_bound_cleanup_fallback
        )
        publication_errors = _ControlFlowErrorLog(first_control_flow)
        errors = publication_errors
        operation_handoff: _OperationLockHandoff | None = None
        boundary_error: BaseException | None = None
        try:
            try:
                with self._release_lock:
                    self._reconcile_pending_operation_handoff()
                    with self._state_lock:
                        if (
                            only_if_context_release_uncommitted
                            and not self._require_explicit_context_release
                        ):
                            return None
                        if self._released:
                            raise ClaudeRefreshLockCompromised(
                                "cannot abandon a released Claude refresh-lock lease"
                            )
                        lifecycle = self._abandonment_cleanup_lifecycle
                        resuming_abandonment = (
                            lifecycle is _AbandonmentCleanupLifecycle.RESUMABLE
                        )
                        if lifecycle is _AbandonmentCleanupLifecycle.NOT_STARTED:
                            if self._cleanup_started:
                                diagnostic = self._cleanup_inconclusive
                                if diagnostic is not None:
                                    return diagnostic
                                raise ClaudeRefreshLockCompromised(
                                    "cannot start abandonment after destructive Claude "
                                    "refresh-lock cleanup"
                                )
                            # Publish the irreversible retention latch before exposing
                            # RESUMABLE. A release caller may already have passed its
                            # pre-lock lifecycle check and be waiting on _release_lock.
                            self._deletion_prohibited = True
                            self._abandonment_cleanup_lifecycle = (
                                _AbandonmentCleanupLifecycle.RESUMABLE
                            )
                        elif lifecycle is _AbandonmentCleanupLifecycle.SETTLED:
                            diagnostic = self._cleanup_inconclusive
                            if diagnostic is None:
                                diagnostic = self._cleanup_inconclusive_fallback
                                self._cleanup_inconclusive = diagnostic
                            diagnostic = self._demote_cleanup_inconclusive_paths(
                                diagnostic,
                                reason=(
                                    self._abandonment_diagnostic_reason
                                    or "Claude refresh-lock lease was intentionally "
                                    "abandoned"
                                ),
                            )
                            self._retention_recovery_evidence = (
                                self._descriptor_bound_cleanup_fallback
                            )
                            return diagnostic
                        # This irreversible latch is the abandonment decision. Publish it
                        # directly before any replaceable or otherwise interruptible
                        # diagnostic/state helper can run.
                        self._deletion_prohibited = True
                        self._heartbeat_stop.set()
                        diagnostic = self._cleanup_inconclusive
                        diagnostic_was_cached = diagnostic is not None
                        if diagnostic is None:
                            diagnostic = self._cleanup_inconclusive_fallback
                            try:
                                self._publish_abandonment_state()
                            except BaseException as error:
                                publication_errors.append(error)
                                try:
                                    self._reassert_abandonment_state()
                                except BaseException as reassert_error:
                                    publication_errors.append(reassert_error)
                        else:
                            self._abandoned = True
                            self._release_started = True
                            self._cleanup_started = True
                        if publication_errors:
                            try:
                                # Decision safety no longer depends on this best-effort
                                # wakeup, but bounded cleanup should still stop a sleeping
                                # heartbeat when both state publishers were interrupted.
                                self._heartbeat_stop.set()
                            except BaseException as error:
                                publication_errors.append(error)
                        thread = self._heartbeat_thread
                        heartbeat_error = self._heartbeat_error

                    with self._state_lock:
                        if self._abandonment_diagnostic_reason is None:
                            self._abandonment_diagnostic_reason = (
                                "Claude refresh-lock lease was intentionally abandoned: "
                                f"{normalized_reason}"
                            )
                        diagnostic_reason = self._abandonment_diagnostic_reason
                    if not diagnostic_was_cached:
                        try:
                            self._customize_cleanup_inconclusive(
                                diagnostic,
                                diagnostic_reason,
                            )
                        except BaseException as error:
                            publication_errors.append(error)
                    elif not diagnostic_reason:
                        diagnostic_reason = (
                            "Claude refresh-lock lease was intentionally abandoned: "
                            f"{normalized_reason}"
                        )

                    if resuming_abandonment or diagnostic_was_cached:
                        demotion_completed = False
                        for _attempt in range(2):
                            try:
                                diagnostic = self._demote_cleanup_inconclusive_paths(
                                    diagnostic,
                                    reason=diagnostic_reason,
                                )
                            except BaseException as error:
                                publication_errors.append(
                                    _normalize_operation_error(
                                        "cannot demote stale Claude refresh-lock "
                                        "recovery paths",
                                        error,
                                    )
                                )
                            else:
                                demotion_completed = True
                                break
                        if not demotion_completed:
                            frozen_control_flow = next(
                                (
                                    error
                                    for error in publication_errors
                                    if _is_control_flow_error(error)
                                ),
                                None,
                            )
                            if frozen_control_flow is not None:
                                try:
                                    _raise_frozen_control_flow_with_cleanup(
                                        frozen_control_flow,
                                        self._descriptor_bound_cleanup_fallback,
                                    )
                                finally:
                                    raise frozen_control_flow
                            try:
                                primary = _primary_error(publication_errors)
                            except BaseException as selection_error:
                                if _is_control_flow_error(selection_error):
                                    try:
                                        _raise_frozen_control_flow_with_cleanup(
                                            selection_error,
                                            self._descriptor_bound_cleanup_fallback,
                                        )
                                    finally:
                                        raise selection_error
                                raise
                            assert primary is not None
                            try:
                                _attach_secondary_cleanup(
                                    primary,
                                    self._descriptor_bound_cleanup_fallback,
                                )
                            except BaseException as attachment_error:
                                if _is_control_flow_error(attachment_error):
                                    try:
                                        _raise_frozen_control_flow_with_cleanup(
                                            attachment_error,
                                            self._descriptor_bound_cleanup_fallback,
                                        )
                                    finally:
                                        raise attachment_error
                                raise
                            raise primary

                    errors = _ControlFlowErrorLog(
                        first_control_flow,
                        publication_errors,
                    )
                    if heartbeat_error is not None:
                        errors.append(heartbeat_error)
                    heartbeat_alive = False
                    if thread is not None:
                        try:
                            thread.join(timeout=self._shutdown_timeout_seconds())
                        except BaseException as error:
                            errors.append(
                                _normalize_operation_error(
                                    "cannot stop Claude refresh-lock heartbeat during "
                                    "abandonment",
                                    error,
                                )
                            )
                        try:
                            heartbeat_alive = thread.is_alive()
                        except BaseException as error:
                            heartbeat_alive = True
                            errors.append(
                                _normalize_operation_error(
                                    "cannot verify Claude refresh-lock heartbeat shutdown",
                                    error,
                                )
                            )
                        with self._state_lock:
                            final_heartbeat_error = self._heartbeat_error
                        if final_heartbeat_error is not None and all(
                            error is not final_heartbeat_error for error in errors
                        ):
                            errors.append(final_heartbeat_error)
                    if heartbeat_alive:
                        errors.append(
                            ClaudeRefreshLockError(
                                "Claude refresh-lock heartbeat did not stop during abandonment"
                            )
                        )
                        self._finish_abandonment(diagnostic, errors)
                        return diagnostic

                    operation_handoff = _OperationLockHandoff(self._operation_lock)
                    self._publish_operation_handoff(operation_handoff)
                    try:
                        operation_handoff.acquire(
                            timeout=self._shutdown_timeout_seconds(),
                            first_control_flow=first_control_flow,
                        )
                    except BaseException as error:
                        errors.append(
                            _normalize_operation_error(
                                "cannot quiesce Claude refresh-lock operations during "
                                "abandonment",
                                error,
                            )
                        )
                    if not operation_handoff.acquired:
                        errors.append(
                            ClaudeRefreshLockError(
                                "Claude refresh-lock operations did not quiesce during "
                                "abandonment"
                            )
                        )
                        self._finish_abandonment(diagnostic, errors)
                        return diagnostic

                    try:
                        try:
                            with self._state_lock:
                                if self._abandonment_descriptors_pending is None:
                                    self._abandonment_descriptors_pending = list(
                                        dict.fromkeys(
                                            (
                                                *(
                                                    lock.descriptor
                                                    for lock in self._locks
                                                ),
                                                self._legacy_parent_anchor.descriptor,
                                                self._config_anchor.descriptor,
                                            )
                                        )
                                    )
                                unconfirmed = tuple(
                                    self._abandonment_descriptors_unconfirmed
                                )
                            for descriptor in unconfirmed:
                                with self._state_lock:
                                    pending_descriptors = (
                                        self._abandonment_descriptors_pending
                                    )
                                    assert pending_descriptors is not None
                                    if (
                                        descriptor
                                        in self._abandonment_descriptors_residue
                                    ):
                                        if descriptor in pending_descriptors:
                                            pending_descriptors.remove(descriptor)
                                        self._abandonment_descriptors_unconfirmed.discard(
                                            descriptor
                                        )
                                        continue
                                    if descriptor in pending_descriptors:
                                        pending_descriptors.remove(descriptor)
                                try:
                                    os.fstat(descriptor)
                                except OSError as error:
                                    if error.errno == errno.EBADF:
                                        with self._state_lock:
                                            self._abandonment_descriptors_unconfirmed.discard(
                                                descriptor
                                            )
                                    else:
                                        with self._state_lock:
                                            self._abandonment_descriptors_residue.add(
                                                descriptor
                                            )
                                            self._abandonment_descriptors_unconfirmed.discard(
                                                descriptor
                                            )
                                        errors.append(
                                            _safe_filesystem_error(
                                                "cannot confirm abandoned Claude "
                                                "refresh-lock descriptor cleanup",
                                                error,
                                            )
                                        )
                                except BaseException as error:
                                    with self._state_lock:
                                        self._abandonment_descriptors_residue.add(
                                            descriptor
                                        )
                                        self._abandonment_descriptors_unconfirmed.discard(
                                            descriptor
                                        )
                                    errors.append(
                                        _normalize_operation_error(
                                            "cannot confirm abandoned Claude "
                                            "refresh-lock descriptor cleanup",
                                            error,
                                        )
                                    )
                                else:
                                    with self._state_lock:
                                        self._abandonment_descriptors_residue.add(
                                            descriptor
                                        )
                                        self._abandonment_descriptors_unconfirmed.discard(
                                            descriptor
                                        )
                                    errors.append(
                                        ClaudeRefreshLockError(
                                            "abandoned Claude refresh-lock descriptor "
                                            "close completion is unconfirmed"
                                        )
                                    )
                            while True:
                                with self._state_lock:
                                    pending_descriptors = (
                                        self._abandonment_descriptors_pending
                                    )
                                    assert pending_descriptors is not None
                                    if not pending_descriptors:
                                        break
                                    descriptor = pending_descriptors[0]
                                    self._abandonment_descriptors_unconfirmed.add(
                                        descriptor
                                    )
                                    pending_descriptors.pop(0)
                                try:
                                    os.close(descriptor)
                                except BaseException as error:
                                    errors.append(
                                        _normalize_operation_error(
                                            "cannot close abandoned Claude refresh-lock "
                                            "descriptor",
                                            error,
                                        )
                                    )
                                else:
                                    with self._state_lock:
                                        self._abandonment_descriptors_unconfirmed.discard(
                                            descriptor
                                        )
                            with self._state_lock:
                                if (
                                    not self._abandonment_descriptors_pending
                                    and not self._abandonment_descriptors_unconfirmed
                                ):
                                    self._abandonment_cleanup_completed = (
                                        not self._abandonment_descriptors_residue
                                    )
                                    self._abandonment_cleanup_lifecycle = (
                                        _AbandonmentCleanupLifecycle.SETTLED
                                    )
                                    self._retention_recovery_evidence = (
                                        self._descriptor_bound_cleanup_fallback
                                    )
                        except BaseException as body_error:
                            # Observe the descriptor/state-lock escape before the
                            # operation-guard release can produce a later error.
                            first_control_flow.observe(body_error)
                            raise
                    finally:
                        try:
                            self._reconcile_pending_operation_handoff()
                        except BaseException as error:
                            errors.append(
                                _normalize_operation_error(
                                    "cannot release the abandoned Claude refresh-lock "
                                    "operation guard",
                                    error,
                                )
                            )

                    self._finish_abandonment(diagnostic, errors)
                    return diagnostic

            except BaseException as error:
                boundary_error = error
                list.append(errors, error)
                first_control_flow.observe(error)
                raise
        finally:
            try:
                self._reconcile_pending_operation_handoff()
            except BaseException as error:
                errors.append(
                    _normalize_operation_error(
                        "cannot release the abandoned Claude refresh-lock "
                        "operation guard",
                        error,
                    )
                )
            selector_error: BaseException | None = None
            try:
                first_control_flow.observe_all(errors)
                first_control_flow.raise_if_set()
            except BaseException as error:
                selector_error = error
                raise
            finally:
                first_control_flow.enforce(
                    errors,
                    selector_error if selector_error is not None else boundary_error,
                )

    def _publish_abandonment_state(self) -> None:
        self._deletion_prohibited = True
        self._abandonment_cleanup_lifecycle = _AbandonmentCleanupLifecycle.RESUMABLE
        self._cleanup_inconclusive = self._cleanup_inconclusive_fallback
        self._abandoned = True
        self._release_started = True
        self._cleanup_started = True
        self._heartbeat_stop.set()

    def _reassert_abandonment_state(self) -> None:
        self._deletion_prohibited = True
        self._abandonment_cleanup_lifecycle = _AbandonmentCleanupLifecycle.RESUMABLE
        self._cleanup_inconclusive = self._cleanup_inconclusive_fallback
        self._abandoned = True
        self._release_started = True
        self._cleanup_started = True
        self._heartbeat_stop.set()

    def _finish_abandonment(
        self,
        diagnostic: ClaudeRefreshLockCleanupInconclusive,
        errors: list[BaseException],
    ) -> None:
        first_control_flow = getattr(errors, "first_control_flow", None)
        if not isinstance(first_control_flow, _FirstControlFlowWinner):
            first_control_flow = _FirstControlFlowWinner(
                self._descriptor_bound_cleanup_fallback
            )
        boundary_error: BaseException | None = None
        try:
            try:
                first_control_flow.observe_all(errors)
                if not errors:
                    return
                try:
                    with self._state_lock:
                        if (
                            self._abandonment_cleanup_lifecycle
                            is _AbandonmentCleanupLifecycle.SETTLED
                        ):
                            recovery_evidence = diagnostic
                        else:
                            recovery_evidence = self._descriptor_bound_cleanup_fallback
                except BaseException as boundary_error:
                    if _is_control_flow_error(boundary_error):
                        try:
                            _raise_frozen_control_flow_with_cleanup(
                                boundary_error,
                                self._descriptor_bound_cleanup_fallback,
                            )
                        finally:
                            raise boundary_error
                    try:
                        winner = _primary_error([*errors, boundary_error])
                    except BaseException as selection_error:
                        if _is_control_flow_error(selection_error):
                            try:
                                _raise_frozen_control_flow_with_cleanup(
                                    selection_error,
                                    self._descriptor_bound_cleanup_fallback,
                                )
                            finally:
                                raise selection_error
                        raise
                    assert winner is not None
                    try:
                        _attach_secondary_cleanup(
                            winner,
                            self._descriptor_bound_cleanup_fallback,
                        )
                    except BaseException as attachment_error:
                        if _is_control_flow_error(attachment_error):
                            try:
                                _raise_frozen_control_flow_with_cleanup(
                                    attachment_error,
                                    self._descriptor_bound_cleanup_fallback,
                                )
                            finally:
                                raise attachment_error
                        raise
                    raise winner
                primary = _primary_error(errors)
                assert primary is not None
                if recovery_evidence is not diagnostic:
                    _attach_secondary_cleanup(primary, recovery_evidence)
                    with self._state_lock:
                        diagnostic_reason = (
                            self._abandonment_diagnostic_reason
                            or "Claude refresh-lock lease was intentionally abandoned"
                        )
                    try:
                        self._demote_cleanup_inconclusive_paths(
                            diagnostic,
                            reason=diagnostic_reason,
                        )
                    except BaseException as demotion_error:
                        normalized_demotion_error = _normalize_operation_error(
                            "cannot demote non-terminal Claude refresh-lock "
                            "recovery paths",
                            demotion_error,
                        )
                        if _is_control_flow_error(normalized_demotion_error):
                            try:
                                _raise_frozen_control_flow_with_cleanup(
                                    normalized_demotion_error,
                                    self._descriptor_bound_cleanup_fallback,
                                )
                            finally:
                                raise normalized_demotion_error
                        try:
                            selected_error = _primary_error(
                                [primary, normalized_demotion_error]
                            )
                        except BaseException as selection_error:
                            if _is_control_flow_error(selection_error):
                                try:
                                    _raise_frozen_control_flow_with_cleanup(
                                        selection_error,
                                        self._descriptor_bound_cleanup_fallback,
                                    )
                                finally:
                                    raise selection_error
                            raise
                        assert selected_error is not None
                        try:
                            _attach_secondary_cleanup(
                                selected_error,
                                self._descriptor_bound_cleanup_fallback,
                            )
                        except BaseException as attachment_error:
                            if _is_control_flow_error(attachment_error):
                                try:
                                    _raise_frozen_control_flow_with_cleanup(
                                        attachment_error,
                                        self._descriptor_bound_cleanup_fallback,
                                    )
                                finally:
                                    raise attachment_error
                            raise
                        raise selected_error
                if diagnostic.__cause__ is None:
                    diagnostic.__cause__ = primary
                _attach_secondary_cleanup(diagnostic, primary)

            except BaseException as error:
                boundary_error = error
                list.append(errors, error)
                first_control_flow.observe(error)
                raise
        finally:
            selector_error: BaseException | None = None
            try:
                first_control_flow.observe_all(errors)
                first_control_flow.raise_if_set()
            except BaseException as error:
                selector_error = error
                raise
            finally:
                first_control_flow.enforce(
                    errors,
                    selector_error if selector_error is not None else boundary_error,
                )

    def release(self) -> None:
        """Release a lease, retaining armed leases until context release commits."""

        self._abandon_if_context_release_uncommitted(
            "direct release was requested before explicit context release was committed"
        )
        if self._prepare_abandonment_resume():
            diagnostic = self._abandon(
                "public release resumed an interrupted abandonment",
                only_if_context_release_uncommitted=False,
            )
            assert diagnostic is not None
            raise diagnostic

        self._release(skip_abandoned=False)

    def _prepare_abandonment_resume(self) -> bool:
        """Adopt a caller-prearmed retention decision into lease lifecycle."""

        with self._state_lock:
            lifecycle = self._abandonment_cleanup_lifecycle
            if (
                lifecycle is _AbandonmentCleanupLifecycle.NOT_STARTED
                and self._deletion_prohibited
                and not self._cleanup_started
                and not self._released
            ):
                lifecycle = _AbandonmentCleanupLifecycle.RESUMABLE
                self._abandonment_cleanup_lifecycle = lifecycle
            return (
                lifecycle is _AbandonmentCleanupLifecycle.RESUMABLE
                and not self._released
            )

    def _release_on_context_exit(self) -> None:
        self._abandon_if_context_release_uncommitted(
            "context exited before explicit context release was committed"
        )
        self._release(skip_abandoned=True)

    def _abandon_if_context_release_uncommitted(self, reason: str) -> None:
        diagnostic = self._abandon(
            reason,
            only_if_context_release_uncommitted=True,
        )
        if diagnostic is None:
            return
        raise diagnostic

    def _release(self, *, skip_abandoned: bool) -> None:
        if self._prepare_abandonment_resume():
            diagnostic = self._abandon(
                "cleanup entry resumed an interrupted abandonment",
                only_if_context_release_uncommitted=False,
            )
            assert diagnostic is not None
            if skip_abandoned:
                return
            raise diagnostic
        with self._release_lock:
            with self._state_lock:
                if skip_abandoned and self._abandoned:
                    return
                cleanup_inconclusive = self._cleanup_inconclusive
                if self._deletion_prohibited and cleanup_inconclusive is None:
                    cleanup_inconclusive = self._cleanup_inconclusive_fallback
                    self._cleanup_inconclusive = cleanup_inconclusive
            if cleanup_inconclusive is not None:
                raise cleanup_inconclusive
            try:
                self._release_once()
            except BaseException as first_error:
                with self._state_lock:
                    cleanup_inconclusive = self._cleanup_inconclusive
                    retry_needed = self._pending_operation_handoff is not None or (
                        not self._released
                        and not self._cleanup_started
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
                        if _is_control_flow_error(first_error) or isinstance(
                            first_error, ReviewError
                        ):
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
                        cleanup_incomplete = cleanup_inconclusive is not None or (
                            not self._released and not self._cleanup_started
                        )
                    if cleanup_incomplete:
                        terminal_was_published = cleanup_inconclusive is not None
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

    def _prove_authoritative_recovery_paths(self) -> tuple[str, ...] | None:
        """Prove path identities while the caller holds _operation_lock."""

        with self._state_lock:
            if (
                self._heartbeat_error is not None
                or self._pending_acquisition is not None
                or not self._config_anchor.verify_path_identity
                or not self._legacy_parent_anchor.verify_path_identity
            ):
                return None
        try:
            _assert_anchor(self._config_anchor, label="config directory")
            _assert_anchor(self._legacy_parent_anchor, label="legacy lock parent")
            for lock in self._locks:
                derived_path = lock.parent.path / lock.name
                if (
                    lock.parent is not self._config_anchor
                    and lock.parent is not self._legacy_parent_anchor
                    or lock.path != derived_path
                    or lock.identity.path != lock.path
                ):
                    return None
                _assert_lock(lock)
            _assert_anchor(self._config_anchor, label="config directory")
            _assert_anchor(self._legacy_parent_anchor, label="legacy lock parent")
        except BaseException as error:
            if _is_control_flow_error(error):
                raise
            return None
        with self._state_lock:
            if self._heartbeat_error is not None:
                return None
        return tuple(str(lock.parent.path / lock.name) for lock in self._locks)

    def _mark_cleanup_inconclusive(
        self,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        with self._state_lock:
            if self._cleanup_inconclusive is not None:
                return self._cleanup_inconclusive
            diagnostic = self._cleanup_inconclusive_fallback
            self._cleanup_inconclusive = diagnostic
            self._customize_cleanup_inconclusive(diagnostic, reason)
            return diagnostic

    def _customize_cleanup_inconclusive(
        self,
        diagnostic: ClaudeRefreshLockCleanupInconclusive,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        with self._state_lock:
            if self._cleanup_inconclusive is not diagnostic:
                assert self._cleanup_inconclusive is not None
                return self._cleanup_inconclusive
            diagnostic.args = (
                f"{reason}; {_descriptor_bound_refresh_lock_recovery_diagnostic()}",
            )
            return diagnostic

    def _promote_cleanup_inconclusive_paths(
        self,
        diagnostic: ClaudeRefreshLockCleanupInconclusive,
        *,
        reason: str,
        authoritative_paths: tuple[str, ...],
    ) -> ClaudeRefreshLockCleanupInconclusive:
        with self._state_lock:
            if (
                self._cleanup_inconclusive is not diagnostic
                or self._heartbeat_error is not None
            ):
                assert self._cleanup_inconclusive is not None
                return self._cleanup_inconclusive
            original_args = diagnostic.args
            promoted_args = (
                f"{reason}; {_refresh_lock_recovery_diagnostic(authoritative_paths)}",
            )
            try:
                setattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_paths",
                    authoritative_paths,
                )
                diagnostic.args = promoted_args
                if hasattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                ):
                    delattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                    )
                return diagnostic
            except BaseException:
                if hasattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_paths",
                ):
                    delattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_paths",
                    )
                diagnostic.args = original_args
                setattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    True,
                )
                raise

    def _demote_cleanup_inconclusive_paths(
        self,
        diagnostic: ClaudeRefreshLockCleanupInconclusive,
        *,
        reason: str,
    ) -> ClaudeRefreshLockCleanupInconclusive:
        """Hide cached paths until a resumed abandonment reproves them."""

        with self._state_lock:
            if self._cleanup_inconclusive is not diagnostic:
                assert self._cleanup_inconclusive is not None
                return self._cleanup_inconclusive
            # Destination-first publication makes a still-present paths
            # attribute non-authoritative across async interruption boundaries.
            setattr(
                diagnostic,
                "_codex_claude_refresh_lock_descriptor_bound",
                True,
            )
            diagnostic.args = (
                f"{reason}; {_descriptor_bound_refresh_lock_recovery_diagnostic()}",
            )
            if hasattr(
                diagnostic,
                "_codex_claude_refresh_lock_paths",
            ):
                delattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_paths",
                )
            return diagnostic

    def _release_once(self) -> None:
        first_control_flow = _FirstControlFlowWinner(None)
        errors = _ControlFlowErrorLog(first_control_flow)
        operation_handoff: _OperationLockHandoff | None = None
        boundary_error: BaseException | None = None
        release_error: BaseException | None = None
        try:
            try:
                self._reconcile_pending_operation_handoff()
                with self._state_lock:
                    if self._released:
                        self._retention_recovery_evidence = None
                        return
                    if self._deletion_prohibited:
                        diagnostic = self._cleanup_inconclusive
                        if diagnostic is None:
                            diagnostic = self._cleanup_inconclusive_fallback
                            self._cleanup_inconclusive = diagnostic
                        raise diagnostic
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
                    try:
                        thread_alive = thread.is_alive()
                    except BaseException as error:
                        thread_alive = True
                        errors.append(
                            _normalize_operation_error(
                                "cannot verify Claude refresh-lock heartbeat shutdown",
                                error,
                            )
                        )
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
                operation_handoff = _OperationLockHandoff(self._operation_lock)
                self._publish_operation_handoff(operation_handoff)
                try:
                    try:
                        operation_handoff.acquire(
                            timeout=shutdown_timeout,
                            first_control_flow=first_control_flow,
                        )
                    except BaseException as error:
                        errors.append(
                            _normalize_operation_error(
                                "cannot quiesce Claude refresh-lock operations",
                                error,
                            )
                        )
                    if not operation_handoff.acquired:
                        errors.append(
                            ClaudeRefreshLockError(
                                "Claude refresh-lock operations did not quiesce"
                            )
                        )
                        primary = _primary_error(errors)
                        assert primary is not None
                        raise primary
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
                            self._retention_recovery_evidence = None
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
                    try:
                        self._reconcile_pending_operation_handoff()
                    except BaseException as error:
                        release_error = _normalize_operation_error(
                            "cannot release the Claude refresh-lock operation guard",
                            error,
                        )
                        errors.append(release_error)
            except BaseException as body_error:
                boundary_error = body_error
                list.append(errors, body_error)
                first_control_flow.observe(body_error)
                raise
        finally:
            try:
                self._reconcile_pending_operation_handoff()
            except BaseException as error:
                final_release_error = _normalize_operation_error(
                    "cannot release the Claude refresh-lock operation guard",
                    error,
                )
                if release_error is None:
                    release_error = final_release_error
                errors.append(final_release_error)
            selector_error: BaseException | None = None
            try:
                first_control_flow.observe_all(errors)
                first_control_flow.raise_if_set()
            except BaseException as error:
                selector_error = error
                raise
            finally:
                first_control_flow.enforce(
                    errors,
                    selector_error if selector_error is not None else boundary_error,
                )
            if release_error is not None:
                raise release_error


class ClaudeRefreshLockOwner:
    """Retain a lease across the callee-return/caller-assignment boundary."""

    def __init__(self) -> None:
        self._lease: ClaudeRefreshLockLease | None = None
        self._transferred = False

    @property
    def lease(self) -> ClaudeRefreshLockLease | None:
        return self._lease

    @property
    def transferred(self) -> bool:
        return self._transferred

    def _publish(self, lease: ClaudeRefreshLockLease) -> None:
        if self._lease is not None or self._transferred:
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock owner already holds a lease"
            )
        self._lease = lease

    def transfer(self, lease: ClaudeRefreshLockLease) -> None:
        """Confirm that the caller now holds the returned active lease."""

        if self._lease is not lease or self._transferred:
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock ownership transfer is invalid"
            )
        self._transferred = True


def acquire_claude_refresh_lock(
    config_dir: os.PathLike[str] | str,
    *,
    protocol: ClaudeRefreshLockProtocol,
    owner: ClaudeRefreshLockOwner,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    retry_interval_seconds: float = DEFAULT_RETRY_INTERVAL_SECONDS,
    config_dir_fd: int | None = None,
    legacy_parent_dir_fd: int | None = None,
    require_explicit_context_release: bool = False,
) -> ClaudeRefreshLockLease:
    """Acquire Claude's current and legacy directory locks in protocol order."""

    _validate_protocol(protocol)
    _validate_timeout(timeout_seconds, retry_interval_seconds)
    raw_path = os.fspath(config_dir)
    if not isinstance(raw_path, str) or not os.path.isabs(raw_path):
        raise ClaudeRefreshLockUnsafe(
            "Claude config directory must be an absolute path"
        )
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

    cleanup_inconclusive_fallback = _new_cleanup_inconclusive_fallback()
    descriptor_bound_cleanup_fallback = _new_cleanup_inconclusive_fallback()
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
        lease = ClaudeRefreshLockLease(
            protocol=protocol,
            config_anchor=config_anchor,
            legacy_parent_anchor=parent_anchor,
            locks=(),
            cleanup_inconclusive_fallback=cleanup_inconclusive_fallback,
            descriptor_bound_cleanup_fallback=(descriptor_bound_cleanup_fallback),
            owner=owner,
            require_explicit_context_release=require_explicit_context_release,
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
            lease=lease,
        )
        legacy_name = canonical_path.name + protocol.legacy_suffix
        legacy_path = pathlib.Path(str(canonical_path) + protocol.legacy_suffix)
        legacy = _acquire_one(
            label="legacy",
            path=legacy_path,
            name=legacy_name,
            parent=parent_anchor,
            protocol=protocol,
            deadline=deadline,
            retry_interval_seconds=retry_interval_seconds,
            lease=lease,
        )
        if (
            len(lease._locks) != 2
            or lease._locks[0] is not primary
            or lease._locks[1] is not legacy
        ):
            raise ClaudeRefreshLockCompromised(
                "Claude refresh-lock acquisition ownership is incomplete"
            )
        lease._start_heartbeat()
        return lease
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        cleanup_lease = lease
        if cleanup_lease is None:
            published_lease = owner.lease
            if (
                published_lease is not None
                and published_lease._cleanup_inconclusive_fallback
                is cleanup_inconclusive_fallback
            ):
                cleanup_lease = published_lease
        if cleanup_lease is not None:
            try:
                # Acquisition has not returned successfully. Explicit-mode
                # retention is armed only after a caller accepts ownership.
                cleanup_fallback = cleanup_lease._cleanup_inconclusive_fallback
                _bind_cleanup_recovery_evidence(
                    primary_error,
                    cleanup_fallback,
                )
                cleanup_lease._heartbeat_stop.set()
                if cleanup_lease._has_pending_acquisition():
                    # Prearm outside the state-lock entry boundary: either the
                    # call below finishes non-destructive abandonment or its
                    # winner retains live descriptor-bound recovery evidence.
                    cleanup_lease._deletion_prohibited = True
                    cleanup_lease._heartbeat_stop.set()
                    with cleanup_lease._state_lock:
                        cleanup_lease._deletion_prohibited = True
                        cleanup_lease._heartbeat_stop.set()
                    cleanup_diagnostic = cleanup_lease.abandon(
                        "refresh-lock acquisition stopped before helper "
                        "ownership was fully anchored"
                    )
                    attach_claude_refresh_lock_recovery(
                        primary_error,
                        cleanup_diagnostic,
                    )
                    cleanup_errors.append(cleanup_diagnostic)
                else:
                    cleanup_lease._release(skip_abandoned=False)
                    _unbind_cleanup_recovery_evidence(
                        primary_error,
                        cleanup_fallback,
                    )
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        else:
            closed: set[int] = set()
            for anchor in (parent_anchor, config_anchor):
                if anchor is None or anchor.descriptor in closed:
                    continue
                closed.add(anchor.descriptor)
                try:
                    os.close(anchor.descriptor)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        selected_error = _primary_error([primary_error, *cleanup_errors])
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
    require_explicit_context_release: bool = False,
) -> Iterator[ClaudeRefreshLockLease]:
    owner = ClaudeRefreshLockOwner()
    lease: ClaudeRefreshLockLease | None = None
    try:
        lease = acquire_claude_refresh_lock(
            config_dir,
            protocol=protocol,
            owner=owner,
            timeout_seconds=timeout_seconds,
            retry_interval_seconds=retry_interval_seconds,
            require_explicit_context_release=require_explicit_context_release,
        )
        owner.transfer(lease)
        yield lease
    except BaseException as body_error:
        cleanup_lease = lease if lease is not None else owner.lease
        if cleanup_lease is not None:
            try:
                if owner.transferred:
                    cleanup_lease._release_on_context_exit()
                else:
                    cleanup_lease._release(skip_abandoned=False)
            except BaseException as cleanup_error:
                selected_error = _primary_error([body_error, cleanup_error])
                if selected_error is not body_error:
                    assert selected_error is not None
                    raise selected_error
        raise
    else:
        assert lease is not None
        lease._release_on_context_exit()


@contextlib.contextmanager
def claude_refresh_lock_release_on_success(
    config_dir: os.PathLike[str] | str,
    *,
    protocol: ClaudeRefreshLockProtocol,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    retry_interval_seconds: float = DEFAULT_RETRY_INTERVAL_SECONDS,
) -> Iterator[ClaudeRefreshLockLease]:
    """Retain an explicit lease unless its context body exits successfully."""

    owner = ClaudeRefreshLockOwner()
    lease: ClaudeRefreshLockLease | None = None
    try:
        lease = acquire_claude_refresh_lock(
            config_dir,
            protocol=protocol,
            owner=owner,
            timeout_seconds=timeout_seconds,
            retry_interval_seconds=retry_interval_seconds,
            require_explicit_context_release=True,
        )
        owner.transfer(lease)
        lease.assert_held()
        yield lease
        lease._release(skip_abandoned=False)
    except BaseException as primary_error:
        cleanup_lease = lease if lease is not None else owner.lease
        if cleanup_lease is not None:
            try:
                if owner.transferred:
                    with cleanup_lease._state_lock:
                        if not cleanup_lease._released:
                            # The call below is interruptible at entry. Latch the
                            # retain-only decision directly in owner state first.
                            cleanup_lease._deletion_prohibited = True
                            cleanup_lease._heartbeat_stop.set()
                    cleanup_lease._release_on_context_exit()
                else:
                    cleanup_lease._release(skip_abandoned=False)
            except BaseException as cleanup_error:
                if (
                    owner.transferred
                    and _refresh_lock_recovery_paths(cleanup_error) is None
                    and not _has_descriptor_bound_refresh_lock_cleanup(cleanup_error)
                ):
                    _attach_secondary_cleanup(
                        cleanup_error,
                        cleanup_lease._cleanup_inconclusive_fallback,
                    )
                selected_error = _primary_error([primary_error, cleanup_error])
                if selected_error is not primary_error:
                    assert selected_error is not None
                    raise selected_error
        raise


__all__ = (
    "CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS",
    "CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211",
    "ClaudeRefreshLockCleanupInconclusive",
    "ClaudeRefreshLockCompromised",
    "ClaudeRefreshLockError",
    "ClaudeRefreshLockIdentity",
    "ClaudeRefreshLockLease",
    "ClaudeRefreshLockOwner",
    "ClaudeRefreshLockProtocol",
    "ClaudeRefreshLockStale",
    "ClaudeRefreshLockTimeout",
    "ClaudeRefreshLockUnsafe",
    "acquire_claude_refresh_lock",
    "attach_claude_refresh_lock_recovery",
    "certified_claude_refresh_lock_protocol",
    "claude_refresh_lock",
    "claude_refresh_lock_release_on_success",
    "recover_abandoned_staged_claude_refresh_locks",
)
