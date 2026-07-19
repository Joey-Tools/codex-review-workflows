from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import math
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Iterator

from .common import (
    PROCESS_GROUP_TERM_GRACE_SECONDS,
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    read_json,
    restore_signal_mask,
    signal_process_group,
    tail_text,
    terminate_process_group,
    unblock_forwarded_signals,
    write_json,
    write_text_atomic,
)
from .providers import run_review
from .workspace import (
    MAX_PREFLIGHT_JSON_BYTES,
    PRIVATE_HELPER_ARTIFACT_NAMES,
    REVIEW_CLEANUP_LOCK_NAME,
    REVIEW_RUNNER_LOCK_NAME,
    REVIEW_STATE_MARKER_NAME,
    BoundReviewLock,
    CleanupIdentity,
    LegacyReviewWorkspace,
    PrivateCleanupEvidence,
    ReviewWorkspace,
    _inspect_control_directory,
    _load_control_artifact_state,
    _read_bounded_json,
    cleanup_legacy_workspace,
    cleanup_workspace,
    load_bound_private_cleanup_state,
    parse_partial_private_cleanup_evidence,
    parse_private_cleanup_evidence,
    prepare_workspace,
    remove_bound_review_text,
    remove_legacy_private_review_artifacts,
    remove_partial_review_container,
    remove_private_review_artifacts,
    remove_ready_review_container,
    open_bound_review_lock,
    validate_workspace_layout,
    write_bound_review_json,
    write_bound_review_text,
)


STATE_FILE = "state.json"
STATE_MARKER = REVIEW_STATE_MARKER_NAME
LEGACY_STATE_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
LEGACY_STATE_MARKER = b"isolated-review-state-v1\n"
COMPATIBLE_STATE_MARKER_SCHEMA_VERSION = 2
STATE_MARKER_SCHEMA_VERSION = 3
MAX_STATE_MARKER_BYTES = 64 * 1024
LEGACY_STATE_REQUIRED_FIELDS = frozenset(
    {
        "attempts_path",
        "egress_consent",
        "final_path",
        "keep_workspace",
        "reviewer",
        "started_at",
        "stderr_path",
        "stdout_path",
        "version",
        "workspace",
    }
)
LEGACY_STATE_OPTIONAL_FIELDS = frozenset({"pid", "synthetic_secret_exemptions"})
EXIT_FILE = "exit-code"
LOCK_FILE = REVIEW_RUNNER_LOCK_NAME
CLEANUP_LOCK_FILE = REVIEW_CLEANUP_LOCK_NAME
FINAL_CLEANUP_TIMEOUT_SECONDS = 30.0
RUNNER_SHUTDOWN_GRACE_SECONDS = PROCESS_GROUP_TERM_GRACE_SECONDS * 4
PRIMARY_DIFF_RELATIVE_PATH = ".codex-review/review.diff"
SAFE_LEGACY_LOCK_MODES = frozenset({0o600, 0o604, 0o640, 0o644})
PRIVATE_STATE_LEGACY_LOCK_MODES = SAFE_LEGACY_LOCK_MODES | {0o664}
_STARTED_PROCESSES: dict[int, subprocess.Popen[bytes]] = {}


def _write_loaded_review_text(
    state_dir: pathlib.Path,
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    name: str,
    text: str,
) -> str | None:
    if isinstance(review, LegacyReviewWorkspace):
        try:
            write_text_atomic(state_dir / name, text)
        except Exception as error:
            return str(error)
        return None
    return write_bound_review_text(
        state_dir,
        expected=review.private_cleanup,
        name=name,
        text=text,
    )


def _remove_loaded_review_text(
    state_dir: pathlib.Path,
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    name: str,
) -> str | None:
    if isinstance(review, LegacyReviewWorkspace):
        try:
            (state_dir / name).unlink(missing_ok=True)
        except OSError as error:
            return str(error)
        return None
    return remove_bound_review_text(
        state_dir,
        expected=review.private_cleanup,
        name=name,
    )


@dataclass(frozen=True)
class LoadedStateMarker:
    version: int
    phase: str
    private_cleanup: PrivateCleanupEvidence | None
    source_root: pathlib.Path | None


@dataclass(frozen=True)
class _CleanupLockSet:
    container: BoundReviewLock
    compatibility: BinaryIO

    def fileno(self) -> int:
        return self.compatibility.fileno()

    def filenos(self) -> tuple[int, ...]:
        return (*self.container.filenos(), self.compatibility.fileno())


def _regular_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_regular_file_path_identity(
    path: pathlib.Path,
    descriptor: int,
    *,
    label: str,
    expected_mode: int | None = None,
    expected_size: int | None = None,
    dir_fd: int | None = None,
    allow_group_or_other_write: bool = False,
) -> os.stat_result:
    try:
        descriptor_before = os.fstat(descriptor)
        path_before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        descriptor_after = os.fstat(descriptor)
        path_after = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as error:
        raise ReviewError(f"cannot validate {label}: {error}") from error

    descriptor_identity = _regular_file_identity(descriptor_before)
    if descriptor_identity != _regular_file_identity(descriptor_after):
        raise ReviewError(f"{label} changed while its identity was validated")
    path_identity = _regular_file_identity(path_before)
    if path_identity != _regular_file_identity(path_after):
        raise ReviewError(f"{label} path changed while its identity was validated")
    if descriptor_identity != path_identity:
        raise ReviewError(f"{label} path does not match its open file descriptor")
    if not stat.S_ISREG(descriptor_after.st_mode):
        raise ReviewError(f"{label} is not a regular file")
    if descriptor_after.st_uid != os.getuid():
        raise ReviewError(f"{label} is not owned by the current user")
    if descriptor_after.st_nlink != 1:
        raise ReviewError(f"{label} must have exactly one hard link")
    if expected_mode is not None:
        if stat.S_IMODE(descriptor_after.st_mode) != expected_mode:
            raise ReviewError(f"{label} mode must be exactly {expected_mode:04o}")
    elif not allow_group_or_other_write and descriptor_after.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    ):
        raise ReviewError(f"{label} must not be group or other writable")
    if expected_size is not None and descriptor_after.st_size != expected_size:
        raise ReviewError(f"{label} has an unexpected size")
    return descriptor_after


def validate_private_lock_file(
    path: pathlib.Path,
    handle: BinaryIO,
    *,
    label: str,
    dir_fd: int | None = None,
) -> None:
    _validate_regular_file_path_identity(
        path,
        handle.fileno(),
        label=label,
        expected_mode=0o600,
        dir_fd=dir_fd,
    )


def validate_safe_legacy_lock_file(
    path: pathlib.Path,
    handle: BinaryIO,
    *,
    label: str,
    allowed_modes: frozenset[int] = SAFE_LEGACY_LOCK_MODES,
    dir_fd: int | None = None,
) -> os.stat_result:
    metadata = _validate_regular_file_path_identity(
        path,
        handle.fileno(),
        label=label,
        dir_fd=dir_fd,
        allow_group_or_other_write=True,
    )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in allowed_modes:
        raise ReviewError(f"{label} has an unsafe legacy mode")
    if mode == 0o664 and metadata.st_size != 0:
        raise ReviewError(f"{label} legacy 0664 file must be empty")
    return metadata


def open_private_lock_file(
    path: pathlib.Path,
    *,
    label: str,
    allow_legacy_read_mode: bool = False,
    allowed_legacy_modes: frozenset[int] = SAFE_LEGACY_LOCK_MODES,
    dir_fd: int | None = None,
) -> BinaryIO:
    existing_flags = (
        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(
                path,
                existing_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            created = True
        except FileExistsError:
            existing_metadata = os.stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=False,
            )
            existing_identity = (
                existing_metadata.st_dev,
                existing_metadata.st_ino,
            )
            descriptor = os.open(path, existing_flags, dir_fd=dir_fd)
            opened_metadata = os.fstat(descriptor)
            if existing_identity != (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
            ):
                raise ReviewError(f"{label} changed before it could be opened safely")
        if created:
            os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = None
        try:
            if allow_legacy_read_mode:
                validate_safe_legacy_lock_file(
                    path,
                    handle,
                    label=label,
                    allowed_modes=allowed_legacy_modes,
                    dir_fd=dir_fd,
                )
            else:
                validate_private_lock_file(
                    path,
                    handle,
                    label=label,
                    dir_fd=dir_fd,
                )
        except BaseException:
            handle.close()
            raise
        return handle
    except OSError as error:
        raise ReviewError(f"cannot open {label} safely: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_private_directory_path_identity(
    path: pathlib.Path,
    descriptor: int,
    *,
    label: str,
    expected_mode: int | None = None,
    dir_fd: int | None = None,
) -> None:
    try:
        descriptor_before = os.fstat(descriptor)
        path_before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        descriptor_after = os.fstat(descriptor)
        path_after = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as error:
        raise ReviewError(f"cannot validate {label}: {error}") from error

    descriptor_identity = _directory_identity(descriptor_before)
    if descriptor_identity != _directory_identity(descriptor_after):
        raise ReviewError(f"{label} changed while its identity was validated")
    path_identity = _directory_identity(path_before)
    if path_identity != _directory_identity(path_after):
        raise ReviewError(f"{label} path changed while its identity was validated")
    if descriptor_identity != path_identity:
        raise ReviewError(f"{label} path does not match its open descriptor")
    if not stat.S_ISDIR(descriptor_after.st_mode):
        raise ReviewError(f"{label} is not a real directory")
    if descriptor_after.st_uid != os.geteuid():
        raise ReviewError(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(descriptor_after.st_mode)
    if expected_mode is not None:
        if mode != expected_mode:
            raise ReviewError(f"{label} mode must be exactly {expected_mode:04o}")
    elif descriptor_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReviewError(f"{label} must not be group or other writable")


@contextmanager
def _open_private_cleanup_state_directory(
    state_dir: pathlib.Path,
) -> Iterator[tuple[int, Callable[[], None]]]:
    review_root = state_dir.parent
    if review_root.name != ".codex-tmp" or not state_dir.name.startswith(
        "isolated-review-"
    ):
        raise ReviewError("review state directory is outside a private review root")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    review_root_fd: int | None = None
    state_dir_fd: int | None = None
    try:
        review_root_fd = os.open(review_root, flags)
        state_dir_fd = os.open(state_dir.name, flags, dir_fd=review_root_fd)

        def revalidate() -> None:
            assert review_root_fd is not None
            assert state_dir_fd is not None
            _validate_private_directory_path_identity(
                review_root,
                review_root_fd,
                label="review state root",
            )
            _validate_private_directory_path_identity(
                pathlib.Path(state_dir.name),
                state_dir_fd,
                label="review state directory",
                expected_mode=0o700,
                dir_fd=review_root_fd,
            )

        revalidate()
        yield state_dir_fd, revalidate
    except OSError as error:
        raise ReviewError(
            f"cannot open review state directory safely: {error}"
        ) from error
    finally:
        if state_dir_fd is not None:
            os.close(state_dir_fd)
        if review_root_fd is not None:
            os.close(review_root_fd)


def _state_path(state_dir: pathlib.Path) -> pathlib.Path:
    state_dir = state_dir.expanduser().resolve()
    marker = state_dir / STATE_MARKER
    if not marker.is_file():
        raise ReviewError(f"not an isolated-review state directory: {state_dir}")
    return state_dir / STATE_FILE


def _state_marker_payload(review: ReviewWorkspace) -> dict[str, Any]:
    return {
        "container_dir": str(review.container_dir),
        "phase": "ready",
        "private_cleanup": review.private_cleanup.to_json(),
        "source_root": str(review.source_root),
        "version": STATE_MARKER_SCHEMA_VERSION,
    }


def _preparing_state_marker_payload(
    container: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
) -> dict[str, Any]:
    return {
        "container_dir": str(container),
        "phase": "preparing",
        "private_cleanup": private_cleanup.to_json(),
        "source_root": str(container.parent.parent),
        "version": STATE_MARKER_SCHEMA_VERSION,
    }


def _write_state_marker_payload(
    container: pathlib.Path,
    payload: dict[str, Any],
    *,
    expected: PrivateCleanupEvidence,
) -> None:
    marker_error = write_bound_review_json(
        container,
        expected=expected,
        name=STATE_MARKER,
        value=payload,
    )
    if marker_error:
        raise ReviewError(
            f"cannot durably persist isolated-review state marker: {marker_error}"
        )


def _write_preparing_state_marker(
    container: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
) -> None:
    _write_state_marker_payload(
        container,
        _preparing_state_marker_payload(container, private_cleanup),
        expected=private_cleanup,
    )


def _write_state_marker(review: ReviewWorkspace) -> None:
    _write_state_marker_payload(
        review.container_dir,
        _state_marker_payload(review),
        expected=review.private_cleanup,
    )


class ReviewPreparationGuard:
    def __init__(self) -> None:
        self._lock_handle = None
        self._lock_container: pathlib.Path | None = None
        self._cleanup_lock: BoundReviewLock | None = None
        self._review: ReviewWorkspace | None = None

    def _ensure_lock(self, container: pathlib.Path) -> None:
        lock_path = container / LOCK_FILE
        if self._lock_handle is not None:
            if self._lock_container != container:
                raise ReviewError(
                    "workspace preparation lock container changed during handoff"
                )
            opened = os.fstat(self._lock_handle.fileno())
            try:
                current = os.lstat(lock_path)
            except OSError as error:
                raise ReviewError(
                    f"workspace preparation lock changed during handoff: {error}"
                ) from error
            if CleanupIdentity(opened.st_dev, opened.st_ino) != CleanupIdentity(
                current.st_dev,
                current.st_ino,
            ):
                raise ReviewError("workspace preparation lock changed during handoff")
            return

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        candidate = None
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            candidate = os.fdopen(descriptor, "w+b")
            descriptor = None
            opened = os.fstat(candidate.fileno())
            current = os.lstat(lock_path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or CleanupIdentity(opened.st_dev, opened.st_ino)
                != CleanupIdentity(current.st_dev, current.st_ino)
            ):
                raise ReviewError("workspace preparation lock is invalid")
            fcntl.flock(candidate.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_handle = candidate
            self._lock_container = container
            candidate = None
        except OSError as error:
            raise ReviewError(
                f"cannot acquire workspace preparation lock {lock_path}: {error}"
            ) from error
        finally:
            if candidate is not None:
                candidate.close()
            elif descriptor is not None:
                os.close(descriptor)

    def accept_preparation_cleanup(
        self,
        container: pathlib.Path,
        private_cleanup: PrivateCleanupEvidence,
    ) -> None:
        self._ensure_lock(container)
        _write_preparing_state_marker(container, private_cleanup)

    def accept_workspace(self, prepared: ReviewWorkspace) -> None:
        if self._lock_handle is None:
            self.accept_preparation_cleanup(
                prepared.container_dir,
                prepared.private_cleanup,
            )
        else:
            self._ensure_lock(prepared.container_dir)
        _write_state_marker(prepared)
        self._review = prepared

    @property
    def review(self) -> ReviewWorkspace | None:
        return self._review

    def require_review(self) -> ReviewWorkspace:
        review = self._review
        if review is None:
            raise ReviewError("workspace ownership handoff did not complete")
        if self._lock_handle is None or self._lock_container != review.container_dir:
            raise ReviewError("workspace preparation lock handoff did not complete")
        return review

    def lock_fd(self) -> int:
        review = self.require_review()
        if self._lock_container != review.container_dir or self._lock_handle is None:
            raise ReviewError("workspace preparation lock handoff did not complete")
        return self._lock_handle.fileno()

    def acquire_final_cleanup_lock(
        self,
        *,
        timeout_seconds: float = FINAL_CLEANUP_TIMEOUT_SECONDS,
    ) -> str | None:
        if self._cleanup_lock is not None:
            return None
        review = self.require_review()
        cleanup_lock, lock_error = open_bound_review_lock(
            review.container_dir,
            expected=review.private_cleanup,
            name=CLEANUP_LOCK_FILE,
        )
        if lock_error or cleanup_lock is None:
            return (
                "cannot open preparation-bound cleanup lock: "
                f"{lock_error or 'lock handle is unavailable'}"
            )
        deadline = time.monotonic() + timeout_seconds
        try:
            acquired = _acquire_cleanup_lock(cleanup_lock, deadline=deadline)
        except BaseException:
            cleanup_lock.close()
            raise
        if not acquired:
            cleanup_lock.close()
            return "timed out acquiring preparation-bound cleanup lock"
        self._cleanup_lock = cleanup_lock
        return None

    def close(self) -> None:
        first_error: OSError | None = None
        if self._lock_handle is not None:
            try:
                self._lock_handle.close()
            except OSError as error:
                first_error = error
            self._lock_handle = None
        if self._cleanup_lock is not None:
            for descriptor in reversed(_cleanup_lock_fds(self._cleanup_lock)):
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError as error:
                    if first_error is None:
                        first_error = error
            try:
                self._cleanup_lock.close()
            except OSError as error:
                if first_error is None:
                    first_error = error
            self._cleanup_lock = None
        if first_error is not None:
            raise first_error


def _reject_duplicate_marker_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewError(
                f"isolated-review state marker has duplicate field: {key}"
            )
        value[key] = item
    return value


def _validate_marker_container(
    raw_container: Any,
    *,
    resolved_state_dir: pathlib.Path,
) -> None:
    if not isinstance(raw_container, str):
        raise ReviewError("isolated-review state marker container is invalid")
    try:
        marker_container = (
            pathlib.Path(raw_container).expanduser().resolve(strict=False)
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(
            "isolated-review state marker container is invalid"
        ) from error
    if marker_container != resolved_state_dir:
        raise ReviewError("isolated-review state marker container is invalid")


def _canonical_v3_marker_path(raw_path: Any, *, label: str) -> pathlib.Path:
    if not isinstance(raw_path, str):
        raise ReviewError(f"isolated-review state marker {label} is invalid")
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    normalized = pathlib.Path(os.path.normpath(os.fspath(candidate)))
    if candidate != normalized:
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(f"isolated-review state marker {label} is invalid") from error
    if resolved != candidate:
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    return resolved


def _validate_v3_marker_layout(
    raw_source_root: Any,
    raw_container: Any,
    *,
    resolved_state_dir: pathlib.Path,
) -> pathlib.Path:
    source_root = _canonical_v3_marker_path(
        raw_source_root,
        label="source root",
    )
    container = _canonical_v3_marker_path(
        raw_container,
        label="container",
    )
    if (
        container != resolved_state_dir
        or container.parent != source_root / ".codex-tmp"
        or not container.name.startswith("isolated-review-")
        or container.name == "isolated-review-"
    ):
        raise ReviewError("isolated-review state marker layout is invalid")
    return source_root


def _state_marker_metadata_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_state_marker_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewError("isolated-review state marker must be a regular file")
    if metadata.st_nlink != 1:
        raise ReviewError(
            "isolated-review state marker must have exactly one hard link"
        )
    if metadata.st_uid != os.geteuid():
        raise ReviewError(
            "isolated-review state marker must be owned by the current user"
        )
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReviewError(
            "isolated-review state marker must not be group or other writable"
        )
    if metadata.st_size > MAX_STATE_MARKER_BYTES:
        raise ReviewError("isolated-review state marker exceeds the size limit")


def _read_state_marker_bytes(state_dir: pathlib.Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblock is None:
        raise ReviewError("secure isolated-review state marker loading is unavailable")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | nofollow
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblock
    directory_descriptor: int | None = None
    marker_descriptor: int | None = None
    try:
        directory_descriptor = os.open(state_dir, directory_flags)
        before = os.stat(
            STATE_MARKER,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _validate_state_marker_metadata(before)
        marker_descriptor = os.open(
            STATE_MARKER,
            file_flags,
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(marker_descriptor)
        current = os.stat(
            STATE_MARKER,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        for metadata in (opened, current):
            _validate_state_marker_metadata(metadata)
        initial_key = _state_marker_metadata_key(before)
        if any(
            _state_marker_metadata_key(metadata) != initial_key
            for metadata in (opened, current)
        ):
            raise ReviewError("isolated-review state marker changed while opening")

        chunks: list[bytes] = []
        remaining = MAX_STATE_MARKER_BYTES + 1
        while remaining:
            chunk = os.read(marker_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) > MAX_STATE_MARKER_BYTES:
            raise ReviewError("isolated-review state marker exceeds the size limit")

        final = os.fstat(marker_descriptor)
        path_final = os.stat(
            STATE_MARKER,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        for metadata in (final, path_final):
            _validate_state_marker_metadata(metadata)
        if len(encoded) != opened.st_size or any(
            _state_marker_metadata_key(metadata) != initial_key
            for metadata in (final, path_final)
        ):
            raise ReviewError("isolated-review state marker changed while reading")
        return encoded
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot read isolated-review state marker {state_dir / STATE_MARKER}: "
            f"{error}"
        ) from error
    finally:
        if marker_descriptor is not None:
            os.close(marker_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _load_state_marker(state_dir: pathlib.Path) -> LoadedStateMarker:
    resolved_state_dir = state_dir.expanduser().resolve(strict=False)
    encoded = _read_state_marker_bytes(resolved_state_dir)
    if encoded == LEGACY_STATE_MARKER:
        return LoadedStateMarker(
            version=LEGACY_STATE_SCHEMA_VERSION,
            phase="legacy",
            private_cleanup=None,
            source_root=None,
        )
    try:
        marker = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_marker_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewError("isolated-review state marker is invalid") from error
    if not isinstance(marker, dict):
        raise ReviewError("isolated-review state marker is not a JSON object")
    version = marker.get("version")
    if type(version) is not int:
        raise ReviewError("isolated-review state marker version is invalid")
    if version == COMPATIBLE_STATE_MARKER_SCHEMA_VERSION:
        if set(marker) != {"container_dir", "private_cleanup", "version"}:
            raise ReviewError("isolated-review state marker fields are invalid")
        _validate_marker_container(
            marker["container_dir"],
            resolved_state_dir=resolved_state_dir,
        )
        return LoadedStateMarker(
            version=version,
            phase="ready",
            private_cleanup=parse_private_cleanup_evidence(marker["private_cleanup"]),
            source_root=None,
        )
    if version != STATE_MARKER_SCHEMA_VERSION:
        raise ReviewError("isolated-review state marker version is invalid")
    if set(marker) != {
        "container_dir",
        "phase",
        "private_cleanup",
        "source_root",
        "version",
    }:
        raise ReviewError("isolated-review state marker fields are invalid")
    source_root = _validate_v3_marker_layout(
        marker["source_root"],
        marker["container_dir"],
        resolved_state_dir=resolved_state_dir,
    )
    phase = marker["phase"]
    if not isinstance(phase, str) or phase not in {"preparing", "ready"}:
        raise ReviewError("isolated-review state marker phase is invalid")
    cleanup_parser = (
        parse_private_cleanup_evidence
        if phase == "ready"
        else parse_partial_private_cleanup_evidence
    )
    return LoadedStateMarker(
        version=version,
        phase=phase,
        private_cleanup=cleanup_parser(marker["private_cleanup"]),
        source_root=source_root,
    )


def _load_state_marker_cleanup(
    state_dir: pathlib.Path,
) -> PrivateCleanupEvidence:
    marker = _load_state_marker(state_dir)
    if marker.private_cleanup is None:
        raise ReviewError("legacy isolated-review state marker has no cleanup identity")
    return marker.private_cleanup


def load_state(state_dir: pathlib.Path) -> dict[str, Any]:
    return read_json(_state_path(state_dir))


def _validate_legacy_state(
    state: dict[str, Any],
    *,
    state_dir: pathlib.Path,
) -> None:
    fields = set(state)
    if not LEGACY_STATE_REQUIRED_FIELDS <= fields or not fields <= (
        LEGACY_STATE_REQUIRED_FIELDS | LEGACY_STATE_OPTIONAL_FIELDS
    ):
        raise ReviewError("legacy v1 review state fields are invalid")
    if not isinstance(state["reviewer"], str):
        raise ReviewError("legacy v1 review state reviewer is invalid")
    if type(state["keep_workspace"]) is not bool:
        raise ReviewError("legacy v1 review state keep flag is invalid")
    if state["egress_consent"] is not None and not isinstance(
        state["egress_consent"], str
    ):
        raise ReviewError("legacy v1 review state egress consent is invalid")
    if not isinstance(state["workspace"], dict):
        raise ReviewError("legacy v1 review state workspace is invalid")
    started_at = state["started_at"]
    if (
        type(started_at) not in {int, float}
        or not math.isfinite(started_at)
        or started_at < 0
    ):
        raise ReviewError("legacy v1 review state start time is invalid")
    expected_paths = {
        "attempts_path": state_dir / "attempts.json",
        "final_path": state_dir / "final.txt",
        "stderr_path": state_dir / "runner.stderr.log",
        "stdout_path": state_dir / "runner.stdout.log",
    }
    if any(state[field] != str(path) for field, path in expected_paths.items()):
        raise ReviewError("legacy v1 review state artifact paths are invalid")
    if "synthetic_secret_exemptions" in state:
        exemptions = state["synthetic_secret_exemptions"]
        if not isinstance(exemptions, list) or any(
            not isinstance(item, str) for item in exemptions
        ):
            raise ReviewError(
                "legacy v1 review state synthetic secret exemptions are invalid"
            )
    if "pid" in state and (type(state["pid"]) is not int or state["pid"] <= 0):
        raise ReviewError("legacy v1 review state pid is invalid")


def load_review_state(
    state_dir: pathlib.Path,
) -> tuple[dict[str, Any], ReviewWorkspace | LegacyReviewWorkspace]:
    resolved_state_dir = state_dir.expanduser().resolve()
    marker = _load_state_marker(resolved_state_dir)
    state = load_state(resolved_state_dir)
    version = state.get("version")
    if type(version) is not int or version not in {
        LEGACY_STATE_SCHEMA_VERSION,
        STATE_SCHEMA_VERSION,
    }:
        raise ReviewError("review state version is invalid")
    if version == LEGACY_STATE_SCHEMA_VERSION:
        if marker.version != LEGACY_STATE_SCHEMA_VERSION:
            raise ReviewError("review state and marker versions are inconsistent")
        _validate_legacy_state(state, state_dir=resolved_state_dir)
        workspace_type = LegacyReviewWorkspace
    else:
        if (
            marker.version
            not in {
                COMPATIBLE_STATE_MARKER_SCHEMA_VERSION,
                STATE_MARKER_SCHEMA_VERSION,
            }
            or marker.phase != "ready"
        ):
            raise ReviewError("review state and marker versions are inconsistent")
        workspace_type = ReviewWorkspace
    review_value = state.get("workspace")
    if not isinstance(review_value, dict):
        raise ReviewError("review state does not contain a workspace object")
    try:
        review = workspace_type.from_json(review_value)
    except (KeyError, TypeError, ValueError, ReviewError) as error:
        raise ReviewError(
            f"review state contains an invalid workspace: {error}"
        ) from error
    validate_workspace_layout(review)
    if review.container_dir.resolve(strict=False) != resolved_state_dir:
        raise ReviewError("review state container does not match its state directory")
    if isinstance(review, LegacyReviewWorkspace):
        return state, review
    marker_cleanup = marker.private_cleanup
    if marker_cleanup is None:
        raise ReviewError("review state marker cleanup identity is missing")
    if marker_cleanup != review.private_cleanup:
        raise ReviewError(
            "review state cleanup identity does not match its state marker"
        )
    load_bound_private_cleanup_state(
        review.container_dir,
        expected=review.private_cleanup,
    )
    return state, review


def _read_exit_code(state_dir: pathlib.Path) -> int | None:
    path = state_dir / EXIT_FILE
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReviewError(f"cannot read review exit code {path}: {error}") from error
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        raise ReviewError(f"invalid exit code in {path}: {text!r}")


def _runner_lock_held(lock_path: pathlib.Path) -> bool:
    try:
        handle = lock_path.open("rb")
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReviewError(
            f"cannot open review runner lock {lock_path}: {error}"
        ) from error
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError as error:
            raise ReviewError(
                f"cannot probe review runner lock {lock_path}: {error}"
            ) from error
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise ReviewError(
                f"cannot release review runner lock probe {lock_path}: {error}"
            ) from error
        return False
    finally:
        handle.close()


def _reap_started_process(pid: int) -> None:
    process = _STARTED_PROCESSES.get(pid)
    if process is None:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        return
    _STARTED_PROCESSES.pop(pid, None)


def start(
    *,
    script_path: pathlib.Path,
    repo: pathlib.Path,
    reviewer: str,
    base_ref: str,
    head_ref: str,
    prompt_file: pathlib.Path | None,
    keep_workspace: bool,
    egress_consent: str | None,
    synthetic_secret_exemptions: tuple[str, ...] = (),
    publisher: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path:
    process: subprocess.Popen[bytes] | None = None
    review: ReviewWorkspace | None = None
    preparation_guard = ReviewPreparationGuard()
    pending_signal: signal.Signals | None = None
    spawning = False
    published = False
    cleaning = False
    handlers_restored = False

    def forward_signal(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        forwarded = signal.Signals(signum)
        pending_signal = forwarded
        if cleaning:
            return
        if process is None:
            if spawning:
                return
            raise ForwardedSignal(forwarded)
        signal_process_group(process, forwarded)
        raise ForwardedSignal(forwarded)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, forward_signal)

    def accept_workspace(prepared: ReviewWorkspace) -> None:
        nonlocal review
        preparation_guard.accept_workspace(prepared)
        review = preparation_guard.require_review()

    try:
        prepare_workspace(
            repo=repo,
            base_ref=base_ref,
            head_ref=head_ref,
            ownership_handoff=accept_workspace,
            preparation_cleanup_handoff=(preparation_guard.accept_preparation_cleanup),
            synthetic_secret_exemptions=synthetic_secret_exemptions,
            prompt_override=prompt_file,
        )
        review = preparation_guard.require_review()
        state_dir = review.container_dir
        stdout_path = state_dir / "runner.stdout.log"
        stderr_path = state_dir / "runner.stderr.log"
        state: dict[str, Any] = {
            "version": STATE_SCHEMA_VERSION,
            "reviewer": reviewer,
            "workspace": review.to_json(),
            "keep_workspace": keep_workspace,
            "egress_consent": egress_consent,
            "synthetic_secret_exemptions": list(synthetic_secret_exemptions),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "final_path": str(state_dir / "final.txt"),
            "attempts_path": str(state_dir / "attempts.json"),
            "started_at": time.time(),
        }
        write_json(state_dir / STATE_FILE, state)
        lock_fd = preparation_guard.lock_fd()
        with (
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            spawning = True
            spawn_mask = block_forwarded_signals()
            try:
                process = subprocess.Popen(
                    (
                        sys.executable,
                        str(script_path),
                        "_run-state",
                        "--state-dir",
                        str(state_dir),
                        "--lock-fd",
                        str(lock_fd),
                    ),
                    cwd=review.workspace_root,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(lock_fd,),
                )
            finally:
                spawning = False
                restore_signal_mask(spawn_mask)
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            raise ForwardedSignal(pending_signal)
        state["pid"] = process.pid
        _STARTED_PROCESSES[process.pid] = process
        write_json(state_dir / STATE_FILE, state)
        publication_mask = block_forwarded_signals()
        publication_signal: signal.Signals | None = None
        try:
            if publisher is not None:
                publisher(state_dir)
            published = True
            if publication_mask is not None:
                publication_signal = consume_pending_forwarded_signal()
        finally:
            restore_signal_mask(publication_mask)
        if publication_signal is not None:
            pending_signal = publication_signal
            signal_process_group(process, publication_signal)
            raise ForwardedSignal(publication_signal)
        return state_dir
    except BaseException as error:
        cleaning = True
        cleanup_mask = block_forwarded_signals()
        cleanup_signal: signal.Signals | None = None
        cleanup_error: str | None = None
        try:
            if process is not None:
                terminate_process_group(
                    process,
                    initial_signal=pending_signal or signal.SIGTERM,
                    signal_already_sent=pending_signal is not None,
                    grace_seconds=RUNNER_SHUTDOWN_GRACE_SECONDS,
                )
                _STARTED_PROCESSES.pop(process.pid, None)
            if review is not None and not published:
                cleanup_error = cleanup_workspace(review, keep_container=False)
        finally:
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)
            handlers_restored = True
            if cleanup_mask is not None:
                cleanup_signal = consume_pending_forwarded_signal()
                if cleanup_signal is not None:
                    pending_signal = cleanup_signal
            restore_signal_mask(cleanup_mask)
        if pending_signal is not None:
            details: list[str] = []
            if isinstance(error, ForwardedSignal) and error.detail:
                details.append(error.detail)
            elif isinstance(error, ReviewError):
                details.append(str(error))
            if cleanup_error and review is not None:
                details.append(
                    "review startup failed and cleanup failed; evidence may remain "
                    f"near {review.container_dir}; inspect cleanup state: "
                    f"{cleanup_error}"
                )
            raise ForwardedSignal(
                pending_signal,
                detail="; ".join(details) or None,
            ) from error
        if cleanup_error and review is not None:
            raise ReviewError(
                "review startup failed and cleanup failed; evidence may remain near "
                f"{review.container_dir}; inspect cleanup state: {cleanup_error}"
            ) from error
        raise
    finally:
        preparation_guard.close()
        if not handlers_restored:
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)


def run_state(
    *,
    state_dir: pathlib.Path,
    terminal_process: bool = False,
) -> int:
    exit_code = 1
    pending_signal: signal.Signals | None = None
    suppress_signal_raise = False
    state_loaded = False
    review: ReviewWorkspace | LegacyReviewWorkspace | None = None

    def record_signal(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        pending_signal = signal.Signals(signum)
        if not suppress_signal_raise:
            raise ForwardedSignal(pending_signal)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, record_signal)

    try:
        state, review = load_review_state(state_dir)
        state_loaded = True
        if isinstance(review, LegacyReviewWorkspace):
            raise ReviewError(
                "legacy v1 review state cannot be resumed; start a new review"
            )
        unblock_forwarded_signals()
        reviewer = state.get("reviewer")
        if not isinstance(reviewer, str):
            raise ReviewError("review state does not contain a reviewer")
        consent_value = state.get("egress_consent")
        egress_consent = consent_value if isinstance(consent_value, str) else None
        outcome = run_review(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
        )
        exit_code = outcome.returncode
    except ForwardedSignal as error:
        exit_code = 128 + int(error.signum)
        if state_loaded and review is not None and error.detail:
            diagnostic = (
                "review orchestration interrupted by signal "
                f"{int(error.signum)}: {error.detail}\n"
            )
            diagnostic_error = _write_loaded_review_text(
                state_dir,
                review,
                name="runner-error.txt",
                text=diagnostic,
            )
            if diagnostic_error:
                print(
                    diagnostic.rstrip("\n")
                    + f"; runner diagnostic was not persisted: {diagnostic_error}",
                    file=sys.stderr,
                )
    except Exception as error:
        if state_loaded and review is not None:
            diagnostic = f"{type(error).__name__}: {error}\n"
            diagnostic_error = _write_loaded_review_text(
                state_dir,
                review,
                name="runner-error.txt",
                text=diagnostic,
            )
            if diagnostic_error:
                print(
                    diagnostic.rstrip("\n")
                    + f"; runner diagnostic was not persisted: {diagnostic_error}",
                    file=sys.stderr,
                )
        exit_code = 1
    finally:
        suppress_signal_raise = True
        previous_mask = block_forwarded_signals()
        try:
            while True:
                masked_signal = (
                    consume_pending_forwarded_signal()
                    if previous_mask is not None
                    else None
                )
                if pending_signal is None:
                    pending_signal = masked_signal
                if pending_signal is not None:
                    exit_code = 128 + int(pending_signal)
                if state_loaded and review is not None:
                    exit_error = _write_loaded_review_text(
                        state_dir,
                        review,
                        name=EXIT_FILE,
                        text=f"{exit_code}\n",
                    )
                    if exit_error:
                        print(
                            f"review runner exit code was not persisted: {exit_error}",
                            file=sys.stderr,
                        )
                if previous_mask is None:
                    break
                pending_signal = consume_pending_forwarded_signal()
                if pending_signal is None:
                    break
            if not terminal_process:
                for forwarded, previous in previous_handlers.items():
                    signal.signal(forwarded, previous)
        finally:
            if not terminal_process:
                restore_signal_mask(previous_mask)
    return exit_code


def status(state_dir: pathlib.Path) -> dict[str, Any]:
    state_dir = state_dir.expanduser().resolve()
    state, review = load_review_state(state_dir)
    pid_value = state.get("pid")
    pid = pid_value if isinstance(pid_value, int) else 0
    process_running = _runner_lock_held(state_dir / LOCK_FILE)
    running = process_running
    if running:
        exit_code = None
    else:
        exit_code = _read_exit_code(state_dir)
        if exit_code is not None:
            _reap_started_process(pid)
    if exit_code is None and not running:
        exit_code = 1
        exit_error = _write_loaded_review_text(
            state_dir,
            review,
            name=EXIT_FILE,
            text="1\n",
        )
        diagnostic_error = _write_loaded_review_text(
            state_dir,
            review,
            name="runner-error.txt",
            text="review runner exited without recording a terminal result\n",
        )
        if exit_error or diagnostic_error:
            raise ReviewError(
                "cannot persist missing runner terminal state: "
                + "; ".join(error for error in (exit_error, diagnostic_error) if error)
            )
    fallback_workspace_retained = not running and _should_retain_fallback_workspace(
        state_dir=state_dir,
        state=state,
        review=review,
        exit_code=exit_code,
    )
    attempts: list[Any] = []
    attempts_path = state_dir / "attempts.json"
    if attempts_path.is_file():
        try:
            parsed_attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parsed_attempts = []
        if isinstance(parsed_attempts, list):
            for item in parsed_attempts:
                if not isinstance(item, dict):
                    continue
                summary = dict(item)
                legacy_final = summary.pop("final_text", None)
                if legacy_final is not None:
                    summary["final_available"] = bool(legacy_final)
                attempts.append(summary)
    return {
        "state_dir": str(state_dir),
        "reviewer": state.get("reviewer"),
        "egress_consent": state.get("egress_consent"),
        "pid": pid or None,
        "runner_lock_held": process_running,
        "running": running,
        "exit_code": exit_code,
        "fallback_workspace_retained": fallback_workspace_retained,
        "fallback_workspace": (
            str(review.workspace_root) if fallback_workspace_retained else ""
        ),
        "attempts": attempts,
        "stdout_tail": tail_text(state_dir / "runner.stdout.log"),
        "stderr_tail": tail_text(state_dir / "runner.stderr.log"),
        "runner_error": tail_text(state_dir / "runner-error.txt"),
        "cleanup_error": tail_text(state_dir / "cleanup-error.txt"),
    }


def _should_retain_fallback_workspace(
    *,
    state_dir: pathlib.Path,
    state: dict[str, Any],
    review: ReviewWorkspace | LegacyReviewWorkspace,
    exit_code: int | None,
) -> bool:
    if (
        state.get("reviewer") != "codex"
        or exit_code != 127
        or not review.workspace_root.is_dir()
    ):
        return False
    try:
        preflight = _read_bounded_json(
            state_dir / "preflight.json",
            label="retained fallback preflight evidence",
            max_bytes=MAX_PREFLIGHT_JSON_BYTES,
        )
        if preflight.get("review_range") != f"{review.base_ref}..{review.head_ref}":
            return False
        if isinstance(review, LegacyReviewWorkspace):
            return (
                preflight.get("status")
                == "sensitive-content and escaping-symlink checks passed"
            )
        if (
            preflight.get("private_artifacts") != "removed"
            or preflight.get("status")
            != "secret-delta and escaping-symlink checks passed"
        ):
            return False
        primary_diff = preflight.get("primary_diff")
        if (
            not isinstance(primary_diff, dict)
            or set(primary_diff) != {"path", "sha256", "size"}
            or primary_diff.get("path") != PRIMARY_DIFF_RELATIVE_PATH
            or type(primary_diff.get("size")) is not int
            or primary_diff["size"] < 0
            or not isinstance(primary_diff.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", primary_diff["sha256"]) is None
        ):
            return False

        expected_diff_path = review.workspace_root / PRIMARY_DIFF_RELATIVE_PATH
        if review.diff_file != expected_diff_path:
            return False
        control_state = _load_control_artifact_state(container_dir=state_dir)
        expected_diff = control_state.artifacts["review.diff"]
        if (
            primary_diff["size"] != expected_diff.size
            or primary_diff["sha256"] != expected_diff.sha256
        ):
            return False
        control_dir = review.workspace_root / ".codex-review"
        _inspect_control_directory(control_dir, expected=control_state.directory)
        flags = (
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(expected_diff_path, flags)
        except OSError as error:
            raise ReviewError(
                f"cannot open retained fallback primary diff safely: {error}"
            ) from error
        try:
            _validate_regular_file_path_identity(
                expected_diff_path,
                descriptor,
                label="retained fallback primary diff",
                expected_size=expected_diff.size,
            )
        finally:
            os.close(descriptor)
        _inspect_control_directory(control_dir, expected=control_state.directory)
        cleanup_state = load_bound_private_cleanup_state(
            review.container_dir,
            expected=review.private_cleanup,
        )
    except ReviewError:
        return False
    # This synchronous status path intentionally validates only bounded metadata.
    # The actual fallback consumer must supervise a complete read and verify the
    # primary diff SHA-256 against both attestations before using any diff bytes.
    return cleanup_state.private_artifacts_removed == frozenset(
        PRIVATE_HELPER_ARTIFACT_NAMES
    )


def _validate_timeout(timeout_seconds: float | None) -> None:
    if timeout_seconds is not None and (
        not math.isfinite(timeout_seconds) or timeout_seconds < 0
    ):
        raise ReviewError("wait timeout must be a non-negative finite number")


def wait(
    state_dir: pathlib.Path,
    *,
    timeout_seconds: float | None,
) -> int:
    _validate_timeout(timeout_seconds)
    state_dir = state_dir.expanduser().resolve()
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    while True:
        summary = status(state_dir)
        if not summary["running"]:
            break
        if deadline is not None and time.monotonic() >= deadline:
            return 124
        remaining = None if deadline is None else deadline - time.monotonic()
        time.sleep(0.25 if remaining is None else min(0.25, max(0.0, remaining)))

    cleanup_code = _cleanup_terminal_workspace(
        state_dir,
        deadline=deadline,
        force=False,
    )
    if cleanup_code != 0:
        return cleanup_code
    exit_code = _read_exit_code(state_dir)
    return 1 if exit_code is None else exit_code


def cleanup(state_dir: pathlib.Path, *, timeout_seconds: float | None) -> int:
    _validate_timeout(timeout_seconds)
    state_dir = state_dir.expanduser().resolve()
    _state_path(state_dir)
    if _runner_lock_held(state_dir / LOCK_FILE):
        return 3
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    return _cleanup_terminal_workspace(state_dir, deadline=deadline, force=True)


@contextmanager
def _open_cleanup_locks(
    state_dir: pathlib.Path,
    marker: LoadedStateMarker,
) -> Iterator[tuple[_CleanupLockSet, pathlib.Path, int, Callable[[], None]]]:
    cleanup_lock_name = pathlib.Path(CLEANUP_LOCK_FILE)
    with _open_private_cleanup_state_directory(state_dir) as (
        state_dir_fd,
        revalidate_state_directory,
    ):
        if marker.private_cleanup is not None:
            metadata = os.fstat(state_dir_fd)
            actual_identity = CleanupIdentity(metadata.st_dev, metadata.st_ino)
            if actual_identity != marker.private_cleanup.container:
                raise ReviewError(
                    "cannot open preparation-bound cleanup lock: private artifact "
                    "container does not match preparation identity"
                )
            container_lock, lock_error = open_bound_review_lock(
                state_dir,
                expected=marker.private_cleanup,
                name=CLEANUP_LOCK_FILE,
            )
            if lock_error or container_lock is None:
                raise ReviewError(
                    "cannot open preparation-bound cleanup lock: "
                    f"{lock_error or 'lock handle is unavailable'}"
                )
        else:
            try:
                container_lock = BoundReviewLock(os.dup(state_dir_fd))
            except OSError as error:
                raise ReviewError(
                    f"cannot duplicate legacy cleanup directory lock: {error}"
                ) from error
        try:
            with open_private_lock_file(
                cleanup_lock_name,
                label="review cleanup lock",
                allow_legacy_read_mode=True,
                allowed_legacy_modes=PRIVATE_STATE_LEGACY_LOCK_MODES,
                dir_fd=state_dir_fd,
            ) as compatibility_lock:
                yield (
                    _CleanupLockSet(container_lock, compatibility_lock),
                    cleanup_lock_name,
                    state_dir_fd,
                    revalidate_state_directory,
                )
        finally:
            container_lock.close()


def _cleanup_terminal_workspace(
    state_dir: pathlib.Path,
    *,
    deadline: float | None,
    force: bool,
) -> int:
    marker = _load_state_marker(state_dir)
    with _open_cleanup_locks(state_dir, marker) as (
        cleanup_lock,
        cleanup_lock_name,
        state_dir_fd,
        revalidate_state_directory,
    ):
        if not _acquire_cleanup_lock(cleanup_lock, deadline=deadline):
            return 124
        revalidate_state_directory()
        cleanup_lock_transferred = False

        def transfer_cleanup_lock() -> None:
            nonlocal cleanup_lock_transferred
            cleanup_lock_transferred = True

        try:
            locked_metadata = validate_safe_legacy_lock_file(
                cleanup_lock_name,
                cleanup_lock.compatibility,
                label="review cleanup lock",
                allowed_modes=PRIVATE_STATE_LEGACY_LOCK_MODES,
                dir_fd=state_dir_fd,
            )
            if stat.S_IMODE(locked_metadata.st_mode) != 0o600:
                os.fchmod(cleanup_lock.fileno(), 0o600)
                os.fsync(cleanup_lock.fileno())
            validate_private_lock_file(
                cleanup_lock_name,
                cleanup_lock.compatibility,
                label="review cleanup lock",
                dir_fd=state_dir_fd,
            )
            revalidate_state_directory()
            if force and _runner_lock_held(state_dir / LOCK_FILE):
                return 3
            try:
                state, review = load_review_state(state_dir)
            except ReviewError as state_error:
                if not force or not (state_dir / STATE_MARKER).is_file():
                    raise
                try:
                    marker = _load_state_marker(state_dir)
                except ReviewError as marker_error:
                    raise ReviewError(
                        f"{state_error}; private artifact cleanup identity failed: "
                        f"{marker_error}"
                    ) from state_error
                state_path = state_dir / STATE_FILE
                if (
                    marker.version == STATE_MARKER_SCHEMA_VERSION
                    and marker.phase == "preparing"
                    and marker.private_cleanup is not None
                    and not os.path.lexists(state_path)
                ):
                    partial_cleanup_error = remove_partial_review_container(
                        state_dir,
                        expected=marker.private_cleanup,
                    )
                    if partial_cleanup_error:
                        raise ReviewError(
                            f"{state_error}; partial container cleanup failed: "
                            f"{partial_cleanup_error}"
                        ) from state_error
                    return 0
                if (
                    marker.version == STATE_MARKER_SCHEMA_VERSION
                    and marker.phase == "ready"
                    and marker.private_cleanup is not None
                    and not os.path.lexists(state_path)
                ):
                    ready_cleanup_error = remove_ready_review_container(
                        state_dir,
                        expected=marker.private_cleanup,
                    )
                    if ready_cleanup_error:
                        raise ReviewError(
                            f"{state_error}; ready container cleanup failed: "
                            f"{ready_cleanup_error}"
                        ) from state_error
                    return 0
                if marker.version == LEGACY_STATE_SCHEMA_VERSION:
                    raise ReviewError(
                        f"{state_error}; legacy v1 state requires manual recovery"
                    ) from state_error
                if marker.phase != "ready" or marker.private_cleanup is None:
                    raise
                private_cleanup_error = remove_private_review_artifacts(
                    state_dir,
                    expected=marker.private_cleanup,
                )
                if private_cleanup_error:
                    raise ReviewError(
                        f"{state_error}; private artifact cleanup failed: "
                        f"{private_cleanup_error}"
                    ) from state_error
                raise
            keep_workspace = bool(state.get("keep_workspace"))
            exit_code = _read_exit_code(state_dir)
            retain_for_fallback = _should_retain_fallback_workspace(
                state_dir=state_dir,
                state=state,
                review=review,
                exit_code=exit_code,
            )
            should_keep = not force and (keep_workspace or retain_for_fallback)
            if should_keep:
                if isinstance(review, LegacyReviewWorkspace):
                    cleanup_error = remove_legacy_private_review_artifacts(review)
                else:
                    cleanup_error = remove_private_review_artifacts(
                        review.container_dir,
                        expected=review.private_cleanup,
                    )
                cleanup_completed = True
            else:
                cleanup_completed, cleanup_error = _cleanup_before_deadline(
                    review,
                    deadline=deadline,
                    cleanup_lock_fds=_cleanup_lock_fds(cleanup_lock),
                    lock_handoff=transfer_cleanup_lock,
                )
            if not cleanup_completed:
                return 124
            if cleanup_error:
                diagnostic_error = _write_loaded_review_text(
                    state_dir,
                    review,
                    name="cleanup-error.txt",
                    text=cleanup_error + "\n",
                )
                if diagnostic_error:
                    raise ReviewError(
                        "cleanup failed and its diagnostic was not persisted: "
                        f"{cleanup_error}; {diagnostic_error}"
                    )
                return 1
            diagnostic_error = _remove_loaded_review_text(
                state_dir,
                review,
                name="cleanup-error.txt",
            )
            if diagnostic_error:
                raise ReviewError(
                    f"cannot clear resolved cleanup error: {diagnostic_error}"
                )
            return 0
        finally:
            if not cleanup_lock_transferred:
                for descriptor in reversed(_cleanup_lock_fds(cleanup_lock)):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _cleanup_lock_fds(handle) -> tuple[int, ...]:
    if isinstance(handle, (BoundReviewLock, _CleanupLockSet)):
        return handle.filenos()
    return (handle.fileno(),)


def _acquire_cleanup_lock(handle, *, deadline: float | None) -> bool:
    if isinstance(handle, BoundReviewLock):
        primary_descriptor = handle.fileno()
        if not _acquire_cleanup_lock_descriptor(
            primary_descriptor,
            deadline=deadline,
        ):
            return False
        acquired = [primary_descriptor]
        compatibility_error = handle.open_compatibility_lock(CLEANUP_LOCK_FILE)
        if compatibility_error:
            fcntl.flock(primary_descriptor, fcntl.LOCK_UN)
            raise ReviewError(
                "cannot open preparation-bound cleanup compatibility lock: "
                f"{compatibility_error}"
            )
        descriptors = list(handle.filenos()[1:])
    else:
        acquired = []
        descriptors = list(_cleanup_lock_fds(handle))
    for descriptor in descriptors:
        if _acquire_cleanup_lock_descriptor(descriptor, deadline=deadline):
            acquired.append(descriptor)
            continue
        for acquired_descriptor in reversed(acquired):
            fcntl.flock(acquired_descriptor, fcntl.LOCK_UN)
        return False
    return True


def _acquire_cleanup_lock_descriptor(
    descriptor: int,
    *,
    deadline: float | None,
) -> bool:
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            remaining = None if deadline is None else deadline - time.monotonic()
            time.sleep(0.05 if remaining is None else min(0.05, max(0.0, remaining)))


def _cleanup_review_workspace(
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    keep_container: bool,
) -> str | None:
    if isinstance(review, LegacyReviewWorkspace):
        return cleanup_legacy_workspace(review, keep_container=keep_container)
    return cleanup_workspace(review, keep_container=keep_container)


def _cleanup_before_deadline(
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    deadline: float | None,
    cleanup_lock_fds: tuple[int, ...],
    lock_handoff: Callable[[], None],
) -> tuple[bool, str | None]:
    if deadline is None:
        return True, _cleanup_review_workspace(review, keep_container=True)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False, None
    worker_path = pathlib.Path(__file__).resolve().with_name("cleanup_worker.py")
    handoff_mask = block_forwarded_signals()
    try:
        try:
            worker = subprocess.Popen(
                (
                    sys.executable,
                    str(worker_path),
                    str(review.container_dir),
                    *(str(descriptor) for descriptor in cleanup_lock_fds),
                ),
                close_fds=True,
                pass_fds=cleanup_lock_fds,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            return True, f"cannot start bounded cleanup worker: {error}"
        lock_handoff()
    finally:
        restore_signal_mask(handoff_mask)

    while True:
        returncode = worker.poll()
        if returncode is not None:
            if returncode == 0:
                return True, None
            cleanup_error = tail_text(review.container_dir / "cleanup-error.txt")
            return (
                True,
                cleanup_error or "cleanup worker exited without completing",
            )
        if time.monotonic() >= deadline:
            threading.Thread(
                target=worker.wait,
                daemon=True,
            ).start()
            return False, None
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def final(state_dir: pathlib.Path) -> tuple[int, str]:
    summary = status(state_dir)
    if summary["running"]:
        return 3, "review is still running"
    wait_code = wait(state_dir, timeout_seconds=FINAL_CLEANUP_TIMEOUT_SECONDS)
    if wait_code == 124:
        return 3, "review completed but workspace cleanup did not finish before timeout"
    cleanup_error = tail_text(state_dir.expanduser().resolve() / "cleanup-error.txt")
    if cleanup_error:
        return 1, f"review completed but workspace cleanup failed: {cleanup_error}"
    summary = status(state_dir)
    exit_code = summary["exit_code"]
    final_path = state_dir.expanduser().resolve() / "final.txt"
    if exit_code == 0 and final_path.is_file():
        text = final_path.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            return 0, text
    details = (
        summary.get("runner_error")
        or summary.get("stderr_tail")
        or "review failed without a final artifact"
    )
    if summary.get("fallback_workspace_retained"):
        details = (
            f"{details}\nfrozen workspace retained for clean-context fallback: "
            f"{summary['fallback_workspace']}"
        )
    return int(wait_code or exit_code or 1), str(details)
