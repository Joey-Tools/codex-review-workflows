from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Iterator

from .common import (
    PROCESS_GROUP_TERM_GRACE_SECONDS,
    ForwardedSignal,
    ReviewError,
    atomic_write_redactions,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    read_json,
    redact_json_string_values,
    redact_text,
    restore_signal_mask,
    signal_process_group,
    tail_text,
    terminate_process_group,
    unblock_forwarded_signals,
    write_json,
    write_text_atomic,
)
from .providers import (
    CLAUDE_EGRESS_CONSENTS,
    CLAUDE_EXPLICIT_AUTH_ENV_KEYS,
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    claude_output_redact_values,
    run_review,
)
from .workspace import (
    MAX_BOUNDED_JSON_DEPTH,
    MAX_PREFLIGHT_JSON_BYTES,
    REVIEW_CONTAINER_PATTERN,
    REVIEW_USER_ROOT_PREFIX,
    PRIVATE_HELPER_ARTIFACT_NAMES,
    REVIEW_CLEANUP_LOCK_NAME,
    REVIEW_RUNNER_LOCK_NAME,
    REVIEW_STATE_MARKER_NAME,
    BoundReviewLock,
    CleanupIdentity,
    LegacyReviewWorkspace,
    PrivateCleanupEvidence,
    ReviewWorkspace,
    SourceLocalReviewWorkspace,
    _canonical_review_root_base,
    _review_root_for_source,
    _inspect_control_directory,
    _load_control_artifact_state,
    _read_bounded_json,
    _validate_bounded_json_depth,
    cleanup_legacy_workspace,
    cleanup_workspace,
    load_bound_private_cleanup_state,
    open_bound_review_lock,
    parse_partial_private_cleanup_evidence,
    parse_private_cleanup_evidence,
    prepare_workspace,
    remove_bound_review_text,
    remove_legacy_private_review_artifacts,
    remove_partial_review_container,
    remove_private_review_artifacts,
    remove_ready_review_container,
    review_preflight_scope,
    validate_secret_delta_summary,
    validate_retained_cleanup_postcondition,
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
PREVIOUS_STATE_MARKER_SCHEMA_VERSION = 3
BOUND_STATE_MARKER_SCHEMA_VERSION = 4
STATE_MARKER_SCHEMA_VERSION = 5
MAX_STATE_MARKER_BYTES = 64 * 1024
MAX_FINAL_ARTIFACT_BYTES = 64 * 1024 * 1024
ADMISSION_SCHEMA_VERSION = 1
PREFLIGHT_RECEIPT_SCHEMA_VERSION = 1
PREFLIGHT_RECEIPT_ALGORITHM = "sha256"
PREFLIGHT_FILE = "preflight.json"
PREFLIGHT_STATUS = "review workspace containment and integrity checks passed"
PREFLIGHT_PRIVATE_ARTIFACTS = "removed"
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
_STATE_OWNED_TEXT_ARTIFACTS = (
    STATE_MARKER,
    STATE_FILE,
    EXIT_FILE,
    "attempts.json",
    "claude-runtime.json",
    "claude-skip.txt",
    "egress.json",
    "final.txt",
    "preflight.json",
    "runner.stdout.log",
    "runner.stderr.log",
    "runner-error.txt",
    "cleanup-error.txt",
)
_STATE_OWNED_TEXT_ARTIFACT_NAMES = frozenset(_STATE_OWNED_TEXT_ARTIFACTS)


def _state_owned_write_filter(
    state_dir: pathlib.Path,
) -> Callable[[pathlib.Path], bool]:
    try:
        root = state_dir.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewError(
            f"cannot resolve isolated-review state directory {state_dir}: {error}"
        ) from error
    if not root.is_dir():
        raise ReviewError(f"isolated-review state path is not a directory: {root}")

    def includes(path: pathlib.Path) -> bool:
        candidate = path.expanduser()
        try:
            parent = candidate.parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ReviewError(
                f"cannot resolve atomic write parent {candidate.parent}: {error}"
            ) from error
        return parent == root and candidate.name in _STATE_OWNED_TEXT_ARTIFACT_NAMES

    return includes


def _freeze_claude_redactions(
    environment: Mapping[str, str] | None = None,
    *,
    reviewer: str | None = "claude",
) -> tuple[str, ...]:
    source = os.environ if environment is None else environment
    if reviewer != "claude":
        source = {
            key: value
            for key, value in source.items()
            if key not in CLAUDE_EXPLICIT_AUTH_ENV_KEYS
        }
    return claude_output_redact_values(source)


def _redact_claude_text(text: str, redact_values: tuple[str, ...]) -> str:
    return redact_text(text, redact_values)


def _redacted_exception_detail(
    error: BaseException,
    redact_values: tuple[str, ...],
) -> str:
    details: list[str] = []
    seen: set[int] = set()

    def visit(current: BaseException, relation: str) -> None:
        identity = id(current)
        if identity in seen:
            details.append(f"{relation}<exception cycle>")
            return
        if len(seen) >= 32:
            details.append(f"{relation}<exception chain truncated>")
            return
        seen.add(identity)
        try:
            message = str(current)
        except Exception:
            message = "<unprintable exception>"
        label = f"{type(current).__name__}: {message}"
        details.append(relation + _redact_claude_text(label, redact_values))
        cause = current.__cause__
        context = current.__context__
        if cause is not None:
            visit(cause, "caused by ")
        elif context is not None and not current.__suppress_context__:
            visit(context, "context: ")

    visit(error, "")
    return "; ".join(details)


def _redact_claude_value(value: Any, redact_values: tuple[str, ...]) -> Any:
    return redact_json_string_values(value, redact_values)


def _write_state_json_without_credentials(
    path: pathlib.Path,
    value: dict[str, Any],
    redact_values: tuple[str, ...],
) -> None:
    if redact_json_string_values(value, redact_values) != value:
        raise ReviewError(
            "review state metadata contains an explicit Claude credential"
        )
    write_json(path, value)


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
class PreflightReceipt:
    schema_version: int
    algorithm: str
    size: int
    sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class LoadedStateMarker:
    version: int
    phase: str
    private_cleanup: PrivateCleanupEvidence | None
    runner_lock: CleanupIdentity | None
    source_root: pathlib.Path | None
    preflight_receipt: PreflightReceipt | None
    preflight_receipt_error: str | None = None


class _CleanupLockSet:
    def __init__(
        self,
        container: BoundReviewLock,
        compatibility_opener: Callable[[], BinaryIO],
    ) -> None:
        self.container = container
        self._compatibility_opener = compatibility_opener
        self._compatibility: BinaryIO | None = None

    @property
    def compatibility(self) -> BinaryIO:
        if self._compatibility is None:
            raise ReviewError("review cleanup compatibility lock is not open")
        return self._compatibility

    def open_compatibility(self) -> None:
        if self._compatibility is None:
            self._compatibility = self._compatibility_opener()

    def fileno(self) -> int:
        return self.compatibility.fileno()

    def filenos(self) -> tuple[int, ...]:
        return (*self.container.filenos(), self.compatibility.fileno())

    def close(self) -> None:
        first_error: OSError | None = None
        if self._compatibility is not None:
            try:
                self._compatibility.close()
            except OSError as error:
                first_error = error
            self._compatibility = None
        try:
            self.container.close()
        except OSError as error:
            if first_error is None:
                first_error = error
        if first_error is not None:
            raise first_error


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
        # A no-op chmod still changes ctime and can race another first opener's
        # path/descriptor identity validation.
        if created and stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
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
    # Directory contents may legitimately change while cleanup waiters race to
    # create the lock or remove a workspace. Bind the open descriptor to the
    # same directory and its safety metadata, not content-derived timestamps
    # or link counts.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _validate_private_directory_path_identity(
    path: pathlib.Path,
    descriptor: int,
    *,
    label: str,
    expected_mode: int | None = None,
    expected_uid: int | None = None,
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
    owner_uid = os.geteuid() if expected_uid is None else expected_uid
    if descriptor_after.st_uid != owner_uid:
        raise ReviewError(f"{label} has an unexpected owner")
    mode = stat.S_IMODE(descriptor_after.st_mode)
    if expected_mode is not None:
        if mode != expected_mode:
            raise ReviewError(f"{label} mode must be exactly {expected_mode:04o}")
    elif descriptor_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReviewError(f"{label} must not be group or other writable")


@contextmanager
def _open_external_cleanup_state_directory(
    state_dir: pathlib.Path,
) -> Iterator[tuple[int, Callable[[], None]]]:
    source_review_root = state_dir.parent
    user_review_root = source_review_root.parent
    review_root_base = user_review_root.parent
    canonical_base = _canonical_review_root_base()
    if (
        review_root_base != canonical_base
        or user_review_root.name != f"{REVIEW_USER_ROOT_PREFIX}{os.geteuid()}"
        or re.fullmatch(r"[0-9a-f]{64}", source_review_root.name) is None
        or REVIEW_CONTAINER_PATTERN.fullmatch(state_dir.name) is None
    ):
        raise ReviewError("review state directory is outside a private review root")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    review_root_base_fd: int | None = None
    user_review_root_fd: int | None = None
    source_review_root_fd: int | None = None
    state_dir_fd: int | None = None
    try:
        review_root_base_fd = os.open(canonical_base, flags)
        user_review_root_fd = os.open(
            user_review_root.name,
            flags,
            dir_fd=review_root_base_fd,
        )
        source_review_root_fd = os.open(
            source_review_root.name,
            flags,
            dir_fd=user_review_root_fd,
        )
        state_dir_fd = os.open(
            state_dir.name,
            flags,
            dir_fd=source_review_root_fd,
        )

        def revalidate() -> None:
            assert review_root_base_fd is not None
            assert user_review_root_fd is not None
            assert source_review_root_fd is not None
            assert state_dir_fd is not None
            _validate_private_directory_path_identity(
                canonical_base,
                review_root_base_fd,
                label="review state base root",
                expected_mode=0o1777,
                expected_uid=0,
            )
            _validate_private_directory_path_identity(
                pathlib.Path(user_review_root.name),
                user_review_root_fd,
                label="review state user root",
                expected_mode=0o700,
                dir_fd=review_root_base_fd,
            )
            _validate_private_directory_path_identity(
                pathlib.Path(source_review_root.name),
                source_review_root_fd,
                label="review state source root",
                expected_mode=0o700,
                dir_fd=user_review_root_fd,
            )
            _validate_private_directory_path_identity(
                pathlib.Path(state_dir.name),
                state_dir_fd,
                label="review state directory",
                expected_mode=0o700,
                dir_fd=source_review_root_fd,
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
        if source_review_root_fd is not None:
            os.close(source_review_root_fd)
        if user_review_root_fd is not None:
            os.close(user_review_root_fd)
        if review_root_base_fd is not None:
            os.close(review_root_base_fd)


@contextmanager
def _open_legacy_cleanup_state_directory(
    state_dir: pathlib.Path,
) -> Iterator[tuple[int, Callable[[], None]]]:
    review_root = state_dir.parent
    if (
        review_root.name != ".codex-tmp"
        or REVIEW_CONTAINER_PATTERN.fullmatch(state_dir.name) is None
    ):
        raise ReviewError("legacy review state directory has an invalid layout")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    review_root_fd: int | None = None
    state_dir_fd: int | None = None
    try:
        review_root_fd = os.open(review_root, flags)
        state_dir_fd = os.open(
            state_dir.name,
            flags,
            dir_fd=review_root_fd,
        )

        def revalidate() -> None:
            assert review_root_fd is not None
            assert state_dir_fd is not None
            _validate_private_directory_path_identity(
                review_root,
                review_root_fd,
                label="legacy review state root",
            )
            _validate_private_directory_path_identity(
                pathlib.Path(state_dir.name),
                state_dir_fd,
                label="legacy review state directory",
                expected_mode=0o700,
                dir_fd=review_root_fd,
            )

        revalidate()
        yield state_dir_fd, revalidate
    except OSError as error:
        raise ReviewError(
            f"cannot open legacy review state directory safely: {error}"
        ) from error
    finally:
        if state_dir_fd is not None:
            os.close(state_dir_fd)
        if review_root_fd is not None:
            os.close(review_root_fd)


def _open_private_cleanup_state_directory(
    state_dir: pathlib.Path,
    *,
    legacy: bool | None = None,
):
    if legacy is None:
        legacy = state_dir.parent.name == ".codex-tmp"
    if legacy:
        return _open_legacy_cleanup_state_directory(state_dir)
    return _open_external_cleanup_state_directory(state_dir)


def _state_path(state_dir: pathlib.Path) -> pathlib.Path:
    state_dir = state_dir.expanduser().resolve()
    marker = state_dir / STATE_MARKER
    if not marker.is_file():
        raise ReviewError(f"not an isolated-review state directory: {state_dir}")
    return state_dir / STATE_FILE


def _state_marker_payload(
    review: ReviewWorkspace,
    runner_lock: CleanupIdentity,
    *,
    preflight_receipt: PreflightReceipt | None = None,
) -> dict[str, Any]:
    return {
        "container_dir": str(review.container_dir),
        "phase": "ready",
        "preflight_receipt": (
            preflight_receipt.to_json() if preflight_receipt is not None else None
        ),
        "private_cleanup": review.private_cleanup.to_json(),
        "runner_lock": runner_lock.to_json(),
        "source_root": str(review.source_root),
        "version": STATE_MARKER_SCHEMA_VERSION,
    }


def _preparing_state_marker_payload(
    container: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
    runner_lock: CleanupIdentity,
) -> dict[str, Any]:
    return {
        "container_dir": str(container),
        "phase": "preparing",
        "preflight_receipt": None,
        "private_cleanup": private_cleanup.to_json(),
        "runner_lock": runner_lock.to_json(),
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
    runner_lock: CleanupIdentity,
) -> None:
    _write_state_marker_payload(
        container,
        _preparing_state_marker_payload(container, private_cleanup, runner_lock),
        expected=private_cleanup,
    )


def _write_state_marker(
    review: ReviewWorkspace,
    runner_lock: CleanupIdentity,
    *,
    preflight_receipt: PreflightReceipt | None = None,
) -> None:
    _write_state_marker_payload(
        review.container_dir,
        _state_marker_payload(
            review,
            runner_lock,
            preflight_receipt=preflight_receipt,
        ),
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
            try:
                validate_private_lock_file(
                    lock_path,
                    self._lock_handle,
                    label="workspace preparation lock",
                )
            except ReviewError as error:
                raise ReviewError(
                    f"workspace preparation lock changed during handoff: {error}"
                ) from error
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
            os.fchmod(descriptor, 0o600)
            candidate = os.fdopen(descriptor, "w+b")
            descriptor = None
            validate_private_lock_file(
                lock_path,
                candidate,
                label="workspace preparation lock",
            )
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
        _write_preparing_state_marker(
            container,
            private_cleanup,
            self._runner_lock_identity(),
        )

    def accept_workspace(self, prepared: ReviewWorkspace) -> None:
        if self._lock_handle is None:
            self.accept_preparation_cleanup(
                prepared.container_dir,
                prepared.private_cleanup,
            )
        else:
            self._ensure_lock(prepared.container_dir)
        _write_state_marker(prepared, self._runner_lock_identity())
        self._review = prepared

    def _runner_lock_identity(self) -> CleanupIdentity:
        if self._lock_handle is None:
            raise ReviewError("workspace preparation lock handoff did not complete")
        metadata = os.fstat(self._lock_handle.fileno())
        return CleanupIdentity(metadata.st_dev, metadata.st_ino)

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


class _MarkerObject(dict[str, Any]):
    duplicate_fields: frozenset[str]


@dataclass(frozen=True)
class _RawMarkerJsonValue:
    encoded: str
    max_container_depth: int


def _capture_duplicate_marker_object(
    pairs: list[tuple[str, Any]],
) -> _MarkerObject:
    value = _MarkerObject()
    duplicates: set[str] = set()
    for key, item in pairs:
        if key in value:
            duplicates.add(key)
        value[key] = item
    value.duplicate_fields = frozenset(duplicates)
    return value


def _first_duplicate_marker_field(value: Any) -> str | None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, _MarkerObject):
            if current.duplicate_fields:
                return sorted(current.duplicate_fields)[0]
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return None


def _skip_marker_json_whitespace(encoded: str, offset: int) -> int:
    while offset < len(encoded) and encoded[offset] in " \t\r\n":
        offset += 1
    return offset


def _scan_marker_json_string_end(encoded: str, offset: int) -> int:
    if offset >= len(encoded) or encoded[offset] != '"':
        raise ValueError("expected a JSON string")
    offset += 1
    while offset < len(encoded):
        character = encoded[offset]
        if character == '"':
            return offset + 1
        if character == "\\":
            offset += 2
        else:
            offset += 1
    raise ValueError("unterminated JSON string")


def _scan_marker_json_value_end(encoded: str, offset: int) -> tuple[int, int]:
    offset = _skip_marker_json_whitespace(encoded, offset)
    if offset >= len(encoded):
        raise ValueError("missing JSON value")
    character = encoded[offset]
    if character == '"':
        return _scan_marker_json_string_end(encoded, offset), -1
    if character in "{[":
        delimiters = [character]
        max_depth = 0
        offset += 1
        while offset < len(encoded):
            character = encoded[offset]
            if character == '"':
                offset = _scan_marker_json_string_end(encoded, offset)
                continue
            if character in "{[":
                delimiters.append(character)
                max_depth = max(max_depth, len(delimiters) - 1)
            elif character in "}]":
                expected = "}" if delimiters[-1] == "{" else "]"
                if character != expected:
                    raise ValueError("mismatched JSON container")
                delimiters.pop()
                if not delimiters:
                    return offset + 1, max_depth
            offset += 1
        raise ValueError("unterminated JSON container")
    if character in ",}]":
        raise ValueError("missing JSON value")
    start = offset
    while offset < len(encoded) and encoded[offset] not in " \t\r\n,}]":
        offset += 1
    if offset == start:
        raise ValueError("missing JSON value")
    return offset, -1


def _isolate_preflight_receipt_json(
    encoded: str,
) -> tuple[str, tuple[_RawMarkerJsonValue, ...]]:
    offset = _skip_marker_json_whitespace(encoded, 0)
    if offset >= len(encoded) or encoded[offset] != "{":
        raise ValueError("state marker root is not a JSON object")
    offset += 1
    spans: list[tuple[int, int, _RawMarkerJsonValue]] = []
    offset = _skip_marker_json_whitespace(encoded, offset)
    if offset < len(encoded) and encoded[offset] == "}":
        offset += 1
    else:
        while True:
            offset = _skip_marker_json_whitespace(encoded, offset)
            key_start = offset
            key_end = _scan_marker_json_string_end(encoded, key_start)
            try:
                key = json.loads(encoded[key_start:key_end])
            except (json.JSONDecodeError, OverflowError, ValueError) as error:
                raise ValueError("invalid JSON object key") from error
            offset = _skip_marker_json_whitespace(encoded, key_end)
            if offset >= len(encoded) or encoded[offset] != ":":
                raise ValueError("missing JSON object colon")
            value_start = _skip_marker_json_whitespace(encoded, offset + 1)
            value_end, max_depth = _scan_marker_json_value_end(
                encoded,
                value_start,
            )
            if key == "preflight_receipt":
                raw_value = encoded[value_start:value_end]
                spans.append(
                    (
                        value_start,
                        value_end,
                        _RawMarkerJsonValue(raw_value, max_depth),
                    )
                )
            offset = _skip_marker_json_whitespace(encoded, value_end)
            if offset >= len(encoded):
                raise ValueError("unterminated JSON object")
            if encoded[offset] == "}":
                offset += 1
                break
            if encoded[offset] != ",":
                raise ValueError("invalid JSON object separator")
            offset += 1
    if _skip_marker_json_whitespace(encoded, offset) != len(encoded):
        raise ValueError("unexpected data after JSON object")

    chunks: list[str] = []
    previous_end = 0
    for start, end, raw_value in spans:
        chunks.append(encoded[previous_end:start])
        chunks.append("null" if raw_value.encoded == "null" else "false")
        previous_end = end
    chunks.append(encoded[previous_end:])
    return "".join(chunks), tuple(value for _, _, value in spans)


def _parse_isolated_preflight_receipt_json(raw: _RawMarkerJsonValue) -> Any:
    label = "isolated-review preflight receipt"
    if raw.max_container_depth > MAX_BOUNDED_JSON_DEPTH:
        raise ReviewError(f"{label} exceeds the JSON nesting depth limit")
    try:
        value = json.loads(
            raw.encoded,
            object_pairs_hook=_capture_duplicate_marker_object,
        )
    except RecursionError as error:
        raise ReviewError(f"{label} exceeds the JSON nesting depth limit") from error
    except (json.JSONDecodeError, OverflowError, ValueError) as error:
        raise ReviewError(f"{label} is not valid JSON") from error
    _validate_bounded_json_depth(value, label=label)
    return value


def _parse_preflight_receipt(value: Any) -> PreflightReceipt:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "schema_version",
        "sha256",
        "size",
    }:
        raise ReviewError("isolated-review preflight receipt fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PREFLIGHT_RECEIPT_SCHEMA_VERSION
    ):
        raise ReviewError("isolated-review preflight receipt version is invalid")
    if value["algorithm"] != PREFLIGHT_RECEIPT_ALGORITHM:
        raise ReviewError("isolated-review preflight receipt algorithm is invalid")
    size = value["size"]
    if type(size) is not int or size < 0 or size > MAX_PREFLIGHT_JSON_BYTES:
        raise ReviewError("isolated-review preflight receipt size is invalid")
    digest = value["sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReviewError("isolated-review preflight receipt digest is invalid")
    return PreflightReceipt(
        schema_version=PREFLIGHT_RECEIPT_SCHEMA_VERSION,
        algorithm=PREFLIGHT_RECEIPT_ALGORITHM,
        size=size,
        sha256=digest,
    )


def _bound_state_marker_version(version: int) -> bool:
    return version in {BOUND_STATE_MARKER_SCHEMA_VERSION, STATE_MARKER_SCHEMA_VERSION}


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
    marker_version: int,
    phase: str,
) -> pathlib.Path:
    source_root = _canonical_v3_marker_path(
        raw_source_root,
        label="source root",
    )
    container = _canonical_v3_marker_path(
        raw_container,
        label="container",
    )
    if marker_version == STATE_MARKER_SCHEMA_VERSION and phase == "preparing":
        canonical_base = _canonical_review_root_base()
        expected_user_root = canonical_base / f"{REVIEW_USER_ROOT_PREFIX}{os.geteuid()}"
        expected_parent = container.parent
        if (
            source_root != expected_user_root
            or expected_parent.parent != expected_user_root
            or re.fullmatch(r"[0-9a-f]{64}", expected_parent.name) is None
        ):
            raise ReviewError("isolated-review state marker layout is invalid")
    else:
        expected_parent = (
            _review_root_for_source(source_root, require_source=False)
            if marker_version == STATE_MARKER_SCHEMA_VERSION
            else source_root / ".codex-tmp"
        )
    if (
        container != resolved_state_dir
        or container.parent != expected_parent
        or REVIEW_CONTAINER_PATTERN.fullmatch(container.name) is None
    ):
        raise ReviewError("isolated-review state marker layout is invalid")
    return source_root


def _parse_runner_lock_identity(value: Any) -> CleanupIdentity:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "inode"}
        or type(value["device"]) is not int
        or type(value["inode"]) is not int
        or value["device"] < 0
        or value["inode"] <= 0
    ):
        raise ReviewError("isolated-review state marker runner lock is invalid")
    return CleanupIdentity(value["device"], value["inode"])


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
            runner_lock=None,
            source_root=None,
            preflight_receipt=None,
        )
    try:
        marker_json = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError("isolated-review state marker is invalid") from error
    try:
        core_json, isolated_receipt_values = _isolate_preflight_receipt_json(
            marker_json
        )
    except (OverflowError, ValueError) as error:
        raise ReviewError("isolated-review state marker is invalid") from error
    try:
        marker = json.loads(
            core_json,
            object_pairs_hook=_capture_duplicate_marker_object,
        )
    except RecursionError as error:
        raise ReviewError(
            "isolated-review state marker exceeds the JSON nesting depth limit"
        ) from error
    except (json.JSONDecodeError, OverflowError, ValueError) as error:
        raise ReviewError("isolated-review state marker is invalid") from error
    if not isinstance(marker, dict):
        raise ReviewError("isolated-review state marker is not a JSON object")
    core_marker = dict(marker)
    if "preflight_receipt" in core_marker:
        core_marker["preflight_receipt"] = None
    _validate_bounded_json_depth(
        core_marker,
        label="isolated-review state marker",
    )
    marker_duplicates = (
        marker.duplicate_fields if isinstance(marker, _MarkerObject) else frozenset()
    )
    nonreceipt_marker_duplicates = marker_duplicates - {"preflight_receipt"}
    if nonreceipt_marker_duplicates:
        duplicate = sorted(nonreceipt_marker_duplicates)[0]
        raise ReviewError(
            f"isolated-review state marker has duplicate field: {duplicate}"
        )
    version = marker.get("version")
    if type(version) is not int:
        raise ReviewError("isolated-review state marker version is invalid")
    for field, value in marker.items():
        if version == STATE_MARKER_SCHEMA_VERSION and field == "preflight_receipt":
            continue
        duplicate = _first_duplicate_marker_field(value)
        if duplicate is not None:
            raise ReviewError(
                f"isolated-review state marker has duplicate field: {duplicate}"
            )
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
            runner_lock=None,
            source_root=None,
            preflight_receipt=None,
        )
    if version not in {
        PREVIOUS_STATE_MARKER_SCHEMA_VERSION,
        BOUND_STATE_MARKER_SCHEMA_VERSION,
        STATE_MARKER_SCHEMA_VERSION,
    }:
        raise ReviewError("isolated-review state marker version is invalid")
    expected_fields = {
        "container_dir",
        "phase",
        "private_cleanup",
        "source_root",
        "version",
    }
    if _bound_state_marker_version(version):
        expected_fields.add("runner_lock")
    if version == STATE_MARKER_SCHEMA_VERSION:
        expected_fields.add("preflight_receipt")
    actual_fields = set(marker)
    missing_receipt = (
        version == STATE_MARKER_SCHEMA_VERSION
        and "preflight_receipt" not in actual_fields
    )
    required_fields = expected_fields - (
        {"preflight_receipt"} if missing_receipt else set()
    )
    if actual_fields != required_fields:
        raise ReviewError("isolated-review state marker fields are invalid")
    phase = marker["phase"]
    if not isinstance(phase, str) or phase not in {"preparing", "ready"}:
        raise ReviewError("isolated-review state marker phase is invalid")
    source_root = _validate_v3_marker_layout(
        marker["source_root"],
        marker["container_dir"],
        resolved_state_dir=resolved_state_dir,
        marker_version=version,
        phase=phase,
    )
    cleanup_parser = (
        parse_private_cleanup_evidence
        if phase == "ready"
        else parse_partial_private_cleanup_evidence
    )
    receipt_value = marker.get("preflight_receipt")
    if phase == "preparing" and any(
        raw.encoded != "null" for raw in isolated_receipt_values
    ):
        raise ReviewError(
            "isolated-review preparing marker cannot contain a preflight receipt"
        )
    preflight_receipt: PreflightReceipt | None = None
    if "preflight_receipt" in marker_duplicates:
        preflight_receipt_error: str | None = (
            "isolated-review state marker has duplicate preflight receipt field"
        )
    elif missing_receipt:
        preflight_receipt_error = "isolated-review preflight receipt field is missing"
    else:
        preflight_receipt_error = None
    if preflight_receipt_error is None and version == STATE_MARKER_SCHEMA_VERSION:
        if len(isolated_receipt_values) != 1:
            raise ReviewError("isolated-review state marker is invalid")
        try:
            receipt_value = _parse_isolated_preflight_receipt_json(
                isolated_receipt_values[0]
            )
        except ReviewError as error:
            preflight_receipt_error = str(error)
    if preflight_receipt_error is None:
        try:
            _validate_bounded_json_depth(
                receipt_value,
                label="isolated-review preflight receipt",
            )
        except ReviewError as error:
            preflight_receipt_error = str(error)
    receipt_duplicate = (
        _first_duplicate_marker_field(receipt_value)
        if preflight_receipt_error is None
        else None
    )
    if receipt_duplicate is not None:
        preflight_receipt_error = (
            f"isolated-review preflight receipt has duplicate field: "
            f"{receipt_duplicate}"
        )
    elif (
        preflight_receipt_error is None
        and version == STATE_MARKER_SCHEMA_VERSION
        and receipt_value is not None
    ):
        try:
            preflight_receipt = _parse_preflight_receipt(receipt_value)
        except ReviewError as error:
            preflight_receipt_error = str(error)
    return LoadedStateMarker(
        version=version,
        phase=phase,
        private_cleanup=cleanup_parser(marker["private_cleanup"]),
        runner_lock=(
            _parse_runner_lock_identity(marker["runner_lock"])
            if _bound_state_marker_version(version)
            else None
        ),
        source_root=source_root,
        preflight_receipt=preflight_receipt,
        preflight_receipt_error=preflight_receipt_error,
    )


def _require_modern_ready_marker(
    marker: LoadedStateMarker,
    *,
    purpose: str,
) -> PrivateCleanupEvidence:
    if (
        not _bound_state_marker_version(marker.version)
        or marker.phase != "ready"
        or marker.private_cleanup is None
    ):
        raise ReviewError(
            f"{purpose} requires a modern v{BOUND_STATE_MARKER_SCHEMA_VERSION}/"
            f"v{STATE_MARKER_SCHEMA_VERSION} ready state marker"
        )
    return marker.private_cleanup


def _validate_bound_state_artifact_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    max_bytes: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewError(f"{label} must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise ReviewError(f"{label} must be owned by the current user")
    if metadata.st_nlink != 1:
        raise ReviewError(f"{label} must have exactly one hard link")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ReviewError(f"{label} mode must be exactly 0600")
    if metadata.st_size > max_bytes:
        raise ReviewError(f"{label} exceeds the {max_bytes}-byte size limit")


def _read_modern_bound_state_artifact(
    state_dir: pathlib.Path,
    *,
    name: str,
    max_bytes: int,
    marker: LoadedStateMarker | None = None,
) -> bytes | None:
    """Read a v4/v5 state artifact without following a mutable path component."""

    if (
        not name
        or pathlib.PurePath(name).name != name
        or name in {".", ".."}
        or max_bytes < 0
    ):
        raise ReviewError("bound review state artifact request is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblock is None:
        raise ReviewError("secure bound review state artifact loading is unavailable")

    resolved_state_dir = state_dir.expanduser().resolve(strict=False)
    marker = _load_state_marker(resolved_state_dir) if marker is None else marker
    expected = _require_modern_ready_marker(
        marker,
        purpose="bound review state artifact loading",
    )
    artifact_name = pathlib.Path(name)
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | nonblock
    descriptor: int | None = None
    label = f"review state artifact {name}"
    try:
        with _open_private_cleanup_state_directory(resolved_state_dir) as (
            state_dir_fd,
            revalidate_state_directory,
        ):
            initial_container_key = _directory_identity(os.fstat(state_dir_fd))

            def revalidate_container() -> None:
                revalidate_state_directory()
                metadata = os.fstat(state_dir_fd)
                if (
                    CleanupIdentity(metadata.st_dev, metadata.st_ino)
                    != expected.container
                ):
                    raise ReviewError(
                        f"{label} container does not match preparation identity"
                    )
                if _directory_identity(metadata) != initial_container_key:
                    raise ReviewError(f"{label} container changed while reading")

            revalidate_container()
            try:
                before = os.stat(
                    artifact_name,
                    dir_fd=state_dir_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                revalidate_container()
                return None
            _validate_bound_state_artifact_metadata(
                before,
                label=label,
                max_bytes=max_bytes,
            )
            initial_key = _state_marker_metadata_key(before)
            revalidate_container()

            descriptor = os.open(artifact_name, flags, dir_fd=state_dir_fd)
            opened = os.fstat(descriptor)
            current = os.stat(
                artifact_name,
                dir_fd=state_dir_fd,
                follow_symlinks=False,
            )
            for metadata in (opened, current):
                _validate_bound_state_artifact_metadata(
                    metadata,
                    label=label,
                    max_bytes=max_bytes,
                )
            if any(
                _state_marker_metadata_key(metadata) != initial_key
                for metadata in (opened, current)
            ):
                raise ReviewError(f"{label} changed while opening")
            revalidate_container()

            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) > max_bytes:
                raise ReviewError(f"{label} exceeds the {max_bytes}-byte size limit")

            final_metadata = os.fstat(descriptor)
            path_final = os.stat(
                artifact_name,
                dir_fd=state_dir_fd,
                follow_symlinks=False,
            )
            for metadata in (final_metadata, path_final):
                _validate_bound_state_artifact_metadata(
                    metadata,
                    label=label,
                    max_bytes=max_bytes,
                )
            if len(payload) != opened.st_size or any(
                _state_marker_metadata_key(metadata) != initial_key
                for metadata in (final_metadata, path_final)
            ):
                raise ReviewError(f"{label} changed while reading")
            revalidate_container()
            return payload
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot read {label} {resolved_state_dir / name} safely: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_duplicate_preflight_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewError(f"preflight evidence has duplicate field: {key}")
        value[key] = item
    return value


def _parse_preflight_payload(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_preflight_object,
        )
    except RecursionError as error:
        raise ReviewError(f"{label} exceeds the JSON nesting depth limit") from error
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OverflowError,
        ValueError,
    ) as error:
        raise ReviewError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    _validate_bounded_json_depth(value, label=label)
    return value


def _seal_preflight_receipt(
    state_dir: pathlib.Path,
    *,
    review: ReviewWorkspace,
    lock_fd: int,
) -> PreflightReceipt:
    validate_inherited_runner_lock_lease(state_dir, lock_fd)
    marker = _load_state_marker(state_dir)
    if marker.version != STATE_MARKER_SCHEMA_VERSION or marker.phase != "ready":
        raise ReviewError(
            f"secret admission sealing requires a v{STATE_MARKER_SCHEMA_VERSION} "
            "ready state marker"
        )
    if marker.preflight_receipt_error is not None:
        raise ReviewError(marker.preflight_receipt_error)
    if marker.preflight_receipt is not None:
        raise ReviewError("secret admission preflight receipt is already sealed")
    payload = _read_modern_bound_state_artifact(
        state_dir,
        name=PREFLIGHT_FILE,
        max_bytes=MAX_PREFLIGHT_JSON_BYTES,
        marker=marker,
    )
    if payload is None:
        raise ReviewError("secret admission preflight evidence is missing")
    _parse_preflight_payload(payload, label="secret admission preflight evidence")
    receipt = PreflightReceipt(
        schema_version=PREFLIGHT_RECEIPT_SCHEMA_VERSION,
        algorithm=PREFLIGHT_RECEIPT_ALGORITHM,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    _write_state_marker(
        review,
        _require_bound_runner_lock(marker),
        preflight_receipt=receipt,
    )
    return receipt


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
                PREVIOUS_STATE_MARKER_SCHEMA_VERSION,
                BOUND_STATE_MARKER_SCHEMA_VERSION,
                STATE_MARKER_SCHEMA_VERSION,
            }
            or marker.phase != "ready"
        ):
            raise ReviewError("review state and marker versions are inconsistent")
        workspace_type = (
            ReviewWorkspace
            if marker.version == STATE_MARKER_SCHEMA_VERSION
            else SourceLocalReviewWorkspace
        )
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


def _require_bound_runner_lock(marker: LoadedStateMarker) -> CleanupIdentity:
    if not _bound_state_marker_version(marker.version) or marker.runner_lock is None:
        raise ReviewError(
            "review state marker has no preparation-bound runner lock identity; "
            "manual recovery is required for legacy v1/v2/v3 review state"
        )
    return marker.runner_lock


def _require_flock_probe_blocked(descriptor: int, *, label: str) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    except OSError as error:
        raise ReviewError(f"cannot probe {label} lease: {error}") from error
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as error:
        raise ReviewError(
            f"{label} was not inherited-held and its probe could not be released: "
            f"{error}"
        ) from error
    raise ReviewError(f"{label} is not an inherited-held lease")


def _prove_inherited_flock_lease(
    inherited_descriptor: int,
    independent_descriptor: int,
    *,
    label: str,
    revalidate: Callable[[], None],
) -> None:
    revalidate()
    _require_flock_probe_blocked(independent_descriptor, label=label)
    revalidate()
    try:
        fcntl.flock(
            inherited_descriptor,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )
    except BlockingIOError as error:
        raise ReviewError(
            f"{label} does not share the inherited-held lock description"
        ) from error
    except OSError as error:
        raise ReviewError(
            f"cannot validate inherited {label} lease: {error}"
        ) from error
    revalidate()
    _require_flock_probe_blocked(independent_descriptor, label=label)
    revalidate()


def validate_inherited_runner_lock_lease(
    state_dir: pathlib.Path,
    lock_fd: int,
) -> None:
    if type(lock_fd) is not int or lock_fd < 0:
        raise ReviewError("review runner lock descriptor is invalid")
    try:
        os.fstat(lock_fd)
    except OSError as error:
        raise ReviewError(
            f"cannot validate inherited review runner lock descriptor: {error}"
        ) from error
    resolved_state_dir = state_dir.expanduser().resolve(strict=False)
    marker = _load_state_marker(resolved_state_dir)
    expected_cleanup = _require_modern_ready_marker(
        marker,
        purpose="review runner execution",
    )
    expected_lock = _require_bound_runner_lock(marker)
    lock_name = pathlib.Path(LOCK_FILE)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    independent_fd: int | None = None
    try:
        with _open_private_cleanup_state_directory(resolved_state_dir) as (
            state_dir_fd,
            revalidate_state_directory,
        ):

            def validate_container() -> None:
                revalidate_state_directory()
                metadata = os.fstat(state_dir_fd)
                if (
                    CleanupIdentity(metadata.st_dev, metadata.st_ino)
                    != expected_cleanup.container
                ):
                    raise ReviewError(
                        "review runner lock container does not match preparation "
                        "identity"
                    )
                revalidate_state_directory()

            validate_container()
            inherited_metadata = _validate_regular_file_path_identity(
                lock_name,
                lock_fd,
                label="review runner lock",
                expected_mode=0o600,
                dir_fd=state_dir_fd,
            )
            if (
                CleanupIdentity(
                    inherited_metadata.st_dev,
                    inherited_metadata.st_ino,
                )
                != expected_lock
            ):
                raise ReviewError(
                    "review runner lock does not match preparation identity"
                )
            validate_container()
            independent_fd = os.open(lock_name, flags, dir_fd=state_dir_fd)

            def revalidate_lock() -> None:
                validate_container()
                for descriptor in (lock_fd, independent_fd):
                    metadata = _validate_regular_file_path_identity(
                        lock_name,
                        descriptor,
                        label="review runner lock",
                        expected_mode=0o600,
                        dir_fd=state_dir_fd,
                    )
                    if (
                        CleanupIdentity(metadata.st_dev, metadata.st_ino)
                        != expected_lock
                    ):
                        raise ReviewError(
                            "review runner lock does not match preparation identity"
                        )
                validate_container()

            _prove_inherited_flock_lease(
                lock_fd,
                independent_fd,
                label="review runner lock",
                revalidate=revalidate_lock,
            )
            os.set_inheritable(lock_fd, False)
            if os.get_inheritable(lock_fd):
                raise ReviewError("review runner lock descriptor remained inheritable")
            revalidate_lock()
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot validate inherited review runner lock safely: {error}"
        ) from error
    finally:
        if independent_fd is not None:
            os.close(independent_fd)


def _probe_bound_runner_lock(
    *,
    state_dir: pathlib.Path,
    state_dir_fd: int,
    revalidate_state_directory: Callable[[], None],
    marker: LoadedStateMarker,
) -> bool:
    expected = _require_bound_runner_lock(marker)
    marker_cleanup = marker.private_cleanup
    if marker_cleanup is None:
        raise ReviewError(
            "review state marker has no preparation-bound container identity"
        )
    container_metadata = os.fstat(state_dir_fd)
    if (
        CleanupIdentity(
            container_metadata.st_dev,
            container_metadata.st_ino,
        )
        != marker_cleanup.container
    ):
        raise ReviewError(
            "review runner lock container does not match preparation identity"
        )

    lock_name = pathlib.Path(LOCK_FILE)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    handle: BinaryIO | None = None
    acquired = False
    try:
        revalidate_state_directory()
        descriptor = os.open(lock_name, flags, dir_fd=state_dir_fd)
        handle = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = None

        def validate() -> None:
            revalidate_state_directory()
            metadata = _validate_regular_file_path_identity(
                lock_name,
                handle.fileno(),
                label="review runner lock",
                expected_mode=0o600,
                dir_fd=state_dir_fd,
            )
            if CleanupIdentity(metadata.st_dev, metadata.st_ino) != expected:
                raise ReviewError(
                    "review runner lock does not match preparation identity"
                )
            revalidate_state_directory()

        validate()
        try:
            # Observers may overlap; only the runner's exclusive lease means active.
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            validate()
            return True
        except OSError as error:
            raise ReviewError(
                f"cannot probe review runner lock {state_dir / LOCK_FILE}: {error}"
            ) from error
        validate()
        return False
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot open review runner lock {state_dir / LOCK_FILE} safely: {error}"
        ) from error
    finally:
        if acquired and handle is not None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError as error:
                if sys.exc_info()[0] is None:
                    raise ReviewError(
                        "cannot release review runner lock probe "
                        f"{state_dir / LOCK_FILE}: {error}"
                    ) from error
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)


def _runner_lock_held(
    state_dir: pathlib.Path,
    *,
    marker: LoadedStateMarker | None = None,
    state_dir_fd: int | None = None,
    revalidate_state_directory: Callable[[], None] | None = None,
) -> bool:
    marker = _load_state_marker(state_dir) if marker is None else marker
    _require_bound_runner_lock(marker)
    if state_dir_fd is not None:
        if revalidate_state_directory is None:
            raise ReviewError("bound review runner lock probe has no revalidator")
        return _probe_bound_runner_lock(
            state_dir=state_dir,
            state_dir_fd=state_dir_fd,
            revalidate_state_directory=revalidate_state_directory,
            marker=marker,
        )
    with _open_private_cleanup_state_directory(state_dir) as (
        opened_state_dir_fd,
        revalidate,
    ):
        return _probe_bound_runner_lock(
            state_dir=state_dir,
            state_dir_fd=opened_state_dir_fd,
            revalidate_state_directory=revalidate,
            marker=marker,
        )


def _reap_started_process(pid: int) -> None:
    process = _STARTED_PROCESSES.get(pid)
    if process is None:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        return
    _STARTED_PROCESSES.pop(pid, None)


def _validate_reviewer_policy(
    reviewer: str,
    egress_consent: str | None,
) -> None:
    if not isinstance(reviewer, str) or reviewer not in {"codex", "claude"}:
        raise ReviewError("reviewer policy is invalid")
    if reviewer == "claude":
        if egress_consent not in CLAUDE_EGRESS_CONSENTS:
            raise ReviewError(
                "Claude reviewer policy requires a valid explicit egress consent"
            )
    elif egress_consent is not None:
        raise ReviewError("Codex reviewer policy cannot contain egress consent")


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
    include_source_wip: bool = False,
    publisher: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path:
    _validate_reviewer_policy(reviewer, egress_consent)
    redact_values = _freeze_claude_redactions(reviewer=reviewer)
    _redact_claude_text("", redact_values)
    process: subprocess.Popen[bytes] | None = None
    review: ReviewWorkspace | None = None
    preparation_guard = ReviewPreparationGuard()
    pending_signal: signal.Signals | None = None
    spawning = False
    published = False
    cleaning = False
    handlers_restored = False
    write_redaction_scope = None
    write_redaction_entered = False

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
            include_source_wip=include_source_wip,
        )
        review = preparation_guard.require_review()
        state_dir = review.container_dir
        write_redaction_scope = atomic_write_redactions(
            redact_values,
            path_filter=_state_owned_write_filter(state_dir),
        )
        write_redaction_scope.__enter__()
        write_redaction_entered = True
        stdout_path = state_dir / "runner.stdout.log"
        stderr_path = state_dir / "runner.stderr.log"
        state: dict[str, Any] = {
            "version": STATE_SCHEMA_VERSION,
            "reviewer": reviewer,
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "workspace": review.to_json(),
            "keep_workspace": keep_workspace,
            "egress_consent": egress_consent,
            "synthetic_secret_exemptions": list(synthetic_secret_exemptions),
            "include_source_wip": include_source_wip,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "final_path": str(state_dir / "final.txt"),
            "attempts_path": str(state_dir / "attempts.json"),
            "started_at": time.time(),
        }
        _write_state_json_without_credentials(
            state_dir / STATE_FILE,
            state,
            redact_values,
        )
        lock_fd = preparation_guard.lock_fd()
        with (
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            os.fchmod(stdout_handle.fileno(), 0o600)
            os.fchmod(stderr_handle.fileno(), 0o600)
            runner_arguments = [
                sys.executable,
                "-B",
                str(script_path),
                "_run-state",
                "--state-dir",
                str(state_dir),
                "--lock-fd",
                str(lock_fd),
                "--reviewer",
                reviewer,
            ]
            if egress_consent is not None:
                runner_arguments.extend(("--egress-consent", egress_consent))
            spawning = True
            spawn_mask = block_forwarded_signals()
            try:
                process = subprocess.Popen(
                    tuple(runner_arguments),
                    cwd=review.workspace_root,
                    stdin=subprocess.DEVNULL,
                    stdout=(subprocess.DEVNULL if redact_values else stdout_handle),
                    stderr=(subprocess.DEVNULL if redact_values else stderr_handle),
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
        _write_state_json_without_credentials(
            state_dir / STATE_FILE,
            state,
            redact_values,
        )
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
                details.append(_redact_claude_text(error.detail, redact_values))
            elif isinstance(error, ReviewError):
                details.append(
                    _redacted_exception_detail(error, redact_values)
                    if redact_values
                    else str(error)
                )
            if cleanup_error and review is not None:
                details.append(
                    "review startup failed and cleanup failed; evidence may remain "
                    f"near {review.container_dir}; inspect cleanup state: "
                    f"{_redact_claude_text(cleanup_error, redact_values)}"
                )
            raise ForwardedSignal(
                pending_signal,
                detail="; ".join(details) or None,
            ) from None
        if cleanup_error and review is not None:
            primary_detail = (
                f"; primary failure: {_redacted_exception_detail(error, redact_values)}"
                if redact_values
                else ""
            )
            raise ReviewError(
                "review startup failed and cleanup failed; evidence may remain near "
                f"{review.container_dir}; inspect cleanup state: "
                f"{_redact_claude_text(cleanup_error, redact_values)}"
                f"{primary_detail}"
            ) from error
        if redact_values:
            raise ReviewError(
                "review startup failed: "
                f"{_redacted_exception_detail(error, redact_values)}"
            ) from None
        raise
    finally:
        try:
            preparation_guard.close()
            if not handlers_restored:
                for forwarded, previous in previous_handlers.items():
                    signal.signal(forwarded, previous)
        finally:
            if write_redaction_entered and write_redaction_scope is not None:
                write_redaction_scope.__exit__(None, None, None)


def run_state(
    *,
    state_dir: pathlib.Path,
    lock_fd: int | None = None,
    terminal_process: bool = False,
    expected_reviewer: str | None = None,
    expected_egress_consent: str | None = None,
) -> int:
    redact_values = _freeze_claude_redactions(
        reviewer=expected_reviewer if terminal_process else None,
    )
    _redact_claude_text("", redact_values)
    exit_code = 1
    pending_signal: signal.Signals | None = None
    suppress_signal_raise = False
    state_loaded = False
    write_redaction_scope = None
    write_redaction_entered = False
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
        if terminal_process:
            if lock_fd is None:
                raise ReviewError(
                    "terminal review runner has no inherited preparation lock"
                )
            if expected_reviewer is None:
                raise ReviewError("terminal review runner has no bound reviewer policy")
            _validate_reviewer_policy(
                expected_reviewer,
                expected_egress_consent,
            )
            validate_inherited_runner_lock_lease(state_dir, lock_fd)
        elif (
            lock_fd is not None
            or expected_reviewer is not None
            or expected_egress_consent is not None
        ):
            raise ReviewError(
                "review runner launch binding is valid only for terminal execution"
            )
        state, review = load_review_state(state_dir)
        state_loaded = True
        if isinstance(review, LegacyReviewWorkspace):
            raise ReviewError(
                "legacy v1 review state cannot be resumed; start a new review"
            )
        state_reviewer = state.get("reviewer")
        selected_reviewer = expected_reviewer if terminal_process else state_reviewer
        redact_values = _freeze_claude_redactions(
            reviewer=(
                selected_reviewer if isinstance(selected_reviewer, str) else None
            ),
        )
        _redact_claude_text("", redact_values)
        state_dir = review.container_dir.expanduser().resolve(strict=True)
        write_redaction_scope = atomic_write_redactions(
            redact_values,
            path_filter=_state_owned_write_filter(state_dir),
        )
        write_redaction_scope.__enter__()
        write_redaction_entered = True
        marker = _load_state_marker(state_dir)
        if marker.version != STATE_MARKER_SCHEMA_VERSION:
            raise ReviewError(
                "legacy v2/v3/v4 review state cannot be resumed safely; start a new "
                "review"
            )
        state_reviewer = state.get("reviewer")
        if not isinstance(state_reviewer, str):
            raise ReviewError("review state does not contain a reviewer")
        consent_value = state.get("egress_consent")
        if consent_value is not None and not isinstance(consent_value, str):
            raise ReviewError("review state contains invalid egress consent")
        state_egress_consent = consent_value
        if terminal_process:
            if (
                state_reviewer != expected_reviewer
                or state_egress_consent != expected_egress_consent
            ):
                raise ReviewError(
                    "review state reviewer policy does not match its trusted launch "
                    "binding"
                )
            reviewer = expected_reviewer
            egress_consent = expected_egress_consent
        else:
            reviewer = state_reviewer
            egress_consent = state_egress_consent
        unblock_forwarded_signals()
        outcome = run_review(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
        )
        exit_code = outcome.returncode
        if terminal_process:
            assert lock_fd is not None
            suppress_signal_raise = True
            try:
                seal_mask = block_forwarded_signals()
                _seal_preflight_receipt(
                    state_dir,
                    review=review,
                    lock_fd=lock_fd,
                )
                if seal_mask is not None:
                    sealed_signal = consume_pending_forwarded_signal()
                    if pending_signal is None:
                        pending_signal = sealed_signal
            except Exception as error:
                print(
                    f"secret admission preflight receipt was not sealed: {error}",
                    file=sys.stderr,
                )
    except ForwardedSignal as error:
        exit_code = 128 + int(error.signum)
        if state_loaded and review is not None and error.detail:
            diagnostic = (
                "review orchestration interrupted by signal "
                f"{int(error.signum)}: "
                f"{_redact_claude_text(error.detail, redact_values)}\n"
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
            diagnostic = _redacted_exception_detail(error, redact_values) + "\n"
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
        try:
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
                                "review runner exit code was not persisted: "
                                f"{exit_error}",
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
        finally:
            if write_redaction_entered and write_redaction_scope is not None:
                write_redaction_scope.__exit__(None, None, None)
    return exit_code


def status(state_dir: pathlib.Path) -> dict[str, Any]:
    redact_values = _freeze_claude_redactions(reviewer=None)
    state_dir = state_dir.expanduser().resolve()
    state, review = load_review_state(state_dir)
    state_reviewer = state.get("reviewer")
    redact_values = _freeze_claude_redactions(
        reviewer=state_reviewer if isinstance(state_reviewer, str) else None,
    )
    _redact_claude_text("", redact_values)
    marker = _load_state_marker(state_dir)
    pid_value = state.get("pid")
    pid = pid_value if isinstance(pid_value, int) else 0
    process_running = _runner_lock_held(state_dir, marker=marker)
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
    admission_summary = _admission_status_for_loaded_state(
        state_dir=state_dir,
        review=review,
        marker=marker,
        running=running,
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
    summary = {
        "state_dir": str(state_dir),
        "reviewer": state.get("reviewer"),
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "egress_consent": state.get("egress_consent"),
        "content_variant": review.content_variant,
        "snapshot_tree_sha": review.snapshot_tree_sha,
        "scope_identity": review.scope_identity,
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
        "admission": admission_summary,
    }
    return {
        key: _redact_claude_value(item, redact_values) for key, item in summary.items()
    }


def _admission_result(
    *,
    state_dir: pathlib.Path,
    review_range: str,
    status: str,
    exit_code: int,
    failure_class: str | None,
    secret_delta: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": ADMISSION_SCHEMA_VERSION,
        "status": status,
        "exit_code": exit_code,
        "review_range": review_range,
        "evidence_path": str(state_dir / PREFLIGHT_FILE),
        "failure_class": failure_class,
        "secret_delta": secret_delta,
    }


def _read_bound_preflight(
    state_dir: pathlib.Path,
    *,
    marker: LoadedStateMarker,
) -> dict[str, Any]:
    receipt = marker.preflight_receipt
    if receipt is None:
        raise ReviewError("secret admission preflight receipt is missing")
    payload = _read_modern_bound_state_artifact(
        state_dir,
        name=PREFLIGHT_FILE,
        max_bytes=MAX_PREFLIGHT_JSON_BYTES,
        marker=marker,
    )
    if payload is None:
        raise ReviewError("sealed secret admission preflight evidence is missing")
    if (
        len(payload) != receipt.size
        or hashlib.sha256(payload).hexdigest() != receipt.sha256
    ):
        raise ReviewError(
            "secret admission preflight evidence does not match its runner-sealed "
            "receipt"
        )
    return _parse_preflight_payload(
        payload,
        label="secret admission preflight evidence",
    )


def _admission_status_for_loaded_state(
    *,
    state_dir: pathlib.Path,
    review: ReviewWorkspace | LegacyReviewWorkspace,
    marker: LoadedStateMarker,
    running: bool,
) -> dict[str, Any]:
    review_range = f"{review.base_ref}..{review.head_ref}"
    if isinstance(review, LegacyReviewWorkspace) or (
        not _bound_state_marker_version(marker.version) or marker.phase != "ready"
    ):
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="legacy-state-no-admission",
            secret_delta=None,
        )
    if running:
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="pending",
            exit_code=3,
            failure_class="preflight-not-ready",
            secret_delta=None,
        )
    if marker.preflight_receipt_error is not None:
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="preflight-invalid",
            secret_delta=None,
        )
    if marker.preflight_receipt is None:
        if marker.version == BOUND_STATE_MARKER_SCHEMA_VERSION:
            failure_class = "legacy-state-no-preflight-receipt"
        else:
            failure_class = "preflight-unsealed"
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class=failure_class,
            secret_delta=None,
        )
    try:
        preflight = _read_bound_preflight(state_dir, marker=marker)
    except ReviewError:
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="preflight-invalid",
            secret_delta=None,
        )
    if preflight.get("review_range") != review_range:
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="preflight-range-mismatch",
            secret_delta=None,
        )
    if (
        preflight.get("status") != PREFLIGHT_STATUS
        or preflight.get("private_artifacts") != PREFLIGHT_PRIVATE_ARTIFACTS
        or preflight.get("content_variant") != review.content_variant
        or preflight.get("snapshot_tree_sha") != review.snapshot_tree_sha
        or preflight.get("scope_identity") != review.scope_identity
        or preflight.get("scope") != review_preflight_scope(review.content_variant)
    ):
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="preflight-invalid",
            secret_delta=None,
        )
    try:
        secret_delta = validate_secret_delta_summary(
            preflight.get("secret_delta"),
            label="secret admission delta evidence",
        )
    except ReviewError:
        return _admission_result(
            state_dir=state_dir,
            review_range=review_range,
            status="inconclusive",
            exit_code=75,
            failure_class="preflight-invalid",
            secret_delta=None,
        )
    delta_status = secret_delta["status"]
    if delta_status == "clean":
        status_value, exit_code, failure_class = "clean", 0, None
    elif delta_status == "violations":
        status_value, exit_code, failure_class = "blocked", 1, None
    else:
        status_value, exit_code, failure_class = (
            "inconclusive",
            75,
            secret_delta["failure_class"],
        )
    return _admission_result(
        state_dir=state_dir,
        review_range=review_range,
        status=status_value,
        exit_code=exit_code,
        failure_class=failure_class,
        secret_delta=secret_delta,
    )


def admission_status(state_dir: pathlib.Path) -> dict[str, Any]:
    state_dir = state_dir.expanduser().resolve()
    _state, review = load_review_state(state_dir)
    marker = _load_state_marker(state_dir)
    running = False
    if (
        not isinstance(review, LegacyReviewWorkspace)
        and _bound_state_marker_version(marker.version)
        and marker.phase == "ready"
    ):
        running = _runner_lock_held(state_dir, marker=marker)
    return _admission_status_for_loaded_state(
        state_dir=state_dir,
        review=review,
        marker=marker,
        running=running,
    )


def admission(state_dir: pathlib.Path) -> tuple[int, dict[str, Any]]:
    summary = admission_status(state_dir)
    return int(summary["exit_code"]), summary


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
        or not (review.git_dir or review.container_dir / "review.git").is_dir()
        or not review.has_complete_scope_identity()
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
            preflight.get("review_range") != f"{review.base_ref}..{review.head_ref}"
            or preflight.get("content_variant") != review.content_variant
            or preflight.get("snapshot_tree_sha") != review.snapshot_tree_sha
            or preflight.get("scope_identity") != review.scope_identity
            or preflight.get("private_artifacts") != "removed"
            or preflight.get("status")
            != "review workspace containment and integrity checks passed"
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
    marker = _load_state_marker(state_dir)
    if _runner_lock_held(state_dir, marker=marker):
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
        cleanup_lock = _CleanupLockSet(
            container_lock,
            lambda: open_private_lock_file(
                cleanup_lock_name,
                label="review cleanup lock",
                allow_legacy_read_mode=True,
                allowed_legacy_modes=PRIVATE_STATE_LEGACY_LOCK_MODES,
                dir_fd=state_dir_fd,
            ),
        )
        try:
            yield (
                cleanup_lock,
                cleanup_lock_name,
                state_dir_fd,
                revalidate_state_directory,
            )
        finally:
            cleanup_lock.close()


def validate_cleanup_worker_lock_leases(
    state_dir: pathlib.Path,
    lock_fds: tuple[int, ...],
) -> None:
    if (
        len(lock_fds) != 2
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in lock_fds)
        or lock_fds[0] == lock_fds[1]
    ):
        raise ReviewError(
            "cleanup worker requires two distinct role-ordered lock descriptors"
        )
    try:
        for descriptor in lock_fds:
            os.fstat(descriptor)
    except OSError as error:
        raise ReviewError(
            f"cannot validate inherited cleanup worker lock descriptor: {error}"
        ) from error

    container_lock_fd, compatibility_lock_fd = lock_fds
    resolved_state_dir = state_dir.expanduser().resolve(strict=False)
    marker = _load_state_marker(resolved_state_dir)
    expected = _require_modern_ready_marker(
        marker,
        purpose="automatic cleanup worker execution",
    )
    compatibility_name = pathlib.Path(CLEANUP_LOCK_FILE)
    compatibility_flags = (
        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    )
    compatibility_probe_fd: int | None = None
    try:
        with _open_private_cleanup_state_directory(resolved_state_dir) as (
            state_dir_fd,
            revalidate_state_directory,
        ):

            def validate_container_lock() -> None:
                revalidate_state_directory()
                _validate_private_directory_path_identity(
                    resolved_state_dir,
                    container_lock_fd,
                    label="cleanup worker container lock",
                    expected_mode=0o700,
                )
                opened_metadata = os.fstat(state_dir_fd)
                inherited_metadata = os.fstat(container_lock_fd)
                if _directory_identity(opened_metadata) != _directory_identity(
                    inherited_metadata
                ):
                    raise ReviewError(
                        "cleanup worker container lock does not match its exact path"
                    )
                if (
                    CleanupIdentity(
                        inherited_metadata.st_dev,
                        inherited_metadata.st_ino,
                    )
                    != expected.container
                ):
                    raise ReviewError(
                        "cleanup worker container lock does not match preparation "
                        "identity"
                    )
                revalidate_state_directory()

            validate_container_lock()
            _validate_regular_file_path_identity(
                compatibility_name,
                compatibility_lock_fd,
                label="cleanup worker compatibility lock",
                expected_mode=0o600,
                dir_fd=state_dir_fd,
            )
            compatibility_probe_fd = os.open(
                compatibility_name,
                compatibility_flags,
                dir_fd=state_dir_fd,
            )

            def revalidate_all() -> None:
                validate_container_lock()
                for descriptor in (
                    compatibility_lock_fd,
                    compatibility_probe_fd,
                ):
                    _validate_regular_file_path_identity(
                        compatibility_name,
                        descriptor,
                        label="cleanup worker compatibility lock",
                        expected_mode=0o600,
                        dir_fd=state_dir_fd,
                    )
                revalidate_state_directory()

            _prove_inherited_flock_lease(
                container_lock_fd,
                state_dir_fd,
                label="cleanup worker container lock",
                revalidate=revalidate_all,
            )
            _prove_inherited_flock_lease(
                compatibility_lock_fd,
                compatibility_probe_fd,
                label="cleanup worker compatibility lock",
                revalidate=revalidate_all,
            )
            for descriptor in lock_fds:
                os.set_inheritable(descriptor, False)
                if os.get_inheritable(descriptor):
                    raise ReviewError(
                        "cleanup worker lock descriptor remained inheritable"
                    )
            revalidate_all()
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot validate inherited cleanup worker locks safely: {error}"
        ) from error
    finally:
        if compatibility_probe_fd is not None:
            os.close(compatibility_probe_fd)


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
            if _runner_lock_held(
                state_dir,
                marker=marker,
                state_dir_fd=state_dir_fd,
                revalidate_state_directory=revalidate_state_directory,
            ):
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
                    _bound_state_marker_version(marker.version)
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
                    _bound_state_marker_version(marker.version)
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
            if exit_code is None:
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
                    text=("review runner exited without recording a terminal result\n"),
                )
                if exit_error or diagnostic_error:
                    raise ReviewError(
                        "cannot persist missing runner terminal state: "
                        + "; ".join(
                            error for error in (exit_error, diagnostic_error) if error
                        )
                    )
                exit_code = 1
            pid_value = state.get("pid")
            _reap_started_process(pid_value if isinstance(pid_value, int) else 0)
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
            if (
                not should_keep
                and not isinstance(review, LegacyReviewWorkspace)
                and cleanup_error is None
            ):
                revalidate_state_directory()
                cleanup_error = validate_retained_cleanup_postcondition(review)
                revalidate_state_directory()
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
    elif isinstance(handle, _CleanupLockSet):
        acquired = []
        for descriptor in handle.container.filenos():
            if _acquire_cleanup_lock_descriptor(descriptor, deadline=deadline):
                acquired.append(descriptor)
                continue
            for acquired_descriptor in reversed(acquired):
                fcntl.flock(acquired_descriptor, fcntl.LOCK_UN)
            return False
        try:
            # Serialize first creation and its chmod/identity validation under
            # the preparation-bound container lease.
            handle.open_compatibility()
        except BaseException:
            for acquired_descriptor in reversed(acquired):
                fcntl.flock(acquired_descriptor, fcntl.LOCK_UN)
            raise
        descriptors = [handle.compatibility.fileno()]
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
                    "-B",
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
    if exit_code == 0:
        payload = _read_modern_bound_state_artifact(
            state_dir,
            name="final.txt",
            max_bytes=MAX_FINAL_ARTIFACT_BYTES,
        )
        text = (
            payload.decode("utf-8", errors="replace").strip()
            if payload is not None
            else ""
        )
        if text:
            return 0, text
    details = (
        summary.get("runner_error")
        or summary.get("stderr_tail")
        or "review failed without a final artifact"
    )
    if summary.get("fallback_workspace_retained"):
        details = (
            f"{details}\nlegacy helper workspace retained for diagnosis only: "
            f"{summary['fallback_workspace']}"
        )
    return int(wait_code or exit_code or 1), str(details)
