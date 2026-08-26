from __future__ import annotations

import contextlib
import contextvars
import copy
import ctypes
import errno
import fcntl
import functools
import hashlib
import json
import os
import pathlib
import re
import secrets
import selectors
import signal
import shutil
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, ParamSpec, Sequence, TypeVar

from .common import (
    ForwardedSignal,
    ForwardedSignalMaskOwner,
    OwnedProcessLease,
    ProcessStartOwner,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
    _is_process_control_flow_error,
    _process_group_exists,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    mark_process_quiescence_unproven,
    process_quiescence_unproven,
    resolve_git,
    run as run_process,
    run_bounded_capture,
    terminate_process_group,
)


WORKSPACE_SCHEMA_VERSION = "review-workspace-v1"
PREPARED_WORKSPACE_RECEIPT_SCHEMA_VERSION = "review-workspace-prepare-v2"
SOURCE_AUTHORITY_BINDING_SCHEMA_VERSION = "review-source-authority-binding-v1"
SOURCE_AUTHORITY_BINDING_ENCODING = "canonical-json-utf8-v1"
SOURCE_AUTHORITY_BINDING_DIGEST_ALGORITHM = "sha256-canonical-json-utf8-v1"
SOURCE_AUTHORITY_BINDING_PATH_ENCODING = "utf8-only-canonical-absolute-v1"
SOURCE_AUTHORITY_BINDING_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
WORKSPACE_MARKER = "review-workspace.json"
RANGE_OBJECT_MANIFEST = "review-range-objects"
PARENT_SUPPORT_OBJECT_MANIFEST = "review-parent-support-objects"
SOURCE_SHALLOW_MANIFEST = "review-source-shallow"
PARTIAL_RECOVERY_SCHEMA_VERSION = "review-workspace-partial-recovery-v1"
PARTIAL_RECOVERY_PREFIX = ".review-partial-recovery-"
ATTRIBUTES_PAYLOAD = b"* diff -text -eol -filter -ident -working-tree-encoding\n"
GIT_TIMEOUT_SECONDS = 120.0
OBJECT_INTEGRITY_TIMEOUT_SECONDS = 900.0
GIT_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
MARKER_LIMIT_BYTES = 64 * 1024
MISSING_OBJECT_SAMPLE_LIMIT = 32
RANGE_COMMIT_COUNT_LIMIT = 250_000
RANGE_OBJECT_COUNT_LIMIT = 250_000
RANGE_PARENT_EDGE_COUNT_LIMIT = 250_000
RANGE_OBJECT_LOGICAL_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
RANGE_PACK_BYTES_LIMIT = 768 * 1024 * 1024
RANGE_PACK_INDEX_BYTES_LIMIT = 256 * 1024 * 1024
CHECKOUT_ENTRY_COUNT_LIMIT = 100_000
CHECKOUT_LOGICAL_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
CHECKOUT_PATH_BYTES_LIMIT = 64 * 1024 * 1024
CHECKOUT_TREE_OUTPUT_LIMIT = 96 * 1024 * 1024
SYMLINK_COUNT_LIMIT = 4_096
SYMLINK_TARGET_LIMIT_BYTES = 16 * 1024
SYMLINK_TARGET_AGGREGATE_LIMIT_BYTES = 64 * 1024 * 1024
SYMLINK_BATCH_HEADER_LIMIT_BYTES = 128
SYMLINK_BATCH_OUTPUT_LIMIT_BYTES = SYMLINK_TARGET_AGGREGATE_LIMIT_BYTES + (
    SYMLINK_COUNT_LIMIT * (SYMLINK_BATCH_HEADER_LIMIT_BYTES + 2)
)
SYMLINK_RESOLUTION_COMPONENT_LIMIT = 100_000
OBJECT_STORE_OBJECT_COUNT_LIMIT = 4_000_000
OBJECT_STORE_FILE_COUNT_LIMIT = 1_000_000
OBJECT_STORE_LOGICAL_BYTES_LIMIT = 32 * 1024 * 1024 * 1024
OBJECT_STORE_PHYSICAL_BYTES_LIMIT = 32 * 1024 * 1024 * 1024
OBJECT_STORE_PATH_BYTES_LIMIT = 256 * 1024 * 1024
WORKSPACE_PREPARATION_DEADLINE_SECONDS = 900.0
PARENT_SUPPORT_VALIDATION_DEADLINE_SECONDS = 900.0
OBJECT_STORE_FREE_SPACE_HEADROOM_BYTES = 512 * 1024 * 1024
CONTROL_FILE_SIZE_LIMIT = 256 * 1024 * 1024
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FILTER_DRIVER = re.compile(r"[A-Za-z0-9_.-]+\Z")
LOOSE_OBJECT_PATH = re.compile(r"[0-9a-f]{2}/(?:[0-9a-f]{38}|[0-9a-f]{62})\Z")
CLEANUP_TOKEN_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CLEANUP_TOKEN_PREFIX = "rw1_"
MINIMUM_GIT_VERSION = (2, 45, 0)
_GIT_VERSION_OUTPUT = re.compile(
    rb"git version ([0-9]+)\.([0-9]+)\.([0-9]+)"
    rb"(?: \(Apple Git-[0-9]+(?:\.[0-9]+)*\))?\Z"
)
_OPERATION_GIT: contextvars.ContextVar[pathlib.Path | None] = contextvars.ContextVar(
    "review_workspace_operation_git",
    default=None,
)
_P = ParamSpec("_P")
_R = TypeVar("_R")

_OBJECT_SNAPSHOT_COMMAND = (
    "rev-list",
    "--objects",
    "--missing=print",
    "--no-object-names",
    "--no-walk=unsorted",
    "--stdin",
)

_CONTROL_DIRECTORIES = (
    (".git",),
    (".git", "info"),
    (".git", "objects"),
    (".git", "refs"),
    (".git", "refs", "review-workspace"),
)
_STATIC_CONTROL_FILES = (
    (".git", "config"),
    (".git", "HEAD"),
    (".git", "refs", "review-workspace", "base"),
    (".git", "refs", "review-workspace", "head"),
    (".git", "info", "attributes"),
    (".git", RANGE_OBJECT_MANIFEST),
    (".git", PARENT_SUPPORT_OBJECT_MANIFEST),
    (".git", SOURCE_SHALLOW_MANIFEST),
)


class ReviewWorkspaceError(ReviewError):
    """A stable review-workspace precondition or validation failure."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        status: str = "blocked-safety",
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.reason = reason
        self.status = status
        self.details = dict(details or {})
        super().__init__(message)

    def payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            **self.details,
        }


class _WorkspaceSecondaryDiagnostic(Exception):
    """Python 3.10-visible secondary failure without replacing the primary."""


def _attach_workspace_diagnostic(error: BaseException, diagnostic: str) -> None:
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)
        return
    node = _WorkspaceSecondaryDiagnostic(diagnostic)
    if error.__cause__ is not None:
        node.__cause__ = error.__cause__
    elif not error.__suppress_context__ and error.__context__ is not None:
        node.__context__ = error.__context__
    error.__cause__ = node


def _attach_workspace_diagnostic_preserving_cause(
    error: BaseException,
    diagnostic: str,
) -> None:
    """Expose text without replacing any already-bound causal predecessor."""

    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)
        return
    tail = error
    visited: set[int] = set()
    while tail.__cause__ is not None and id(tail) not in visited:
        visited.add(id(tail))
        tail = tail.__cause__
    _attach_workspace_diagnostic(tail, diagnostic)


def _attach_workspace_failure_diagnostic(
    primary: BaseException,
    secondary: BaseException,
    *,
    context: str,
) -> None:
    """Expose a secondary failure without replacing an explicit primary cause."""

    if primary is secondary:
        return
    detail = str(secondary).strip()
    diagnostic = f"{context} ({type(secondary).__name__})"
    reason = getattr(secondary, "reason", None)
    if isinstance(reason, str) and reason:
        diagnostic += f" [{reason}]"
    if detail:
        diagnostic += f": {detail}"
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)
        return
    # Python 3.10 has no exception notes. Append the visible diagnostic below
    # the existing explicit-cause chain so every causal identity remains intact.
    _attach_workspace_diagnostic_preserving_cause(primary, diagnostic)


def _bind_workspace_failure_cause(
    primary: BaseException,
    cause: BaseException | None,
    *,
    context: str,
) -> None:
    """Bind one causal predecessor while retaining any existing explicit cause."""

    if cause is None or primary is cause:
        return
    if primary.__cause__ is None:
        primary.__cause__ = cause
        primary.__suppress_context__ = True
        return
    if primary.__cause__ is not cause:
        _attach_workspace_failure_diagnostic(
            primary,
            cause,
            context=context,
        )


@dataclass(frozen=True)
class _RecoveryProcessIdentity:
    pid: int
    pgid: int
    start_identity: str

    def payload(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "pgid": self.pgid,
            "start_identity": self.start_identity,
        }


class RangeIncomplete(ReviewWorkspaceError):
    """The frozen committed range is not locally complete without fetching."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        base: str,
        head: str,
        source_shallow: bool | None,
        source_promisor: bool | None = None,
        missing_objects: Sequence[str] = (),
    ) -> None:
        fetch = f"git fetch --no-tags --recurse-submodules=no <remote> {base} {head}"
        deepen = (
            "If the exact base is beyond the shallow boundary, deepen only the "
            "selected branch in the smallest useful increments with "
            "git fetch --no-tags --recurse-submodules=no --deepen=<small-step> "
            "<remote> <branch>. Do not default to --unshallow."
        )
        missing_sample = tuple(missing_objects[:MISSING_OBJECT_SAMPLE_LIMIT])
        super().__init__(
            reason,
            message,
            status="range-incomplete",
            details={
                "base": base,
                "head": head,
                "source_shallow": source_shallow,
                "source_promisor": source_promisor,
                "missing_object_count": len(missing_objects),
                "missing_objects": list(missing_sample),
                "missing_objects_truncated": len(missing_objects) > len(missing_sample),
                "remediation": {
                    "recommended_action": (
                        "batch-exact-object-fetch"
                        if source_promisor and missing_objects
                        else "fetch-exact-endpoints-or-deepen"
                    ),
                    "batch_exact_object_fetch": {
                        "applicable": bool(source_promisor and missing_objects),
                        "command": (
                            "git fetch-pack --stdin --no-progress <promisor-url>"
                        ),
                        "stdin": (
                            "Pass the reported missing_objects, one object ID per "
                            "line. Rerun prepare-workspace and repeat when "
                            "missing_objects_truncated is true."
                        ),
                        "fallback": (
                            "If the server rejects exact reachable-object wants, "
                            "stop and choose an explicitly approved, narrowly "
                            "scoped hydration method; do not refetch or unfilter "
                            "the whole repository by default."
                        ),
                    },
                    "fetch_exact_endpoints": fetch,
                    "shallow_history": deepen,
                    "constraints": [
                        "fetch no tags",
                        "do not recurse into submodules",
                        "batch only the reported promisor objects when applicable",
                        "fetch or deepen only the missing committed range",
                        "rerun prepare-workspace after the local objects exist",
                    ],
                },
            },
        )


@dataclass(frozen=True)
class PreparedWorkspace:
    root: pathlib.Path
    base_sha: str
    head_sha: str
    object_format: str
    strategy: str
    source_shallow: bool
    commit_count: int
    range_object_count: int
    range_object_sha256: str
    parent_support_object_count: int
    parent_support_object_sha256: str
    config_sha256: str
    shallow_bytes: str
    shallow_sha256: str
    cleanup_token: str
    parent_identity: tuple[int, int, int]
    workspace_identity: tuple[int, int, int]
    git_identity: tuple[int, int, int]
    objects_identity: tuple[int, int, int]
    marker_sha256: str
    cleanup_token_sha256: str
    _source_authority_binding_bytes: bytes = field(repr=False, compare=False)
    source_authority_binding_sha256: str
    _handoff_signal_mask: ForwardedSignalMaskOwner | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def receipt(self) -> dict[str, object]:
        try:
            source_authority_binding, _ = (
                parse_canonical_source_authority_binding_bytes(
                    self._source_authority_binding_bytes,
                    self.source_authority_binding_sha256,
                )
            )
        except SourceAuthorityBindingError as error:
            raise ReviewWorkspaceError(
                "source-authority-binding-invalid",
                "prepared source-authority binding is not canonical or digest-bound",
            ) from error
        return {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "receipt_schema_version": PREPARED_WORKSPACE_RECEIPT_SCHEMA_VERSION,
            "status": "ok",
            "command": "prepare-workspace",
            "worktree": str(self.root),
            "base": self.base_sha,
            "head": self.head_sha,
            "object_format": self.object_format,
            "strategy": self.strategy,
            "source_shallow": self.source_shallow,
            "commit_count": self.commit_count,
            "range_object_count": self.range_object_count,
            "range_object_sha256": self.range_object_sha256,
            "parent_support_object_count": self.parent_support_object_count,
            "parent_support_object_sha256": self.parent_support_object_sha256,
            "config_sha256": self.config_sha256,
            "shallow_bytes": self.shallow_bytes,
            "shallow_sha256": self.shallow_sha256,
            "cleanup_token": self.cleanup_token,
            "parent_identity": {
                "device": self.parent_identity[0],
                "inode": self.parent_identity[1],
                "uid": self.parent_identity[2],
            },
            "workspace_identity": {
                "device": self.workspace_identity[0],
                "inode": self.workspace_identity[1],
                "uid": self.workspace_identity[2],
            },
            "git_identity": {
                "device": self.git_identity[0],
                "inode": self.git_identity[1],
                "uid": self.git_identity[2],
            },
            "objects_identity": {
                "device": self.objects_identity[0],
                "inode": self.objects_identity[1],
                "uid": self.objects_identity[2],
            },
            "marker_sha256": self.marker_sha256,
            "cleanup_token_sha256": self.cleanup_token_sha256,
            "source_authority_binding": source_authority_binding,
            "source_authority_binding_sha256": (self.source_authority_binding_sha256),
        }


@dataclass(frozen=True)
class ValidatedWorkspace:
    root: pathlib.Path
    base_sha: str
    head_sha: str
    object_format: str
    strategy: str
    source_shallow: bool
    commit_count: int
    range_object_count: int
    range_object_sha256: str
    parent_support_object_count: int
    parent_support_object_sha256: str
    config_sha256: str
    shallow_bytes: str
    shallow_sha256: str
    symlink_count: int
    parent_identity: tuple[int, int, int]
    workspace_identity: tuple[int, int, int]
    git_identity: tuple[int, int, int]
    objects_identity: tuple[int, int, int]
    marker_sha256: str
    cleanup_token_sha256: str

    def receipt(self) -> dict[str, object]:
        return {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "status": "ok",
            "command": "validate-workspace",
            "worktree": str(self.root),
            "base": self.base_sha,
            "head": self.head_sha,
            "object_format": self.object_format,
            "strategy": self.strategy,
            "source_shallow": self.source_shallow,
            "commit_count": self.commit_count,
            "range_object_count": self.range_object_count,
            "range_object_sha256": self.range_object_sha256,
            "parent_support_object_count": self.parent_support_object_count,
            "parent_support_object_sha256": self.parent_support_object_sha256,
            "config_sha256": self.config_sha256,
            "shallow_bytes": self.shallow_bytes,
            "shallow_sha256": self.shallow_sha256,
            "symlink_count": self.symlink_count,
            "parent_identity": {
                "device": self.parent_identity[0],
                "inode": self.parent_identity[1],
                "uid": self.parent_identity[2],
            },
            "workspace_identity": {
                "device": self.workspace_identity[0],
                "inode": self.workspace_identity[1],
                "uid": self.workspace_identity[2],
            },
            "git_identity": {
                "device": self.git_identity[0],
                "inode": self.git_identity[1],
                "uid": self.git_identity[2],
            },
            "objects_identity": {
                "device": self.objects_identity[0],
                "inode": self.objects_identity[1],
                "uid": self.objects_identity[2],
            },
            "marker_sha256": self.marker_sha256,
            "cleanup_token_sha256": self.cleanup_token_sha256,
        }


@dataclass(frozen=True)
class CleanedWorkspace:
    root: pathlib.Path
    command: str = "cleanup-workspace"
    cleanup_status: str = "complete"
    tombstone_status: str | None = None
    _handoff_signal_mask: ForwardedSignalMaskOwner | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def receipt(self) -> dict[str, object]:
        receipt: dict[str, object] = {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "status": "ok",
            "command": self.command,
            "worktree": str(self.root),
            "cleanup_status": self.cleanup_status,
        }
        if self.tombstone_status is not None:
            receipt["tombstone_status"] = self.tombstone_status
        return receipt


@dataclass(frozen=True)
class _SourceDirectoryAuthority:
    label: str
    path: pathlib.Path
    identity: tuple[int, int, int]


@dataclass(frozen=True)
class _SourceControlFileAuthority:
    path: pathlib.Path
    identity: tuple[int, int, int]
    file_type: int
    size: int
    sha256: str


@dataclass(frozen=True)
class _SourceGitMarkerAuthority:
    path: pathlib.Path
    expected_admin: pathlib.Path
    identity: tuple[int, int, int]
    file_type: int
    kind: str
    size: int | None
    sha256: str | None
    back_pointer: _SourceControlFileAuthority | None


@dataclass(frozen=True)
class _SourceRepository:
    root: pathlib.Path
    marker: _SourceGitMarkerAuthority
    commondir: _SourceControlFileAuthority | None
    git_dir: pathlib.Path
    common_dir: pathlib.Path
    object_stores: tuple[pathlib.Path, ...]
    object_info_identity: tuple[int, int, int] | None
    authorities: tuple[_SourceDirectoryAuthority, ...]
    object_format: str
    shallow_path: pathlib.Path | None
    shallow_payload: bytes
    promisor: bool


@dataclass(frozen=True)
class _RawCommitGraphProbe:
    parents: Mapping[str, tuple[str, ...]]
    missing: frozenset[str]
    returncode: int
    stderr_preview: str


@dataclass(frozen=True)
class _RawCommitScope:
    range_commits: tuple[str, ...]
    base_support_commits: tuple[str, ...]
    parent_snapshot_commits: tuple[str, ...]
    shallow_boundaries: tuple[str, ...]


@dataclass(frozen=True)
class _DirectoryControlSnapshot:
    relative: tuple[str, ...]
    device: int
    inode: int
    uid: int
    mode: int


@dataclass(frozen=True)
class _FileControlSnapshot:
    relative: tuple[str, ...]
    device: int
    inode: int
    uid: int
    mode: int
    link_count: int
    size: int
    mtime_ns: int = field(compare=False)
    ctime_ns: int = field(compare=False)
    sha256: str
    payload: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _WorkspaceControlBinding:
    root: pathlib.Path
    include_index: bool
    include_marker: bool
    marker_only: bool
    directories: tuple[_DirectoryControlSnapshot, ...]
    files: tuple[_FileControlSnapshot, ...]

    def revalidate(self) -> None:
        observed_directories, observed_files = _snapshot_workspace_controls(
            self.root,
            include_index=self.include_index,
            include_marker=self.include_marker,
            marker_only=self.marker_only,
        )
        if observed_directories != self.directories:
            raise ReviewWorkspaceError(
                "workspace-control-directory-drift",
                "workspace root or Git control-directory identity/access policy changed",
            )
        if observed_files != self.files:
            raise ReviewWorkspaceError(
                "workspace-control-file-drift",
                "workspace Git control-file identity/content/access policy changed",
            )

    def payload(self, relative: tuple[str, ...]) -> bytes:
        for snapshot in self.files:
            if snapshot.relative == relative and snapshot.payload is not None:
                return snapshot.payload
        raise ReviewWorkspaceError(
            "workspace-control-file-missing",
            "workspace Git control payload is not bound",
        )


def _nofollow_flags(*, directory: bool) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise ReviewWorkspaceError(
            "workspace-nofollow-unavailable",
            "the host does not expose O_NOFOLLOW for workspace control custody",
        )
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _validate_no_extended_acl(descriptor: int, label: str) -> None:
    """Reject macOS extended ACLs that POSIX mode bits do not describe."""

    if os.uname().sysname != "Darwin":
        return
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        acl_get_fd_np = library.acl_get_fd_np
        acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
        acl_get_fd_np.restype = ctypes.c_void_p
        acl_get_entry = library.acl_get_entry
        acl_get_entry.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        )
        acl_get_entry.restype = ctypes.c_int
        acl_free = library.acl_free
        acl_free.argtypes = (ctypes.c_void_p,)
        acl_free.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise ReviewWorkspaceError(
            "workspace-acl-policy-unavailable",
            f"{label} extended ACL policy cannot be inspected",
        ) from error
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)
    if not acl:
        acl_errno = ctypes.get_errno()
        if acl_errno in {errno.ENOENT, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise ReviewWorkspaceError(
            "workspace-acl-policy-unavailable",
            f"{label} extended ACL policy cannot be inspected",
            details={"errno": acl_errno},
        )
    try:
        entry = ctypes.c_void_p()
        result = acl_get_entry(acl, 0, ctypes.byref(entry))
        if result == 0:
            raise ReviewWorkspaceError(
                "workspace-extended-acl",
                f"{label} must not carry an extended ACL",
            )
        acl_errno = ctypes.get_errno()
        if result != -1 or acl_errno != errno.EINVAL:
            raise ReviewWorkspaceError(
                "workspace-acl-policy-unavailable",
                f"{label} extended ACL policy cannot be enumerated",
                details={"errno": acl_errno},
            )
    finally:
        acl_free(acl)


def _validate_private_directory_metadata(
    metadata: os.stat_result,
    label: str,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReviewWorkspaceError(
            "workspace-control-directory-policy",
            f"{label} must be an owner-private mode-0700 directory",
        )


def _directory_snapshot_from_descriptor(
    descriptor: int,
    relative: tuple[str, ...],
) -> _DirectoryControlSnapshot:
    metadata = os.fstat(descriptor)
    label = "workspace root" if not relative else "/".join(relative)
    _validate_private_directory_metadata(metadata, label)
    _validate_no_extended_acl(descriptor, label)
    return _DirectoryControlSnapshot(
        relative=relative,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _open_relative_directory(root_descriptor: int, parts: Sequence[str]) -> int:
    descriptor = os.dup(root_descriptor)
    child = -1
    result = -1
    operation_error: BaseException | None = None
    try:
        traversed: list[str] = []
        for part in parts:
            child = os.open(
                part,
                _nofollow_flags(directory=True),
                dir_fd=descriptor,
            )
            traversed.append(part)
            _validate_private_directory_metadata(
                os.fstat(child),
                "/".join(traversed),
            )
            _validate_no_extended_acl(child, "/".join(traversed))
            previous = descriptor
            descriptor = -1
            os.close(previous)
            descriptor = child
            child = -1
        result = descriptor
        descriptor = -1
    except BaseException as error:
        operation_error = error
    close_failures = _attempt_workspace_descriptor_closes(
        (
            ("relative-directory child descriptor close failed", child),
            ("relative-directory descriptor close failed", descriptor),
        )
    )
    if operation_error is not None:
        _attach_workspace_teardown_failures(operation_error, close_failures)
        raise operation_error
    close_error = _select_workspace_teardown_failure(close_failures)
    if close_error is not None:
        raise close_error
    return result


def _snapshot_control_file(
    root_descriptor: int,
    relative: tuple[str, ...],
    *,
    capture_payload: bool,
) -> _FileControlSnapshot:
    parent_descriptor = _open_relative_directory(root_descriptor, relative[:-1])
    try:
        descriptor = os.open(
            relative[-1],
            _nofollow_flags(directory=False),
            dir_fd=parent_descriptor,
        )
    except BaseException as error:
        close_failures = _attempt_workspace_descriptor_closes(
            (("control-file parent descriptor close failed", parent_descriptor),)
        )
        _attach_workspace_teardown_failures(error, close_failures)
        raise
    label = "/".join(relative)

    def validate_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > CONTROL_FILE_SIZE_LIMIT
        ):
            raise ReviewWorkspaceError(
                "workspace-control-file-policy",
                (
                    f"{label} must be an owner-held single-link "
                    "mode-0600 bounded regular file"
                ),
            )

    def protected_metadata(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
        )

    def read_complete() -> tuple[int, str, bytes | None]:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        captured = bytearray() if capture_payload else None
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > CONTROL_FILE_SIZE_LIMIT:
                raise ReviewWorkspaceError(
                    "workspace-control-file-policy",
                    f"{label} exceeds its content bound",
                )
            digest.update(chunk)
            if captured is not None:
                captured.extend(chunk)
        return total, digest.hexdigest(), None if captured is None else bytes(captured)

    def revalidate_after_read(
        expected: os.stat_result,
    ) -> tuple[os.stat_result, os.stat_result]:
        final_metadata = os.fstat(descriptor)
        final_path_metadata = os.stat(
            relative[-1],
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        validate_metadata(final_metadata)
        validate_metadata(final_path_metadata)
        _validate_no_extended_acl(descriptor, label)
        if (
            protected_metadata(final_metadata) != protected_metadata(expected)
            or protected_metadata(final_path_metadata)
            != protected_metadata(final_metadata)
            or not os.path.samestat(final_metadata, final_path_metadata)
        ):
            raise ReviewWorkspaceError(
                "workspace-control-file-unstable",
                f"{label} identity, content size, or access policy changed",
            )
        return final_metadata, final_path_metadata

    result: _FileControlSnapshot | None = None
    operation_error: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        validate_metadata(metadata)
        _validate_no_extended_acl(descriptor, label)
        total, digest, captured = read_complete()
        final_metadata, final_path_metadata = revalidate_after_read(metadata)
        if total != metadata.st_size:
            raise ReviewWorkspaceError(
                "workspace-control-file-unstable",
                f"{label} content size changed while it was bound",
            )
        timestamp_changed = (
            final_metadata.st_mtime_ns != metadata.st_mtime_ns
            or final_metadata.st_ctime_ns != metadata.st_ctime_ns
            or final_path_metadata.st_mtime_ns != final_metadata.st_mtime_ns
            or final_path_metadata.st_ctime_ns != final_metadata.st_ctime_ns
        )
        if timestamp_changed:
            try:
                repeated_total, repeated_digest, repeated_payload = read_complete()
                repeated_metadata, repeated_path = revalidate_after_read(
                    final_path_metadata
                )
            except OSError as error:
                raise ReviewWorkspaceError(
                    "workspace-control-file-revalidation-unavailable",
                    f"{label} could not be completely revalidated",
                    status="inconclusive",
                ) from error
            if (
                repeated_total != total
                or not secrets.compare_digest(repeated_digest, digest)
                or repeated_payload != captured
            ):
                raise ReviewWorkspaceError(
                    "workspace-control-file-unstable",
                    f"{label} content changed during bounded revalidation",
                )
            if (
                repeated_metadata.st_mtime_ns != final_path_metadata.st_mtime_ns
                or repeated_metadata.st_ctime_ns != final_path_metadata.st_ctime_ns
                or repeated_path.st_mtime_ns != repeated_metadata.st_mtime_ns
                or repeated_path.st_ctime_ns != repeated_metadata.st_ctime_ns
            ):
                raise ReviewWorkspaceError(
                    "workspace-control-file-revalidation-unavailable",
                    f"{label} timestamp state changed during bounded revalidation",
                    status="inconclusive",
                )
            final_metadata = repeated_metadata
            digest = repeated_digest
            captured = repeated_payload
        result = _FileControlSnapshot(
            relative=relative,
            device=final_metadata.st_dev,
            inode=final_metadata.st_ino,
            uid=final_metadata.st_uid,
            mode=stat.S_IMODE(final_metadata.st_mode),
            link_count=final_metadata.st_nlink,
            size=final_metadata.st_size,
            mtime_ns=final_metadata.st_mtime_ns,
            ctime_ns=final_metadata.st_ctime_ns,
            sha256=digest,
            payload=captured,
        )
    except OSError as error:
        operation_error = ReviewWorkspaceError(
            "workspace-control-file-unavailable",
            f"{label} could not be completely read and validated",
            status="inconclusive",
        )
        _bind_workspace_failure_cause(
            operation_error,
            error,
            context="control-file read failure",
        )
    except BaseException as error:
        operation_error = error
    close_failures = _attempt_workspace_descriptor_closes(
        (
            ("control-file descriptor close failed", descriptor),
            ("control-file parent descriptor close failed", parent_descriptor),
        )
    )
    if operation_error is not None:
        _attach_workspace_teardown_failures(operation_error, close_failures)
        raise operation_error
    close_error = _select_workspace_teardown_failure(close_failures)
    if close_error is not None:
        raise close_error
    assert result is not None
    return result


def _snapshot_workspace_controls(
    root: pathlib.Path,
    *,
    include_index: bool,
    include_marker: bool,
    marker_only: bool = False,
) -> tuple[tuple[_DirectoryControlSnapshot, ...], tuple[_FileControlSnapshot, ...]]:
    try:
        root_descriptor = os.open(root, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-control-root-unavailable",
            "workspace root cannot be opened without following links",
        ) from error
    try:
        directories = [_directory_snapshot_from_descriptor(root_descriptor, ())]
        control_directories = ((".git",),) if marker_only else _CONTROL_DIRECTORIES
        for relative in control_directories:
            descriptor = _open_relative_directory(root_descriptor, relative)
            try:
                directories.append(
                    _directory_snapshot_from_descriptor(descriptor, relative)
                )
            finally:
                os.close(descriptor)
        file_paths = [] if marker_only else list(_STATIC_CONTROL_FILES)
        if not marker_only:
            git_descriptor = _open_relative_directory(root_descriptor, (".git",))
            try:
                try:
                    os.stat("shallow", dir_fd=git_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    file_paths.append((".git", "shallow"))
            finally:
                os.close(git_descriptor)
        if include_index and not marker_only:
            file_paths.append((".git", "index"))
        if include_marker:
            file_paths.append((".git", WORKSPACE_MARKER))
        files = tuple(
            _snapshot_control_file(
                root_descriptor,
                relative,
                capture_payload=relative
                not in {
                    (".git", RANGE_OBJECT_MANIFEST),
                },
            )
            for relative in file_paths
        )
        bound_root = os.fstat(root_descriptor)
        lexical_root = root.stat(follow_symlinks=False)
        _validate_private_directory_metadata(bound_root, "workspace root")
        _validate_no_extended_acl(root_descriptor, "workspace root")
        if not os.path.samestat(bound_root, lexical_root):
            raise ReviewWorkspaceError(
                "workspace-control-root-drift",
                "workspace root path changed while control state was bound",
            )
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-control-state-unavailable",
            "workspace Git control state cannot be opened safely",
        ) from error
    finally:
        os.close(root_descriptor)
    return tuple(directories), files


def _bind_workspace_controls(
    root: pathlib.Path,
    *,
    include_index: bool,
    include_marker: bool,
    marker_only: bool = False,
) -> _WorkspaceControlBinding:
    directories, files = _snapshot_workspace_controls(
        root,
        include_index=include_index,
        include_marker=include_marker,
        marker_only=marker_only,
    )
    return _WorkspaceControlBinding(
        root=root,
        include_index=include_index,
        include_marker=include_marker,
        marker_only=marker_only,
        directories=directories,
        files=files,
    )


def _bind_workspace_marker(root: pathlib.Path) -> _WorkspaceControlBinding:
    return _bind_workspace_controls(
        root,
        include_index=False,
        include_marker=True,
        marker_only=True,
    )


def _git_environment() -> dict[str, str]:
    return {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
    }


def _validate_git_executable(git: pathlib.Path) -> None:
    """Validate the fixed Git trust root before any repository operation."""

    try:
        capture = run_bounded_capture(
            (str(git), "--version"),
            env=_git_environment(),
            timeout_seconds=30.0,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )
    except (
        ForwardedSignal,
        ReviewTimeoutError,
        ReviewOutputLimitError,
        ReviewOutputDrainError,
        ReviewProcessLeakError,
    ):
        raise
    except BaseException as error:
        if _is_process_control_flow_error(error):
            raise
        raise ReviewWorkspaceError(
            "git-version-unverified",
            "the fixed Git executable version could not be validated",
        ) from error
    try:
        output = bytes(capture.stdout)
        if output.endswith(b"\n"):
            output = output[:-1]
        if capture.returncode != 0 or capture.stderr:
            raise ReviewWorkspaceError(
                "git-version-unverified",
                "the fixed Git executable version could not be validated",
            )
        match = _GIT_VERSION_OUTPUT.fullmatch(output)
        if match is None:
            raise ReviewWorkspaceError(
                "git-version-unverified",
                "the fixed Git executable returned an unsupported version format",
            )
        version = tuple(int(component) for component in match.groups())
        if version < MINIMUM_GIT_VERSION:
            raise ReviewWorkspaceError(
                "git-version-unsupported",
                "review workspace preparation requires Git 2.45.0 or newer",
                details={
                    "minimum_version": "2.45.0",
                    "observed_version": ".".join(str(part) for part in version),
                },
            )
    finally:
        capture.zeroize()


@contextlib.contextmanager
def _validated_git_operation() -> Iterable[pathlib.Path]:
    """Resolve and validate Git once, then reuse that exact path throughout."""

    current = _OPERATION_GIT.get()
    if current is not None:
        yield current
        return
    try:
        git = resolve_git()
    except BaseException as error:
        if _is_process_control_flow_error(error):
            raise
        raise ReviewWorkspaceError(
            "git-executable-unavailable",
            "Git is not available at a fixed trusted executable path",
        ) from error
    if not git.is_absolute():
        raise ReviewWorkspaceError(
            "git-executable-unverified",
            "the fixed Git executable path must be absolute",
        )
    _validate_git_executable(git)
    token = _OPERATION_GIT.set(git)
    try:
        yield git
    finally:
        _OPERATION_GIT.reset(token)


def _requires_validated_git(function: Callable[_P, _R]) -> Callable[_P, _R]:
    @functools.wraps(function)
    def invoke(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with _validated_git_operation():
            return function(*args, **kwargs)

    return invoke


def _git_argv(root: pathlib.Path, arguments: Iterable[str]) -> tuple[str, ...]:
    git = _OPERATION_GIT.get()
    if git is None:
        raise ReviewWorkspaceError(
            "git-executable-unverified",
            "Git repository commands require a validated fixed executable",
        )
    return (
        str(git),
        "--no-pager",
        "--no-lazy-fetch",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "color.ui=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "diff.external=",
        "-C",
        str(root),
        *tuple(arguments),
    )


@_requires_validated_git
def _run_git_raw(
    root: pathlib.Path,
    arguments: Iterable[str],
    *,
    stdin: bytes | None = None,
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
    control_binding: _WorkspaceControlBinding | None = None,
    extra_environment: Mapping[str, str] | None = None,
    partial_recovery_control: _PartialRecoveryControl | None = None,
    partial_recovery_operation: str | None = None,
) -> tuple[int, bytes, bytes]:
    owns_recovery_control = (
        partial_recovery_control is None and control_binding is not None
    )
    if not owns_recovery_control:
        return _run_git_raw_impl(
            root,
            arguments,
            stdin=stdin,
            output_limit_bytes=output_limit_bytes,
            timeout_seconds=timeout_seconds,
            absolute_deadline=absolute_deadline,
            deadline_checker=deadline_checker,
            control_binding=control_binding,
            extra_environment=extra_environment,
            partial_recovery_control=partial_recovery_control,
            partial_recovery_operation=partial_recovery_operation,
        )

    signal_owner = _begin_forwarded_signal_mask()
    primary_error: BaseException | None = None
    try:
        return _run_git_raw_impl(
            root,
            arguments,
            stdin=stdin,
            output_limit_bytes=output_limit_bytes,
            timeout_seconds=timeout_seconds,
            absolute_deadline=absolute_deadline,
            deadline_checker=deadline_checker,
            control_binding=control_binding,
            extra_environment=extra_environment,
            partial_recovery_control=partial_recovery_control,
            partial_recovery_operation=partial_recovery_operation,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _finish_forwarded_signal_mask(
            signal_owner,
            primary_error=primary_error,
        )


def _run_git_raw_impl(
    root: pathlib.Path,
    arguments: Iterable[str],
    *,
    stdin: bytes | None = None,
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
    control_binding: _WorkspaceControlBinding | None = None,
    extra_environment: Mapping[str, str] | None = None,
    partial_recovery_control: _PartialRecoveryControl | None = None,
    partial_recovery_operation: str | None = None,
) -> tuple[int, bytes, bytes]:
    arguments = tuple(arguments)
    if control_binding is not None:
        control_binding.revalidate()
    owned_recovery_control = False
    if partial_recovery_control is None and control_binding is not None:
        partial_recovery_control = _PartialRecoveryControl.create(root)
        owned_recovery_control = True
    if partial_recovery_control is not None and partial_recovery_operation is None:
        partial_recovery_operation = "workspace-git"
    process_start = ProcessStartOwner()
    process_quiescent = False
    active_binding: _RecoveryProcessIdentity | None = None
    recovery_payload: dict[str, object] | None = None

    def publish_process_binding(binding: object) -> None:
        nonlocal active_binding
        assert partial_recovery_control is not None
        assert partial_recovery_operation is not None
        if not isinstance(binding, _RecoveryProcessIdentity):
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-invalid",
                "workspace Git process returned a malformed recovery identity",
                status="inconclusive",
            )
        partial_recovery_control.bind_process(
            partial_recovery_operation,
            binding,
        )
        active_binding = binding

    def publish_process_quiescent() -> None:
        nonlocal process_quiescent
        process_quiescent = True
        if partial_recovery_control is not None and active_binding is not None:
            partial_recovery_control.release_process(active_binding)

    def retain_unquiescent(error: BaseException) -> None:
        nonlocal recovery_payload
        if (
            partial_recovery_control is None
            or not process_start.may_have_started()
            or process_quiescent
        ):
            return
        recovery_payload = _retain_unquiesced_workspace(
            error,
            partial_recovery_control,
            diagnostic_context="workspace Git process",
        )

    primary_error: BaseException | None = None
    revalidation_error: BaseException | None = None
    absolute_deadline_controls_timeout = False
    try:
        environment = _git_environment()
        environment["GIT_CEILING_DIRECTORIES"] = str(root.parent)
        if control_binding is not None:
            environment["GIT_DIR"] = str(root / ".git")
            environment["GIT_WORK_TREE"] = str(root)
        if extra_environment:
            environment.update(extra_environment)
        if absolute_deadline is not None:
            remaining = absolute_deadline - time.monotonic()
            if remaining <= 0:
                (deadline_checker or _check_object_store_deadline)(absolute_deadline)
            absolute_deadline_controls_timeout = remaining <= timeout_seconds
            timeout_seconds = min(timeout_seconds, remaining)
        try:
            capture = run_bounded_capture(
                _git_argv(root, arguments),
                env=environment,
                stdin=None if stdin is None else bytearray(stdin),
                timeout_seconds=timeout_seconds,
                stdout_limit_bytes=output_limit_bytes,
                stderr_limit_bytes=1024 * 1024,
                prepare_process_spawned=(
                    _bind_recovery_process
                    if partial_recovery_control is not None
                    else None
                ),
                on_process_spawned=(
                    publish_process_binding
                    if partial_recovery_control is not None
                    else None
                ),
                on_process_starting=(
                    process_start.publish_starting
                    if partial_recovery_control is not None
                    else None
                ),
                on_process_started=(
                    process_start.publish_started
                    if partial_recovery_control is not None
                    else None
                ),
                on_process_quiescent=(
                    publish_process_quiescent
                    if partial_recovery_control is not None
                    else None
                ),
            )
        except ReviewTimeoutError:
            if absolute_deadline_controls_timeout:
                assert absolute_deadline is not None
                (deadline_checker or _check_object_store_deadline)(absolute_deadline)
            raise
        try:
            return capture.returncode, bytes(capture.stdout), bytes(capture.stderr)
        finally:
            capture.zeroize()
    except BaseException as error:
        primary_error = error
        retain_unquiescent(error)
        raise
    finally:
        try:
            if control_binding is not None:
                try:
                    control_binding.revalidate()
                except BaseException as error:
                    revalidation_error = error
                    if primary_error is not None and process_quiescence_unproven(
                        primary_error
                    ):
                        if recovery_payload is not None:
                            _inherit_unquiesced_workspace_retention(
                                error,
                                recovery_payload,
                            )
                        else:
                            mark_process_quiescence_unproven(error)
                            _mark_partial_workspace_for_retention(error)
                    raise
        finally:
            if owned_recovery_control and partial_recovery_control is not None:
                selected_error = revalidation_error or primary_error
                retain = selected_error is not None and (
                    _partial_workspace_requires_retention(selected_error)
                    or process_quiescence_unproven(selected_error)
                )
                try:
                    partial_recovery_control.close(retain=retain)
                except BaseException as control_error:
                    if selected_error is None:
                        raise
                    _attach_workspace_diagnostic(
                        selected_error,
                        "partial recovery control finalization failed: "
                        f"{type(control_error).__name__}",
                    )


def _run_git(
    root: pathlib.Path,
    arguments: Iterable[str],
    *,
    stdin: bytes | None = None,
    allowed_returncodes: tuple[int, ...] = (0,),
    reason: str = "git-command-failed",
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
    control_binding: _WorkspaceControlBinding | None = None,
    extra_environment: Mapping[str, str] | None = None,
    partial_recovery_control: _PartialRecoveryControl | None = None,
    partial_recovery_operation: str | None = None,
) -> bytes:
    returncode, stdout, _stderr = _run_git_raw(
        root,
        arguments,
        stdin=stdin,
        output_limit_bytes=output_limit_bytes,
        timeout_seconds=timeout_seconds,
        absolute_deadline=absolute_deadline,
        deadline_checker=deadline_checker,
        control_binding=control_binding,
        extra_environment=extra_environment,
        partial_recovery_control=partial_recovery_control,
        partial_recovery_operation=partial_recovery_operation,
    )
    if returncode not in allowed_returncodes:
        raise ReviewWorkspaceError(
            reason,
            f"bounded Git command failed with exit {returncode}",
        )
    return stdout


def _absolute_existing_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_absolute():
        raise ReviewWorkspaceError("invalid-path", f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as error:
        raise ReviewWorkspaceError(
            "invalid-path", f"{label} is not accessible"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReviewWorkspaceError("invalid-path", f"{label} must be a directory")
    return resolved


def _bind_source_directory_authority(
    path: pathlib.Path,
    label: str,
) -> _SourceDirectoryAuthority:
    """Bind one resolved source directory to its advertised filesystem object."""

    try:
        descriptor = os.open(path, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-authority-unavailable",
            f"{label} cannot be opened without following links",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        observed = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-authority-unavailable",
            f"{label} identity cannot be inspected",
        ) from error
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or not os.path.samestat(metadata, observed)
    ):
        raise ReviewWorkspaceError(
            "source-authority-identity-mismatch",
            f"{label} does not resolve to one stable directory object",
        )
    return _SourceDirectoryAuthority(
        label=label,
        path=path,
        identity=(metadata.st_dev, metadata.st_ino, metadata.st_uid),
    )


def _bind_source_directory_authorities(
    root: pathlib.Path,
    git_dir: pathlib.Path,
    common_dir: pathlib.Path,
    object_stores: Sequence[pathlib.Path],
) -> tuple[_SourceDirectoryAuthority, ...]:
    candidates = (
        ("source worktree", root),
        ("source Git directory", git_dir),
        ("source common Git directory", common_dir),
        *(
            (f"source object authority {index}", path)
            for index, path in enumerate(object_stores)
        ),
    )
    authorities: list[_SourceDirectoryAuthority] = []
    seen: set[tuple[int, int]] = set()
    for label, path in candidates:
        authority = _bind_source_directory_authority(path, label)
        object_identity = authority.identity[:2]
        if object_identity in seen:
            continue
        seen.add(object_identity)
        authorities.append(authority)
    return tuple(authorities)


def _decode_git_path(payload: bytes, label: str) -> pathlib.Path:
    try:
        value = os.fsdecode(payload.rstrip(b"\n"))
    except UnicodeError as error:
        raise ReviewWorkspaceError(
            "repository-layout-invalid", f"{label} is not decodable"
        ) from error
    path = pathlib.Path(value)
    if not path.is_absolute():
        raise ReviewWorkspaceError(
            "repository-layout-invalid", f"{label} is not absolute"
        )
    return _absolute_existing_directory(path, label)


def _check_object_store_deadline(deadline: float) -> None:
    observed_at = time.monotonic()
    if observed_at >= deadline:
        observed_seconds = max(
            0.0,
            WORKSPACE_PREPARATION_DEADLINE_SECONDS + observed_at - deadline,
        )
        raise ReviewWorkspaceError(
            "workspace-preparation-deadline",
            "review workspace preparation exceeded its monotonic deadline",
            details={
                "metric": "elapsed seconds",
                "observed": observed_seconds,
                "limit": WORKSPACE_PREPARATION_DEADLINE_SECONDS,
            },
        )


def _check_parent_support_validation_deadline(deadline: float) -> None:
    observed_at = time.monotonic()
    if observed_at >= deadline:
        observed_seconds = max(
            0.0,
            PARENT_SUPPORT_VALIDATION_DEADLINE_SECONDS + observed_at - deadline,
        )
        raise ReviewWorkspaceError(
            "workspace-parent-support-validation-deadline",
            "workspace parent-support validation exceeded its monotonic deadline",
            details={
                "metric": "elapsed seconds",
                "observed": observed_seconds,
                "limit": PARENT_SUPPORT_VALIDATION_DEADLINE_SECONDS,
            },
        )


def _read_bounded_regular_file(
    path: pathlib.Path,
    *,
    limit: int,
    deadline: float,
    reason: str,
    label: str,
    unavailable_reason: str | None = None,
    revalidation_unavailable_reason: str | None = None,
    drift_reason: str | None = None,
) -> bytes:
    unavailable_reason = unavailable_reason or reason
    revalidation_unavailable_reason = revalidation_unavailable_reason or reason
    drift_reason = drift_reason or reason

    def signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
        )

    def read_once(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) <= limit:
            _check_object_store_deadline(deadline)
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        return bytes(payload)

    _check_object_store_deadline(deadline)
    try:
        descriptor = os.open(path, _nofollow_flags(directory=False))
    except OSError as error:
        raise ReviewWorkspaceError(
            unavailable_reason, f"{label} cannot be opened safely"
        ) from error
    try:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise ReviewWorkspaceError(
                unavailable_reason,
                f"{label} metadata cannot be inspected",
            ) from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ReviewWorkspaceError(
                reason,
                f"{label} must be a bounded regular file",
                details={"observed": metadata.st_size, "limit": limit},
            )
        try:
            payload = read_once(descriptor)
        except OSError as error:
            raise ReviewWorkspaceError(
                unavailable_reason, f"{label} cannot be read completely"
            ) from error
        try:
            final_metadata = os.fstat(descriptor)
            lexical_metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ReviewWorkspaceError(
                revalidation_unavailable_reason,
                f"{label} identity cannot be revalidated",
            ) from error
        if (
            len(payload) > limit
            or len(payload) != metadata.st_size
            or signature(metadata) != signature(final_metadata)
            or signature(final_metadata) != signature(lexical_metadata)
        ):
            raise ReviewWorkspaceError(
                drift_reason, f"{label} changed while it was read"
            )
        timestamp_changed = (
            final_metadata.st_mtime_ns != metadata.st_mtime_ns
            or final_metadata.st_ctime_ns != metadata.st_ctime_ns
            or lexical_metadata.st_mtime_ns != final_metadata.st_mtime_ns
            or lexical_metadata.st_ctime_ns != final_metadata.st_ctime_ns
        )
        if not timestamp_changed:
            return payload
        try:
            repeated_payload = read_once(descriptor)
            repeated_metadata = os.fstat(descriptor)
            repeated_lexical = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ReviewWorkspaceError(
                revalidation_unavailable_reason,
                f"{label} cannot be completely revalidated",
                status="inconclusive",
            ) from error
        if (
            repeated_payload != payload
            or len(repeated_payload) != metadata.st_size
            or signature(metadata) != signature(repeated_metadata)
            or signature(repeated_metadata) != signature(repeated_lexical)
        ):
            raise ReviewWorkspaceError(
                drift_reason,
                f"{label} changed during bounded content revalidation",
            )
        if (
            repeated_metadata.st_mtime_ns != lexical_metadata.st_mtime_ns
            or repeated_metadata.st_ctime_ns != lexical_metadata.st_ctime_ns
            or repeated_lexical.st_mtime_ns != repeated_metadata.st_mtime_ns
            or repeated_lexical.st_ctime_ns != repeated_metadata.st_ctime_ns
        ):
            raise ReviewWorkspaceError(
                revalidation_unavailable_reason,
                f"{label} timestamp state changed during bounded revalidation",
                status="inconclusive",
            )
        return payload
    finally:
        os.close(descriptor)


class SourceAuthorityBindingError(ValueError):
    """A malformed or non-canonical parent-owned source authority binding."""


class SourceAuthorityPathEncodingError(SourceAuthorityBindingError):
    """A path cannot be represented by the closed UTF-8 binding contract."""


def canonical_source_authority_binding_bytes(
    binding: Mapping[str, object],
) -> bytes:
    """Encode one closed source-authority binding for cross-phase handoff."""

    return json.dumps(
        binding,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def source_authority_binding_digest(binding: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_source_authority_binding_bytes(binding)).hexdigest()


def _source_authority_path_text(path: pathlib.Path) -> str:
    value = str(path)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise SourceAuthorityPathEncodingError(
            "source-authority binding paths must be valid UTF-8; "
            "non-UTF-8 filesystem byte paths are unsupported"
        ) from error
    return value


def source_authority_directory_record(
    path: pathlib.Path,
    identity: tuple[int, int, int],
) -> dict[str, object]:
    return {
        "path": _source_authority_path_text(path),
        "identity": {
            "device": identity[0],
            "inode": identity[1],
            "uid": identity[2],
        },
    }


def source_authority_control_record(
    path: pathlib.Path,
    identity: tuple[int, int, int],
    *,
    file_type: int,
    size: int,
    sha256: str,
) -> dict[str, object]:
    return {
        "path": _source_authority_path_text(path),
        "identity": {
            "device": identity[0],
            "inode": identity[1],
            "uid": identity[2],
            "file_type": file_type,
        },
        "size": size,
        "sha256": sha256,
    }


def source_authority_common_marker_record(
    control: Mapping[str, object],
    resolved_common: pathlib.Path,
) -> dict[str, object]:
    return {
        **control,
        "resolved_common": _source_authority_path_text(resolved_common),
    }


def source_authority_marker_record(
    path: pathlib.Path,
    expected_admin: pathlib.Path,
    identity: tuple[int, int, int],
    *,
    file_type: int,
    kind: str,
    size: int | None,
    sha256: str | None,
) -> dict[str, object]:
    return {
        "path": _source_authority_path_text(path),
        "identity": {
            "device": identity[0],
            "inode": identity[1],
            "uid": identity[2],
            "file_type": file_type,
        },
        "kind": kind,
        "expected_admin": _source_authority_path_text(expected_admin),
        "size": size,
        "sha256": sha256,
    }


def build_source_authority_binding(
    *,
    source_worktree: Mapping[str, object],
    git_marker: Mapping[str, object],
    linked_worktree_back_pointer: Mapping[str, object] | None,
    git_common_directory_marker: Mapping[str, object] | None,
    git_admin: Mapping[str, object],
    git_common: Mapping[str, object],
    primary_object_store: Mapping[str, object],
    object_info_path: pathlib.Path,
    object_info_identity: tuple[int, int, int] | None,
) -> dict[str, object]:
    return {
        "schema_version": SOURCE_AUTHORITY_BINDING_SCHEMA_VERSION,
        "identity_encoding": SOURCE_AUTHORITY_BINDING_ENCODING,
        "identity_algorithm": SOURCE_AUTHORITY_BINDING_DIGEST_ALGORITHM,
        "path_encoding": SOURCE_AUTHORITY_BINDING_PATH_ENCODING,
        "source_authority_policy": "direct-primary-only",
        "source_worktree": dict(source_worktree),
        "git_marker": dict(git_marker),
        "linked_worktree_back_pointer": (
            None
            if linked_worktree_back_pointer is None
            else dict(linked_worktree_back_pointer)
        ),
        "git_common_directory_marker": (
            None
            if git_common_directory_marker is None
            else dict(git_common_directory_marker)
        ),
        "git_admin": dict(git_admin),
        "git_common": dict(git_common),
        "primary_object_store": dict(primary_object_store),
        "object_info": {
            "path": _source_authority_path_text(object_info_path),
            "identity": (
                None
                if object_info_identity is None
                else {
                    "device": object_info_identity[0],
                    "inode": object_info_identity[1],
                    "uid": object_info_identity[2],
                }
            ),
        },
        "alternate_controls": {
            "objects_info_alternates": "absent",
            "objects_info_http_alternates": "absent",
        },
    }


def _source_binding_closed_mapping(
    value: object,
    keys: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise SourceAuthorityBindingError(f"{label} does not match its closed schema")
    return value


def _source_binding_identity(
    value: object,
    *,
    label: str,
    include_file_type: bool = False,
) -> None:
    keys = {"device", "inode", "uid"}
    if include_file_type:
        keys.add("file_type")
    identity = _source_binding_closed_mapping(value, keys, label=f"{label} identity")
    for key, item in identity.items():
        if type(item) is not int or item < 0:
            raise SourceAuthorityBindingError(
                f"{label} identity field {key} is invalid"
            )


def _source_binding_path(value: object, *, label: str) -> pathlib.Path:
    if type(value) is not str or not value:
        raise SourceAuthorityBindingError(f"{label} path must be a nonempty string")
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise SourceAuthorityBindingError(f"{label} path contains a control character")
    try:
        value.encode("utf-8", errors="strict")
        if os.fsdecode(os.fsencode(value)) != value:
            raise SourceAuthorityBindingError(
                f"{label} path does not round-trip through filesystem bytes"
            )
    except UnicodeError as error:
        raise SourceAuthorityPathEncodingError(
            f"{label} path must be valid UTF-8"
        ) from error
    path = pathlib.Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise SourceAuthorityBindingError(
            f"{label} path must be canonical and absolute"
        )
    return path


def _source_binding_directory(value: object, *, label: str) -> pathlib.Path:
    record = _source_binding_closed_mapping(
        value,
        {"path", "identity"},
        label=label,
    )
    path = _source_binding_path(record["path"], label=label)
    _source_binding_identity(record["identity"], label=label)
    return path


def _source_binding_control(
    value: object,
    *,
    label: str,
    include_resolved_common: bool = False,
) -> pathlib.Path:
    keys = {"path", "identity", "size", "sha256"}
    if include_resolved_common:
        keys.add("resolved_common")
    record = _source_binding_closed_mapping(
        value,
        keys,
        label=label,
    )
    path = _source_binding_path(record["path"], label=label)
    _source_binding_identity(
        record["identity"],
        label=label,
        include_file_type=True,
    )
    identity = record["identity"]
    assert type(identity) is dict
    if identity["file_type"] != stat.S_IFREG:
        raise SourceAuthorityBindingError(f"{label} must bind a regular file")
    if type(record["size"]) is not int or record["size"] < 0:
        raise SourceAuthorityBindingError(f"{label} size is invalid")
    if (
        type(record["sha256"]) is not str
        or SOURCE_AUTHORITY_BINDING_SHA256.fullmatch(record["sha256"]) is None
    ):
        raise SourceAuthorityBindingError(f"{label} digest is invalid")
    return path


def validate_source_authority_binding(
    value: object,
    expected_sha256: object,
) -> tuple[dict[str, object], str]:
    """Validate and detach one parent-owned binding without filesystem probes."""

    if type(value) is not dict:
        raise SourceAuthorityBindingError(
            "parent source-authority binding does not match its closed schema"
        )
    if (
        type(expected_sha256) is not str
        or SOURCE_AUTHORITY_BINDING_SHA256.fullmatch(expected_sha256) is None
    ):
        raise SourceAuthorityBindingError(
            "parent source-authority binding digest is invalid"
        )
    try:
        canonical = canonical_source_authority_binding_bytes(value)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise SourceAuthorityBindingError(
            "parent source-authority binding cannot be canonically encoded"
        ) from error
    observed_sha256 = hashlib.sha256(canonical).hexdigest()
    if not secrets.compare_digest(observed_sha256, expected_sha256):
        raise SourceAuthorityBindingError(
            "parent source-authority binding digest does not match"
        )
    detached = json.loads(canonical)
    record = _source_binding_closed_mapping(
        detached,
        {
            "schema_version",
            "identity_encoding",
            "identity_algorithm",
            "path_encoding",
            "source_authority_policy",
            "source_worktree",
            "git_marker",
            "linked_worktree_back_pointer",
            "git_common_directory_marker",
            "git_admin",
            "git_common",
            "primary_object_store",
            "object_info",
            "alternate_controls",
        },
        label="parent source-authority binding",
    )
    if (
        record["schema_version"] != SOURCE_AUTHORITY_BINDING_SCHEMA_VERSION
        or record["identity_encoding"] != SOURCE_AUTHORITY_BINDING_ENCODING
        or record["identity_algorithm"] != SOURCE_AUTHORITY_BINDING_DIGEST_ALGORITHM
        or record["path_encoding"] != SOURCE_AUTHORITY_BINDING_PATH_ENCODING
        or record["source_authority_policy"] != "direct-primary-only"
    ):
        raise SourceAuthorityBindingError(
            "parent source-authority binding contract identifier is invalid"
        )
    source = _source_binding_directory(
        record["source_worktree"],
        label="source worktree",
    )
    admin = _source_binding_directory(record["git_admin"], label="source Git admin")
    common = _source_binding_directory(
        record["git_common"],
        label="source Git common",
    )
    common_marker = record["git_common_directory_marker"]
    if common_marker is None:
        if common != admin:
            raise SourceAuthorityBindingError(
                "parent source common-directory marker absence is inconsistent"
            )
    else:
        if (
            _source_binding_control(
                common_marker,
                label="source Git common-directory marker",
                include_resolved_common=True,
            )
            != admin / "commondir"
            or _source_binding_path(
                common_marker["resolved_common"],
                label="source Git common-directory marker resolved common",
            )
            != common
        ):
            raise SourceAuthorityBindingError(
                "parent source common-directory marker relationship is invalid"
            )
    objects = _source_binding_directory(
        record["primary_object_store"],
        label="source primary object store",
    )
    if objects != common / "objects":
        raise SourceAuthorityBindingError(
            "parent source primary object store must be exact <common>/objects"
        )
    marker = _source_binding_closed_mapping(
        record["git_marker"],
        {"path", "kind", "expected_admin", "identity", "size", "sha256"},
        label="parent source Git marker",
    )
    marker_path = _source_binding_path(marker["path"], label="source Git marker")
    expected_admin = _source_binding_path(
        marker["expected_admin"],
        label="source Git marker expected admin",
    )
    _source_binding_identity(
        marker["identity"],
        label="source Git marker",
        include_file_type=True,
    )
    marker_identity = marker["identity"]
    assert type(marker_identity) is dict
    if marker_path != source / ".git" or expected_admin != admin:
        raise SourceAuthorityBindingError(
            "parent source Git marker path relationship is invalid"
        )
    back_pointer = record["linked_worktree_back_pointer"]
    if marker["kind"] == "directory":
        if (
            marker_identity["file_type"] != stat.S_IFDIR
            or marker["size"] is not None
            or marker["sha256"] is not None
            or back_pointer is not None
            or marker_path != admin
        ):
            raise SourceAuthorityBindingError(
                "parent ordinary source Git marker binding is invalid"
            )
    elif marker["kind"] == "gitfile":
        if (
            marker_identity["file_type"] != stat.S_IFREG
            or type(marker["size"]) is not int
            or marker["size"] < 0
            or type(marker["sha256"]) is not str
            or SOURCE_AUTHORITY_BINDING_SHA256.fullmatch(marker["sha256"]) is None
            or back_pointer is None
        ):
            raise SourceAuthorityBindingError(
                "parent linked source Git marker binding is invalid"
            )
        if (
            _source_binding_control(
                back_pointer,
                label="source Git admin back-pointer",
            )
            != admin / "gitdir"
        ):
            raise SourceAuthorityBindingError(
                "parent source Git admin back-pointer path is invalid"
            )
    else:
        raise SourceAuthorityBindingError("parent source Git marker kind is invalid")
    object_info = _source_binding_closed_mapping(
        record["object_info"],
        {"path", "identity"},
        label="parent source object-info binding",
    )
    if (
        _source_binding_path(
            object_info["path"],
            label="source object-info",
        )
        != objects / "info"
    ):
        raise SourceAuthorityBindingError("parent source object-info path is invalid")
    if object_info["identity"] is not None:
        _source_binding_identity(
            object_info["identity"],
            label="source object-info",
        )
    if record["alternate_controls"] != {
        "objects_info_alternates": "absent",
        "objects_info_http_alternates": "absent",
    }:
        raise SourceAuthorityBindingError(
            "parent source alternate-control binding is invalid"
        )
    return detached, observed_sha256


def _strict_source_authority_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SourceAuthorityBindingError(
                "parent source-authority binding JSON contains a duplicate key"
            )
        value[key] = item
    return value


def _reject_source_authority_json_constant(value: str) -> object:
    raise SourceAuthorityBindingError(
        f"parent source-authority binding JSON contains invalid constant {value}"
    )


def parse_canonical_source_authority_binding_bytes(
    encoded: bytes,
    expected_sha256: object,
) -> tuple[dict[str, object], str]:
    try:
        value = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_source_authority_json_object,
            parse_constant=_reject_source_authority_json_constant,
        )
    except (RecursionError, UnicodeError, ValueError) as error:
        if isinstance(error, SourceAuthorityBindingError):
            raise
        raise SourceAuthorityBindingError(
            "parent source-authority binding is not strict UTF-8 JSON"
        ) from error
    binding, digest = validate_source_authority_binding(value, expected_sha256)
    if canonical_source_authority_binding_bytes(binding) != encoded:
        raise SourceAuthorityBindingError(
            "parent source-authority binding JSON is not canonical"
        )
    return binding, digest


def _source_control_file_authority(
    path: pathlib.Path,
    *,
    label: str,
    deadline: float,
) -> tuple[_SourceControlFileAuthority, bytes]:
    payload = _read_bounded_regular_file(
        path,
        limit=MARKER_LIMIT_BYTES,
        deadline=deadline,
        reason="source-git-control-invalid",
        label=label,
        unavailable_reason="source-git-control-unavailable",
        revalidation_unavailable_reason="source-git-control-revalidation-unavailable",
        drift_reason="source-git-control-drift",
    )
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-git-control-revalidation-unavailable",
            f"{label} identity cannot be captured",
            status="inconclusive",
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReviewWorkspaceError(
            "source-git-control-invalid",
            f"{label} must remain a regular file",
        )
    return (
        _SourceControlFileAuthority(
            path=path,
            identity=(metadata.st_dev, metadata.st_ino, metadata.st_uid),
            file_type=stat.S_IFMT(metadata.st_mode),
            size=metadata.st_size,
            sha256=hashlib.sha256(payload).hexdigest(),
        ),
        payload,
    )


def _source_control_path(
    payload: bytes,
    *,
    relative_to: pathlib.Path,
    label: str,
) -> pathlib.Path:
    stripped = payload.rstrip(b"\r\n")
    if not stripped or b"\0" in stripped or b"\n" in stripped or b"\r" in stripped:
        raise ReviewWorkspaceError(
            "source-git-control-invalid",
            f"{label} is malformed",
        )
    candidate = pathlib.Path(os.fsdecode(stripped))
    if not candidate.is_absolute():
        candidate = relative_to / candidate
    try:
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewWorkspaceError(
            "source-git-control-invalid",
            f"{label} cannot be resolved safely",
        ) from error


def _bind_source_git_marker(
    root: pathlib.Path,
    git_dir: pathlib.Path,
    deadline: float,
) -> _SourceGitMarkerAuthority:
    """Bind the exact worktree marker and linked-worktree back-pointer bytes."""

    _check_object_store_deadline(deadline)
    marker_path = root / ".git"
    try:
        metadata = marker_path.lstat()
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-git-marker-unavailable",
            "source must name an exact Git worktree root",
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ReviewWorkspaceError(
            "source-git-marker-invalid",
            "source Git marker must not be a symlink",
        )
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
    if stat.S_ISDIR(metadata.st_mode):
        try:
            resolved = marker_path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ReviewWorkspaceError(
                "source-git-marker-invalid",
                "source Git directory marker cannot be resolved safely",
            ) from error
        if resolved != marker_path or resolved != git_dir:
            raise ReviewWorkspaceError(
                "source-git-marker-invalid",
                "source Git directory marker does not match the discovered admin",
            )
        return _SourceGitMarkerAuthority(
            path=marker_path,
            expected_admin=git_dir,
            identity=identity,
            file_type=stat.S_IFMT(metadata.st_mode),
            kind="directory",
            size=None,
            sha256=None,
            back_pointer=None,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewWorkspaceError(
            "source-git-marker-invalid",
            "source Git marker must be a real directory or regular gitfile",
        )
    marker, marker_payload = _source_control_file_authority(
        marker_path,
        label="source Git admin marker",
        deadline=deadline,
    )
    prefix = b"gitdir: "
    stripped = marker_payload.rstrip(b"\r\n")
    if not stripped.startswith(prefix) or not stripped[len(prefix) :]:
        raise ReviewWorkspaceError(
            "source-git-marker-invalid",
            "source Git admin marker is malformed",
        )
    expected_admin = _source_control_path(
        stripped[len(prefix) :],
        relative_to=root,
        label="source Git admin marker",
    )
    if expected_admin != git_dir:
        raise ReviewWorkspaceError(
            "source-git-marker-invalid",
            "source Git admin marker does not match the discovered admin",
        )
    back_pointer, back_pointer_payload = _source_control_file_authority(
        git_dir / "gitdir",
        label="source Git admin back-pointer",
        deadline=deadline,
    )
    if (
        _source_control_path(
            back_pointer_payload,
            relative_to=git_dir,
            label="source Git admin back-pointer",
        )
        != marker_path
    ):
        raise ReviewWorkspaceError(
            "source-git-back-pointer-invalid",
            "source Git admin back-pointer does not match the exact marker",
        )
    return _SourceGitMarkerAuthority(
        path=marker_path,
        expected_admin=git_dir,
        identity=marker.identity,
        file_type=marker.file_type,
        kind="gitfile",
        size=marker.size,
        sha256=marker.sha256,
        back_pointer=back_pointer,
    )


def _revalidate_source_git_marker(
    expected: _SourceGitMarkerAuthority,
    root: pathlib.Path,
    git_dir: pathlib.Path,
    deadline: float,
) -> None:
    observed = _bind_source_git_marker(root, git_dir, deadline)
    if observed != expected:
        raise ReviewWorkspaceError(
            "source-git-marker-drift",
            "source Git marker or linked-worktree back-pointer changed after discovery",
        )


def _bind_source_common_directory_marker(
    git_dir: pathlib.Path,
    common_dir: pathlib.Path,
    deadline: float,
) -> _SourceControlFileAuthority | None:
    marker_path = git_dir / "commondir"
    try:
        marker_path.lstat()
    except FileNotFoundError:
        if common_dir != git_dir:
            raise ReviewWorkspaceError(
                "source-git-commondir-invalid",
                "source Git commondir absence conflicts with its resolved common directory",
            )
        return None
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-git-commondir-unavailable",
            "source Git commondir state cannot be inspected",
            status="inconclusive",
        ) from error
    marker, payload = _source_control_file_authority(
        marker_path,
        label="source Git common-directory marker",
        deadline=deadline,
    )
    if (
        _source_control_path(
            payload,
            relative_to=git_dir,
            label="source Git common-directory marker",
        )
        != common_dir
    ):
        raise ReviewWorkspaceError(
            "source-git-commondir-invalid",
            "source Git commondir content does not match the resolved common directory",
        )
    return marker


def _revalidate_source_common_directory_marker(
    expected: _SourceControlFileAuthority | None,
    git_dir: pathlib.Path,
    common_dir: pathlib.Path,
    deadline: float,
) -> None:
    if _bind_source_common_directory_marker(git_dir, common_dir, deadline) != expected:
        raise ReviewWorkspaceError(
            "source-git-commondir-drift",
            "source Git commondir presence, identity, or exact content changed",
        )


def _discover_source(source: pathlib.Path, deadline: float) -> _SourceRepository:
    _check_object_store_deadline(deadline)
    root = _absolute_existing_directory(source, "source repository")
    bare = _run_git(
        root,
        ("rev-parse", "--is-bare-repository"),
        reason="source-not-repository",
        absolute_deadline=deadline,
    ).strip()
    if bare != b"false":
        raise ReviewWorkspaceError(
            "source-not-worktree", "source must be a Git worktree"
        )
    git_dir = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--absolute-git-dir"),
            reason="source-not-repository",
            absolute_deadline=deadline,
        ),
        "source Git directory",
    )
    common_dir = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--path-format=absolute", "--git-common-dir"),
            reason="source-not-repository",
            absolute_deadline=deadline,
        ),
        "source common Git directory",
    )
    objects = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--path-format=absolute", "--git-path", "objects"),
            reason="source-not-repository",
            absolute_deadline=deadline,
        ),
        "source object directory",
    )
    object_format_bytes = _run_git(
        root,
        ("rev-parse", "--show-object-format"),
        reason="source-object-format-unavailable",
        absolute_deadline=deadline,
    ).strip()
    if object_format_bytes not in {b"sha1", b"sha256"}:
        raise ReviewWorkspaceError(
            "source-object-format-unsupported",
            "source object format must be sha1 or sha256",
        )
    object_format = object_format_bytes.decode("ascii")

    partial_config = _run_git(
        root,
        (
            "config",
            "--local",
            "--get-regexp",
            r"^(extensions\.partialClone|remote\..*\.promisor)$",
        ),
        allowed_returncodes=(0, 1),
        reason="source-config-unavailable",
        absolute_deadline=deadline,
    )
    promisor = bool(partial_config.strip())

    shallow_candidates = (git_dir / "shallow", common_dir / "shallow")
    present: list[tuple[pathlib.Path, bytes]] = []
    seen_shallow_paths: set[pathlib.Path] = set()
    for candidate in shallow_candidates:
        if candidate in seen_shallow_paths:
            continue
        seen_shallow_paths.add(candidate)
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReviewWorkspaceError(
                "source-shallow-state-unavailable",
                "source shallow state cannot be inspected",
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewWorkspaceError(
                "source-shallow-state-invalid",
                "source shallow state must be a regular file",
            )
        payload = _read_bounded_regular_file(
            candidate,
            limit=MARKER_LIMIT_BYTES,
            deadline=deadline,
            reason="source-shallow-state-invalid",
            label="source shallow state",
            unavailable_reason="source-shallow-state-unavailable",
            revalidation_unavailable_reason=(
                "source-shallow-state-revalidation-unavailable"
            ),
            drift_reason="source-shallow-state-drift",
        )
        present.append((candidate, payload))
    if len(present) > 1 and present[0][1] != present[1][1]:
        raise ReviewWorkspaceError(
            "source-shallow-state-conflict",
            "source Git directories expose conflicting shallow state",
        )
    marker = _bind_source_git_marker(root, git_dir, deadline)
    commondir = _bind_source_common_directory_marker(
        git_dir,
        common_dir,
        deadline,
    )
    primary_object_store, object_info_identity = _validate_direct_primary_object_store(
        objects, common_dir, deadline
    )
    object_stores = (primary_object_store,)
    for store in object_stores:
        _check_object_store_deadline(deadline)
        pack_directory = store / "pack"
        try:
            pack_descriptor = os.open(
                pack_directory,
                _nofollow_flags(directory=True),
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReviewWorkspaceError(
                "source-promisor-state-unavailable",
                "source promisor state cannot be opened safely",
            ) from error
        try:
            if not stat.S_ISDIR(os.fstat(pack_descriptor).st_mode):
                raise ReviewWorkspaceError(
                    "source-promisor-state-unavailable",
                    "source pack authority is not a real directory",
                )
            with os.scandir(pack_descriptor) as entries:
                for entry in entries:
                    _check_object_store_deadline(deadline)
                    if entry.name.endswith(".promisor"):
                        promisor = True
                        break
        except OSError as error:
            raise ReviewWorkspaceError(
                "source-promisor-state-unavailable",
                "source promisor state cannot be inspected",
            ) from error
        finally:
            os.close(pack_descriptor)
    authorities = _bind_source_directory_authorities(
        root,
        git_dir,
        common_dir,
        object_stores,
    )
    return _SourceRepository(
        root=root,
        marker=marker,
        commondir=commondir,
        git_dir=git_dir,
        common_dir=common_dir,
        object_stores=object_stores,
        object_info_identity=object_info_identity,
        authorities=authorities,
        object_format=object_format,
        shallow_path=present[0][0] if present else None,
        shallow_payload=present[0][1] if present else b"",
        promisor=promisor,
    )


def _direct_primary_object_store_guidance() -> str:
    return (
        "use an ordinary or linked worktree with canonical <common>/objects, "
        "a filesystem reflink/COW copy, or a clone made independent with "
        "--dissociate"
    )


def _direct_primary_object_store_details() -> dict[str, object]:
    """Return closed parent-facing remediation for a rejected source layout."""

    return {
        "source_authority_policy": "direct-primary-only",
        "remediation": {
            "action": "use-independent-primary-object-store",
            "accepted_source_layouts": [
                "ordinary-clone",
                "linked-worktree",
                "filesystem-reflink-or-cow-copy",
            ],
            "alternate_backed_clone": (
                "recreate the source as an independent clone with --dissociate"
            ),
        },
    }


def _validate_source_object_info_directory(
    objects: pathlib.Path,
    deadline: float,
) -> tuple[pathlib.Path, tuple[int, int, int] | None]:
    """Bind the lexical object-info directory without following a link."""

    _check_object_store_deadline(deadline)
    info = objects / "info"
    try:
        metadata = info.lstat()
    except FileNotFoundError:
        return info, None
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-object-info-unavailable",
            "source Git object-info storage cannot be inspected; "
            + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        ) from error
    try:
        resolved = info.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewWorkspaceError(
            "source-object-info-invalid",
            "source Git object-info storage must be a canonical real directory; "
            + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != info
    ):
        raise ReviewWorkspaceError(
            "source-object-info-invalid",
            "source Git object-info storage must be a canonical real directory; "
            + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        )
    return info, (metadata.st_dev, metadata.st_ino, metadata.st_uid)


def _validate_source_alternate_absence(
    objects: pathlib.Path,
    deadline: float,
) -> tuple[int, int, int] | None:
    """Reject every lexical local or HTTP alternates control entry."""

    info, initial_identity = _validate_source_object_info_directory(objects, deadline)

    def reject_entries() -> None:
        for candidate, label in (
            (info / "alternates", "local alternates"),
            (info / "http-alternates", "HTTP alternates"),
        ):
            _check_object_store_deadline(deadline)
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise ReviewWorkspaceError(
                    "source-alternates-unavailable",
                    f"source Git {label} state cannot be inspected; "
                    + _direct_primary_object_store_guidance(),
                    details=_direct_primary_object_store_details(),
                ) from error
            raise ReviewWorkspaceError(
                "source-alternates-forbidden",
                f"source Git {label} entry must be absent, regardless of its "
                "contents or file type; " + _direct_primary_object_store_guidance(),
                details=_direct_primary_object_store_details(),
            )

    for _ in range(2):
        reject_entries()
        _check_object_store_deadline(deadline)
        _, observed_identity = _validate_source_object_info_directory(
            objects,
            deadline,
        )
        if observed_identity != initial_identity:
            raise ReviewWorkspaceError(
                "source-object-info-drift",
                "source Git object-info storage changed during alternates "
                "validation; " + _direct_primary_object_store_guidance(),
                details=_direct_primary_object_store_details(),
            )
    return initial_identity


def _validate_direct_primary_object_store(
    advertised: pathlib.Path,
    common_dir: pathlib.Path,
    deadline: float,
) -> tuple[pathlib.Path, tuple[int, int, int] | None]:
    """Require the only source authority to be real ``<common>/objects``."""

    _check_object_store_deadline(deadline)
    expected = common_dir / "objects"
    try:
        metadata = expected.lstat()
        resolved = expected.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewWorkspaceError(
            "source-primary-object-store-unavailable",
            "source primary Git object storage cannot be resolved safely; "
            + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != expected
        or advertised != expected
    ):
        raise ReviewWorkspaceError(
            "source-primary-object-store-invalid",
            "source primary Git object storage must be canonical real "
            "<common>/objects; " + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        )
    object_info_identity = _validate_source_alternate_absence(expected, deadline)
    return expected, object_info_identity


def _revalidate_source_repository(
    source: _SourceRepository,
    deadline: float,
) -> None:
    """Point-revalidate direct source authority and alternates absence."""

    def revalidate_authorities() -> None:
        for authority in source.authorities:
            descriptor = _open_revalidated_source_authority(authority)
            os.close(descriptor)

    revalidate_authorities()
    _revalidate_source_git_marker(
        source.marker,
        source.root,
        source.git_dir,
        deadline,
    )
    _revalidate_source_common_directory_marker(
        source.commondir,
        source.git_dir,
        source.common_dir,
        deadline,
    )
    try:
        layout_payload = _run_git(
            source.root,
            (
                "rev-parse",
                "--path-format=absolute",
                "--absolute-git-dir",
                "--git-common-dir",
                "--git-path",
                "objects",
            ),
            reason="source-repository-layout-revalidation-unavailable",
            absolute_deadline=deadline,
        )
    except ReviewWorkspaceError as error:
        error.details.update(_direct_primary_object_store_details())
        raise
    layout_lines = layout_payload.splitlines()
    if len(layout_lines) != 3 or any(not line for line in layout_lines):
        raise ReviewWorkspaceError(
            "source-repository-layout-revalidation-invalid",
            "source Git layout revalidation returned a malformed direct-primary "
            "authority set; " + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        )
    observed_git_dir, observed_common_dir, observed_objects = (
        _decode_git_path(line, label)
        for line, label in zip(
            layout_lines,
            (
                "source Git directory",
                "source common Git directory",
                "source object directory",
            ),
            strict=True,
        )
    )
    if (
        observed_git_dir != source.git_dir
        or observed_common_dir != source.common_dir
        or observed_objects != source.common_dir / "objects"
    ):
        raise ReviewWorkspaceError(
            "source-repository-layout-drift",
            "source Git admin, common, or direct primary object authority changed "
            "after discovery; " + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        )
    expected, object_info_identity = _validate_direct_primary_object_store(
        observed_objects,
        source.common_dir,
        deadline,
    )
    if (
        source.object_stores != (expected,)
        or object_info_identity != source.object_info_identity
    ):
        raise ReviewWorkspaceError(
            "source-primary-object-store-drift",
            "source Git object authority changed after discovery; "
            + _direct_primary_object_store_guidance(),
            details=_direct_primary_object_store_details(),
        )
    _revalidate_source_git_marker(
        source.marker,
        source.root,
        source.git_dir,
        deadline,
    )
    _revalidate_source_common_directory_marker(
        source.commondir,
        source.git_dir,
        source.common_dir,
        deadline,
    )
    revalidate_authorities()


def _source_directory_binding_payload(
    source: _SourceRepository,
    path: pathlib.Path,
) -> dict[str, object]:
    matches = tuple(
        authority for authority in source.authorities if authority.path == path
    )
    if len(matches) != 1:
        raise ReviewWorkspaceError(
            "source-authority-binding-invalid",
            "captured source directory authority is missing or ambiguous",
        )
    return source_authority_directory_record(path, matches[0].identity)


def _source_control_file_binding_payload(
    control: _SourceControlFileAuthority,
) -> dict[str, object]:
    return source_authority_control_record(
        control.path,
        control.identity,
        file_type=control.file_type,
        size=control.size,
        sha256=control.sha256,
    )


def _source_authority_binding_payload(
    source: _SourceRepository,
) -> dict[str, object]:
    """Project only originally captured source authorities into a closed record."""

    marker = source.marker
    return build_source_authority_binding(
        source_worktree=_source_directory_binding_payload(source, source.root),
        git_marker=source_authority_marker_record(
            marker.path,
            marker.expected_admin,
            marker.identity,
            file_type=marker.file_type,
            kind=marker.kind,
            size=marker.size,
            sha256=marker.sha256,
        ),
        linked_worktree_back_pointer=(
            None
            if marker.back_pointer is None
            else _source_control_file_binding_payload(marker.back_pointer)
        ),
        git_common_directory_marker=(
            None
            if source.commondir is None
            else source_authority_common_marker_record(
                _source_control_file_binding_payload(source.commondir),
                source.common_dir,
            )
        ),
        git_admin=_source_directory_binding_payload(source, source.git_dir),
        git_common=_source_directory_binding_payload(source, source.common_dir),
        primary_object_store=_source_directory_binding_payload(
            source,
            source.object_stores[0],
        ),
        object_info_path=source.object_stores[0] / "info",
        object_info_identity=source.object_info_identity,
    )


def _validate_requested_oid(value: str, label: str, object_format: str) -> str:
    expected_length = 40 if object_format == "sha1" else 64
    if not FULL_OBJECT_ID.fullmatch(value) or len(value) != expected_length:
        raise ReviewWorkspaceError(
            "invalid-frozen-endpoint",
            f"{label} must be a full lowercase {object_format} object ID",
        )
    return value


def _parse_source_shallow_boundaries(
    payload: bytes,
    object_format: str,
    *,
    shallow: bool,
) -> tuple[str, ...]:
    if not shallow:
        if payload:
            raise ReviewWorkspaceError(
                "source-shallow-state-invalid",
                "source shallow bytes exist without a shallow repository marker",
            )
        return ()
    if not payload or not payload.endswith(b"\n"):
        raise ReviewWorkspaceError(
            "source-shallow-state-invalid",
            "source shallow state must contain newline-terminated commit IDs",
        )
    expected_length = 40 if object_format == "sha1" else 64
    boundaries: list[str] = []
    for raw_boundary in payload.splitlines():
        try:
            boundary = raw_boundary.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "source-shallow-state-invalid",
                "source shallow state contains a non-ASCII commit ID",
            ) from error
        if len(boundary) != expected_length or not FULL_OBJECT_ID.fullmatch(boundary):
            raise ReviewWorkspaceError(
                "source-shallow-state-invalid",
                "source shallow state contains a malformed commit ID",
            )
        boundaries.append(boundary)
    if len(set(boundaries)) != len(boundaries):
        raise ReviewWorkspaceError(
            "source-shallow-state-invalid",
            "source shallow state contains duplicate commit IDs",
        )
    return tuple(boundaries)


def _decode_reported_missing_oid(
    raw_line: bytes,
    expected_length: int,
    *,
    reason: str,
    label: str,
) -> str:
    try:
        oid = raw_line[1:].decode("ascii")
    except UnicodeDecodeError as error:
        raise ReviewWorkspaceError(
            reason,
            f"Git returned a non-ASCII {label}",
        ) from error
    if len(oid) != expected_length or not FULL_OBJECT_ID.fullmatch(oid):
        raise ReviewWorkspaceError(
            reason,
            f"Git returned a malformed {label}",
        )
    return oid


def _object_id_hex_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    raise ReviewWorkspaceError(
        "object-format-unsupported",
        "object snapshot format must be sha1 or sha256",
    )


def _object_snapshot_output_limit_bytes(object_format: str) -> int:
    # The longest admitted row is ``?OID\n``.  Keep a small framing margin so
    # the parser, rather than the process sink, supplies the stable row-limit
    # classification for the first over-limit records.
    return RANGE_OBJECT_COUNT_LIMIT * (_object_id_hex_length(object_format) + 2) + 1024


def _parse_object_snapshot_rows(
    payload: bytes,
    object_format: str,
    *,
    invalid_reason: str,
    limit_reason: str,
    label: str,
    deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
) -> tuple[set[str], list[str]]:
    expected_length = _object_id_hex_length(object_format)
    present: set[str] = set()
    missing: list[str] = []
    for row_count, raw_line in enumerate(payload.splitlines(), start=1):
        if deadline is not None and (row_count - 1) % 4096 == 0:
            (deadline_checker or _check_object_store_deadline)(deadline)
        if row_count > RANGE_OBJECT_COUNT_LIMIT:
            raise ReviewWorkspaceError(
                limit_reason,
                f"{label} exceeds the object-row count limit",
                details={
                    "observed_row_count": row_count,
                    "limit": RANGE_OBJECT_COUNT_LIMIT,
                },
            )
        if raw_line.startswith(b"?"):
            missing.append(
                _decode_reported_missing_oid(
                    raw_line,
                    expected_length,
                    reason=invalid_reason,
                    label=f"missing {label} object ID",
                )
            )
            continue
        try:
            oid = raw_line.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                invalid_reason,
                f"Git returned non-ASCII {label} output",
            ) from error
        if len(oid) != expected_length or not FULL_OBJECT_ID.fullmatch(oid):
            raise ReviewWorkspaceError(
                invalid_reason,
                f"Git returned a malformed {label} object ID",
            )
        present.add(oid)
    if deadline is not None:
        (deadline_checker or _check_object_store_deadline)(deadline)
    return present, missing


def _read_object_snapshot(
    root: pathlib.Path,
    requested_ids: Sequence[str],
    object_format: str,
    *,
    invalid_reason: str,
    limit_reason: str,
    label: str,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
    control_binding: _WorkspaceControlBinding | None = None,
) -> tuple[int, set[str], list[str], bytes]:
    returncode, output, stderr = _run_git_raw(
        root,
        _OBJECT_SNAPSHOT_COMMAND,
        stdin=b"".join(f"{oid}\n".encode("ascii") for oid in requested_ids),
        output_limit_bytes=_object_snapshot_output_limit_bytes(object_format),
        absolute_deadline=absolute_deadline,
        deadline_checker=deadline_checker,
        control_binding=control_binding,
        extra_environment={"GIT_SHALLOW_FILE": os.devnull},
    )
    present, missing = _parse_object_snapshot_rows(
        output,
        object_format,
        invalid_reason=invalid_reason,
        limit_reason=limit_reason,
        label=label,
        deadline=absolute_deadline,
        deadline_checker=deadline_checker,
    )
    return returncode, present, missing, stderr


def _read_raw_commit_graph(
    root: pathlib.Path,
    head: str,
    *,
    deadline: float | None,
    deadline_checker: Callable[[float], None] | None = None,
    control_binding: _WorkspaceControlBinding | None = None,
    workspace: bool,
) -> _RawCommitGraphProbe:
    command = ("rev-list", "--parents", "--missing=print", head)
    oid_row_bytes = len(head) + 1
    missing_row_bytes = len(head) + 2
    returncode, output, stderr = _run_git_raw(
        root,
        command,
        output_limit_bytes=(
            (RANGE_OBJECT_COUNT_LIMIT + RANGE_PARENT_EDGE_COUNT_LIMIT) * oid_row_bytes
            # Every distinct missing parent can add a separate ``?OID\n`` row;
            # a missing head is the only possible extra report without an edge.
            + (RANGE_PARENT_EDGE_COUNT_LIMIT + 1) * missing_row_bytes
            + 1024
        ),
        absolute_deadline=deadline,
        deadline_checker=deadline_checker,
        control_binding=control_binding,
        extra_environment={"GIT_SHALLOW_FILE": os.devnull},
    )
    invalid_reason = (
        "workspace-range-object-invalid"
        if workspace
        else "range-parent-graph-output-invalid"
    )
    parents: dict[str, tuple[str, ...]] = {}
    missing: set[str] = set()
    parent_edge_count = 0
    for line_number, raw_line in enumerate(output.splitlines()):
        if deadline is not None and line_number % 4096 == 0:
            (deadline_checker or _check_object_store_deadline)(deadline)
        if raw_line.startswith(b"?"):
            missing.add(
                _decode_reported_missing_oid(
                    raw_line,
                    len(head),
                    reason=invalid_reason,
                    label="missing raw parent-graph commit ID",
                )
            )
            continue
        fields = raw_line.split()
        if not fields:
            raise ReviewWorkspaceError(
                invalid_reason,
                "Git returned an empty raw parent-graph row",
            )
        decoded: list[str] = []
        for raw_oid in fields:
            try:
                oid = raw_oid.decode("ascii")
            except UnicodeDecodeError as error:
                raise ReviewWorkspaceError(
                    invalid_reason,
                    "Git returned a non-ASCII raw parent-graph object ID",
                ) from error
            if len(oid) != len(head) or not FULL_OBJECT_ID.fullmatch(oid):
                raise ReviewWorkspaceError(
                    invalid_reason,
                    "Git returned a malformed raw parent-graph object ID",
                )
            decoded.append(oid)
        commit_oid, *parent_oids = decoded
        if commit_oid in parents:
            raise ReviewWorkspaceError(
                invalid_reason,
                "Git returned duplicate raw parent-graph commit rows",
            )
        parents[commit_oid] = tuple(parent_oids)
        if len(parents) > RANGE_OBJECT_COUNT_LIMIT:
            raise ReviewWorkspaceError(
                (
                    "workspace-range-support-commit-limit"
                    if workspace
                    else "base-support-commit-limit"
                ),
                (
                    "raw parent graph exceeds the "
                    f"{RANGE_OBJECT_COUNT_LIMIT:,}-commit support limit"
                ),
            )
        parent_edge_count += len(parent_oids)
        if parent_edge_count > RANGE_PARENT_EDGE_COUNT_LIMIT:
            raise ReviewWorkspaceError(
                (
                    "workspace-range-parent-edge-limit"
                    if workspace
                    else "range-parent-edge-limit"
                ),
                (
                    "raw parent graph exceeds the "
                    f"{RANGE_PARENT_EDGE_COUNT_LIMIT:,}-parent-edge limit"
                ),
            )
    if deadline is not None:
        (deadline_checker or _check_object_store_deadline)(deadline)
    if set(parents).intersection(missing):
        raise ReviewWorkspaceError(
            invalid_reason,
            "Git classified the same raw parent-graph commit as present and missing",
        )
    referenced_parents = {
        parent_oid for parent_oids in parents.values() for parent_oid in parent_oids
    }
    if referenced_parents.difference(parents, missing):
        raise ReviewWorkspaceError(
            invalid_reason,
            "Git omitted raw parent-graph commits without missing-object evidence",
        )
    if missing.difference(referenced_parents, {head}):
        raise ReviewWorkspaceError(
            invalid_reason,
            "Git reported an unreferenced missing raw parent-graph commit",
        )
    return _RawCommitGraphProbe(
        parents=parents,
        missing=frozenset(missing),
        returncode=returncode,
        stderr_preview=stderr.decode("utf-8", "backslashreplace")[:4096],
    )


def _select_raw_commit_scope(
    root: pathlib.Path,
    base: str,
    head: str,
    *,
    deadline: float | None,
    control_binding: _WorkspaceControlBinding | None = None,
    source_shallow: bool | None,
    source_promisor: bool | None = None,
    operational_reason: str = "range-parent-graph-check-failed",
    missing_reason: str = "range-parent-graph-missing",
) -> _RawCommitScope:
    workspace = source_shallow is None
    probe = _read_raw_commit_graph(
        root,
        head,
        deadline=deadline,
        control_binding=control_binding,
        workspace=workspace,
    )

    def fail_incomplete(message: str, missing: Sequence[str]) -> None:
        missing_sample = tuple(sorted(set(missing)))
        if workspace:
            raise ReviewWorkspaceError(
                "workspace-range-object-missing",
                message,
                details={
                    "missing_object_count": len(missing_sample),
                    "missing_objects": list(
                        missing_sample[:MISSING_OBJECT_SAMPLE_LIMIT]
                    ),
                },
            )
        assert source_shallow is not None
        raise RangeIncomplete(
            missing_reason,
            message,
            base=base,
            head=head,
            source_shallow=source_shallow,
            source_promisor=source_promisor,
            missing_objects=missing_sample,
        )

    if probe.returncode != 0:
        if probe.missing:
            fail_incomplete(
                "the raw commit-parent graph is locally incomplete",
                tuple(probe.missing),
            )
        raise ReviewWorkspaceError(
            (
                "workspace-range-object-check-failed"
                if workspace
                else operational_reason
            ),
            "the raw commit-parent graph probe failed operationally",
            details={
                "base": base,
                "head": head,
                "returncode": probe.returncode,
                "stderr_preview": probe.stderr_preview,
            },
        )

    def walk(start: str) -> tuple[set[str], set[str]]:
        known: set[str] = set()
        frontier: set[str] = set()
        pending = [start]
        while pending:
            oid = pending.pop()
            if oid in known or oid in frontier:
                continue
            parent_oids = probe.parents.get(oid)
            if parent_oids is None:
                if oid in probe.missing:
                    frontier.add(oid)
                    continue
                raise ReviewWorkspaceError(
                    (
                        "workspace-range-object-invalid"
                        if workspace
                        else "range-parent-graph-output-invalid"
                    ),
                    "raw parent-graph traversal reached an unclassified commit",
                )
            known.add(oid)
            pending.extend(parent_oids)
        return known, frontier

    head_known, head_frontier = walk(head)
    if set(probe.parents) != head_known or set(probe.missing) != head_frontier:
        raise ReviewWorkspaceError(
            (
                "workspace-range-object-invalid"
                if workspace
                else "range-parent-graph-output-invalid"
            ),
            "raw parent-graph output contains commits outside the head traversal",
        )
    if base not in head_known:
        if head_frontier:
            fail_incomplete(
                "the raw local graph cannot prove base is an ancestor of head",
                tuple(head_frontier),
            )
        if workspace:
            raise ReviewWorkspaceError(
                "workspace-range-topology-mismatch",
                "workspace base is not an ancestor of head in the raw local graph",
            )
        raise ReviewWorkspaceError(
            "base-not-ancestor",
            "base is not an ancestor of head in the complete raw local graph",
            status="invalid-range",
            details={"base": base, "head": head},
        )

    base_known, base_frontier = walk(base)
    unresolved = head_frontier.difference(base_frontier)
    if unresolved:
        fail_incomplete(
            "the raw local graph cannot prove where a head-side history overlaps base",
            tuple(unresolved),
        )
    range_commits = head_known.difference(base_known)
    if head_frontier:
        children_by_parent: dict[str, set[str]] = {}
        for child_oid, parent_oids in probe.parents.items():
            for parent_oid in parent_oids:
                if parent_oid in probe.parents:
                    children_by_parent.setdefault(parent_oid, set()).add(child_oid)
        # A present path from any ancestor of base is not proof that a commit
        # is outside Reach(base): a shared missing frontier can still lead from
        # base back to that same commit.  Only a present child path rooted at
        # the exact base proves that a head-side commit is its descendant.
        proven_base_descendants = {base}
        pending_children = [base]
        while pending_children:
            parent_oid = pending_children.pop()
            for child_oid in children_by_parent.get(parent_oid, ()):
                if child_oid in proven_base_descendants:
                    continue
                proven_base_descendants.add(child_oid)
                pending_children.append(child_oid)
        ambiguous = tuple(sorted(range_commits.difference(proven_base_descendants)))
        if ambiguous:
            fail_incomplete(
                (
                    "the raw local graph has shared missing ancestry and cannot prove "
                    "that every head-side commit is outside base history"
                ),
                tuple(base_frontier),
            )
    if len(range_commits) + 1 > RANGE_COMMIT_COUNT_LIMIT:
        raise ReviewWorkspaceError(
            ("workspace-range-commit-limit" if workspace else "range-commit-limit"),
            "frozen range exceeds the 250,000-commit safety limit",
        )

    # Preserve the complete available base-side commit DAG so ordinary Git's
    # negative BASE walk has the same semantics as the raw graph.  Destination
    # shallow boundaries represent only an actual locally missing frontier;
    # never synthesize one merely to reduce the visible history.
    direct_external_parents: set[str] = {base}
    missing_review_parents: set[str] = set()
    for commit_oid in range_commits:
        for parent_oid in probe.parents[commit_oid]:
            if parent_oid in range_commits:
                continue
            if parent_oid in probe.missing:
                missing_review_parents.add(parent_oid)
            else:
                direct_external_parents.add(parent_oid)
    if missing_review_parents:
        fail_incomplete(
            "a reviewed commit has a locally missing parent snapshot",
            tuple(missing_review_parents),
        )
    unexpected_external = direct_external_parents.difference(base_known)
    if unexpected_external:
        fail_incomplete(
            "the raw graph cannot bind every reviewed commit parent to base history",
            tuple(unexpected_external),
        )

    shallow_boundaries: set[str] = set()
    for commit_oid in base_known:
        parent_oids = probe.parents[commit_oid]
        missing_parents = [parent for parent in parent_oids if parent in probe.missing]
        if not missing_parents:
            continue
        present_parents = [parent for parent in parent_oids if parent in probe.parents]
        if present_parents:
            fail_incomplete(
                (
                    "source incompleteness admits no shallow boundary without "
                    "cutting an available parent edge"
                ),
                tuple(missing_parents),
            )
        shallow_boundaries.add(commit_oid)
    return _RawCommitScope(
        range_commits=tuple(sorted(range_commits)),
        base_support_commits=tuple(sorted(base_known)),
        parent_snapshot_commits=tuple(
            sorted(direct_external_parents.difference({base}))
        ),
        shallow_boundaries=tuple(sorted(shallow_boundaries)),
    )


def _source_object_budget_quiescence_unproven(error: BaseException) -> bool:
    """Inspect the complete cause/context graph before normalizing a failure."""

    pending = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in visited:
            continue
        visited.add(identity)
        if process_quiescence_unproven(current):
            return True
        for related in (current.__cause__, current.__context__):
            if isinstance(related, BaseException):
                pending.append(related)
    return False


def _map_source_object_budget_error(
    reason: str,
    message: str,
    source: BaseException,
    *,
    status: str = "blocked-safety",
    details: Mapping[str, object] | None = None,
) -> ReviewWorkspaceError:
    quiescence_unproven = _source_object_budget_quiescence_unproven(source)
    mapped = ReviewWorkspaceError(
        reason,
        message,
        status="inconclusive" if quiescence_unproven else status,
        details=details,
    )
    if quiescence_unproven:
        mark_process_quiescence_unproven(mapped)
    return mapped


def _validate_source_object_logical_budget(
    root: pathlib.Path,
    object_format: str,
    object_ids: Sequence[str],
    *,
    deadline: float,
) -> None:
    """Bind and budget the exact source object union before pack generation."""

    _check_object_store_deadline(deadline)
    expected_ids = tuple(sorted(set(object_ids)))
    expected_length = 40 if object_format == "sha1" else 64
    if (
        not expected_ids
        or len(expected_ids) > RANGE_OBJECT_COUNT_LIMIT
        or tuple(object_ids) != expected_ids
        or any(
            len(oid) != expected_length or FULL_OBJECT_ID.fullmatch(oid) is None
            for oid in expected_ids
        )
    ):
        raise ReviewWorkspaceError(
            "range-object-size-input-invalid",
            "source object-size budgeting did not receive the exact bounded object union",
        )
    command = (
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    )
    query = b"".join(f"{oid}\n".encode("ascii") for oid in expected_ids)
    output_limit = len(expected_ids) * (expected_length + 64) + 1024
    try:
        returncode, output, stderr = _run_git_raw(
            root,
            command,
            stdin=query,
            output_limit_bytes=output_limit,
            absolute_deadline=deadline,
        )
    except ReviewWorkspaceError as error:
        if _source_object_budget_quiescence_unproven(error):
            mark_process_quiescence_unproven(error)
            error.status = "inconclusive"
        raise
    except ReviewTimeoutError as error:
        raise _map_source_object_budget_error(
            "range-object-size-timeout",
            "source object-size budgeting exceeded its bounded process deadline",
            error,
            status="inconclusive",
            details={"retryable": True},
        ) from error
    except ReviewOutputLimitError as error:
        raise _map_source_object_budget_error(
            "range-object-size-output-limit",
            "source object-size budgeting exceeded its derived output bound",
            error,
            details={
                "limit": output_limit,
                "limit_kind": error.limit_kind,
            },
        ) from error
    except (ReviewOutputDrainError, ReviewProcessLeakError) as error:
        reason = (
            "range-object-size-output-drain"
            if isinstance(error, ReviewOutputDrainError)
            else "range-object-size-process-leak"
        )
        mapped = _map_source_object_budget_error(
            reason,
            "source object-size budgeting did not prove complete process settlement",
            error,
            status="inconclusive",
        )
        raise mapped from error
    except (ReviewError, OSError) as error:
        raise _map_source_object_budget_error(
            "range-object-size-check-failed",
            "source object-size budgeting failed operationally",
            error,
        ) from error
    if returncode != 0:
        raise ReviewWorkspaceError(
            "range-object-size-check-failed",
            "source object-size budgeting failed operationally",
            details={
                "returncode": returncode,
                "stderr_preview": stderr.decode("utf-8", "backslashreplace")[:4096],
            },
        )
    if not output.endswith(b"\n"):
        raise ReviewWorkspaceError(
            "range-object-size-output-invalid",
            "source object-size budgeting returned an unterminated object record",
        )
    records = output[:-1].split(b"\n")
    if len(records) != len(expected_ids):
        raise ReviewWorkspaceError(
            "range-object-size-output-invalid",
            "source object-size budgeting returned the wrong record count",
            details={
                "expected_object_count": len(expected_ids),
                "observed_record_count": len(records),
            },
        )
    logical_bytes = 0
    accepted_types = {b"blob", b"commit", b"tree"}
    for index, (expected_oid, record) in enumerate(zip(expected_ids, records)):
        if index % 4096 == 0:
            _check_object_store_deadline(deadline)
        fields = record.split(b" ")
        if (
            len(fields) != 3
            or fields[0] != expected_oid.encode("ascii")
            or fields[1] not in accepted_types
            or not fields[2].isdigit()
        ):
            raise ReviewWorkspaceError(
                "range-object-size-output-invalid",
                "source object-size budgeting did not bind the exact object union",
                details={"record_index": index},
            )
        size = int(fields[2])
        logical_bytes += size
    _check_object_store_deadline(deadline)
    if logical_bytes > RANGE_OBJECT_LOGICAL_BYTES_LIMIT:
        raise ReviewWorkspaceError(
            "range-object-logical-byte-limit",
            "frozen range plus parent support exceeds the logical-byte limit",
            details={
                "object_count": len(expected_ids),
                "observed": logical_bytes,
                "limit": RANGE_OBJECT_LOGICAL_BYTES_LIMIT,
            },
        )


def _freeze_range(
    root: pathlib.Path,
    object_format: str,
    base: str,
    head: str,
    *,
    shallow: bool,
    promisor: bool,
    shallow_boundaries: Sequence[str] = (),
    deadline: float | None = None,
) -> tuple[
    str,
    str,
    int,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    if deadline is None:
        deadline = time.monotonic() + WORKSPACE_PREPARATION_DEADLINE_SECONDS
    base = _validate_requested_oid(base, "base", object_format)
    head = _validate_requested_oid(head, "head", object_format)
    for label, oid in (("base", base), ("head", head)):
        _check_object_store_deadline(deadline)
        returncode, stdout, _stderr = _run_git_raw(
            root,
            ("cat-file", "--batch-check=%(objectname) %(objecttype)"),
            stdin=f"{oid}\n".encode("ascii"),
            absolute_deadline=deadline,
        )
        if returncode != 0:
            raise ReviewWorkspaceError(
                f"{label}-object-check-failed",
                f"frozen {label} object classification failed operationally",
                details={"returncode": returncode, label: oid},
            )
        fields = stdout.strip().split()
        if fields == [oid.encode("ascii"), b"missing"]:
            raise RangeIncomplete(
                f"{label}-commit-missing",
                f"frozen {label} commit is not locally available",
                base=base,
                head=head,
                source_shallow=shallow,
                source_promisor=promisor,
                missing_objects=(oid,),
            )
        if fields != [oid.encode("ascii"), b"commit"]:
            raise ReviewWorkspaceError(
                f"{label}-not-commit",
                f"frozen {label} object exists but is not a commit",
                status="invalid-range",
                details={
                    label: oid,
                    "observed_type": (
                        fields[1].decode("ascii", "replace")
                        if len(fields) == 2
                        else "malformed"
                    ),
                },
            )
    if bool(shallow_boundaries) != shallow:
        raise ReviewWorkspaceError(
            "source-shallow-state-invalid",
            "source shallow boundaries disagree with repository shallow state",
        )
    scope = _select_raw_commit_scope(
        root,
        base,
        head,
        deadline=deadline,
        source_shallow=shallow,
        source_promisor=promisor,
    )
    range_commits = scope.range_commits

    snapshot_code, range_objects, missing_objects, snapshot_stderr = (
        _read_object_snapshot(
            root,
            (base, *range_commits),
            object_format,
            invalid_reason="range-object-output-invalid",
            limit_reason="range-object-limit",
            label="range snapshot",
            absolute_deadline=deadline,
        )
    )
    missing = tuple(sorted(set(missing_objects)))
    if missing:
        raise RangeIncomplete(
            "range-object-missing",
            "the frozen committed range snapshots are not locally object-complete",
            base=base,
            head=head,
            source_shallow=shallow,
            source_promisor=promisor,
            missing_objects=missing,
        )
    if snapshot_code != 0:
        raise ReviewWorkspaceError(
            "range-object-check-failed",
            "the frozen range snapshot-completeness probe failed operationally",
            details={
                "base": base,
                "head": head,
                "failures": [
                    {
                        "command": list(_OBJECT_SNAPSHOT_COMMAND),
                        "returncode": snapshot_code,
                        "stderr_preview": snapshot_stderr.decode(
                            "utf-8", "backslashreplace"
                        )[:4096],
                    }
                ],
            },
        )
    parent_snapshot_objects: set[str] = set()
    if scope.parent_snapshot_commits:
        (
            parent_code,
            parent_snapshot_objects,
            missing_parent_objects,
            parent_stderr,
        ) = _read_object_snapshot(
            root,
            scope.parent_snapshot_commits,
            object_format,
            invalid_reason="parent-support-object-output-invalid",
            limit_reason="range-object-limit",
            label="direct-parent snapshot",
            absolute_deadline=deadline,
        )
        if missing_parent_objects:
            raise RangeIncomplete(
                "parent-support-object-missing",
                "a reviewed commit's direct-parent snapshot is locally incomplete",
                base=base,
                head=head,
                source_shallow=shallow,
                source_promisor=promisor,
                missing_objects=tuple(sorted(set(missing_parent_objects))),
            )
        if parent_code != 0:
            raise ReviewWorkspaceError(
                "parent-support-object-check-failed",
                "direct-parent snapshot traversal failed operationally",
                details={
                    "base": base,
                    "head": head,
                    "returncode": parent_code,
                    "stderr_preview": parent_stderr.decode("utf-8", "backslashreplace")[
                        :4096
                    ],
                },
            )
    support_objects = set(scope.base_support_commits)
    support_objects.update(parent_snapshot_objects)
    support_objects.difference_update(range_objects)
    total_objects = set(range_objects).union(support_objects)
    if len(total_objects) > RANGE_OBJECT_COUNT_LIMIT:
        raise ReviewWorkspaceError(
            "range-object-limit",
            (
                "frozen range plus parent support exceeds the "
                f"{RANGE_OBJECT_COUNT_LIMIT:,}-object limit"
            ),
            details={
                "range_object_count": len(range_objects),
                "parent_support_object_count": len(support_objects),
                "total_object_count": len(total_objects),
                "limit": RANGE_OBJECT_COUNT_LIMIT,
            },
        )
    _validate_source_object_logical_budget(
        root,
        object_format,
        tuple(sorted(total_objects)),
        deadline=deadline,
    )
    return (
        base,
        head,
        len(range_commits) + 1,
        tuple(sorted(range_objects)),
        tuple(sorted(support_objects)),
        scope.shallow_boundaries,
    )


def _destination_path(path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ReviewWorkspaceError(
            "invalid-path", "workspace must be an absolute absent child path"
        )
    parent = _absolute_existing_directory(path.parent, "workspace parent")
    _private_directory_identity(
        parent,
        "workspace parent",
        reason="workspace-parent-policy",
    )
    destination = parent / path.name
    if destination.exists() or destination.is_symlink():
        raise ReviewWorkspaceError(
            "workspace-exists", "workspace destination must be absent"
        )
    return parent, destination


def _open_revalidated_source_authority(
    authority: _SourceDirectoryAuthority,
) -> int:
    try:
        descriptor = os.open(authority.path, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            "source-authority-revalidation-unavailable",
            f"{authority.label} cannot be reopened before workspace creation",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        observed = authority.path.stat(follow_symlinks=False)
    except OSError as error:
        os.close(descriptor)
        raise ReviewWorkspaceError(
            "source-authority-revalidation-unavailable",
            f"{authority.label} identity cannot be revalidated before creation",
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or not os.path.samestat(metadata, observed)
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid) != authority.identity
    ):
        os.close(descriptor)
        raise ReviewWorkspaceError(
            "source-authority-identity-mismatch",
            f"{authority.label} changed before workspace creation",
        )
    return descriptor


def _reject_destination_source_overlap(
    parent_descriptor: int,
    authorities: Sequence[_SourceDirectoryAuthority],
) -> None:
    """Reject an absent destination whose bound parent is inside source state."""

    authority_descriptors: list[int] = []
    ancestor_descriptor: int | None = None
    next_ancestor_descriptor: int | None = None
    try:
        authority_by_identity: dict[tuple[int, int], _SourceDirectoryAuthority] = {}
        for authority in authorities:
            descriptor = _open_revalidated_source_authority(authority)
            authority_descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            authority_by_identity[(metadata.st_dev, metadata.st_ino)] = authority

        ancestor_descriptor = os.dup(parent_descriptor)
        visited: set[tuple[int, int]] = set()
        while True:
            metadata = os.fstat(ancestor_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ReviewWorkspaceError(
                    "workspace-source-overlap-check-failed",
                    "workspace parent ancestry contains a non-directory object",
                )
            identity = (metadata.st_dev, metadata.st_ino)
            authority = authority_by_identity.get(identity)
            if authority is not None:
                raise ReviewWorkspaceError(
                    "workspace-source-overlap",
                    "workspace destination must be outside every source authority",
                    details={
                        "source_authority": authority.label,
                        "source_authority_path": str(authority.path),
                    },
                )
            if identity in visited:
                raise ReviewWorkspaceError(
                    "workspace-source-overlap-check-failed",
                    "workspace parent ancestry could not be traversed uniquely",
                )
            visited.add(identity)
            next_ancestor_descriptor = os.open(
                "..",
                _nofollow_flags(directory=True),
                dir_fd=ancestor_descriptor,
            )
            parent_metadata = os.fstat(next_ancestor_descriptor)
            if os.path.samestat(metadata, parent_metadata):
                closing_descriptor = next_ancestor_descriptor
                next_ancestor_descriptor = None
                os.close(closing_descriptor)
                break
            closing_descriptor = ancestor_descriptor
            ancestor_descriptor = next_ancestor_descriptor
            next_ancestor_descriptor = None
            os.close(closing_descriptor)
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-source-overlap-check-failed",
            "workspace parent ancestry cannot be inspected safely",
        ) from error
    finally:
        if next_ancestor_descriptor is not None:
            os.close(next_ancestor_descriptor)
        if ancestor_descriptor is not None:
            os.close(ancestor_descriptor)
        for descriptor in authority_descriptors:
            os.close(descriptor)


def _base_ancestry_support_objects(
    root: pathlib.Path,
    base: str,
    head: str,
    *,
    deadline: float,
    source_shallow: bool,
) -> tuple[str, ...]:
    scope = _select_raw_commit_scope(
        root,
        base,
        head,
        deadline=deadline,
        source_shallow=source_shallow,
        operational_reason="base-parent-graph-check-failed",
        missing_reason="base-parent-graph-missing",
    )
    return scope.base_support_commits


def _clonefile_function() -> object | None:
    if os.uname().sysname != "Darwin":
        return None
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        clonefile = library.clonefile
        clonefile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32)
        clonefile.restype = ctypes.c_int
    except (AttributeError, OSError):
        return None
    return clonefile


@dataclass(frozen=True)
class _ObjectStoreInventory:
    object_count: int
    file_count: int
    logical_bytes: int
    physical_bytes: int
    path_bytes: int


def _object_store_inventory_payload(
    inventory: _ObjectStoreInventory,
) -> dict[str, int]:
    return {
        "object_count": inventory.object_count,
        "file_count": inventory.file_count,
        "logical_bytes": inventory.logical_bytes,
        "physical_bytes": inventory.physical_bytes,
        "path_bytes": inventory.path_bytes,
    }


def _raise_object_store_budget(
    reason: str,
    label: str,
    observed: int,
    limit: int,
) -> None:
    raise ReviewWorkspaceError(
        reason,
        f"source object-store {label} exceeds its safety limit",
        details={"metric": label, "observed": observed, "limit": limit},
    )


def _pack_index_object_count(path: pathlib.Path, object_format: str) -> int:
    descriptor = os.open(path, _nofollow_flags(directory=False))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewWorkspaceError(
                "source-pack-index-invalid",
                "source pack index must be a regular file",
            )
        prefix = bytearray()
        while len(prefix) < 1032:
            chunk = os.read(descriptor, 1032 - len(prefix))
            if not chunk:
                break
            prefix.extend(chunk)
        if prefix.startswith(b"\xfftOc"):
            if len(prefix) < 1032 or prefix[4:8] != b"\x00\x00\x00\x02":
                raise ReviewWorkspaceError(
                    "source-pack-index-invalid",
                    "source pack index version is unsupported",
                )
            fanout_offset = 8
        else:
            if object_format != "sha1" or len(prefix) < 1024:
                raise ReviewWorkspaceError(
                    "source-pack-index-invalid",
                    "source pack index header is malformed",
                )
            fanout_offset = 0
        fanout = struct.unpack(
            ">256I",
            bytes(prefix[fanout_offset : fanout_offset + 1024]),
        )
        if any(left > right for left, right in zip(fanout, fanout[1:])):
            raise ReviewWorkspaceError(
                "source-pack-index-invalid",
                "source pack index fanout table is not monotonic",
            )
        object_count = fanout[-1]
        oid_width = 20 if object_format == "sha1" else 32
        minimum_size = fanout_offset + 1024 + object_count * (4 + oid_width)
        if metadata.st_size < minimum_size:
            raise ReviewWorkspaceError(
                "source-pack-index-invalid",
                "source pack index is shorter than its fanout table requires",
            )
        return object_count
    finally:
        os.close(descriptor)


def _copied_object_store_entry(relative: pathlib.PurePath, name: str) -> bool:
    if relative in {
        pathlib.PurePath("info/alternates"),
        pathlib.PurePath("info/http-alternates"),
        pathlib.PurePath("info/commit-graph"),
        pathlib.PurePath("pack/multi-pack-index"),
    }:
        return False
    if name.endswith(".promisor") or name.endswith(".lock") or name.startswith("tmp_"):
        return False
    return True


def _inventory_object_stores(
    sources: Sequence[pathlib.Path],
    object_format: str,
    deadline: float,
) -> _ObjectStoreInventory:
    object_count = 0
    file_count = 0
    logical_bytes = 0
    physical_bytes = 0
    path_bytes = 0
    for source in sources:
        pack_names: set[str] = set()
        index_names: set[str] = set()
        for current, directory_names, file_names in os.walk(source, followlinks=False):
            _check_object_store_deadline(deadline)
            current_path = pathlib.Path(current)
            relative_directory = current_path.relative_to(source)
            directory_names[:] = sorted(directory_names)
            for name in directory_names:
                _check_object_store_deadline(deadline)
                candidate = current_path / name
                metadata = candidate.stat(follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ReviewWorkspaceError(
                        "source-object-store-invalid",
                        "source object store contains a non-directory traversal entry",
                    )
                path_bytes += len(os.fsencode(str(relative_directory / name)))
                if path_bytes > OBJECT_STORE_PATH_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-path-limit",
                        "raw relative-path bytes",
                        path_bytes,
                        OBJECT_STORE_PATH_BYTES_LIMIT,
                    )
            for name in sorted(file_names):
                _check_object_store_deadline(deadline)
                relative = relative_directory / name
                if not _copied_object_store_entry(relative, name):
                    continue
                source_file = current_path / name
                metadata = source_file.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ReviewWorkspaceError(
                        "source-object-store-invalid",
                        "source object store contains a non-regular file",
                    )
                file_count += 1
                logical_bytes += metadata.st_size
                physical_bytes += max(0, getattr(metadata, "st_blocks", 0)) * 512
                path_bytes += len(os.fsencode(str(relative)))
                if file_count > OBJECT_STORE_FILE_COUNT_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-file-limit",
                        "file count",
                        file_count,
                        OBJECT_STORE_FILE_COUNT_LIMIT,
                    )
                if logical_bytes > OBJECT_STORE_LOGICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-logical-byte-limit",
                        "logical bytes",
                        logical_bytes,
                        OBJECT_STORE_LOGICAL_BYTES_LIMIT,
                    )
                if physical_bytes > OBJECT_STORE_PHYSICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-physical-byte-limit",
                        "physical bytes",
                        physical_bytes,
                        OBJECT_STORE_PHYSICAL_BYTES_LIMIT,
                    )
                if path_bytes > OBJECT_STORE_PATH_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-path-limit",
                        "raw relative-path bytes",
                        path_bytes,
                        OBJECT_STORE_PATH_BYTES_LIMIT,
                    )
                relative_text = relative.as_posix()
                if LOOSE_OBJECT_PATH.fullmatch(relative_text):
                    object_count += 1
                elif relative_directory == pathlib.Path("pack") and name.startswith(
                    "pack-"
                ):
                    if name.endswith(".pack"):
                        pack_names.add(name[:-5])
                    elif name.endswith(".idx"):
                        index_names.add(name[:-4])
                        object_count += _pack_index_object_count(
                            source_file,
                            object_format,
                        )
                if object_count > OBJECT_STORE_OBJECT_COUNT_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-object-limit",
                        "object count",
                        object_count,
                        OBJECT_STORE_OBJECT_COUNT_LIMIT,
                    )
        if pack_names != index_names:
            raise ReviewWorkspaceError(
                "source-pack-pair-invalid",
                "source object store pack and index files are not one-to-one",
                details={
                    "pack_without_index": sorted(pack_names - index_names)[:32],
                    "index_without_pack": sorted(index_names - pack_names)[:32],
                },
            )
    if file_count == 0 or object_count == 0:
        raise ReviewWorkspaceError(
            "source-object-store-empty",
            "source object store contains no countable Git objects",
        )
    return _ObjectStoreInventory(
        object_count=object_count,
        file_count=file_count,
        logical_bytes=logical_bytes,
        physical_bytes=physical_bytes,
        path_bytes=path_bytes,
    )


def _check_copy_capacity(
    destination: pathlib.Path,
    required_bytes: int,
    *,
    metric: str,
    reason: str = "workspace-copy-capacity-insufficient",
) -> None:
    free_bytes = shutil.disk_usage(destination.parent).free
    required_with_headroom = required_bytes + OBJECT_STORE_FREE_SPACE_HEADROOM_BYTES
    if free_bytes < required_with_headroom:
        raise ReviewWorkspaceError(
            reason,
            "workspace preparation lacks bounded free-space headroom",
            details={
                "metric": metric,
                "observed": free_bytes,
                "limit": required_with_headroom,
                "free_bytes": free_bytes,
                "required_bytes": required_bytes,
                "headroom_bytes": OBJECT_STORE_FREE_SPACE_HEADROOM_BYTES,
            },
        )


def _copy_regular_file(
    source: pathlib.Path,
    destination: pathlib.Path,
    mode: int,
    clonefile: object | None,
    deadline: float,
) -> bool:
    _check_object_store_deadline(deadline)
    cloned = False
    if clonefile is not None:
        ctypes.set_errno(0)
        result = clonefile(os.fsencode(source), os.fsencode(destination), 0)
        if result == 0:
            cloned = True
        else:
            clone_errno = ctypes.get_errno()
            expected_fallback = {
                errno.EINVAL,
                errno.ENOSYS,
                errno.ENOTSUP,
                errno.EXDEV,
            }
            if clone_errno not in expected_fallback:
                raise ReviewWorkspaceError(
                    "clonefile-failed",
                    f"APFS clonefile failed with unexpected errno {clone_errno}",
                )
    if not cloned:
        source_metadata = source.stat(follow_symlinks=False)
        _check_copy_capacity(
            destination,
            source_metadata.st_size,
            metric="clonefile fallback file",
        )
        if destination.exists() or destination.is_symlink():
            destination.unlink()
        try:
            source_descriptor = os.open(
                source,
                _nofollow_flags(directory=False),
            )
        except OSError as error:
            raise ReviewWorkspaceError(
                "source-object-store-invalid",
                "source object file cannot be opened without following links",
            ) from error
        destination_descriptor: int | None = None
        try:
            bound_source = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(bound_source.st_mode)
                or bound_source.st_dev != source_metadata.st_dev
                or bound_source.st_ino != source_metadata.st_ino
                or bound_source.st_size != source_metadata.st_size
            ):
                raise ReviewWorkspaceError(
                    "source-object-store-drift",
                    "source object file identity or size changed before copying",
                )
            destination_descriptor = os.open(
                destination,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                stat.S_IMODE(mode),
            )
            copied_bytes = 0
            while True:
                _check_object_store_deadline(deadline)
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied_bytes += len(chunk)
                if copied_bytes > bound_source.st_size:
                    raise ReviewWorkspaceError(
                        "source-object-store-drift",
                        "source object file grew while it was copied",
                    )
                view = memoryview(chunk)
                while view:
                    _check_object_store_deadline(deadline)
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            final_source = os.fstat(source_descriptor)
            final_destination = os.fstat(destination_descriptor)
            if (
                final_source.st_dev != bound_source.st_dev
                or final_source.st_ino != bound_source.st_ino
                or final_source.st_size != bound_source.st_size
                or copied_bytes != bound_source.st_size
                or not stat.S_ISREG(final_destination.st_mode)
                or final_destination.st_size != copied_bytes
            ):
                raise ReviewWorkspaceError(
                    "source-object-store-drift",
                    "source object file identity or size changed while it was copied",
                )
        finally:
            if destination_descriptor is not None:
                os.close(destination_descriptor)
            os.close(source_descriptor)
    _check_object_store_deadline(deadline)
    os.chmod(destination, stat.S_IMODE(mode), follow_symlinks=False)
    source_metadata = source.stat(follow_symlinks=False)
    destination_metadata = destination.stat(follow_symlinks=False)
    if (
        source_metadata.st_dev == destination_metadata.st_dev
        and source_metadata.st_ino == destination_metadata.st_ino
    ):
        raise ReviewWorkspaceError(
            "object-hardlink-detected",
            "workspace object copy unexpectedly shares an inode with its source",
        )
    return cloned


def _regular_files_equal(
    left: pathlib.Path,
    right: pathlib.Path,
    deadline: float,
) -> bool:
    if (
        left.stat(follow_symlinks=False).st_size
        != right.stat(follow_symlinks=False).st_size
    ):
        return False
    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            _check_object_store_deadline(deadline)
            left_chunk = left_stream.read(1024 * 1024)
            right_chunk = right_stream.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def _copy_object_stores(
    sources: Sequence[pathlib.Path],
    destination: pathlib.Path,
    object_format: str,
    deadline: float,
) -> str:
    raise ReviewWorkspaceError(
        "deprecated-object-store-copy",
        "raw source object-store copying is retired; use exact-pack normalization",
    )
    # Retain the former implementation below temporarily as non-callable
    # migration context. It is not a named-lane or public helper entrypoint.
    inventory = _inventory_object_stores(sources, object_format, deadline)
    _check_object_store_deadline(deadline)
    clonefile = _clonefile_function()
    if clonefile is None:
        _check_copy_capacity(
            destination,
            inventory.logical_bytes,
            metric="independent full object-store copy",
        )
    else:
        _check_copy_capacity(destination, 0, metric="copy-on-write metadata")
    destination.mkdir(mode=0o700)
    copied = 0
    cloned = 0
    destination_logical_bytes = 0
    destination_physical_bytes = 0
    traversed_files = 0
    source_object_count = 0
    source_file_count = 0
    source_logical_bytes = 0
    source_physical_bytes = 0
    source_path_bytes = 0
    for source in sources:
        pack_names: set[str] = set()
        index_names: set[str] = set()
        for current, directory_names, file_names in os.walk(source, followlinks=False):
            _check_object_store_deadline(deadline)
            current_path = pathlib.Path(current)
            relative_directory = current_path.relative_to(source)
            directory_names[:] = sorted(directory_names)
            for name in tuple(directory_names):
                _check_object_store_deadline(deadline)
                candidate = current_path / name
                metadata = candidate.stat(follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ReviewWorkspaceError(
                        "source-object-store-invalid",
                        "source object store contains a non-directory traversal entry",
                    )
                source_path_bytes += len(os.fsencode(str(relative_directory / name)))
                if source_path_bytes > OBJECT_STORE_PATH_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-path-limit",
                        "copy-pass raw relative-path bytes",
                        source_path_bytes,
                        OBJECT_STORE_PATH_BYTES_LIMIT,
                    )
                (destination / relative_directory / name).mkdir(
                    mode=stat.S_IMODE(metadata.st_mode), exist_ok=True
                )
            for name in sorted(file_names):
                _check_object_store_deadline(deadline)
                relative = relative_directory / name
                if not _copied_object_store_entry(relative, name):
                    continue
                source_file = current_path / name
                metadata = source_file.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ReviewWorkspaceError(
                        "source-object-store-invalid",
                        "source object store contains a non-regular file",
                    )
                source_file_count += 1
                source_logical_bytes += metadata.st_size
                source_physical_bytes += max(0, getattr(metadata, "st_blocks", 0)) * 512
                source_path_bytes += len(os.fsencode(str(relative)))
                if source_file_count > OBJECT_STORE_FILE_COUNT_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-file-limit",
                        "copy-pass file count",
                        source_file_count,
                        OBJECT_STORE_FILE_COUNT_LIMIT,
                    )
                if source_logical_bytes > OBJECT_STORE_LOGICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-logical-byte-limit",
                        "copy-pass logical bytes",
                        source_logical_bytes,
                        OBJECT_STORE_LOGICAL_BYTES_LIMIT,
                    )
                if source_physical_bytes > OBJECT_STORE_PHYSICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-physical-byte-limit",
                        "copy-pass physical bytes",
                        source_physical_bytes,
                        OBJECT_STORE_PHYSICAL_BYTES_LIMIT,
                    )
                if source_path_bytes > OBJECT_STORE_PATH_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-path-limit",
                        "copy-pass raw relative-path bytes",
                        source_path_bytes,
                        OBJECT_STORE_PATH_BYTES_LIMIT,
                    )
                relative_text = relative.as_posix()
                if LOOSE_OBJECT_PATH.fullmatch(relative_text):
                    source_object_count += 1
                elif relative_directory == pathlib.Path("pack") and name.startswith(
                    "pack-"
                ):
                    if name.endswith(".pack"):
                        pack_names.add(name[:-5])
                    elif name.endswith(".idx"):
                        index_names.add(name[:-4])
                        source_object_count += _pack_index_object_count(
                            source_file,
                            object_format,
                        )
                if source_object_count > OBJECT_STORE_OBJECT_COUNT_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-object-limit",
                        "copy-pass object count",
                        source_object_count,
                        OBJECT_STORE_OBJECT_COUNT_LIMIT,
                    )
                target_file = destination / relative
                if target_file.exists():
                    if not _regular_files_equal(target_file, source_file, deadline):
                        raise ReviewWorkspaceError(
                            "source-object-collision",
                            "object authorities contain conflicting object files",
                        )
                    continue
                traversed_files += 1
                if traversed_files > OBJECT_STORE_FILE_COUNT_LIMIT:
                    _raise_object_store_budget(
                        "source-object-store-file-limit",
                        "copy-pass file count",
                        traversed_files,
                        OBJECT_STORE_FILE_COUNT_LIMIT,
                    )
                copied += 1
                if _copy_regular_file(
                    source_file,
                    target_file,
                    metadata.st_mode,
                    clonefile,
                    deadline,
                ):
                    cloned += 1
                target_metadata = target_file.stat(follow_symlinks=False)
                destination_logical_bytes += target_metadata.st_size
                destination_physical_bytes += (
                    max(0, getattr(target_metadata, "st_blocks", 0)) * 512
                )
                if destination_logical_bytes > OBJECT_STORE_LOGICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "workspace-object-store-logical-byte-limit",
                        "destination logical bytes",
                        destination_logical_bytes,
                        OBJECT_STORE_LOGICAL_BYTES_LIMIT,
                    )
                if destination_physical_bytes > OBJECT_STORE_PHYSICAL_BYTES_LIMIT:
                    _raise_object_store_budget(
                        "workspace-object-store-physical-byte-limit",
                        "destination physical bytes",
                        destination_physical_bytes,
                        OBJECT_STORE_PHYSICAL_BYTES_LIMIT,
                    )
        if pack_names != index_names:
            raise ReviewWorkspaceError(
                "source-pack-pair-invalid",
                "source object store pack and index files changed during copying",
                details={
                    "pack_without_index": sorted(pack_names - index_names)[:32],
                    "index_without_pack": sorted(index_names - pack_names)[:32],
                },
            )
    copy_inventory = _ObjectStoreInventory(
        object_count=source_object_count,
        file_count=source_file_count,
        logical_bytes=source_logical_bytes,
        physical_bytes=source_physical_bytes,
        path_bytes=source_path_bytes,
    )
    final_inventory = _inventory_object_stores(sources, object_format, deadline)
    if copy_inventory != inventory or final_inventory != inventory:
        raise ReviewWorkspaceError(
            "source-object-store-drift",
            "source object-store inventory changed across preflight and copying",
            details={
                "preflight": _object_store_inventory_payload(inventory),
                "copy_pass": _object_store_inventory_payload(copy_inventory),
                "final": _object_store_inventory_payload(final_inventory),
            },
        )
    if copied == 0:
        raise ReviewWorkspaceError(
            "source-object-store-empty", "source object store contains no files"
        )
    if cloned == copied:
        return "apfs-cow"
    if cloned:
        return "mixed-cow-copy"
    return "independent-copy"


def _config_payload(object_format: str) -> bytes:
    version = "0" if object_format == "sha1" else "1"
    lines = [
        "[core]",
        f"\trepositoryformatversion = {version}",
        "\tbare = false",
        "\tfilemode = true",
        "\tsymlinks = true",
        "\tignorecase = false",
        "\tautocrlf = false",
        "\thooksPath = /dev/null",
        "\tfsmonitor = false",
        "\tcommitGraph = false",
        "\tmultiPackIndex = false",
        "\tlogAllRefUpdates = false",
    ]
    if object_format == "sha256":
        lines.extend(("[extensions]", "\tobjectFormat = sha256"))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _write_bytes(path: pathlib.Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


_RETAIN_PARTIAL_WORKSPACE_ATTRIBUTE = "_review_workspace_retain_partial"
_PARTIAL_WORKSPACE_RECOVERY_ATTRIBUTE = "_review_workspace_partial_recovery"


def _mark_partial_workspace_for_retention(error: BaseException) -> None:
    setattr(error, _RETAIN_PARTIAL_WORKSPACE_ATTRIBUTE, True)


def _partial_workspace_requires_retention(error: BaseException) -> bool:
    return bool(getattr(error, _RETAIN_PARTIAL_WORKSPACE_ATTRIBUTE, False))


def _record_partial_workspace_recovery(
    error: BaseException,
    recovery: Mapping[str, object],
) -> None:
    setattr(error, _PARTIAL_WORKSPACE_RECOVERY_ATTRIBUTE, dict(recovery))


def _partial_workspace_recovery_payload(
    error: BaseException,
) -> dict[str, object] | None:
    recovery = getattr(error, _PARTIAL_WORKSPACE_RECOVERY_ATTRIBUTE, None)
    if not isinstance(recovery, dict):
        return None
    return dict(recovery)


def _inherit_workspace_failure_metadata(
    primary: BaseException,
    secondary: BaseException,
) -> None:
    """Preserve recovery and retention state from a secondary teardown fault."""

    if process_quiescence_unproven(secondary):
        mark_process_quiescence_unproven(primary)
    if _partial_workspace_requires_retention(secondary):
        _mark_partial_workspace_for_retention(primary)
    recovery = _partial_workspace_recovery_payload(secondary)
    if recovery is not None:
        _record_partial_workspace_recovery(primary, recovery)
        if isinstance(primary, ReviewWorkspaceError):
            primary.details.update(recovery)


def _attach_workspace_teardown_failures(
    primary: BaseException,
    failures: Sequence[tuple[str, BaseException]],
) -> None:
    """Attach every attempted teardown failure without replacing ``primary``."""

    for context, secondary in failures:
        _inherit_workspace_failure_metadata(primary, secondary)
        _attach_workspace_failure_diagnostic(
            primary,
            secondary,
            context=context,
        )


def _select_workspace_teardown_failure(
    failures: Sequence[tuple[str, BaseException]],
) -> BaseException | None:
    """Select the first teardown fault and retain every later diagnostic."""

    if not failures:
        return None
    first_context, selected = failures[0]
    _attach_workspace_diagnostic(selected, first_context)
    _attach_workspace_teardown_failures(selected, failures[1:])
    return selected


def _attempt_workspace_descriptor_closes(
    descriptors: Sequence[tuple[str, int]],
) -> list[tuple[str, BaseException]]:
    """Best-effort close each distinct owned descriptor exactly once."""

    failures: list[tuple[str, BaseException]] = []
    attempted: set[int] = set()
    for context, descriptor in descriptors:
        if descriptor < 0 or descriptor in attempted:
            continue
        attempted.add(descriptor)
        try:
            os.close(descriptor)
        except BaseException as error:
            failures.append((context, error))
    return failures


class _WorkspaceStreamCloseOwner:
    """Own streams after raw-FD handoff and close every one exactly once."""

    def __init__(self) -> None:
        self._streams: list[tuple[str, object]] = []

    def __enter__(self) -> _WorkspaceStreamCloseOwner:
        return self

    def adopt(self, context: str, stream: object) -> object:
        self._streams.append((context, stream))
        return stream

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        primary_error: BaseException | None,
        _traceback: object,
    ) -> bool:
        owned_streams = self._streams
        self._streams = []
        close_failures: list[tuple[str, BaseException]] = []
        for context, stream in owned_streams:
            try:
                stream.close()  # type: ignore[attr-defined]
            except BaseException as error:
                close_failures.append((context, error))
        if primary_error is not None:
            _attach_workspace_teardown_failures(primary_error, close_failures)
            return False
        close_error = _select_workspace_teardown_failure(close_failures)
        if close_error is not None:
            raise close_error
        return False


def _process_start_identity(pid: int) -> str:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise ReviewWorkspaceError(
            "partial-recovery-process-identity-invalid",
            "process identity requires a PID greater than one",
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise
    except PermissionError:
        pass
    if sys.platform.startswith("linux"):
        try:
            raw = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
        except FileNotFoundError as error:
            raise ProcessLookupError(pid) from error
        if len(raw) > 4096:
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Linux process stat record exceeds its bound",
            )
        closing = raw.rfind(b")")
        if closing < 0:
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Linux process stat record is malformed",
            )
        fields = raw[closing + 2 :].split()
        if len(fields) < 20:
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Linux process stat record is malformed",
            )
        try:
            start_ticks = fields[19].decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Linux process start identity is malformed",
            ) from error
        if not start_ticks.isdigit():
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Linux process start identity is malformed",
            )
        return f"linux-start-ticks:{start_ticks}"
    if sys.platform == "darwin":

        class ProcBsdInfo(ctypes.Structure):
            _fields_ = (
                ("pbi_flags", ctypes.c_uint32),
                ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32),
                ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32),
                ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32),
                ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16),
                ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32),
                ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32),
                ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64),
            )

        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidinfo = library.proc_pidinfo
        proc_pidinfo.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        proc_pidinfo.restype = ctypes.c_int
        value = ProcBsdInfo()
        result = proc_pidinfo(
            pid,
            3,
            0,
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
        if (
            result != ctypes.sizeof(value)
            or value.pbi_pid != pid
            or value.pbi_start_tvsec == 0
            or value.pbi_start_tvusec >= 1_000_000
        ):
            error_number = ctypes.get_errno()
            if error_number == errno.ESRCH:
                raise ProcessLookupError(error_number, os.strerror(error_number), pid)
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "Darwin process start identity could not be bound",
                status="inconclusive",
            )
        return f"darwin-proc-start:{value.pbi_start_tvsec}:{value.pbi_start_tvusec}"
    try:
        completed = subprocess.run(
            ("/bin/ps", "-o", "lstart=", "-p", str(pid)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=2,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReviewWorkspaceError(
            "partial-recovery-process-identity-unavailable",
            "process start identity could not be obtained",
            status="inconclusive",
        ) from error
    if completed.returncode != 0 or not 1 <= len(completed.stdout) <= 256:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise
        raise ReviewWorkspaceError(
            "partial-recovery-process-identity-unavailable",
            "process start identity could not be obtained",
            status="inconclusive",
        )
    try:
        start = completed.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise ReviewWorkspaceError(
            "partial-recovery-process-identity-unavailable",
            "process start identity is malformed",
            status="inconclusive",
        ) from error
    if not start:
        raise ReviewWorkspaceError(
            "partial-recovery-process-identity-unavailable",
            "process start identity is empty",
            status="inconclusive",
        )
    return f"ps-lstart:{start}"


def _bind_recovery_process(pid: int) -> _RecoveryProcessIdentity:
    try:
        first_pgid = os.getpgid(pid)
        first_start = _process_start_identity(pid)
        second_pgid = os.getpgid(pid)
        second_start = _process_start_identity(pid)
    except ProcessLookupError as error:
        raise ReviewWorkspaceError(
            "range-pack-process-identity-unavailable",
            "exact-pack process exited before its identity could be bound",
            status="inconclusive",
        ) from error
    if (
        first_pgid != pid
        or second_pgid != pid
        or first_pgid != second_pgid
        or not secrets.compare_digest(first_start, second_start)
    ):
        raise ReviewWorkspaceError(
            "range-pack-process-identity-mismatch",
            "exact-pack process PID, PGID, or start identity is unstable",
            status="inconclusive",
        )
    return _RecoveryProcessIdentity(pid, first_pgid, first_start)


def _write_partial_recovery_record(
    descriptor: int,
    parent_descriptor: int,
    leaf: str,
    identity: tuple[int, int, int],
    payload: Mapping[str, object],
) -> str:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > MARKER_LIMIT_BYTES:
        raise ReviewWorkspaceError(
            "partial-recovery-control-limit",
            "partial recovery control exceeds its content bound",
        )
    metadata = os.fstat(descriptor)
    path_metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid) != identity
        or not os.path.samestat(metadata, path_metadata)
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-drift",
            "partial recovery control identity or access policy changed",
        )
    _validate_no_extended_acl(descriptor, "partial recovery control")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]
    os.fsync(descriptor)
    final_metadata = os.fstat(descriptor)
    final_path_metadata = os.stat(
        leaf,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        (final_metadata.st_dev, final_metadata.st_ino, final_metadata.st_uid)
        != identity
        or final_metadata.st_nlink != 1
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
        or final_metadata.st_size != len(encoded)
        or not os.path.samestat(final_metadata, final_path_metadata)
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-drift",
            "partial recovery control changed while it was published",
        )
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class _PartialRecoveryControl:
    path: pathlib.Path
    parent_descriptor: int
    root_descriptor: int
    descriptor: int
    identity: tuple[int, int, int]
    parent_identity: tuple[int, int, int]
    root_identity: tuple[int, int, int]
    payload: dict[str, object]
    sha256: str
    active_process: _RecoveryProcessIdentity | None = None
    active_operation: str | None = None
    _committed_recovery: dict[str, object] | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def _build_committed_recovery_payload(self) -> dict[str, object]:
        state = self.payload.get("state")
        if (
            state
            not in {
                "retained-quiescence-unproven",
                "retained-owner-exit-required",
            }
            or not self.sha256
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-unsealed",
                "partial recovery control has no durably sealed recovery state",
            )
        control = {
            "path": str(self.path),
            "sha256": self.sha256,
            "schema_version": PARTIAL_RECOVERY_SCHEMA_VERSION,
            "identity": {
                "device": self.identity[0],
                "inode": self.identity[1],
                "uid": self.identity[2],
            },
        }
        recovery = {
            "command": "recover-partial-workspace",
            "argv": [
                "recover-partial-workspace",
                "--control-file",
                str(self.path),
                "--control-sha256",
                self.sha256,
            ],
            "argv_ready": True,
            "requires_quiescence_proof": True,
            "ordinary_cleanup_available": False,
        }
        if state == "retained-quiescence-unproven":
            active_process = dict(self.payload["active_process"])
            recovery["instruction"] = (
                "Invoke this exact trusted-guard argv after the original prepare "
                "process exits. The route verifies the owner start identity, exact "
                "active PID/PGID/start identity and process-group absence, control "
                "digest/identity, and parent/workspace identities before "
                "descriptor-bound removal."
            )
        else:
            active_process = None
            recovery["instruction"] = (
                "Invoke this exact trusted-guard argv after the original prepare "
                "process exits. The route verifies owner-process absence plus the "
                "exact control, parent, workspace, and formal marker identities "
                "before descriptor-bound removal."
            )
        return {
            "partial_recovery_control": control,
            "retained_path": self.payload["worktree"],
            "parent_identity": dict(self.payload["parent_identity"]),
            "workspace_identity": dict(self.payload["workspace_identity"]),
            "workspace_state": dict(self.payload["workspace_state"]),
            "owner_process": dict(self.payload["owner_process"]),
            "active_process": active_process,
            "cleanup_unavailable_until_quiescent": True,
            "recovery": recovery,
        }

    def committed_recovery_payload(self) -> dict[str, object] | None:
        if self._committed_recovery is None:
            return None
        return copy.deepcopy(self._committed_recovery)

    def _attach_committed_recovery(self, error: BaseException) -> None:
        recovery = self.committed_recovery_payload()
        if recovery is None:
            return
        _mark_partial_workspace_for_retention(error)
        _record_partial_workspace_recovery(error, recovery)
        if isinstance(error, ReviewWorkspaceError):
            error.details.update(recovery)

    def _revalidate_bindings(self) -> None:
        """Bind the advertised paths to the held parent/root/control objects."""

        parent_metadata = os.fstat(self.parent_descriptor)
        root_metadata = os.fstat(self.root_descriptor)
        control_metadata = os.fstat(self.descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise ReviewWorkspaceError(
                "workspace-parent-policy",
                "partial recovery parent must be an owner-private mode-0700 directory",
            )
        _validate_private_directory_metadata(
            root_metadata,
            "partial recovery workspace",
        )
        _validate_no_extended_acl(
            self.parent_descriptor,
            "partial recovery parent",
        )
        _validate_no_extended_acl(
            self.root_descriptor,
            "partial recovery workspace",
        )
        _validate_no_extended_acl(
            self.descriptor,
            "partial recovery control",
        )
        if (
            (parent_metadata.st_dev, parent_metadata.st_ino, parent_metadata.st_uid)
            != self.parent_identity
            or (root_metadata.st_dev, root_metadata.st_ino, root_metadata.st_uid)
            != self.root_identity
            or (
                control_metadata.st_dev,
                control_metadata.st_ino,
                control_metadata.st_uid,
            )
            != self.identity
            or not stat.S_ISREG(control_metadata.st_mode)
            or control_metadata.st_nlink != 1
            or control_metadata.st_uid != os.getuid()
            or stat.S_IMODE(control_metadata.st_mode) != 0o600
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-binding-drift",
                "partial recovery descriptor identities or access policy changed",
            )
        advertised_root = pathlib.Path(str(self.payload["worktree"]))
        advertised_parent_descriptor = -1
        advertised_root_descriptor = -1
        advertised_control_descriptor = -1
        final_parent_descriptor = -1
        operation_error: BaseException | None = None
        try:
            root_path_metadata = advertised_root.stat(follow_symlinks=False)
            advertised_parent_descriptor = os.open(
                advertised_root.parent,
                _nofollow_flags(directory=True),
            )
            advertised_parent = os.fstat(advertised_parent_descriptor)
            advertised_root_descriptor = os.open(
                advertised_root.name,
                _nofollow_flags(directory=True),
                dir_fd=advertised_parent_descriptor,
            )
            advertised_control_descriptor = os.open(
                self.path.name,
                _nofollow_flags(directory=False),
                dir_fd=advertised_parent_descriptor,
            )
            if (
                not os.path.samestat(parent_metadata, advertised_parent)
                or not os.path.samestat(
                    root_metadata,
                    os.fstat(advertised_root_descriptor),
                )
                or not os.path.samestat(
                    root_metadata,
                    root_path_metadata,
                )
                or not os.path.samestat(
                    control_metadata,
                    os.fstat(advertised_control_descriptor),
                )
                or not os.path.samestat(
                    control_metadata,
                    os.stat(
                        self.path.name,
                        dir_fd=advertised_parent_descriptor,
                        follow_symlinks=False,
                    ),
                )
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-binding-drift",
                    (
                        "partial recovery advertised paths no longer name the "
                        "descriptor-bound parent, workspace, and control"
                    ),
                )
            final_parent_descriptor = os.open(
                advertised_root.parent,
                _nofollow_flags(directory=True),
            )
            if not os.path.samestat(
                parent_metadata,
                os.fstat(final_parent_descriptor),
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-binding-drift",
                    "partial recovery parent alias changed during revalidation",
                )
        except OSError as error:
            operation_error = ReviewWorkspaceError(
                "partial-recovery-binding-unavailable",
                "partial recovery advertised paths cannot be revalidated",
                status="inconclusive",
            )
            _bind_workspace_failure_cause(
                operation_error,
                error,
                context="partial recovery binding revalidation failed",
            )
        except BaseException as error:
            operation_error = error
        close_failures = _attempt_workspace_descriptor_closes(
            (
                (
                    "partial recovery final parent descriptor close failed",
                    final_parent_descriptor,
                ),
                (
                    "partial recovery advertised control descriptor close failed",
                    advertised_control_descriptor,
                ),
                (
                    "partial recovery advertised root descriptor close failed",
                    advertised_root_descriptor,
                ),
                (
                    "partial recovery advertised parent descriptor close failed",
                    advertised_parent_descriptor,
                ),
            )
        )
        if operation_error is not None:
            _attach_workspace_teardown_failures(operation_error, close_failures)
            raise operation_error
        close_error = _select_workspace_teardown_failure(close_failures)
        if close_error is not None:
            raise close_error

    @classmethod
    def create(cls, root: pathlib.Path) -> _PartialRecoveryControl:
        leaf = f"{PARTIAL_RECOVERY_PREFIX}{secrets.token_hex(16)}.json"
        parent_descriptor = os.open(root.parent, _nofollow_flags(directory=True))
        root_descriptor = -1
        descriptor = -1
        locked = False
        control_created = False
        control_identity: tuple[int, int, int] | None = None
        digest: str | None = None
        publication_committed = False
        try:
            fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
            locked = True
            parent_metadata = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.getuid()
                or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            ):
                raise ReviewWorkspaceError(
                    "workspace-parent-policy",
                    "workspace parent must be an owner-private mode-0700 directory",
                )
            _validate_no_extended_acl(parent_descriptor, "workspace parent")
            parent_identity = (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
                parent_metadata.st_uid,
            )
            root_path_metadata = os.stat(
                root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            root_descriptor = os.open(
                root.name,
                _nofollow_flags(directory=True),
                dir_fd=parent_descriptor,
            )
            root_metadata = os.fstat(root_descriptor)
            _validate_private_directory_metadata(root_metadata, "workspace root")
            _validate_no_extended_acl(root_descriptor, "workspace root")
            if not os.path.samestat(root_path_metadata, root_metadata):
                raise ReviewWorkspaceError(
                    "partial-recovery-binding-drift",
                    "workspace changed before partial recovery descriptor custody",
                )
            workspace_identity = (
                root_metadata.st_dev,
                root_metadata.st_ino,
                root_metadata.st_uid,
            )
            try:
                marker = _snapshot_control_file(
                    root_descriptor,
                    (".git", WORKSPACE_MARKER),
                    capture_payload=False,
                )
            except FileNotFoundError:
                workspace_state: dict[str, object] = {"kind": "unpublished-markerless"}
            else:
                workspace_state = {
                    "kind": "formal-marked",
                    "marker_sha256": marker.sha256,
                }
            owner_pid = os.getpid()
            owner_start_identity = _process_start_identity(owner_pid)
            descriptor = os.open(
                leaf,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            control_created = True
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
            control_identity = identity
            payload: dict[str, object] = {
                "schema_version": PARTIAL_RECOVERY_SCHEMA_VERSION,
                "control_id": secrets.token_hex(32),
                "control_identity": {
                    "device": identity[0],
                    "inode": identity[1],
                    "uid": identity[2],
                },
                "worktree": str(root),
                "parent_identity": {
                    "device": parent_identity[0],
                    "inode": parent_identity[1],
                    "uid": parent_identity[2],
                },
                "workspace_identity": {
                    "device": workspace_identity[0],
                    "inode": workspace_identity[1],
                    "uid": workspace_identity[2],
                },
                "workspace_state": workspace_state,
                "owner_process": {
                    "pid": owner_pid,
                    "start_identity": owner_start_identity,
                },
                "active_process": None,
                "state": "armed",
            }
            result = cls(
                path=root.parent / leaf,
                parent_descriptor=parent_descriptor,
                root_descriptor=root_descriptor,
                descriptor=descriptor,
                identity=identity,
                parent_identity=parent_identity,
                root_identity=workspace_identity,
                payload=payload,
                sha256="",
            )
            result._revalidate_bindings()
            digest = _write_partial_recovery_record(
                descriptor,
                parent_descriptor,
                leaf,
                identity,
                payload,
            )
            os.fsync(parent_descriptor)
            publication_committed = True
            result.sha256 = digest
            result._revalidate_bindings()
            fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
            locked = False
            return result
        except BaseException as primary_error:
            cleanup_failures: list[tuple[str, BaseException]] = []
            control_to_close = descriptor
            root_to_close = root_descriptor
            parent_to_close = parent_descriptor
            descriptor = -1
            root_descriptor = -1
            parent_descriptor = -1
            control_retained = False
            locator_status = "removed"
            advertised_parent_matches = False
            if control_created:
                absence_durable = True
                unlink_safe = False
                try:
                    held_metadata = os.fstat(control_to_close)
                    path_metadata = os.stat(
                        leaf,
                        dir_fd=parent_to_close,
                        follow_symlinks=False,
                    )
                    unlink_safe = bool(
                        control_identity is not None
                        and (
                            held_metadata.st_dev,
                            held_metadata.st_ino,
                            held_metadata.st_uid,
                        )
                        == control_identity
                        and os.path.samestat(held_metadata, path_metadata)
                    )
                    if not unlink_safe:
                        raise ReviewWorkspaceError(
                            "partial-recovery-control-drift",
                            "partial recovery create cleanup control identity changed",
                        )
                except BaseException as identity_error:
                    cleanup_failures.append(
                        (
                            "partial recovery create control unlink identity check "
                            "failed",
                            identity_error,
                        )
                    )
                    locator_status = "unverified"
                if unlink_safe:
                    try:
                        os.unlink(leaf, dir_fd=parent_to_close)
                    except FileNotFoundError:
                        pass
                    except BaseException as unlink_error:
                        cleanup_failures.append(
                            (
                                "partial recovery create control unlink failed",
                                unlink_error,
                            )
                        )
                try:
                    os.fsync(parent_to_close)
                except BaseException as sync_error:
                    absence_durable = False
                    cleanup_failures.append(
                        (
                            "partial recovery create parent sync after control cleanup "
                            "failed",
                            sync_error,
                        )
                    )
                try:
                    residual_metadata = os.stat(
                        leaf,
                        dir_fd=parent_to_close,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    control_retained = not absence_durable
                    if control_retained:
                        locator_status = "absence-undurable"
                except BaseException as locator_error:
                    control_retained = True
                    locator_status = "unverified"
                    cleanup_failures.append(
                        (
                            "partial recovery create retained control locator "
                            "could not be verified",
                            locator_error,
                        )
                    )
                else:
                    control_retained = True
                    locator_status = (
                        "retained"
                        if control_identity is not None
                        and (
                            residual_metadata.st_dev,
                            residual_metadata.st_ino,
                            residual_metadata.st_uid,
                        )
                        == control_identity
                        else "identity-mismatch"
                    )
                if control_retained:
                    try:
                        held_parent_metadata = os.fstat(parent_to_close)
                        advertised_parent_metadata = os.stat(
                            root.parent,
                            follow_symlinks=False,
                        )
                        advertised_parent_matches = bool(
                            (
                                held_parent_metadata.st_dev,
                                held_parent_metadata.st_ino,
                                held_parent_metadata.st_uid,
                            )
                            == parent_identity
                            and os.path.samestat(
                                held_parent_metadata,
                                advertised_parent_metadata,
                            )
                        )
                        if not advertised_parent_matches:
                            raise ReviewWorkspaceError(
                                "partial-recovery-parent-alias-drift",
                                "partial recovery create retained parent path no "
                                "longer names the descriptor-bound directory",
                            )
                    except BaseException as parent_alias_error:
                        cleanup_failures.append(
                            (
                                "partial recovery create retained parent path "
                                "could not be verified",
                                parent_alias_error,
                            )
                        )
            cleanup_failures.extend(
                _attempt_workspace_descriptor_closes(
                    (
                        (
                            "partial recovery create control descriptor close failed",
                            control_to_close,
                        ),
                    )
                )
            )
            cleanup_failures.extend(
                _attempt_workspace_descriptor_closes(
                    (
                        (
                            "partial recovery create workspace root descriptor "
                            "close failed",
                            root_to_close,
                        ),
                    )
                )
            )
            if locked:
                try:
                    fcntl.flock(parent_to_close, fcntl.LOCK_UN)
                except BaseException as unlock_error:
                    cleanup_failures.append(
                        (
                            "partial recovery create parent unlock failed",
                            unlock_error,
                        )
                    )
                locked = False
            cleanup_failures.extend(
                _attempt_workspace_descriptor_closes(
                    (
                        (
                            "partial recovery create workspace parent descriptor "
                            "close failed",
                            parent_to_close,
                        ),
                    )
                )
            )
            if control_retained:
                locator = {
                    "status": "cleanup-incomplete",
                    "control_file": (
                        str(root.parent / leaf) if advertised_parent_matches else None
                    ),
                    "control_sha256": digest if publication_committed else None,
                    "publication_status": (
                        "durable-armed" if publication_committed else "unverified"
                    ),
                    "locator_status": (
                        locator_status
                        if advertised_parent_matches
                        else "parent-path-unverified"
                    ),
                    "bound_control_status": locator_status,
                    "state": "armed",
                    "ordinary_cleanup_available": False,
                    "parent_identity": {
                        "device": parent_identity[0],
                        "inode": parent_identity[1],
                        "uid": parent_identity[2],
                    },
                    "workspace_identity": {
                        "device": workspace_identity[0],
                        "inode": workspace_identity[1],
                        "uid": workspace_identity[2],
                    },
                    "recovery": {
                        "command": None,
                        "argv": None,
                        "argv_ready": False,
                        "unavailable_reason": "armed-control-cleanup-incomplete",
                    },
                }
                if not advertised_parent_matches:
                    locator["expected_locator"] = {
                        "parent": str(root.parent),
                        "leaf": leaf,
                        "parent_identity": dict(locator["parent_identity"]),
                        "control_identity": (
                            None
                            if control_identity is None
                            else {
                                "device": control_identity[0],
                                "inode": control_identity[1],
                                "uid": control_identity[2],
                            }
                        ),
                    }
                if control_identity is not None:
                    locator["identity"] = {
                        "device": control_identity[0],
                        "inode": control_identity[1],
                        "uid": control_identity[2],
                    }
                setattr(
                    primary_error,
                    "_review_workspace_partial_control_cleanup",
                    locator,
                )
                _mark_partial_workspace_for_retention(primary_error)
                if isinstance(primary_error, ReviewWorkspaceError):
                    primary_error.details["partial_recovery_control_cleanup"] = locator
                if advertised_parent_matches:
                    locator_diagnostic = (
                        "partial recovery armed control cleanup is incomplete; "
                        f"retained locator: {root.parent / leaf}"
                    )
                else:
                    locator_diagnostic = (
                        "partial recovery armed control cleanup is incomplete; "
                        "the advertised parent path is unverified and only the "
                        "expected identity locator is authoritative"
                    )
                _attach_workspace_diagnostic(primary_error, locator_diagnostic)
            _attach_workspace_teardown_failures(primary_error, cleanup_failures)
            raise

    def _publish(self) -> None:
        signal_owner = _begin_forwarded_signal_mask()
        primary_error: BaseException | None = None
        locked = False
        try:
            try:
                fcntl.flock(self.parent_descriptor, fcntl.LOCK_EX)
                locked = True
                self._revalidate_bindings()
                digest = _write_partial_recovery_record(
                    self.descriptor,
                    self.parent_descriptor,
                    self.path.name,
                    self.identity,
                    self.payload,
                )
                os.fsync(self.parent_descriptor)
                self.sha256 = digest
                if self.payload.get("state") in {
                    "retained-quiescence-unproven",
                    "retained-owner-exit-required",
                }:
                    self._committed_recovery = self._build_committed_recovery_payload()
                else:
                    self._committed_recovery = None
                self._revalidate_bindings()
            except BaseException as error:
                primary_error = error
            unlock_failures: list[tuple[str, BaseException]] = []
            if locked:
                try:
                    fcntl.flock(self.parent_descriptor, fcntl.LOCK_UN)
                except BaseException as unlock_error:
                    unlock_failures.append(
                        ("partial recovery publication unlock failed", unlock_error)
                    )
                locked = False
            if primary_error is not None:
                _attach_workspace_teardown_failures(
                    primary_error,
                    unlock_failures,
                )
            else:
                primary_error = _select_workspace_teardown_failure(unlock_failures)
            _finish_forwarded_signal_mask(
                signal_owner,
                primary_error=primary_error,
            )
            if primary_error is not None:
                raise primary_error
        except BaseException as error:
            self._attach_committed_recovery(error)
            raise

    def bind_process(self, operation: str, binding: object) -> None:
        if not isinstance(binding, _RecoveryProcessIdentity):
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-invalid",
                "workspace process callback returned a malformed identity",
                status="inconclusive",
            )
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", operation) is None:
            raise ReviewWorkspaceError(
                "partial-recovery-operation-invalid",
                "workspace process operation label is invalid",
                status="inconclusive",
            )
        if self.active_process is not None or self.payload.get("state") != "armed":
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-duplicate",
                "workspace process identity was published while another was active",
                status="inconclusive",
            )
        self.active_process = binding
        self.active_operation = operation
        self.payload["active_process"] = {
            **binding.payload(),
            "operation": operation,
            "process_state": "bound-before-exec",
        }
        self.payload["state"] = "process-bound"
        self._publish()

    def release_process(self, binding: _RecoveryProcessIdentity) -> None:
        if (
            self.active_process != binding
            or self.active_operation is None
            or self.payload.get("state") != "process-bound"
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-mismatch",
                "workspace process quiescence did not match the active identity",
                status="inconclusive",
            )
        self.active_process = None
        self.active_operation = None
        self.payload["active_process"] = None
        self.payload["state"] = "armed"
        self._publish()

    def recovery_payload(self) -> dict[str, object]:
        if (
            self.active_process is None
            or self.active_operation is None
            or self.payload.get("state")
            not in {
                "process-bound",
                "retained-quiescence-unproven",
            }
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "unsafe workspace process identity was not bound for recovery",
                status="inconclusive",
            )
        try:
            if self.payload.get("state") == "process-bound":
                self.payload["active_process"] = {
                    **self.active_process.payload(),
                    "operation": self.active_operation,
                    "process_state": "quiescence-unproven",
                }
                self.payload["state"] = "retained-quiescence-unproven"
                self._publish()
            self._revalidate_bindings()
            recovery = self.committed_recovery_payload()
            if recovery is None:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unsealed",
                    "partial recovery process control was not durably sealed",
                )
            return recovery
        except BaseException as error:
            self._attach_committed_recovery(error)
            raise

    def owner_exit_recovery_payload(self) -> dict[str, object]:
        """Seal a workspace for recovery after this owner process exits."""

        if self.active_process is not None or self.payload.get("state") != "armed":
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-unavailable",
                "owner-exit recovery requires an armed control with no child process",
                status="inconclusive",
            )
        try:
            self.payload["state"] = "retained-owner-exit-required"
            self._publish()
            self._revalidate_bindings()
            recovery = self.committed_recovery_payload()
            if recovery is None:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unsealed",
                    "owner-exit recovery control was not durably sealed",
                )
            return recovery
        except BaseException as error:
            self._attach_committed_recovery(error)
            raise

    def unavailable_recovery_payload(
        self,
        publication_error: BaseException,
    ) -> dict[str, object]:
        """Describe fail-closed retention without claiming a usable control."""

        active_process: dict[str, object] | None = None
        if self.active_process is not None and self.active_operation is not None:
            active_process = {
                **self.active_process.payload(),
                "operation": self.active_operation,
                "process_state": "quiescence-unproven",
            }
        return {
            "partial_recovery_control": {
                "path": str(self.path),
                "sha256": None,
                "schema_version": PARTIAL_RECOVERY_SCHEMA_VERSION,
                "identity": {
                    "device": self.identity[0],
                    "inode": self.identity[1],
                    "uid": self.identity[2],
                },
                "publication_status": "unverified",
            },
            "retained_path": self.payload["worktree"],
            "parent_identity": dict(self.payload["parent_identity"]),
            "workspace_identity": dict(self.payload["workspace_identity"]),
            "workspace_state": dict(self.payload["workspace_state"]),
            "owner_process": dict(self.payload["owner_process"]),
            "active_process": active_process,
            "cleanup_unavailable_until_quiescent": True,
            "recovery": {
                "command": None,
                "argv": None,
                "argv_ready": False,
                "requires_quiescence_proof": True,
                "ordinary_cleanup_available": False,
                "unavailable_reason": getattr(
                    publication_error,
                    "reason",
                    type(publication_error).__name__,
                ),
                "instruction": (
                    "Retain the workspace and control file. Automatic recovery "
                    "is unavailable because the identity-bound control could not "
                    "be sealed; do not invoke cleanup-workspace."
                ),
            },
        }

    def close(self, *, retain: bool) -> None:
        descriptor = self.descriptor
        parent_descriptor = self.parent_descriptor
        root_descriptor = self.root_descriptor
        self.descriptor = -1
        self.parent_descriptor = -1
        self.root_descriptor = -1
        operation_error: BaseException | None = None
        try:
            if retain and self.payload.get("state") not in {
                "retained-quiescence-unproven",
                "retained-owner-exit-required",
            }:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unsealed",
                    "partial recovery control was not sealed for retention",
                )
            if not retain:
                metadata = os.fstat(descriptor)
                path_metadata = os.stat(
                    self.path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                ) != self.identity or not os.path.samestat(metadata, path_metadata):
                    raise ReviewWorkspaceError(
                        "partial-recovery-control-drift",
                        "partial recovery control changed before removal",
                    )
                os.unlink(self.path.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
        except BaseException as error:
            operation_error = error
            raise
        finally:
            close_errors: list[tuple[str, BaseException]] = []
            for label, opened in (
                ("control", descriptor),
                ("workspace root", root_descriptor),
                ("workspace parent", parent_descriptor),
            ):
                try:
                    os.close(opened)
                except BaseException as error:
                    close_errors.append((label, error))
            if operation_error is not None:
                for label, error in close_errors:
                    _attach_workspace_failure_diagnostic(
                        operation_error,
                        error,
                        context=f"partial recovery {label} descriptor close failed",
                    )
            elif close_errors:
                selected_label, selected_error = close_errors[0]
                _attach_workspace_diagnostic(
                    selected_error,
                    f"partial recovery {selected_label} descriptor close failed",
                )
                for label, error in close_errors[1:]:
                    _attach_workspace_failure_diagnostic(
                        selected_error,
                        error,
                        context=f"partial recovery {label} descriptor close failed",
                    )
                raise selected_error


def retain_workspace_for_owner_exit_recovery(
    root: pathlib.Path,
    expected_parent_identity: tuple[int, int, int],
    expected_workspace_identity: tuple[int, int, int],
    *,
    primary_error: BaseException | None = None,
    signal_owner: ForwardedSignalMaskOwner | None = None,
) -> dict[str, object]:
    """Persist an executable parent-private recovery capability for ``root``."""

    owns_signal_owner = signal_owner is None
    if signal_owner is None:
        signal_owner = _begin_forwarded_signal_mask()
    elif not signal_owner.active:
        raise ReviewWorkspaceError(
            "partial-recovery-signal-custody-invalid",
            "owner-exit recovery requires an active forwarded-signal mask owner",
        )
    sealed_recovery: list[dict[str, object]] = []

    def attach_sealed_recovery(error: BaseException | None) -> None:
        if error is None or not sealed_recovery:
            return
        recovery = sealed_recovery[0]
        _mark_partial_workspace_for_retention(error)
        _record_partial_workspace_recovery(error, recovery)
        if isinstance(error, ReviewWorkspaceError):
            error.details.update(recovery)

    try:
        result = _retain_workspace_for_owner_exit_recovery_under_signal_mask(
            root,
            expected_parent_identity,
            expected_workspace_identity,
            sealed_recovery=sealed_recovery,
        )
    except BaseException as error:
        attach_sealed_recovery(error)
        attach_sealed_recovery(primary_error)
        if owns_signal_owner:
            try:
                _finish_forwarded_signal_mask(
                    signal_owner,
                    primary_error=error,
                )
            except BaseException as finish_error:
                attach_sealed_recovery(finish_error)
                raise
        raise
    attach_sealed_recovery(primary_error)
    if owns_signal_owner:
        try:
            _finish_forwarded_signal_mask(
                signal_owner,
                primary_error=primary_error,
            )
        except BaseException as finish_error:
            attach_sealed_recovery(finish_error)
            raise
    return result


def _retain_workspace_for_owner_exit_recovery_under_signal_mask(
    root: pathlib.Path,
    expected_parent_identity: tuple[int, int, int],
    expected_workspace_identity: tuple[int, int, int],
    *,
    sealed_recovery: list[dict[str, object]],
) -> dict[str, object]:
    control = _PartialRecoveryControl.create(root)
    retain = False
    result: dict[str, object] | None = None
    operation_error: BaseException | None = None
    try:
        observed_parent = _partial_control_identity(
            control.payload,
            "parent_identity",
        )
        observed_workspace = _partial_control_identity(
            control.payload,
            "workspace_identity",
        )
        if (
            observed_parent != expected_parent_identity
            or observed_workspace != expected_workspace_identity
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-workspace-identity-mismatch",
                "retained workspace differs from the publication rollback binding",
            )
        result = control.owner_exit_recovery_payload()
    except BaseException as error:
        operation_error = error
    committed_recovery = control.committed_recovery_payload()
    if committed_recovery is not None:
        retain = True
        sealed_recovery.append(committed_recovery)
        result = committed_recovery
        if operation_error is not None:
            control._attach_committed_recovery(operation_error)
    try:
        control.close(retain=retain)
    except BaseException as close_error:
        control._attach_committed_recovery(close_error)
        if operation_error is not None:
            _inherit_workspace_failure_metadata(operation_error, close_error)
            _attach_workspace_failure_diagnostic(
                operation_error,
                close_error,
                context="owner-exit recovery control finalization failed",
            )
        else:
            operation_error = close_error
    if operation_error is not None:
        raise operation_error
    assert result is not None
    return result


def _retain_unquiesced_workspace(
    error: BaseException,
    control: _PartialRecoveryControl,
    *,
    diagnostic_context: str,
) -> dict[str, object]:
    """Retain first, then best-effort publish an executable recovery route."""

    mark_process_quiescence_unproven(error)
    _mark_partial_workspace_for_retention(error)
    try:
        recovery = control.recovery_payload()
    except BaseException as publication_error:
        _attach_workspace_diagnostic_preserving_cause(
            error,
            f"{diagnostic_context} recovery publication failed: "
            f"{type(publication_error).__name__}",
        )
        recovery = (
            _partial_workspace_recovery_payload(publication_error)
            or control.committed_recovery_payload()
        )
        if recovery is None:
            try:
                recovery = control.unavailable_recovery_payload(publication_error)
            except BaseException as fallback_error:
                _attach_workspace_diagnostic_preserving_cause(
                    error,
                    f"{diagnostic_context} recovery fallback failed: "
                    f"{type(fallback_error).__name__}",
                )
                recovery = {
                    "retained_path": str(
                        control.payload.get("worktree", control.path.parent)
                    ),
                    "cleanup_unavailable_until_quiescent": True,
                    "recovery": {
                        "command": None,
                        "argv": None,
                        "argv_ready": False,
                        "requires_quiescence_proof": True,
                        "ordinary_cleanup_available": False,
                        "unavailable_reason": type(publication_error).__name__,
                    },
                }
    _record_partial_workspace_recovery(error, recovery)
    return recovery


def _inherit_unquiesced_workspace_retention(
    error: BaseException,
    recovery: Mapping[str, object],
) -> None:
    mark_process_quiescence_unproven(error)
    _mark_partial_workspace_for_retention(error)
    _record_partial_workspace_recovery(error, recovery)


def _build_exact_object_store(
    root: pathlib.Path,
    source: _SourceRepository,
    object_ids: Sequence[str],
    deadline: float,
) -> str:
    """Normalize the exact reviewed closure into one self-contained pack."""

    signal_owner = _begin_forwarded_signal_mask()
    primary_error: BaseException | None = None
    try:
        return _build_exact_object_store_under_signal_mask(
            root,
            source,
            object_ids,
            deadline,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _finish_forwarded_signal_mask(
            signal_owner,
            primary_error=primary_error,
        )


def _build_exact_object_store_under_signal_mask(
    root: pathlib.Path,
    source: _SourceRepository,
    object_ids: Sequence[str],
    deadline: float,
) -> str:
    _check_object_store_deadline(deadline)
    _revalidate_source_repository(source, deadline)
    pack_directory = root / ".git/objects/pack"
    pack_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    token = secrets.token_hex(16)
    temporary_pack = pack_directory / f".review-{token}.pack"
    temporary_error = pack_directory / f".review-{token}.stderr"
    temporary_index = pack_directory / f".review-{token}.idx"
    query = b"".join(f"{oid}\n".encode("ascii") for oid in object_ids)
    process_start = ProcessStartOwner()
    process_quiescent = False
    retain_temporary_output = False
    active_binding: _RecoveryProcessIdentity | None = None

    def publish_process_quiescent() -> None:
        nonlocal process_quiescent
        process_quiescent = True
        if active_binding is not None:
            partial_control.release_process(active_binding)

    def publish_process_binding(binding: object) -> None:
        nonlocal active_binding
        if not isinstance(binding, _RecoveryProcessIdentity):
            raise ReviewWorkspaceError(
                "partial-recovery-process-identity-invalid",
                "exact-pack process returned a malformed recovery identity",
                status="inconclusive",
            )
        partial_control.bind_process("pack-objects", binding)
        active_binding = binding

    pack_descriptor = -1
    error_descriptor = -1
    partial_control = _PartialRecoveryControl.create(root)
    operation_error: BaseException | None = None
    try:
        pack_descriptor = os.open(
            temporary_pack,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        error_descriptor = os.open(
            temporary_error,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with _WorkspaceStreamCloseOwner() as streams:
            pack_stream = streams.adopt(
                "exact-pack pack stream close failed",
                os.fdopen(pack_descriptor, "w+b", closefd=True),
            )
            pack_descriptor = -1
            error_stream = streams.adopt(
                "exact-pack error stream close failed",
                os.fdopen(error_descriptor, "w+b", closefd=True),
            )
            error_descriptor = -1
            environment = _git_environment()
            environment.update(
                {
                    "GIT_CEILING_DIRECTORIES": str(source.root.parent),
                    "GIT_DIR": str(source.git_dir),
                    "GIT_WORK_TREE": str(source.root),
                }
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _check_object_store_deadline(deadline)
            try:
                completed = run_process(
                    _git_argv(
                        source.root,
                        (
                            "-c",
                            "pack.threads=1",
                            "-c",
                            "pack.window=10",
                            "-c",
                            "pack.depth=50",
                            "pack-objects",
                            "--stdout",
                            "--no-reuse-delta",
                            "--no-reuse-object",
                        ),
                    ),
                    env=environment,
                    stdin=query,
                    stdout_file=pack_stream,
                    stderr_file=error_stream,
                    capture_limit_bytes=64 * 1024,
                    timeout_seconds=remaining,
                    output_file_limit_bytes=RANGE_PACK_BYTES_LIMIT,
                    prepare_process_spawned=_bind_recovery_process,
                    on_process_spawned=publish_process_binding,
                    on_process_starting=process_start.publish_starting,
                    on_process_started=process_start.publish_started,
                    on_process_quiescent=publish_process_quiescent,
                )
            except BaseException as error:
                cleanup_unsafe = (
                    process_start.may_have_started() and not process_quiescent
                )
                if cleanup_unsafe:
                    retain_temporary_output = True
                    pack_recovery = _retain_unquiesced_workspace(
                        error,
                        partial_control,
                        diagnostic_context="exact-pack process",
                    )
                if _is_process_control_flow_error(error):
                    raise
                details: dict[str, object] = {}
                if cleanup_unsafe:
                    details.update(
                        {
                            "process_quiescence": "unproven",
                            "rollback": "skipped-process-quiescence-unproven",
                        }
                    )
                if isinstance(error, ReviewProcessLeakError):
                    mapped = ReviewWorkspaceError(
                        "range-pack-process-leak",
                        "exact frozen-range pack process-group quiescence was not proved",
                        status="inconclusive",
                        details=details,
                    )
                elif isinstance(error, ReviewOutputDrainError):
                    mapped = ReviewWorkspaceError(
                        "range-pack-output-drain",
                        "exact frozen-range pack output could not be drained completely",
                        status="inconclusive",
                        details=details,
                    )
                elif isinstance(error, ReviewTimeoutError):
                    mapped = ReviewWorkspaceError(
                        "range-pack-timeout",
                        "exact frozen-range pack generation exceeded its deadline",
                        status="inconclusive",
                        details={**details, "retryable": True},
                    )
                elif isinstance(error, ReviewOutputLimitError):
                    mapped = ReviewWorkspaceError(
                        "range-pack-limit",
                        "exact frozen-range pack exceeded its compressed output bound",
                        status="inconclusive" if cleanup_unsafe else "blocked-safety",
                        details={
                            **details,
                            "limit": RANGE_PACK_BYTES_LIMIT,
                            "limit_kind": error.limit_kind,
                        },
                    )
                elif isinstance(error, (ReviewError, OSError)):
                    if cleanup_unsafe:
                        mapped = ReviewWorkspaceError(
                            "range-pack-quiescence-unproven",
                            "exact frozen-range pack failure left process quiescence unproved",
                            status="inconclusive",
                            details={
                                **details,
                                "operation_reason": "range-pack-failed",
                            },
                        )
                    else:
                        mapped = ReviewWorkspaceError(
                            "range-pack-failed",
                            "exact frozen-range pack generation failed",
                        )
                else:
                    raise
                if cleanup_unsafe:
                    _inherit_unquiesced_workspace_retention(
                        mapped,
                        pack_recovery,
                    )
                raise mapped from error
            if completed.returncode != 0:
                raise ReviewWorkspaceError(
                    "range-pack-failed",
                    "exact frozen-range pack generation failed",
                    details={
                        "returncode": completed.returncode,
                        "stderr_preview": completed.stderr.decode(
                            "utf-8", "backslashreplace"
                        )[:4096],
                    },
                )
            _revalidate_source_repository(source, deadline)
            pack_stream.flush()
            os.fsync(pack_stream.fileno())
            pack_metadata = os.fstat(pack_stream.fileno())
            if (
                not stat.S_ISREG(pack_metadata.st_mode)
                or pack_metadata.st_size <= 0
                or pack_metadata.st_size > RANGE_PACK_BYTES_LIMIT
            ):
                raise ReviewWorkspaceError(
                    "range-pack-limit",
                    "exact frozen-range pack is empty or exceeds its compressed bound",
                    details={
                        "observed": pack_metadata.st_size,
                        "limit": RANGE_PACK_BYTES_LIMIT,
                    },
                )
        static_binding = _bind_workspace_controls(
            root,
            include_index=False,
            include_marker=False,
        )
        returncode, output, index_stderr = _run_git_raw(
            root,
            (
                "index-pack",
                "--no-rev-index",
                "-o",
                str(temporary_index),
                str(temporary_pack),
            ),
            output_limit_bytes=4096,
            timeout_seconds=max(0.001, deadline - time.monotonic()),
            absolute_deadline=deadline,
            control_binding=static_binding,
            partial_recovery_control=partial_control,
            partial_recovery_operation="index-pack",
        )
        if returncode != 0:
            stderr_preview = index_stderr.decode("utf-8", "backslashreplace")[:4096]
            raise ReviewWorkspaceError(
                "range-pack-index-failed",
                f"exact frozen-range pack indexing failed: {stderr_preview.strip()}",
                details={
                    "returncode": returncode,
                    "stderr_preview": stderr_preview,
                },
            )
        output = output.strip()
        try:
            pack_hash = output.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "range-pack-index-invalid",
                "exact frozen-range pack index returned a non-ASCII checksum",
            ) from error
        expected_length = 40 if source.object_format == "sha1" else 64
        if not FULL_OBJECT_ID.fullmatch(pack_hash) or len(pack_hash) != expected_length:
            raise ReviewWorkspaceError(
                "range-pack-index-invalid",
                "exact frozen-range pack index returned a malformed checksum",
            )
        index_metadata = temporary_index.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(index_metadata.st_mode)
            or index_metadata.st_size <= 0
            or index_metadata.st_size > RANGE_PACK_INDEX_BYTES_LIMIT
        ):
            raise ReviewWorkspaceError(
                "range-pack-index-limit",
                "exact frozen-range pack index exceeds its bound",
                details={
                    "observed": index_metadata.st_size,
                    "limit": RANGE_PACK_INDEX_BYTES_LIMIT,
                },
            )
        canonical_pack = pack_directory / f"pack-{pack_hash}.pack"
        canonical_index = pack_directory / f"pack-{pack_hash}.idx"
        if canonical_pack.exists() or canonical_index.exists():
            raise ReviewWorkspaceError(
                "range-pack-collision",
                "exact frozen-range pack destination unexpectedly exists",
            )
        os.replace(temporary_pack, canonical_pack)
        os.replace(temporary_index, canonical_index)
        os.chmod(canonical_pack, 0o400, follow_symlinks=False)
        os.chmod(canonical_index, 0o400, follow_symlinks=False)
        return "exact-pack"
    except BaseException as error:
        operation_error = error
        raise
    finally:
        teardown_failures = _attempt_workspace_descriptor_closes(
            (
                ("exact-pack temporary pack descriptor close failed", pack_descriptor),
                (
                    "exact-pack temporary error descriptor close failed",
                    error_descriptor,
                ),
            )
        )
        if operation_error is not None and _partial_workspace_requires_retention(
            operation_error
        ):
            retain_temporary_output = True
        if not retain_temporary_output:
            for context, temporary in (
                ("exact-pack temporary pack removal failed", temporary_pack),
                ("exact-pack temporary index removal failed", temporary_index),
                ("exact-pack temporary error removal failed", temporary_error),
            ):
                try:
                    temporary.unlink(missing_ok=True)
                except BaseException as unlink_error:
                    teardown_failures.append((context, unlink_error))
        try:
            partial_control.close(retain=retain_temporary_output)
        except BaseException as control_error:
            teardown_failures.append(
                ("partial recovery control finalization failed", control_error)
            )
        if operation_error is not None:
            _attach_workspace_teardown_failures(
                operation_error,
                teardown_failures,
            )
        else:
            teardown_error = _select_workspace_teardown_failure(teardown_failures)
            if teardown_error is not None:
                raise teardown_error


def _initialize_git_directory(
    root: pathlib.Path,
    source: _SourceRepository,
    base: str,
    head: str,
    range_objects: Sequence[str],
    support_objects: Sequence[str],
    shallow_boundaries: Sequence[str],
    object_store_deadline: float,
) -> tuple[str, str, str, str, str, str]:
    git_dir = root / ".git"
    git_dir.mkdir(mode=0o700)
    for relative in (
        "objects",
        "refs/review-workspace",
        "refs/heads",
        "refs/tags",
        "info",
        "logs",
    ):
        (git_dir / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
    for relative in (
        "info",
        "objects",
        "refs",
        "refs/review-workspace",
    ):
        os.chmod(git_dir / relative, 0o700, follow_symlinks=False)
    config = _config_payload(source.object_format)
    _write_bytes(git_dir / "config", config, 0o600)
    _write_bytes(git_dir / "info/attributes", ATTRIBUTES_PAYLOAD, 0o600)
    _write_bytes(git_dir / "HEAD", f"{head}\n".encode("ascii"), 0o600)
    _write_bytes(
        git_dir / "refs/review-workspace/base",
        f"{base}\n".encode("ascii"),
        0o600,
    )
    _write_bytes(
        git_dir / "refs/review-workspace/head",
        f"{head}\n".encode("ascii"),
        0o600,
    )
    shallow = b"".join(f"{oid}\n".encode("ascii") for oid in sorted(shallow_boundaries))
    if shallow:
        _write_bytes(git_dir / "shallow", shallow, 0o600)
    range_manifest = b"".join(f"{oid}\n".encode("ascii") for oid in range_objects)
    _write_bytes(git_dir / RANGE_OBJECT_MANIFEST, range_manifest, 0o600)
    support_manifest = b"".join(f"{oid}\n".encode("ascii") for oid in support_objects)
    _write_bytes(
        git_dir / PARENT_SUPPORT_OBJECT_MANIFEST,
        support_manifest,
        0o600,
    )
    _write_bytes(
        git_dir / SOURCE_SHALLOW_MANIFEST,
        source.shallow_payload,
        0o600,
    )
    strategy = _build_exact_object_store(
        root,
        source,
        tuple(sorted(set(range_objects).union(support_objects))),
        object_store_deadline,
    )
    return (
        strategy,
        hashlib.sha256(config).hexdigest(),
        shallow.decode("ascii"),
        hashlib.sha256(shallow).hexdigest(),
        hashlib.sha256(range_manifest).hexdigest(),
        hashlib.sha256(support_manifest).hexdigest(),
    )


def _filter_checkout_arguments(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
) -> tuple[str, ...]:
    paths = _run_git(
        root,
        ("ls-files", "-z"),
        reason="index-list-failed",
        control_binding=control_binding,
    )
    if not paths:
        return ()
    attributes = _run_git(
        root,
        ("check-attr", "--cached", "--stdin", "-z", "filter"),
        stdin=paths,
        reason="filter-attribute-query-failed",
        control_binding=control_binding,
    ).split(b"\0")
    if attributes and attributes[-1] == b"":
        attributes.pop()
    if len(attributes) % 3:
        raise ReviewWorkspaceError(
            "filter-attribute-output-invalid",
            "Git returned malformed filter attribute output",
        )
    drivers: set[str] = set()
    for index in range(0, len(attributes), 3):
        value = attributes[index + 2]
        if value in {b"unspecified", b"unset", b"set"}:
            continue
        try:
            driver = value.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "filter-driver-invalid",
                "tracked attributes name a non-ASCII filter driver",
            ) from error
        if not FILTER_DRIVER.fullmatch(driver):
            raise ReviewWorkspaceError(
                "filter-driver-invalid",
                "tracked attributes name an unsafe filter driver",
            )
        drivers.add(driver)
    arguments: list[str] = []
    for driver in sorted(drivers):
        arguments.extend(("-c", f"filter.{driver}.process="))
        arguments.extend(("-c", f"filter.{driver}.smudge=cat"))
        arguments.extend(("-c", f"filter.{driver}.required=false"))
    return tuple(arguments)


def _preflight_checkout(
    root: pathlib.Path,
    head: str,
    control_binding: _WorkspaceControlBinding,
) -> None:
    payload = _run_git(
        root,
        ("ls-tree", "-r", "-z", "--long", head),
        reason="checkout-tree-preflight-failed",
        output_limit_bytes=CHECKOUT_TREE_OUTPUT_LIMIT,
        control_binding=control_binding,
    )
    if payload and not payload.endswith(b"\0"):
        raise ReviewWorkspaceError(
            "checkout-tree-output-invalid",
            "Git returned an unterminated checkout-tree inventory",
        )
    entry_count = 0
    logical_bytes = 0
    path_bytes = 0
    for record in payload[:-1].split(b"\0") if payload else ():
        if not record or b"\t" not in record:
            raise ReviewWorkspaceError(
                "checkout-tree-output-invalid",
                "Git returned a malformed checkout-tree inventory",
            )
        header, raw_path = record.split(b"\t", 1)
        fields = header.split()
        if len(fields) != 4 or not raw_path:
            raise ReviewWorkspaceError(
                "checkout-tree-output-invalid",
                "Git returned a malformed checkout-tree entry",
            )
        mode, object_type, oid, raw_size = fields
        if (
            mode not in {b"100644", b"100755", b"120000", b"160000"}
            or object_type not in {b"blob", b"commit"}
            or not FULL_OBJECT_ID.fullmatch(oid.decode("ascii", "strict"))
        ):
            raise ReviewWorkspaceError(
                "checkout-tree-output-invalid",
                "Git returned an unsupported checkout-tree entry",
            )
        entry_count += 1
        path_bytes += len(raw_path)
        if object_type == b"blob":
            try:
                size = int(raw_size)
            except ValueError as error:
                raise ReviewWorkspaceError(
                    "checkout-tree-output-invalid",
                    "Git returned an invalid checkout blob size",
                ) from error
            if size < 0:
                raise ReviewWorkspaceError(
                    "checkout-tree-output-invalid",
                    "Git returned a negative checkout blob size",
                )
            logical_bytes += size
        elif raw_size != b"-" or mode != b"160000":
            raise ReviewWorkspaceError(
                "checkout-tree-output-invalid",
                "Git returned an invalid gitlink checkout entry",
            )
        for observed, limit, reason, metric in (
            (
                entry_count,
                CHECKOUT_ENTRY_COUNT_LIMIT,
                "checkout-entry-limit",
                "checkout entry occurrences",
            ),
            (
                logical_bytes,
                CHECKOUT_LOGICAL_BYTES_LIMIT,
                "checkout-logical-byte-limit",
                "checkout blob-occurrence bytes",
            ),
            (
                path_bytes,
                CHECKOUT_PATH_BYTES_LIMIT,
                "checkout-path-byte-limit",
                "checkout raw path bytes",
            ),
        ):
            if observed > limit:
                raise ReviewWorkspaceError(
                    reason,
                    f"head tree exceeds its {metric} safety limit",
                    details={"metric": metric, "observed": observed, "limit": limit},
                )
    _check_copy_capacity(
        root,
        logical_bytes,
        metric="head checkout expansion",
        reason="checkout-capacity-insufficient",
    )


def _checkout_head(root: pathlib.Path, head: str) -> None:
    static_binding = _bind_workspace_controls(
        root,
        include_index=False,
        include_marker=False,
    )
    _preflight_checkout(root, head, static_binding)
    _run_git(
        root,
        ("read-tree", head),
        reason="index-initialization-failed",
        control_binding=static_binding,
        partial_recovery_operation="read-tree",
    )
    index = root / ".git/index"
    descriptor = os.open(index, _nofollow_flags(directory=False))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
        ):
            raise ReviewWorkspaceError(
                "workspace-index-policy",
                "Git index must be an owner-held single-link regular file",
            )
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    control_binding = _bind_workspace_controls(
        root,
        include_index=True,
        include_marker=False,
    )
    filter_arguments = _filter_checkout_arguments(root, control_binding)
    _run_git(
        root,
        (*filter_arguments, "checkout-index", "--all", "--force"),
        reason="checkout-failed",
        control_binding=control_binding,
        partial_recovery_operation="checkout-index",
    )
    _restore_checkout_transformations(root, control_binding)


def _restore_checkout_transformations(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
) -> None:
    status = _run_git(
        root,
        (
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=no",
            "--ignore-submodules=all",
        ),
        reason="checkout-status-failed",
        control_binding=control_binding,
    )
    if status:
        raise ReviewWorkspaceError(
            "checkout-transformation-unsupported",
            (
                "checkout did not reproduce the indexed bytes exactly; private "
                "attributes disable supported transformations and the workspace "
                "will not rewrite a post-checkout file"
            ),
            details={
                "status_preview": status[:8_192].decode("utf-8", "backslashreplace")
            },
        )


def _parse_marker_payload(raw: bytes) -> dict[str, object]:
    if len(raw) > MARKER_LIMIT_BYTES:
        raise ReviewWorkspaceError(
            "workspace-marker-invalid",
            "workspace identity marker exceeds its bound",
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace identity marker is malformed"
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != WORKSPACE_SCHEMA_VERSION
    ):
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace identity marker schema is invalid"
        )
    return payload


def _cleanup_token_digest(cleanup_token: str) -> str:
    if not isinstance(cleanup_token, str) or not cleanup_token:
        raise ReviewWorkspaceError(
            "cleanup-token-invalid",
            "cleanup token must be a nonempty string from the preparation receipt",
        )
    return hashlib.sha256(cleanup_token.encode("utf-8")).hexdigest()


def _marker_cleanup_token_digest(payload: Mapping[str, object]) -> str:
    cleanup_token_sha256 = payload.get("cleanup_token_sha256")
    if (
        "cleanup_token" in payload
        or not isinstance(cleanup_token_sha256, str)
        or CLEANUP_TOKEN_SHA256.fullmatch(cleanup_token_sha256) is None
    ):
        raise ReviewWorkspaceError(
            "workspace-marker-invalid",
            "workspace cleanup-token verifier is malformed",
        )
    return cleanup_token_sha256


def _marker_identity(payload: Mapping[str, object], key: str) -> tuple[int, int, int]:
    identity = payload.get(key)
    if not isinstance(identity, dict):
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace identity binding is missing"
        )
    device = identity.get("device")
    inode = identity.get("inode")
    uid = identity.get("uid")
    if (
        not isinstance(device, int)
        or not isinstance(inode, int)
        or not isinstance(uid, int)
    ):
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace identity binding is malformed"
        )
    return device, inode, uid


def _directory_identity(path: pathlib.Path) -> tuple[int, int, int]:
    try:
        descriptor = os.open(path, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-identity-unavailable",
            "bound directory cannot be opened without following links",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        observed = path.stat(follow_symlinks=False)
        _validate_no_extended_acl(descriptor, str(path))
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-identity-unavailable",
            "bound directory identity cannot be revalidated",
        ) from error
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid)
        != (observed.st_dev, observed.st_ino, observed.st_uid)
    ):
        raise ReviewWorkspaceError(
            "workspace-identity-mismatch", "bound path is not a directory"
        )
    return metadata.st_dev, metadata.st_ino, metadata.st_uid


def _private_directory_identity(
    path: pathlib.Path,
    label: str,
    *,
    reason: str,
) -> tuple[int, int, int]:
    try:
        descriptor = os.open(path, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            reason,
            f"{label} cannot be opened without following links",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        observed = path.stat(follow_symlinks=False)
        _validate_no_extended_acl(descriptor, label)
    except OSError as error:
        raise ReviewWorkspaceError(
            reason,
            f"{label} identity and access policy cannot be revalidated",
        ) from error
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_dev != metadata.st_dev
        or observed.st_ino != metadata.st_ino
        or observed.st_uid != metadata.st_uid
        or stat.S_IMODE(observed.st_mode) != stat.S_IMODE(metadata.st_mode)
    ):
        raise ReviewWorkspaceError(
            reason,
            f"{label} must remain one owner-private mode-0700 directory object",
        )
    return metadata.st_dev, metadata.st_ino, metadata.st_uid


def _begin_forwarded_signal_mask() -> ForwardedSignalMaskOwner:
    owner = ForwardedSignalMaskOwner()
    block_forwarded_signals(signal_mask_owner=owner)
    return owner


def _finish_forwarded_signal_mask(
    owner: ForwardedSignalMaskOwner,
    *,
    primary_error: BaseException | None,
) -> None:
    pending: signal.Signals | None = None
    pending_error: BaseException | None = None
    if owner.active:
        try:
            pending = consume_pending_forwarded_signal()
        except BaseException as error:
            pending_error = error
    restore_errors: list[BaseException] = []
    for _attempt in range(2):
        if not owner.active:
            break
        try:
            owner.restore()
        except BaseException as error:
            restore_errors.append(error)
    direct_fallback_error: BaseException | None = None
    direct_fallback_succeeded = False
    if owner.active:
        try:
            if owner.previous_mask is None or not hasattr(signal, "pthread_sigmask"):
                raise ReviewWorkspaceError(
                    "workspace-signal-mask-state-invalid",
                    "the exact previous signal mask is unavailable",
                )
            signal.pthread_sigmask(signal.SIG_SETMASK, owner.previous_mask)
            owner.active = False
            direct_fallback_succeeded = True
        except BaseException as error:
            direct_fallback_error = error
    if owner.active:
        details: dict[str, object] = {}
        status = "blocked-safety"
        if isinstance(primary_error, ReviewWorkspaceError):
            details.update(primary_error.details)
            status = primary_error.status
            details["operation_status"] = primary_error.status
            details["operation_reason"] = primary_error.reason
        elif primary_error is not None:
            details["operation_failure_type"] = type(primary_error).__name__
        details.update(
            {
                "restore_attempts": len(restore_errors),
                "restore_failure_types": [
                    type(error).__name__ for error in restore_errors
                ],
                "direct_exact_mask_fallback": (
                    "succeeded" if direct_fallback_succeeded else "failed"
                ),
                "signal_mask_owner_active": owner.active,
            }
        )
        if direct_fallback_error is not None:
            details["direct_fallback_failure_type"] = type(
                direct_fallback_error
            ).__name__
        if pending is not None:
            details["deferred_signal"] = int(pending)
        failure = ReviewWorkspaceError(
            "workspace-signal-mask-restore-failed",
            "workspace operation could not restore its forwarded-signal mask",
            status=status,
            details=details,
        )
        selected_cause = direct_fallback_error or (
            restore_errors[-1] if restore_errors else primary_error
        )
        _bind_workspace_failure_cause(
            failure,
            selected_cause,
            context="signal-mask restoration had another causal predecessor",
        )
        if primary_error is not None:
            if process_quiescence_unproven(primary_error):
                mark_process_quiescence_unproven(failure)
            if _partial_workspace_requires_retention(primary_error):
                _mark_partial_workspace_for_retention(failure)
            recovery_payload = _partial_workspace_recovery_payload(primary_error)
            if recovery_payload is not None:
                _record_partial_workspace_recovery(failure, recovery_payload)
        if pending_error is not None:
            _attach_workspace_diagnostic_preserving_cause(
                failure,
                f"pending-signal drain also failed: {pending_error}",
            )
        raise failure
    if primary_error is not None:
        if pending is not None:
            _attach_workspace_diagnostic_preserving_cause(
                primary_error,
                f"forwarded signal {int(pending)} was deferred behind the primary failure",
            )
        for error in restore_errors:
            _attach_workspace_diagnostic_preserving_cause(
                primary_error,
                f"signal-mask restoration also failed: {error}",
            )
        if pending_error is not None:
            _attach_workspace_diagnostic_preserving_cause(
                primary_error,
                f"pending-signal drain also failed: {pending_error}",
            )
        return
    process_control_error = next(
        (
            error
            for error in (pending_error, *restore_errors)
            if error is not None and _is_process_control_flow_error(error)
        ),
        None,
    )
    if process_control_error is not None:
        raise process_control_error
    if pending_error is not None:
        raise pending_error
    if pending is not None:
        raise ForwardedSignal(pending)


def _validate_parent_identity(
    root: pathlib.Path, marker: Mapping[str, object]
) -> tuple[int, int, int]:
    if marker.get("worktree") != str(root):
        raise ReviewWorkspaceError(
            "workspace-path-mismatch", "workspace path differs from its identity marker"
        )
    observed = _private_directory_identity(
        root.parent,
        "workspace parent",
        reason="workspace-parent-policy",
    )
    if observed != _marker_identity(marker, "parent_identity"):
        raise ReviewWorkspaceError(
            "workspace-parent-identity-mismatch",
            "workspace parent identity changed",
        )
    return observed


def _validate_root_identity(
    root: pathlib.Path, marker: Mapping[str, object]
) -> tuple[int, int, int]:
    observed = _directory_identity(root)
    if observed != _marker_identity(marker, "workspace_identity"):
        raise ReviewWorkspaceError(
            "workspace-identity-mismatch", "workspace root identity changed"
        )
    return observed


def _validate_storage_identities(
    root: pathlib.Path,
    marker: Mapping[str, object],
) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    identities: list[tuple[int, int, int]] = []
    for key, path in (
        ("git_identity", root / ".git"),
        ("objects_identity", root / ".git/objects"),
    ):
        observed = _directory_identity(path)
        if observed != _marker_identity(marker, key):
            raise ReviewWorkspaceError(
                "workspace-storage-identity-mismatch",
                f"workspace {key.removesuffix('_identity')} identity changed",
            )
        identities.append(observed)
    return identities[0], identities[1]


def _remaining_symlink_validation_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReviewWorkspaceError(
            "symlink-validation-deadline",
            "tracked symlink validation exceeded its shared monotonic deadline",
            details={"limit_seconds": GIT_TIMEOUT_SECONDS},
        )
    return remaining


def _tracked_path_components(raw_path: bytes) -> tuple[bytes, ...]:
    components = tuple(raw_path.split(b"/"))
    if (
        not raw_path
        or raw_path.startswith(b"/")
        or any(component in {b"", b".", b".."} for component in components)
    ):
        raise ReviewWorkspaceError(
            "index-output-invalid",
            "Git returned a non-canonical tracked symlink path",
        )
    return components


def _apply_lexical_symlink_target(
    parent: Sequence[bytes],
    target: bytes,
    *,
    raw_path: bytes,
) -> tuple[bytes, ...]:
    if target.startswith(b"/"):
        raise ReviewWorkspaceError(
            "symlink-escape",
            f"tracked symlink {os.fsdecode(raw_path)!r} is absolute",
        )
    resolved = list(parent)
    for component in target.split(b"/"):
        if component in {b"", b"."}:
            continue
        if component == b"..":
            if not resolved:
                raise ReviewWorkspaceError(
                    "symlink-escape",
                    f"tracked symlink {os.fsdecode(raw_path)!r} escapes workspace",
                )
            resolved.pop()
            continue
        resolved.append(component)
    return tuple(resolved)


def _read_tracked_symlink(
    root_descriptor: int,
    raw_path: bytes,
    *,
    deadline: float,
) -> tuple[os.stat_result, bytes]:
    components = _tracked_path_components(raw_path)
    descriptor = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            _remaining_symlink_validation_seconds(deadline)
            child = os.open(
                component,
                _nofollow_flags(directory=True),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        _remaining_symlink_validation_seconds(deadline)
        metadata = os.stat(
            components[-1],
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        target = os.readlink(components[-1], dir_fd=descriptor)
        return metadata, os.fsencode(target)
    finally:
        os.close(descriptor)


def _open_tracked_directory_stack(
    root_descriptor: int,
    components: Sequence[bytes],
    *,
    deadline: float,
) -> list[int]:
    descriptors = [os.dup(root_descriptor)]
    try:
        for component in components:
            _remaining_symlink_validation_seconds(deadline)
            child = os.open(
                component,
                _nofollow_flags(directory=True),
                dir_fd=descriptors[-1],
            )
            descriptors.append(child)
        return descriptors
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _validate_tracked_symlink_chain(
    root_descriptor: int,
    raw_path: bytes,
    target: bytes,
    target_by_identity: Mapping[tuple[int, int], tuple[bytes, bytes]],
    *,
    deadline: float,
) -> None:
    link_components = _tracked_path_components(raw_path)
    try:
        directory_stack = _open_tracked_directory_stack(
            root_descriptor,
            link_components[:-1],
            deadline=deadline,
        )
    except OSError as error:
        raise ReviewWorkspaceError(
            "symlink-validation-failed",
            "tracked symlink parent cannot be opened without following links",
        ) from error
    pending = list(reversed(target.split(b"/")))
    expansions = 0
    component_steps = 0
    try:
        while pending:
            if component_steps % 256 == 0:
                _remaining_symlink_validation_seconds(deadline)
            component_steps += 1
            if component_steps > SYMLINK_RESOLUTION_COMPONENT_LIMIT:
                raise ReviewWorkspaceError(
                    "symlink-resolution-limit",
                    "tracked symlink chain exceeds its component-resolution limit",
                    details={"limit": SYMLINK_RESOLUTION_COMPONENT_LIMIT},
                )
            component = pending.pop()
            if component in {b"", b"."}:
                continue
            if component == b"..":
                if len(directory_stack) == 1:
                    raise ReviewWorkspaceError(
                        "symlink-escape",
                        f"tracked symlink {os.fsdecode(raw_path)!r} escapes workspace",
                    )
                os.close(directory_stack.pop())
                continue

            try:
                metadata = os.stat(
                    component,
                    dir_fd=directory_stack[-1],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                # A missing component makes the link dangling.  The prior pure
                # lexical check already proved that this unresolved spelling is
                # contained, and no target path has been followed.
                return
            except OSError as error:
                raise ReviewWorkspaceError(
                    "symlink-validation-failed",
                    "tracked symlink target component cannot be inspected safely",
                ) from error

            if stat.S_ISLNK(metadata.st_mode):
                identity = (metadata.st_dev, metadata.st_ino)
                binding = target_by_identity.get(identity)
                if binding is None:
                    raise ReviewWorkspaceError(
                        "symlink-resolution-unbound",
                        (
                            "tracked symlink target reached a filesystem symlink "
                            "that is not bound to the staged Git symlink map"
                        ),
                    )
                _bound_path, nested_target = binding
                try:
                    observed_target = os.fsencode(
                        os.readlink(component, dir_fd=directory_stack[-1])
                    )
                    repeated_metadata = os.stat(
                        component,
                        dir_fd=directory_stack[-1],
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise ReviewWorkspaceError(
                        "symlink-validation-failed",
                        "tracked symlink alias cannot be revalidated safely",
                    ) from error
                if (
                    not stat.S_ISLNK(repeated_metadata.st_mode)
                    or not os.path.samestat(metadata, repeated_metadata)
                    or observed_target != nested_target
                ):
                    raise ReviewWorkspaceError(
                        "symlink-content-drift",
                        "tracked symlink alias changed during chain validation",
                    )
                expansions += 1
                if expansions > SYMLINK_COUNT_LIMIT:
                    raise ReviewWorkspaceError(
                        "symlink-resolution-limit",
                        "tracked symlink chain is cyclic or exceeds its expansion limit",
                        details={"limit": SYMLINK_COUNT_LIMIT},
                    )
                nested_components = nested_target.split(b"/")
                if (
                    len(pending) + len(nested_components)
                    > SYMLINK_RESOLUTION_COMPONENT_LIMIT
                ):
                    raise ReviewWorkspaceError(
                        "symlink-resolution-limit",
                        "tracked symlink chain exceeds its pending-component limit",
                        details={"limit": SYMLINK_RESOLUTION_COMPONENT_LIMIT},
                    )
                pending.extend(reversed(nested_components))
                continue

            if not pending or not stat.S_ISDIR(metadata.st_mode):
                # A non-directory with unresolved suffix is an ordinary dangling
                # path, while a terminal entry is already contained in this dirfd.
                return
            child = -1
            try:
                child = os.open(
                    component,
                    _nofollow_flags(directory=True),
                    dir_fd=directory_stack[-1],
                )
                child_metadata = os.fstat(child)
            except OSError as error:
                if child >= 0:
                    os.close(child)
                raise ReviewWorkspaceError(
                    "symlink-validation-failed",
                    "tracked symlink target directory cannot be opened safely",
                ) from error
            if not os.path.samestat(metadata, child_metadata):
                os.close(child)
                raise ReviewWorkspaceError(
                    "symlink-content-drift",
                    "tracked symlink target directory changed during validation",
                )
            directory_stack.append(child)
    finally:
        for descriptor in reversed(directory_stack):
            os.close(descriptor)


def _run_symlink_git(
    root: pathlib.Path,
    arguments: tuple[str, ...],
    *,
    deadline: float,
    output_limit_bytes: int,
    reason: str,
    output_limit_reason: str,
    control_binding: _WorkspaceControlBinding,
    stdin: bytes | None = None,
) -> bytes:
    try:
        return _run_git(
            root,
            arguments,
            stdin=stdin,
            reason=reason,
            output_limit_bytes=output_limit_bytes,
            timeout_seconds=_remaining_symlink_validation_seconds(deadline),
            control_binding=control_binding,
        )
    except ReviewTimeoutError as error:
        raise ReviewWorkspaceError(
            "symlink-validation-deadline",
            "tracked symlink validation exceeded its shared monotonic deadline",
            details={"limit_seconds": GIT_TIMEOUT_SECONDS},
        ) from error
    except ReviewOutputLimitError as error:
        raise ReviewWorkspaceError(
            output_limit_reason,
            "tracked symlink validation exceeded its bounded Git output allowance",
            details={"limit_bytes": output_limit_bytes},
        ) from error


def _parse_staged_index_for_symlinks(
    payload: bytes,
) -> tuple[tuple[tuple[bytes, bytes], ...], tuple[tuple[bytes, bytes], ...]]:
    if not payload:
        return (), ()
    if not payload.endswith(b"\0"):
        raise ReviewWorkspaceError(
            "index-output-invalid",
            "Git staged-index output is not NUL terminated",
        )
    records = payload[:-1].split(b"\0")
    if any(not record for record in records):
        raise ReviewWorkspaceError(
            "index-output-invalid",
            "Git staged-index output contains an empty record",
        )
    gitlinks: list[tuple[bytes, bytes]] = []
    symlinks: list[tuple[bytes, bytes]] = []
    for record in records:
        header, separator, raw_path = record.partition(b"\t")
        fields = header.split(b" ")
        if (
            separator != b"\t"
            or not raw_path
            or len(fields) != 3
            or any(not field for field in fields)
        ):
            raise ReviewWorkspaceError(
                "index-output-invalid", "Git returned malformed staged index output"
            )
        mode, oid, stage = fields
        if stage != b"0":
            raise ReviewWorkspaceError(
                "index-stage-invalid", "workspace index contains an unmerged entry"
            )
        if mode not in {b"120000", b"160000"}:
            continue
        try:
            oid_text = oid.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "index-output-invalid",
                "Git staged-index link object ID is not ASCII",
            ) from error
        if not FULL_OBJECT_ID.fullmatch(oid_text):
            raise ReviewWorkspaceError(
                "index-output-invalid",
                "Git staged-index link object ID is malformed",
            )
        if mode == b"160000":
            gitlinks.append((raw_path, oid))
            continue
        symlinks.append((raw_path, oid))
        if len(symlinks) > SYMLINK_COUNT_LIMIT:
            raise ReviewWorkspaceError(
                "symlink-count-limit",
                "tracked symlink count exceeds the validation limit",
                details={
                    "observed": len(symlinks),
                    "limit": SYMLINK_COUNT_LIMIT,
                },
            )
    return tuple(gitlinks), tuple(symlinks)


def _parse_symlink_batch(
    payload: bytes,
    expected_oids: Sequence[bytes],
) -> tuple[bytes, ...]:
    targets: list[bytes] = []
    aggregate_size = 0
    cursor = 0
    for expected_oid in expected_oids:
        header_end = payload.find(
            b"\n",
            cursor,
            min(len(payload), cursor + SYMLINK_BATCH_HEADER_LIMIT_BYTES + 1),
        )
        if header_end < 0:
            raise ReviewWorkspaceError(
                "symlink-batch-output-invalid",
                "Git symlink batch output contains a missing or oversized header",
            )
        fields = payload[cursor:header_end].split(b" ")
        if fields == [expected_oid, b"missing"]:
            raise ReviewWorkspaceError(
                "symlink-blob-unavailable",
                "tracked symlink blob is not locally available",
            )
        if len(fields) != 3 or any(not field for field in fields):
            raise ReviewWorkspaceError(
                "symlink-batch-output-invalid",
                "Git symlink batch output contains a malformed header",
            )
        object_id, object_type, raw_size = fields
        if (
            object_id != expected_oid
            or object_type != b"blob"
            or not raw_size.isdigit()
            or (len(raw_size) > 1 and raw_size.startswith(b"0"))
        ):
            raise ReviewWorkspaceError(
                "symlink-batch-output-invalid",
                "Git symlink batch output does not match the requested blob",
            )
        size = int(raw_size)
        if size > SYMLINK_TARGET_LIMIT_BYTES:
            raise ReviewWorkspaceError(
                "symlink-target-limit",
                "tracked symlink target exceeds the per-target byte limit",
                details={
                    "observed": size,
                    "limit": SYMLINK_TARGET_LIMIT_BYTES,
                },
            )
        aggregate_size += size
        if aggregate_size > SYMLINK_TARGET_AGGREGATE_LIMIT_BYTES:
            raise ReviewWorkspaceError(
                "symlink-target-aggregate-limit",
                "tracked symlink targets exceed the aggregate byte limit",
                details={
                    "observed": aggregate_size,
                    "limit": SYMLINK_TARGET_AGGREGATE_LIMIT_BYTES,
                },
            )
        target_start = header_end + 1
        target_end = target_start + size
        if target_end >= len(payload) or payload[target_end : target_end + 1] != b"\n":
            raise ReviewWorkspaceError(
                "symlink-batch-output-invalid",
                "Git symlink batch output contains a malformed blob payload",
            )
        target = payload[target_start:target_end]
        if b"\0" in target:
            raise ReviewWorkspaceError(
                "symlink-target-invalid", "tracked symlink contains a NUL byte"
            )
        targets.append(target)
        cursor = target_end + 1
    if cursor != len(payload):
        raise ReviewWorkspaceError(
            "symlink-batch-output-invalid",
            "Git symlink batch output contains trailing data",
        )
    return tuple(targets)


def _validate_gitlink_placeholders(
    root: pathlib.Path,
    entries: Sequence[tuple[bytes, bytes]],
    deadline: float,
) -> frozenset[bytes]:
    absent: set[bytes] = set()
    for raw_path, _expected_oid in entries:
        _remaining_symlink_validation_seconds(deadline)
        gitlink = root / pathlib.Path(os.fsdecode(raw_path))
        try:
            metadata = gitlink.stat(follow_symlinks=False)
        except FileNotFoundError:
            absent.add(raw_path)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReviewWorkspaceError(
                "gitlink-materialized",
                "review workspace must not materialize submodule content",
            )
        try:
            with os.scandir(gitlink) as entries:
                if next(entries, None) is not None:
                    raise ReviewWorkspaceError(
                        "gitlink-materialized",
                        "review workspace contains initialized submodule content",
                    )
        except OSError as error:
            raise ReviewWorkspaceError(
                "gitlink-materialized",
                "review workspace submodule placeholder cannot be inspected",
            ) from error
    return frozenset(absent)


@dataclass(frozen=True)
class _ValidatedLinks:
    gitlinks: tuple[tuple[bytes, bytes], ...]
    absent_gitlinks: frozenset[bytes]
    symlink_count: int


def _validate_links(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
) -> _ValidatedLinks:
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    index = _run_symlink_git(
        root,
        ("ls-files", "--stage", "-z"),
        deadline=deadline,
        output_limit_bytes=CHECKOUT_TREE_OUTPUT_LIMIT,
        reason="index-inspection-failed",
        output_limit_reason="index-output-limit",
        control_binding=control_binding,
    )
    gitlinks, symlinks = _parse_staged_index_for_symlinks(index)
    if not symlinks:
        absent_gitlinks = _validate_gitlink_placeholders(root, gitlinks, deadline)
        return _ValidatedLinks(
            gitlinks=gitlinks,
            absent_gitlinks=absent_gitlinks,
            symlink_count=0,
        )
    batch = _run_symlink_git(
        root,
        ("cat-file", "--batch"),
        stdin=b"".join(oid + b"\n" for _raw_path, oid in symlinks),
        deadline=deadline,
        output_limit_bytes=SYMLINK_BATCH_OUTPUT_LIMIT_BYTES,
        reason="symlink-blob-unavailable",
        output_limit_reason="symlink-target-aggregate-limit",
        control_binding=control_binding,
    )
    targets = _parse_symlink_batch(batch, tuple(oid for _path, oid in symlinks))
    target_by_path: dict[tuple[bytes, ...], bytes] = {}
    # Reject every overt lexical escape before opening any checkout path.  A
    # hostile target therefore cannot select host metadata for validation.
    for (raw_path, _oid), target in zip(symlinks, targets, strict=True):
        _remaining_symlink_validation_seconds(deadline)
        path_components = _tracked_path_components(raw_path)
        _apply_lexical_symlink_target(
            path_components[:-1],
            target,
            raw_path=raw_path,
        )
        if path_components in target_by_path:
            raise ReviewWorkspaceError(
                "index-output-invalid",
                "Git returned duplicate tracked symlink paths",
            )
        target_by_path[path_components] = target

    target_by_identity: dict[tuple[int, int], tuple[bytes, bytes]] = {}
    # Bind each actual link through root-relative no-follow directory handles.
    # Object replacement is mutation evidence; timestamp-only changes are not.
    try:
        root_descriptor = os.open(root, _nofollow_flags(directory=True))
    except OSError as error:
        raise ReviewWorkspaceError(
            "symlink-validation-failed",
            "workspace root cannot be opened safely for symlink validation",
        ) from error
    try:
        for (raw_path, _oid), target in zip(symlinks, targets, strict=True):
            _remaining_symlink_validation_seconds(deadline)
            try:
                first_metadata, first_target = _read_tracked_symlink(
                    root_descriptor,
                    raw_path,
                    deadline=deadline,
                )
                second_metadata, second_target = _read_tracked_symlink(
                    root_descriptor,
                    raw_path,
                    deadline=deadline,
                )
            except (OSError, RuntimeError) as error:
                raise ReviewWorkspaceError(
                    "symlink-validation-failed",
                    "tracked symlink cannot be validated without following ancestors",
                ) from error
            if not stat.S_ISLNK(first_metadata.st_mode) or not stat.S_ISLNK(
                second_metadata.st_mode
            ):
                raise ReviewWorkspaceError(
                    "symlink-content-mismatch",
                    "tracked symlink differs from its Git blob",
                )
            if first_target != second_target or not os.path.samestat(
                first_metadata, second_metadata
            ):
                raise ReviewWorkspaceError(
                    "symlink-content-drift",
                    "tracked symlink changed during validation",
                )
            if first_target != target:
                raise ReviewWorkspaceError(
                    "symlink-content-mismatch",
                    "tracked symlink differs from its Git blob",
                )
            identity = (first_metadata.st_dev, first_metadata.st_ino)
            if identity in target_by_identity:
                raise ReviewWorkspaceError(
                    "symlink-content-drift",
                    "distinct tracked symlink paths unexpectedly share one object",
                )
            target_by_identity[identity] = (raw_path, target)

        # Actual links now match their Git blobs.  Resolve each component through
        # the root dirfd, and identify aliases by bound inode instead of guessing
        # APFS case-folding or Unicode-normalization rules in Python.  A
        # case-sensitive volume simply reports a differently spelled entry absent.
        for (raw_path, _oid), target in zip(symlinks, targets, strict=True):
            _validate_tracked_symlink_chain(
                root_descriptor,
                raw_path,
                target,
                target_by_identity,
                deadline=deadline,
            )
            _remaining_symlink_validation_seconds(deadline)
    finally:
        os.close(root_descriptor)
    absent_gitlinks = _validate_gitlink_placeholders(root, gitlinks, deadline)
    return _ValidatedLinks(
        gitlinks=gitlinks,
        absent_gitlinks=absent_gitlinks,
        symlink_count=len(symlinks),
    )


def _validate_symlinks(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
) -> int:
    """Retain the standalone symlink-validation API used by focused probes."""

    return _validate_links(root, control_binding).symlink_count


def _validate_no_object_dependencies(root: pathlib.Path) -> None:
    objects = root / ".git/objects"
    forbidden = (
        objects / "info/alternates",
        objects / "info/http-alternates",
    )
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise ReviewWorkspaceError(
            "workspace-object-dependency",
            "workspace object store contains an alternate dependency",
        )
    root_metadata = objects.stat(follow_symlinks=False)
    pack_files: set[str] = set()
    index_files: set[str] = set()
    allowed_directories = {pathlib.PurePath("."), pathlib.PurePath("pack")}
    for directory, directory_names, file_names in os.walk(
        objects,
        topdown=True,
        followlinks=False,
        onerror=lambda error: (_ for _ in ()).throw(error),
    ):
        current = pathlib.Path(directory)
        relative_directory = current.relative_to(objects)
        if relative_directory not in allowed_directories:
            raise ReviewWorkspaceError(
                "workspace-object-layout",
                "workspace normalized object store contains an unexpected directory",
                details={"entry": str(relative_directory)},
            )
        for name in (*directory_names, *file_names):
            path = current / name
            metadata = path.stat(follow_symlinks=False)
            if metadata.st_dev != root_metadata.st_dev:
                raise ReviewWorkspaceError(
                    "workspace-object-mount-boundary",
                    "workspace object store crosses a filesystem boundary",
                )
            if stat.S_ISLNK(metadata.st_mode):
                raise ReviewWorkspaceError(
                    "workspace-object-dependency",
                    "workspace object store contains a symlink",
                )
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
                    raise ReviewWorkspaceError(
                        "workspace-object-hardlink",
                        "workspace object store contains a hard-linked file",
                    )
                if name.endswith(".promisor"):
                    raise ReviewWorkspaceError(
                        "workspace-promisor-state",
                        "workspace object store contains promisor state",
                    )
                relative = relative_directory / name
                match = re.fullmatch(
                    r"pack/pack-([0-9a-f]{40}|[0-9a-f]{64})\.(pack|idx)",
                    relative.as_posix(),
                )
                if match is None:
                    raise ReviewWorkspaceError(
                        "workspace-object-layout",
                        "workspace normalized object store contains an unexpected file",
                        details={"entry": relative.as_posix()},
                    )
                if match.group(2) == "pack":
                    pack_files.add(match.group(1))
                else:
                    index_files.add(match.group(1))
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ReviewWorkspaceError(
                    "workspace-object-layout",
                    "workspace normalized object store contains a special file",
                )
    if len(pack_files) != 1 or pack_files != index_files:
        raise ReviewWorkspaceError(
            "workspace-object-layout",
            "workspace normalized object store must contain one matching pack/index pair",
            details={
                "pack_count": len(pack_files),
                "index_count": len(index_files),
            },
        )


def _validate_layout(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
) -> None:
    git_dir = root / ".git"
    metadata = git_dir.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReviewWorkspaceError(
            "workspace-gitdir-invalid", "workspace .git must be a real directory"
        )
    absolute_git_dir = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--absolute-git-dir"),
            control_binding=control_binding,
        ),
        "workspace Git directory",
    )
    common_dir = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--path-format=absolute", "--git-common-dir"),
            control_binding=control_binding,
        ),
        "workspace common Git directory",
    )
    objects = _decode_git_path(
        _run_git(
            root,
            ("rev-parse", "--path-format=absolute", "--git-path", "objects"),
            control_binding=control_binding,
        ),
        "workspace object directory",
    )
    if (
        absolute_git_dir != git_dir
        or common_dir != git_dir
        or objects != git_dir / "objects"
    ):
        raise ReviewWorkspaceError(
            "workspace-not-independent",
            "workspace shares or redirects Git administrative/object state",
        )
    try:
        attributes_bytes = control_binding.payload((".git", "info", "attributes"))
    except ReviewWorkspaceError as error:
        raise ReviewWorkspaceError(
            "workspace-attributes-missing",
            "workspace private attributes override is not readable",
        ) from error
    if attributes_bytes != ATTRIBUTES_PAYLOAD:
        raise ReviewWorkspaceError(
            "workspace-attributes-drift",
            "workspace private attributes override changed",
        )
    modules = git_dir / "modules"
    if modules.exists() or modules.is_symlink():
        raise ReviewWorkspaceError(
            "workspace-submodule-state",
            "workspace must not contain initialized submodule administration",
        )
    if _run_git(root, ("remote",), control_binding=control_binding).strip():
        raise ReviewWorkspaceError(
            "workspace-remote-present", "workspace must not retain a Git remote"
        )
    promisor = _run_git(
        root,
        (
            "config",
            "--local",
            "--get-regexp",
            r"^(extensions\.partialClone|remote\..*\.promisor)$",
        ),
        allowed_returncodes=(0, 1),
        control_binding=control_binding,
    )
    if promisor.strip():
        raise ReviewWorkspaceError(
            "workspace-promisor-state", "workspace contains promisor configuration"
        )
    control_binding.revalidate()
    _validate_no_object_dependencies(root)
    control_binding.revalidate()


def _derive_destination_range_objects(
    root: pathlib.Path,
    base: str,
    head: str,
    source_shallow: bool,
    control_binding: _WorkspaceControlBinding,
    expected_range_commits: Sequence[str],
) -> tuple[str, ...]:
    source_shallow_payload = control_binding.payload((".git", SOURCE_SHALLOW_MANIFEST))
    if bool(source_shallow_payload) != source_shallow:
        raise ReviewWorkspaceError(
            "workspace-source-shallow-drift",
            "workspace source-shallow evidence disagrees with its marker",
        )
    object_format = "sha1" if len(base) == 40 else "sha256"
    try:
        _parse_source_shallow_boundaries(
            source_shallow_payload,
            object_format,
            shallow=source_shallow,
        )
    except ReviewWorkspaceError as error:
        raise ReviewWorkspaceError(
            "workspace-source-shallow-invalid",
            "workspace source-shallow evidence is malformed",
        ) from error
    visible = _run_git(
        root,
        ("rev-list", "--parents", "--full-history", f"{base}..{head}"),
        reason="workspace-visible-range-check-failed",
        output_limit_bytes=(
            (RANGE_COMMIT_COUNT_LIMIT + RANGE_PARENT_EDGE_COUNT_LIMIT) * (len(base) + 1)
            + 1024
        ),
        control_binding=control_binding,
    )

    def parse_parent_rows(
        payload: bytes,
        *,
        reason: str,
    ) -> dict[str, tuple[str, ...]]:
        rows: dict[str, tuple[str, ...]] = {}
        for raw_row in payload.splitlines():
            fields = raw_row.split()
            if not fields:
                raise ReviewWorkspaceError(reason, "Git returned an empty parent row")
            decoded: list[str] = []
            for raw_oid in fields:
                try:
                    oid = raw_oid.decode("ascii")
                except UnicodeDecodeError as error:
                    raise ReviewWorkspaceError(
                        reason,
                        "Git returned a non-ASCII commit-parent object ID",
                    ) from error
                if len(oid) != len(base) or not FULL_OBJECT_ID.fullmatch(oid):
                    raise ReviewWorkspaceError(
                        reason,
                        "Git returned a malformed commit-parent object ID",
                    )
                decoded.append(oid)
            commit_oid, *parents = decoded
            if commit_oid in rows:
                raise ReviewWorkspaceError(
                    reason,
                    "Git returned duplicate commit-parent rows",
                )
            rows[commit_oid] = tuple(parents)
        return rows

    visible_rows = parse_parent_rows(
        visible,
        reason="workspace-visible-range-invalid",
    )
    expected_set = set(expected_range_commits)
    if set(visible_rows) != expected_set:
        raise ReviewWorkspaceError(
            "workspace-visible-range-mismatch",
            "ordinary Git base..head visibility differs from the bound raw range",
            details={
                "recorded_commit_count": len(expected_set),
                "visible_commit_count": len(visible_rows),
            },
        )
    if expected_range_commits:
        raw_code, raw_payload, raw_stderr = _run_git_raw(
            root,
            ("rev-list", "--parents", "--no-walk=unsorted", "--stdin"),
            stdin=b"".join(
                f"{oid}\n".encode("ascii") for oid in expected_range_commits
            ),
            output_limit_bytes=(
                (len(expected_range_commits) + RANGE_PARENT_EDGE_COUNT_LIMIT)
                * (len(base) + 1)
                + 1024
            ),
            control_binding=control_binding,
            extra_environment={"GIT_SHALLOW_FILE": os.devnull},
        )
        if raw_code != 0:
            raise ReviewWorkspaceError(
                "workspace-raw-range-check-failed",
                "raw reviewed parent-edge inspection failed operationally",
                details={
                    "returncode": raw_code,
                    "stderr_preview": raw_stderr.decode("utf-8", "backslashreplace")[
                        :4096
                    ],
                },
            )
        raw_rows = parse_parent_rows(
            raw_payload,
            reason="workspace-raw-range-invalid",
        )
        if set(raw_rows) != expected_set:
            raise ReviewWorkspaceError(
                "workspace-raw-range-mismatch",
                "raw reviewed commit rows differ from the bound range",
            )
        for commit_oid in expected_range_commits:
            if visible_rows[commit_oid] != raw_rows[commit_oid]:
                raise ReviewWorkspaceError(
                    "workspace-visible-parent-edge-mismatch",
                    "ordinary Git cut or rewrote a reviewed commit parent edge",
                    details={"commit": commit_oid},
                )
    range_commits = tuple(sorted(expected_set))

    returncode, object_ids, missing_objects, snapshot_stderr = _read_object_snapshot(
        root,
        (base, *range_commits),
        object_format,
        invalid_reason="workspace-range-object-invalid",
        limit_reason="workspace-range-object-limit",
        label="workspace range snapshot",
        control_binding=control_binding,
    )
    if missing_objects:
        missing = tuple(sorted(set(missing_objects)))
        missing_sample = missing[:MISSING_OBJECT_SAMPLE_LIMIT]
        raise ReviewWorkspaceError(
            "workspace-range-object-missing",
            (
                "workspace exact frozen range snapshot is incomplete; first missing "
                f"object is {missing_sample[0]}"
            ),
            details={
                "missing_object_count": len(missing),
                "missing_objects": list(missing_sample),
                "missing_objects_truncated": len(missing) > len(missing_sample),
            },
        )
    if returncode != 0:
        raise ReviewWorkspaceError(
            "workspace-range-object-check-failed",
            "workspace range snapshot traversal failed operationally",
            details={
                "returncode": returncode,
                "stderr_preview": snapshot_stderr.decode("utf-8", "backslashreplace")[
                    :4096
                ],
            },
        )
    return tuple(sorted(object_ids))


def _verify_range_object_contents_under_signal_mask(
    root: pathlib.Path,
    object_format: str,
    object_ids: Sequence[str],
    control_binding: _WorkspaceControlBinding,
    *,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
) -> None:
    started_at = time.monotonic()
    integrity_deadline = started_at + OBJECT_INTEGRITY_TIMEOUT_SECONDS
    deadline = (
        min(integrity_deadline, absolute_deadline)
        if absolute_deadline is not None
        else integrity_deadline
    )
    validation_deadline_controls = (
        absolute_deadline is not None and absolute_deadline <= integrity_deadline
    )

    def check_forwarded_signal() -> None:
        pending = consume_pending_forwarded_signal()
        if pending is not None:
            raise ForwardedSignal(pending)

    def check_deadline() -> None:
        check_forwarded_signal()
        if time.monotonic() < deadline:
            return
        if validation_deadline_controls and deadline_checker is not None:
            assert absolute_deadline is not None
            deadline_checker(absolute_deadline)
        raise ReviewWorkspaceError(
            "workspace-range-object-integrity-deadline",
            "workspace object-content verification exceeded its monotonic deadline",
            details={"deadline_seconds": OBJECT_INTEGRITY_TIMEOUT_SECONDS},
        )

    query_parts: list[bytes] = []
    for index, oid in enumerate(object_ids):
        if index % 4096 == 0:
            check_deadline()
        query_parts.append(f"{oid}\n".encode("ascii"))
    query = b"".join(query_parts)
    check_deadline()
    stderr_limit = 1024 * 1024
    header_limit = 256
    maximum_output = RANGE_OBJECT_LOGICAL_BYTES_LIMIT + len(object_ids) * (
        len(object_ids[0]) + 64
    )
    control_binding.revalidate()
    partial_control = _PartialRecoveryControl.create(root)
    process: subprocess.Popen[bytes] | None = None
    process_binding: _RecoveryProcessIdentity | None = None
    control_binding_published = False
    process_lease = OwnedProcessLease()
    selector = selectors.DefaultSelector()
    stderr = bytearray()
    header = bytearray()
    input_offset = 0
    output_bytes = 0
    logical_bytes = 0
    verified = 0
    remaining_content = 0
    need_separator = False
    current_hasher: object | None = None
    stdout_eof = False
    stderr_eof = False
    verification_error: BaseException | None = None

    def fail(reason: str, message: str, **details: object) -> None:
        raise ReviewWorkspaceError(reason, message, details=details)

    def complete_object() -> None:
        nonlocal verified, need_separator, current_hasher
        assert current_hasher is not None
        observed = current_hasher.hexdigest()
        expected = object_ids[verified]
        if observed != expected:
            fail(
                "workspace-range-object-hash-mismatch",
                "workspace range object content does not hash to its bound object ID",
                object_id=expected,
                observed_object_id=observed,
            )
        verified += 1
        need_separator = False
        current_hasher = None

    def consume_stdout(payload: bytes) -> None:
        nonlocal logical_bytes, need_separator, output_bytes
        nonlocal remaining_content, current_hasher
        check_deadline()
        output_bytes += len(payload)
        if output_bytes > maximum_output:
            fail(
                "workspace-range-object-output-limit",
                "workspace object-content stream exceeded its derived output bound",
                observed=output_bytes,
                limit=maximum_output,
            )
        offset = 0
        while offset < len(payload):
            if need_separator:
                if payload[offset : offset + 1] != b"\n":
                    fail(
                        "workspace-range-object-stream-invalid",
                        "workspace object-content stream omitted its payload separator",
                    )
                offset += 1
                complete_object()
                continue
            if remaining_content:
                take = min(remaining_content, len(payload) - offset)
                assert current_hasher is not None
                current_hasher.update(payload[offset : offset + take])
                remaining_content -= take
                offset += take
                if remaining_content == 0:
                    need_separator = True
                continue
            newline = payload.find(b"\n", offset)
            if newline < 0:
                header.extend(payload[offset:])
                if len(header) > header_limit:
                    fail(
                        "workspace-range-object-stream-invalid",
                        "workspace object-content header exceeds its bound",
                    )
                return
            header.extend(payload[offset:newline])
            offset = newline + 1
            if len(header) > header_limit or verified >= len(object_ids):
                fail(
                    "workspace-range-object-stream-invalid",
                    "workspace object-content stream returned an unexpected header",
                )
            fields = bytes(header).split()
            header.clear()
            if len(fields) != 3:
                fail(
                    "workspace-range-object-stream-invalid",
                    "workspace object-content stream returned a malformed header",
                )
            expected_oid = object_ids[verified].encode("ascii")
            if fields[0] != expected_oid or fields[1] not in {
                b"blob",
                b"commit",
                b"tree",
            }:
                fail(
                    "workspace-range-object-stream-invalid",
                    "workspace object-content stream returned the wrong object",
                )
            try:
                size = int(fields[2])
            except ValueError:
                fail(
                    "workspace-range-object-stream-invalid",
                    "workspace object-content stream returned an invalid size",
                )
            if size < 0:
                fail(
                    "workspace-range-object-stream-invalid",
                    "workspace object-content stream returned a negative size",
                )
            logical_bytes += size
            if logical_bytes > RANGE_OBJECT_LOGICAL_BYTES_LIMIT:
                fail(
                    "workspace-range-object-logical-byte-limit",
                    "workspace exact frozen range exceeds the logical-byte limit",
                    observed=logical_bytes,
                    limit=RANGE_OBJECT_LOGICAL_BYTES_LIMIT,
                )
            current_hasher = (
                hashlib.new(object_format, usedforsecurity=False)
                if object_format == "sha1"
                else hashlib.new(object_format)
            )
            current_hasher.update(fields[1] + b" " + str(size).encode("ascii") + b"\0")
            remaining_content = size
            if remaining_content == 0:
                need_separator = True
        check_deadline()

    try:
        process_environment = _git_environment()
        process_environment.update(
            {
                "GIT_CEILING_DIRECTORIES": str(root.parent),
                "GIT_DIR": str(root / ".git"),
                "GIT_WORK_TREE": str(root),
            }
        )
        process_command = _git_argv(root, ("cat-file", "--batch"))
        check_deadline()

        def spawn_process() -> subprocess.Popen[bytes]:
            return subprocess.Popen(
                process_command,
                env=process_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

        # Keep forwarded signals blocked in the lease worker and verifier child.
        # The main-thread checkpoints drain them while the outer mask retains
        # custody through lease settlement and recovery-control finalization.
        process = process_lease.spawn(
            spawn_process,
            command=process_command,
            deadline=deadline,
            terminate=terminate_process_group,
            process_group_exists=_process_group_exists,
            grace_seconds=5.0,
            check_interruption=check_forwarded_signal,
            unblock_signals=(),
        )
        process_binding = _bind_recovery_process(process.pid)
        partial_control.bind_process(
            "object-integrity-verifier",
            process_binding,
        )
        control_binding_published = True
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while True:
            check_forwarded_signal()
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                check_deadline()
            if process.poll() is not None and stdout_eof and stderr_eof:
                break
            events = selector.select(min(0.25, remaining_time))
            check_forwarded_signal()
            for key, _events in events:
                if key.data == "stdin":
                    if input_offset >= len(query):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                        continue
                    try:
                        written = os.write(
                            process.stdin.fileno(),
                            query[input_offset : input_offset + 64 * 1024],
                        )
                    except BrokenPipeError:
                        selector.unregister(process.stdin)
                        process.stdin.close()
                    else:
                        input_offset += written
                elif key.data == "stdout":
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(process.stdout)
                        process.stdout.close()
                        stdout_eof = True
                    else:
                        consume_stdout(chunk)
                else:
                    chunk = os.read(process.stderr.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(process.stderr)
                        process.stderr.close()
                        stderr_eof = True
                    else:
                        stderr.extend(chunk)
                        if len(stderr) > stderr_limit:
                            fail(
                                "workspace-range-object-stderr-limit",
                                "workspace object-content verifier exceeded its stderr bound",
                                observed=len(stderr),
                                limit=stderr_limit,
                            )
        returncode = process.wait(timeout=5)
        check_deadline()
        if (
            returncode != 0
            or input_offset != len(query)
            or header
            or remaining_content
            or need_separator
            or verified != len(object_ids)
        ):
            fail(
                "workspace-range-object-integrity-failed",
                "workspace exact frozen range failed complete content verification",
                returncode=returncode,
                verified_object_count=verified,
                expected_object_count=len(object_ids),
                stderr_preview=bytes(stderr[:4096]).decode("utf-8", "backslashreplace"),
            )
    except BaseException as error:
        verification_error = error
        raise
    finally:
        selector_error: BaseException | None = None
        process_leak: ReviewWorkspaceError | None = None
        settlement_error: BaseException | None = None
        release_error: BaseException | None = None
        recovery_payload: dict[str, object] | None = None
        try:
            try:
                selector.close()
            except BaseException as error:
                selector_error = error
        finally:
            primary_error = (
                verification_error if verification_error is not None else selector_error
            )
            try:
                process_lease.settle(
                    primary_error=primary_error,
                    cleanup_signal=signal.SIGKILL,
                    grace_seconds=5.0,
                )
            except BaseException as error:
                settlement_error = error
        if settlement_error is not None:
            _bind_workspace_failure_cause(
                settlement_error,
                primary_error,
                context=(
                    "object verifier primary failure preceded lease settlement failure"
                ),
            )
        if selector_error is not None and verification_error is not None:
            _attach_workspace_diagnostic_preserving_cause(
                verification_error,
                "object verifier selector close failed: "
                f"{type(selector_error).__name__}",
            )
        unsafe_error = settlement_error or primary_error
        if unsafe_error is not None and process_quiescence_unproven(unsafe_error):
            if not control_binding_published:
                try:
                    if process_binding is None:
                        published_process = process_lease.process or process
                        if published_process is None:
                            raise ReviewWorkspaceError(
                                "partial-recovery-process-identity-unavailable",
                                "object verifier process handle was not published",
                                status="inconclusive",
                            )
                        process_binding = _bind_recovery_process(published_process.pid)
                    if partial_control.active_process is None:
                        partial_control.bind_process(
                            "object-integrity-verifier",
                            process_binding,
                        )
                    elif (
                        partial_control.active_process != process_binding
                        or partial_control.active_operation
                        != "object-integrity-verifier"
                    ):
                        raise ReviewWorkspaceError(
                            "partial-recovery-process-identity-mismatch",
                            "object verifier recovery control bound another process",
                            status="inconclusive",
                        )
                    control_binding_published = True
                except BaseException as identity_error:
                    _attach_workspace_diagnostic_preserving_cause(
                        unsafe_error,
                        "partial recovery process binding failed: "
                        f"{type(identity_error).__name__}",
                    )
            recovery_payload = _retain_unquiesced_workspace(
                unsafe_error,
                partial_control,
                diagnostic_context="object-integrity verifier",
            )
            process_leak = ReviewWorkspaceError(
                "workspace-range-object-process-leak",
                "workspace object-content verifier did not prove process-group quiescence",
                status="inconclusive",
                details={
                    "pid": None,
                    "process_handle": "unavailable",
                    "process_identity_status": "unavailable",
                    "verification_reason": (
                        None
                        if verification_error is None
                        else getattr(
                            verification_error,
                            "reason",
                            type(verification_error).__name__,
                        )
                    ),
                    **(recovery_payload or {}),
                },
            )
            _inherit_unquiesced_workspace_retention(
                process_leak,
                recovery_payload,
            )
            try:
                published_process = process_lease.process
                if published_process is None:
                    published_process = process
                published_pid = (
                    None
                    if published_process is None
                    else getattr(published_process, "pid", None)
                )
                if type(published_pid) is int and published_pid > 1:
                    process_leak.details.update(
                        {
                            "pid": published_pid,
                            "process_handle": "lease-published",
                            "process_identity_status": "pid-only",
                        }
                    )
                    try:
                        bound_identity = process_binding or _bind_recovery_process(
                            published_pid
                        )
                    except BaseException as identity_error:
                        process_leak.details.update(
                            {
                                "process_identity_status": "unavailable",
                                "process_identity_reason": getattr(
                                    identity_error,
                                    "reason",
                                    type(identity_error).__name__,
                                ),
                            }
                        )
                    else:
                        process_leak.details.update(
                            {
                                "process_identity_status": "bound",
                                "process_identity": bound_identity.payload(),
                            }
                        )
            except BaseException as handle_error:
                process_leak.details["process_handle_reason"] = getattr(
                    handle_error,
                    "reason",
                    type(handle_error).__name__,
                )
        if verification_error is not None and process_quiescence_unproven(
            verification_error
        ):
            if recovery_payload is not None:
                _inherit_unquiesced_workspace_retention(
                    verification_error,
                    recovery_payload,
                )
            else:
                mark_process_quiescence_unproven(verification_error)
                _mark_partial_workspace_for_retention(verification_error)
        elif (
            process_leak is None
            and process_binding is not None
            and control_binding_published
        ):
            try:
                partial_control.release_process(process_binding)
            except BaseException as error:
                release_error = error
        for index in range(len(stderr)):
            stderr[index] = 0

        selected_teardown_error = next(
            (
                error
                for error in (
                    process_leak,
                    settlement_error,
                    primary_error,
                    release_error,
                )
                if error is not None
            ),
            None,
        )
        labeled_teardown_failures = [
            (context, error)
            for context, error in (
                ("object verifier process leak also occurred", process_leak),
                (
                    "object verifier lease settlement also failed",
                    settlement_error,
                ),
                ("object verifier primary operation also failed", primary_error),
                ("partial recovery process release also failed", release_error),
            )
            if error is not None
        ]
        revalidation_error: BaseException | None = None
        revalidation_original_cause: BaseException | None = None
        finalization_error: BaseException | None = None
        try:
            if process_leak is not None:
                process_leak_predecessor = (
                    settlement_error if settlement_error is not None else primary_error
                )
                _bind_workspace_failure_cause(
                    process_leak,
                    process_leak_predecessor,
                    context="object verifier process leak had another teardown source",
                )
            if (
                release_error is not None
                and release_error is not selected_teardown_error
            ):
                if selected_teardown_error is primary_error and isinstance(
                    release_error, ForwardedSignal
                ):
                    _attach_workspace_diagnostic_preserving_cause(
                        selected_teardown_error,
                        "forwarded signal "
                        f"{int(release_error.signum)} was deferred behind the "
                        "primary failure",
                    )
                elif selected_teardown_error is not None:
                    _attach_workspace_failure_diagnostic(
                        selected_teardown_error,
                        release_error,
                        context="partial recovery process release failed",
                    )

            try:
                control_binding.revalidate()
            except BaseException as error:
                revalidation_error = error
                revalidation_original_cause = error.__cause__
                _bind_workspace_failure_cause(
                    revalidation_error,
                    revalidation_original_cause or selected_teardown_error,
                    context=(
                        "object verifier teardown failed during final revalidation"
                    ),
                )
                if process_leak is not None:
                    if recovery_payload is not None:
                        _inherit_unquiesced_workspace_retention(
                            revalidation_error,
                            recovery_payload,
                        )
                    else:
                        mark_process_quiescence_unproven(revalidation_error)
                        _mark_partial_workspace_for_retention(revalidation_error)
                _attach_workspace_teardown_failures(
                    revalidation_error,
                    labeled_teardown_failures,
                )
        except BaseException as error:
            finalization_error = error
            raise
        finally:
            retain_control = process_leak is not None
            try:
                partial_control.close(retain=retain_control)
            except BaseException as control_error:
                selected_error = next(
                    (
                        error
                        for error in (
                            revalidation_error,
                            finalization_error,
                            selected_teardown_error,
                        )
                        if error is not None
                    ),
                    None,
                )
                if selected_error is None:
                    raise
                _attach_workspace_failure_diagnostic(
                    selected_error,
                    control_error,
                    context="partial recovery control finalization failed",
                )

        if revalidation_error is not None:
            raise revalidation_error
        if process_leak is not None:
            raise process_leak from process_leak.__cause__
        if settlement_error is not None:
            if settlement_error.__cause__ is not None:
                raise settlement_error from settlement_error.__cause__
            raise settlement_error
        if release_error is not None and selected_teardown_error is release_error:
            raise release_error
        if selector_error is not None and verification_error is None:
            raise selector_error


def _verify_range_object_contents(
    root: pathlib.Path,
    object_format: str,
    object_ids: Sequence[str],
    control_binding: _WorkspaceControlBinding,
    *,
    absolute_deadline: float | None = None,
    deadline_checker: Callable[[float], None] | None = None,
) -> None:
    """Verify exact objects while deferring forwarded signals through teardown."""

    signal_owner = _begin_forwarded_signal_mask()
    primary_error: BaseException | None = None
    try:
        _verify_range_object_contents_under_signal_mask(
            root,
            object_format,
            object_ids,
            control_binding,
            absolute_deadline=absolute_deadline,
            deadline_checker=deadline_checker,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _finish_forwarded_signal_mask(
            signal_owner,
            primary_error=primary_error,
        )


def _validate_range_manifest(
    root: pathlib.Path,
    object_format: str,
    base: str,
    head: str,
    expected_count: int,
    expected_commit_count: int,
    expected_sha256: str,
    source_shallow: bool,
    control_binding: _WorkspaceControlBinding,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    manifest = root / ".git" / RANGE_OBJECT_MANIFEST
    try:
        descriptor = os.open(manifest, _nofollow_flags(directory=False))
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-range-manifest-missing",
            "workspace range-object manifest is not readable",
        ) from error
    manifest_limit = RANGE_OBJECT_COUNT_LIMIT * 65
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > manifest_limit
        ):
            raise ReviewWorkspaceError(
                "workspace-range-manifest-invalid",
                "workspace range-object manifest is not a bounded private file",
            )
        payload_buffer = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload_buffer.extend(chunk)
            if len(payload_buffer) > manifest_limit:
                raise ReviewWorkspaceError(
                    "workspace-range-manifest-invalid",
                    "workspace range-object manifest exceeds its bound",
                )
        payload = bytes(payload_buffer)
        final_metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_mode != metadata.st_mode
        or final_metadata.st_uid != metadata.st_uid
        or final_metadata.st_nlink != metadata.st_nlink
        or final_metadata.st_size != metadata.st_size
        or len(payload) != metadata.st_size
    ):
        raise ReviewWorkspaceError(
            "workspace-range-manifest-drift",
            "workspace range-object manifest changed while being read",
        )
    if (
        not payload.endswith(b"\n")
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ReviewWorkspaceError(
            "workspace-range-manifest-drift",
            "workspace range-object manifest changed",
        )
    try:
        object_ids = tuple(line.decode("ascii") for line in payload.splitlines())
    except UnicodeDecodeError as error:
        raise ReviewWorkspaceError(
            "workspace-range-manifest-invalid",
            "workspace range-object manifest is not ASCII",
        ) from error
    expected_length = 40 if object_format == "sha1" else 64
    if (
        len(object_ids) != expected_count
        or tuple(sorted(set(object_ids))) != object_ids
        or any(
            not FULL_OBJECT_ID.fullmatch(oid) or len(oid) != expected_length
            for oid in object_ids
        )
        or base not in object_ids
        or head not in object_ids
    ):
        raise ReviewWorkspaceError(
            "workspace-range-manifest-invalid",
            "workspace range-object manifest entries are malformed",
        )
    observed_types: dict[str, str] = {}
    observed_commit_count = 0
    observed_commit_ids: set[str] = set()
    for offset in range(0, len(object_ids), 4_096):
        batch = object_ids[offset : offset + 4_096]
        query = b"".join(f"{oid}\n".encode("ascii") for oid in batch)
        output = _run_git(
            root,
            ("cat-file", "--batch-check=%(objectname) %(objecttype)"),
            stdin=query,
            reason="workspace-range-object-missing",
            control_binding=control_binding,
        )
        rows = output.splitlines()
        if len(rows) != len(batch):
            raise ReviewWorkspaceError(
                "workspace-range-object-missing",
                "Git did not classify every range object",
            )
        for expected_oid, row in zip(batch, rows, strict=True):
            fields = row.split()
            if (
                len(fields) != 2
                or fields[0] != expected_oid.encode("ascii")
                or fields[1] not in {b"blob", b"commit", b"tree"}
            ):
                raise ReviewWorkspaceError(
                    "workspace-range-object-missing",
                    "workspace cannot read a bound range object",
                )
            if expected_oid in {base, head}:
                observed_types[expected_oid] = fields[1].decode("ascii")
            if fields[1] == b"commit":
                observed_commit_count += 1
                observed_commit_ids.add(expected_oid)
    if observed_types != {base: "commit", head: "commit"}:
        raise ReviewWorkspaceError(
            "workspace-range-endpoint-invalid",
            "workspace frozen endpoints are not commits",
        )
    if observed_commit_count != expected_commit_count:
        raise ReviewWorkspaceError(
            "workspace-range-commit-count-mismatch",
            "workspace exact frozen-range commit count differs from its marker",
            details={
                "recorded_commit_count": expected_commit_count,
                "derived_commit_count": observed_commit_count,
            },
        )
    expected_range_commits = tuple(sorted(observed_commit_ids.difference({base})))
    derived_object_ids = _derive_destination_range_objects(
        root,
        base,
        head,
        source_shallow,
        control_binding,
        expected_range_commits,
    )
    if derived_object_ids != object_ids:
        raise ReviewWorkspaceError(
            "workspace-range-manifest-mismatch",
            "workspace exact frozen range closure differs from its bound manifest",
            details={
                "recorded_object_count": len(object_ids),
                "derived_object_count": len(derived_object_ids),
            },
        )
    return object_ids, expected_range_commits


def _validate_parent_support_manifest(
    root: pathlib.Path,
    object_format: str,
    base: str,
    head: str,
    range_object_ids: Sequence[str],
    range_commits: Sequence[str],
    expected_count: int,
    expected_sha256: str,
    shallow_bytes: str,
    control_binding: _WorkspaceControlBinding,
) -> None:
    deadline = time.monotonic() + PARENT_SUPPORT_VALIDATION_DEADLINE_SECONDS
    _check_parent_support_validation_deadline(deadline)
    try:
        payload = control_binding.payload((".git", PARENT_SUPPORT_OBJECT_MANIFEST))
    except ReviewWorkspaceError as error:
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-missing",
            "workspace parent-support manifest is not readable",
        ) from error
    if len(payload) > RANGE_OBJECT_COUNT_LIMIT * 65:
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-invalid",
            "workspace parent-support manifest exceeds its bound",
        )
    if payload and not payload.endswith(b"\n"):
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-invalid",
            "workspace parent-support manifest is not newline terminated",
        )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-drift",
            "workspace parent-support manifest changed",
        )
    support_id_list: list[str] = []
    for line_number, line in enumerate(payload.splitlines()):
        if line_number % 4096 == 0:
            _check_parent_support_validation_deadline(deadline)
        try:
            support_id_list.append(line.decode("ascii"))
        except UnicodeDecodeError as error:
            raise ReviewWorkspaceError(
                "workspace-parent-support-manifest-invalid",
                "workspace parent-support manifest is not ASCII",
            ) from error
    support_ids = tuple(support_id_list)
    _check_parent_support_validation_deadline(deadline)
    expected_length = 40 if object_format == "sha1" else 64
    range_object_set = set(range_object_ids)
    range_commit_set = set(range_commits)
    support_id_set = set(support_ids)
    _check_parent_support_validation_deadline(deadline)
    malformed_support_id = False
    for support_index, oid in enumerate(support_ids):
        if support_index % 4096 == 0:
            _check_parent_support_validation_deadline(deadline)
        if len(oid) != expected_length or not FULL_OBJECT_ID.fullmatch(oid):
            malformed_support_id = True
            break
    if (
        len(support_ids) != expected_count
        or tuple(sorted(support_id_set)) != support_ids
        or malformed_support_id
        or not support_id_set.isdisjoint(range_object_set)
    ):
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-invalid",
            "workspace parent-support manifest entries are malformed or overlap range",
        )
    all_object_ids = tuple(sorted(range_object_set.union(support_id_set)))
    _check_parent_support_validation_deadline(deadline)
    if len(all_object_ids) > RANGE_OBJECT_COUNT_LIMIT:
        raise ReviewWorkspaceError(
            "workspace-range-object-limit",
            "workspace range plus parent support exceeds the object-count limit",
        )

    support_commit_ids: set[str] = set()
    for offset in range(0, len(support_ids), 4_096):
        _check_parent_support_validation_deadline(deadline)
        batch = support_ids[offset : offset + 4_096]
        output = _run_git(
            root,
            ("cat-file", "--batch-check=%(objectname) %(objecttype)"),
            stdin=b"".join(f"{oid}\n".encode("ascii") for oid in batch),
            reason="workspace-parent-support-object-missing",
            absolute_deadline=deadline,
            deadline_checker=_check_parent_support_validation_deadline,
            control_binding=control_binding,
        )
        rows = output.splitlines()
        if len(rows) != len(batch):
            raise ReviewWorkspaceError(
                "workspace-parent-support-object-missing",
                "Git did not classify every parent-support object",
            )
        for expected_oid, row in zip(batch, rows, strict=True):
            fields = row.split()
            if (
                len(fields) != 2
                or fields[0] != expected_oid.encode("ascii")
                or fields[1] not in {b"blob", b"commit", b"tree"}
            ):
                raise ReviewWorkspaceError(
                    "workspace-parent-support-object-missing",
                    "workspace cannot read a bound parent-support object",
                )
            if fields[1] == b"commit":
                support_commit_ids.add(expected_oid)
    _check_parent_support_validation_deadline(deadline)

    probe = _read_raw_commit_graph(
        root,
        head,
        deadline=deadline,
        deadline_checker=_check_parent_support_validation_deadline,
        control_binding=control_binding,
        workspace=True,
    )
    _check_parent_support_validation_deadline(deadline)
    if probe.returncode != 0:
        raise ReviewWorkspaceError(
            "workspace-parent-support-graph-check-failed",
            "workspace parent-support graph probe failed operationally",
            details={
                "returncode": probe.returncode,
                "stderr_preview": probe.stderr_preview,
            },
        )
    expected_graph_commits = range_commit_set.union(support_commit_ids, {base})
    _check_parent_support_validation_deadline(deadline)
    if probe.parents.keys() != expected_graph_commits:
        raise ReviewWorkspaceError(
            "workspace-parent-support-graph-mismatch",
            "workspace imported commit graph differs from its bound manifests",
            details={
                "recorded_commit_count": len(expected_graph_commits),
                "raw_commit_count": len(probe.parents),
            },
        )

    try:
        encoded_shallow = shallow_bytes.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ReviewWorkspaceError(
            "workspace-shallow-drift",
            "workspace shallow binding is not ASCII",
        ) from error
    if encoded_shallow and not encoded_shallow.endswith(b"\n"):
        raise ReviewWorkspaceError(
            "workspace-shallow-drift",
            "workspace shallow binding is not newline terminated",
        )
    boundary_list: list[str] = []
    for line_number, line in enumerate(encoded_shallow.splitlines()):
        if line_number % 4096 == 0:
            _check_parent_support_validation_deadline(deadline)
        boundary_list.append(line.decode("ascii"))
    boundaries = tuple(boundary_list)
    boundary_set = set(boundaries)
    _check_parent_support_validation_deadline(deadline)
    malformed_boundary = False
    for boundary_index, oid in enumerate(boundaries):
        if boundary_index % 4096 == 0:
            _check_parent_support_validation_deadline(deadline)
        if len(oid) != expected_length or not FULL_OBJECT_ID.fullmatch(oid):
            malformed_boundary = True
            break
    if (
        tuple(sorted(boundary_set)) != boundaries
        or malformed_boundary
        or not boundary_set.isdisjoint(range_commit_set)
    ):
        raise ReviewWorkspaceError(
            "workspace-shallow-drift",
            "workspace shallow boundaries are malformed or cut a reviewed commit",
        )
    expected_boundaries: set[str] = set()
    frontier_parent_index = 0
    for commit_index, (commit_oid, parents) in enumerate(probe.parents.items()):
        if commit_index % 4096 == 0:
            _check_parent_support_validation_deadline(deadline)
        has_missing_parent = False
        has_present_parent = False
        for parent in parents:
            if frontier_parent_index % 4096 == 0:
                _check_parent_support_validation_deadline(deadline)
            frontier_parent_index += 1
            if parent in probe.missing:
                has_missing_parent = True
            elif parent in probe.parents:
                has_present_parent = True
        if not has_missing_parent:
            continue
        if commit_oid in range_commit_set or has_present_parent:
            raise ReviewWorkspaceError(
                "workspace-shallow-frontier-unsafe",
                "workspace missing-parent frontier would cut a reviewed or available edge",
                details={"commit": commit_oid},
            )
        expected_boundaries.add(commit_oid)
    _check_parent_support_validation_deadline(deadline)
    if boundary_set != expected_boundaries:
        raise ReviewWorkspaceError(
            "workspace-shallow-drift",
            "workspace shallow boundaries differ from the real missing-parent frontier",
        )

    direct_external_parents: set[str] = set()
    parent_edge_index = 0
    for commit_oid in range_commits:
        for parent in probe.parents[commit_oid]:
            if parent_edge_index % 4096 == 0:
                _check_parent_support_validation_deadline(deadline)
            parent_edge_index += 1
            if parent not in range_commit_set and parent != base:
                direct_external_parents.add(parent)
    _check_parent_support_validation_deadline(deadline)
    parent_snapshot_ids: set[str] = set()
    if direct_external_parents:
        (
            returncode,
            parent_snapshot_ids,
            missing_parent_objects,
            stderr,
        ) = _read_object_snapshot(
            root,
            tuple(sorted(direct_external_parents)),
            object_format,
            invalid_reason="workspace-parent-support-object-invalid",
            limit_reason="workspace-range-object-limit",
            label="workspace direct-parent snapshot",
            absolute_deadline=deadline,
            deadline_checker=_check_parent_support_validation_deadline,
            control_binding=control_binding,
        )
        if missing_parent_objects:
            missing = tuple(sorted(set(missing_parent_objects)))
            missing_sample = missing[:MISSING_OBJECT_SAMPLE_LIMIT]
            raise ReviewWorkspaceError(
                "workspace-parent-support-object-missing",
                "workspace direct-parent snapshot is incomplete",
                details={
                    "missing_object_count": len(missing),
                    "missing_objects": list(missing_sample),
                    "missing_objects_truncated": len(missing) > len(missing_sample),
                },
            )
        _check_parent_support_validation_deadline(deadline)
        if returncode != 0:
            raise ReviewWorkspaceError(
                "workspace-parent-support-object-check-failed",
                "workspace direct-parent snapshot traversal failed operationally",
                details={
                    "returncode": returncode,
                    "stderr_preview": stderr.decode("utf-8", "backslashreplace")[:4096],
                },
            )
    expected_support = support_commit_ids.union(parent_snapshot_ids)
    expected_support.difference_update(range_object_set)
    _check_parent_support_validation_deadline(deadline)
    if support_id_set != expected_support:
        raise ReviewWorkspaceError(
            "workspace-parent-support-manifest-mismatch",
            "workspace parent-support closure differs from its bound manifest",
            details={
                "recorded_object_count": len(support_ids),
                "derived_object_count": len(expected_support),
            },
        )
    _verify_range_object_contents(
        root,
        object_format,
        all_object_ids,
        control_binding,
        absolute_deadline=deadline,
        deadline_checker=_check_parent_support_validation_deadline,
    )
    _check_parent_support_validation_deadline(deadline)


def _validate_fixed_state(
    root: pathlib.Path,
    marker: Mapping[str, object],
    base: str,
    head: str,
    control_binding: _WorkspaceControlBinding,
) -> tuple[str, str, bool, int, int, str, int, str, str, str, str]:
    for key, supplied in (("base", base), ("head", head)):
        recorded = marker.get(key)
        if recorded != supplied:
            raise ReviewWorkspaceError(
                "workspace-range-mismatch",
                f"workspace {key} does not match the receipt",
            )
    object_format = marker.get("object_format")
    strategy = marker.get("strategy")
    source_shallow = marker.get("source_shallow")
    commit_count = marker.get("commit_count")
    range_object_count = marker.get("range_object_count")
    range_object_sha256 = marker.get("range_object_sha256")
    parent_support_object_count = marker.get("parent_support_object_count")
    parent_support_object_sha256 = marker.get("parent_support_object_sha256")
    config_sha256 = marker.get("config_sha256")
    shallow_bytes = marker.get("shallow_bytes")
    shallow_sha256 = marker.get("shallow_sha256")
    if (
        object_format not in {"sha1", "sha256"}
        or strategy != "exact-pack"
        or not isinstance(source_shallow, bool)
        or type(commit_count) is not int
        or commit_count < 1
        or commit_count > RANGE_COMMIT_COUNT_LIMIT
        or type(range_object_count) is not int
        or range_object_count < 1
        or range_object_count > RANGE_OBJECT_COUNT_LIMIT
        or not isinstance(range_object_sha256, str)
        or type(parent_support_object_count) is not int
        or parent_support_object_count < 0
        or parent_support_object_count > RANGE_OBJECT_COUNT_LIMIT
        or not isinstance(parent_support_object_sha256, str)
        or not isinstance(config_sha256, str)
        or not isinstance(shallow_bytes, str)
        or not isinstance(shallow_sha256, str)
    ):
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace marker fields are malformed"
        )
    config_bytes = control_binding.payload((".git", "config"))
    expected_config = _config_payload(object_format)
    observed_digest = hashlib.sha256(config_bytes).hexdigest()
    if config_bytes != expected_config or observed_digest != config_sha256:
        raise ReviewWorkspaceError(
            "workspace-config-drift", "workspace Git config changed"
        )
    try:
        expected_shallow = shallow_bytes.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ReviewWorkspaceError(
            "workspace-shallow-drift", "workspace shallow binding is not ASCII"
        ) from error
    shallow_snapshot = next(
        (
            snapshot
            for snapshot in control_binding.files
            if snapshot.relative == (".git", "shallow")
        ),
        None,
    )
    if expected_shallow:
        if shallow_snapshot is None or shallow_snapshot.payload is None:
            raise ReviewWorkspaceError(
                "workspace-shallow-drift",
                "workspace shallow boundary is missing",
            )
        observed_shallow = shallow_snapshot.payload
    else:
        if shallow_snapshot is not None:
            raise ReviewWorkspaceError(
                "workspace-shallow-drift",
                "workspace unexpectedly exposes shallow state",
            )
        observed_shallow = b""
    if (
        observed_shallow != expected_shallow
        or hashlib.sha256(observed_shallow).hexdigest() != shallow_sha256
    ):
        raise ReviewWorkspaceError(
            "workspace-shallow-drift", "workspace shallow boundary changed"
        )
    expected_refs = {
        root / ".git/HEAD": f"{head}\n".encode("ascii"),
        root / ".git/refs/review-workspace/base": f"{base}\n".encode("ascii"),
        root / ".git/refs/review-workspace/head": f"{head}\n".encode("ascii"),
    }
    for path, expected in expected_refs.items():
        try:
            relative = tuple(path.relative_to(root).parts)
            observed = control_binding.payload(relative)
        except (ValueError, ReviewWorkspaceError) as error:
            raise ReviewWorkspaceError(
                "workspace-ref-drift", "workspace frozen ref cannot be read"
            ) from error
        if observed != expected:
            raise ReviewWorkspaceError(
                "workspace-ref-drift", "workspace frozen ref changed"
            )
    if _run_git(
        root,
        ("rev-parse", "HEAD"),
        control_binding=control_binding,
    ).strip() != head.encode("ascii"):
        raise ReviewWorkspaceError("workspace-head-drift", "workspace HEAD changed")
    if _run_git(
        root,
        ("symbolic-ref", "-q", "HEAD"),
        allowed_returncodes=(0, 1),
        control_binding=control_binding,
    ):
        raise ReviewWorkspaceError(
            "workspace-head-attached", "workspace HEAD must remain detached"
        )
    range_object_ids, range_commits = _validate_range_manifest(
        root,
        object_format,
        base,
        head,
        range_object_count,
        commit_count,
        range_object_sha256,
        source_shallow,
        control_binding,
    )
    _validate_parent_support_manifest(
        root,
        object_format,
        base,
        head,
        range_object_ids,
        range_commits,
        parent_support_object_count,
        parent_support_object_sha256,
        shallow_bytes,
        control_binding,
    )
    return (
        object_format,
        strategy,
        source_shallow,
        commit_count,
        range_object_count,
        range_object_sha256,
        parent_support_object_count,
        parent_support_object_sha256,
        config_sha256,
        shallow_bytes,
        shallow_sha256,
    )


def _permitted_absent_gitlink_status_path(
    record: bytes,
    expected_gitlinks: Mapping[bytes, bytes],
) -> bytes | None:
    fields = record.split(b" ", 8)
    if len(fields) != 9:
        return None
    (
        kind,
        xy,
        submodule,
        head_mode,
        index_mode,
        worktree_mode,
        head_oid,
        index_oid,
        raw_path,
    ) = fields
    expected_oid = expected_gitlinks.get(raw_path)
    if expected_oid is None:
        return None
    if (
        kind != b"1"
        or xy != b".D"
        or submodule != b"S..."
        or head_mode != b"160000"
        or index_mode != b"160000"
        or worktree_mode != b"0" * 6
        or head_oid != expected_oid
        or index_oid != expected_oid
    ):
        return None
    return raw_path


def _status_contains_only_permitted_absent_gitlinks(
    payload: bytes,
    expected_gitlinks: Mapping[bytes, bytes],
    absent_gitlinks: frozenset[bytes],
) -> bool:
    if not payload:
        return True
    if not payload.endswith(b"\0") or b"\0\0" in payload:
        return False
    observed: set[bytes] = set()
    for record in payload[:-1].split(b"\0"):
        raw_path = _permitted_absent_gitlink_status_path(record, expected_gitlinks)
        if raw_path is None or raw_path not in absent_gitlinks or raw_path in observed:
            return False
        observed.add(raw_path)
    return True


def _validate_clean(
    root: pathlib.Path,
    control_binding: _WorkspaceControlBinding,
    *,
    gitlinks: Sequence[tuple[bytes, bytes]],
    absent_gitlinks: frozenset[bytes],
) -> None:
    expected_gitlinks = dict(gitlinks)
    status = _run_git(
        root,
        (
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        reason="workspace-status-failed",
        control_binding=control_binding,
    )
    if not _status_contains_only_permitted_absent_gitlinks(
        status,
        expected_gitlinks,
        absent_gitlinks,
    ):
        raise ReviewWorkspaceError(
            "workspace-not-clean",
            "workspace contains staged, dirty, untracked, or ignored state",
            details={
                "status_preview": status[:8_192].decode("utf-8", "backslashreplace")
            },
        )
    flags = _run_git(
        root,
        ("ls-files", "-v", "-z"),
        reason="index-flags-failed",
        control_binding=control_binding,
    )
    if flags and (not flags.endswith(b"\0") or b"\0\0" in flags):
        raise ReviewWorkspaceError(
            "index-flags-output-invalid",
            "Git returned malformed ls-files -v record framing",
        )
    for record in flags[:-1].split(b"\0") if flags else ():
        if len(record) < 3 or record[1:2] != b" " or not record[2:]:
            raise ReviewWorkspaceError(
                "index-flags-output-invalid",
                "Git returned malformed ls-files -v output",
            )
        tag = record[:1]
        if tag in {b"h", b"s", b"S"}:
            raise ReviewWorkspaceError(
                "workspace-index-flags", "workspace index hides tracked changes"
            )
        if tag != b"H":
            raise ReviewWorkspaceError(
                "index-flags-output-invalid",
                "Git returned an unexpected ls-files -v status tag",
            )
    _validate_gitlink_placeholders(
        root,
        gitlinks,
        time.monotonic() + GIT_TIMEOUT_SECONDS,
    )


def _raise_workspace_index_invalid(message: str) -> None:
    raise ReviewWorkspaceError("workspace-index-invalid", message)


def _validate_index_name_length(flags: int, path_length: int) -> None:
    encoded_length = flags & 0x0FFF
    if encoded_length == 0x0FFF:
        if path_length < 0x0FFF:
            _raise_workspace_index_invalid(
                "workspace index entry pathname length is malformed"
            )
        return
    if encoded_length != path_length:
        _raise_workspace_index_invalid(
            "workspace index entry pathname length is malformed"
        )


def _accumulate_index_path_bytes(accumulated: int, path_length: int) -> int:
    if (
        accumulated < 0
        or path_length < 0
        or accumulated > CHECKOUT_PATH_BYTES_LIMIT
        or path_length > CHECKOUT_PATH_BYTES_LIMIT - accumulated
    ):
        _raise_workspace_index_invalid(
            "workspace index pathname bytes exceed the checkout path-byte limit"
        )
    return accumulated + path_length


def _materialize_index_v4_path(
    previous_path: bytes,
    retained_length: int,
    payload: bytes,
    suffix_start: int,
    suffix_end: int,
) -> bytes:
    return b"".join(
        (
            memoryview(previous_path)[:retained_length],
            memoryview(payload)[suffix_start:suffix_end],
        )
    )


def _decode_index_v4_strip_length(
    payload: bytes,
    cursor: int,
    entries_end: int,
    previous_path_length: int,
) -> tuple[int, int]:
    if cursor >= entries_end:
        _raise_workspace_index_invalid(
            "workspace index v4 pathname prefix is truncated"
        )
    octet = payload[cursor]
    cursor += 1
    value = octet & 0x7F
    while octet & 0x80:
        if value >= previous_path_length:
            _raise_workspace_index_invalid(
                "workspace index v4 pathname prefix is malformed"
            )
        if cursor >= entries_end:
            _raise_workspace_index_invalid(
                "workspace index v4 pathname prefix is truncated"
            )
        octet = payload[cursor]
        cursor += 1
        value = ((value + 1) << 7) | (octet & 0x7F)
    if value > previous_path_length:
        _raise_workspace_index_invalid(
            "workspace index v4 pathname prefix exceeds the previous pathname"
        )
    return value, cursor


def _index_entries_end(payload: bytes, oid_width: int) -> tuple[int, int]:
    if oid_width not in {20, 32} or len(payload) < 12 + oid_width:
        _raise_workspace_index_invalid("workspace index header is malformed")
    if payload[:4] != b"DIRC":
        _raise_workspace_index_invalid("workspace index header is malformed")
    version, entry_count = struct.unpack(">II", payload[4:12])
    if version not in {2, 3, 4}:
        _raise_workspace_index_invalid("workspace index version is unsupported")
    if entry_count > CHECKOUT_ENTRY_COUNT_LIMIT:
        _raise_workspace_index_invalid(
            "workspace index entry count exceeds the checkout entry limit"
        )

    entries_end = len(payload) - oid_width
    payload_view = memoryview(payload)
    expected_checksum = (
        hashlib.sha1(
            payload_view[:entries_end],
            usedforsecurity=False,
        ).digest()
        if oid_width == 20
        else hashlib.sha256(payload_view[:entries_end]).digest()
    )
    if not secrets.compare_digest(expected_checksum, payload_view[entries_end:]):
        _raise_workspace_index_invalid("workspace index checksum is invalid")

    cursor = 12
    fixed_entry_size = 40 + oid_width + 2
    previous_path = b""
    path_bytes = 0
    for _entry_index in range(entry_count):
        entry_start = cursor
        if fixed_entry_size > entries_end - cursor:
            _raise_workspace_index_invalid("workspace index entry is truncated")
        cursor += fixed_entry_size
        flags = struct.unpack(">H", payload[cursor - 2 : cursor])[0]
        if flags & 0x4000:
            if version == 2:
                _raise_workspace_index_invalid(
                    "workspace index v2 entry has extended flags"
                )
            if entries_end - cursor < 2:
                _raise_workspace_index_invalid(
                    "workspace index extended flags are truncated"
                )
            cursor += 2

        if version == 4:
            strip_length, cursor = _decode_index_v4_strip_length(
                payload,
                cursor,
                entries_end,
                len(previous_path),
            )
            terminator = payload.find(b"\0", cursor, entries_end)
            if terminator < 0:
                _raise_workspace_index_invalid(
                    "workspace index v4 pathname is unterminated"
                )
            retained_length = len(previous_path) - strip_length
            path_length = retained_length + (terminator - cursor)
            _validate_index_name_length(flags, path_length)
            path_bytes = _accumulate_index_path_bytes(path_bytes, path_length)
            previous_path = _materialize_index_v4_path(
                previous_path,
                retained_length,
                payload,
                cursor,
                terminator,
            )
            cursor = terminator + 1
            continue

        terminator = payload.find(b"\0", cursor, entries_end)
        if terminator < 0:
            _raise_workspace_index_invalid("workspace index pathname is unterminated")
        path_length = terminator - cursor
        _validate_index_name_length(flags, path_length)
        path_bytes = _accumulate_index_path_bytes(path_bytes, path_length)
        unpadded_size = terminator + 1 - entry_start
        padded_size = (unpadded_size + 7) & ~7
        cursor = entry_start + padded_size
        if cursor > entries_end:
            _raise_workspace_index_invalid("workspace index entry padding is truncated")
        if any(payload[terminator:cursor]):
            _raise_workspace_index_invalid("workspace index entry padding is malformed")
    return cursor, entries_end


def _index_contains_split_link_extension(payload: bytes, oid_width: int) -> bool:
    cursor, extension_end = _index_entries_end(payload, oid_width)
    found_link = False
    while cursor < extension_end:
        if extension_end - cursor < 8:
            _raise_workspace_index_invalid("workspace index extension is truncated")
        signature = payload[cursor : cursor + 4]
        size = struct.unpack(">I", payload[cursor + 4 : cursor + 8])[0]
        cursor += 8
        if size > extension_end - cursor:
            _raise_workspace_index_invalid(
                "workspace index extension payload is truncated"
            )
        if signature == b"link":
            found_link = True
        cursor += size
    return found_link


def _validate_no_split_index(
    root: pathlib.Path,
    object_format: str,
    control_binding: _WorkspaceControlBinding,
) -> None:
    index_payload = control_binding.payload((".git", "index"))
    if _index_contains_split_link_extension(
        index_payload,
        20 if object_format == "sha1" else 32,
    ):
        raise ReviewWorkspaceError(
            "workspace-split-index",
            "workspace index must not depend on a shared split index",
        )
    git_descriptor = os.open(root / ".git", _nofollow_flags(directory=True))
    try:
        with os.scandir(git_descriptor) as entries:
            if any(entry.name.startswith("sharedindex.") for entry in entries):
                raise ReviewWorkspaceError(
                    "workspace-split-index",
                    "workspace Git directory contains shared-index state",
                )
    finally:
        os.close(git_descriptor)
    shared_path = _run_git(
        root,
        ("rev-parse", "--shared-index-path"),
        reason="workspace-split-index-check-failed",
        output_limit_bytes=4096,
        control_binding=control_binding,
    ).strip()
    if shared_path:
        raise ReviewWorkspaceError(
            "workspace-split-index",
            "workspace Git reports an active shared split index",
        )


@_requires_validated_git
def validate_workspace(
    worktree: pathlib.Path,
    base: str,
    head: str,
    *,
    expected_cleanup_token: str | None = None,
) -> ValidatedWorkspace:
    root = _absolute_existing_directory(worktree, "workspace")
    control_binding = _bind_workspace_controls(
        root,
        include_index=True,
        include_marker=True,
    )
    marker_payload = control_binding.payload((".git", WORKSPACE_MARKER))
    marker = _parse_marker_payload(marker_payload)
    cleanup_token_sha256 = _marker_cleanup_token_digest(marker)
    if expected_cleanup_token is not None and not secrets.compare_digest(
        cleanup_token_sha256,
        _cleanup_token_digest(expected_cleanup_token),
    ):
        raise ReviewWorkspaceError(
            "workspace-cleanup-token-drift",
            "workspace marker cleanup token differs from the preparation token",
        )
    object_format_hint = marker.get("object_format")
    if object_format_hint not in {"sha1", "sha256"}:
        raise ReviewWorkspaceError(
            "workspace-marker-invalid", "workspace object format is malformed"
        )
    _validate_no_split_index(root, object_format_hint, control_binding)
    parent_identity = _validate_parent_identity(root, marker)
    identity = _validate_root_identity(root, marker)
    git_identity, objects_identity = _validate_storage_identities(root, marker)
    _validate_layout(root, control_binding)
    (
        object_format,
        strategy,
        source_shallow,
        commit_count,
        range_object_count,
        range_object_sha256,
        parent_support_object_count,
        parent_support_object_sha256,
        config_sha256,
        shallow_bytes,
        shallow_sha256,
    ) = _validate_fixed_state(root, marker, base, head, control_binding)
    links = _validate_links(root, control_binding)
    symlink_count = links.symlink_count
    _validate_clean(
        root,
        control_binding,
        gitlinks=links.gitlinks,
        absent_gitlinks=links.absent_gitlinks,
    )
    control_binding.revalidate()
    _validate_no_object_dependencies(root)
    control_binding.revalidate()
    _validate_parent_identity(root, marker)
    _validate_root_identity(root, marker)
    final_git_identity, final_objects_identity = _validate_storage_identities(
        root, marker
    )
    if final_git_identity != git_identity or final_objects_identity != objects_identity:
        raise ReviewWorkspaceError(
            "workspace-storage-identity-mismatch",
            "workspace Git storage identities changed during validation",
        )
    return ValidatedWorkspace(
        root=root,
        base_sha=base,
        head_sha=head,
        object_format=object_format,
        strategy=strategy,
        source_shallow=source_shallow,
        commit_count=commit_count,
        range_object_count=range_object_count,
        range_object_sha256=range_object_sha256,
        parent_support_object_count=parent_support_object_count,
        parent_support_object_sha256=parent_support_object_sha256,
        config_sha256=config_sha256,
        shallow_bytes=shallow_bytes,
        shallow_sha256=shallow_sha256,
        symlink_count=symlink_count,
        parent_identity=parent_identity,
        workspace_identity=identity,
        git_identity=git_identity,
        objects_identity=objects_identity,
        marker_sha256=hashlib.sha256(marker_payload).hexdigest(),
        cleanup_token_sha256=cleanup_token_sha256,
    )


def _descriptor_bound_path(descriptor: int) -> pathlib.Path | None:
    get_path = getattr(fcntl, "F_GETPATH", None)
    if get_path is not None:
        try:
            payload = fcntl.fcntl(descriptor, get_path, bytes(1024))
        except (OSError, TypeError):
            return None
        return pathlib.Path(os.fsdecode(payload.split(b"\0", 1)[0]))
    proc_descriptor = pathlib.Path(f"/proc/self/fd/{descriptor}")
    try:
        payload = os.readlink(proc_descriptor)
    except OSError:
        return None
    return pathlib.Path(payload)


@dataclass
class _CleanupDirectoryFrame:
    descriptor: int
    display_path: pathlib.Path
    entries: list[os.DirEntry[str]]
    retained_marker_path: tuple[str, ...] | None
    preserve_retained_marker: bool
    owns_descriptor: bool
    parent_descriptor: int | None = None
    parent_entry_name: str | None = None
    bound_metadata: os.stat_result | None = None
    remove_from_parent: bool = False
    cursor: int = 0


def _close_cleanup_descriptor(
    descriptor: int,
    primary_error: BaseException | None,
) -> None:
    try:
        os.close(descriptor)
    except BaseException as close_error:
        if primary_error is None:
            raise
        _attach_workspace_diagnostic(
            primary_error,
            "workspace cleanup child descriptor close failed: "
            f"{type(close_error).__name__}",
        )


def _close_cleanup_frame(
    frame: _CleanupDirectoryFrame,
    primary_error: BaseException | None,
) -> None:
    if not frame.owns_descriptor:
        return
    frame.owns_descriptor = False
    _close_cleanup_descriptor(frame.descriptor, primary_error)


def _cleanup_directory_frame(
    descriptor: int,
    display_path: pathlib.Path,
    root_device: int,
    *,
    retained_marker_path: tuple[str, ...] | None,
    preserve_retained_marker: bool,
    owns_descriptor: bool,
    parent_descriptor: int | None = None,
    parent_entry_name: str | None = None,
    bound_metadata: os.stat_result | None = None,
    remove_from_parent: bool = False,
) -> _CleanupDirectoryFrame:
    current_metadata = os.fstat(descriptor)
    if current_metadata.st_dev != root_device:
        raise ReviewWorkspaceError(
            "workspace-cleanup-mount-boundary",
            "workspace cleanup refuses to cross a filesystem boundary",
            details={"entry": str(display_path)},
        )
    with os.scandir(descriptor) as iterator:
        entries = list(iterator)
    if retained_marker_path:
        retained_entry = retained_marker_path[0]
        entries.sort(key=lambda entry: entry.name == retained_entry)
    return _CleanupDirectoryFrame(
        descriptor=descriptor,
        display_path=display_path,
        entries=entries,
        retained_marker_path=retained_marker_path,
        preserve_retained_marker=preserve_retained_marker,
        owns_descriptor=owns_descriptor,
        parent_descriptor=parent_descriptor,
        parent_entry_name=parent_entry_name,
        bound_metadata=bound_metadata,
        remove_from_parent=remove_from_parent,
    )


def _clear_directory_descriptor(
    descriptor: int,
    display_path: pathlib.Path,
    root_device: int,
    *,
    retained_marker_path: tuple[str, ...] | None = None,
    preserve_retained_marker: bool = False,
) -> None:
    frames = [
        _cleanup_directory_frame(
            descriptor,
            display_path,
            root_device,
            retained_marker_path=retained_marker_path,
            preserve_retained_marker=preserve_retained_marker,
            owns_descriptor=False,
        )
    ]
    try:
        while frames:
            frame = frames[-1]
            if frame.cursor >= len(frame.entries):
                if not frame.owns_descriptor:
                    frames.pop()
                    continue
                completion_error: BaseException | None = None
                try:
                    assert frame.parent_descriptor is not None
                    assert frame.parent_entry_name is not None
                    assert frame.bound_metadata is not None
                    current_child = os.stat(
                        frame.parent_entry_name,
                        dir_fd=frame.parent_descriptor,
                        follow_symlinks=False,
                    )
                    if not os.path.samestat(frame.bound_metadata, current_child):
                        raise ReviewWorkspaceError(
                            "workspace-cleanup-entry-drift",
                            "workspace directory entry changed during cleanup custody",
                            details={"entry": str(frame.display_path)},
                        )
                    if frame.remove_from_parent:
                        os.rmdir(
                            frame.parent_entry_name,
                            dir_fd=frame.parent_descriptor,
                        )
                except BaseException as error:
                    completion_error = error
                    raise
                finally:
                    _close_cleanup_frame(frame, completion_error)
                    frames.pop()
                continue

            entry = frame.entries[frame.cursor]
            frame.cursor += 1
            entry_path = frame.display_path / entry.name
            retained_entry = bool(
                frame.retained_marker_path
                and entry.name == frame.retained_marker_path[0]
            )
            try:
                entry_metadata = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(entry_metadata.st_mode):
                if entry_metadata.st_dev != root_device or os.path.ismount(entry_path):
                    raise ReviewWorkspaceError(
                        "workspace-cleanup-mount-boundary",
                        "workspace cleanup refuses to descend into a mount boundary",
                        details={"entry": str(entry_path)},
                    )
                child_descriptor: int | None = None
                child_frame: _CleanupDirectoryFrame | None = None
                try:
                    child_descriptor = os.open(
                        entry.name,
                        _nofollow_flags(directory=True),
                        dir_fd=frame.descriptor,
                    )
                    bound_child = os.fstat(child_descriptor)
                    if not os.path.samestat(entry_metadata, bound_child):
                        raise ReviewWorkspaceError(
                            "workspace-cleanup-entry-drift",
                            "workspace directory entry changed before cleanup custody",
                            details={"entry": str(entry_path)},
                        )
                    child_retained_marker_path = (
                        frame.retained_marker_path[1:]
                        if frame.retained_marker_path
                        and retained_entry
                        and len(frame.retained_marker_path) > 1
                        else None
                    )
                    child_preserves_retained_marker = (
                        frame.preserve_retained_marker and retained_entry
                    )
                    child_frame = _cleanup_directory_frame(
                        child_descriptor,
                        entry_path,
                        root_device,
                        retained_marker_path=child_retained_marker_path,
                        preserve_retained_marker=child_preserves_retained_marker,
                        owns_descriptor=True,
                        parent_descriptor=frame.descriptor,
                        parent_entry_name=entry.name,
                        bound_metadata=bound_child,
                        remove_from_parent=not child_preserves_retained_marker,
                    )
                    frames.append(child_frame)
                except BaseException as child_error:
                    if child_frame is not None:
                        _close_cleanup_frame(child_frame, child_error)
                        if frames and frames[-1] is child_frame:
                            frames.pop()
                    elif child_descriptor is not None:
                        _close_cleanup_descriptor(child_descriptor, child_error)
                    raise
                continue
            if (
                frame.preserve_retained_marker
                and retained_entry
                and frame.retained_marker_path is not None
                and len(frame.retained_marker_path) == 1
            ):
                continue
            try:
                os.unlink(entry.name, dir_fd=frame.descriptor)
            except FileNotFoundError:
                continue
    except BaseException as primary_error:
        for frame in reversed(frames):
            _close_cleanup_frame(frame, primary_error)
        raise


def _read_descriptor_payload(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    consumed = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - consumed))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        consumed += len(chunk)
        if consumed > limit:
            raise ReviewWorkspaceError(
                "workspace-cleanup-recovery-marker-invalid",
                "workspace cleanup recovery marker exceeds its bound",
            )


def _ensure_cleanup_recovery_marker(
    root_descriptor: int,
    root_identity: tuple[int, int, int],
    root_device: int,
    marker_payload: bytes,
) -> None:
    """Keep or recreate the cleanup verifier inside the bound retained root."""

    root_metadata = os.fstat(root_descriptor)
    if (
        root_metadata.st_dev,
        root_metadata.st_ino,
        root_metadata.st_uid,
    ) != root_identity or root_metadata.st_dev != root_device:
        raise ReviewWorkspaceError(
            "workspace-cleanup-recovery-identity-mismatch",
            "workspace cleanup cannot restore authentication after root identity drift",
        )

    git_descriptor: int | None = None
    marker_descriptor: int | None = None
    try:
        try:
            git_path_metadata = os.stat(
                ".git",
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _validate_private_directory_metadata(
                root_metadata,
                "workspace cleanup recovery root",
            )
            _validate_no_extended_acl(
                root_descriptor,
                "workspace cleanup recovery root",
            )
            os.mkdir(".git", mode=0o700, dir_fd=root_descriptor)
            git_path_metadata = os.stat(
                ".git",
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        git_descriptor = os.open(
            ".git",
            _nofollow_flags(directory=True),
            dir_fd=root_descriptor,
        )
        git_metadata = os.fstat(git_descriptor)
        if (
            not os.path.samestat(git_path_metadata, git_metadata)
            or git_metadata.st_dev != root_device
            or git_metadata.st_uid != os.getuid()
            or stat.S_IMODE(git_metadata.st_mode) != 0o700
        ):
            raise ReviewWorkspaceError(
                "workspace-cleanup-recovery-identity-mismatch",
                "workspace cleanup recovery Git directory is not bound and private",
            )
        _validate_no_extended_acl(
            git_descriptor,
            "workspace cleanup recovery Git directory",
        )

        try:
            marker_path_metadata = os.stat(
                WORKSPACE_MARKER,
                dir_fd=git_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            marker_descriptor = os.open(
                WORKSPACE_MARKER,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=git_descriptor,
            )
            view = memoryview(marker_payload)
            while view:
                written = os.write(marker_descriptor, view)
                if written <= 0:
                    raise ReviewWorkspaceError(
                        "workspace-cleanup-recovery-marker-write-failed",
                        "workspace cleanup recovery marker write made no progress",
                    )
                view = view[written:]
            os.fchmod(marker_descriptor, 0o600)
            os.fsync(marker_descriptor)
            marker_path_metadata = os.stat(
                WORKSPACE_MARKER,
                dir_fd=git_descriptor,
                follow_symlinks=False,
            )
        else:
            marker_descriptor = os.open(
                WORKSPACE_MARKER,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=git_descriptor,
            )
        marker_metadata = os.fstat(marker_descriptor)
        if (
            not os.path.samestat(marker_path_metadata, marker_metadata)
            or not stat.S_ISREG(marker_metadata.st_mode)
            or marker_metadata.st_dev != root_device
            or marker_metadata.st_uid != os.getuid()
            or stat.S_IMODE(marker_metadata.st_mode) != 0o600
            or marker_metadata.st_nlink != 1
        ):
            raise ReviewWorkspaceError(
                "workspace-cleanup-recovery-marker-invalid",
                "workspace cleanup recovery marker is not a bound private file",
            )
        os.lseek(marker_descriptor, 0, os.SEEK_SET)
        if (
            _read_descriptor_payload(marker_descriptor, MARKER_LIMIT_BYTES)
            != marker_payload
        ):
            raise ReviewWorkspaceError(
                "workspace-cleanup-recovery-marker-invalid",
                "workspace cleanup recovery marker differs from the authenticated marker",
            )
        os.fsync(git_descriptor)
        os.fsync(root_descriptor)
    finally:
        if marker_descriptor is not None:
            os.close(marker_descriptor)
        if git_descriptor is not None:
            os.close(git_descriptor)


def _finish_bound_directory_removal(
    path: pathlib.Path,
    identity: tuple[int, int, int],
    parent_descriptor: int,
    root_descriptor: int,
    bound_root: os.stat_result,
) -> None:
    final_bound_root = os.fstat(root_descriptor)
    final_parent = os.fstat(parent_descriptor)
    _validate_private_directory_metadata(
        final_bound_root,
        "workspace cleanup root",
    )
    _validate_private_directory_metadata(
        final_parent,
        "workspace cleanup parent",
    )
    _validate_no_extended_acl(root_descriptor, "workspace cleanup root")
    _validate_no_extended_acl(parent_descriptor, "workspace cleanup parent")
    current_root = os.stat(
        path.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        not os.path.samestat(bound_root, current_root)
        or current_root.st_uid != os.getuid()
        or stat.S_IMODE(current_root.st_mode) != 0o700
    ):
        raise ReviewWorkspaceError(
            "workspace-cleanup-identity-mismatch",
            "workspace cleanup target changed before final removal",
        )
    os.rmdir(path.name, dir_fd=parent_descriptor)
    final_parent = os.fstat(parent_descriptor)
    _validate_private_directory_metadata(
        final_parent,
        "workspace cleanup parent",
    )
    _validate_no_extended_acl(parent_descriptor, "workspace cleanup parent")
    try:
        os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        raise ReviewWorkspaceError(
            "workspace-cleanup-path-reoccupied",
            "workspace cleanup path was reoccupied during final removal",
        )
    retained_path = _descriptor_bound_path(root_descriptor)
    if retained_path is None:
        raise ReviewWorkspaceError(
            "workspace-cleanup-proof-unavailable",
            "workspace cleanup cannot prove the bound directory was unlinked",
        )
    try:
        retained_metadata = retained_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReviewWorkspaceError(
            "workspace-cleanup-proof-unavailable",
            "workspace cleanup cannot inspect the bound directory recovery path",
        ) from error
    if (
        stat.S_ISDIR(retained_metadata.st_mode)
        and (
            retained_metadata.st_dev,
            retained_metadata.st_ino,
            retained_metadata.st_uid,
        )
        == identity
    ):
        raise ReviewWorkspaceError(
            "workspace-cleanup-identity-retained",
            "workspace cleanup target moved instead of being removed",
            details={"retained_path": str(retained_path)},
        )
    raise ReviewWorkspaceError(
        "workspace-cleanup-proof-unavailable",
        "workspace cleanup descriptor path was replaced during final removal",
    )


def _remove_bound_directory_at(
    path: pathlib.Path,
    identity: tuple[int, int, int],
    parent_descriptor: int,
    root_descriptor: int,
    *,
    recovery_marker_payload: bytes | None = None,
) -> None:
    _validate_private_directory_metadata(
        os.fstat(parent_descriptor),
        "workspace cleanup parent",
    )
    path_metadata = os.stat(
        path.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    bound_root = os.fstat(root_descriptor)
    if (
        not os.path.samestat(path_metadata, bound_root)
        or (bound_root.st_dev, bound_root.st_ino, bound_root.st_uid) != identity
        or bound_root.st_uid != os.getuid()
        or stat.S_IMODE(bound_root.st_mode) != 0o700
    ):
        raise ReviewWorkspaceError(
            "workspace-cleanup-identity-mismatch",
            "workspace cleanup target differs from its bound private directory",
        )
    try:
        _clear_directory_descriptor(
            root_descriptor,
            path,
            bound_root.st_dev,
            retained_marker_path=(
                (".git", WORKSPACE_MARKER)
                if recovery_marker_payload is not None
                else None
            ),
        )
    except BaseException as primary_error:
        if recovery_marker_payload is not None:
            try:
                _ensure_cleanup_recovery_marker(
                    root_descriptor,
                    identity,
                    bound_root.st_dev,
                    recovery_marker_payload,
                )
            except BaseException as recovery_error:
                raise ReviewWorkspaceError(
                    "workspace-cleanup-recovery-marker-failed",
                    "workspace cleanup failed and its retry verifier could not be restored",
                    details={
                        "primary_reason": getattr(
                            primary_error,
                            "reason",
                            type(primary_error).__name__,
                        ),
                        "recovery_reason": getattr(
                            recovery_error,
                            "reason",
                            type(recovery_error).__name__,
                        ),
                    },
                ) from primary_error
        raise
    try:
        _finish_bound_directory_removal(
            path,
            identity,
            parent_descriptor,
            root_descriptor,
            bound_root,
        )
    except BaseException as primary_error:
        if recovery_marker_payload is not None:
            try:
                _ensure_cleanup_recovery_marker(
                    root_descriptor,
                    identity,
                    bound_root.st_dev,
                    recovery_marker_payload,
                )
            except BaseException as recovery_error:
                raise ReviewWorkspaceError(
                    "workspace-cleanup-recovery-marker-failed",
                    "workspace cleanup failed and its retry verifier could not be restored",
                    details={
                        "primary_reason": getattr(
                            primary_error,
                            "reason",
                            type(primary_error).__name__,
                        ),
                        "recovery_reason": getattr(
                            recovery_error,
                            "reason",
                            type(recovery_error).__name__,
                        ),
                    },
                ) from primary_error
        raise


def _remove_bound_directory(
    path: pathlib.Path,
    identity: tuple[int, int, int],
    *,
    recovery_marker_payload: bytes | None = None,
) -> None:
    parent_descriptor = os.open(path.parent, _nofollow_flags(directory=True))
    root_descriptor = -1
    operation_error: BaseException | None = None
    try:
        root_descriptor = os.open(
            path.name,
            _nofollow_flags(directory=True),
            dir_fd=parent_descriptor,
        )
        _remove_bound_directory_at(
            path,
            identity,
            parent_descriptor,
            root_descriptor,
            recovery_marker_payload=recovery_marker_payload,
        )
    except BaseException as error:
        operation_error = error
    root_to_close = root_descriptor
    parent_to_close = parent_descriptor
    root_descriptor = -1
    parent_descriptor = -1
    teardown_failures = _attempt_workspace_descriptor_closes(
        (
            (
                "workspace removal root descriptor close failed",
                root_to_close,
            ),
            (
                "workspace removal parent descriptor close failed",
                parent_to_close,
            ),
        )
    )
    if operation_error is not None:
        _attach_workspace_teardown_failures(operation_error, teardown_failures)
        raise operation_error
    teardown_error = _select_workspace_teardown_failure(teardown_failures)
    if teardown_error is not None:
        raise teardown_error


def _partial_recovery_tombstone_matches(
    path: pathlib.Path,
    root_descriptor: int,
    identity: tuple[int, int, int],
    marker_payload: bytes | None,
) -> bool:
    def directory_signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        )

    def file_signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
        )

    def validate_root_identity() -> tuple[os.stat_result, os.stat_result]:
        root_metadata = os.fstat(root_descriptor)
        path_metadata = path.stat(follow_symlinks=False)
        _validate_private_directory_metadata(
            root_metadata,
            "partial recovery tombstone",
        )
        _validate_no_extended_acl(root_descriptor, "partial recovery tombstone")
        if (
            not os.path.samestat(root_metadata, path_metadata)
            or (root_metadata.st_dev, root_metadata.st_ino, root_metadata.st_uid)
            != identity
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-workspace-identity-mismatch",
                "partial recovery tombstone differs from its bound workspace root",
            )
        return root_metadata, path_metadata

    root_metadata, root_path_metadata = validate_root_identity()
    root_entries = set(os.listdir(root_descriptor))
    if marker_payload is None:
        window_root_metadata = os.fstat(root_descriptor)
        final_entries = set(os.listdir(root_descriptor))
        final_root_metadata, final_root_path = validate_root_identity()
        return (
            not root_entries
            and not final_entries
            and directory_signature(root_metadata)
            == directory_signature(root_path_metadata)
            == directory_signature(window_root_metadata)
            == directory_signature(final_root_metadata)
            == directory_signature(final_root_path)
        )
    if root_entries != {".git"}:
        validate_root_identity()
        return False
    git_descriptor = os.open(
        ".git",
        _nofollow_flags(directory=True),
        dir_fd=root_descriptor,
    )
    marker_descriptor = -1
    try:
        git_metadata = os.fstat(git_descriptor)
        git_path_metadata = os.stat(
            ".git",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        _validate_private_directory_metadata(
            git_metadata,
            "partial recovery tombstone Git directory",
        )
        _validate_no_extended_acl(
            git_descriptor,
            "partial recovery tombstone Git directory",
        )
        if (
            not os.path.samestat(git_metadata, git_path_metadata)
            or directory_signature(git_metadata)
            != directory_signature(git_path_metadata)
            or set(os.listdir(git_descriptor)) != {WORKSPACE_MARKER}
        ):
            return False
        marker_descriptor = os.open(
            WORKSPACE_MARKER,
            _nofollow_flags(directory=False),
            dir_fd=git_descriptor,
        )
        marker_metadata = os.fstat(marker_descriptor)
        marker_path_metadata = os.stat(
            WORKSPACE_MARKER,
            dir_fd=git_descriptor,
            follow_symlinks=False,
        )
        _validate_no_extended_acl(
            marker_descriptor,
            "partial recovery tombstone marker",
        )
        if (
            not os.path.samestat(marker_metadata, marker_path_metadata)
            or file_signature(marker_metadata) != file_signature(marker_path_metadata)
            or not stat.S_ISREG(marker_metadata.st_mode)
            or marker_metadata.st_uid != os.getuid()
            or marker_metadata.st_nlink != 1
            or stat.S_IMODE(marker_metadata.st_mode) != 0o600
            or marker_metadata.st_size != len(marker_payload)
        ):
            return False
        os.lseek(marker_descriptor, 0, os.SEEK_SET)
        first_marker_payload = _read_descriptor_payload(
            marker_descriptor,
            MARKER_LIMIT_BYTES,
        )

        # Re-read every selected property after a late-entry window. The
        # retained descriptors bind the same root, .git directory, and marker.
        window_root_metadata = os.fstat(root_descriptor)
        final_root_entries = set(os.listdir(root_descriptor))
        window_git_metadata = os.fstat(git_descriptor)
        final_git_entries = set(os.listdir(git_descriptor))
        final_git_metadata = os.fstat(git_descriptor)
        final_git_path = os.stat(
            ".git",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        os.lseek(marker_descriptor, 0, os.SEEK_SET)
        final_marker_payload = _read_descriptor_payload(
            marker_descriptor,
            MARKER_LIMIT_BYTES,
        )
        final_marker_metadata = os.fstat(marker_descriptor)
        final_marker_path = os.stat(
            WORKSPACE_MARKER,
            dir_fd=git_descriptor,
            follow_symlinks=False,
        )
        terminal_git_entries = set(os.listdir(git_descriptor))
        terminal_git_metadata = os.fstat(git_descriptor)
        terminal_git_path = os.stat(
            ".git",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        _validate_private_directory_metadata(
            terminal_git_metadata,
            "partial recovery tombstone Git directory",
        )
        _validate_no_extended_acl(
            git_descriptor,
            "partial recovery tombstone Git directory",
        )
        _validate_no_extended_acl(
            marker_descriptor,
            "partial recovery tombstone marker",
        )
        final_root_metadata, final_root_path = validate_root_identity()
        return (
            final_root_entries == {".git"}
            and directory_signature(root_metadata)
            == directory_signature(root_path_metadata)
            == directory_signature(window_root_metadata)
            == directory_signature(final_root_metadata)
            == directory_signature(final_root_path)
            and os.path.samestat(git_metadata, final_git_metadata)
            and os.path.samestat(final_git_metadata, final_git_path)
            and os.path.samestat(final_git_metadata, terminal_git_metadata)
            and os.path.samestat(terminal_git_metadata, terminal_git_path)
            and directory_signature(git_metadata)
            == directory_signature(git_path_metadata)
            == directory_signature(window_git_metadata)
            == directory_signature(final_git_metadata)
            == directory_signature(final_git_path)
            == directory_signature(terminal_git_metadata)
            == directory_signature(terminal_git_path)
            and final_git_entries == {WORKSPACE_MARKER}
            and terminal_git_entries == {WORKSPACE_MARKER}
            and os.path.samestat(marker_metadata, final_marker_metadata)
            and os.path.samestat(final_marker_metadata, final_marker_path)
            and file_signature(marker_metadata)
            == file_signature(marker_path_metadata)
            == file_signature(final_marker_metadata)
            == file_signature(final_marker_path)
            and first_marker_payload == marker_payload
            and final_marker_payload == marker_payload
            and final_marker_metadata.st_uid == os.getuid()
            and final_marker_metadata.st_nlink == 1
            and stat.S_IMODE(final_marker_metadata.st_mode) == 0o600
        )
    finally:
        if marker_descriptor >= 0:
            os.close(marker_descriptor)
        os.close(git_descriptor)


def _clear_bound_partial_contents(
    path: pathlib.Path,
    root_descriptor: int,
    identity: tuple[int, int, int],
    *,
    recovery_marker_payload: bytes | None,
) -> None:
    """Remove payload while retaining the exact root as an idempotent tombstone."""

    bound_root = os.fstat(root_descriptor)
    path_metadata = path.stat(follow_symlinks=False)
    if (
        not os.path.samestat(bound_root, path_metadata)
        or (bound_root.st_dev, bound_root.st_ino, bound_root.st_uid) != identity
        or stat.S_IMODE(bound_root.st_mode) != 0o700
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-workspace-identity-mismatch",
            "partial recovery workspace differs from its bound private root",
        )
    try:
        _clear_directory_descriptor(
            root_descriptor,
            path,
            bound_root.st_dev,
            retained_marker_path=(
                (".git", WORKSPACE_MARKER)
                if recovery_marker_payload is not None
                else None
            ),
            preserve_retained_marker=recovery_marker_payload is not None,
        )
        if not _partial_recovery_tombstone_matches(
            path,
            root_descriptor,
            identity,
            recovery_marker_payload,
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-cleanup-incomplete",
                "partial recovery did not reach its authenticated tombstone state",
            )
        os.fsync(root_descriptor)
    except BaseException as primary_error:
        if recovery_marker_payload is not None:
            try:
                _ensure_cleanup_recovery_marker(
                    root_descriptor,
                    identity,
                    bound_root.st_dev,
                    recovery_marker_payload,
                )
            except BaseException as recovery_error:
                raise ReviewWorkspaceError(
                    "workspace-cleanup-recovery-marker-failed",
                    "partial recovery failed and its retry verifier could not be restored",
                    details={
                        "primary_reason": getattr(
                            primary_error,
                            "reason",
                            type(primary_error).__name__,
                        ),
                        "recovery_reason": getattr(
                            recovery_error,
                            "reason",
                            type(recovery_error).__name__,
                        ),
                    },
                ) from primary_error
        raise


def _remove_owned_partial(
    root: pathlib.Path,
    identity: tuple[int, int, int],
    *,
    primary_error: BaseException | None = None,
    recovery_marker_payload: bytes | None = None,
) -> None:
    signal_owner = _begin_forwarded_signal_mask()
    cleanup_error: BaseException | None = None
    try:
        _remove_bound_directory(
            root,
            identity,
            recovery_marker_payload=recovery_marker_payload,
        )
    except BaseException as error:
        cleanup_error = error
        raise
    finally:
        _finish_forwarded_signal_mask(
            signal_owner,
            primary_error=primary_error if primary_error is not None else cleanup_error,
        )


def _partial_control_identity(
    payload: Mapping[str, object],
    key: str,
) -> tuple[int, int, int]:
    value = payload.get(key)
    if not isinstance(value, dict) or set(value) != {"device", "inode", "uid"}:
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            f"partial recovery {key} is malformed",
        )
    fields = tuple(value.get(field) for field in ("device", "inode", "uid"))
    if any(type(field) is not int or field < 0 for field in fields):
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            f"partial recovery {key} is malformed",
        )
    return fields  # type: ignore[return-value]


def _partial_process_identity(
    payload: Mapping[str, object],
    key: str,
    *,
    require_group: bool,
) -> tuple[int, int | None, str]:
    value = payload.get(key)
    expected_keys = {"pid", "start_identity"}
    if require_group:
        expected_keys.add("pgid")
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            f"partial recovery {key} is malformed",
        )
    pid = value.get("pid")
    pgid = value.get("pgid") if require_group else None
    start_identity = value.get("start_identity")
    if (
        type(pid) is not int
        or pid <= 1
        or (require_group and (type(pgid) is not int or pgid != pid))
        or not isinstance(start_identity, str)
        or not start_identity
        or len(start_identity.encode("utf-8")) > 512
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            f"partial recovery {key} is malformed",
        )
    return pid, pgid, start_identity


def _partial_active_process_identity(
    payload: Mapping[str, object],
) -> tuple[int, int, str, str]:
    value = payload.get("active_process")
    expected_keys = {
        "pid",
        "pgid",
        "start_identity",
        "operation",
        "process_state",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            "partial recovery active_process is malformed",
        )
    pid = value.get("pid")
    pgid = value.get("pgid")
    start_identity = value.get("start_identity")
    operation = value.get("operation")
    if (
        type(pid) is not int
        or pid <= 1
        or type(pgid) is not int
        or pgid != pid
        or not isinstance(start_identity, str)
        or not start_identity
        or len(start_identity.encode("utf-8")) > 512
        or not isinstance(operation, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", operation) is None
        or value.get("process_state") != "quiescence-unproven"
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            "partial recovery active_process is malformed",
        )
    return pid, pgid, start_identity, operation


def _assert_no_bound_partial_recovery_control(
    root: pathlib.Path,
    workspace_identity: tuple[int, int, int],
    parent_descriptor: int,
) -> None:
    def protected_file_signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
        )

    candidates: list[str] = []
    with os.scandir(parent_descriptor) as entries:
        for entry in entries:
            if entry.name.startswith(PARTIAL_RECOVERY_PREFIX) and entry.name.endswith(
                ".json"
            ):
                candidates.append(entry.name)
                if len(candidates) > 4096:
                    raise ReviewWorkspaceError(
                        "partial-recovery-control-limit",
                        "workspace parent contains too many partial recovery controls",
                    )
    for leaf in candidates:
        descriptor = os.open(
            leaf,
            _nofollow_flags(directory=False),
            dir_fd=parent_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                leaf,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size <= 0
                or metadata.st_size > MARKER_LIMIT_BYTES
                or not os.path.samestat(metadata, path_metadata)
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "ordinary cleanup found an unverifiable partial recovery control",
                    details={"control_file": str(root.parent / leaf)},
                )
            try:
                _validate_no_extended_acl(descriptor, "partial recovery control")
                os.lseek(descriptor, 0, os.SEEK_SET)
                first = _read_descriptor_payload(descriptor, MARKER_LIMIT_BYTES)
                os.lseek(descriptor, 0, os.SEEK_SET)
                second = _read_descriptor_payload(descriptor, MARKER_LIMIT_BYTES)
                final_metadata = os.fstat(descriptor)
                final_path = os.stat(
                    leaf,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                _validate_no_extended_acl(descriptor, "partial recovery control")
            except OSError as error:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "ordinary cleanup could not completely read the partial recovery control",
                    status="inconclusive",
                    details={"control_file": str(root.parent / leaf)},
                ) from error
            if (
                first != second
                or len(first) != metadata.st_size
                or not os.path.samestat(metadata, final_metadata)
                or not os.path.samestat(final_metadata, final_path)
                or protected_file_signature(metadata)
                != protected_file_signature(final_metadata)
                or protected_file_signature(final_metadata)
                != protected_file_signature(final_path)
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "partial recovery control changed during ordinary cleanup preflight",
                    details={"control_file": str(root.parent / leaf)},
                )
            try:
                payload = json.loads(first)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "ordinary cleanup found a malformed partial recovery control",
                    details={"control_file": str(root.parent / leaf)},
                ) from error
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version") != PARTIAL_RECOVERY_SCHEMA_VERSION
                or payload.get("state")
                not in {
                    "armed",
                    "process-bound",
                    "retained-quiescence-unproven",
                    "retained-owner-exit-required",
                }
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "ordinary cleanup found an unsupported partial recovery control",
                    details={"control_file": str(root.parent / leaf)},
                )
            control_identity = _partial_control_identity(
                payload,
                "control_identity",
            )
            if control_identity != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-unverifiable",
                    "partial recovery control identity is inconsistent",
                    details={"control_file": str(root.parent / leaf)},
                )
            if (
                _partial_control_identity(payload, "workspace_identity")
                == workspace_identity
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-required",
                    "ordinary cleanup is unavailable for this retained workspace",
                    status="inconclusive",
                    details={
                        "cleanup_unavailable_until_quiescent": True,
                        "control_file": str(root.parent / leaf),
                        "instruction": (
                            "Use the exact recover-partial-workspace argv from the "
                            "failure receipt; do not invoke cleanup-workspace."
                        ),
                    },
                )
        finally:
            os.close(descriptor)


def recover_partial_workspace(
    control_file: pathlib.Path,
    control_sha256: str,
    *,
    defer_signal_handoff: bool = False,
) -> CleanedWorkspace:
    """Remove an exact retained workspace only after process closure is proved."""

    if os.name != "posix":
        raise ReviewWorkspaceError(
            "partial-recovery-unsupported",
            "partial recovery requires POSIX process-group semantics",
        )
    if (
        not isinstance(control_sha256, str)
        or CLEANUP_TOKEN_SHA256.fullmatch(control_sha256) is None
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            "partial recovery control digest is malformed",
        )
    if (
        not control_file.is_absolute()
        or not control_file.name.startswith(PARTIAL_RECOVERY_PREFIX)
        or control_file.suffix != ".json"
    ):
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            "partial recovery control path is invalid",
        )
    parent = _absolute_existing_directory(
        control_file.parent,
        "partial recovery parent",
    )
    if parent != control_file.parent:
        raise ReviewWorkspaceError(
            "partial-recovery-control-invalid",
            "partial recovery control parent is not canonical",
        )
    signal_owner = _begin_forwarded_signal_mask()
    parent_descriptor = -1
    control_descriptor = -1
    root_descriptor = -1
    parent_locked = False
    cleaned: CleanedWorkspace | None = None
    operation_error: BaseException | None = None

    def control_metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
        )

    try:
        parent_descriptor = os.open(parent, _nofollow_flags(directory=True))
        fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
        parent_locked = True
        parent_metadata = os.fstat(parent_descriptor)
        _validate_private_directory_metadata(
            parent_metadata,
            "partial recovery parent",
        )
        _validate_no_extended_acl(parent_descriptor, "partial recovery parent")
        control_descriptor = os.open(
            control_file.name,
            _nofollow_flags(directory=False),
            dir_fd=parent_descriptor,
        )
        control_metadata = os.fstat(control_descriptor)
        if (
            not stat.S_ISREG(control_metadata.st_mode)
            or control_metadata.st_uid != os.getuid()
            or control_metadata.st_nlink != 1
            or stat.S_IMODE(control_metadata.st_mode) != 0o600
            or control_metadata.st_size <= 0
            or control_metadata.st_size > MARKER_LIMIT_BYTES
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-policy",
                "partial recovery control is not an owner-held bounded mode-0600 file",
            )
        _validate_no_extended_acl(control_descriptor, "partial recovery control")
        try:
            chunks = bytearray()
            while len(chunks) <= MARKER_LIMIT_BYTES:
                chunk = os.read(
                    control_descriptor,
                    min(64 * 1024, MARKER_LIMIT_BYTES + 1),
                )
                if not chunk:
                    break
                chunks.extend(chunk)
            initial_control_after_read = os.fstat(control_descriptor)
            initial_control_path = os.stat(
                control_file.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _validate_no_extended_acl(
                control_descriptor,
                "partial recovery control",
            )
        except OSError as error:
            raise ReviewWorkspaceError(
                "partial-recovery-control-unavailable",
                "partial recovery control could not be completely read",
                status="inconclusive",
            ) from error
        if (
            len(chunks) != control_metadata.st_size
            or len(chunks) > MARKER_LIMIT_BYTES
            or not os.path.samestat(control_metadata, initial_control_after_read)
            or not os.path.samestat(initial_control_after_read, initial_control_path)
            or control_metadata_signature(control_metadata)
            != control_metadata_signature(initial_control_after_read)
            or control_metadata_signature(initial_control_after_read)
            != control_metadata_signature(initial_control_path)
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-drift",
                "partial recovery control changed while it was read",
            )
        timestamp_changed = (
            control_metadata.st_mtime_ns != initial_control_after_read.st_mtime_ns
            or control_metadata.st_ctime_ns != initial_control_after_read.st_ctime_ns
            or initial_control_path.st_mtime_ns
            != initial_control_after_read.st_mtime_ns
            or initial_control_path.st_ctime_ns
            != initial_control_after_read.st_ctime_ns
        )
        if timestamp_changed:
            try:
                os.lseek(control_descriptor, 0, os.SEEK_SET)
                repeated_chunks = _read_descriptor_payload(
                    control_descriptor,
                    MARKER_LIMIT_BYTES,
                )
                repeated_metadata = os.fstat(control_descriptor)
                repeated_path = os.stat(
                    control_file.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                _validate_no_extended_acl(
                    control_descriptor,
                    "partial recovery control",
                )
            except OSError as error:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-revalidation-unavailable",
                    "partial recovery control could not be completely revalidated",
                    status="inconclusive",
                ) from error
            if (
                repeated_chunks != chunks
                or not os.path.samestat(
                    initial_control_after_read,
                    repeated_metadata,
                )
                or not os.path.samestat(repeated_metadata, repeated_path)
                or control_metadata_signature(initial_control_after_read)
                != control_metadata_signature(repeated_metadata)
                or control_metadata_signature(repeated_metadata)
                != control_metadata_signature(repeated_path)
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-drift",
                    "partial recovery control changed during bounded revalidation",
                )
            if (
                repeated_metadata.st_mtime_ns != initial_control_path.st_mtime_ns
                or repeated_metadata.st_ctime_ns != initial_control_path.st_ctime_ns
                or repeated_path.st_mtime_ns != repeated_metadata.st_mtime_ns
                or repeated_path.st_ctime_ns != repeated_metadata.st_ctime_ns
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-revalidation-unavailable",
                    (
                        "partial recovery control timestamp state changed during "
                        "bounded revalidation"
                    ),
                    status="inconclusive",
                )
            initial_control_after_read = repeated_metadata
            initial_control_path = repeated_path
        observed_digest = hashlib.sha256(chunks).hexdigest()
        if not secrets.compare_digest(observed_digest, control_sha256):
            raise ReviewWorkspaceError(
                "partial-recovery-control-digest-mismatch",
                "partial recovery control does not match the terminal receipt",
            )
        try:
            payload = json.loads(chunks)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery control JSON is malformed",
            ) from error
        expected_keys = {
            "schema_version",
            "control_id",
            "control_identity",
            "worktree",
            "parent_identity",
            "workspace_identity",
            "workspace_state",
            "owner_process",
            "active_process",
            "state",
        }
        recovery_state = payload.get("state") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or set(payload) != expected_keys
            or payload.get("schema_version") != PARTIAL_RECOVERY_SCHEMA_VERSION
            or recovery_state
            not in {
                "retained-quiescence-unproven",
                "retained-owner-exit-required",
            }
            or not isinstance(payload.get("control_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["control_id"]) is None
            or (
                recovery_state == "retained-owner-exit-required"
                and payload.get("active_process") is not None
            )
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery control schema is invalid",
            )
        control_identity = _partial_control_identity(payload, "control_identity")
        if control_identity != (
            control_metadata.st_dev,
            control_metadata.st_ino,
            control_metadata.st_uid,
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-identity-mismatch",
                "partial recovery control identity changed",
            )
        parent_identity = _partial_control_identity(payload, "parent_identity")
        workspace_identity = _partial_control_identity(payload, "workspace_identity")
        if parent_identity != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
            parent_metadata.st_uid,
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-parent-identity-mismatch",
                "partial recovery parent identity changed",
            )
        worktree_value = payload.get("worktree")
        if not isinstance(worktree_value, str):
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery worktree path is malformed",
            )
        root = pathlib.Path(worktree_value)
        if (
            not root.is_absolute()
            or root.parent != parent
            or root.name in {"", ".", ".."}
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery worktree path is invalid",
            )
        root_descriptor = os.open(
            root.name,
            _nofollow_flags(directory=True),
            dir_fd=parent_descriptor,
        )

        workspace_state = payload.get("workspace_state")
        if not isinstance(workspace_state, dict):
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery workspace state is malformed",
            )
        formal_marker_payload: bytes | None = None

        def validate_recoverable_root() -> None:
            nonlocal formal_marker_payload
            root_metadata = os.fstat(root_descriptor)
            path_metadata = os.stat(
                root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _validate_private_directory_metadata(
                root_metadata,
                "partial recovery workspace",
            )
            _validate_no_extended_acl(
                root_descriptor,
                "partial recovery workspace",
            )
            if (
                root_metadata.st_dev,
                root_metadata.st_ino,
                root_metadata.st_uid,
            ) != workspace_identity or not os.path.samestat(
                root_metadata, path_metadata
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-workspace-identity-mismatch",
                    "partial recovery workspace identity changed",
                )
            try:
                marker = _snapshot_control_file(
                    root_descriptor,
                    (".git", WORKSPACE_MARKER),
                    capture_payload=True,
                )
            except FileNotFoundError:
                marker = None
            kind = workspace_state.get("kind")
            if kind == "unpublished-markerless":
                if set(workspace_state) != {"kind"} or marker is not None:
                    raise ReviewWorkspaceError(
                        "partial-recovery-workspace-state-mismatch",
                        "unpublished partial workspace state changed",
                    )
                formal_marker_payload = None
            elif kind == "formal-marked":
                if set(workspace_state) != {
                    "kind",
                    "marker_sha256",
                }:
                    raise ReviewWorkspaceError(
                        "partial-recovery-control-invalid",
                        "formal workspace state binding is malformed",
                    )
                marker_sha256 = workspace_state.get("marker_sha256")
                if (
                    marker is None
                    or marker.payload is None
                    or not isinstance(marker_sha256, str)
                    or CLEANUP_TOKEN_SHA256.fullmatch(marker_sha256) is None
                    or not secrets.compare_digest(marker.sha256, marker_sha256)
                ):
                    raise ReviewWorkspaceError(
                        "partial-recovery-workspace-state-mismatch",
                        "formal workspace marker identity or content changed",
                    )
                formal_marker_payload = marker.payload
            else:
                raise ReviewWorkspaceError(
                    "partial-recovery-control-invalid",
                    "partial recovery workspace state kind is invalid",
                )

        kind = workspace_state.get("kind")
        if kind == "unpublished-markerless":
            terminal_marker_payload: bytes | None = None
            terminal_marker_available = True
        elif kind == "formal-marked":
            marker_sha256 = workspace_state.get("marker_sha256")
            if (
                set(workspace_state) != {"kind", "marker_sha256"}
                or not isinstance(marker_sha256, str)
                or CLEANUP_TOKEN_SHA256.fullmatch(marker_sha256) is None
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-control-invalid",
                    "formal workspace state binding is malformed",
                )
            try:
                terminal_marker = _snapshot_control_file(
                    root_descriptor,
                    (".git", WORKSPACE_MARKER),
                    capture_payload=True,
                )
            except FileNotFoundError:
                terminal_marker_payload = None
                terminal_marker_available = False
            else:
                terminal_marker_payload = terminal_marker.payload
                terminal_marker_available = bool(
                    terminal_marker_payload is not None
                    and secrets.compare_digest(
                        terminal_marker.sha256,
                        marker_sha256,
                    )
                )
                if terminal_marker_payload is None:
                    terminal_marker_available = False
                elif not terminal_marker_available:
                    terminal_marker_payload = None
        else:
            raise ReviewWorkspaceError(
                "partial-recovery-control-invalid",
                "partial recovery workspace state kind is invalid",
            )
        tombstone_complete = terminal_marker_available and (
            _partial_recovery_tombstone_matches(
                root,
                root_descriptor,
                workspace_identity,
                terminal_marker_payload,
            )
        )
        if not tombstone_complete:
            validate_recoverable_root()
        owner_pid, _owner_pgid, owner_start = _partial_process_identity(
            payload,
            "owner_process",
            require_group=False,
        )
        active_process: tuple[int, int, str, str] | None
        if recovery_state == "retained-quiescence-unproven":
            active_process = _partial_active_process_identity(payload)
        else:
            active_process = None
        try:
            observed_owner_start = _process_start_identity(owner_pid)
        except ProcessLookupError:
            observed_owner_start = None
        if observed_owner_start is not None and secrets.compare_digest(
            observed_owner_start,
            owner_start,
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-owner-active",
                "the original prepare process is still active; retry later",
                status="inconclusive",
                details={"retryable": True},
            )
        if active_process is not None:
            active_pid, active_pgid, active_start, _active_operation = active_process
            try:
                observed_active_start = _process_start_identity(active_pid)
            except ProcessLookupError:
                observed_active_start = None
            if observed_active_start is not None and secrets.compare_digest(
                observed_active_start,
                active_start,
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-process-active",
                    "the retained workspace process is still active; retry later",
                    status="inconclusive",
                    details={"retryable": True},
                )
            if _process_group_exists(active_pgid):
                raise ReviewWorkspaceError(
                    "partial-recovery-process-group-active",
                    "the retained workspace process group is still active; retry later",
                    status="inconclusive",
                    details={"retryable": True},
                )
            try:
                final_active_start = _process_start_identity(active_pid)
            except ProcessLookupError:
                final_active_start = None
            if final_active_start is not None and secrets.compare_digest(
                final_active_start,
                active_start,
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-process-active",
                    "the retained workspace process became active during recovery",
                    status="inconclusive",
                    details={"retryable": True},
                )
        if tombstone_complete:
            if not _partial_recovery_tombstone_matches(
                root,
                root_descriptor,
                workspace_identity,
                terminal_marker_payload,
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-workspace-state-mismatch",
                    "partial recovery tombstone changed during recovery",
                )
        else:
            validate_recoverable_root()
            _clear_bound_partial_contents(
                root,
                root_descriptor,
                workspace_identity,
                recovery_marker_payload=formal_marker_payload,
            )
            if not _partial_recovery_tombstone_matches(
                root,
                root_descriptor,
                workspace_identity,
                formal_marker_payload,
            ):
                raise ReviewWorkspaceError(
                    "partial-recovery-cleanup-incomplete",
                    "partial recovery tombstone changed after payload removal",
                )
        try:
            terminal_control_metadata = os.fstat(control_descriptor)
            os.lseek(control_descriptor, 0, os.SEEK_SET)
            terminal_control_payload = _read_descriptor_payload(
                control_descriptor,
                MARKER_LIMIT_BYTES,
            )
            os.lseek(control_descriptor, 0, os.SEEK_SET)
            confirmed_control_payload = _read_descriptor_payload(
                control_descriptor,
                MARKER_LIMIT_BYTES,
            )
            final_control_metadata = os.fstat(control_descriptor)
            final_control_path = os.stat(
                control_file.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ReviewWorkspaceError(
                "partial-recovery-control-revalidation-unavailable",
                "partial recovery control could not be revalidated before receipt",
                status="inconclusive",
            ) from error
        _validate_no_extended_acl(control_descriptor, "partial recovery control")
        if (
            terminal_control_payload != chunks
            or confirmed_control_payload != terminal_control_payload
            or not secrets.compare_digest(
                hashlib.sha256(terminal_control_payload).hexdigest(),
                control_sha256,
            )
            or terminal_control_metadata.st_size != len(terminal_control_payload)
            or not stat.S_ISREG(final_control_metadata.st_mode)
            or final_control_metadata.st_uid != os.getuid()
            or final_control_metadata.st_nlink != 1
            or stat.S_IMODE(final_control_metadata.st_mode) != 0o600
            or not os.path.samestat(control_metadata, terminal_control_metadata)
            or not os.path.samestat(
                terminal_control_metadata,
                final_control_metadata,
            )
            or not os.path.samestat(final_control_metadata, final_control_path)
            or control_metadata_signature(control_metadata)
            != control_metadata_signature(initial_control_after_read)
            or control_metadata_signature(initial_control_after_read)
            != control_metadata_signature(initial_control_path)
            or control_metadata_signature(initial_control_path)
            != control_metadata_signature(terminal_control_metadata)
            or control_metadata_signature(terminal_control_metadata)
            != control_metadata_signature(final_control_metadata)
            or control_metadata_signature(final_control_metadata)
            != control_metadata_signature(final_control_path)
        ):
            raise ReviewWorkspaceError(
                "partial-recovery-control-drift",
                "partial recovery control changed before terminal receipt",
            )
        cleaned = CleanedWorkspace(
            root=root,
            command="recover-partial-workspace",
            cleanup_status=(
                "already-clean" if tombstone_complete else "payload-removed"
            ),
            tombstone_status="retained",
            _handoff_signal_mask=signal_owner if defer_signal_handoff else None,
        )
    except BaseException as error:
        operation_error = error
    teardown_failures: list[tuple[str, BaseException]] = []
    if parent_locked:
        try:
            fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
        except BaseException as unlock_error:
            teardown_failures.append(
                ("partial recovery parent unlock failed", unlock_error)
            )
        parent_locked = False
    root_to_close = root_descriptor
    control_to_close = control_descriptor
    parent_to_close = parent_descriptor
    root_descriptor = -1
    control_descriptor = -1
    parent_descriptor = -1
    teardown_failures.extend(
        _attempt_workspace_descriptor_closes(
            (
                (
                    "partial recovery workspace root descriptor close failed",
                    root_to_close,
                ),
                (
                    "partial recovery control descriptor close failed",
                    control_to_close,
                ),
                (
                    "partial recovery parent descriptor close failed",
                    parent_to_close,
                ),
            )
        )
    )
    selected_error = operation_error
    if selected_error is not None:
        _attach_workspace_teardown_failures(selected_error, teardown_failures)
    else:
        selected_error = _select_workspace_teardown_failure(teardown_failures)
    if defer_signal_handoff and selected_error is None:
        assert cleaned is not None
        return cleaned
    _finish_forwarded_signal_mask(
        signal_owner,
        primary_error=selected_error,
    )
    if selected_error is not None:
        raise selected_error
    assert cleaned is not None
    return cleaned


def _rename_exclusive(
    parent_descriptor: int,
    source: pathlib.Path,
    destination: pathlib.Path,
    expected_parent_identity: tuple[int, int, int],
    expected_source_identity: tuple[int, int, int],
) -> None:
    if source.parent != destination.parent:
        raise ReviewWorkspaceError(
            "workspace-cleanup-rename-invalid",
            "workspace cleanup rename must remain within one bound parent",
        )
    parent_metadata = os.fstat(parent_descriptor)
    source_metadata = os.stat(
        source.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    _validate_private_directory_metadata(parent_metadata, "workspace cleanup parent")
    _validate_no_extended_acl(parent_descriptor, "workspace cleanup parent")
    if (
        (parent_metadata.st_dev, parent_metadata.st_ino, parent_metadata.st_uid)
        != expected_parent_identity
        or not stat.S_ISDIR(source_metadata.st_mode)
        or (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_uid,
        )
        != expected_source_identity
        or stat.S_IMODE(source_metadata.st_mode) != 0o700
    ):
        raise ReviewWorkspaceError(
            "workspace-cleanup-rename-invalid",
            "workspace cleanup source differs from its descriptor-bound identity",
        )
    library = ctypes.CDLL(None, use_errno=True)
    if os.uname().sysname == "Darwin" and hasattr(library, "renameatx_np"):
        renameatx_np = library.renameatx_np
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_descriptor,
            os.fsencode(source.name),
            parent_descriptor,
            os.fsencode(destination.name),
            0x00000004 | 0x00000010,
        )
    elif hasattr(library, "renameat2"):
        renameat2 = library.renameat2
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            os.fsencode(source.name),
            parent_descriptor,
            os.fsencode(destination.name),
            1,
        )
    else:
        raise ReviewWorkspaceError(
            "workspace-exclusive-rename-unavailable",
            "host does not expose an exclusive workspace rename primitive",
        )
    if result != 0:
        rename_errno = ctypes.get_errno()
        raise ReviewWorkspaceError(
            "workspace-cleanup-rename-failed",
            "workspace cleanup could not acquire an exclusive quarantine name",
            details={"errno": rename_errno},
        )
    destination_metadata = os.stat(
        destination.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        destination_metadata.st_dev,
        destination_metadata.st_ino,
        destination_metadata.st_uid,
    ) != expected_source_identity:
        raise ReviewWorkspaceError(
            "workspace-cleanup-rename-invalid",
            "workspace cleanup quarantine differs from the bound source",
        )


def _workspace_recovery_locator(
    root: pathlib.Path,
    parent_identity: tuple[int, int, int],
    workspace_identity: tuple[int, int, int] | None,
    *,
    quarantine: pathlib.Path | None = None,
    retained_candidate: pathlib.Path | None = None,
) -> dict[str, object]:
    try:
        current_parent_identity = _private_directory_identity(
            root.parent,
            "workspace parent",
            reason="workspace-parent-policy",
        )
    except ReviewWorkspaceError:
        current_parent_identity = None
    if current_parent_identity == parent_identity and workspace_identity is not None:
        for candidate in (root, quarantine, retained_candidate):
            if candidate is None:
                continue
            if candidate.parent != root.parent:
                continue
            try:
                candidate_metadata = candidate.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISDIR(candidate_metadata.st_mode):
                continue
            candidate_identity = (
                candidate_metadata.st_dev,
                candidate_metadata.st_ino,
                candidate_metadata.st_uid,
            )
            if candidate_identity == workspace_identity:
                return {
                    "retained_path": str(candidate),
                    "retained_mode": stat.S_IMODE(candidate_metadata.st_mode),
                }
    return {
        "expected_locator": {
            "parent": str(root.parent),
            "leaf": root.name,
            "parent_identity": {
                "device": parent_identity[0],
                "inode": parent_identity[1],
                "uid": parent_identity[2],
            },
            "workspace_identity": None
            if workspace_identity is None
            else {
                "device": workspace_identity[0],
                "inode": workspace_identity[1],
                "uid": workspace_identity[2],
            },
        }
    }


@_requires_validated_git
def prepare_workspace(
    source: pathlib.Path,
    worktree: pathlib.Path,
    base: str,
    head: str,
    *,
    defer_signal_handoff: bool = False,
) -> PreparedWorkspace:
    object_store_deadline = time.monotonic() + WORKSPACE_PREPARATION_DEADLINE_SECONDS
    source_repo = _discover_source(source, object_store_deadline)
    _revalidate_source_repository(source_repo, object_store_deadline)
    (
        base,
        head,
        commit_count,
        range_objects,
        support_objects,
        shallow_boundaries,
    ) = _freeze_range(
        source_repo.root,
        source_repo.object_format,
        base,
        head,
        shallow=source_repo.shallow_path is not None,
        promisor=source_repo.promisor,
        shallow_boundaries=_parse_source_shallow_boundaries(
            source_repo.shallow_payload,
            source_repo.object_format,
            shallow=source_repo.shallow_path is not None,
        ),
        deadline=object_store_deadline,
    )
    _revalidate_source_repository(source_repo, object_store_deadline)
    range_object_count = len(range_objects)
    parent_support_object_count = len(support_objects)
    parent, root = _destination_path(worktree)
    parent_identity = _private_directory_identity(
        parent,
        "workspace parent",
        reason="workspace-parent-policy",
    )
    creation_mask = _begin_forwarded_signal_mask()
    identity: tuple[int, int, int] | None = None
    created = False
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    marker_payload: bytes | None = None
    try:
        parent_descriptor = os.open(parent, _nofollow_flags(directory=True))
        bound_parent = os.fstat(parent_descriptor)
        _validate_private_directory_metadata(bound_parent, "workspace parent")
        if (
            bound_parent.st_dev,
            bound_parent.st_ino,
            bound_parent.st_uid,
        ) != parent_identity:
            raise ReviewWorkspaceError(
                "workspace-parent-identity-mismatch",
                "workspace parent identity changed before workspace creation",
            )
        _reject_destination_source_overlap(
            parent_descriptor,
            source_repo.authorities,
        )
        _revalidate_source_repository(source_repo, object_store_deadline)
        os.mkdir(root.name, mode=0o700, dir_fd=parent_descriptor)
        created = True
        created_metadata = os.stat(
            root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(created_metadata.st_mode)
            or created_metadata.st_uid != os.getuid()
            or stat.S_IMODE(created_metadata.st_mode) != 0o700
        ):
            raise ReviewWorkspaceError(
                "workspace-owner-mismatch",
                "new workspace root is not an owner-private mode-0700 directory",
            )
        identity = (
            created_metadata.st_dev,
            created_metadata.st_ino,
            created_metadata.st_uid,
        )
        root_descriptor = os.open(
            root.name,
            _nofollow_flags(directory=True),
            dir_fd=parent_descriptor,
        )
        root_metadata = os.fstat(root_descriptor)
        opened_identity = (
            root_metadata.st_dev,
            root_metadata.st_ino,
            root_metadata.st_uid,
        )
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ReviewWorkspaceError(
                "workspace-owner-mismatch",
                "workspace root is not an owner-private mode-0700 directory",
            )
        if opened_identity != identity:
            raise ReviewWorkspaceError(
                "workspace-identity-mismatch",
                "workspace root changed between creation and descriptor custody",
            )
        final_parent = os.fstat(parent_descriptor)
        _validate_private_directory_metadata(final_parent, "workspace parent")
        if (
            _private_directory_identity(
                root,
                "workspace root",
                reason="workspace-owner-mismatch",
            )
            != identity
            or _private_directory_identity(
                parent,
                "workspace parent",
                reason="workspace-parent-policy",
            )
            != parent_identity
            or (
                final_parent.st_dev,
                final_parent.st_ino,
                final_parent.st_uid,
            )
            != parent_identity
        ):
            raise ReviewWorkspaceError(
                "workspace-identity-mismatch",
                "workspace identity changed during workspace creation",
            )
    except BaseException as primary_error:
        if root_descriptor is not None:
            try:
                os.close(root_descriptor)
            except OSError:
                pass
            root_descriptor = None
        cleanup_error: BaseException | None = None
        if identity is not None:
            try:
                _remove_owned_partial(
                    root,
                    identity,
                    primary_error=primary_error,
                )
            except BaseException as error:
                cleanup_error = error
        elif created and parent_descriptor is not None:
            try:
                os.rmdir(root.name, dir_fd=parent_descriptor)
            except BaseException as error:
                cleanup_error = error
        if cleanup_error is not None:
            failure = ReviewWorkspaceError(
                "workspace-publication-rollback-incomplete",
                "workspace creation failed and its partial root could not be removed",
                details={
                    "primary_reason": getattr(
                        primary_error,
                        "reason",
                        type(primary_error).__name__,
                    ),
                    "cleanup_reason": getattr(
                        cleanup_error,
                        "reason",
                        type(cleanup_error).__name__,
                    ),
                    **_workspace_recovery_locator(
                        root,
                        parent_identity,
                        identity,
                    ),
                },
            )
            _bind_workspace_failure_cause(
                failure,
                primary_error,
                context="workspace creation failure preceded rollback failure",
            )
            _finish_forwarded_signal_mask(
                creation_mask,
                primary_error=failure,
            )
            raise failure
        _finish_forwarded_signal_mask(
            creation_mask,
            primary_error=primary_error,
        )
        raise
    finally:
        if root_descriptor is not None:
            try:
                os.close(root_descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
    try:
        _finish_forwarded_signal_mask(creation_mask, primary_error=None)
        assert identity is not None
        (
            strategy,
            config_sha256,
            shallow_bytes,
            shallow_sha256,
            range_object_sha256,
            parent_support_object_sha256,
        ) = _initialize_git_directory(
            root,
            source_repo,
            base,
            head,
            range_objects,
            support_objects,
            shallow_boundaries,
            object_store_deadline,
        )
        _checkout_head(root, head)
        # argparse treats a separate option value that begins with "-" as a new
        # option. Prefix the still-unguessable random value so every preparation
        # receipt can be passed back through the documented ``--token VALUE``
        # CLI form without probabilistic parsing failures.
        cleanup_token = CLEANUP_TOKEN_PREFIX + secrets.token_urlsafe(32)
        cleanup_token_sha256 = _cleanup_token_digest(cleanup_token)
        git_identity = _directory_identity(root / ".git")
        objects_identity = _directory_identity(root / ".git/objects")
        marker = {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "worktree": str(root),
            "base": base,
            "head": head,
            "object_format": source_repo.object_format,
            "strategy": strategy,
            "source_shallow": source_repo.shallow_path is not None,
            "commit_count": commit_count,
            "range_object_count": range_object_count,
            "range_object_sha256": range_object_sha256,
            "parent_support_object_count": parent_support_object_count,
            "parent_support_object_sha256": parent_support_object_sha256,
            "config_sha256": config_sha256,
            "shallow_bytes": shallow_bytes,
            "shallow_sha256": shallow_sha256,
            "cleanup_token_sha256": cleanup_token_sha256,
            "parent_identity": {
                "device": parent_identity[0],
                "inode": parent_identity[1],
                "uid": parent_identity[2],
            },
            "workspace_identity": {
                "device": identity[0],
                "inode": identity[1],
                "uid": identity[2],
            },
            "git_identity": {
                "device": git_identity[0],
                "inode": git_identity[1],
                "uid": git_identity[2],
            },
            "objects_identity": {
                "device": objects_identity[0],
                "inode": objects_identity[1],
                "uid": objects_identity[2],
            },
        }
        serialized_marker_payload = (json.dumps(marker, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        _write_bytes(
            root / ".git" / WORKSPACE_MARKER,
            serialized_marker_payload,
            0o600,
        )
        marker_payload = serialized_marker_payload
        handoff_mask = _begin_forwarded_signal_mask()
        try:
            validated = validate_workspace(
                root,
                base,
                head,
                expected_cleanup_token=cleanup_token,
            )
            _revalidate_source_repository(source_repo, object_store_deadline)
            try:
                source_authority_binding = _source_authority_binding_payload(
                    source_repo
                )
                source_authority_binding_bytes = (
                    canonical_source_authority_binding_bytes(source_authority_binding)
                )
                source_authority_binding_sha256 = hashlib.sha256(
                    source_authority_binding_bytes
                ).hexdigest()
                parse_canonical_source_authority_binding_bytes(
                    source_authority_binding_bytes,
                    source_authority_binding_sha256,
                )
            except SourceAuthorityPathEncodingError as error:
                raise ReviewWorkspaceError(
                    "source-authority-path-encoding-unsupported",
                    "source authority paths must be valid UTF-8 for the closed "
                    "prepare-workspace receipt binding",
                    details={
                        "binding_path_encoding": (
                            SOURCE_AUTHORITY_BINDING_PATH_ENCODING
                        )
                    },
                ) from error
            except SourceAuthorityBindingError as error:
                raise ReviewWorkspaceError(
                    "source-authority-binding-invalid",
                    "source authorities cannot be published as the closed "
                    "prepare-workspace receipt binding",
                ) from error
            prepared = PreparedWorkspace(
                root=root,
                base_sha=base,
                head_sha=head,
                object_format=validated.object_format,
                strategy=validated.strategy,
                source_shallow=validated.source_shallow,
                commit_count=validated.commit_count,
                range_object_count=validated.range_object_count,
                range_object_sha256=validated.range_object_sha256,
                parent_support_object_count=(validated.parent_support_object_count),
                parent_support_object_sha256=(validated.parent_support_object_sha256),
                config_sha256=validated.config_sha256,
                shallow_bytes=validated.shallow_bytes,
                shallow_sha256=validated.shallow_sha256,
                cleanup_token=cleanup_token,
                parent_identity=parent_identity,
                workspace_identity=identity,
                git_identity=validated.git_identity,
                objects_identity=validated.objects_identity,
                marker_sha256=validated.marker_sha256,
                cleanup_token_sha256=validated.cleanup_token_sha256,
                _source_authority_binding_bytes=source_authority_binding_bytes,
                source_authority_binding_sha256=(source_authority_binding_sha256),
                _handoff_signal_mask=handoff_mask if defer_signal_handoff else None,
            )
        except BaseException as primary_error:
            _finish_forwarded_signal_mask(
                handoff_mask,
                primary_error=primary_error,
            )
            raise
        if defer_signal_handoff:
            return prepared
        _finish_forwarded_signal_mask(handoff_mask, primary_error=None)
        return prepared
    except BaseException as primary_error:
        if _partial_workspace_requires_retention(primary_error):
            pack_recovery = _partial_workspace_recovery_payload(primary_error) or {}
            recovery_locator = _workspace_recovery_locator(
                root,
                parent_identity,
                identity,
            )
            recovery_route = pack_recovery.get("recovery")
            if not isinstance(recovery_route, dict):
                recovery_route = {
                    "command": None,
                    "argv_ready": False,
                    "requires_quiescence_proof": True,
                    "ordinary_cleanup_available": False,
                    "instruction": (
                        "Do not invoke cleanup-workspace: this unpublished partial "
                        "workspace has no ordinary marker or caller-held cleanup "
                        "token. Retain it for manual identity-bound recovery."
                    ),
                }
            recovery: dict[str, object] = {
                **pack_recovery,
                "parent_identity": {
                    "device": parent_identity[0],
                    "inode": parent_identity[1],
                    "uid": parent_identity[2],
                },
                "workspace_identity": {
                    "device": identity[0],
                    "inode": identity[1],
                    "uid": identity[2],
                },
                "cleanup_unavailable_until_quiescent": True,
                "recovery": recovery_route,
                **recovery_locator,
            }
            _record_partial_workspace_recovery(primary_error, recovery)
            if isinstance(primary_error, ReviewWorkspaceError):
                primary_error.details.update(recovery)
            else:
                retained_path = recovery.get("retained_path")
                _attach_workspace_diagnostic(
                    primary_error,
                    "exact-pack process quiescence was not proved; "
                    f"partial workspace retained at {retained_path or root}",
                )
            raise
        try:
            _remove_owned_partial(
                root,
                identity,
                primary_error=primary_error,
                recovery_marker_payload=marker_payload,
            )
        except BaseException as cleanup_error:
            recovery_locator = _workspace_recovery_locator(
                root,
                parent_identity,
                identity,
            )
            retained_path = recovery_locator.get("retained_path")
            recovery_payload: dict[str, object] = {}
            recovery_error: BaseException | None = None
            recovery_owner: ForwardedSignalMaskOwner | None = None
            if isinstance(retained_path, str):
                recovery_owner = _begin_forwarded_signal_mask()
                try:
                    recovery_payload = retain_workspace_for_owner_exit_recovery(
                        pathlib.Path(retained_path),
                        parent_identity,
                        identity,
                        primary_error=primary_error,
                        signal_owner=recovery_owner,
                    )
                except BaseException as error:
                    recovery_error = error
                    recovery_payload = _partial_workspace_recovery_payload(error) or {}
            failure = ReviewWorkspaceError(
                "workspace-publication-rollback-incomplete",
                "workspace preparation failed and rollback could not be proved",
                details={
                    "primary_reason": getattr(
                        primary_error,
                        "reason",
                        type(primary_error).__name__,
                    ),
                    "cleanup_reason": getattr(
                        cleanup_error,
                        "reason",
                        type(cleanup_error).__name__,
                    ),
                    **recovery_locator,
                    **recovery_payload,
                    **(
                        {
                            "recovery_capability_reason": getattr(
                                recovery_error,
                                "reason",
                                type(recovery_error).__name__,
                            )
                        }
                        if recovery_error is not None
                        else {}
                    ),
                },
            )
            if recovery_payload:
                _mark_partial_workspace_for_retention(failure)
                _record_partial_workspace_recovery(failure, recovery_payload)
            _bind_workspace_failure_cause(
                failure,
                primary_error,
                context="workspace preparation failure preceded rollback failure",
            )
            if recovery_owner is not None:
                _finish_forwarded_signal_mask(
                    recovery_owner,
                    primary_error=failure,
                )
            raise failure
        raise


def cleanup_workspace(
    worktree: pathlib.Path,
    cleanup_token: str,
    *,
    defer_signal_handoff: bool = False,
) -> CleanedWorkspace:
    root = _absolute_existing_directory(worktree, "workspace")
    marker_binding = _bind_workspace_marker(root)
    marker_payload = marker_binding.payload((".git", WORKSPACE_MARKER))
    marker = _parse_marker_payload(marker_payload)
    recorded_worktree = marker.get("worktree")
    if recorded_worktree == str(root):
        parent_identity = _validate_parent_identity(root, marker)
    else:
        if not isinstance(recorded_worktree, str):
            raise ReviewWorkspaceError(
                "workspace-path-mismatch",
                "workspace marker has no valid original path",
            )
        original = pathlib.Path(recorded_worktree)
        observed_parent = _private_directory_identity(
            root.parent,
            "workspace recovery parent",
            reason="workspace-parent-policy",
        )
        if (
            original.parent != root.parent
            or not root.name.startswith(".review-cleanup-")
            or observed_parent != _marker_identity(marker, "parent_identity")
        ):
            raise ReviewWorkspaceError(
                "workspace-path-mismatch",
                "workspace recovery path is not the marker-bound quarantine",
            )
        parent_identity = observed_parent
    identity = _validate_root_identity(root, marker)
    expected_token_sha256 = _marker_cleanup_token_digest(marker)
    if not secrets.compare_digest(
        expected_token_sha256,
        _cleanup_token_digest(cleanup_token),
    ):
        raise ReviewWorkspaceError(
            "cleanup-token-mismatch", "cleanup token does not match the workspace"
        )
    parent = root.parent
    quarantine = parent / f".review-cleanup-{secrets.token_hex(12)}"
    if (
        _private_directory_identity(
            parent,
            "workspace parent",
            reason="workspace-parent-policy",
        )
        != parent_identity
    ):
        raise ReviewWorkspaceError(
            "workspace-parent-identity-mismatch",
            "workspace parent identity changed before cleanup",
        )
    root_metadata = root.stat(follow_symlinks=False)
    _validate_private_directory_metadata(root_metadata, "workspace root")
    cleanup_parent_descriptor = -1
    cleanup_root_descriptor = -1
    cleanup_parent_locked = False

    def release_cleanup_parent(
        primary_error: BaseException | None = None,
    ) -> BaseException | None:
        nonlocal cleanup_parent_descriptor, cleanup_root_descriptor
        nonlocal cleanup_parent_locked
        teardown_failures: list[tuple[str, BaseException]] = []
        if cleanup_parent_locked:
            try:
                fcntl.flock(cleanup_parent_descriptor, fcntl.LOCK_UN)
            except BaseException as unlock_error:
                teardown_failures.append(
                    ("workspace cleanup parent unlock failed", unlock_error)
                )
            cleanup_parent_locked = False
        root_to_close = cleanup_root_descriptor
        parent_to_close = cleanup_parent_descriptor
        cleanup_root_descriptor = -1
        cleanup_parent_descriptor = -1
        teardown_failures.extend(
            _attempt_workspace_descriptor_closes(
                (
                    (
                        "workspace cleanup root descriptor close failed",
                        root_to_close,
                    ),
                    (
                        "workspace cleanup parent descriptor close failed",
                        parent_to_close,
                    ),
                )
            )
        )
        if primary_error is not None:
            _attach_workspace_teardown_failures(primary_error, teardown_failures)
            return primary_error
        return _select_workspace_teardown_failure(teardown_failures)

    try:
        cleanup_parent_descriptor = os.open(
            parent,
            _nofollow_flags(directory=True),
        )
        fcntl.flock(cleanup_parent_descriptor, fcntl.LOCK_EX)
        cleanup_parent_locked = True
        locked_parent = os.fstat(cleanup_parent_descriptor)
        if (
            locked_parent.st_dev,
            locked_parent.st_ino,
            locked_parent.st_uid,
        ) != parent_identity:
            raise ReviewWorkspaceError(
                "workspace-parent-identity-mismatch",
                "workspace parent identity changed before cleanup lock",
            )
        cleanup_root_descriptor = os.open(
            root.name,
            _nofollow_flags(directory=True),
            dir_fd=cleanup_parent_descriptor,
        )
        bound_root = os.fstat(cleanup_root_descriptor)
        bound_root_path = os.stat(
            root.name,
            dir_fd=cleanup_parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not os.path.samestat(bound_root, bound_root_path)
            or (bound_root.st_dev, bound_root.st_ino, bound_root.st_uid) != identity
            or stat.S_IMODE(bound_root.st_mode) != 0o700
        ):
            raise ReviewWorkspaceError(
                "workspace-identity-mismatch",
                "workspace root changed before descriptor-bound cleanup custody",
            )
        _assert_no_bound_partial_recovery_control(
            root,
            identity,
            cleanup_parent_descriptor,
        )
        signal_owner = _begin_forwarded_signal_mask()
    except BaseException as error:
        release_cleanup_parent(error)
        raise
    operation_error: BaseException | None = None
    rollback_error: BaseException | None = None
    cleaned: CleanedWorkspace | None = None
    try:
        try:
            marker_binding.revalidate()
            if recorded_worktree == str(root):
                _validate_parent_identity(root, marker)
            elif (
                _private_directory_identity(
                    root.parent,
                    "workspace recovery parent",
                    reason="workspace-parent-policy",
                )
                != parent_identity
            ):
                raise ReviewWorkspaceError(
                    "workspace-parent-identity-mismatch",
                    "workspace recovery parent identity changed",
                )
            _validate_root_identity(root, marker)
            _rename_exclusive(
                cleanup_parent_descriptor,
                root,
                quarantine,
                parent_identity,
                identity,
            )
            metadata = os.stat(
                quarantine.name,
                dir_fd=cleanup_parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid) != identity
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or (
                    os.fstat(cleanup_parent_descriptor).st_dev,
                    os.fstat(cleanup_parent_descriptor).st_ino,
                    os.fstat(cleanup_parent_descriptor).st_uid,
                )
                != parent_identity
            ):
                raise ReviewWorkspaceError(
                    "workspace-identity-mismatch",
                    "workspace identity changed during cleanup custody transfer",
                )
            descriptor_parent_path = _descriptor_bound_path(cleanup_parent_descriptor)
            cleanup_display_path = (
                quarantine
                if descriptor_parent_path is None
                else descriptor_parent_path / quarantine.name
            )
            _remove_bound_directory_at(
                cleanup_display_path,
                identity,
                cleanup_parent_descriptor,
                cleanup_root_descriptor,
                recovery_marker_payload=marker_payload,
            )
            for leaf in (root.name, quarantine.name):
                try:
                    os.stat(
                        leaf,
                        dir_fd=cleanup_parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                raise ReviewWorkspaceError(
                    "workspace-cleanup-incomplete",
                    "workspace cleanup could not be proved in the bound parent",
                )
        except BaseException as primary_error:
            retained_candidate: pathlib.Path | None = None
            if isinstance(primary_error, ReviewWorkspaceError):
                retained_path = primary_error.details.get("retained_path")
                if isinstance(retained_path, str):
                    retained_candidate = pathlib.Path(retained_path)
            recovery_locator = _workspace_recovery_locator(
                root,
                parent_identity,
                identity,
                quarantine=quarantine,
                retained_candidate=retained_candidate,
            )
            retained_path = recovery_locator.get("retained_path")
            recovery_command_argv: list[str] | None = None
            if isinstance(retained_path, str):
                recovery_command_argv = [
                    "cleanup-workspace",
                    "--worktree",
                    retained_path,
                    "--token",
                    "<cleanup-token-from-prepare-receipt>",
                ]
            failure = ReviewWorkspaceError(
                "workspace-cleanup-incomplete",
                "workspace cleanup failed and recovery location was recorded",
                details={
                    "primary_reason": getattr(
                        primary_error,
                        "reason",
                        type(primary_error).__name__,
                    ),
                    "cleanup_reason": None
                    if rollback_error is None
                    else getattr(
                        rollback_error,
                        "reason",
                        type(rollback_error).__name__,
                    ),
                    "cleanup_token_sha256": expected_token_sha256,
                    "parent_identity": {
                        "device": parent_identity[0],
                        "inode": parent_identity[1],
                        "uid": parent_identity[2],
                    },
                    "workspace_identity": {
                        "device": identity[0],
                        "inode": identity[1],
                        "uid": identity[2],
                    },
                    "recovery_command_argv": recovery_command_argv,
                    **recovery_locator,
                },
            )
            _bind_workspace_failure_cause(
                failure,
                primary_error,
                context="workspace cleanup primary operation failed",
            )
            raise failure
        cleaned = CleanedWorkspace(
            root=root,
            _handoff_signal_mask=signal_owner if defer_signal_handoff else None,
        )
    except BaseException as error:
        operation_error = error
    selected_error = release_cleanup_parent(operation_error)
    if defer_signal_handoff and selected_error is None:
        assert cleaned is not None
        return cleaned
    _finish_forwarded_signal_mask(
        signal_owner,
        primary_error=selected_error,
    )
    if selected_error is not None:
        raise selected_error
    assert cleaned is not None
    return cleaned
