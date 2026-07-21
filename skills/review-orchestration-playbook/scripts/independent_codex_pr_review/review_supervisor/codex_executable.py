from __future__ import annotations

import ctypes
import errno
import grp
import hashlib
import os
import pathlib
import pwd
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Never, Protocol, TypeVar

from .errors import SupervisorError


EXPECTED_CODEX_SHA256 = (
    "f0b214b476e04175bee104fe441caea874baeef3efc3828bfb79e972266156a9"
)
EXPECTED_CODEX_VERSION = "codex-cli 0.145.0-alpha.18"
EXPECTED_CODEX_TEAM_IDENTIFIER = "2DC432GLL2"
EXPECTED_CODEX_FULL_CDHASH = (
    "d47f8969f99c2ff8accb9e50c5bcea5dc837bfda27a2347a10bbbcfb40b723c7"
)
EXPECTED_APP_SERVER_SCHEMA_SHA256 = (
    "3e8ce5e8e74550f85ec1ad5dc10799e117e47e8f4bfdb6531ea590529916c4bc"
)

CODESIGN_PATH = "/usr/bin/codesign"
AGGREGATE_SCHEMA_NAME = "codex_app_server_protocol.v2.schemas.json"
MAX_CODEX_EXECUTABLE_BYTES = 300 * 1024 * 1024
MAX_APP_SERVER_SCHEMA_BYTES = 8 * 1024 * 1024
MAX_CODESIGN_OUTPUT_BYTES = 128 * 1024
MAX_VERSION_OUTPUT_BYTES = 4 * 1024
MAX_HELP_OUTPUT_BYTES = 256 * 1024
MAX_SCHEMA_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_ACL_TEXT_BYTES = 64 * 1024
MAX_SNAPSHOT_SEATBELT_RULE_BYTES = 8192
EXPECTED_PATH_ALIAS_WARNING = (
    b"WARNING: proceeding, even though we could not create PATH aliases: "
    b"Operation not permitted (os error 1)\n"
)
CODESIGN_TIMEOUT_SECONDS = 15.0
PROBE_TIMEOUT_SECONDS = 10.0
SCHEMA_TIMEOUT_SECONDS = 30.0
READ_CHUNK = 64 * 1024
SNAPSHOT_DIRECTORY_PREFIX = "codex-executable-"
SNAPSHOT_FILE_NAME = "codex"
SNAPSHOT_DIRECTORY_MODE = 0o700
SNAPSHOT_BUILD_MODE = 0o600
SNAPSHOT_EXECUTABLE_MODE = 0o500
SNAPSHOT_NAME_ATTEMPTS = 8
REQUIRED_SNAPSHOT_DENIALS = (
    "filesystem-write-default",
    "write",
    "unlink",
    "rename",
    "chmod",
    "ancestor-relocation",
    "hardlink-alias",
    "firmlink-alias",
)
BOUND_LAUNCH_STATE = "bound-launch"
NEVER_LAUNCHED_ABORT_STATE = "never-launched-abort"
TRUSTED_CHATGPT_BUNDLE_ROOT = pathlib.Path("/Applications/ChatGPT.app")
UNIVERSALLY_PERMITTED_MACOS_XATTRS = frozenset({"com.apple.provenance"})
TRUSTED_CHATGPT_BUNDLE_ROOT_XATTRS = frozenset(
    {
        "com.apple.macl",
        "com.apple.metadata:_kMDItemLastOutOfSpotlightEngagementDate",
    }
)
RESTRICTIVE_HOME_ACL_ENTRY = (
    "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete"
)
THREAT_CONTAINED_SUBJECTS = (
    "untrusted-reviewed-repository",
    "model-runtime",
)
THREAT_EXCLUDED_SUBJECTS = (
    "unrelated-already-compromised-same-uid-process",
    "malicious-root-or-admin-tcb-member",
)

HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TEAM_IDENTIFIER = re.compile(r"[A-Z0-9]{10}\Z")
TEAM_LINE = re.compile(r"TeamIdentifier=([A-Z0-9]{10})\Z")
FULL_CDHASH_LINE = re.compile(r"CandidateCDHashFull sha256=([0-9a-f]{64})\Z")
REQUIRED_EXCLUSION_LABELS = ("repo", "helper", "runtime", "retention", "checkout")


class CodexExecutableError(SupervisorError):
    def __init__(self, message: str, *, code: str = "codex-executable-invalid") -> None:
        super().__init__(
            message,
            status="blocked",
            stage="codex-executable-authentication",
            code=code,
        )


class CodexExecutableExecutionUnsupported(CodexExecutableError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="codex-fd-exec-unsupported")


class CodexExecutableCustodyStale(CodexExecutableError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="codex-snapshot-custody-stale")


@dataclass(frozen=True, slots=True)
class CodexExecutablePolicy:
    expected_sha256: str = EXPECTED_CODEX_SHA256
    expected_version: str = EXPECTED_CODEX_VERSION
    expected_team_identifier: str = EXPECTED_CODEX_TEAM_IDENTIFIER
    expected_full_cdhash: str = EXPECTED_CODEX_FULL_CDHASH
    expected_schema_sha256: str = EXPECTED_APP_SERVER_SCHEMA_SHA256
    max_executable_bytes: int = MAX_CODEX_EXECUTABLE_BYTES
    max_schema_bytes: int = MAX_APP_SERVER_SCHEMA_BYTES

    def validate(self) -> None:
        digests = (
            self.expected_sha256,
            self.expected_full_cdhash,
            self.expected_schema_sha256,
        )
        if any(HEX_SHA256.fullmatch(value) is None for value in digests):
            raise ValueError("executable policy contains a malformed SHA-256 value")
        if TEAM_IDENTIFIER.fullmatch(self.expected_team_identifier) is None:
            raise ValueError("executable policy contains a malformed TeamIdentifier")
        if (
            not self.expected_version
            or "\n" in self.expected_version
            or "\r" in self.expected_version
            or "\0" in self.expected_version
        ):
            raise ValueError("executable policy contains a malformed version")
        self.expected_version.encode("ascii", "strict")
        if not 0 < self.max_executable_bytes <= MAX_CODEX_EXECUTABLE_BYTES:
            raise ValueError("executable policy exceeds the hard binary-size cap")
        if not 0 < self.max_schema_bytes <= MAX_APP_SERVER_SCHEMA_BYTES:
            raise ValueError("executable policy exceeds the hard schema-size cap")


DEFAULT_CODEX_EXECUTABLE_POLICY = CodexExecutablePolicy()


@dataclass(frozen=True, slots=True)
class ExecutableExclusionRoots:
    repo: pathlib.Path
    helper: pathlib.Path
    runtime: pathlib.Path
    retention: pathlib.Path
    checkout: pathlib.Path

    def items(self) -> tuple[tuple[str, pathlib.Path], ...]:
        return tuple(
            (label, getattr(self, label)) for label in REQUIRED_EXCLUSION_LABELS
        )


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int
    flags: int
    generation: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> NodeIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            link_count=value.st_nlink,
            uid=value.st_uid,
            gid=value.st_gid,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
            flags=getattr(value, "st_flags", 0),
            generation=getattr(value, "st_gen", 0),
        )

    def directory_object_key(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.mode,
            self.uid,
            self.gid,
            self.flags,
            self.generation,
        )

    def directory_metadata_key(
        self,
    ) -> tuple[int, int, int, int, int, int, int, int]:
        return (*self.directory_object_key(), self.ctime_ns)

    def to_json(self) -> dict[str, int]:
        return asdict(self)


def _same_node_for_kind(
    left: NodeIdentity,
    right: NodeIdentity,
    *,
    kind: str,
) -> bool:
    if kind == "directory":
        return left.directory_object_key() == right.directory_object_key()
    return left == right


def _same_node_during_metadata_inspection(
    left: NodeIdentity,
    right: NodeIdentity,
    *,
    kind: str,
) -> bool:
    if kind == "directory":
        return left.directory_metadata_key() == right.directory_metadata_key()
    return left == right


@dataclass(frozen=True, slots=True)
class ExtendedMetadataEvidence:
    acl_entry_count: int
    xattrs: tuple[str, ...]
    quarantine_present: bool
    acl_entries: tuple[str, ...] = ()

    @property
    def clear(self) -> bool:
        return (
            self.acl_entry_count == 0
            and not self.acl_entries
            and not self.xattrs
            and not self.quarantine_present
        )


FilesystemMetadataVerifier = Callable[
    [int, pathlib.Path, str], ExtendedMetadataEvidence
]


@dataclass(frozen=True, slots=True)
class PathComponentEvidence:
    path: str
    kind: str
    identity: NodeIdentity
    extended_metadata: ExtendedMetadataEvidence | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "identity": self.identity.to_json(),
            "extended_metadata": (
                asdict(self.extended_metadata) if self.extended_metadata else None
            ),
        }


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class SignatureMetadata:
    team_identifier: str
    full_cdhash: str


MetadataVerifier = Callable[[CommandResult], SignatureMetadata]


@dataclass(frozen=True, slots=True)
class CommandEvidence:
    argv: tuple[str, ...]
    timeout_seconds: float
    max_output_bytes: int
    returncode: int
    stdout_size: int
    stdout_sha256: str
    stderr_size: int
    stderr_sha256: str

    @classmethod
    def from_result(
        cls,
        result: CommandResult,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandEvidence:
        return cls(
            argv=result.argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            returncode=result.returncode,
            stdout_size=len(result.stdout),
            stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
            stderr_size=len(result.stderr),
            stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class SignatureEvidence:
    team_identifier: str
    full_cdhash: str
    strict_verification: CommandEvidence
    metadata_query: CommandEvidence


@dataclass(frozen=True, slots=True)
class SchemaEvidence:
    source: str
    size: int
    sha256: str
    generation_command: CommandEvidence | None


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    stdio: bool
    strict_config: bool
    help_sha256: str
    help_command: CommandEvidence
    schema: SchemaEvidence


@dataclass(frozen=True, slots=True)
class OperationIdentityEvidence:
    operation: str
    before: NodeIdentity
    after: NodeIdentity


@dataclass(frozen=True, slots=True)
class FdExecutionEvidence:
    supported: bool
    mechanism: str
    reason: str


@dataclass(frozen=True, slots=True)
class SnapshotCopyResult:
    size: int
    sha256: str


SnapshotCopier = Callable[
    [int, int, int, int],
    SnapshotCopyResult,
]


@dataclass(frozen=True, slots=True)
class SnapshotCopyEvidence:
    source_identity_before: NodeIdentity
    source_identity_after: NodeIdentity
    destination_identity: NodeIdentity
    size: int
    sha256: str
    max_bytes: int
    source_fd_only: bool
    file_fsynced: bool
    directory_fsynced: bool


@dataclass(frozen=True, slots=True)
class SnapshotSeatbeltPolicy:
    snapshot_directory: str
    protected_ancestors: tuple[str, ...]
    rules: str
    sha256: str
    required_denials: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SnapshotProtectionEvidence:
    snapshot_directory: str
    snapshot_policy_sha256: str
    effective_profile_sha256: str
    kernel: str
    no_child_profile_verified: bool
    applied_before_snapshot_exec: bool
    denied_operations: tuple[str, ...]
    self_mutation_probe_denied: bool


SnapshotProtectionVerifier = Callable[
    [SnapshotSeatbeltPolicy, SnapshotProtectionEvidence], None
]


@dataclass(frozen=True, slots=True)
class ThreatBoundaryEvidence:
    statement: str
    contained_subjects: tuple[str, ...]
    excluded_subjects: tuple[str, ...]
    source_path_never_executed_after_fd_authentication: bool
    fd_bound_exec_claimed: bool
    snapshot_path_is_only_launch_target: bool


@dataclass(frozen=True, slots=True)
class SnapshotEvidence:
    parent_path: str
    parent_identity: NodeIdentity
    parent_components: tuple[PathComponentEvidence, ...]
    directory_path: str
    executable_path: str
    directory_identity: NodeIdentity
    executable_identity: NodeIdentity
    directory_components: tuple[PathComponentEvidence, ...]
    executable_components: tuple[PathComponentEvidence, ...]
    directory_metadata: ExtendedMetadataEvidence
    executable_metadata: ExtendedMetadataEvidence
    copy: SnapshotCopyEvidence
    seatbelt_policy: SnapshotSeatbeltPolicy


@dataclass(frozen=True, slots=True)
class SnapshotHandoffEvidence:
    generation: int
    token: str
    phase: str
    snapshot_path: str
    identity: NodeIdentity
    sha256: str
    protection: SnapshotProtectionEvidence | None
    identity_operations: tuple[OperationIdentityEvidence, ...]
    revalidation: ExecutableRevalidationEvidence


@dataclass(frozen=True, slots=True)
class SnapshotExecTarget:
    executable_path: str
    seatbelt_rules: str
    handoff: SnapshotHandoffEvidence
    revalidation: ExecutableRevalidationEvidence


@dataclass(frozen=True, slots=True)
class ProcessQuiescenceEvidence:
    handoff_token: str | None
    process_id: int | None
    leader_reaped: bool
    process_group_empty: bool
    descendant_handles_closed: bool
    observed_by_supervisor: bool
    reason: str
    launch_state: str = BOUND_LAUNCH_STATE


QuiescenceVerifier = Callable[[ProcessQuiescenceEvidence], None]


@dataclass(frozen=True, slots=True)
class CodexExecutableEvidence:
    source_path: str
    path_components: tuple[PathComponentEvidence, ...]
    identity: NodeIdentity
    size: int
    sha256: str
    source_signature: SignatureEvidence
    snapshot: SnapshotEvidence
    version: str
    version_command: CommandEvidence
    signature: SignatureEvidence
    capabilities: CapabilityEvidence
    identity_operations: tuple[OperationIdentityEvidence, ...]
    exclusion_roots: tuple[tuple[str, str], ...]
    no_follow: bool
    executable_fd_close_on_exec: bool
    fd_execution: FdExecutionEvidence
    threat_boundary: ThreatBoundaryEvidence

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExecutableRevalidationEvidence:
    identity: NodeIdentity
    sha256: str
    operation: OperationIdentityEvidence
    fd_execution: FdExecutionEvidence


@dataclass(frozen=True, slots=True)
class OwnerSnapshotLaunchAttestation:
    """Launch authority for one owner-only snapshot held by custody.

    ``executable_fd`` and ``directory_fd`` remain owned by
    :class:`CodexExecutableCustody`; consumers must keep that custody open through
    launch. ``snapshot`` is the complete seal evidence and ``revalidation`` is a
    fresh FD/path/digest check. A consumer must revalidate both descriptors and
    the pathname immediately before exec. This attestation authorizes only the
    sealed 0500 executable inside its sealed 0700 directory; it does not weaken
    the root-only policy for ordinary installed executables.
    """

    executable_fd: int
    directory_fd: int
    snapshot: SnapshotEvidence
    expected_sha256: str
    revalidation: ExecutableRevalidationEvidence


@dataclass(slots=True)
class _PathAnchor:
    path: pathlib.Path
    fd: int
    components: tuple[PathComponentEvidence, ...]
    owner_uid: int
    leaf_kind: str
    require_executable: bool
    filesystem_metadata_verifier: FilesystemMetadataVerifier | None

    @property
    def identity(self) -> NodeIdentity:
        return self.components[-1].identity


@dataclass(slots=True)
class _StagedSnapshot:
    parent_path: pathlib.Path
    directory_name: str
    directory_anchor: _PathAnchor
    file_anchor: _PathAnchor
    evidence: SnapshotEvidence


T = TypeVar("T")


def _require_python_313() -> None:
    if sys.version_info[:2] != (3, 13):
        raise CodexExecutableError(
            "Codex executable custody requires Python 3.13",
            code="python-version-unsupported",
        )


def _canonical_absolute_path(value: pathlib.Path, *, label: str) -> pathlib.Path:
    raw = os.fspath(value)
    if not isinstance(raw, str):
        raise ValueError(f"{label} must be a text path")
    if not raw or "\0" in raw or any(ord(character) < 32 for character in raw):
        raise ValueError(f"{label} contains an invalid character")
    if not raw.startswith("/") or raw.startswith("//"):
        raise ValueError(f"{label} must be an explicit absolute path")
    if raw != os.path.normpath(raw):
        raise ValueError(f"{label} must not contain dot, empty, or trailing components")
    parts = raw.split("/")[1:]
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{label} contains an invalid path component")
    return pathlib.Path(raw)


def _casefolded_parts(path: pathlib.Path) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFD", part).casefold() for part in path.parts)


def _path_object_provenance(path: pathlib.Path) -> tuple[tuple[int, int], ...]:
    current = pathlib.Path("/")
    provenance: list[tuple[int, int]] = []
    try:
        root_metadata = os.stat(current, follow_symlinks=True)
        provenance.append((root_metadata.st_dev, root_metadata.st_ino))
        for part in path.parts[1:]:
            current /= part
            metadata = os.stat(current, follow_symlinks=True)
            provenance.append((metadata.st_dev, metadata.st_ino))
    except OSError as error:
        raise ValueError(
            f"path object provenance cannot be inspected: {current}"
        ) from error
    return tuple(provenance)


def _macos_acl_entry_count(fd: int) -> int:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended ACL inspection requires macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    acl_get_entry.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(fd, 0x00000100)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return 0
        raise OSError(error_number or errno.EIO, "cannot inspect extended ACL")
    try:
        count = 0
        entry = ctypes.c_void_p()
        entry_selector = 0
        while True:
            ctypes.set_errno(0)
            status = acl_get_entry(acl, entry_selector, ctypes.byref(entry))
            if status == 0:
                count += 1
                if count > 128:
                    raise ValueError("extended ACL exceeds the macOS entry bound")
                entry_selector = -1
                continue
            error_number = ctypes.get_errno()
            if status == -1 and error_number == errno.EINVAL:
                return count
            raise OSError(
                error_number or errno.EIO,
                "cannot enumerate extended ACL",
            )
    finally:
        if acl_free(acl) != 0:
            raise OSError(ctypes.get_errno() or errno.EIO, "cannot release ACL state")


def _macos_acl_entries(fd: int) -> tuple[str, ...]:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended ACL inspection requires macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_to_text = libc.acl_to_text
    acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    acl_to_text.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(fd, 0x00000100)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return ()
        raise OSError(error_number or errno.EIO, "cannot inspect extended ACL")

    text_pointer: int | None = None
    cleanup_error: OSError | None = None
    try:
        length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text_pointer = acl_to_text(acl, ctypes.byref(length))
        if not text_pointer:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot serialize extended ACL",
            )
        if not 0 < length.value <= MAX_ACL_TEXT_BYTES:
            raise ValueError("extended ACL text exceeds its byte bound")
        raw = ctypes.string_at(text_pointer, length.value)
        if b"\0" in raw or b"\r" in raw or not raw.endswith(b"\n"):
            raise ValueError("extended ACL text is malformed")
        rendered = raw.decode("ascii", "strict")
        lines = rendered[:-1].split("\n")
        if not lines:
            raise ValueError("extended ACL text is malformed")
        header = re.fullmatch(r"!#acl ([0-9]{1,3})", lines[0])
        if header is None:
            raise ValueError("extended ACL header is malformed")
        count = int(header.group(1))
        entries = tuple(lines[1:])
        if (
            count > 128
            or len(entries) != count
            or any(
                not entry
                or len(entry.encode("ascii")) > 1024
                or any(not 0x20 <= ord(character) <= 0x7E for character in entry)
                for entry in entries
            )
            or len(set(entries)) != len(entries)
        ):
            raise ValueError("extended ACL entries are malformed")
        return entries
    finally:
        if text_pointer is not None and acl_free(text_pointer) != 0:
            cleanup_error = OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot release serialized ACL state",
            )
        if acl_free(acl) != 0 and cleanup_error is None:
            cleanup_error = OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot release ACL state",
            )
        if cleanup_error is not None and sys.exc_info()[0] is None:
            raise cleanup_error


def _macos_fd_xattr_names(fd: int) -> tuple[str, ...]:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended attribute inspection requires macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    flistxattr = libc.flistxattr
    flistxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    flistxattr.restype = ctypes.c_ssize_t

    def required_size() -> int:
        ctypes.set_errno(0)
        value = flistxattr(fd, None, 0, 0)
        if value < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot size extended attribute names",
            )
        if value > 4096:
            raise ValueError("extended attribute names exceed their byte bound")
        return int(value)

    size = required_size()
    if size == 0:
        if required_size() != 0:
            raise OSError(errno.ESTALE, "extended attributes changed during inspection")
        return ()

    def read_names() -> bytes:
        buffer = ctypes.create_string_buffer(size)
        ctypes.set_errno(0)
        value = flistxattr(fd, buffer, size, 0)
        if value < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot read extended attribute names",
            )
        if value != size:
            raise OSError(errno.ESTALE, "extended attributes changed during inspection")
        return bytes(buffer.raw[:size])

    first = read_names()
    second = read_names()
    if first != second or required_size() != size:
        raise OSError(errno.ESTALE, "extended attributes changed during inspection")
    if not first.endswith(b"\0"):
        raise ValueError("extended attribute name list is malformed")
    raw_names = first[:-1].split(b"\0")
    if any(not name for name in raw_names) or len(raw_names) > 128:
        raise ValueError("extended attribute names exceed their count bound")
    try:
        names = tuple(sorted(name.decode("utf-8", "strict") for name in raw_names))
    except UnicodeDecodeError as error:
        raise ValueError("extended attribute name is not UTF-8") from error
    if len(set(names)) != len(names):
        raise ValueError("extended attribute names contain duplicates")
    return names


def _read_macos_filesystem_metadata(fd: int) -> ExtendedMetadataEvidence:
    names = _macos_fd_xattr_names(fd)
    acl_entries = _macos_acl_entries(fd)
    if len(names) > 128 or sum(len(name.encode("utf-8")) for name in names) > 4096:
        raise ValueError("extended attribute names exceed their bound")
    return ExtendedMetadataEvidence(
        acl_entry_count=len(acl_entries),
        xattrs=names,
        quarantine_present="com.apple.quarantine" in names,
        acl_entries=acl_entries,
    )


def inspect_macos_filesystem_metadata(
    fd: int,
    kind: str,
) -> ExtendedMetadataEvidence:
    before = NodeIdentity.from_stat(os.fstat(fd))
    first = _read_macos_filesystem_metadata(fd)
    middle = NodeIdentity.from_stat(os.fstat(fd))
    second = _read_macos_filesystem_metadata(fd)
    after = NodeIdentity.from_stat(os.fstat(fd))
    if (
        not _same_node_during_metadata_inspection(before, middle, kind=kind)
        or not _same_node_during_metadata_inspection(middle, after, kind=kind)
        or first != second
    ):
        raise OSError(errno.ESTALE, "filesystem metadata changed during inspection")
    return second


def verify_macos_filesystem_metadata(
    fd: int,
    path: pathlib.Path,
    kind: str,
) -> ExtendedMetadataEvidence:
    evidence = inspect_macos_filesystem_metadata(fd, kind)
    if not _filesystem_metadata_is_permitted(evidence, path=path, kind=kind):
        raise ValueError("extended ACLs, xattrs, and quarantine are forbidden")
    return evidence


def _permitted_macos_xattrs(path: pathlib.Path, *, kind: str) -> frozenset[str]:
    if kind not in {"directory", "file"}:
        return frozenset()
    if path == TRUSTED_CHATGPT_BUNDLE_ROOT:
        return UNIVERSALLY_PERMITTED_MACOS_XATTRS | TRUSTED_CHATGPT_BUNDLE_ROOT_XATTRS
    return UNIVERSALLY_PERMITTED_MACOS_XATTRS


def _filesystem_metadata_is_permitted(
    evidence: ExtendedMetadataEvidence,
    *,
    path: pathlib.Path,
    kind: str,
) -> bool:
    permitted_acl_entries: frozenset[str] = frozenset()
    try:
        current_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, TypeError, ValueError):
        current_home = pathlib.Path()
    if kind == "directory" and path == current_home:
        permitted_acl_entries = frozenset({RESTRICTIVE_HOME_ACL_ENTRY})
    return (
        evidence.acl_entry_count == len(evidence.acl_entries)
        and set(evidence.acl_entries) <= permitted_acl_entries
        and not evidence.quarantine_present
        and set(evidence.xattrs) <= _permitted_macos_xattrs(path, kind=kind)
    )


def _verify_extended_metadata(
    verifier: FilesystemMetadataVerifier | None,
    fd: int,
    path: pathlib.Path,
    kind: str,
) -> ExtendedMetadataEvidence | None:
    if verifier is None:
        return None
    identity_before = NodeIdentity.from_stat(os.fstat(fd))
    evidence = verifier(fd, path, kind)
    identity_after = NodeIdentity.from_stat(os.fstat(fd))
    if not _same_node_during_metadata_inspection(
        identity_before,
        identity_after,
        kind=kind,
    ):
        raise OSError(errno.ESTALE, "filesystem metadata raced with inspection")
    if (
        not isinstance(evidence, ExtendedMetadataEvidence)
        or type(evidence.acl_entry_count) is not int
        or evidence.acl_entry_count < 0
        or not isinstance(evidence.acl_entries, tuple)
        or any(
            not isinstance(entry, str)
            or not entry
            or "\0" in entry
            or "\n" in entry
            or "\r" in entry
            for entry in evidence.acl_entries
        )
        or len(set(evidence.acl_entries)) != len(evidence.acl_entries)
        or evidence.acl_entry_count != len(evidence.acl_entries)
        or not isinstance(evidence.xattrs, tuple)
        or any(not isinstance(name, str) or not name for name in evidence.xattrs)
        or len(set(evidence.xattrs)) != len(evidence.xattrs)
        or type(evidence.quarantine_present) is not bool
    ):
        raise ValueError("filesystem metadata verifier returned malformed evidence")
    if evidence.quarantine_present != ("com.apple.quarantine" in evidence.xattrs):
        raise ValueError("filesystem metadata quarantine evidence is inconsistent")
    if not _filesystem_metadata_is_permitted(evidence, path=path, kind=kind):
        raise ValueError("extended ACLs, xattrs, and quarantine are forbidden")
    return evidence


def verify_filesystem_metadata_evidence(
    verifier: FilesystemMetadataVerifier,
    fd: int,
    path: pathlib.Path,
    kind: str,
) -> ExtendedMetadataEvidence:
    evidence = _verify_extended_metadata(verifier, fd, path, kind)
    if evidence is None:
        raise ValueError("filesystem metadata verifier is required")
    return evidence


def _seatbelt_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_snapshot_seatbelt_policy(
    snapshot_directory: pathlib.Path,
) -> SnapshotSeatbeltPolicy:
    path = _canonical_absolute_path(
        snapshot_directory, label="snapshot Seatbelt directory"
    )
    try:
        str(path).encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ValueError("snapshot Seatbelt path must be ASCII") from error
    protected_ancestors = tuple(str(ancestor) for ancestor in reversed(path.parents))
    protected_paths = (*protected_ancestors, str(path))
    snapshot_literal = _seatbelt_string(str(path))
    rules = "\n".join(
        (
            "(deny file-write*)",
            "(deny file-link)",
            *(
                f"(deny file-write* (literal {_seatbelt_string(protected)}))"
                for protected in protected_paths
            ),
            f"(deny file-write* (subpath {snapshot_literal}))",
            "",
        )
    )
    if len(rules.encode("ascii")) > MAX_SNAPSHOT_SEATBELT_RULE_BYTES:
        raise ValueError("snapshot Seatbelt policy exceeds its byte bound")
    return SnapshotSeatbeltPolicy(
        snapshot_directory=str(path),
        protected_ancestors=protected_ancestors,
        rules=rules,
        sha256=hashlib.sha256(rules.encode("ascii")).hexdigest(),
        required_denials=REQUIRED_SNAPSHOT_DENIALS,
    )


def copy_executable_from_fd(
    source_fd: int,
    destination_fd: int,
    expected_size: int,
    max_bytes: int,
) -> SnapshotCopyResult:
    if (
        type(expected_size) is not int
        or type(max_bytes) is not int
        or not 0 <= expected_size <= max_bytes <= MAX_CODEX_EXECUTABLE_BYTES
    ):
        raise ValueError("snapshot copy size policy is invalid")
    os.lseek(destination_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(source_fd, min(READ_CHUNK, expected_size - offset), offset)
        if not chunk:
            raise ValueError("source ended before the authenticated copy length")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "snapshot copy made no write progress")
            view = view[written:]
        offset += len(chunk)
    if os.pread(source_fd, 1, expected_size):
        raise ValueError("source exceeds the authenticated copy length")
    return SnapshotCopyResult(offset, digest.hexdigest())


def _validate_exclusions(
    source: pathlib.Path,
    roots: ExecutableExclusionRoots,
) -> tuple[tuple[str, str], ...]:
    source_parts = _casefolded_parts(source)
    source_provenance: frozenset[tuple[int, int]] | None = None
    evidence: list[tuple[str, str]] = []
    for label, raw_root in roots.items():
        root = _canonical_absolute_path(raw_root, label=f"{label} exclusion root")
        root_parts = _casefolded_parts(root)
        lexical_descendant = source_parts[: len(root_parts)] == root_parts
        if lexical_descendant:
            raise ValueError(f"Codex executable is inside the {label} exclusion root")
        if source_provenance is None:
            source_provenance = frozenset(_path_object_provenance(source))
        root_provenance = _path_object_provenance(root)
        if root_provenance[-1] in source_provenance:
            raise ValueError(
                "Codex executable is inside the "
                f"{label} exclusion root through a filesystem path alias"
            )
        evidence.append((label, str(root)))
    return tuple(evidence)


def _validate_node(
    identity: NodeIdentity,
    *,
    path: pathlib.Path,
    kind: str,
    owner_uid: int,
    root: bool = False,
    require_executable: bool = False,
) -> None:
    mode = identity.mode
    if root:
        if identity.uid != 0:
            raise ValueError("filesystem root is not owned by root")
    elif identity.uid not in {0, owner_uid}:
        raise ValueError(f"path component has an untrusted owner: {path}")
    if mode & (stat.S_IWGRP | stat.S_IWOTH) and not _trusted_applications_directory(
        identity,
        path=path,
        kind=kind,
        owner_uid=owner_uid,
    ):
        raise ValueError(f"path component is group/world-writable: {path}")
    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError(f"path component has setuid/setgid permission: {path}")
    if kind == "directory":
        if not stat.S_ISDIR(mode):
            raise ValueError(f"path component is not a directory: {path}")
        return
    if kind != "file" or not stat.S_ISREG(mode):
        raise ValueError(f"path leaf is not a regular file: {path}")
    if identity.link_count != 1:
        raise ValueError(f"path leaf has an unsafe hard-link count: {path}")
    if require_executable and not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ValueError(f"path leaf is not executable: {path}")


def _trusted_applications_directory(
    identity: NodeIdentity,
    *,
    path: pathlib.Path,
    kind: str,
    owner_uid: int,
) -> bool:
    if (
        kind != "directory"
        or path != pathlib.Path("/Applications")
        or identity.uid != 0
        or stat.S_IMODE(identity.mode) != 0o775
        or identity.gid not in os.getgroups()
        or owner_uid != os.getuid()
    ):
        return False
    try:
        return identity.gid == grp.getgrnam("admin").gr_gid
    except KeyError:
        return False


def _open_path_anchor(
    path: pathlib.Path,
    *,
    owner_uid: int,
    leaf_kind: str,
    require_executable: bool,
    filesystem_metadata_verifier: FilesystemMetadataVerifier | None = None,
) -> _PathAnchor:
    parts = path.parts[1:]
    root_before = NodeIdentity.from_stat(os.stat("/", follow_symlinks=False))
    _validate_node(
        root_before,
        path=pathlib.Path("/"),
        kind="directory",
        owner_uid=owner_uid,
        root=True,
    )
    current_fd = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    evidence: list[PathComponentEvidence] = []
    try:
        root_descriptor = NodeIdentity.from_stat(os.fstat(current_fd))
        root_after = NodeIdentity.from_stat(os.stat("/", follow_symlinks=False))
        if not _same_node_for_kind(
            root_before,
            root_descriptor,
            kind="directory",
        ) or not _same_node_for_kind(
            root_descriptor,
            root_after,
            kind="directory",
        ):
            raise ValueError("filesystem root identity changed while opening")
        root_metadata = _verify_extended_metadata(
            filesystem_metadata_verifier,
            current_fd,
            pathlib.Path("/"),
            "directory",
        )
        root_descriptor_after_metadata = NodeIdentity.from_stat(os.fstat(current_fd))
        root_path_after_metadata = NodeIdentity.from_stat(
            os.stat("/", follow_symlinks=False)
        )
        if not _same_node_during_metadata_inspection(
            root_descriptor,
            root_descriptor_after_metadata,
            kind="directory",
        ) or not _same_node_during_metadata_inspection(
            root_descriptor_after_metadata,
            root_path_after_metadata,
            kind="directory",
        ):
            raise ValueError("filesystem root raced with metadata inspection")
        evidence.append(
            PathComponentEvidence("/", "directory", root_descriptor, root_metadata)
        )

        display_path = pathlib.Path("/")
        for index, part in enumerate(parts):
            display_path /= part
            final = index == len(parts) - 1
            kind = leaf_kind if final else "directory"
            before = NodeIdentity.from_stat(
                os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            )
            _validate_node(
                before,
                path=display_path,
                kind=kind,
                owner_uid=owner_uid,
                require_executable=final and require_executable,
            )
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if kind == "directory":
                flags |= os.O_DIRECTORY
            else:
                flags |= os.O_NONBLOCK
            child_fd = os.open(os.fsencode(part), flags, dir_fd=current_fd)
            try:
                descriptor = NodeIdentity.from_stat(os.fstat(child_fd))
                after = NodeIdentity.from_stat(
                    os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                )
                _validate_node(
                    descriptor,
                    path=display_path,
                    kind=kind,
                    owner_uid=owner_uid,
                    require_executable=final and require_executable,
                )
                if not _same_node_for_kind(
                    before,
                    descriptor,
                    kind=kind,
                ) or not _same_node_for_kind(
                    descriptor,
                    after,
                    kind=kind,
                ):
                    raise ValueError(
                        f"path component changed while opening: {display_path}"
                    )
                extended_metadata = _verify_extended_metadata(
                    filesystem_metadata_verifier,
                    child_fd,
                    display_path,
                    kind,
                )
                descriptor_after_metadata = NodeIdentity.from_stat(os.fstat(child_fd))
                path_after_metadata = NodeIdentity.from_stat(
                    os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                )
                if not _same_node_during_metadata_inspection(
                    descriptor,
                    descriptor_after_metadata,
                    kind=kind,
                ) or not _same_node_during_metadata_inspection(
                    descriptor_after_metadata,
                    path_after_metadata,
                    kind=kind,
                ):
                    raise ValueError(
                        f"path component raced with metadata inspection: {display_path}"
                    )
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
            evidence.append(
                PathComponentEvidence(
                    str(display_path), kind, descriptor, extended_metadata
                )
            )
        if not parts or not evidence or evidence[-1].kind != leaf_kind:
            raise ValueError("path does not identify the required leaf type")
        return _PathAnchor(
            path=path,
            fd=current_fd,
            components=tuple(evidence),
            owner_uid=owner_uid,
            leaf_kind=leaf_kind,
            require_executable=require_executable,
            filesystem_metadata_verifier=filesystem_metadata_verifier,
        )
    except BaseException:
        os.close(current_fd)
        raise


def _path_components_match(
    expected: tuple[PathComponentEvidence, ...],
    current: tuple[PathComponentEvidence, ...],
) -> bool:
    if len(expected) != len(current):
        return False
    return all(
        left.path == right.path
        and left.kind == right.kind
        and _same_node_for_kind(
            left.identity,
            right.identity,
            kind=left.kind,
        )
        and left.extended_metadata == right.extended_metadata
        for left, right in zip(expected, current, strict=True)
    )


def _assert_anchor_stable(anchor: _PathAnchor) -> NodeIdentity:
    descriptor_before = NodeIdentity.from_stat(os.fstat(anchor.fd))
    if not _same_node_for_kind(
        descriptor_before,
        anchor.identity,
        kind=anchor.leaf_kind,
    ):
        raise ValueError("held executable identity changed")
    current = _open_path_anchor(
        anchor.path,
        owner_uid=anchor.owner_uid,
        leaf_kind=anchor.leaf_kind,
        require_executable=anchor.require_executable,
        filesystem_metadata_verifier=anchor.filesystem_metadata_verifier,
    )
    try:
        if not _path_components_match(anchor.components, current.components):
            raise ValueError("no-follow path identity changed")
    finally:
        os.close(current.fd)
    descriptor_after = NodeIdentity.from_stat(os.fstat(anchor.fd))
    if not _same_node_for_kind(
        descriptor_before,
        descriptor_after,
        kind=anchor.leaf_kind,
    ):
        raise ValueError("held executable identity raced with path revalidation")
    return descriptor_after


def _assert_directory_object_stable(anchor: _PathAnchor) -> NodeIdentity:
    descriptor_before = NodeIdentity.from_stat(os.fstat(anchor.fd))
    if (
        descriptor_before.directory_object_key()
        != anchor.identity.directory_object_key()
    ):
        raise ValueError("held directory object changed")
    current = _open_path_anchor(
        anchor.path,
        owner_uid=anchor.owner_uid,
        leaf_kind="directory",
        require_executable=False,
        filesystem_metadata_verifier=anchor.filesystem_metadata_verifier,
    )
    try:
        expected_prefix = anchor.components[:-1]
        if not _path_components_match(
            expected_prefix,
            current.components[:-1],
        ):
            raise ValueError("directory path components changed")
        if (
            current.identity.directory_object_key()
            != anchor.identity.directory_object_key()
        ):
            raise ValueError("directory path now identifies a different object")
    finally:
        os.close(current.fd)
    descriptor_after = NodeIdentity.from_stat(os.fstat(anchor.fd))
    if (
        descriptor_before.directory_object_key()
        != descriptor_after.directory_object_key()
    ):
        raise ValueError("held directory object raced with revalidation")
    return descriptor_after


def _snapshot_components_match(
    expected: tuple[PathComponentEvidence, ...],
    current: tuple[PathComponentEvidence, ...],
    *,
    leaf_kind: str,
) -> bool:
    if len(expected) != len(current):
        return False
    for index, (left, right) in enumerate(zip(expected, current, strict=True)):
        if left.path != right.path or left.kind != right.kind:
            return False
        is_leaf = index == len(expected) - 1
        is_snapshot_directory = (
            leaf_kind == "file" and index == len(expected) - 2
        ) or (leaf_kind == "directory" and is_leaf)
        if (is_leaf and leaf_kind == "file") or is_snapshot_directory:
            if left.identity != right.identity:
                return False
        elif (
            left.identity.directory_object_key()
            != right.identity.directory_object_key()
        ):
            return False
        if left.extended_metadata != right.extended_metadata:
            return False
    return True


def _assert_snapshot_stable(
    directory_anchor: _PathAnchor,
    file_anchor: _PathAnchor,
) -> NodeIdentity:
    directory_before = NodeIdentity.from_stat(os.fstat(directory_anchor.fd))
    file_before = NodeIdentity.from_stat(os.fstat(file_anchor.fd))
    if (
        directory_before != directory_anchor.identity
        or file_before != file_anchor.identity
    ):
        raise ValueError("held snapshot descriptor identity changed")

    current_directory = _open_path_anchor(
        directory_anchor.path,
        owner_uid=directory_anchor.owner_uid,
        leaf_kind="directory",
        require_executable=False,
        filesystem_metadata_verifier=directory_anchor.filesystem_metadata_verifier,
    )
    current_file = _open_path_anchor(
        file_anchor.path,
        owner_uid=file_anchor.owner_uid,
        leaf_kind="file",
        require_executable=True,
        filesystem_metadata_verifier=file_anchor.filesystem_metadata_verifier,
    )
    try:
        if not _snapshot_components_match(
            directory_anchor.components,
            current_directory.components,
            leaf_kind="directory",
        ):
            raise ValueError("snapshot directory path identity changed")
        if not _snapshot_components_match(
            file_anchor.components,
            current_file.components,
            leaf_kind="file",
        ):
            raise ValueError("snapshot executable path identity changed")
    finally:
        os.close(current_file.fd)
        os.close(current_directory.fd)

    names = os.listdir(directory_anchor.fd)
    if names != [SNAPSHOT_FILE_NAME]:
        raise ValueError("snapshot directory entry set changed")
    directory_after = NodeIdentity.from_stat(os.fstat(directory_anchor.fd))
    file_after = NodeIdentity.from_stat(os.fstat(file_anchor.fd))
    if directory_before != directory_after or file_before != file_after:
        raise ValueError("snapshot descriptor identity raced with revalidation")
    return file_after


def _guarded_source_operation(
    anchor: _PathAnchor,
    operations: list[OperationIdentityEvidence],
    label: str,
    operation: Callable[[], T],
) -> T:
    before = _assert_anchor_stable(anchor)
    operation_error: Exception | None = None
    result: T | None = None
    try:
        result = operation()
    except Exception as error:  # Revalidate even when an external probe fails.
        operation_error = error
    try:
        after = _assert_anchor_stable(anchor)
    except Exception as identity_error:
        if operation_error is not None:
            raise identity_error from operation_error
        raise
    operations.append(OperationIdentityEvidence(label, before, after))
    if operation_error is not None:
        raise operation_error
    return result  # type: ignore[return-value]


def _guarded_snapshot_operation(
    staged: _StagedSnapshot,
    operations: list[OperationIdentityEvidence],
    label: str,
    operation: Callable[[], T],
) -> T:
    before = _assert_snapshot_stable(
        staged.directory_anchor,
        staged.file_anchor,
    )
    operation_error: Exception | None = None
    result: T | None = None
    try:
        result = operation()
    except Exception as error:  # Revalidate even when an external probe fails.
        operation_error = error
    try:
        after = _assert_snapshot_stable(
            staged.directory_anchor,
            staged.file_anchor,
        )
    except Exception as identity_error:
        if operation_error is not None:
            raise identity_error from operation_error
        raise
    operations.append(OperationIdentityEvidence(label, before, after))
    if operation_error is not None:
        raise operation_error
    return result  # type: ignore[return-value]


def _sha256_fd(fd: int, *, expected_size: int, max_bytes: int) -> str:
    if expected_size < 0 or expected_size > max_bytes:
        raise ValueError(f"file exceeds the explicit {max_bytes}-byte cap")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(fd, min(READ_CHUNK, expected_size - offset), offset)
        if not chunk:
            raise ValueError("file ended before its measured size")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(fd, 1, expected_size):
        raise ValueError("file contains data beyond its measured size")
    return digest.hexdigest()


def _refresh_directory_anchor(
    anchor: _PathAnchor,
    *,
    allow_controlled_mode_change: bool = False,
) -> NodeIdentity:
    fresh = _open_path_anchor(
        anchor.path,
        owner_uid=anchor.owner_uid,
        leaf_kind="directory",
        require_executable=False,
        filesystem_metadata_verifier=anchor.filesystem_metadata_verifier,
    )
    try:
        held = NodeIdentity.from_stat(os.fstat(anchor.fd))
        if held != fresh.identity:
            raise ValueError("held directory differs from its refreshed path identity")
        same_object = (held.device, held.inode, held.uid, held.gid) == (
            anchor.identity.device,
            anchor.identity.inode,
            anchor.identity.uid,
            anchor.identity.gid,
        )
        if not same_object or (
            not allow_controlled_mode_change
            and held.directory_object_key() != anchor.identity.directory_object_key()
        ):
            raise ValueError("directory object changed while it was refreshed")
        anchor.components = fresh.components
        return held
    finally:
        os.close(fresh.fd)


def _rollback_new_snapshot(
    *,
    parent_fd: int,
    directory_name: str,
    directory_fd: int | None,
    directory_identity: NodeIdentity,
    file_created: bool,
    file_fd: int | None,
    file_identity: NodeIdentity | None,
) -> None:
    opened_for_rollback = False
    if directory_fd is None:
        directory_fd = os.open(
            os.fsencode(directory_name),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        opened_for_rollback = True
    try:
        held_directory = NodeIdentity.from_stat(os.fstat(directory_fd))
        path_directory = NodeIdentity.from_stat(
            os.stat(
                os.fsencode(directory_name),
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        )
        expected_directory = (
            held_directory if not opened_for_rollback else directory_identity
        )
        if held_directory != expected_directory or path_directory != held_directory:
            raise ValueError("snapshot rollback refused a replaced directory path")

        expected_names = [SNAPSHOT_FILE_NAME] if file_created else []
        if os.listdir(directory_fd) != expected_names:
            raise ValueError("snapshot rollback refused an unexpected directory entry")
        if file_created:
            held_file = (
                NodeIdentity.from_stat(os.fstat(file_fd))
                if file_fd is not None
                else file_identity
            )
            if held_file is None:
                raise ValueError("snapshot rollback lacks the created file identity")
            path_file = NodeIdentity.from_stat(
                os.stat(
                    os.fsencode(SNAPSHOT_FILE_NAME),
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            )
            if path_file != held_file:
                raise ValueError("snapshot rollback refused a replaced file path")
            os.unlink(os.fsencode(SNAPSHOT_FILE_NAME), dir_fd=directory_fd)
            os.fsync(directory_fd)
        os.rmdir(os.fsencode(directory_name), dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(directory_fd)


def _stage_snapshot(
    *,
    source_anchor: _PathAnchor,
    snapshot_parent: pathlib.Path,
    owner_uid: int,
    policy: CodexExecutablePolicy,
    operations: list[OperationIdentityEvidence],
    snapshot_copier: SnapshotCopier,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
) -> _StagedSnapshot:
    parent_path = _canonical_absolute_path(snapshot_parent, label="snapshot parent")
    parent_anchor = _open_path_anchor(
        parent_path,
        owner_uid=owner_uid,
        leaf_kind="directory",
        require_executable=False,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
    )
    directory_name: str | None = None
    directory_creation_identity: NodeIdentity | None = None
    directory_anchor: _PathAnchor | None = None
    build_fd: int | None = None
    rollback_file_identity: NodeIdentity | None = None
    file_created = False
    staged = False
    try:
        if (
            parent_anchor.identity.uid != owner_uid
            or stat.S_IMODE(parent_anchor.identity.mode) != SNAPSHOT_DIRECTORY_MODE
        ):
            raise ValueError("snapshot parent must be supervisor-owned mode 0700")
        for _ in range(SNAPSHOT_NAME_ATTEMPTS):
            candidate = SNAPSHOT_DIRECTORY_PREFIX + secrets.token_hex(16)
            try:
                os.mkdir(
                    os.fsencode(candidate),
                    SNAPSHOT_DIRECTORY_MODE,
                    dir_fd=parent_anchor.fd,
                )
            except FileExistsError:
                continue
            directory_name = candidate
            directory_creation_identity = NodeIdentity.from_stat(
                os.stat(
                    os.fsencode(candidate),
                    dir_fd=parent_anchor.fd,
                    follow_symlinks=False,
                )
            )
            _validate_node(
                directory_creation_identity,
                path=parent_path / candidate,
                kind="directory",
                owner_uid=owner_uid,
            )
            break
        if directory_name is None:
            raise FileExistsError("cannot allocate a fresh snapshot directory")
        os.fsync(parent_anchor.fd)
        directory_path = parent_path / directory_name
        directory_anchor = _open_path_anchor(
            directory_path,
            owner_uid=owner_uid,
            leaf_kind="directory",
            require_executable=False,
            filesystem_metadata_verifier=filesystem_metadata_verifier,
        )
        os.fchmod(directory_anchor.fd, SNAPSHOT_DIRECTORY_MODE)
        directory_identity = _refresh_directory_anchor(
            directory_anchor,
            allow_controlled_mode_change=True,
        )
        if (
            directory_identity.uid != owner_uid
            or stat.S_IMODE(directory_identity.mode) != SNAPSHOT_DIRECTORY_MODE
        ):
            raise ValueError("snapshot directory is not supervisor-owned mode 0700")

        build_fd = os.open(
            os.fsencode(SNAPSHOT_FILE_NAME),
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK,
            SNAPSHOT_BUILD_MODE,
            dir_fd=directory_anchor.fd,
        )
        file_created = True
        os.fchmod(build_fd, SNAPSHOT_BUILD_MODE)
        build_identity = NodeIdentity.from_stat(os.fstat(build_fd))
        _validate_node(
            build_identity,
            path=directory_path / SNAPSHOT_FILE_NAME,
            kind="file",
            owner_uid=owner_uid,
        )
        if (
            build_identity.uid != owner_uid
            or stat.S_IMODE(build_identity.mode) != SNAPSHOT_BUILD_MODE
            or build_identity.size != 0
        ):
            raise ValueError("fresh snapshot file does not have exact build metadata")
        _verify_extended_metadata(
            filesystem_metadata_verifier,
            build_fd,
            directory_path / SNAPSHOT_FILE_NAME,
            "file",
        )

        copy_result = _guarded_source_operation(
            source_anchor,
            operations,
            "snapshot-copy-from-source-fd",
            lambda: snapshot_copier(
                source_anchor.fd,
                build_fd,
                source_anchor.identity.size,
                policy.max_executable_bytes,
            ),
        )
        if (
            not isinstance(copy_result, SnapshotCopyResult)
            or type(copy_result.size) is not int
            or copy_result.size != source_anchor.identity.size
            or not isinstance(copy_result.sha256, str)
            or HEX_SHA256.fullmatch(copy_result.sha256) is None
            or copy_result.sha256 != policy.expected_sha256
        ):
            raise ValueError(
                "snapshot copier returned incomplete or mismatched evidence"
            )
        copied_identity = NodeIdentity.from_stat(os.fstat(build_fd))
        if copied_identity.size != source_anchor.identity.size:
            raise ValueError(
                "snapshot file length differs from the authenticated source"
            )
        copied_digest = _sha256_fd(
            build_fd,
            expected_size=copied_identity.size,
            max_bytes=policy.max_executable_bytes,
        )
        if copied_digest != copy_result.sha256:
            raise ValueError("snapshot file digest differs from the copy stream")

        os.fsync(build_fd)
        os.fchmod(build_fd, SNAPSHOT_EXECUTABLE_MODE)
        os.fsync(build_fd)
        os.fsync(directory_anchor.fd)
        sealed_identity = NodeIdentity.from_stat(os.fstat(build_fd))
        rollback_file_identity = sealed_identity
        if (
            sealed_identity.uid != owner_uid
            or stat.S_IMODE(sealed_identity.mode) != SNAPSHOT_EXECUTABLE_MODE
            or sealed_identity.link_count != 1
            or sealed_identity.size != source_anchor.identity.size
        ):
            raise ValueError("sealed snapshot executable metadata is invalid")
        sealed_metadata = _verify_extended_metadata(
            filesystem_metadata_verifier,
            build_fd,
            directory_path / SNAPSHOT_FILE_NAME,
            "file",
        )
        assert sealed_metadata is not None
        os.close(build_fd)
        build_fd = None

        _refresh_directory_anchor(parent_anchor)
        directory_identity = _refresh_directory_anchor(directory_anchor)
        executable_path = directory_path / SNAPSHOT_FILE_NAME
        file_anchor = _open_path_anchor(
            executable_path,
            owner_uid=owner_uid,
            leaf_kind="file",
            require_executable=True,
            filesystem_metadata_verifier=filesystem_metadata_verifier,
        )
        try:
            if file_anchor.identity != sealed_identity:
                raise ValueError("reopened snapshot identity differs from its seal")
            reopened_digest = _sha256_fd(
                file_anchor.fd,
                expected_size=file_anchor.identity.size,
                max_bytes=policy.max_executable_bytes,
            )
            if reopened_digest != policy.expected_sha256:
                raise ValueError("reopened snapshot digest differs from its pin")
            _assert_snapshot_stable(directory_anchor, file_anchor)
            directory_metadata = directory_anchor.components[-1].extended_metadata
            executable_metadata = file_anchor.components[-1].extended_metadata
            assert directory_metadata is not None
            assert executable_metadata is not None
            copy_operation = operations[-1]
            copy_evidence = SnapshotCopyEvidence(
                source_identity_before=copy_operation.before,
                source_identity_after=copy_operation.after,
                destination_identity=file_anchor.identity,
                size=copy_result.size,
                sha256=copy_result.sha256,
                max_bytes=policy.max_executable_bytes,
                source_fd_only=snapshot_copier is copy_executable_from_fd,
                file_fsynced=True,
                directory_fsynced=True,
            )
            snapshot_evidence = SnapshotEvidence(
                parent_path=str(parent_path),
                parent_identity=parent_anchor.identity,
                parent_components=parent_anchor.components,
                directory_path=str(directory_path),
                executable_path=str(executable_path),
                directory_identity=directory_identity,
                executable_identity=file_anchor.identity,
                directory_components=directory_anchor.components,
                executable_components=file_anchor.components,
                directory_metadata=directory_metadata,
                executable_metadata=executable_metadata,
                copy=copy_evidence,
                seatbelt_policy=build_snapshot_seatbelt_policy(directory_path),
            )
            result = _StagedSnapshot(
                parent_path=parent_path,
                directory_name=directory_name,
                directory_anchor=directory_anchor,
                file_anchor=file_anchor,
                evidence=snapshot_evidence,
            )
            directory_anchor = None
            staged = True
            return result
        except BaseException:
            os.close(file_anchor.fd)
            raise
    finally:
        try:
            if not staged and directory_name is not None:
                assert directory_creation_identity is not None
                rollback_directory_fd = (
                    directory_anchor.fd if directory_anchor else None
                )
                directory_anchor = None
                _rollback_new_snapshot(
                    parent_fd=parent_anchor.fd,
                    directory_name=directory_name,
                    directory_fd=rollback_directory_fd,
                    directory_identity=directory_creation_identity,
                    file_created=file_created,
                    file_fd=build_fd,
                    file_identity=rollback_file_identity,
                )
        finally:
            if build_fd is not None:
                os.close(build_fd)
            if directory_anchor is not None:
                os.close(directory_anchor.fd)
            os.close(parent_anchor.fd)


def _destroy_staged_snapshot(
    staged: _StagedSnapshot,
    *,
    require_stable: bool,
) -> None:
    if require_stable:
        _assert_snapshot_stable(staged.directory_anchor, staged.file_anchor)
    parent = _open_path_anchor(
        staged.parent_path,
        owner_uid=staged.directory_anchor.owner_uid,
        leaf_kind="directory",
        require_executable=False,
        filesystem_metadata_verifier=(
            staged.directory_anchor.filesystem_metadata_verifier
        ),
    )
    try:
        expected_parent = staged.evidence.parent_identity
        if (
            parent.identity.directory_object_key()
            != expected_parent.directory_object_key()
        ):
            raise ValueError("snapshot parent mode, owner, or identity changed")
        directory_path_identity = NodeIdentity.from_stat(
            os.stat(
                os.fsencode(staged.directory_name),
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
        )
        held_directory_identity = NodeIdentity.from_stat(
            os.fstat(staged.directory_anchor.fd)
        )
        if directory_path_identity != held_directory_identity:
            raise ValueError("snapshot directory path changed before cleanup")
        file_path_identity = NodeIdentity.from_stat(
            os.stat(
                os.fsencode(SNAPSHOT_FILE_NAME),
                dir_fd=staged.directory_anchor.fd,
                follow_symlinks=False,
            )
        )
        held_file_identity = NodeIdentity.from_stat(os.fstat(staged.file_anchor.fd))
        if (
            file_path_identity != held_file_identity
            or held_file_identity != staged.evidence.executable_identity
        ):
            raise ValueError("snapshot executable path changed before cleanup")
        os.unlink(
            os.fsencode(SNAPSHOT_FILE_NAME),
            dir_fd=staged.directory_anchor.fd,
        )
        os.fsync(staged.directory_anchor.fd)
        os.rmdir(os.fsencode(staged.directory_name), dir_fd=parent.fd)
        os.fsync(parent.fd)
    finally:
        os.close(parent.fd)


def _close_staged_snapshot_fds(staged: _StagedSnapshot) -> None:
    for descriptor in (staged.file_anchor.fd, staged.directory_anchor.fd):
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def _kill_command(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2.0)


def run_bounded_command(
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> CommandResult:
    _require_python_313()
    if (
        not argv
        or not pathlib.Path(argv[0]).is_absolute()
        or any(not isinstance(argument, str) or "\0" in argument for argument in argv)
    ):
        raise ValueError(
            "bounded command requires an absolute executable and text argv"
        )
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise ValueError("bounded command limits must be positive")
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
        close_fds=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams = {
        stdout_fd: bytearray(),
        stderr_fd: bytearray(),
    }
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    total = 0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"command exceeded {timeout_seconds} seconds")
            events = selector.select(remaining)
            if not events:
                raise TimeoutError(f"command exceeded {timeout_seconds} seconds")
            for key, _ in events:
                chunk = os.read(
                    key.fd,
                    min(READ_CHUNK, max_output_bytes + 1 - total),
                )
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                streams[key.fd].extend(chunk)
                total += len(chunk)
                if total > max_output_bytes:
                    raise ValueError(f"command output exceeds {max_output_bytes} bytes")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"command exceeded {timeout_seconds} seconds")
        returncode = process.wait(timeout=remaining)
    except BaseException:
        _kill_command(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        argv=argv,
        returncode=returncode,
        stdout=bytes(streams[stdout_fd]),
        stderr=bytes(streams[stderr_fd]),
    )


def _validate_command_result(
    result: CommandResult,
    *,
    argv: tuple[str, ...],
    max_output_bytes: int,
) -> None:
    if not isinstance(result, CommandResult) or result.argv != argv:
        raise ValueError("command runner returned evidence for a different argv")
    if type(result.returncode) is not int:
        raise ValueError("command runner returned a malformed exit status")
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise ValueError("command runner returned non-byte output")
    if len(result.stdout) + len(result.stderr) > max_output_bytes:
        raise ValueError("command runner exceeded the requested output bound")


def _invoke_guarded(
    *,
    anchor: _PathAnchor,
    operations: list[OperationIdentityEvidence],
    label: str,
    argv: tuple[str, ...],
    timeout_seconds: float,
    max_output_bytes: int,
    command_runner: CommandRunner,
    additional_guard: Callable[[], object] | None = None,
    staged_snapshot: _StagedSnapshot | None = None,
) -> CommandResult:
    def invoke() -> CommandResult:
        if additional_guard is not None:
            additional_guard()
        result = command_runner(
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if additional_guard is not None:
            additional_guard()
        _validate_command_result(
            result,
            argv=argv,
            max_output_bytes=max_output_bytes,
        )
        return result

    if staged_snapshot is None:
        return _guarded_source_operation(anchor, operations, label, invoke)
    if anchor is not staged_snapshot.file_anchor:
        raise ValueError("snapshot command guard does not match its executable")
    return _guarded_snapshot_operation(staged_snapshot, operations, label, invoke)


def parse_codesign_metadata(result: CommandResult) -> SignatureMetadata:
    if result.stdout:
        raise ValueError("codesign metadata unexpectedly used stdout")
    if b"\0" in result.stderr or b"\r" in result.stderr:
        raise ValueError("codesign metadata contains an invalid byte")
    text = result.stderr.decode("utf-8", "strict")
    teams: list[str] = []
    full_hashes: list[str] = []
    for line in text.split("\n"):
        if "TeamIdentifier" in line:
            match = TEAM_LINE.fullmatch(line)
            if match is None:
                raise ValueError("codesign TeamIdentifier output is malformed")
            teams.append(match.group(1))
        if "CandidateCDHashFull" in line:
            match = FULL_CDHASH_LINE.fullmatch(line)
            if match is None:
                raise ValueError("codesign full CDHash output is malformed")
            full_hashes.append(match.group(1))
    if len(teams) != 1 or len(full_hashes) != 1:
        raise ValueError("codesign metadata fields are missing or duplicated")
    return SignatureMetadata(teams[0], full_hashes[0])


def _authenticate_signature(
    *,
    anchor: _PathAnchor,
    operations: list[OperationIdentityEvidence],
    command_runner: CommandRunner,
    metadata_verifier: MetadataVerifier,
    policy: CodexExecutablePolicy,
    label_prefix: str,
    staged_snapshot: _StagedSnapshot | None = None,
) -> SignatureEvidence:
    path = str(anchor.path)
    verify_argv = (
        CODESIGN_PATH,
        "--verify",
        "--strict",
        "--verbose=4",
        "--",
        path,
    )
    verified = _invoke_guarded(
        anchor=anchor,
        operations=operations,
        label=f"{label_prefix}-codesign-strict-verification",
        argv=verify_argv,
        timeout_seconds=CODESIGN_TIMEOUT_SECONDS,
        max_output_bytes=MAX_CODESIGN_OUTPUT_BYTES,
        command_runner=command_runner,
        staged_snapshot=staged_snapshot,
    )
    if verified.returncode != 0:
        raise ValueError(f"{label_prefix} codesign strict verification failed")

    metadata_argv = (
        CODESIGN_PATH,
        "--display",
        "--verbose=4",
        "--",
        path,
    )
    metadata_result = _invoke_guarded(
        anchor=anchor,
        operations=operations,
        label=f"{label_prefix}-codesign-metadata",
        argv=metadata_argv,
        timeout_seconds=CODESIGN_TIMEOUT_SECONDS,
        max_output_bytes=MAX_CODESIGN_OUTPUT_BYTES,
        command_runner=command_runner,
        staged_snapshot=staged_snapshot,
    )
    if metadata_result.returncode != 0:
        raise ValueError(f"{label_prefix} codesign metadata query failed")
    signature_metadata = metadata_verifier(metadata_result)
    if not isinstance(signature_metadata, SignatureMetadata):
        raise ValueError("metadata verifier returned malformed evidence")
    if signature_metadata.team_identifier != policy.expected_team_identifier:
        raise ValueError(f"{label_prefix} codesign TeamIdentifier mismatch")
    if signature_metadata.full_cdhash != policy.expected_full_cdhash:
        raise ValueError(f"{label_prefix} codesign full CDHash mismatch")
    return SignatureEvidence(
        team_identifier=signature_metadata.team_identifier,
        full_cdhash=signature_metadata.full_cdhash,
        strict_verification=CommandEvidence.from_result(
            verified,
            timeout_seconds=CODESIGN_TIMEOUT_SECONDS,
            max_output_bytes=MAX_CODESIGN_OUTPUT_BYTES,
        ),
        metadata_query=CommandEvidence.from_result(
            metadata_result,
            timeout_seconds=CODESIGN_TIMEOUT_SECONDS,
            max_output_bytes=MAX_CODESIGN_OUTPUT_BYTES,
        ),
    )


def _probe_stderr_is_expected(stderr: bytes) -> bool:
    return stderr in {b"", EXPECTED_PATH_ALIAS_WARNING}


def _parse_version(result: CommandResult, expected: str) -> str:
    if result.returncode != 0 or not _probe_stderr_is_expected(result.stderr):
        raise ValueError("Codex --version probe did not complete cleanly")
    expected_bytes = expected.encode("ascii")
    if result.stdout not in {expected_bytes, expected_bytes + b"\n"}:
        raise ValueError("Codex version does not match the pinned version")
    return expected


def _option_declarations(help_text: str, option: str) -> int:
    pattern = re.compile(
        rf"^[ \t]*(?:-[A-Za-z0-9](?:,[ \t]+|[ \t]+))?"
        rf"{re.escape(option)}(?=$|[ \t=,<])"
    )
    return sum(pattern.match(line) is not None for line in help_text.split("\n"))


def _parse_help(result: CommandResult) -> tuple[bool, bool]:
    if result.returncode != 0 or not _probe_stderr_is_expected(result.stderr):
        raise ValueError("Codex app-server --help probe did not complete cleanly")
    if b"\0" in result.stdout or b"\r" in result.stdout:
        raise ValueError("Codex app-server help contains an invalid byte")
    text = result.stdout.decode("utf-8", "strict")
    stdio_count = _option_declarations(text, "--stdio")
    strict_count = _option_declarations(text, "--strict-config")
    if stdio_count != 1 or strict_count != 1:
        raise ValueError(
            "Codex app-server help does not uniquely advertise required options"
        )
    return True, True


def _hash_provided_schema(
    path: pathlib.Path,
    *,
    owner_uid: int,
    policy: CodexExecutablePolicy,
) -> SchemaEvidence:
    schema_path = _canonical_absolute_path(path, label="aggregate schema path")
    anchor = _open_path_anchor(
        schema_path,
        owner_uid=owner_uid,
        leaf_kind="file",
        require_executable=False,
    )
    try:
        before = _assert_anchor_stable(anchor)
        digest = _sha256_fd(
            anchor.fd,
            expected_size=before.size,
            max_bytes=policy.max_schema_bytes,
        )
        after = _assert_anchor_stable(anchor)
        if before != after:
            raise ValueError("aggregate schema identity changed while hashing")
        return SchemaEvidence("provided", before.size, digest, None)
    finally:
        os.close(anchor.fd)


def _open_generated_schema_at(
    output_fd: int,
    *,
    owner_uid: int,
    max_bytes: int,
) -> tuple[int, str]:
    name = os.fsencode(AGGREGATE_SCHEMA_NAME)
    before = NodeIdentity.from_stat(
        os.stat(name, dir_fd=output_fd, follow_symlinks=False)
    )
    path = pathlib.Path(AGGREGATE_SCHEMA_NAME)
    _validate_node(
        before,
        path=path,
        kind="file",
        owner_uid=owner_uid,
    )
    fd = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=output_fd,
    )
    try:
        descriptor = NodeIdentity.from_stat(os.fstat(fd))
        after_open = NodeIdentity.from_stat(
            os.stat(name, dir_fd=output_fd, follow_symlinks=False)
        )
        if before != descriptor or descriptor != after_open:
            raise ValueError("generated aggregate schema raced while opening")
        digest = _sha256_fd(fd, expected_size=descriptor.size, max_bytes=max_bytes)
        after_hash = NodeIdentity.from_stat(os.fstat(fd))
        path_after_hash = NodeIdentity.from_stat(
            os.stat(name, dir_fd=output_fd, follow_symlinks=False)
        )
        if descriptor != after_hash or after_hash != path_after_hash:
            raise ValueError("generated aggregate schema raced while hashing")
        return descriptor.size, digest
    finally:
        os.close(fd)


def _generate_schema(
    *,
    source_anchor: _PathAnchor,
    operations: list[OperationIdentityEvidence],
    schema_work_root: pathlib.Path,
    command_runner: CommandRunner,
    owner_uid: int,
    policy: CodexExecutablePolicy,
    staged_snapshot: _StagedSnapshot | None = None,
) -> SchemaEvidence:
    work_root_path = _canonical_absolute_path(
        schema_work_root, label="schema work root"
    )
    work_root = _open_path_anchor(
        work_root_path,
        owner_uid=owner_uid,
        leaf_kind="directory",
        require_executable=False,
    )
    output_path: pathlib.Path | None = None
    output_anchor: _PathAnchor | None = None
    try:
        _assert_directory_object_stable(work_root)
        output_path = pathlib.Path(
            tempfile.mkdtemp(prefix="codex-schema-", dir=work_root_path)
        )
        os.chmod(output_path, 0o700, follow_symlinks=False)
        _assert_directory_object_stable(work_root)
        output_anchor = _open_path_anchor(
            output_path,
            owner_uid=owner_uid,
            leaf_kind="directory",
            require_executable=False,
        )
        argv = (
            str(source_anchor.path),
            "app-server",
            "generate-json-schema",
            "--out",
            str(output_path),
        )
        generated = _invoke_guarded(
            anchor=source_anchor,
            operations=operations,
            label="app-server-generate-json-schema",
            argv=argv,
            timeout_seconds=SCHEMA_TIMEOUT_SECONDS,
            max_output_bytes=MAX_SCHEMA_COMMAND_OUTPUT_BYTES,
            command_runner=command_runner,
            additional_guard=lambda: _assert_directory_object_stable(output_anchor),
            staged_snapshot=staged_snapshot,
        )
        if generated.returncode != 0 or not _probe_stderr_is_expected(generated.stderr):
            raise ValueError("Codex app-server schema generation failed")
        size, digest = _open_generated_schema_at(
            output_anchor.fd,
            owner_uid=owner_uid,
            max_bytes=policy.max_schema_bytes,
        )
        return SchemaEvidence(
            "generated",
            size,
            digest,
            CommandEvidence.from_result(
                generated,
                timeout_seconds=SCHEMA_TIMEOUT_SECONDS,
                max_output_bytes=MAX_SCHEMA_COMMAND_OUTPUT_BYTES,
            ),
        )
    finally:
        if output_anchor is not None:
            os.close(output_anchor.fd)
        os.close(work_root.fd)
        if output_path is not None:
            shutil.rmtree(output_path)


def _fd_execution_evidence() -> FdExecutionEvidence:
    return FdExecutionEvidence(
        supported=False,
        mechanism="unsupported-on-macos",
        reason=(
            "macOS /dev/fd execution is not accepted as fd-bound execution; "
            "the authenticated source pathname is forbidden and launch is "
            "permitted only from the revalidated private snapshot pathname"
        ),
    )


def _revalidate_staged_snapshot(
    staged: _StagedSnapshot,
    *,
    policy: CodexExecutablePolicy,
    label: str,
) -> ExecutableRevalidationEvidence:
    operations: list[OperationIdentityEvidence] = []
    digest = _guarded_snapshot_operation(
        staged,
        operations,
        label,
        lambda: _sha256_fd(
            staged.file_anchor.fd,
            expected_size=staged.evidence.executable_identity.size,
            max_bytes=policy.max_executable_bytes,
        ),
    )
    operation = operations[0]
    if (
        operation.before != staged.evidence.executable_identity
        or operation.after != staged.evidence.executable_identity
        or digest != staged.evidence.copy.sha256
        or digest != policy.expected_sha256
    ):
        raise ValueError("private snapshot identity or digest changed")
    return ExecutableRevalidationEvidence(
        identity=operation.after,
        sha256=digest,
        operation=operation,
        fd_execution=_fd_execution_evidence(),
    )


def _validate_snapshot_protection(
    policy: SnapshotSeatbeltPolicy,
    evidence: SnapshotProtectionEvidence,
    verifier: SnapshotProtectionVerifier | None,
) -> None:
    if not isinstance(evidence, SnapshotProtectionEvidence):
        raise ValueError("snapshot protection evidence is malformed")
    if (
        not isinstance(evidence.snapshot_directory, str)
        or not isinstance(evidence.snapshot_policy_sha256, str)
        or not isinstance(evidence.effective_profile_sha256, str)
        or not isinstance(evidence.kernel, str)
        or not isinstance(evidence.denied_operations, tuple)
        or any(
            not isinstance(operation, str) for operation in evidence.denied_operations
        )
    ):
        raise ValueError("snapshot protection evidence is malformed")
    expected_policy = build_snapshot_seatbelt_policy(
        pathlib.Path(policy.snapshot_directory)
    )
    if policy != expected_policy:
        raise ValueError("snapshot Seatbelt policy evidence changed")
    if (
        evidence.snapshot_directory != policy.snapshot_directory
        or evidence.snapshot_policy_sha256 != policy.sha256
        or HEX_SHA256.fullmatch(evidence.effective_profile_sha256) is None
        or evidence.kernel != "macos-seatbelt"
        or type(evidence.no_child_profile_verified) is not bool
        or not evidence.no_child_profile_verified
        or type(evidence.applied_before_snapshot_exec) is not bool
        or not evidence.applied_before_snapshot_exec
        or evidence.denied_operations != policy.required_denials
        or type(evidence.self_mutation_probe_denied) is not bool
        or not evidence.self_mutation_probe_denied
    ):
        raise ValueError("kernel no-child/Seatbelt snapshot protection is incomplete")
    if verifier is None:
        raise ValueError("snapshot protection verifier is required before launch")
    if verifier(policy, evidence) is not None:
        raise ValueError("snapshot protection verifier returned malformed evidence")


def _validate_quiescence(
    evidence: ProcessQuiescenceEvidence,
    *,
    expected_token: str | None,
    expected_process_id: int | None,
    current_phase: str,
    verifier: QuiescenceVerifier | None,
) -> None:
    if not isinstance(evidence, ProcessQuiescenceEvidence):
        raise ValueError("process quiescence evidence is malformed")
    if evidence.handoff_token is not None and not isinstance(
        evidence.handoff_token, str
    ):
        raise ValueError("process quiescence handoff token is malformed")
    if evidence.process_id is not None and (
        type(evidence.process_id) is not int or evidence.process_id <= 0
    ):
        raise ValueError("process quiescence PID is malformed")
    if not isinstance(evidence.launch_state, str) or evidence.launch_state not in {
        BOUND_LAUNCH_STATE,
        NEVER_LAUNCHED_ABORT_STATE,
    }:
        raise ValueError("process quiescence launch state is malformed")
    if evidence.handoff_token != expected_token:
        raise ValueError("process quiescence handoff token is stale")
    if evidence.launch_state == NEVER_LAUNCHED_ABORT_STATE:
        if expected_process_id is not None or evidence.process_id is not None:
            raise ValueError("never-launched abort evidence contains a process PID")
        if current_phase not in {
            "authenticated",
            "pre-fork",
            "child-immediately-before-exec",
        }:
            raise ValueError("custody is not in a never-launched abort state")
    else:
        if expected_process_id is None or current_phase not in {
            "parent-exec-handoff-bound",
            "parent-post-exec-handoff",
        }:
            raise ValueError("process quiescence lacks a bound launch identity")
        if evidence.process_id != expected_process_id:
            raise ValueError("process quiescence PID does not match the handoff")
    if any(
        type(value) is not bool or not value
        for value in (
            evidence.leader_reaped,
            evidence.process_group_empty,
            evidence.descendant_handles_closed,
            evidence.observed_by_supervisor,
        )
    ):
        raise ValueError("process is not proven quiescent")
    if (
        not isinstance(evidence.reason, str)
        or not evidence.reason
        or len(evidence.reason) > 256
        or any(
            ord(character) < 32 or ord(character) > 126 for character in evidence.reason
        )
    ):
        raise ValueError("process quiescence reason is malformed")
    if verifier is None:
        raise ValueError("process quiescence verifier is required before cleanup")
    if verifier(evidence) is not None:
        raise ValueError("process quiescence verifier returned malformed evidence")


class CodexExecutableCustody:
    def __init__(
        self,
        *,
        evidence: CodexExecutableEvidence,
        staged: _StagedSnapshot,
        policy: CodexExecutablePolicy,
        snapshot_protection_verifier: SnapshotProtectionVerifier | None,
        quiescence_verifier: QuiescenceVerifier | None,
    ) -> None:
        self.evidence = evidence
        self._staged = staged
        self._policy = policy
        self._snapshot_protection_verifier = snapshot_protection_verifier
        self._quiescence_verifier = quiescence_verifier
        self._phase = "authenticated"
        self._generation = 0
        self._handoff_token: str | None = None
        self._process_id: int | None = None
        self._quiescence: ProcessQuiescenceEvidence | None = None
        self._closed = False
        self._retained_snapshot = False
        self._stale_reason: str | None = None

    def _ensure_open(self) -> None:
        if self._closed:
            raise CodexExecutableError(
                "Codex executable custody is closed",
                code="codex-custody-closed",
            )

    def _mark_stale(self, message: str, error: Exception | None = None) -> Never:
        self._stale_reason = message
        exception = CodexExecutableCustodyStale(message)
        if error is None:
            raise exception
        raise exception from error

    def _require_live_handoff(self) -> None:
        self._ensure_open()
        if self._stale_reason is not None:
            raise CodexExecutableCustodyStale(self._stale_reason)

    @property
    def executable_fd(self) -> int:
        self._ensure_open()
        return self._staged.file_anchor.fd

    @property
    def directory_fd(self) -> int:
        self._ensure_open()
        return self._staged.directory_anchor.fd

    @property
    def snapshot_path(self) -> pathlib.Path:
        self._ensure_open()
        return self._staged.file_anchor.path

    @property
    def seatbelt_policy(self) -> SnapshotSeatbeltPolicy:
        return self.evidence.snapshot.seatbelt_policy

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def retained_snapshot(self) -> bool:
        return self._retained_snapshot

    def fileno(self) -> int:
        return self.executable_fd

    def attest_owner_snapshot_launch(self) -> OwnerSnapshotLaunchAttestation:
        """Bind the current private snapshot evidence to its held custody FDs.

        The returned attestation is intended for
        ``prepare_custodied_snapshot_no_child_profile``. The custody object must
        remain open, and neither descriptor may be closed, replaced, or made
        inheritable until that prepared launch has either succeeded or failed.
        """

        _require_python_313()
        self._require_live_handoff()
        if self._phase != "authenticated":
            self._mark_stale(
                "owner snapshot launch attestation requires fresh authenticated custody"
            )
        revalidation = self.revalidate()
        try:
            inconsistent = (
                revalidation.identity != self.evidence.snapshot.executable_identity
                or revalidation.sha256 != self.evidence.sha256
                or os.get_inheritable(self.executable_fd)
                or os.get_inheritable(self.directory_fd)
            )
        except OSError as error:
            self._mark_stale(
                "owner snapshot launch descriptors became unavailable",
                error,
            )
        if inconsistent:
            self._mark_stale("owner snapshot launch attestation is inconsistent")
        return OwnerSnapshotLaunchAttestation(
            executable_fd=self.executable_fd,
            directory_fd=self.directory_fd,
            snapshot=self.evidence.snapshot,
            expected_sha256=self.evidence.sha256,
            revalidation=revalidation,
        )

    def revalidate(self) -> ExecutableRevalidationEvidence:
        _require_python_313()
        self._require_live_handoff()
        try:
            return _revalidate_staged_snapshot(
                self._staged,
                policy=self._policy,
                label="custody-snapshot-revalidation-sha256",
            )
        except Exception as error:
            self._mark_stale(str(error), error)

    def _validate_handoff(
        self,
        handoff: SnapshotHandoffEvidence,
        *,
        phase: str,
        require_protection: bool,
    ) -> None:
        if not isinstance(handoff, SnapshotHandoffEvidence):
            self._mark_stale("snapshot handoff evidence is malformed")
        assert self._handoff_token is not None
        if (
            type(handoff.generation) is not int
            or not isinstance(handoff.token, str)
            or len(handoff.token) != 64
            or not isinstance(handoff.phase, str)
            or not isinstance(handoff.snapshot_path, str)
            or not isinstance(handoff.identity, NodeIdentity)
            or not isinstance(handoff.sha256, str)
            or not isinstance(
                handoff.revalidation,
                ExecutableRevalidationEvidence,
            )
            or not isinstance(
                handoff.revalidation.fd_execution,
                FdExecutionEvidence,
            )
            or not isinstance(
                handoff.revalidation.operation,
                OperationIdentityEvidence,
            )
            or not isinstance(handoff.identity_operations, tuple)
            or any(
                not isinstance(operation, OperationIdentityEvidence)
                for operation in handoff.identity_operations
            )
        ):
            self._mark_stale("snapshot handoff evidence is malformed")
        if (
            handoff.generation != self._generation
            or not secrets.compare_digest(handoff.token, self._handoff_token)
            or handoff.phase != phase
            or handoff.snapshot_path != str(self._staged.file_anchor.path)
            or handoff.identity != self._staged.evidence.executable_identity
            or handoff.sha256 != self._policy.expected_sha256
            or handoff.revalidation.identity
            != self._staged.evidence.executable_identity
            or handoff.revalidation.sha256 != self._policy.expected_sha256
            or handoff.revalidation.fd_execution != _fd_execution_evidence()
            or not handoff.identity_operations
            or handoff.identity_operations[-1] != handoff.revalidation.operation
            or any(
                operation.before != self._staged.evidence.executable_identity
                or operation.after != self._staged.evidence.executable_identity
                for operation in handoff.identity_operations
            )
        ):
            self._mark_stale("snapshot handoff evidence is stale or inconsistent")
        if require_protection and handoff.protection is None:
            self._mark_stale("snapshot handoff lacks kernel protection evidence")
        if not require_protection and handoff.protection is not None:
            self._mark_stale("pre-fork handoff unexpectedly claims kernel protection")

    def pre_fork_revalidate(self) -> SnapshotHandoffEvidence:
        self._require_live_handoff()
        if self._phase != "authenticated":
            self._mark_stale("snapshot custody is not fresh for a pre-fork handoff")
        revalidation = self.revalidate()
        self._generation += 1
        self._handoff_token = secrets.token_hex(32)
        self._phase = "pre-fork"
        return SnapshotHandoffEvidence(
            generation=self._generation,
            token=self._handoff_token,
            phase="pre-fork",
            snapshot_path=str(self._staged.file_anchor.path),
            identity=revalidation.identity,
            sha256=revalidation.sha256,
            protection=None,
            identity_operations=(revalidation.operation,),
            revalidation=revalidation,
        )

    def child_revalidate_immediately_before_exec(
        self,
        handoff: SnapshotHandoffEvidence,
        *,
        protection: SnapshotProtectionEvidence,
    ) -> SnapshotExecTarget:
        self._require_live_handoff()
        if self._phase not in {"pre-fork", "child-immediately-before-exec"}:
            self._mark_stale("snapshot custody is not awaiting child exec")
        if self._phase == "child-immediately-before-exec":
            self._mark_stale("child exec handoff was already consumed")
        self._validate_handoff(
            handoff,
            phase="pre-fork",
            require_protection=False,
        )
        operations: list[OperationIdentityEvidence] = []
        try:
            _guarded_snapshot_operation(
                self._staged,
                operations,
                "child-seatbelt-protection-verification",
                lambda: _validate_snapshot_protection(
                    self.seatbelt_policy,
                    protection,
                    self._snapshot_protection_verifier,
                ),
            )
            revalidation = _revalidate_staged_snapshot(
                self._staged,
                policy=self._policy,
                label="child-immediately-before-exec-sha256",
            )
        except Exception as error:
            self._mark_stale(str(error), error)
        child_handoff = SnapshotHandoffEvidence(
            generation=self._generation,
            token=handoff.token,
            phase="child-immediately-before-exec",
            snapshot_path=str(self._staged.file_anchor.path),
            identity=revalidation.identity,
            sha256=revalidation.sha256,
            protection=protection,
            identity_operations=(operations[0], revalidation.operation),
            revalidation=revalidation,
        )
        self._phase = "child-immediately-before-exec"
        return SnapshotExecTarget(
            executable_path=str(self._staged.file_anchor.path),
            seatbelt_rules=self.seatbelt_policy.rules,
            handoff=child_handoff,
            revalidation=revalidation,
        )

    def parent_revalidate_after_exec_handoff(
        self,
        target: SnapshotExecTarget,
        *,
        process_id: int,
    ) -> SnapshotHandoffEvidence:
        self._require_live_handoff()
        if self._phase not in {"pre-fork", "child-immediately-before-exec"}:
            self._mark_stale("snapshot custody is not awaiting parent exec handoff")
        if type(process_id) is not int or process_id <= 0:
            self._mark_stale("parent exec handoff PID is malformed")
        self._process_id = process_id
        self._phase = "parent-exec-handoff-bound"
        if (
            not isinstance(target, SnapshotExecTarget)
            or target.executable_path != str(self._staged.file_anchor.path)
            or target.seatbelt_rules != self.seatbelt_policy.rules
        ):
            self._mark_stale("parent received a malformed snapshot exec target")
        self._validate_handoff(
            target.handoff,
            phase="child-immediately-before-exec",
            require_protection=True,
        )
        if target.revalidation != target.handoff.revalidation:
            self._mark_stale("parent received inconsistent exec revalidation evidence")
        assert target.handoff.protection is not None
        operations: list[OperationIdentityEvidence] = []
        try:
            _guarded_snapshot_operation(
                self._staged,
                operations,
                "parent-seatbelt-protection-verification",
                lambda: _validate_snapshot_protection(
                    self.seatbelt_policy,
                    target.handoff.protection,
                    self._snapshot_protection_verifier,
                ),
            )
            revalidation = _revalidate_staged_snapshot(
                self._staged,
                policy=self._policy,
                label="parent-post-exec-handoff-sha256",
            )
        except Exception as error:
            self._mark_stale(str(error), error)
        self._phase = "parent-post-exec-handoff"
        return SnapshotHandoffEvidence(
            generation=self._generation,
            token=target.handoff.token,
            phase=self._phase,
            snapshot_path=str(self._staged.file_anchor.path),
            identity=revalidation.identity,
            sha256=revalidation.sha256,
            protection=target.handoff.protection,
            identity_operations=(operations[0], revalidation.operation),
            revalidation=revalidation,
        )

    def confirm_process_quiescence(
        self,
        evidence: ProcessQuiescenceEvidence,
    ) -> None:
        self._ensure_open()
        if self._phase in {"quiescent", "cleaned"}:
            raise CodexExecutableCustodyStale("process quiescence was already consumed")
        try:
            _validate_quiescence(
                evidence,
                expected_token=self._handoff_token,
                expected_process_id=self._process_id,
                current_phase=self._phase,
                verifier=self._quiescence_verifier,
            )
        except Exception as error:
            raise CodexExecutableCustodyStale(str(error)) from error
        self._quiescence = evidence
        self._phase = "quiescent"

    def cleanup(self) -> None:
        if self._closed:
            return
        if self._phase != "quiescent" or self._quiescence is None:
            raise CodexExecutableCustodyStale(
                "snapshot cleanup requires verified process quiescence"
            )
        cleanup_error: Exception | None = None
        try:
            _destroy_staged_snapshot(self._staged, require_stable=True)
        except Exception as error:
            cleanup_error = error
            self._retained_snapshot = True
            self._stale_reason = str(error)
        finally:
            try:
                _close_staged_snapshot_fds(self._staged)
            finally:
                self._closed = True
                self._phase = "stale-retained" if cleanup_error else "cleaned"
        if cleanup_error is not None:
            raise CodexExecutableCustodyStale(
                "snapshot changed before cleanup; suspicious paths were retained"
            ) from cleanup_error

    def close(self) -> None:
        self.cleanup()

    def revalidate_before_exec(self) -> ExecutableRevalidationEvidence:
        self.revalidate()
        raise CodexExecutableExecutionUnsupported(self.evidence.fd_execution.reason)


def authenticate_codex_executable(
    source_path: pathlib.Path,
    *,
    snapshot_parent: pathlib.Path,
    exclusion_roots: ExecutableExclusionRoots,
    aggregate_schema_path: pathlib.Path | None = None,
    schema_work_root: pathlib.Path | None = None,
    command_runner: CommandRunner = run_bounded_command,
    metadata_verifier: MetadataVerifier = parse_codesign_metadata,
    filesystem_metadata_verifier: FilesystemMetadataVerifier = (
        verify_macos_filesystem_metadata
    ),
    snapshot_copier: SnapshotCopier = copy_executable_from_fd,
    snapshot_protection_verifier: SnapshotProtectionVerifier | None = None,
    quiescence_verifier: QuiescenceVerifier | None = None,
    policy: CodexExecutablePolicy = DEFAULT_CODEX_EXECUTABLE_POLICY,
    owner_uid: int | None = None,
    platform_name: str | None = None,
) -> CodexExecutableCustody:
    _require_python_313()
    selected_platform = sys.platform if platform_name is None else platform_name
    if selected_platform != "darwin":
        raise CodexExecutableError(
            "Codex executable authentication is implemented only for macOS",
            code="codex-executable-platform-unsupported",
        )
    source_anchor: _PathAnchor | None = None
    staged: _StagedSnapshot | None = None
    try:
        policy.validate()
        source = _canonical_absolute_path(source_path, label="Codex executable")
        exclusions = _validate_exclusions(source, exclusion_roots)
        if aggregate_schema_path is not None and schema_work_root is not None:
            raise ValueError(
                "provided and generated schema inputs are mutually exclusive"
            )
        if aggregate_schema_path is None and schema_work_root is None:
            raise ValueError(
                "schema_work_root is required when no aggregate schema is provided"
            )
        trusted_uid = os.getuid() if owner_uid is None else owner_uid
        if type(trusted_uid) is not int or trusted_uid < 0:
            raise ValueError("owner UID policy is invalid")

        source_anchor = _open_path_anchor(
            source,
            owner_uid=trusted_uid,
            leaf_kind="file",
            require_executable=True,
            filesystem_metadata_verifier=filesystem_metadata_verifier,
        )
        if os.get_inheritable(source_anchor.fd):
            raise ValueError("held source executable FD is unexpectedly inheritable")
        source_components = source_anchor.components
        source_identity = source_anchor.identity
        operations: list[OperationIdentityEvidence] = []
        digest = _guarded_source_operation(
            source_anchor,
            operations,
            "source-sha256",
            lambda: _sha256_fd(
                source_anchor.fd,
                expected_size=source_identity.size,
                max_bytes=policy.max_executable_bytes,
            ),
        )
        if digest != policy.expected_sha256:
            raise ValueError(
                "Codex executable SHA-256 does not match the pinned digest"
            )
        source_signature = _authenticate_signature(
            anchor=source_anchor,
            operations=operations,
            command_runner=command_runner,
            metadata_verifier=metadata_verifier,
            policy=policy,
            label_prefix="source",
        )

        staged = _stage_snapshot(
            source_anchor=source_anchor,
            snapshot_parent=snapshot_parent,
            owner_uid=trusted_uid,
            policy=policy,
            operations=operations,
            snapshot_copier=snapshot_copier,
            filesystem_metadata_verifier=filesystem_metadata_verifier,
        )
        if os.get_inheritable(staged.file_anchor.fd) or os.get_inheritable(
            staged.directory_anchor.fd
        ):
            raise ValueError("snapshot custody FDs are unexpectedly inheritable")
        final_source_identity = _assert_anchor_stable(source_anchor)
        if final_source_identity != source_identity:
            raise ValueError("source identity changed before its custody ended")
        os.close(source_anchor.fd)
        source_anchor = None

        snapshot_signature = _authenticate_signature(
            anchor=staged.file_anchor,
            operations=operations,
            command_runner=command_runner,
            metadata_verifier=metadata_verifier,
            policy=policy,
            label_prefix="snapshot",
            staged_snapshot=staged,
        )
        snapshot_text = str(staged.file_anchor.path)
        version_argv = (snapshot_text, "--version")
        version_result = _invoke_guarded(
            anchor=staged.file_anchor,
            operations=operations,
            label="snapshot-version",
            argv=version_argv,
            timeout_seconds=PROBE_TIMEOUT_SECONDS,
            max_output_bytes=MAX_VERSION_OUTPUT_BYTES,
            command_runner=command_runner,
            staged_snapshot=staged,
        )
        version = _parse_version(version_result, policy.expected_version)

        help_argv = (snapshot_text, "app-server", "--help")
        help_result = _invoke_guarded(
            anchor=staged.file_anchor,
            operations=operations,
            label="snapshot-app-server-help",
            argv=help_argv,
            timeout_seconds=PROBE_TIMEOUT_SECONDS,
            max_output_bytes=MAX_HELP_OUTPUT_BYTES,
            command_runner=command_runner,
            staged_snapshot=staged,
        )
        stdio, strict_config = _parse_help(help_result)

        if aggregate_schema_path is not None:
            schema = _hash_provided_schema(
                aggregate_schema_path,
                owner_uid=trusted_uid,
                policy=policy,
            )
        else:
            assert schema_work_root is not None
            schema = _generate_schema(
                source_anchor=staged.file_anchor,
                operations=operations,
                schema_work_root=schema_work_root,
                command_runner=command_runner,
                owner_uid=trusted_uid,
                policy=policy,
                staged_snapshot=staged,
            )
        if schema.sha256 != policy.expected_schema_sha256:
            raise ValueError("app-server aggregate schema digest does not match")
        final_revalidation = _revalidate_staged_snapshot(
            staged,
            policy=policy,
            label="authentication-final-snapshot-sha256",
        )
        operations.append(final_revalidation.operation)

        fd_execution = _fd_execution_evidence()
        evidence = CodexExecutableEvidence(
            source_path=str(source),
            path_components=source_components,
            identity=source_identity,
            size=source_identity.size,
            sha256=digest,
            source_signature=source_signature,
            snapshot=staged.evidence,
            version=version,
            version_command=CommandEvidence.from_result(
                version_result,
                timeout_seconds=PROBE_TIMEOUT_SECONDS,
                max_output_bytes=MAX_VERSION_OUTPUT_BYTES,
            ),
            signature=snapshot_signature,
            capabilities=CapabilityEvidence(
                stdio=stdio,
                strict_config=strict_config,
                help_sha256=hashlib.sha256(help_result.stdout).hexdigest(),
                help_command=CommandEvidence.from_result(
                    help_result,
                    timeout_seconds=PROBE_TIMEOUT_SECONDS,
                    max_output_bytes=MAX_HELP_OUTPUT_BYTES,
                ),
                schema=schema,
            ),
            identity_operations=tuple(operations),
            exclusion_roots=exclusions,
            no_follow=True,
            executable_fd_close_on_exec=True,
            fd_execution=fd_execution,
            threat_boundary=ThreatBoundaryEvidence(
                statement=(
                    "Containment covers the untrusted reviewed repository and "
                    "model runtime after verified kernel Seatbelt activation; "
                    "an unrelated already-compromised same-UID process and a "
                    "malicious root/admin TCB member are outside this contract."
                ),
                contained_subjects=THREAT_CONTAINED_SUBJECTS,
                excluded_subjects=THREAT_EXCLUDED_SUBJECTS,
                source_path_never_executed_after_fd_authentication=True,
                fd_bound_exec_claimed=False,
                snapshot_path_is_only_launch_target=True,
            ),
        )
        custody = CodexExecutableCustody(
            evidence=evidence,
            staged=staged,
            policy=policy,
            snapshot_protection_verifier=snapshot_protection_verifier,
            quiescence_verifier=quiescence_verifier,
        )
        staged = None
        return custody
    except Exception as error:
        rollback_error: Exception | None = None
        if staged is not None:
            try:
                _destroy_staged_snapshot(staged, require_stable=True)
            except Exception as caught:
                rollback_error = caught
            finally:
                _close_staged_snapshot_fds(staged)
                staged = None
        if rollback_error is not None:
            raise CodexExecutableError(
                "authentication failed and private snapshot rollback was refused: "
                f"{rollback_error}"
            ) from error
        if isinstance(error, CodexExecutableError):
            raise
        raise CodexExecutableError(str(error)) from error
    finally:
        if source_anchor is not None:
            os.close(source_anchor.fd)


__all__ = [
    "AGGREGATE_SCHEMA_NAME",
    "CODESIGN_PATH",
    "CommandResult",
    "CodexExecutableCustody",
    "CodexExecutableCustodyStale",
    "CodexExecutableError",
    "CodexExecutableExecutionUnsupported",
    "CodexExecutablePolicy",
    "DEFAULT_CODEX_EXECUTABLE_POLICY",
    "ExtendedMetadataEvidence",
    "EXPECTED_APP_SERVER_SCHEMA_SHA256",
    "EXPECTED_CODEX_FULL_CDHASH",
    "EXPECTED_CODEX_SHA256",
    "EXPECTED_CODEX_TEAM_IDENTIFIER",
    "EXPECTED_CODEX_VERSION",
    "ExecutableExclusionRoots",
    "OwnerSnapshotLaunchAttestation",
    "ProcessQuiescenceEvidence",
    "SnapshotCopyResult",
    "SnapshotExecTarget",
    "SnapshotHandoffEvidence",
    "SnapshotProtectionEvidence",
    "SnapshotSeatbeltPolicy",
    "SignatureMetadata",
    "authenticate_codex_executable",
    "build_snapshot_seatbelt_policy",
    "copy_executable_from_fd",
    "parse_codesign_metadata",
    "run_bounded_command",
    "verify_macos_filesystem_metadata",
]
