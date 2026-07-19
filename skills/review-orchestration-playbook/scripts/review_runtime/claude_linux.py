from __future__ import annotations

import contextlib
import errno
import enum
import json
import math
import mmap
import os
import pathlib
import platform
import re
import secrets
import stat
import struct
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from .claude_refresh_lock import (
    ClaudeRefreshLockError,
    ClaudeRefreshLockProtocol,
    ClaudeRefreshLockStale,
    ClaudeRefreshLockTimeout,
    acquire_claude_refresh_lock,
    attach_claude_refresh_lock_recovery,
    recover_abandoned_staged_claude_refresh_locks,
)
from .common import (
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    restore_signal_mask,
    run_bounded_capture,
)
from .workspace import symlink_target_stays_within_workspace


class LinuxRuntimeError(ReviewError):
    """A fail-closed Linux Claude runtime validation failure."""


class LinuxUnsupportedHost(LinuxRuntimeError):
    """The current host is not a supported native Linux or WSL2 host."""


class LinuxIsolationUnavailable(LinuxRuntimeError):
    """The required Linux isolation capability is unavailable."""


class LinuxHostDependencyUnavailable(LinuxIsolationUnavailable):
    """A required trusted host dependency is absent or unusable."""


class LinuxRuntimeInspectionInconclusive(LinuxRuntimeError):
    """Runtime dependency inspection could not reach a stable conclusion."""


class LinuxRuntimeUnsafe(LinuxRuntimeError):
    """Runtime dependency metadata violates a fail-closed safety rule."""


class LinuxCredentialError(LinuxRuntimeError):
    """A Claude local-login credential failed private-file validation."""


class LinuxCredentialUnavailable(LinuxCredentialError):
    """Claude local login is absent or is not refresh-capable."""


class LinuxCredentialUnsafe(LinuxCredentialError):
    """Claude credential storage or contents violate fail-closed safety rules."""


class LinuxCredentialInspectionInconclusive(LinuxCredentialError):
    """Credential I/O or a source race prevented a stable inspection."""


class LinuxCredentialStaleRefreshLock(LinuxCredentialInspectionInconclusive):
    """A stale shared refresh lock needs controlled operator recovery."""


class LinuxStagedCredentialRefreshLockBlocked(
    LinuxCredentialInspectionInconclusive
):
    """A helper-owned staged lock blocked final refresh persistence."""


class LinuxStagedCredentialWriterUnquiescent(
    LinuxCredentialInspectionInconclusive
):
    """A launched staged credential writer has no safe cleanup attestation."""


class LinuxStagedCredentialWatcherUnstopped(
    LinuxCredentialInspectionInconclusive
):
    """The staged credential watcher did not stop within its bounded join."""


class LinuxCredentialCleanupDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary cleanup failure."""


class LinuxCredentialPersistenceDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary refresh writeback failure."""


class LinuxRuntimeInspectionCleanupDiagnostic(Exception):
    """Visible Python 3.10 fallback for an ELF descriptor cleanup failure."""


class LinuxHostKind(str, enum.Enum):
    LINUX = "linux"
    WSL2 = "wsl2"
    WSL1 = "wsl1"
    NATIVE_WINDOWS = "native-windows"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class LinuxHost:
    kind: LinuxHostKind
    arch: str
    kernel_release: str

    @property
    def supported(self) -> bool:
        return self.kind in {LinuxHostKind.LINUX, LinuxHostKind.WSL2}


@dataclass(frozen=True)
class ElfInfo:
    path: pathlib.Path
    arch: str
    interpreter: str | None
    libc: str | None
    elf_type: int
    has_rpath: bool = False
    has_runpath: bool = False
    has_audit: bool = False
    has_depaudit: bool = False

    @property
    def manifest_platform_key(self) -> str:
        if self.libc == "glibc":
            return f"linux-{self.arch}"
        if self.libc == "musl":
            return f"linux-{self.arch}-musl"
        raise LinuxRuntimeError(
            f"cannot determine Claude Linux libc from ELF interpreter: {self.path}"
        )


@dataclass(frozen=True)
class _ElfProgramSegment:
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int


@dataclass(frozen=True)
class NativeToolchain:
    bwrap: pathlib.Path
    socat: pathlib.Path
    rg: pathlib.Path
    cc: pathlib.Path


@dataclass(frozen=True)
class PathComponentIdentity:
    path: pathlib.Path
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class TrustedPathIdentity:
    path: pathlib.Path
    components: tuple[PathComponentIdentity, ...]
    allow_root_sticky_temp_ancestor: bool = False
    ignore_parent_directory_content_changes: bool = False


@dataclass(frozen=True)
class RuntimeMount:
    source: pathlib.Path
    destination: pathlib.PurePosixPath
    identity: TrustedPathIdentity | None = None


@dataclass(frozen=True)
class HostRuntimeDependency:
    lexical_path: pathlib.Path
    destination: pathlib.PurePosixPath
    lexical_components: tuple[PathComponentIdentity, ...]
    resolved_identity: TrustedPathIdentity


@dataclass(frozen=True)
class HostRuntimeClosure:
    host: LinuxHost
    executable_identity: TrustedPathIdentity
    loader: HostRuntimeDependency
    glibc_version: tuple[int, int]
    interpreter: str | None
    dependencies: tuple[HostRuntimeDependency, ...]
    trusted_owner_uids: frozenset[int]
    executable_owner_uids: frozenset[int]


@dataclass(frozen=True)
class StagedCredential:
    carrier_root: pathlib.Path
    config_dir: pathlib.Path
    credential_path: pathlib.Path
    expires_at_ms: float


@dataclass(frozen=True)
class _CredentialFileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    link_count: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _CredentialParentIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


class _CredentialDirectoryAnchor:
    """Retain every no-follow directory edge leading to a credential parent."""

    def __init__(
        self,
        *,
        path: pathlib.Path,
        components: tuple[str, ...],
        descriptors: tuple[int, ...],
        identities: tuple[_CredentialParentIdentity, ...],
    ) -> None:
        self.path = path
        self.components = components
        self._descriptors = descriptors
        self.identities = identities
        self._state_lock = threading.Lock()
        self._detached_to_watcher = False

    @property
    def descriptor(self) -> int:
        with self._state_lock:
            if not self._descriptors:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential directory anchor is closed"
                )
            return self._descriptors[-1]

    @property
    def legacy_parent_descriptor(self) -> int:
        with self._state_lock:
            if not self._descriptors:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential directory anchor is closed"
                )
            return (
                self._descriptors[-2]
                if len(self._descriptors) > 1
                else self._descriptors[0]
            )

    @property
    def identity(self) -> _CredentialParentIdentity:
        return self.identities[-1]

    @property
    def detached_to_watcher(self) -> bool:
        with self._state_lock:
            return self._detached_to_watcher

    def assert_stable(self, *, owner_uid: int) -> None:
        with self._state_lock:
            if not self._descriptors:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential directory anchor is closed"
                )
            descriptors = self._descriptors
        try:
            current_metadata = tuple(
                os.fstat(descriptor) for descriptor in descriptors
            )
            current_identities = tuple(
                _credential_directory_identity(metadata)
                for metadata in current_metadata
            )
            edge_identities = tuple(
                _credential_directory_identity(
                    os.stat(
                        component,
                        dir_fd=descriptors[index],
                        follow_symlinks=False,
                    )
                )
                for index, component in enumerate(self.components)
            )
        except OSError as error:
            raise LinuxCredentialInspectionInconclusive(
                "Claude credential directory ancestor changed"
            ) from error
        if current_identities != self.identities or edge_identities != tuple(
            self.identities[1:]
        ):
            raise LinuxCredentialInspectionInconclusive(
                "Claude credential directory ancestor changed"
            )
        _validate_credential_parent_metadata(
            current_metadata[-1],
            owner_uid=owner_uid,
        )

    def detach_to_watcher(self) -> None:
        with self._state_lock:
            self._detached_to_watcher = True

    def close_if_owned(self) -> None:
        self._close(detached=False)

    def close_if_detached(self) -> None:
        self._close(detached=True)

    def _close(self, *, detached: bool) -> None:
        with self._state_lock:
            if self._detached_to_watcher is not detached or not self._descriptors:
                return
            descriptors = self._descriptors
            self._descriptors = ()
        cleanup_errors: list[BaseException] = []
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        primary = _primary_cleanup_error(cleanup_errors)
        if primary is None:
            return
        if _is_control_flow_error(primary):
            raise primary
        raise LinuxCredentialInspectionInconclusive(
            "cannot close Claude credential directory anchors"
        ) from primary


@dataclass(frozen=True)
class SandboxSpec:
    host: LinuxHost
    toolchain: NativeToolchain
    claude: pathlib.Path
    launcher: pathlib.Path
    workspace: pathlib.Path
    helper_root: pathlib.Path
    helper_home: pathlib.Path
    helper_tmp: pathlib.Path
    config_dir: pathlib.Path
    proxy_socket: pathlib.Path
    runtime_libraries: tuple[RuntimeMount, ...]
    ca_bundle: pathlib.Path | None = None
    ca_bundle_identity: TrustedPathIdentity | None = None
    node_extra_ca_certs_configured: bool = False


@dataclass(frozen=True)
class SandboxCommand:
    argv: tuple[str, ...]
    env: dict[str, str]
    workspace_path: pathlib.PurePosixPath
    home_path: pathlib.PurePosixPath
    tmp_path: pathlib.PurePosixPath
    config_path: pathlib.PurePosixPath


class CaptureResult(Protocol):
    returncode: int
    stdout: bytes | bytearray
    stderr: bytes | bytearray


Runner = Callable[..., CaptureResult]


LAUNCHER_SOURCE = pathlib.Path(__file__).with_name("claude_linux_launcher.c")
ELF_HEADER_SIZE = 64
ELF_MAX_PROGRAM_HEADER_OFFSET = 1024 * 1024
ELF_MAX_PROGRAM_HEADERS = 128
ELF_MAX_INTERPRETER_BYTES = 4096
ELF_MAX_DYNAMIC_SEGMENT_BYTES = 1024 * 1024
ELF_UINT64_MAX = (1 << 64) - 1
ELF_DYNAMIC_ENTRY_BYTES = 16
ELF_DYNAMIC_NULL = 0
ELF_DYNAMIC_RPATH = 15
ELF_DYNAMIC_RUNPATH = 29
ELF_DYNAMIC_DEPAUDIT = 0x6FFFFEFB
ELF_DYNAMIC_AUDIT = 0x6FFFFEFC
CREDENTIAL_LIMIT_BYTES = 1024 * 1024
DEFAULT_CREDENTIAL_VALIDITY_SECONDS = 0.0
STAGED_CREDENTIAL_POLL_SECONDS = 0.05
STAGED_CREDENTIAL_RETRY_SECONDS = 1.0
STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS = 0.2
STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS = 6.0
PROBE_TIMEOUT_SECONDS = 20.0
PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
TOOL_PROBE_TIMEOUT_SECONDS = 10.0
TOOL_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
MOUNTINFO_LIMIT_BYTES = 2 * 1024 * 1024
MOUNTINFO_LINE_LIMIT_BYTES = 64 * 1024
MOUNTINFO_ENTRY_LIMIT = 16 * 1024
MOUNTINFO_PATH = pathlib.Path("/proc/self/mountinfo")
WORKSPACE_SYMLINK_LIMIT = 100_000
SANDBOX_WORKSPACE = pathlib.PurePosixPath("/workspace")
SANDBOX_HOME = pathlib.PurePosixPath("/home/reviewer")
SANDBOX_TMP = pathlib.PurePosixPath("/tmp")
SANDBOX_AUTH_ROOT = pathlib.PurePosixPath("/auth")
SANDBOX_CONFIG = SANDBOX_AUTH_ROOT / "config"
SANDBOX_PROXY_SOCKET = pathlib.PurePosixPath("/run/codex-review/proxy.sock")
SANDBOX_BIN = pathlib.PurePosixPath("/opt/codex-review/bin")
SANDBOX_CLAUDE = SANDBOX_BIN / "claude"
SANDBOX_LAUNCHER = SANDBOX_BIN / "claude-linux-launcher"
SANDBOX_SOCAT = SANDBOX_BIN / "socat"
SANDBOX_RG = SANDBOX_BIN / "rg"
SANDBOX_CA_BUNDLE = pathlib.PurePosixPath("/etc/ssl/certs/ca-certificates.crt")
CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS = "Read"
CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS = "Read(./**)"
CLAUDE_LINUX_REVIEW_PERMISSION_MODE = "dontAsk"
CLAUDE_LINUX_REVIEW_NON_FILE_DENY_RULES = (
    "Bash",
    "Edit",
    "Write",
    "NotebookEdit",
    "Grep",
    "Glob",
    "WebFetch",
    "WebSearch",
    "Task",
)
# Claude Code releases below 2.1.208 do not reliably apply Read deny rules to
# Grep/Glob/LSP, so the supported Linux range exposes only Read. Cover every
# non-workspace top-level path that the synthetic root can expose, including
# credential files and /proc/self/environ in API-key mode.
CLAUDE_LINUX_FILE_TOOL_DENIED_ROOTS = (
    SANDBOX_AUTH_ROOT,
    pathlib.PurePosixPath("/dev"),
    pathlib.PurePosixPath("/etc"),
    pathlib.PurePosixPath("/home"),
    pathlib.PurePosixPath("/lib"),
    pathlib.PurePosixPath("/lib64"),
    pathlib.PurePosixPath("/opt"),
    pathlib.PurePosixPath("/proc"),
    pathlib.PurePosixPath("/run"),
    pathlib.PurePosixPath("/tmp"),
    pathlib.PurePosixPath("/usr"),
)


def _absolute_read_rule(path: pathlib.PurePosixPath, *, recursive: bool) -> str:
    suffix = "/**" if recursive else ""
    return f"Read(//{path.as_posix().lstrip('/')}{suffix})"


CLAUDE_LINUX_FILE_TOOL_DENY_RULES = tuple(
    _absolute_read_rule(root, recursive=recursive)
    for root in CLAUDE_LINUX_FILE_TOOL_DENIED_ROOTS
    for recursive in (False, True)
)
CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS = ",".join(
    (*CLAUDE_LINUX_REVIEW_NON_FILE_DENY_RULES, *CLAUDE_LINUX_FILE_TOOL_DENY_RULES)
)
PROBE_SUCCESS = b"claude-linux-isolation-probe: ok\n"
_SUPPORTED_ARCHES = {"x64": 62, "arm64": 183}
_MACHINE_ALIASES = {
    "amd64": "x64",
    "x86_64": "x64",
    "aarch64": "arm64",
    "arm64": "arm64",
}
_WSL_MARKER = re.compile(r"microsoft", re.IGNORECASE)
_WSL2_MARKER = re.compile(r"(?:wsl2|microsoft-standard)", re.IGNORECASE)
_WINDOWS_DRIVE_SOURCE = re.compile(r"^[a-z]:(?:[\\\\/]|$)", re.IGNORECASE)
_WINDOWS_DRIVE_OPTION = re.compile(
    r"(?:^|[,;])(?:path|source)=[a-z]:(?:[\\\\/]|$)", re.IGNORECASE
)
_DRVFS_OPTION = re.compile(r"(?:^|[,;])(?:aname=)?drvfs(?:[,;]|$)", re.IGNORECASE)
_WSL_PROVEN_EXT4_SOURCE = re.compile(r"^/dev/sd[a-z]+[0-9]*$")
_TRUSTED_TOOL_ROOTS = (
    pathlib.Path("/usr/bin"),
    pathlib.Path("/bin"),
    pathlib.Path("/usr/local/bin"),
)
_TOOL_CANDIDATES: Mapping[str, tuple[pathlib.Path, ...]] = {
    "bwrap": (pathlib.Path("/usr/bin/bwrap"), pathlib.Path("/bin/bwrap")),
    "socat": (pathlib.Path("/usr/bin/socat"), pathlib.Path("/bin/socat")),
    "rg": (
        pathlib.Path("/usr/bin/rg"),
        pathlib.Path("/bin/rg"),
        pathlib.Path("/usr/local/bin/rg"),
    ),
    "cc": (
        pathlib.Path("/usr/bin/cc"),
        pathlib.Path("/usr/bin/clang"),
        pathlib.Path("/usr/bin/gcc"),
    ),
}
_TRUSTED_LDD_CANDIDATES = (pathlib.Path("/usr/bin/ldd"), pathlib.Path("/bin/ldd"))
_CANONICAL_GLIBC_LOADERS: Mapping[str, pathlib.PurePosixPath] = {
    "x64": pathlib.PurePosixPath("/lib64/ld-linux-x86-64.so.2"),
    "arm64": pathlib.PurePosixPath("/lib/ld-linux-aarch64.so.1"),
}
_MINIMUM_GLIBC_VERSION = (2, 27)
_MAXIMUM_GLIBC_VERSION = (3, 0)
_GLIBC_LOADER_VERSION = re.compile(
    r"\Ald\.so \((?:GNU libc|[^()\r\n]*\bGLIBC\b[^()\r\n]*)\) "
    r"stable release version ([0-9]{1,9})\.([0-9]{1,9})\.\r?\n"
)
_ALLOWED_LIBRARY_DESTINATIONS = (
    pathlib.PurePosixPath("/lib"),
    pathlib.PurePosixPath("/lib64"),
    pathlib.PurePosixPath("/usr/lib"),
    pathlib.PurePosixPath("/usr/lib64"),
)
_AUTH_ENV_KEYS = frozenset({"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"})
_HOST_TOOL_ENV = MappingProxyType(
    {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
    }
)


def fixed_host_tool_environment() -> dict[str, str]:
    """Return a fresh minimal environment for trusted Linux host tools."""

    return dict(_HOST_TOOL_ENV)


def _read_proc_text(path: pathlib.Path, *, limit: int = 64 * 1024) -> str:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError:
        return ""
    if len(payload) > limit:
        return ""
    return payload.decode("utf-8", errors="replace")


def _normalize_arch(machine: str) -> str:
    return _MACHINE_ALIASES.get(machine.strip().lower(), "unsupported")


def _path_marker_exists(path: pathlib.Path, *, directory: bool = False) -> bool:
    try:
        return path.is_dir() if directory else path.exists()
    except OSError:
        return False


def _is_run_wsl_interop_path(value: str) -> bool:
    if not value or not value.startswith("/"):
        return False
    path = pathlib.PurePosixPath(value)
    if "." in path.parts or ".." in path.parts:
        return False
    try:
        path.relative_to(pathlib.PurePosixPath("/run/WSL"))
    except ValueError:
        return False
    return path != pathlib.PurePosixPath("/run/WSL")


def detect_host(
    *,
    system: str | None = None,
    machine: str | None = None,
    kernel_release: str | None = None,
    proc_version: str | None = None,
    env: Mapping[str, str] | None = None,
    run_wsl_exists: bool | None = None,
    interop_path_exists: bool | None = None,
    binfmt_wslinterop_exists: bool | None = None,
) -> LinuxHost:
    """Classify Linux/WSL hosts from kernel and independently checked markers."""

    system_name = (system if system is not None else platform.system()).strip()
    machine_name = machine if machine is not None else platform.machine()
    arch = _normalize_arch(machine_name)
    if system_name.lower() == "windows":
        return LinuxHost(LinuxHostKind.NATIVE_WINDOWS, arch, "")
    if system_name.lower() != "linux":
        return LinuxHost(LinuxHostKind.UNSUPPORTED, arch, "")
    release = (
        kernel_release
        if kernel_release is not None
        else _read_proc_text(pathlib.Path("/proc/sys/kernel/osrelease"))
    ).strip()
    version = (
        proc_version
        if proc_version is not None
        else _read_proc_text(pathlib.Path("/proc/version"))
    ).strip()
    host_env = os.environ if env is None else env
    interop_value = host_env.get("WSL_INTEROP", "").strip()
    distro_value = host_env.get("WSL_DISTRO_NAME", "").strip()
    run_wsl_marker = (
        _path_marker_exists(pathlib.Path("/run/WSL"), directory=True)
        if run_wsl_exists is None
        else run_wsl_exists
    )
    binfmt_marker = (
        _path_marker_exists(pathlib.Path("/proc/sys/fs/binfmt_misc/WSLInterop"))
        if binfmt_wslinterop_exists is None
        else binfmt_wslinterop_exists
    )
    interop_marker = False
    if _is_run_wsl_interop_path(interop_value):
        interop_marker = (
            _path_marker_exists(pathlib.Path(interop_value))
            if interop_path_exists is None
            else interop_path_exists
        )
    combined = f"{release}\n{version}"
    kernel_wsl = bool(_WSL_MARKER.search(combined))
    kernel_wsl2 = bool(_WSL2_MARKER.search(combined))
    any_wsl_signal = bool(
        kernel_wsl
        or interop_value
        or interop_marker
        or distro_value
        or run_wsl_marker
        or binfmt_marker
    )
    # WSL1 and WSL2 both expose /run/WSL interop endpoints, so runtime and
    # environment markers prove only WSL presence. Without an explicit WSL2
    # kernel marker, custom-kernel state cannot be distinguished safely from
    # WSL1 inside the guest and remains unsupported.
    positively_wsl2 = kernel_wsl2
    if positively_wsl2:
        kind = LinuxHostKind.WSL2
    elif any_wsl_signal:
        # Ambiguous/spoofed WSL environment state must not accidentally receive
        # the WSL2 sandbox path. WSL1 is the existing unsupported fail-closed
        # classification and gives the caller actionable WSL2 guidance.
        kind = LinuxHostKind.WSL1
    else:
        kind = LinuxHostKind.LINUX
    return LinuxHost(kind, arch, release)


def require_supported_host(host: LinuxHost) -> None:
    if host.arch not in _SUPPORTED_ARCHES:
        raise LinuxUnsupportedHost(f"unsupported Linux architecture: {host.arch}")
    if host.kind == LinuxHostKind.WSL1:
        raise LinuxUnsupportedHost(
            "WSL1 cannot provide the required bubblewrap namespaces; use WSL2"
        )
    if host.kind == LinuxHostKind.NATIVE_WINDOWS:
        raise LinuxUnsupportedHost(
            "native Windows is not supported; run the helper inside WSL2"
        )
    if host.kind != LinuxHostKind.LINUX and host.kind != LinuxHostKind.WSL2:
        raise LinuxUnsupportedHost(f"unsupported Claude review host: {host.kind.value}")


def _is_windows_drive_mount(path: pathlib.Path | pathlib.PurePosixPath) -> bool:
    parts = pathlib.PurePosixPath(str(path)).parts
    return (
        len(parts) >= 3
        and parts[0] == "/"
        and parts[1].lower() == "mnt"
        and len(parts[2]) == 1
        and parts[2].isalpha()
    )


@dataclass(frozen=True)
class _MountInfoEntry:
    mount_id: int
    root: pathlib.PurePosixPath | str
    mount_point: pathlib.PurePosixPath
    file_system: str
    source: str
    super_options: str


_MOUNTINFO_ESCAPES = {
    "011": "\t",
    "012": "\n",
    "040": " ",
    "054": ",",
    "072": ":",
    "134": "\\",
}

_NSFS_ROOT = re.compile(
    r"(?P<namespace>[a-z][a-z0-9_]{0,31}):"
    r"\[(?P<inode>[1-9][0-9]{0,19})\]"
)
_MAX_NSFS_INODE = (1 << 64) - 1


def _decode_mountinfo_field(value: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        escape = value[index + 1 : index + 4]
        replacement = _MOUNTINFO_ESCAPES.get(escape)
        if replacement is None:
            raise LinuxRuntimeError("mountinfo contains an invalid escape sequence")
        decoded.append(replacement)
        index += 4
    return "".join(decoded)


def _mountinfo_path(value: str) -> pathlib.PurePosixPath:
    decoded = _decode_mountinfo_field(value)
    path = pathlib.PurePosixPath(decoded)
    if (
        not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or str(path) != decoded
    ):
        raise LinuxRuntimeError("mountinfo contains a non-canonical path")
    return path


def _mountinfo_root(
    value: str,
    *,
    file_system: str,
) -> pathlib.PurePosixPath | str:
    decoded = _decode_mountinfo_field(value)
    path = pathlib.PurePosixPath(decoded)
    if (
        path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and str(path) == decoded
    ):
        return path
    match = _NSFS_ROOT.fullmatch(decoded) if file_system == "nsfs" else None
    if match is not None and int(match.group("inode")) <= _MAX_NSFS_INODE:
        return decoded
    raise LinuxRuntimeError("mountinfo contains a non-canonical root")


def _parse_mountinfo(payload: str) -> tuple[_MountInfoEntry, ...]:
    encoded_size = len(payload.encode("utf-8", errors="surrogateescape"))
    if not payload or encoded_size > MOUNTINFO_LIMIT_BYTES:
        raise LinuxRuntimeError("Linux mountinfo is empty or exceeds its size limit")
    lines = payload.splitlines()
    if not lines or len(lines) > MOUNTINFO_ENTRY_LIMIT:
        raise LinuxRuntimeError("Linux mountinfo has an invalid entry count")
    entries: list[_MountInfoEntry] = []
    for line in lines:
        if (
            not line
            or len(line.encode("utf-8", errors="surrogateescape"))
            > MOUNTINFO_LINE_LIMIT_BYTES
        ):
            raise LinuxRuntimeError("Linux mountinfo contains an invalid line")
        fields = line.split(" ")
        if "" in fields:
            raise LinuxRuntimeError("Linux mountinfo contains malformed spacing")
        try:
            separator = fields.index("-", 6)
        except (ValueError, IndexError) as error:
            raise LinuxRuntimeError(
                "Linux mountinfo is missing its field separator"
            ) from error
        if separator < 6 or len(fields) != separator + 4:
            raise LinuxRuntimeError("Linux mountinfo has an invalid field shape")
        if not fields[0].isdigit() or not fields[1].isdigit():
            raise LinuxRuntimeError("Linux mountinfo has an invalid mount identifier")
        if re.fullmatch(r"[0-9]+:[0-9]+", fields[2]) is None:
            raise LinuxRuntimeError("Linux mountinfo has an invalid device identifier")
        if not fields[5] or not fields[separator + 1] or not fields[separator + 3]:
            raise LinuxRuntimeError("Linux mountinfo has an empty required field")
        file_system = _decode_mountinfo_field(fields[separator + 1])
        root = _mountinfo_root(fields[3], file_system=file_system)
        mount_point = _mountinfo_path(fields[4])
        entries.append(
            _MountInfoEntry(
                mount_id=int(fields[0]),
                root=root,
                mount_point=mount_point,
                file_system=file_system,
                source=_decode_mountinfo_field(fields[separator + 2]),
                super_options=_decode_mountinfo_field(fields[separator + 3]),
            )
        )
    return tuple(entries)


def _read_mountinfo(path: pathlib.Path) -> str:
    try:
        with path.open("rb") as handle:
            payload = handle.read(MOUNTINFO_LIMIT_BYTES + 1)
    except OSError as error:
        raise LinuxRuntimeError(
            f"cannot read Linux mountinfo {path}: {error}"
        ) from error
    if len(payload) > MOUNTINFO_LIMIT_BYTES:
        raise LinuxRuntimeError("Linux mountinfo exceeds its size limit")
    return payload.decode("utf-8", errors="surrogateescape")


def _mount_contains(path: pathlib.PurePosixPath, mount: pathlib.PurePosixPath) -> bool:
    try:
        path.relative_to(mount)
    except ValueError:
        return False
    return True


def _mount_has_windows_provenance(entry: _MountInfoEntry) -> bool:
    file_system = entry.file_system.casefold()
    source = entry.source.casefold()
    super_options = entry.super_options.casefold()
    if file_system == "drvfs" or file_system.endswith(".drvfs"):
        return True
    if _WINDOWS_DRIVE_SOURCE.match(source):
        return True
    if _WINDOWS_DRIVE_OPTION.search(super_options):
        return True
    explicit_drvfs = source == "drvfs" or _DRVFS_OPTION.search(super_options)
    if explicit_drvfs:
        return True
    # Do not reject every 9p or virtiofs mount: both can carry ordinary Linux
    # filesystems. UNC-style sources are Windows provenance only when paired
    # with one of WSL's known shared-filesystem transports.
    return file_system in {"9p", "virtiofs"} and source.startswith(("//", "\\\\"))


def _mount_has_proven_local_linux_provenance(entry: _MountInfoEntry) -> bool:
    file_system = entry.file_system.casefold()
    source = entry.source.casefold()
    # WSL2's supported local storage proof is deliberately narrow. The distro
    # VHD and `wsl --mount` Linux disks are exposed as ext4 on /dev/sdX, while
    # tmpfs has no backing filesystem. Other local-looking sources (loop, dm,
    # mapper, nbd, overlay, FUSE, or shared transports) need evidence mountinfo
    # does not provide and therefore remain inconclusive.
    if file_system == "ext4":
        return _WSL_PROVEN_EXT4_SOURCE.fullmatch(source) is not None
    return file_system == "tmpfs" and source == "tmpfs"


def _deepest_mounts(
    candidate: pathlib.PurePosixPath,
    entries: Sequence[_MountInfoEntry],
) -> tuple[_MountInfoEntry, ...]:
    matching = tuple(
        entry for entry in entries if _mount_contains(candidate, entry.mount_point)
    )
    if not matching:
        raise LinuxRuntimeError(
            f"Linux mountinfo does not cover runtime path: {candidate}"
        )
    depth = max(len(entry.mount_point.parts) for entry in matching)
    return tuple(entry for entry in matching if len(entry.mount_point.parts) == depth)


def _wsl_runtime_path_candidates(
    path: pathlib.Path,
    *,
    reject_literal_windows_drive: bool = True,
) -> tuple[pathlib.PurePosixPath, ...]:
    lexical = pathlib.Path(os.path.abspath(path))
    candidates = [lexical]
    # Preserve the cheap, deterministic /mnt/<drive> rejection before touching
    # procfs so a missing mountinfo file cannot obscure the decisive finding.
    if reject_literal_windows_drive and _is_windows_drive_mount(lexical):
        raise LinuxRuntimeUnsafe(
            f"WSL2 runtime files must not come from a Windows drive mount: {path}"
        )
    try:
        candidates.append(path.resolve(strict=False))
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot resolve WSL2 runtime path {path}: {error}"
        ) from error
    if reject_literal_windows_drive and any(
        _is_windows_drive_mount(candidate) for candidate in candidates
    ):
        raise LinuxRuntimeUnsafe(
            f"WSL2 runtime files must not come from a Windows drive mount: {path}"
        )
    return tuple(
        dict.fromkeys(pathlib.PurePosixPath(str(candidate)) for candidate in candidates)
    )


def reject_wsl_windows_paths(
    paths: Sequence[pathlib.Path],
    host: LinuxHost,
    *,
    mountinfo_path: pathlib.Path = MOUNTINFO_PATH,
    mountinfo_text: str | None = None,
) -> None:
    if host.kind not in {LinuxHostKind.LINUX, LinuxHostKind.WSL2}:
        return
    candidates_by_path = tuple(
        (
            path,
            _wsl_runtime_path_candidates(
                path,
                reject_literal_windows_drive=host.kind == LinuxHostKind.WSL2,
            ),
        )
        for path in paths
    )
    if not candidates_by_path:
        return
    # Production Linux always has procfs available before this helper can build
    # its namespace sandbox. Keep synthetic Linux-host unit tests runnable on a
    # non-Linux test runner while requiring mount provenance in every real Linux
    # or WSL process. This also protects a markerless WSL2 guest that is otherwise
    # observationally indistinguishable from native Linux.
    if (
        host.kind == LinuxHostKind.LINUX
        and mountinfo_text is None
        and mountinfo_path == MOUNTINFO_PATH
        and platform.system().lower() != "linux"
    ):
        return
    try:
        payload = (
            _read_mountinfo(mountinfo_path)
            if mountinfo_text is None
            else mountinfo_text
        )
        entries = _parse_mountinfo(payload)
    except LinuxRuntimeError as error:
        raise LinuxRuntimeInspectionInconclusive(str(error)) from error
    for path, candidates in candidates_by_path:
        for candidate in candidates:
            try:
                selected = _deepest_mounts(candidate, entries)
            except LinuxRuntimeError as error:
                raise LinuxRuntimeInspectionInconclusive(str(error)) from error
            if any(_mount_has_windows_provenance(entry) for entry in selected):
                raise LinuxRuntimeUnsafe(
                    "Linux review runtime files must not come from a Windows drive "
                    f"filesystem: {path}"
                )
            if host.kind != LinuxHostKind.WSL2:
                # Native Linux permits its normal filesystem variety. The common
                # guard exists only to reject positive Windows/DrvFS provenance
                # even when a markerless WSL2 guest was classified as Linux.
                continue
            unproven = tuple(
                entry
                for entry in selected
                if not _mount_has_proven_local_linux_provenance(entry)
            )
            if unproven:
                file_systems = ", ".join(
                    sorted({entry.file_system for entry in unproven}, key=str.casefold)
                )
                raise LinuxRuntimeInspectionInconclusive(
                    "cannot prove that the WSL2 runtime path uses a local native "
                    f"Linux filesystem ({file_systems}): {path}"
                )


def reject_wsl_windows_path(
    path: pathlib.Path,
    host: LinuxHost,
    *,
    mountinfo_path: pathlib.Path = MOUNTINFO_PATH,
    mountinfo_text: str | None = None,
) -> None:
    reject_wsl_windows_paths(
        (path,),
        host,
        mountinfo_path=mountinfo_path,
        mountinfo_text=mountinfo_text,
    )


_ELF_STABLE_METADATA_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _pread_exact(
    fd: int,
    length: int,
    offset: int,
    *,
    known_size: int,
    label: str,
) -> bytes:
    if (
        offset < 0
        or length < 0
        or offset > known_size
        or length > known_size - offset
    ):
        raise LinuxRuntimeError(f"truncated ELF {label}")
    payload = os.pread(fd, length, offset)
    if len(payload) != length:
        raise LinuxRuntimeInspectionInconclusive(
            f"short read while inspecting ELF {label}"
        )
    return payload


def _checked_elf_range_end(
    start: int,
    length: int,
    *,
    path: pathlib.Path,
    label: str,
) -> int:
    if start > ELF_UINT64_MAX - length:
        raise LinuxRuntimeError(f"ELF {label} range overflows: {path}")
    return start + length


def _parse_elf_program_segment(entry: bytes) -> _ElfProgramSegment:
    file_offset, virtual_address = struct.unpack_from("<QQ", entry, 8)
    file_size, memory_size = struct.unpack_from("<QQ", entry, 32)
    return _ElfProgramSegment(
        file_offset=file_offset,
        virtual_address=virtual_address,
        file_size=file_size,
        memory_size=memory_size,
    )


def _require_elf_page_size(path: pathlib.Path) -> int:
    page_size = mmap.PAGESIZE
    if (
        not isinstance(page_size, int)
        or isinstance(page_size, bool)
        or page_size <= 0
        or page_size > ELF_UINT64_MAX
        or page_size & (page_size - 1)
    ):
        raise LinuxRuntimeInspectionInconclusive(
            f"host ELF page size is not a bounded power of two: {path}"
        )
    return page_size


def _elf_page_interval(
    start: int,
    length: int,
    *,
    page_size: int,
    path: pathlib.Path,
    label: str,
) -> tuple[int, int]:
    end = _checked_elf_range_end(start, length, path=path, label=label)
    page_mask = page_size - 1
    page_start = start & ~page_mask
    if length == 0:
        return page_start, page_start
    if end & page_mask:
        if end > ELF_UINT64_MAX - page_mask:
            raise LinuxRuntimeError(f"ELF {label} page range overflows: {path}")
        end = (end + page_mask) & ~page_mask
    return page_start, end


def _require_stable_elf_metadata(
    before: os.stat_result,
    after: os.stat_result,
    path: pathlib.Path,
) -> None:
    if any(
        getattr(before, field) != getattr(after, field)
        for field in _ELF_STABLE_METADATA_FIELDS
    ):
        raise LinuxRuntimeInspectionInconclusive(
            f"ELF executable changed during inspection: {path}"
        )


def _revalidate_elf_after_failure(
    fd: int,
    before: os.stat_result,
    path: pathlib.Path,
) -> None:
    try:
        after = os.fstat(fd)
    except OSError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot revalidate ELF executable {path}: {error}"
        ) from error
    _require_stable_elf_metadata(before, after, path)


def inspect_elf(path: pathlib.Path) -> ElfInfo:
    """Validate a native 64-bit little-endian ELF and return its architecture."""

    try:
        resolved = path.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot open ELF executable {path}: {error}"
        ) from error
    failure: BaseException | None = None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise LinuxRuntimeError(f"ELF candidate is not a regular file: {path}")
        header = _pread_exact(
            fd,
            ELF_HEADER_SIZE,
            0,
            known_size=metadata.st_size,
            label="header",
        )
        if header[:4] != b"\x7fELF":
            raise LinuxRuntimeError(
                f"candidate is not a 64-bit little-endian native ELF: {path}"
            )
        if header[4] != 2 or header[5] != 1:
            raise LinuxRuntimeError(
                f"candidate is not a 64-bit little-endian native ELF: {path}"
            )
        elf_type, machine = struct.unpack_from("<HH", header, 16)
        if elf_type not in {2, 3}:
            raise LinuxRuntimeError(f"ELF candidate is not executable or PIE: {path}")
        arch = next(
            (
                name
                for name, machine_id in _SUPPORTED_ARCHES.items()
                if machine_id == machine
            ),
            None,
        )
        if arch is None:
            raise LinuxRuntimeError(f"unsupported ELF machine {machine}: {path}")
        page_size = _require_elf_page_size(path)
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        program_entry_size = struct.unpack_from("<H", header, 54)[0]
        program_count = struct.unpack_from("<H", header, 56)[0]
        if program_count > ELF_MAX_PROGRAM_HEADERS:
            raise LinuxRuntimeError(f"ELF has too many program headers: {path}")
        if program_count and (
            program_offset > ELF_MAX_PROGRAM_HEADER_OFFSET
            or program_entry_size < 56
            or program_entry_size > 256
        ):
            raise LinuxRuntimeError(f"ELF program-header table is invalid: {path}")
        interpreter: str | None = None
        has_rpath = False
        has_runpath = False
        has_audit = False
        has_depaudit = False
        dynamic_segment: _ElfProgramSegment | None = None
        load_segments: list[_ElfProgramSegment] = []
        load_page_intervals: list[tuple[int, int]] = []
        for index in range(program_count):
            entry = _pread_exact(
                fd,
                program_entry_size,
                program_offset + index * program_entry_size,
                known_size=metadata.st_size,
                label="program-header entry",
            )
            program_type = struct.unpack_from("<I", entry, 0)[0]
            if program_type == 1:
                load_segment = _parse_elf_program_segment(entry)
                load_file_end = _checked_elf_range_end(
                    load_segment.file_offset,
                    load_segment.file_size,
                    path=path,
                    label="PT_LOAD file",
                )
                _checked_elf_range_end(
                    load_segment.virtual_address,
                    load_segment.memory_size,
                    path=path,
                    label="PT_LOAD memory",
                )
                if (
                    load_segment.file_size > load_segment.memory_size
                    or load_file_end > metadata.st_size
                ):
                    raise LinuxRuntimeError(
                        f"ELF PT_LOAD segment metadata is invalid: {path}"
                    )
                if (
                    load_segment.file_offset % page_size
                    != load_segment.virtual_address % page_size
                ):
                    raise LinuxRuntimeError(
                        "ELF PT_LOAD offset and virtual address are not congruent "
                        f"at the host page size: {path}"
                    )
                load_segments.append(load_segment)
                load_page_intervals.append(
                    _elf_page_interval(
                        load_segment.virtual_address,
                        load_segment.memory_size,
                        page_size=page_size,
                        path=path,
                        label="PT_LOAD memory mapping",
                    )
                )
                continue
            if program_type == 2:
                if dynamic_segment is not None:
                    raise LinuxRuntimeError(
                        f"ELF has duplicate dynamic segments: {path}"
                    )
                dynamic_segment = _parse_elf_program_segment(entry)
                if (
                    dynamic_segment.file_size <= 0
                    or dynamic_segment.file_size > ELF_MAX_DYNAMIC_SEGMENT_BYTES
                    or dynamic_segment.memory_size > ELF_MAX_DYNAMIC_SEGMENT_BYTES
                    or dynamic_segment.file_size % ELF_DYNAMIC_ENTRY_BYTES != 0
                    or dynamic_segment.file_size > dynamic_segment.memory_size
                ):
                    raise LinuxRuntimeError(
                        f"ELF dynamic segment metadata is invalid: {path}"
                    )
                _checked_elf_range_end(
                    dynamic_segment.file_offset,
                    dynamic_segment.file_size,
                    path=path,
                    label="dynamic-segment file",
                )
                _checked_elf_range_end(
                    dynamic_segment.virtual_address,
                    dynamic_segment.memory_size,
                    path=path,
                    label="dynamic-segment memory",
                )
                continue
            if program_type != 3:
                continue
            if interpreter is not None:
                raise LinuxRuntimeError(
                    f"ELF has duplicate interpreter metadata: {path}"
                )
            data_offset = struct.unpack_from("<Q", entry, 8)[0]
            data_size = struct.unpack_from("<Q", entry, 32)[0]
            if data_size <= 1 or data_size > ELF_MAX_INTERPRETER_BYTES:
                raise LinuxRuntimeError(f"ELF interpreter metadata is invalid: {path}")
            raw_interpreter = _pread_exact(
                fd,
                data_size,
                data_offset,
                known_size=metadata.st_size,
                label="interpreter metadata",
            )
            if not raw_interpreter.endswith(b"\x00") or b"\x00" in raw_interpreter[:-1]:
                raise LinuxRuntimeError(f"ELF interpreter is malformed: {path}")
            interpreter = raw_interpreter[:-1].decode("utf-8", errors="strict")
        if dynamic_segment is not None:
            dynamic_memory_end = _checked_elf_range_end(
                dynamic_segment.virtual_address,
                dynamic_segment.memory_size,
                path=path,
                label="dynamic-segment memory",
            )
            covering_load_indexes = tuple(
                index
                for index, load_segment in enumerate(load_segments)
                if load_segment.virtual_address <= dynamic_segment.virtual_address
                and dynamic_memory_end
                <= load_segment.virtual_address + load_segment.memory_size
            )
            if len(covering_load_indexes) != 1:
                raise LinuxRuntimeError(
                    "ELF dynamic segment does not have exactly one covering "
                    f"PT_LOAD: {path}"
                )
            covering_load_index = covering_load_indexes[0]
            covering_load = load_segments[covering_load_index]
            address_delta = (
                dynamic_segment.virtual_address - covering_load.virtual_address
            )
            mapped_file_offset = _checked_elf_range_end(
                covering_load.file_offset,
                address_delta,
                path=path,
                label="dynamic-segment PT_LOAD mapping",
            )
            if mapped_file_offset != dynamic_segment.file_offset:
                raise LinuxRuntimeError(
                    "ELF dynamic segment PT_LOAD offset mapping is inconsistent: "
                    f"{path}"
                )
            dynamic_file_virtual_end = _checked_elf_range_end(
                dynamic_segment.virtual_address,
                dynamic_segment.file_size,
                path=path,
                label="dynamic-segment file-backed memory",
            )
            load_file_virtual_end = _checked_elf_range_end(
                covering_load.virtual_address,
                covering_load.file_size,
                path=path,
                label="PT_LOAD file-backed memory",
            )
            dynamic_file_end = _checked_elf_range_end(
                dynamic_segment.file_offset,
                dynamic_segment.file_size,
                path=path,
                label="dynamic-segment file",
            )
            load_file_end = _checked_elf_range_end(
                covering_load.file_offset,
                covering_load.file_size,
                path=path,
                label="PT_LOAD file",
            )
            if (
                dynamic_segment.file_offset < covering_load.file_offset
                or dynamic_file_end > load_file_end
                or dynamic_file_virtual_end > load_file_virtual_end
            ):
                raise LinuxRuntimeError(
                    "ELF dynamic segment is not fully file-backed by its "
                    f"PT_LOAD: {path}"
                )
            dynamic_file_page_start, dynamic_file_page_end = _elf_page_interval(
                dynamic_segment.virtual_address,
                dynamic_segment.file_size,
                page_size=page_size,
                path=path,
                label="dynamic-segment file mapping",
            )
            for index, (load_page_start, load_page_end) in enumerate(
                load_page_intervals
            ):
                if index == covering_load_index:
                    continue
                if (
                    load_page_start < load_page_end
                    and load_page_start < dynamic_file_page_end
                    and dynamic_file_page_start < load_page_end
                ):
                    raise LinuxRuntimeError(
                        "ELF PT_LOAD page-rounded mapping overlaps the "
                        f"PT_DYNAMIC file-byte pages: {path}"
                    )
            raw_dynamic = _pread_exact(
                fd,
                dynamic_segment.file_size,
                dynamic_segment.file_offset,
                known_size=metadata.st_size,
                label="dynamic segment",
            )
            terminated = False
            for dynamic_offset in range(
                0,
                len(raw_dynamic),
                ELF_DYNAMIC_ENTRY_BYTES,
            ):
                dynamic_tag = struct.unpack_from("<q", raw_dynamic, dynamic_offset)[0]
                if dynamic_tag == ELF_DYNAMIC_NULL:
                    terminated = True
                    break
                has_rpath = has_rpath or dynamic_tag == ELF_DYNAMIC_RPATH
                has_runpath = has_runpath or dynamic_tag == ELF_DYNAMIC_RUNPATH
                has_audit = has_audit or dynamic_tag == ELF_DYNAMIC_AUDIT
                has_depaudit = has_depaudit or dynamic_tag == ELF_DYNAMIC_DEPAUDIT
            if not terminated:
                raise LinuxRuntimeError(f"ELF dynamic segment is unterminated: {path}")
        final_metadata = os.fstat(fd)
        _require_stable_elf_metadata(metadata, final_metadata, path)
    except LinuxRuntimeInspectionInconclusive as error:
        failure = error
        raise
    except OSError as error:
        failure = LinuxRuntimeInspectionInconclusive(
            f"cannot inspect ELF executable {path}: {error}"
        )
        raise failure from error
    except (UnicodeDecodeError, struct.error) as error:
        invalid = LinuxRuntimeError(
            f"cannot inspect ELF executable {path}: {error}"
        )
        try:
            _revalidate_elf_after_failure(fd, metadata, path)
        except LinuxRuntimeInspectionInconclusive as inspection_error:
            failure = inspection_error
            raise inspection_error from invalid
        failure = invalid
        raise invalid from error
    except LinuxRuntimeError as error:
        try:
            _revalidate_elf_after_failure(fd, metadata, path)
        except LinuxRuntimeInspectionInconclusive as inspection_error:
            failure = inspection_error
            raise inspection_error from error
        failure = error
        raise
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as close_error:
            if failure is not None:
                _add_elf_inspection_cleanup_note(failure, close_error)
            elif isinstance(close_error, OSError):
                raise LinuxRuntimeInspectionInconclusive(
                    f"cannot close inspected ELF executable {path}: {close_error}"
                ) from close_error
            else:
                raise
    libc: str | None = None
    if interpreter is not None:
        if "ld-musl-" in interpreter:
            libc = "musl"
        elif "ld-linux" in interpreter or "ld64.so" in interpreter:
            libc = "glibc"
    return ElfInfo(
        resolved,
        arch,
        interpreter,
        libc,
        elf_type,
        has_rpath=has_rpath,
        has_runpath=has_runpath,
        has_audit=has_audit,
        has_depaudit=has_depaudit,
    )


def validate_claude_executable(path: pathlib.Path, host: LinuxHost) -> ElfInfo:
    require_supported_host(host)
    reject_wsl_windows_path(path, host)
    info = inspect_elf(path)
    _require_no_elf_audit_modules(info)
    if info.arch != host.arch:
        raise LinuxRuntimeError(
            f"Claude ELF architecture {info.arch} does not match host {host.arch}"
        )
    # Accessing this property deliberately rejects unknown/static libc builds because
    # they cannot be matched to an Anthropic manifest platform key.
    _ = info.manifest_platform_key
    return info


def _is_relative_to(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_trusted_roots(
    roots: Sequence[pathlib.Path],
) -> tuple[pathlib.Path, ...]:
    resolved: list[pathlib.Path] = []
    for root in roots:
        if not root.is_absolute():
            raise LinuxRuntimeUnsafe(f"trusted root is not absolute: {root}")
        try:
            resolved.append(root.resolve(strict=True))
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError) as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot resolve trusted root {root}: {error}"
            ) from error
    if not resolved:
        raise LinuxHostDependencyUnavailable("no trusted system root is available")
    return tuple(dict.fromkeys(resolved))


def _validate_trusted_path_chain(
    path: pathlib.Path,
    *,
    trusted_roots: Sequence[pathlib.Path],
    trusted_owner_uids: frozenset[int],
    allow_setuid: bool = False,
) -> pathlib.Path:
    if not path.is_absolute():
        raise LinuxRuntimeUnsafe(f"trusted tool path is not absolute: {path}")
    lexical = pathlib.Path(os.path.normpath(path))
    normalized_roots = _resolve_trusted_roots(trusted_roots)
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot resolve trusted tool {path}: {error}"
        ) from error
    matching_root = next(
        (root for root in normalized_roots if _is_relative_to(resolved, root)), None
    )
    if matching_root is None:
        raise LinuxRuntimeUnsafe(
            f"trusted tool resolves outside system roots: {path}"
        )
    current = resolved
    while True:
        try:
            metadata = current.stat()
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot stat trusted path {current}: {error}"
            ) from error
        if metadata.st_uid not in trusted_owner_uids:
            raise LinuxRuntimeUnsafe(
                f"trusted path has an untrusted owner: {current}"
            )
        if metadata.st_mode & 0o022:
            raise LinuxRuntimeUnsafe(
                f"trusted path is group- or world-writable: {current}"
            )
        if current == matching_root:
            break
        current = current.parent
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise LinuxRuntimeUnsafe(
            f"trusted tool is not an executable regular file: {path}"
        )
    if not allow_setuid and metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise LinuxRuntimeUnsafe(
            f"trusted tool unexpectedly has set-id mode: {path}"
        )
    inspect_elf(resolved)
    return resolved


def _run_tool_probe(
    runner: Runner,
    argv: Iterable[str],
    *,
    timeout_seconds: float = TOOL_PROBE_TIMEOUT_SECONDS,
) -> CaptureResult:
    try:
        return runner(
            tuple(str(item) for item in argv),
            env=fixed_host_tool_environment(),
            timeout_seconds=timeout_seconds,
            stdout_limit_bytes=TOOL_PROBE_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes=TOOL_PROBE_OUTPUT_LIMIT_BYTES,
        )
    except (ReviewError, ForwardedSignal):
        raise
    except Exception as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"tool capability probe failed: {error}"
        ) from error


def _probe_identity(name: str, executable: pathlib.Path, runner: Runner) -> None:
    arguments = {
        "bwrap": ("--version",),
        "socat": ("-V",),
        "rg": ("--version",),
        "cc": ("--version",),
    }[name]
    result = _run_tool_probe(runner, (str(executable), *arguments))
    output = bytes(result.stdout) + b"\n" + bytes(result.stderr)
    normalized = output.decode("utf-8", errors="replace").lower()
    markers = {
        "bwrap": ("bubblewrap ",),
        "socat": ("socat version",),
        "rg": ("ripgrep ",),
        "cc": ("clang", "gcc", "free software foundation"),
    }[name]
    if result.returncode != 0 or not any(marker in normalized for marker in markers):
        raise LinuxIsolationUnavailable(
            f"{name} failed its bounded native identity probe: {executable}"
        )


def discover_native_toolchain(
    host: LinuxHost,
    *,
    runner: Runner = run_bounded_capture,
    candidates: Mapping[str, Sequence[pathlib.Path]] | None = None,
    trusted_roots: Sequence[pathlib.Path] = _TRUSTED_TOOL_ROOTS,
    trusted_owner_uids: frozenset[int] = frozenset({0}),
) -> NativeToolchain:
    """Discover root-owned native tools from fixed paths and probe their identity."""

    require_supported_host(host)
    selected: dict[str, pathlib.Path] = {}
    configured = candidates if candidates is not None else _TOOL_CANDIDATES
    for name in ("bwrap", "socat", "rg", "cc"):
        failures: list[str] = []
        unsafe_failures: list[LinuxRuntimeUnsafe] = []
        inspection_failures: list[LinuxRuntimeInspectionInconclusive] = []
        for candidate in configured.get(name, ()):
            try:
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise LinuxRuntimeInspectionInconclusive(
                        f"cannot inspect {name} candidate {candidate}: {error}"
                    ) from error
                reject_wsl_windows_path(candidate, host)
                executable = _validate_trusted_path_chain(
                    candidate,
                    trusted_roots=trusted_roots,
                    trusted_owner_uids=trusted_owner_uids,
                    allow_setuid=name == "bwrap",
                )
                info = inspect_elf(executable)
                if info.arch != host.arch:
                    raise LinuxRuntimeError(
                        f"{name} architecture {info.arch} does not match {host.arch}"
                )
                _probe_identity(name, executable, runner)
            except LinuxRuntimeUnsafe as error:
                unsafe_failures.append(error)
                failures.append(str(error))
                continue
            except LinuxRuntimeInspectionInconclusive as error:
                inspection_failures.append(error)
                failures.append(str(error))
                continue
            except LinuxRuntimeError as error:
                failures.append(str(error))
                continue
            selected[name] = executable
            break
        if name not in selected:
            if unsafe_failures:
                raise unsafe_failures[-1]
            if inspection_failures:
                raise inspection_failures[-1]
            detail = f"; last rejection: {failures[-1]}" if failures else ""
            raise LinuxHostDependencyUnavailable(
                f"no trusted native {name} executable is available{detail}"
            )
    toolchain = NativeToolchain(
        bwrap=selected["bwrap"],
        socat=selected["socat"],
        rg=selected["rg"],
        cc=selected["cc"],
    )
    probe_bwrap(host, toolchain, runner=runner)
    return toolchain


def probe_bwrap(
    host: LinuxHost,
    toolchain: NativeToolchain,
    *,
    runner: Runner = run_bounded_capture,
) -> None:
    """Run the namespace/capability shape used by the real sandbox."""

    require_supported_host(host)
    command = (
        str(toolchain.bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--",
        str(toolchain.rg),
        "--version",
    )
    result = _run_tool_probe(runner, command)
    if result.returncode != 0 or not bytes(result.stdout).lower().startswith(
        b"ripgrep "
    ):
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise LinuxIsolationUnavailable(
            "bubblewrap cannot create the required user/PID/network/IPC/UTS/cgroup "
            f"namespaces with dropped capabilities: {detail or 'probe rejected'}"
        )


def _validate_private_directory(path: pathlib.Path, *, owner_uid: int) -> pathlib.Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise LinuxRuntimeError(
            f"cannot inspect private directory {path}: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LinuxRuntimeError(f"private path is not a real directory: {path}")
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise LinuxRuntimeError(
            f"private directory must be owned by uid {owner_uid} with mode 0700: {path}"
        )
    return resolved


def _credential_file_identity(metadata: os.stat_result) -> _CredentialFileIdentity:
    return _CredentialFileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        link_count=metadata.st_nlink,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def _validate_credential_file_metadata(
    metadata: os.stat_result,
    *,
    owner_uid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise LinuxCredentialUnsafe("Claude credential is not a regular file")
    if metadata.st_uid != owner_uid:
        raise LinuxCredentialUnsafe(
            f"Claude credential is not owned by current uid {owner_uid}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise LinuxCredentialUnsafe("Claude credential mode must be exactly 0600")
    if metadata.st_nlink != 1:
        raise LinuxCredentialUnsafe("Claude credential must have exactly one link")
    if metadata.st_size <= 0 or metadata.st_size > CREDENTIAL_LIMIT_BYTES:
        raise LinuxCredentialUnsafe("Claude credential has an invalid size")


def _credential_directory_identity(
    metadata: os.stat_result,
) -> _CredentialParentIdentity:
    return _CredentialParentIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _validate_credential_parent_metadata(
    metadata: os.stat_result,
    *,
    owner_uid: int,
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LinuxCredentialUnsafe(
            "Claude credential parent is not a real directory"
        )
    if metadata.st_uid not in {0, owner_uid}:
        raise LinuxCredentialUnsafe(
            "Claude credential parent has an untrusted owner"
        )
    if metadata.st_mode & 0o022:
        raise LinuxCredentialUnsafe(
            "Claude credential parent must not be group- or world-writable"
        )


def _credential_parent_identity(
    path: pathlib.Path,
    *,
    owner_uid: int,
) -> _CredentialParentIdentity:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise LinuxCredentialUnavailable(
            f"Claude credential directory is unavailable: {path}"
        ) from error
    except OSError as error:
        raise LinuxCredentialInspectionInconclusive(
            f"cannot inspect Claude credential directory {path}: {error}"
        ) from error
    _validate_credential_parent_metadata(metadata, owner_uid=owner_uid)
    return _credential_directory_identity(metadata)


def _open_credential_directory_anchor(
    source: pathlib.Path,
    *,
    owner_uid: int,
) -> _CredentialDirectoryAnchor:
    parent = source.parent
    if (
        not source.is_absolute()
        or not source.name
        or any(part in {".", ".."} for part in source.parts)
    ):
        raise LinuxCredentialUnsafe(
            "Claude credential path must be absolute without traversal"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    components = tuple(parent.parts[1:])
    descriptors: list[int] = []
    identities: list[_CredentialParentIdentity] = []
    try:
        root_descriptor = os.open(parent.anchor, flags)
        descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise LinuxCredentialUnsafe(
                "Claude credential root is not a real directory"
            )
        identities.append(_credential_directory_identity(root_metadata))
        for component in components:
            parent_descriptor = descriptors[-1]
            before = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(before.st_mode):
                raise LinuxCredentialUnsafe(
                    "Claude credential directory ancestor must not be a symlink"
                )
            if not stat.S_ISDIR(before.st_mode):
                raise LinuxCredentialUnsafe(
                    "Claude credential directory ancestor is not a real directory"
                )
            descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            descriptors.append(descriptor)
            current = os.fstat(descriptor)
            after = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            current_identity = _credential_directory_identity(current)
            if (
                _credential_directory_identity(before) != current_identity
                or _credential_directory_identity(after) != current_identity
            ):
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential directory ancestor changed while opened"
                )
            identities.append(current_identity)
        _validate_credential_parent_metadata(
            os.fstat(descriptors[-1]),
            owner_uid=owner_uid,
        )
        anchor = _CredentialDirectoryAnchor(
            path=parent,
            components=components,
            descriptors=tuple(descriptors),
            identities=tuple(identities),
        )
        anchor.assert_stable(owner_uid=owner_uid)
        return anchor
    except BaseException as error:
        if isinstance(error, LinuxCredentialError) or _is_control_flow_error(error):
            failure = error
        elif isinstance(error, FileNotFoundError):
            failure = LinuxCredentialUnavailable(
                f"Claude credential directory is unavailable: {parent}"
            )
            failure.__cause__ = error
        elif isinstance(error, OSError) and error.errno == errno.ELOOP:
            failure = LinuxCredentialUnsafe(
                "Claude credential directory ancestor must not be a symlink"
            )
            failure.__cause__ = error
        else:
            failure = LinuxCredentialInspectionInconclusive(
                f"cannot safely open Claude credential directory {parent}"
            )
            failure.__cause__ = error
        cleanup_errors: list[BaseException] = []
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        primary = _primary_cleanup_error([failure, *cleanup_errors])
        assert primary is not None
        raise primary


def _parse_oauth_credential(payload: bytearray) -> float:
    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    value = json.loads(
        payload,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise LinuxCredentialUnsafe("Claude credential JSON is not an object")
    if "claudeAiOauth" not in value:
        raise LinuxCredentialUnavailable("Claude local login is unavailable")
    oauth = value["claudeAiOauth"]
    if not isinstance(oauth, dict):
        raise LinuxCredentialUnsafe("Claude credential JSON is malformed")
    access_token = oauth.get("accessToken")
    refresh_token = oauth.get("refreshToken")
    expires_at = oauth.get("expiresAt")
    if not isinstance(access_token, str) or not access_token.strip():
        raise LinuxCredentialUnavailable("Claude local login lacks an access token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise LinuxCredentialUnavailable("Claude local login lacks a refresh token")
    try:
        access_token.encode("utf-8")
        refresh_token.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LinuxCredentialUnsafe(
            "Claude credential token encoding is malformed"
        ) from error
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        raise LinuxCredentialUnsafe("Claude credential expiry is malformed")
    expires_at_ms = float(expires_at)
    if not math.isfinite(expires_at_ms):
        raise LinuxCredentialUnsafe("Claude credential expiry is malformed")
    return expires_at_ms


def _read_valid_credential(
    path: pathlib.Path,
    *,
    owner_uid: int,
    now: float,
    required_validity_seconds: float,
    dir_fd: int | None = None,
) -> tuple[bytearray, float, _CredentialFileIdentity]:
    # Retain the timing arguments for caller compatibility. Claude Code 2.1.211+
    # can refresh an expired access token through the private writable copy.
    _ = now, required_validity_seconds
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    open_path: pathlib.Path | str = path.name if dir_fd is not None else path
    try:
        fd = os.open(open_path, flags, dir_fd=dir_fd)
    except FileNotFoundError as error:
        raise LinuxCredentialUnavailable(
            f"Claude local-login credential is unavailable: {path}"
        ) from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise LinuxCredentialUnsafe(
                f"Claude credential must not be a symlink: {path}"
            ) from error
        raise LinuxCredentialInspectionInconclusive(
            f"cannot safely open Claude credential {path}: {error}"
        ) from error
    payload = bytearray()
    failure: BaseException | None = None
    result: tuple[bytearray, float, _CredentialFileIdentity] | None = None
    try:
        metadata = os.fstat(fd)
        _validate_credential_file_metadata(metadata, owner_uid=owner_uid)
        while len(payload) <= CREDENTIAL_LIMIT_BYTES:
            chunk = os.read(
                fd, min(64 * 1024, CREDENTIAL_LIMIT_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
        final_metadata = os.fstat(fd)
        if (
            len(payload) != metadata.st_size
            or len(payload) > CREDENTIAL_LIMIT_BYTES
            or _credential_file_identity(metadata)
            != _credential_file_identity(final_metadata)
        ):
            raise LinuxCredentialInspectionInconclusive(
                "Claude credential changed while it was read"
            )
        expires_at_ms = _parse_oauth_credential(payload)
        result = (
            payload,
            expires_at_ms,
            _credential_file_identity(final_metadata),
        )
    except LinuxCredentialError as error:
        failure = error
        payload[:] = b"\x00" * len(payload)
        raise
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        OverflowError,
        ValueError,
    ) as error:
        payload[:] = b"\x00" * len(payload)
        failure = LinuxCredentialUnsafe("Claude credential JSON is malformed")
        raise failure from error
    except OSError as error:
        payload[:] = b"\x00" * len(payload)
        failure = LinuxCredentialInspectionInconclusive(
            f"cannot read Claude credential source: {error}"
        )
        raise failure from error
    except BaseException as error:
        failure = error
        payload[:] = b"\x00" * len(payload)
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as close_error:
            payload[:] = b"\x00" * len(payload)
            if failure is not None:
                primary_error = _primary_cleanup_error([failure, close_error])
                if primary_error is not failure:
                    raise primary_error
            elif not _is_control_flow_error(close_error):
                raise LinuxCredentialInspectionInconclusive(
                    f"cannot close Claude credential source: {close_error}"
                ) from close_error
            else:
                raise
    assert result is not None
    return result


def _attach_secondary_failure(
    error: BaseException,
    secondary_error: BaseException,
    *,
    label: str,
    diagnostic_type: type[Exception],
) -> None:
    attach_claude_refresh_lock_recovery(error, secondary_error)
    note = f"{label}: {type(secondary_error).__name__}: {secondary_error}"
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    # BaseException.add_note() was added in Python 3.11. On Python 3.10, attach
    # a visible explicit-cause node without replacing the original exception or
    # discarding its existing explicit/implicit chain. Modifying ``args`` is not
    # sufficient because structured OSError/Unicode errors format fixed fields.
    diagnostic = diagnostic_type(note)
    if error.__cause__ is not None:
        diagnostic.__cause__ = error.__cause__
    elif error.__context__ is not None:
        diagnostic.__context__ = error.__context__
    error.__cause__ = diagnostic


def _add_cleanup_note(error: BaseException, cleanup_error: BaseException) -> None:
    _attach_secondary_failure(
        error,
        cleanup_error,
        label="Claude credential cleanup also failed",
        diagnostic_type=LinuxCredentialCleanupDiagnostic,
    )


def _add_writeback_note(error: BaseException, writeback_error: BaseException) -> None:
    setattr(error, "_codex_claude_refresh_persistence_failed", True)
    retained_carrier = getattr(
        writeback_error,
        "_codex_claude_retained_credential_carrier",
        None,
    )
    if isinstance(retained_carrier, str):
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            retained_carrier,
        )
    _attach_secondary_failure(
        error,
        writeback_error,
        label="Claude credential refresh persistence also failed",
        diagnostic_type=LinuxCredentialPersistenceDiagnostic,
    )


def _add_elf_inspection_cleanup_note(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    _attach_secondary_failure(
        error,
        cleanup_error,
        label="ELF descriptor cleanup also failed",
        diagnostic_type=LinuxRuntimeInspectionCleanupDiagnostic,
    )


def _is_control_flow_error(error: BaseException) -> bool:
    return not isinstance(error, Exception) or isinstance(error, ForwardedSignal)


@contextlib.contextmanager
def _defer_forwarded_signals_during_cleanup(
) -> Iterator[list[ForwardedSignal]]:
    previous_mask = block_forwarded_signals()
    deferred_signals: list[ForwardedSignal] = []
    try:
        yield deferred_signals
    finally:
        try:
            pending_signal = (
                consume_pending_forwarded_signal()
                if previous_mask is not None
                else None
            )
            if pending_signal is not None:
                deferred_signals.append(ForwardedSignal(pending_signal))
        finally:
            restore_signal_mask(previous_mask)


def _primary_cleanup_error(
    errors: list[BaseException],
) -> BaseException | None:
    if not errors:
        return None
    primary = next(
        (
            error
            for error in errors
            if _is_control_flow_error(error)
        ),
        errors[0],
    )
    for error in errors:
        if error is not primary:
            _add_cleanup_note(primary, error)
    return primary


def _discard_private_file(
    path: pathlib.Path,
    fd: int | None,
) -> BaseException | None:
    """Always attempt close and unlink after a best-effort in-place scrub."""

    cleanup_errors: list[BaseException] = []
    if fd is None:
        flags = (
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            fd = None
        except BaseException as error:
            cleanup_errors.append(error)
            fd = None
    if fd is not None:
        try:
            size = min(os.fstat(fd).st_size, CREDENTIAL_LIMIT_BYTES)
            zeroes = b"\x00" * min(size, 64 * 1024)
            remaining = size
            os.lseek(fd, 0, os.SEEK_SET)
            while remaining > 0:
                chunk = zeroes[: min(remaining, len(zeroes))]
                written = os.write(fd, chunk)
                if written <= 0:
                    break
                remaining -= written
            os.fsync(fd)
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_errors.append(error)
    unlink_error: BaseException | None = None
    try:
        path.unlink(missing_ok=True)
    except BaseException as error:
        unlink_error = error
        cleanup_errors.append(error)
    if unlink_error is None:
        return next(
            (
                error
                for error in cleanup_errors
                if _is_control_flow_error(error)
            ),
            None,
        )
    return _primary_cleanup_error(
        [
            unlink_error,
            *(error for error in cleanup_errors if error is not unlink_error),
        ]
    )


def _raise_partial_credential_cleanup_failure(
    cleanup_error: BaseException,
    cause: BaseException,
) -> None:
    if _is_control_flow_error(cleanup_error):
        _add_cleanup_note(cleanup_error, cause)
        raise cleanup_error
    raise LinuxCredentialInspectionInconclusive(
        f"cannot remove partial staged Claude credential safely: {cleanup_error}"
    ) from cause


def _write_private_file(path: pathlib.Path, payload: bytearray) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise LinuxCredentialInspectionInconclusive(
            f"cannot create staged Claude credential: {error}"
        ) from error
    try:
        view = memoryview(payload)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as error:
                raise LinuxCredentialInspectionInconclusive(
                    f"cannot write staged Claude credential: {error}"
                ) from error
            if written <= 0:
                raise LinuxCredentialInspectionInconclusive(
                    "cannot write staged Claude credential"
                )
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    except LinuxCredentialError as error:
        cleanup_error = _discard_private_file(path, fd)
        if cleanup_error is not None:
            _raise_partial_credential_cleanup_failure(cleanup_error, error)
        raise
    except OSError as error:
        cleanup_error = _discard_private_file(path, fd)
        if cleanup_error is not None:
            _raise_partial_credential_cleanup_failure(cleanup_error, error)
        raise LinuxCredentialInspectionInconclusive(
            f"cannot finalize staged Claude credential: {error}"
        ) from error
    except BaseException as error:
        cleanup_error = _discard_private_file(path, fd)
        if cleanup_error is not None:
            _add_cleanup_note(error, cleanup_error)
        raise
    try:
        os.close(fd)
    except BaseException as error:
        # POSIX does not make retrying the same numeric descriptor safe after a
        # failed close. Reopen by private path only for scrub/unlink cleanup.
        cleanup_error = _discard_private_file(path, None)
        if isinstance(error, OSError):
            if cleanup_error is not None:
                _raise_partial_credential_cleanup_failure(cleanup_error, error)
            raise LinuxCredentialInspectionInconclusive(
                f"cannot close staged Claude credential: {error}"
            ) from error
        if cleanup_error is not None:
            _add_cleanup_note(error, cleanup_error)
        raise


def _discard_private_file_at(
    parent_fd: int,
    name: str,
    fd: int | None,
) -> BaseException | None:
    """Scrub and unlink one helper-created credential file by directory fd."""

    cleanup_errors: list[BaseException] = []
    if fd is None:
        flags = (
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            fd = None
        except BaseException as error:
            cleanup_errors.append(error)
            fd = None
    if fd is not None:
        try:
            size = min(os.fstat(fd).st_size, CREDENTIAL_LIMIT_BYTES)
            zeroes = b"\x00" * min(size, 64 * 1024)
            remaining = size
            os.lseek(fd, 0, os.SEEK_SET)
            while remaining > 0:
                chunk = zeroes[: min(remaining, len(zeroes))]
                written = os.write(fd, chunk)
                if written <= 0:
                    break
                remaining -= written
            os.fsync(fd)
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_errors.append(error)
    unlink_error: BaseException | None = None
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except BaseException as error:
        unlink_error = error
        cleanup_errors.append(error)
    if unlink_error is None:
        return _primary_cleanup_error(cleanup_errors)
    return _primary_cleanup_error(
        [
            unlink_error,
            *(error for error in cleanup_errors if error is not unlink_error),
        ]
    )


def _create_private_credential_update(
    parent_fd: int,
    source_name: str,
    payload: bytearray,
    *,
    owner_uid: int,
) -> str:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd: int | None = None
    candidate = ""
    for _attempt in range(16):
        candidate = f".{source_name}.codex-review-{secrets.token_hex(16)}"
        try:
            fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
            break
        except FileExistsError:
            continue
        except OSError as error:
            raise LinuxCredentialUnsafe(
                f"cannot create atomic Claude credential update: {error}"
            ) from error
    if fd is None:
        raise LinuxCredentialUnsafe(
            "cannot allocate a unique atomic Claude credential update"
        )
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise LinuxCredentialUnsafe(
                "atomic Claude credential update has unsafe initial metadata"
            )
        view = memoryview(payload)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as error:
                raise LinuxCredentialUnsafe(
                    f"cannot write atomic Claude credential update: {error}"
                ) from error
            if written <= 0:
                raise LinuxCredentialUnsafe(
                    "cannot write atomic Claude credential update"
                )
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        final_metadata = os.fstat(fd)
        _validate_credential_file_metadata(final_metadata, owner_uid=owner_uid)
        if final_metadata.st_size != len(payload):
            raise LinuxCredentialUnsafe(
                "atomic Claude credential update has an invalid size"
            )
    except BaseException as error:
        cleanup_error = _discard_private_file_at(parent_fd, candidate, fd)
        if cleanup_error is not None:
            if _is_control_flow_error(cleanup_error):
                _add_cleanup_note(cleanup_error, error)
                raise cleanup_error
            _add_cleanup_note(error, cleanup_error)
        if isinstance(error, LinuxCredentialError) or _is_control_flow_error(
            error
        ):
            raise
        raise LinuxCredentialUnsafe(
            f"cannot finalize atomic Claude credential update: {error}"
        ) from error
    try:
        os.close(fd)
    except BaseException as error:
        cleanup_error = _discard_private_file_at(parent_fd, candidate, None)
        if cleanup_error is not None:
            if _is_control_flow_error(cleanup_error):
                _add_cleanup_note(cleanup_error, error)
                raise cleanup_error
            _add_cleanup_note(error, cleanup_error)
        if not _is_control_flow_error(error):
            raise LinuxCredentialUnsafe(
                f"cannot close atomic Claude credential update: {error}"
            ) from error
        raise
    return candidate


def _lock_credential_parent(
    source_anchor: _CredentialDirectoryAnchor,
    expected: _CredentialParentIdentity,
    *,
    owner_uid: int,
) -> None:
    try:
        import fcntl
    except ImportError as error:
        raise LinuxCredentialUnsafe(
            "Claude credential writeback locking is unavailable"
        ) from error
    source_anchor.assert_stable(owner_uid=owner_uid)
    descriptor = source_anchor.descriptor
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise LinuxCredentialUnsafe(
            f"cannot inspect anchored Claude credential directory: {error}"
        ) from error
    _validate_credential_parent_metadata(metadata, owner_uid=owner_uid)
    if _credential_directory_identity(metadata) != expected:
        raise LinuxCredentialUnsafe(
            "Claude credential parent changed concurrently"
        )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise LinuxCredentialUnsafe(
            "another Claude credential writeback is already active"
        ) from error
    except OSError as error:
        raise LinuxCredentialUnsafe(
            f"cannot lock Claude credential directory: {error}"
        ) from error


def _unlock_credential_parent(source_anchor: _CredentialDirectoryAnchor) -> None:
    try:
        import fcntl

        fcntl.flock(source_anchor.descriptor, fcntl.LOCK_UN)
    except BaseException as error:
        if _is_control_flow_error(error):
            raise
        raise LinuxCredentialInspectionInconclusive(
            f"cannot unlock Claude credential directory: {error}"
        ) from error


def _credential_source_identity_at(
    parent_fd: int,
    source_name: str,
    *,
    owner_uid: int,
) -> _CredentialFileIdentity:
    try:
        metadata = os.stat(
            source_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as error:
        raise LinuxCredentialInspectionInconclusive(
            "Claude credential source changed concurrently"
        ) from error
    try:
        _validate_credential_file_metadata(metadata, owner_uid=owner_uid)
    except LinuxCredentialError as error:
        raise LinuxCredentialInspectionInconclusive(
            "Claude credential source changed concurrently"
        ) from error
    return _credential_file_identity(metadata)


def _writeback_refreshed_credential_impl(
    source: pathlib.Path,
    source_anchor: _CredentialDirectoryAnchor,
    staged: StagedCredential,
    original_payload: bytearray,
    original_identity: _CredentialFileIdentity,
    parent_identity: _CredentialParentIdentity,
    *,
    owner_uid: int,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None,
    staged_payload: bytearray | None = None,
) -> _CredentialFileIdentity:
    owns_updated_payload = staged_payload is None
    if staged_payload is None:
        try:
            (
                updated_payload,
                _expires_at_ms,
                _updated_identity,
            ) = _read_valid_credential(
                staged.credential_path,
                owner_uid=owner_uid,
                now=0.0,
                required_validity_seconds=0.0,
            )
        except LinuxCredentialInspectionInconclusive:
            raise
        except LinuxCredentialError as error:
            raise LinuxCredentialUnsafe(
                "Claude staged credential update is malformed or unavailable"
            ) from error
    else:
        updated_payload = staged_payload
    try:
        if updated_payload == original_payload and refresh_lock_protocol is None:
            return original_identity
        if refresh_lock_protocol is None:
            raise LinuxCredentialInspectionInconclusive(
                "Claude credential-lock protocol is unavailable for refresh writeback"
            )
        try:
            refresh_lock = acquire_claude_refresh_lock(
                source.parent,
                protocol=refresh_lock_protocol,
                config_dir_fd=source_anchor.descriptor,
                legacy_parent_dir_fd=source_anchor.legacy_parent_descriptor,
            )
        except ClaudeRefreshLockStale as error:
            raise LinuxCredentialStaleRefreshLock(
                "a stale Claude refresh lock requires controlled cleanup after "
                "confirming that no Claude credential writer is active"
            ) from error
        except ClaudeRefreshLockError as error:
            raise LinuxCredentialInspectionInconclusive(
                f"cannot coordinate Claude credential refresh writeback: {error}"
            ) from error
        parent_fd = source_anchor.descriptor
        parent_locked = False
        current_payload: bytearray | None = None
        candidate: str | None = None
        operation_error: BaseException | None = None
        try:
            try:
                _lock_credential_parent(
                    source_anchor,
                    parent_identity,
                    owner_uid=owner_uid,
                )
                parent_locked = True
                (
                    current_payload,
                    _current_expires_at_ms,
                    current_identity,
                ) = _read_valid_credential(
                    source,
                    owner_uid=owner_uid,
                    now=0.0,
                    required_validity_seconds=0.0,
                    dir_fd=parent_fd,
                )
            except LinuxCredentialError as error:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential source changed concurrently; refusing "
                    "refresh writeback"
                ) from error
            if (
                current_identity != original_identity
                or current_payload != original_payload
            ):
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential source changed concurrently; refusing "
                    "refresh writeback"
                )
            if updated_payload == original_payload:
                return current_identity
            try:
                candidate = _create_private_credential_update(
                    parent_fd,
                    source.name,
                    updated_payload,
                    owner_uid=owner_uid,
                )
            except LinuxCredentialInspectionInconclusive:
                raise
            except LinuxCredentialError as error:
                raise LinuxCredentialInspectionInconclusive(
                    "cannot prepare Claude credential refresh writeback"
                ) from error
            candidate_identity = _credential_source_identity_at(
                parent_fd,
                candidate,
                owner_uid=owner_uid,
            )
            if (
                _credential_source_identity_at(
                    parent_fd,
                    source.name,
                    owner_uid=owner_uid,
                )
                != original_identity
            ):
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential source changed concurrently; refusing "
                    "refresh writeback"
                )
            source_anchor.assert_stable(owner_uid=owner_uid)
            try:
                refresh_lock.assert_held()
            except ClaudeRefreshLockError as error:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude refresh lock changed before credential writeback"
                ) from error
            try:
                os.replace(
                    candidate,
                    source.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            except OSError as error:
                raise LinuxCredentialInspectionInconclusive(
                    "cannot atomically replace Claude credential source"
                ) from error
            candidate = None
            committed_identity = _credential_source_identity_at(
                parent_fd,
                source.name,
                owner_uid=owner_uid,
            )
            stable_replacement_fields = (
                "device",
                "inode",
                "mode",
                "uid",
                "gid",
                "link_count",
                "size",
                "mtime_ns",
            )
            if any(
                getattr(committed_identity, field)
                != getattr(candidate_identity, field)
                for field in stable_replacement_fields
            ):
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential writeback committed but the replacement "
                    "changed concurrently"
                )
            try:
                os.fsync(parent_fd)
            except OSError as error:
                raise LinuxCredentialInspectionInconclusive(
                    "Claude credential writeback committed but directory sync failed"
                ) from error
            source_anchor.assert_stable(owner_uid=owner_uid)
            return committed_identity
        except BaseException as error:
            operation_error = error
        finally:
            payload_error: BaseException | None = None
            candidate_cleanup_error: BaseException | None = None
            unlock_error: BaseException | None = None
            refresh_lock_error: BaseException | None = None
            if current_payload is not None:
                try:
                    current_payload[:] = b"\x00" * len(current_payload)
                except BaseException as error:
                    payload_error = error
            if candidate is not None:
                candidate_cleanup_error = _discard_private_file_at(
                    parent_fd,
                    candidate,
                    None,
                )
            if parent_locked:
                try:
                    _unlock_credential_parent(source_anchor)
                except BaseException as error:
                    unlock_error = error
            try:
                refresh_lock.release()
            except ClaudeRefreshLockError as error:
                refresh_lock_error = LinuxCredentialInspectionInconclusive(
                    f"cannot release Claude credential refresh lock: {error}"
                )
                refresh_lock_error.__cause__ = error
            except BaseException as error:
                refresh_lock_error = error
            primary_error = _primary_cleanup_error(
                [
                    error
                    for error in (
                        operation_error,
                        payload_error,
                        candidate_cleanup_error,
                        unlock_error,
                        refresh_lock_error,
                    )
                    if error is not None
                ]
            )
            if primary_error is not None:
                raise primary_error
    finally:
        if owns_updated_payload:
            updated_payload[:] = b"\x00" * len(updated_payload)


def _writeback_refreshed_credential(
    source: pathlib.Path,
    source_anchor: _CredentialDirectoryAnchor,
    staged: StagedCredential,
    original_payload: bytearray,
    original_identity: _CredentialFileIdentity,
    parent_identity: _CredentialParentIdentity,
    *,
    owner_uid: int,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None,
    staged_payload: bytearray | None = None,
) -> _CredentialFileIdentity:
    """Persist a runtime refresh without reclassifying writeback as login loss."""

    try:
        return _writeback_refreshed_credential_impl(
            source,
            source_anchor,
            staged,
            original_payload,
            original_identity,
            parent_identity,
            owner_uid=owner_uid,
            refresh_lock_protocol=refresh_lock_protocol,
            staged_payload=staged_payload,
        )
    except LinuxCredentialInspectionInconclusive:
        raise
    except LinuxCredentialError:
        raise
    except BaseException as error:
        if _is_control_flow_error(error):
            raise
        wrapped = LinuxCredentialInspectionInconclusive(
            "Claude credential refresh writeback was inconclusive"
        )
        attach_claude_refresh_lock_recovery(wrapped, error)
        raise wrapped from error


def _staged_credential_observation(
    path: pathlib.Path,
) -> _CredentialFileIdentity:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise LinuxCredentialInspectionInconclusive(
            "cannot observe the staged Claude credential"
        ) from error
    return _credential_file_identity(metadata)


def _read_staged_credential_under_lock(
    staged: StagedCredential,
    *,
    owner_uid: int,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    timeout_seconds: float,
) -> tuple[bytearray, _CredentialFileIdentity] | None:
    """Read one stable staged candidate without holding the host-side locks."""

    try:
        refresh_lock = acquire_claude_refresh_lock(
            staged.config_dir,
            protocol=refresh_lock_protocol,
            timeout_seconds=timeout_seconds,
        )
    except ClaudeRefreshLockTimeout:
        return None
    except ClaudeRefreshLockStale as error:
        raise LinuxStagedCredentialRefreshLockBlocked(
            "a staged Claude refresh lock remained after the runtime writer "
            "stopped"
        ) from error
    except ClaudeRefreshLockError as error:
        raise LinuxCredentialInspectionInconclusive(
            f"cannot coordinate staged Claude credential inspection: {error}"
        ) from error

    candidate: bytearray | None = None
    candidate_identity: _CredentialFileIdentity | None = None
    operation_error: BaseException | None = None
    release_error: BaseException | None = None
    try:
        candidate, _expires_at_ms, candidate_identity = _read_valid_credential(
            staged.credential_path,
            owner_uid=owner_uid,
            now=0.0,
            required_validity_seconds=0.0,
        )
    except BaseException as error:
        operation_error = error
    finally:
        try:
            refresh_lock.release()
        except ClaudeRefreshLockError as error:
            release_error = LinuxCredentialInspectionInconclusive(
                f"cannot release staged Claude credential refresh lock: {error}"
            )
            release_error.__cause__ = error
        except BaseException as error:
            release_error = error
    primary_error = _primary_cleanup_error(
        [
            error
            for error in (operation_error, release_error)
            if error is not None
        ]
    )
    if primary_error is not None:
        if candidate is not None:
            candidate[:] = b"\x00" * len(candidate)
        raise primary_error
    assert candidate is not None
    assert candidate_identity is not None
    return candidate, candidate_identity


class _StagedCredentialWatcher:
    """Persist every observed Claude refresh rotation before carrier cleanup."""

    def __init__(
        self,
        *,
        source: pathlib.Path,
        source_anchor: _CredentialDirectoryAnchor,
        staged: StagedCredential,
        original_payload: bytearray,
        original_identity: _CredentialFileIdentity,
        parent_identity: _CredentialParentIdentity,
        owner_uid: int,
        refresh_lock_protocol: ClaudeRefreshLockProtocol,
    ) -> None:
        self._source = source
        self._source_anchor = source_anchor
        self._staged = staged
        self._baseline_payload = bytearray(original_payload)
        self._baseline_identity = original_identity
        self._parent_identity = parent_identity
        self._owner_uid = owner_uid
        self._refresh_lock_protocol = refresh_lock_protocol
        self._observed_identity = _staged_credential_observation(
            staged.credential_path
        )
        self._candidate_failure_observation: _CredentialFileIdentity | None = None
        self._candidate_failure_started_at: float | None = None
        self._stop = threading.Event()
        self._drain_lock = threading.Lock()
        self._background_writeback_state_lock = threading.Lock()
        self._background_writeback_admission_open = True
        self._background_writeback_in_flight = False
        self._background_writeback_was_in_flight_at_stop = False
        self._failure_lock = threading.Lock()
        self._worker_failure: BaseException | None = None
        self._source_anchor_handoff_lock = threading.Lock()
        self._source_anchor_cleanup_reached = False
        self._thread = threading.Thread(
            target=self._run,
            name="codex-claude-staged-credential-watcher",
            # A bounded join timeout hands the private carrier to operator
            # recovery. The daemon must never keep the helper alive forever on
            # an uninterruptible filesystem operation; normal paths still join
            # it before reading or cleaning the carrier.
            daemon=True,
        )

    def start(self) -> None:
        try:
            self._thread.start()
        except BaseException as error:
            if not _is_control_flow_error(error):
                raise LinuxCredentialInspectionInconclusive(
                    "cannot start staged Claude credential watcher"
                ) from error
            raise

    def has_started(self) -> bool:
        return self._thread.ident is not None

    def request_stop(self) -> BaseException | None:
        stop_errors: list[BaseException] = []
        while True:
            try:
                with self._background_writeback_state_lock:
                    self._background_writeback_admission_open = False
                    if self._background_writeback_in_flight:
                        self._background_writeback_was_in_flight_at_stop = True
                break
            except BaseException as error:
                stop_errors.append(error)
        while True:
            try:
                if self._stop.is_set():
                    break
                self._stop.set()
            except BaseException as error:
                stop_errors.append(error)
        return _primary_cleanup_error(stop_errors)

    def wait_until_stopped(self) -> bool:
        self._thread.join(timeout=STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS)
        return not self._thread.is_alive()

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def background_writeback_was_in_flight_at_stop(self) -> bool:
        with self._background_writeback_state_lock:
            return self._background_writeback_was_in_flight_at_stop

    def worker_failure(self) -> BaseException | None:
        with self._failure_lock:
            return self._worker_failure

    def scrub(self) -> None:
        self._baseline_payload[:] = b"\x00" * len(self._baseline_payload)

    def retain_source_anchor_after_timeout(self) -> None:
        with self._source_anchor_handoff_lock:
            self._source_anchor.detach_to_watcher()
            close_here = self._source_anchor_cleanup_reached
        if close_here:
            self._source_anchor.close_if_detached()

    def _close_source_anchor_after_worker(self) -> None:
        with self._source_anchor_handoff_lock:
            self._source_anchor_cleanup_reached = True
            close_here = self._source_anchor.detached_to_watcher
        if close_here:
            self._source_anchor.close_if_detached()

    def final_drain(self) -> None:
        self._drain(final=True)

    def has_unpersisted_update(self) -> bool:
        try:
            return (
                _staged_credential_observation(self._staged.credential_path)
                != self._observed_identity
            )
        except BaseException:
            return True

    def _record_worker_failure(self, error: BaseException) -> None:
        with self._failure_lock:
            if self._worker_failure is None:
                self._worker_failure = error

    def _admit_background_writeback(self) -> bool:
        with self._background_writeback_state_lock:
            if not self._background_writeback_admission_open:
                return False
            self._background_writeback_in_flight = True
            return True

    def _finish_background_writeback(self) -> None:
        with self._background_writeback_state_lock:
            self._background_writeback_in_flight = False

    def _run(self) -> None:
        try:
            while not self._stop.wait(STAGED_CREDENTIAL_POLL_SECONDS):
                try:
                    self._drain(final=False)
                except BaseException as error:
                    self._record_worker_failure(error)
                    self._stop.set()
                    return
        finally:
            try:
                self._close_source_anchor_after_worker()
            except BaseException as error:
                self._record_worker_failure(error)

    def _retry_candidate_error(
        self,
        observation: _CredentialFileIdentity,
        error: BaseException,
        *,
        final: bool,
        final_deadline: float,
    ) -> bool:
        if _is_control_flow_error(error):
            raise error
        now = time.monotonic()
        if self._candidate_failure_observation != observation:
            self._candidate_failure_observation = observation
            self._candidate_failure_started_at = now
        assert self._candidate_failure_started_at is not None
        retry_deadline = self._candidate_failure_started_at + (
            STAGED_CREDENTIAL_RETRY_SECONDS
        )
        if final:
            retry_deadline = min(retry_deadline, final_deadline)
        if now < retry_deadline:
            if final:
                time.sleep(
                    min(STAGED_CREDENTIAL_POLL_SECONDS, retry_deadline - now)
                )
                return True
            return False
        normalized = LinuxCredentialInspectionInconclusive(
            "staged Claude credential update remained unstable: "
            f"{error}"
        )
        normalized.__cause__ = error
        raise normalized

    def _drain(self, *, final: bool) -> None:
        final_deadline = time.monotonic() + STAGED_CREDENTIAL_RETRY_SECONDS
        with self._drain_lock:
            while True:
                try:
                    observation = _staged_credential_observation(
                        self._staged.credential_path
                    )
                except BaseException as error:
                    if _is_control_flow_error(error):
                        raise
                    observation = self._observed_identity
                    if self._retry_candidate_error(
                        observation,
                        error,
                        final=final,
                        final_deadline=final_deadline,
                    ):
                        continue
                    return
                if not final and observation == self._observed_identity:
                    return

                try:
                    stable = _read_staged_credential_under_lock(
                        self._staged,
                        owner_uid=self._owner_uid,
                        refresh_lock_protocol=self._refresh_lock_protocol,
                        timeout_seconds=(
                            STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS
                        ),
                    )
                except BaseException as error:
                    if isinstance(
                        error,
                        (
                            LinuxCredentialStaleRefreshLock,
                            LinuxStagedCredentialRefreshLockBlocked,
                        ),
                    ):
                        raise
                    if _is_control_flow_error(error):
                        raise
                    if self._retry_candidate_error(
                        observation,
                        error,
                        final=final,
                        final_deadline=final_deadline,
                    ):
                        continue
                    return
                if stable is None:
                    if final and time.monotonic() < final_deadline:
                        time.sleep(STAGED_CREDENTIAL_POLL_SECONDS)
                        continue
                    if final:
                        raise LinuxStagedCredentialRefreshLockBlocked(
                            "staged Claude credential remained locked during "
                            "final refresh persistence"
                        )
                    return

                candidate, candidate_identity = stable
                self._candidate_failure_observation = None
                self._candidate_failure_started_at = None
                adopted_candidate = False
                background_writeback_admitted = False
                try:
                    if candidate == self._baseline_payload and not final:
                        self._observed_identity = candidate_identity
                        return
                    if not final:
                        # Admission and stop closure share one state lock. Once
                        # request_stop() wins this transition, a candidate that
                        # was read earlier cannot start a new host writeback.
                        background_writeback_admitted = (
                            self._admit_background_writeback()
                        )
                        if not background_writeback_admitted:
                            return
                    committed_identity = _writeback_refreshed_credential(
                        self._source,
                        self._source_anchor,
                        self._staged,
                        self._baseline_payload,
                        self._baseline_identity,
                        self._parent_identity,
                        owner_uid=self._owner_uid,
                        refresh_lock_protocol=self._refresh_lock_protocol,
                        staged_payload=candidate,
                    )
                    if candidate != self._baseline_payload:
                        self._baseline_payload[:] = b"\x00" * len(
                            self._baseline_payload
                        )
                        self._baseline_payload = candidate
                        adopted_candidate = True
                    self._baseline_identity = committed_identity
                    self._observed_identity = candidate_identity
                    return
                finally:
                    if background_writeback_admitted:
                        self._finish_background_writeback()
                    if not adopted_candidate:
                        candidate[:] = b"\x00" * len(candidate)


def _cleanup_staged_credential(
    staged: StagedCredential,
) -> BaseException | None:
    removal_error = _discard_private_file(staged.credential_path, None)
    cleanup_errors = [
        error for error in (removal_error,) if error is not None
    ]
    for directory in (staged.config_dir, staged.carrier_root):
        try:
            directory.rmdir()
        except BaseException as error:
            cleanup_errors.append(error)
    primary = _primary_cleanup_error(cleanup_errors)
    if primary is None or _is_control_flow_error(primary):
        return primary
    if isinstance(primary, LinuxCredentialInspectionInconclusive):
        return primary
    normalized = LinuxCredentialInspectionInconclusive(
        "cannot remove the staged Claude credential carrier"
    )
    normalized.__cause__ = primary
    return normalized


def _retained_staged_credential_error(
    staged: StagedCredential,
    error: BaseException,
) -> LinuxCredentialInspectionInconclusive:
    retained = LinuxCredentialInspectionInconclusive(
        "Claude credential refresh persistence was not proven; the private "
        f"recovery carrier was retained at {staged.carrier_root}. Resume only "
        "after recovering or removing that carrier. Original failure: "
        f"{error}"
    )
    setattr(
        retained,
        "_codex_claude_retained_credential_carrier",
        str(staged.carrier_root),
    )
    setattr(retained, "_codex_claude_refresh_persistence_failed", True)
    if getattr(
        error,
        "_codex_claude_host_writeback_in_flight_at_stop",
        False,
    ):
        setattr(
            retained,
            "_codex_claude_host_writeback_in_flight_at_stop",
            True,
        )
    retained.__cause__ = error
    return retained


def _final_drain_with_staged_lock_recovery(
    watcher: _StagedCredentialWatcher,
    staged: StagedCredential,
    *,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    writer_quiescent: Callable[[], bool] | None,
) -> None:
    try:
        watcher.final_drain()
        return
    except LinuxStagedCredentialRefreshLockBlocked as blocked:
        try:
            quiescent = (
                writer_quiescent is not None
                and writer_quiescent() is True
            )
        except BaseException as proof_error:
            if _is_control_flow_error(proof_error):
                raise
            raise LinuxStagedCredentialRefreshLockBlocked(
                "cannot prove that the staged Claude credential writer stopped"
            ) from proof_error
        if not quiescent:
            raise LinuxStagedCredentialRefreshLockBlocked(
                "cannot reclaim staged Claude refresh locks without proven "
                "writer quiescence"
            ) from blocked
        try:
            recover_abandoned_staged_claude_refresh_locks(
                staged.carrier_root,
                staged.config_dir,
                protocol=refresh_lock_protocol,
                writer_quiescent=True,
            )
        except ClaudeRefreshLockError as recovery_error:
            raise LinuxStagedCredentialRefreshLockBlocked(
                "cannot safely reclaim abandoned staged Claude refresh locks"
            ) from recovery_error
        watcher.final_drain()


@contextlib.contextmanager
def stage_claude_credentials(
    source: pathlib.Path,
    helper_root: pathlib.Path,
    *,
    now: float | None = None,
    required_validity_seconds: float = DEFAULT_CREDENTIAL_VALIDITY_SECONDS,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None = None,
    writer_started: Callable[[], bool] | None = None,
    writer_quiescent: Callable[[], bool] | None = None,
) -> Iterator[StagedCredential]:
    """Copy a validated local-login credential into an isolated private config."""

    if (
        not math.isfinite(required_validity_seconds)
        or required_validity_seconds < 0
    ):
        raise LinuxCredentialUnsafe(
            "required credential validity must be finite and non-negative"
        )
    owner_uid = os.getuid()
    source = source.absolute()
    source_anchor = _open_credential_directory_anchor(
        source,
        owner_uid=owner_uid,
    )
    failure: BaseException | None = None
    try:
        with _stage_claude_credentials_anchored(
            source,
            helper_root,
            source_anchor=source_anchor,
            now=now,
            required_validity_seconds=required_validity_seconds,
            refresh_lock_protocol=refresh_lock_protocol,
            writer_started=writer_started,
            writer_quiescent=writer_quiescent,
        ) as staged:
            yield staged
    except BaseException as error:
        failure = error
        raise
    finally:
        if not source_anchor.detached_to_watcher:
            anchor_errors: list[BaseException] = []
            try:
                source_anchor.assert_stable(owner_uid=owner_uid)
            except BaseException as error:
                anchor_errors.append(error)
            try:
                source_anchor.close_if_owned()
            except BaseException as error:
                anchor_errors.append(error)
            anchor_error = _primary_cleanup_error(anchor_errors)
            if anchor_error is not None:
                if failure is None:
                    raise anchor_error
                primary = _primary_cleanup_error([failure, anchor_error])
                if primary is not failure:
                    raise primary


@contextlib.contextmanager
def _stage_claude_credentials_anchored(
    source: pathlib.Path,
    helper_root: pathlib.Path,
    *,
    source_anchor: _CredentialDirectoryAnchor,
    now: float | None,
    required_validity_seconds: float,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None,
    writer_started: Callable[[], bool] | None,
    writer_quiescent: Callable[[], bool] | None,
) -> Iterator[StagedCredential]:
    owner_uid = os.getuid()
    parent_identity = source_anchor.identity
    private_root = _validate_private_directory(helper_root, owner_uid=owner_uid)
    payload, expires_at_ms, original_identity = _read_valid_credential(
        source,
        owner_uid=owner_uid,
        now=time.time() if now is None else now,
        required_validity_seconds=required_validity_seconds,
        dir_fd=source_anchor.descriptor,
    )
    staged: StagedCredential | None = None
    carrier_root: pathlib.Path | None = None
    config_dir: pathlib.Path | None = None
    credential_path: pathlib.Path | None = None
    watcher: _StagedCredentialWatcher | None = None
    watcher_started = False
    failure: BaseException | None = None
    try:
        carrier_root = pathlib.Path(
            tempfile.mkdtemp(prefix="claude-carrier-", dir=private_root)
        )
        os.chmod(carrier_root, 0o700)
        config_dir = carrier_root / "config"
        config_dir.mkdir(mode=0o700)
        os.chmod(config_dir, 0o700)
        credential_path = config_dir / ".credentials.json"
        _write_private_file(credential_path, payload)
        staged = StagedCredential(
            carrier_root,
            config_dir,
            credential_path,
            expires_at_ms,
        )
        if refresh_lock_protocol is not None:
            watcher = _StagedCredentialWatcher(
                source=source,
                source_anchor=source_anchor,
                staged=staged,
                original_payload=payload,
                original_identity=original_identity,
                parent_identity=parent_identity,
                owner_uid=owner_uid,
                refresh_lock_protocol=refresh_lock_protocol,
            )
            start_mask = block_forwarded_signals()
            try:
                watcher.start()
                watcher_started = True
            finally:
                restore_signal_mask(start_mask)
        yield staged
    except BaseException as error:
        failure = error
        raise
    finally:
        with _defer_forwarded_signals_during_cleanup() as deferred_signals:
            writeback_error: BaseException | None = None
            payload_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            cleanup_is_safe = True
            retain_for_recovery = False
            if (
                watcher is not None
                and not watcher_started
                and watcher.has_started()
            ):
                watcher_started = True
            if watcher is not None and not watcher_started:
                try:
                    watcher.scrub()
                except BaseException as error:
                    payload_error = error
            if watcher is not None and watcher_started:
                watcher_stopped = False
                try:
                    writeback_error = watcher.request_stop()
                    watcher_stopped = watcher.wait_until_stopped()
                    if not watcher_stopped:
                        # The recovery carrier becomes authoritative before
                        # descriptor ownership handoff can itself fail.
                        retain_for_recovery = True
                        watcher.retain_source_anchor_after_timeout()
                        if (
                            watcher.background_writeback_was_in_flight_at_stop()
                        ):
                            unstopped = LinuxStagedCredentialWatcherUnstopped(
                                "staged Claude credential watcher did not stop "
                                "within its bounded join; a background host "
                                "credential writeback was already in flight "
                                "when stop closed new admission, so it may "
                                "still complete and host credential state is "
                                "ambiguous; refusing concurrent final drain "
                                "or carrier cleanup"
                            )
                            setattr(
                                unstopped,
                                "_codex_claude_host_writeback_in_flight_at_stop",
                                True,
                            )
                            raise unstopped
                        raise LinuxStagedCredentialWatcherUnstopped(
                            "staged Claude credential watcher did not stop "
                            "within its bounded join after background "
                            "writeback admission closed; refusing concurrent "
                            "final drain or carrier cleanup"
                        )
                    try:
                        runtime_writer_started = (
                            writer_started is not None
                            and writer_started() is True
                        )
                        runtime_writer_quiescent = (
                            writer_quiescent is not None
                            and writer_quiescent() is True
                        )
                    except BaseException as state_error:
                        if _is_control_flow_error(state_error):
                            raise
                        raise LinuxStagedCredentialWriterUnquiescent(
                            "cannot inspect staged Claude writer lifecycle state"
                        ) from state_error
                    if runtime_writer_started and not runtime_writer_quiescent:
                        raise LinuxStagedCredentialWriterUnquiescent(
                            "the launched Claude credential writer has no proven "
                            "process-group quiescence; refusing final drain or "
                            "carrier cleanup"
                        )
                    worker_failure = watcher.worker_failure()
                    if worker_failure is not None and _is_control_flow_error(
                        worker_failure
                    ):
                        raise worker_failure
                    try:
                        _final_drain_with_staged_lock_recovery(
                            watcher,
                            staged,
                            refresh_lock_protocol=refresh_lock_protocol,
                            writer_quiescent=writer_quiescent,
                        )
                    except BaseException as final_drain_error:
                        if worker_failure is None:
                            raise
                        primary = _primary_cleanup_error(
                            [worker_failure, final_drain_error]
                        )
                        assert primary is not None
                        raise primary
                except BaseException as error:
                    should_retain = (
                        retain_for_recovery
                        or isinstance(
                            error,
                            (
                                LinuxStagedCredentialRefreshLockBlocked,
                                LinuxStagedCredentialWatcherUnstopped,
                                LinuxStagedCredentialWriterUnquiescent,
                            ),
                        )
                        or (
                            watcher_stopped
                            and watcher.has_unpersisted_update()
                        )
                    )
                    if should_retain:
                        retain_for_recovery = True
                        retained_error = _retained_staged_credential_error(
                            staged,
                            error,
                        )
                        if _is_control_flow_error(error):
                            _add_writeback_note(error, retained_error)
                        else:
                            error = retained_error
                    writeback_error = _primary_cleanup_error(
                        [
                            candidate
                            for candidate in (writeback_error, error)
                            if candidate is not None
                        ]
                    )
                    if retain_for_recovery and writeback_error is not None:
                        setattr(
                            writeback_error,
                            "_codex_claude_retained_credential_carrier",
                            str(staged.carrier_root),
                        )
                        setattr(
                            writeback_error,
                            "_codex_claude_refresh_persistence_failed",
                            True,
                        )
                        if getattr(
                            error,
                            "_codex_claude_host_writeback_in_flight_at_stop",
                            False,
                        ):
                            setattr(
                                writeback_error,
                                "_codex_claude_host_writeback_in_flight_at_stop",
                                True,
                            )
                    if not watcher_stopped:
                        cleanup_is_safe = not watcher.is_alive()
                if cleanup_is_safe:
                    try:
                        watcher.scrub()
                    except BaseException as error:
                        writeback_error = _primary_cleanup_error(
                            [
                                candidate
                                for candidate in (writeback_error, error)
                                if candidate is not None
                            ]
                        )
            elif staged is not None:
                try:
                    _writeback_refreshed_credential(
                        source,
                        source_anchor,
                        staged,
                        payload,
                        original_identity,
                        parent_identity,
                        owner_uid=owner_uid,
                        refresh_lock_protocol=refresh_lock_protocol,
                    )
                except BaseException as error:
                    writeback_error = error
            try:
                payload[:] = b"\x00" * len(payload)
            except BaseException as error:
                payload_error = _primary_cleanup_error(
                    [
                        candidate
                        for candidate in (payload_error, error)
                        if candidate is not None
                    ]
                )
            if (
                staged is not None
                and cleanup_is_safe
                and not retain_for_recovery
            ):
                cleanup_error = _cleanup_staged_credential(staged)
            elif staged is None and carrier_root is not None:
                cleanup_errors: list[BaseException] = []
                if credential_path is not None:
                    candidate_error = _discard_private_file(
                        credential_path, None
                    )
                    if candidate_error is not None:
                        cleanup_errors.append(candidate_error)
                for directory in (config_dir, carrier_root):
                    if directory is None:
                        continue
                    try:
                        directory.rmdir()
                    except BaseException as error:
                        cleanup_errors.append(error)
                cleanup_error = _primary_cleanup_error(cleanup_errors)
        control_flow_error = next(
            (
                error
                for error in (
                    failure,
                    writeback_error,
                    payload_error,
                    cleanup_error,
                    *deferred_signals,
                )
                if error is not None and _is_control_flow_error(error)
            ),
            None,
        )
        if (
            writeback_error is not None
            and control_flow_error is not None
            and control_flow_error is not writeback_error
        ):
            _add_writeback_note(control_flow_error, writeback_error)
            writeback_error = None
        elif failure is not None and writeback_error is not None:
            if _is_control_flow_error(failure) or not _is_control_flow_error(
                writeback_error
            ):
                _add_writeback_note(failure, writeback_error)
                writeback_error = None
        primary_error = _primary_cleanup_error(
            [
                error
                for error in (
                    failure,
                    writeback_error,
                    payload_error,
                    cleanup_error,
                    *deferred_signals,
                )
                if error is not None
            ]
        )
        if primary_error is not None and primary_error is not failure:
            raise primary_error


def _path_components(path: pathlib.Path) -> tuple[pathlib.Path, ...]:
    if not path.is_absolute():
        raise LinuxRuntimeUnsafe(f"trusted runtime path is not absolute: {path}")
    current = pathlib.Path(path.anchor)
    components = [current]
    for part in path.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def _path_component_identity(
    path: pathlib.Path, metadata: os.stat_result
) -> PathComponentIdentity:
    return PathComponentIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def _path_component_anchor_identity(
    path: pathlib.Path, metadata: os.stat_result
) -> PathComponentIdentity:
    """Track directory replacement and policy metadata, not entry churn."""

    return PathComponentIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=0,
        mtime_ns=0,
        ctime_ns=0,
    )


def _capture_trusted_path_identity(
    path: pathlib.Path,
    *,
    trusted_owner_uids: frozenset[int] = frozenset({0}),
    expected_kind: str = "file",
    require_executable: bool = False,
    missing_is_unavailable: bool = False,
    allow_root_sticky_temp_ancestor: bool = False,
    ignore_parent_directory_content_changes: bool = False,
) -> TrustedPathIdentity:
    """Capture immutable metadata for every resolved path component."""

    if not path.is_absolute():
        raise LinuxRuntimeUnsafe(f"trusted runtime path is not absolute: {path}")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        error_type = (
            LinuxHostDependencyUnavailable
            if missing_is_unavailable
            else LinuxRuntimeInspectionInconclusive
        )
        raise error_type(f"trusted runtime path is unavailable: {path}") from error
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot resolve trusted runtime path {path}: {error}"
        ) from error
    captured: list[PathComponentIdentity] = []
    components = _path_components(resolved)
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot inspect trusted runtime path component {component}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise LinuxRuntimeInspectionInconclusive(
                f"trusted runtime path changed while resolving: {component}"
            )
        if metadata.st_uid not in trusted_owner_uids:
            raise LinuxRuntimeUnsafe(
                f"trusted runtime path has an untrusted owner: {component}"
            )
        is_final = index == len(components) - 1
        trusted_sticky_ancestor = (
            allow_root_sticky_temp_ancestor
            and not is_final
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o1777
        )
        if metadata.st_mode & 0o022 and not trusted_sticky_ancestor:
            raise LinuxRuntimeUnsafe(
                f"trusted runtime path is group- or world-writable: {component}"
            )
        if not is_final and not stat.S_ISDIR(metadata.st_mode):
            raise LinuxRuntimeUnsafe(
                f"trusted runtime parent is not a directory: {component}"
            )
        if is_final:
            valid_kind = (
                stat.S_ISREG(metadata.st_mode)
                if expected_kind == "file"
                else stat.S_ISDIR(metadata.st_mode)
                if expected_kind == "directory"
                else False
            )
            if not valid_kind:
                raise LinuxRuntimeUnsafe(
                    f"trusted runtime path is not a {expected_kind}: {component}"
                )
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise LinuxRuntimeUnsafe(
                    f"trusted runtime path unexpectedly has set-id mode: {component}"
                )
        captured.append(
            _path_component_anchor_identity(component, metadata)
            if ignore_parent_directory_content_changes and not is_final
            else _path_component_identity(component, metadata)
        )
    if require_executable and not os.access(resolved, os.X_OK):
        raise LinuxRuntimeUnsafe(
            f"trusted runtime tool is not executable: {resolved}"
        )
    identity = TrustedPathIdentity(
        resolved,
        tuple(captured),
        allow_root_sticky_temp_ancestor=allow_root_sticky_temp_ancestor,
        ignore_parent_directory_content_changes=(
            ignore_parent_directory_content_changes
        ),
    )
    _revalidate_trusted_path_identity(identity)
    return identity


def _revalidate_trusted_path_identity(
    identity: TrustedPathIdentity,
) -> pathlib.Path:
    """Fail if a trusted path or any of its parents changed after capture."""

    if not identity.components or identity.components[-1].path != identity.path:
        raise LinuxRuntimeUnsafe("trusted runtime path identity is malformed")
    for index, expected in enumerate(identity.components):
        try:
            metadata = expected.path.lstat()
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"trusted runtime path disappeared during validation: {expected.path}"
            ) from error
        is_final = index == len(identity.components) - 1
        trusted_sticky_ancestor = (
            identity.allow_root_sticky_temp_ancestor
            and not is_final
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o1777
        )
        if metadata.st_uid != expected.uid or (
            metadata.st_mode & 0o022 and not trusted_sticky_ancestor
        ):
            raise LinuxRuntimeUnsafe(
                f"trusted runtime path became unsafe: {expected.path}"
            )
        expected_type = stat.S_IFMT(expected.mode)
        if stat.S_IFMT(metadata.st_mode) != expected_type or (
            not is_final and not stat.S_ISDIR(metadata.st_mode)
        ):
            raise LinuxRuntimeUnsafe(
                f"trusted runtime path type changed: {expected.path}"
            )
        current = (
            _path_component_anchor_identity(expected.path, metadata)
            if identity.ignore_parent_directory_content_changes and not is_final
            else _path_component_identity(expected.path, metadata)
        )
        if current != expected:
            raise LinuxRuntimeInspectionInconclusive(
                f"trusted runtime path changed after inspection: {expected.path}"
            )
    return identity.path


def _capture_host_runtime_dependency(
    path: pathlib.Path,
    destination: pathlib.PurePosixPath,
    *,
    trusted_owner_uids: frozenset[int],
) -> HostRuntimeDependency:
    """Capture both the loader-visible lexical chain and its resolved file."""

    if not path.is_absolute():
        raise LinuxRuntimeUnsafe(
            f"host runtime dependency is not absolute: {path}"
        )
    if (
        not destination.is_absolute()
        or "." in destination.parts
        or ".." in destination.parts
        or not any(
            _pure_is_relative_to(destination, root)
            for root in _ALLOWED_LIBRARY_DESTINATIONS
        )
    ):
        raise LinuxRuntimeUnsafe(
            f"host runtime dependency has an unsafe destination: {destination}"
        )
    try:
        resolved_before = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot resolve host runtime dependency {path}: {error}"
        ) from error

    lexical_components: list[PathComponentIdentity] = []
    components = _path_components(path)
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot inspect host runtime dependency {component}: {error}"
            ) from error
        if metadata.st_uid not in trusted_owner_uids:
            raise LinuxRuntimeUnsafe(
                f"host runtime dependency has an untrusted owner: {component}"
            )
        if not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022:
            raise LinuxRuntimeUnsafe(
                "host runtime dependency is group- or world-writable: "
                f"{component}"
            )
        is_final = index == len(components) - 1
        if is_final:
            if not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            ):
                raise LinuxRuntimeUnsafe(
                    f"host runtime dependency is not a file or symlink: {component}"
                )
        elif not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        ):
            raise LinuxRuntimeUnsafe(
                f"host runtime dependency parent is not a directory: {component}"
            )
        lexical_components.append(_path_component_identity(component, metadata))

    resolved_identity = _capture_trusted_path_identity(
        path,
        trusted_owner_uids=trusted_owner_uids,
    )
    try:
        resolved_after = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"host runtime dependency changed while resolving {path}: {error}"
        ) from error
    if (
        resolved_before != resolved_after
        or resolved_after != resolved_identity.path
    ):
        raise LinuxRuntimeInspectionInconclusive(
            f"host runtime dependency changed while capturing: {path}"
        )
    dependency = HostRuntimeDependency(
        lexical_path=path,
        destination=destination,
        lexical_components=tuple(lexical_components),
        resolved_identity=resolved_identity,
    )
    _revalidate_host_runtime_dependency(dependency)
    return dependency


def _revalidate_host_runtime_dependency(
    dependency: HostRuntimeDependency,
) -> pathlib.Path:
    """Revalidate a host loader path without collapsing its symlink chain."""

    if not dependency.lexical_components:
        raise LinuxRuntimeUnsafe("host runtime dependency identity is malformed")
    for expected in dependency.lexical_components:
        try:
            metadata = expected.path.lstat()
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                "host runtime dependency disappeared during validation: "
                f"{expected.path}"
            ) from error
        if metadata.st_uid != expected.uid or (
            not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022
        ):
            raise LinuxRuntimeUnsafe(
                f"host runtime dependency became unsafe: {expected.path}"
            )
        if _path_component_identity(expected.path, metadata) != expected:
            raise LinuxRuntimeInspectionInconclusive(
                f"host runtime dependency changed after inspection: {expected.path}"
            )
    try:
        resolved = dependency.lexical_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LinuxRuntimeInspectionInconclusive(
            "host runtime dependency changed while resolving: "
            f"{dependency.lexical_path}: {error}"
        ) from error
    if resolved != dependency.resolved_identity.path:
        raise LinuxRuntimeInspectionInconclusive(
            "host runtime dependency resolved target changed: "
            f"{dependency.lexical_path}"
        )
    return _revalidate_trusted_path_identity(dependency.resolved_identity)


def _trusted_ldd(
    host: LinuxHost,
    *,
    trusted_owner_uids: frozenset[int] = frozenset({0}),
) -> TrustedPathIdentity:
    for candidate in _TRUSTED_LDD_CANDIDATES:
        try:
            reject_wsl_windows_path(candidate, host)
            # ldd is commonly a root-owned script, so validate its filesystem trust
            # separately instead of pretending it is a native runtime dependency.
            identity = _capture_trusted_path_identity(
                candidate,
                trusted_owner_uids=trusted_owner_uids,
                require_executable=True,
                missing_is_unavailable=True,
            )
            resolved = identity.path
            if not any(
                _is_relative_to(resolved, root)
                for root in _resolve_trusted_roots(_TRUSTED_TOOL_ROOTS)
            ):
                raise LinuxRuntimeUnsafe(
                    f"trusted ldd resolves outside system roots: {candidate}"
                )
            return identity
        except LinuxHostDependencyUnavailable:
            continue
        except OSError as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot inspect trusted ldd candidate {candidate}: {error}"
            ) from error
    raise LinuxHostDependencyUnavailable("no trusted system ldd is available")


def _parse_ldd_output(
    output: str,
    *,
    reject_unrecognized: bool = False,
) -> tuple[RuntimeMount, ...]:
    mounts: dict[pathlib.PurePosixPath, pathlib.Path] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("linux-vdso"):
            continue
        if "not found" in line:
            raise LinuxHostDependencyUnavailable(
                f"runtime dependency is missing: {line}"
            )
        candidate = line.split("=>", 1)[1].strip() if "=>" in line else line
        candidate = candidate.split(" (", 1)[0].strip()
        if candidate in {"statically linked", "not a dynamic executable"}:
            continue
        if not candidate.startswith("/"):
            if reject_unrecognized:
                raise LinuxRuntimeInspectionInconclusive(
                    f"cannot prove host runtime dependency from ldd output: {line}"
                )
            continue
        destination = pathlib.PurePosixPath(candidate)
        source = pathlib.Path(candidate)
        previous = mounts.get(destination)
        if previous is not None and previous != source:
            raise LinuxRuntimeUnsafe(
                "runtime dependency output maps one destination to conflicting "
                f"sources: {destination}"
            )
        mounts[destination] = source
    return tuple(
        RuntimeMount(source, destination)
        for destination, source in sorted(mounts.items(), key=lambda item: str(item[0]))
    )


def _canonical_glibc_loader(host: LinuxHost) -> pathlib.PurePosixPath:
    try:
        return _CANONICAL_GLIBC_LOADERS[host.arch]
    except KeyError as error:
        raise LinuxHostDependencyUnavailable(
            f"no canonical glibc loader is defined for {host.arch}"
        ) from error


def _capture_glibc_loader(
    host: LinuxHost,
    interpreter: pathlib.PurePosixPath,
    *,
    trusted_owner_uids: frozenset[int],
) -> HostRuntimeDependency:
    expected = _canonical_glibc_loader(host)
    if interpreter != expected:
        raise LinuxRuntimeUnsafe(
            "host GPG does not use the canonical glibc loader for "
            f"{host.arch}: {interpreter}"
        )
    lexical = pathlib.Path(str(interpreter))
    try:
        lexical.lstat()
    except (FileNotFoundError, NotADirectoryError) as error:
        raise LinuxHostDependencyUnavailable(
            f"canonical glibc loader is unavailable: {interpreter}"
        ) from error
    except OSError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot inspect canonical glibc loader {interpreter}: {error}"
        ) from error
    reject_wsl_windows_path(lexical, host)
    loader = _capture_host_runtime_dependency(
        lexical,
        interpreter,
        trusted_owner_uids=trusted_owner_uids,
    )
    reject_wsl_windows_paths(
        (loader.lexical_path, loader.resolved_identity.path),
        host,
    )
    return loader


def _parse_glibc_loader_version(output: str) -> tuple[int, int]:
    match = _GLIBC_LOADER_VERSION.match(output)
    if match is None:
        raise LinuxHostDependencyUnavailable(
            "canonical loader did not identify itself as a supported glibc ld.so"
        )
    version = (int(match.group(1)), int(match.group(2)))
    if not (_MINIMUM_GLIBC_VERSION <= version < _MAXIMUM_GLIBC_VERSION):
        raise LinuxHostDependencyUnavailable(
            "canonical glibc loader version is outside the supported range "
            f">={_MINIMUM_GLIBC_VERSION[0]}.{_MINIMUM_GLIBC_VERSION[1]},"
            f"<{_MAXIMUM_GLIBC_VERSION[0]}.{_MAXIMUM_GLIBC_VERSION[1]}: "
            f"{version[0]}.{version[1]}"
        )
    return version


def _require_safe_glibc_loader(
    loader: HostRuntimeDependency,
    host: LinuxHost,
) -> pathlib.Path:
    if loader.destination != _canonical_glibc_loader(host):
        raise LinuxRuntimeUnsafe(
            f"glibc loader identity has an unexpected destination: {loader.destination}"
        )
    resolved = _revalidate_host_runtime_dependency(loader)
    if not os.access(resolved, os.X_OK):
        raise LinuxRuntimeUnsafe(
            f"canonical glibc loader is not executable: {resolved}"
        )
    info = inspect_elf(resolved)
    _require_safe_host_elf_loader_policy(info)
    if info.elf_type != 3:
        raise LinuxRuntimeUnsafe(f"glibc loader is not an ET_DYN image: {resolved}")
    if info.interpreter is not None:
        raise LinuxRuntimeUnsafe(
            f"glibc loader unexpectedly names another interpreter: {resolved}"
        )
    if info.arch != host.arch:
        raise LinuxRuntimeUnsafe(
            f"glibc loader architecture {info.arch} does not match {host.arch}"
        )
    return resolved


def _probe_glibc_loader_version(
    loader: HostRuntimeDependency,
    host: LinuxHost,
    *,
    runner: Runner,
) -> tuple[int, int]:
    resolved = _require_safe_glibc_loader(loader, host)
    try:
        result = _run_tool_probe(runner, (str(resolved), "--version"))
    except LinuxRuntimeInspectionInconclusive:
        raise
    except ReviewError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"glibc loader identity probe failed: {error}"
        ) from error
    _require_safe_glibc_loader(loader, host)
    if result.returncode != 0:
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise LinuxHostDependencyUnavailable(
            f"canonical glibc loader does not support --version: {detail}"
        )
    try:
        output = bytes(result.stdout).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot parse canonical glibc loader version: {error}"
        ) from error
    return _parse_glibc_loader_version(output)


def _require_no_elf_audit_modules(info: ElfInfo) -> None:
    if not info.has_audit and not info.has_depaudit:
        return
    labels = ", ".join(
        label
        for present, label in (
            (info.has_audit, "DT_AUDIT"),
            (info.has_depaudit, "DT_DEPAUDIT"),
        )
        if present
    )
    raise LinuxRuntimeUnsafe(
        f"ELF uses an embedded dynamic-loader audit module ({labels}): {info.path}"
    )


def _require_safe_host_elf_loader_policy(info: ElfInfo) -> None:
    _require_no_elf_audit_modules(info)
    if info.has_rpath or info.has_runpath:
        labels = ", ".join(
            label
            for present, label in (
                (info.has_rpath, "DT_RPATH"),
                (info.has_runpath, "DT_RUNPATH"),
            )
            if present
        )
        raise LinuxRuntimeUnsafe(
            f"host GPG ELF uses a mutable loader search path ({labels}): {info.path}"
        )
    if info.interpreter is None:
        return
    interpreter = pathlib.PurePosixPath(info.interpreter)
    if (
        not interpreter.is_absolute()
        or "." in interpreter.parts
        or ".." in interpreter.parts
        or not any(
            _pure_is_relative_to(interpreter, root)
            for root in _ALLOWED_LIBRARY_DESTINATIONS
        )
    ):
        raise LinuxRuntimeUnsafe(
            f"host GPG ELF has an unsafe interpreter: {info.interpreter}"
        )


def _require_safe_host_gpg_loader_policy(
    info: ElfInfo,
    host: LinuxHost,
) -> pathlib.PurePosixPath:
    _require_safe_host_elf_loader_policy(info)
    expected = _canonical_glibc_loader(host)
    if info.interpreter != str(expected) or info.libc != "glibc":
        raise LinuxRuntimeUnsafe(
            "host GPG does not use the canonical glibc loader for "
            f"{host.arch}: {info.interpreter or '<none>'}"
        )
    return expected


def _require_safe_host_dependency_loader_policy(
    info: ElfInfo,
    host: LinuxHost,
) -> None:
    _require_safe_host_elf_loader_policy(info)
    if info.elf_type != 3:
        raise LinuxRuntimeUnsafe(
            f"host runtime library is not an ET_DYN image: {info.path}"
        )
    if (
        info.interpreter is not None
        and info.interpreter != str(_canonical_glibc_loader(host))
    ):
        raise LinuxRuntimeUnsafe(
            "host runtime library names a noncanonical interpreter: "
            f"{info.path}"
        )


def _collect_host_runtime_closure_with_loader(
    host: LinuxHost,
    executable: pathlib.Path,
    loader: HostRuntimeDependency,
    *,
    runner: Runner,
    trusted_owner_uids: frozenset[int],
    executable_owner_uids: frozenset[int],
    expected_glibc_version: tuple[int, int] | None = None,
) -> HostRuntimeClosure:
    executable_identity = _capture_trusted_path_identity(
        executable,
        trusted_owner_uids=executable_owner_uids,
        require_executable=True,
        allow_root_sticky_temp_ancestor=True,
        ignore_parent_directory_content_changes=True,
    )
    info = inspect_elf(executable_identity.path)
    interpreter = _require_safe_host_gpg_loader_policy(info, host)
    if info.path != executable_identity.path:
        raise LinuxRuntimeInspectionInconclusive(
            "host GPG executable changed during ELF inspection"
        )
    if info.arch != host.arch:
        raise LinuxRuntimeUnsafe(
            f"host GPG architecture {info.arch} does not match {host.arch}"
        )

    loader_path = _require_safe_glibc_loader(loader, host)
    reject_wsl_windows_paths(
        (
            executable_identity.path,
            loader.lexical_path,
            loader.resolved_identity.path,
        ),
        host,
    )
    glibc_version = _probe_glibc_loader_version(loader, host, runner=runner)
    if (
        expected_glibc_version is not None
        and glibc_version != expected_glibc_version
    ):
        raise LinuxRuntimeInspectionInconclusive(
            "canonical glibc loader changed its reported version"
        )
    # The host GPG has already been restricted to this canonical, statically
    # inspected glibc loader. Its fixed --list trace path maps dependencies but
    # exits before application relocation, constructors, or entry-point code.
    # Dependency policy is checked immediately after the trace and before GPG.
    # Do not add --verify, --list-diagnostics, or any relocation-bearing mode.
    loader_path = _require_safe_glibc_loader(loader, host)
    try:
        result = _run_tool_probe(
            runner,
            (str(loader_path), "--list", str(executable_identity.path)),
        )
    except LinuxRuntimeInspectionInconclusive:
        raise
    except ReviewError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"host runtime dependency inspection failed for {executable}: {error}"
        ) from error
    _revalidate_trusted_path_identity(executable_identity)
    _require_safe_glibc_loader(loader, host)
    if result.returncode != 0:
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot resolve host runtime libraries for {executable}: {detail}"
        )
    try:
        parsed = _parse_ldd_output(
            bytes(result.stdout).decode("utf-8", errors="strict"),
            reject_unrecognized=True,
        )
    except UnicodeDecodeError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot parse host runtime libraries for {executable}: {error}"
        ) from error

    requested: dict[pathlib.PurePosixPath, pathlib.Path] = {
        mount.destination: mount.source for mount in parsed
    }
    interpreter_path = loader.lexical_path
    previous = requested.get(interpreter)
    if previous is not None and previous != interpreter_path:
        raise LinuxRuntimeUnsafe(
            "host runtime interpreter resolves to conflicting sources: "
            f"{interpreter}"
        )
    requested[interpreter] = interpreter_path

    captured_dependencies: list[HostRuntimeDependency] = []
    for destination, source in sorted(
        requested.items(), key=lambda item: str(item[0])
    ):
        if destination == interpreter:
            if source != loader.lexical_path:
                raise LinuxRuntimeUnsafe(
                    "canonical glibc loader resolves to an unexpected source: "
                    f"{source}"
                )
            dependency = loader
        else:
            dependency = _capture_host_runtime_dependency(
                source,
                destination,
                trusted_owner_uids=trusted_owner_uids,
            )
        dependency_info = inspect_elf(dependency.resolved_identity.path)
        _require_safe_host_dependency_loader_policy(dependency_info, host)
        if dependency_info.arch != host.arch:
            raise LinuxRuntimeUnsafe(
                "host runtime dependency architecture does not match the host: "
                f"{dependency.lexical_path}"
            )
        captured_dependencies.append(dependency)
    dependencies = tuple(captured_dependencies)
    reject_wsl_windows_paths(
        (
            executable_identity.path,
            loader.lexical_path,
            loader.resolved_identity.path,
            *(dependency.lexical_path for dependency in dependencies),
            *(
                dependency.resolved_identity.path
                for dependency in dependencies
            ),
        ),
        host,
    )
    for dependency in dependencies:
        _revalidate_host_runtime_dependency(dependency)
    _revalidate_trusted_path_identity(executable_identity)
    _require_safe_glibc_loader(loader, host)
    return HostRuntimeClosure(
        host=host,
        executable_identity=executable_identity,
        loader=loader,
        glibc_version=glibc_version,
        interpreter=info.interpreter,
        dependencies=dependencies,
        trusted_owner_uids=trusted_owner_uids,
        executable_owner_uids=executable_owner_uids,
    )


def collect_host_runtime_closure(
    host: LinuxHost,
    executable: pathlib.Path,
    *,
    runner: Runner = run_bounded_capture,
    trusted_owner_uids: frozenset[int] = frozenset({0}),
    executable_owner_uids: frozenset[int] | None = None,
) -> HostRuntimeClosure:
    """Capture the exact host loader closure for one trusted GPG snapshot."""

    require_supported_host(host)
    selected_executable_owners = (
        frozenset({0, os.geteuid()})
        if executable_owner_uids is None
        else executable_owner_uids
    )
    executable_identity = _capture_trusted_path_identity(
        executable,
        trusted_owner_uids=selected_executable_owners,
        require_executable=True,
        allow_root_sticky_temp_ancestor=True,
        ignore_parent_directory_content_changes=True,
    )
    info = inspect_elf(executable_identity.path)
    interpreter = _require_safe_host_gpg_loader_policy(info, host)
    _revalidate_trusted_path_identity(executable_identity)
    loader = _capture_glibc_loader(
        host,
        interpreter,
        trusted_owner_uids=trusted_owner_uids,
    )
    return _collect_host_runtime_closure_with_loader(
        host,
        executable,
        loader,
        runner=runner,
        trusted_owner_uids=trusted_owner_uids,
        executable_owner_uids=selected_executable_owners,
    )


def revalidate_host_runtime_closure(
    closure: HostRuntimeClosure,
    *,
    runner: Runner = run_bounded_capture,
) -> HostRuntimeClosure:
    """Re-resolve and require an identical host GPG loader closure."""

    require_supported_host(closure.host)
    _revalidate_trusted_path_identity(closure.executable_identity)
    _require_safe_glibc_loader(closure.loader, closure.host)
    reject_wsl_windows_paths(
        (
            closure.executable_identity.path,
            closure.loader.lexical_path,
            closure.loader.resolved_identity.path,
            *(dependency.lexical_path for dependency in closure.dependencies),
            *(
                dependency.resolved_identity.path
                for dependency in closure.dependencies
            ),
        ),
        closure.host,
    )
    for dependency in closure.dependencies:
        _revalidate_host_runtime_dependency(dependency)
    refreshed = _collect_host_runtime_closure_with_loader(
        closure.host,
        closure.executable_identity.path,
        closure.loader,
        runner=runner,
        trusted_owner_uids=closure.trusted_owner_uids,
        executable_owner_uids=closure.executable_owner_uids,
        expected_glibc_version=closure.glibc_version,
    )
    if refreshed != closure:
        raise LinuxRuntimeInspectionInconclusive(
            "host GPG runtime closure changed before execution"
        )
    return refreshed


def collect_runtime_libraries(
    host: LinuxHost,
    executables: Sequence[pathlib.Path],
    *,
    runner: Runner = run_bounded_capture,
    ldd_path: pathlib.Path | None = None,
    ldd_trusted_roots: Sequence[pathlib.Path] = _TRUSTED_TOOL_ROOTS,
    trusted_owner_uids: frozenset[int] = frozenset({0}),
) -> tuple[RuntimeMount, ...]:
    """Resolve exact dynamic-loader/library files for verified runtime binaries."""

    require_supported_host(host)
    if ldd_path is None:
        ldd_identity = _trusted_ldd(
            host, trusted_owner_uids=trusted_owner_uids
        )
    else:
        ldd_identity = _capture_trusted_path_identity(
            ldd_path,
            trusted_owner_uids=trusted_owner_uids,
            require_executable=True,
            missing_is_unavailable=True,
        )
        if not any(
            _is_relative_to(ldd_identity.path, root)
            for root in _resolve_trusted_roots(ldd_trusted_roots)
        ):
            raise LinuxRuntimeUnsafe(
                f"trusted ldd resolves outside configured roots: {ldd_path}"
            )
    mounts: dict[pathlib.PurePosixPath, RuntimeMount] = {}
    for executable in executables:
        reject_wsl_windows_path(executable, host)
        _require_no_elf_audit_modules(inspect_elf(executable))
        ldd = _revalidate_trusted_path_identity(ldd_identity)
        try:
            result = _run_tool_probe(runner, (str(ldd), str(executable)))
        except LinuxIsolationUnavailable as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"runtime dependency inspection failed for {executable}: {error}"
            ) from error
        _revalidate_trusted_path_identity(ldd_identity)
        if result.returncode != 0:
            detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot resolve runtime libraries for {executable}: {detail}"
            )
        try:
            parsed = _parse_ldd_output(
                bytes(result.stdout).decode("utf-8", errors="strict")
            )
        except (OSError, UnicodeDecodeError) as error:
            raise LinuxRuntimeInspectionInconclusive(
                f"cannot parse runtime libraries for {executable}: {error}"
            ) from error
        for mount in parsed:
            reject_wsl_windows_path(mount.source, host)
            if (
                not mount.destination.is_absolute()
                or "." in mount.destination.parts
                or ".." in mount.destination.parts
                or not any(
                    _pure_is_relative_to(mount.destination, root)
                    for root in _ALLOWED_LIBRARY_DESTINATIONS
                )
            ):
                raise LinuxRuntimeUnsafe(
                    f"runtime library has an unsafe destination: {mount.destination}"
                )
            identity = _capture_trusted_path_identity(
                mount.source,
                trusted_owner_uids=trusted_owner_uids,
            )
            validated = RuntimeMount(
                identity.path,
                mount.destination,
                identity,
            )
            previous = mounts.get(mount.destination)
            if previous is not None and previous.source != validated.source:
                raise LinuxRuntimeUnsafe(
                    "runtime dependency destination resolves to conflicting sources: "
                    f"{mount.destination}"
                )
            mounts[mount.destination] = validated
    return tuple(
        _validate_runtime_mount(mount, host)
        for _destination, mount in sorted(mounts.items(), key=lambda item: str(item[0]))
    )


def compile_launcher(
    host: LinuxHost,
    toolchain: NativeToolchain,
    output_path: pathlib.Path,
    *,
    source_path: pathlib.Path = LAUNCHER_SOURCE,
    runner: Runner = run_bounded_capture,
) -> pathlib.Path:
    """Compile the fixed no-shell proxy/reaper launcher into a private directory."""

    require_supported_host(host)
    parent = _validate_private_directory(output_path.parent, owner_uid=os.getuid())
    temporary = parent / f".{output_path.name}.{os.getpid()}.tmp"
    if temporary.exists():
        raise LinuxRuntimeError(f"launcher temporary path already exists: {temporary}")
    result = _run_tool_probe(
        runner,
        (
            str(toolchain.cc),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_POSIX_C_SOURCE=200809L",
            str(source_path),
            "-o",
            str(temporary),
        ),
        timeout_seconds=30.0,
    )
    if result.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise LinuxIsolationUnavailable(
            f"cannot compile Claude Linux launcher: {detail}"
        )
    try:
        os.chmod(temporary, 0o500)
        info = inspect_elf(temporary)
        if info.arch != host.arch:
            raise LinuxRuntimeError(
                f"compiled launcher architecture {info.arch} does not match {host.arch}"
            )
        os.replace(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path.resolve(strict=True)


def _pure_is_relative_to(
    path: pathlib.PurePosixPath, parent: pathlib.PurePosixPath
) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_runtime_mount(mount: RuntimeMount, host: LinuxHost) -> RuntimeMount:
    reject_wsl_windows_path(mount.source, host)
    if (
        not mount.destination.is_absolute()
        or "." in mount.destination.parts
        or ".." in mount.destination.parts
        or not any(
            _pure_is_relative_to(mount.destination, root)
            for root in _ALLOWED_LIBRARY_DESTINATIONS
        )
    ):
        raise LinuxRuntimeUnsafe(
            f"runtime library destination is outside loader roots: {mount.destination}"
        )
    if mount.identity is None or mount.source != mount.identity.path:
        raise LinuxRuntimeUnsafe(
            f"runtime library lacks a trusted path identity: {mount.source}"
        )
    source = _revalidate_trusted_path_identity(mount.identity)
    return RuntimeMount(source, mount.destination, mount.identity)


def revalidate_runtime_libraries(
    host: LinuxHost,
    libraries: Sequence[RuntimeMount],
) -> tuple[RuntimeMount, ...]:
    """Revalidate one previously captured loader/library closure."""

    require_supported_host(host)
    return tuple(_validate_runtime_mount(mount, host) for mount in libraries)


def _validate_private_socket(
    path: pathlib.Path,
    *,
    helper_root: pathlib.Path,
    owner_uid: int,
    host: LinuxHost,
) -> pathlib.Path:
    reject_wsl_windows_path(path, host)
    if path.is_symlink():
        raise LinuxRuntimeError(f"proxy socket must not be a symlink: {path}")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise LinuxRuntimeError(
            f"cannot inspect proxy socket {path}: {error}"
        ) from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LinuxRuntimeError(
            "proxy socket must be current-user-owned with mode 0600"
        )
    parent = resolved.parent
    lexical_parent = path.absolute().parent
    temporary_alias = pathlib.Path("/tmp").absolute()
    try:
        temporary_root = temporary_alias.resolve(strict=True)
    except OSError:
        temporary_root = temporary_alias
    try:
        if temporary_root != temporary_alias and _is_relative_to(
            lexical_parent,
            temporary_alias,
        ):
            alias_relative = lexical_parent.relative_to(temporary_alias)
            canonical_parent = temporary_root.joinpath(alias_relative)
            if (
                canonical_parent.resolve(strict=True) != canonical_parent
                or canonical_parent != parent
            ):
                raise LinuxRuntimeError(
                    "proxy socket parent path must not contain symlinks"
                )
        elif lexical_parent.resolve(strict=True) != lexical_parent:
            raise LinuxRuntimeError(
                "proxy socket parent path must not contain symlinks"
            )
    except OSError as error:
        raise LinuxRuntimeError(
            f"cannot inspect proxy socket parent path {lexical_parent}: {error}"
        ) from error
    stop = (
        helper_root
        if _is_relative_to(parent, helper_root)
        else temporary_root
        if _is_relative_to(parent, temporary_root)
        else None
    )
    if stop is None:
        raise LinuxRuntimeError(
            "proxy socket parent must be below helper_root or a private /tmp directory"
        )
    if stop == temporary_root and parent == temporary_root:
        raise LinuxRuntimeError(
            "proxy socket must be inside a current-user 0700 directory below /tmp"
        )
    current = parent
    while current != stop:
        try:
            current_lstat = current.lstat()
        except OSError as error:
            raise LinuxRuntimeError(
                f"cannot inspect proxy socket parent {current}: {error}"
            ) from error
        if (
            stat.S_ISLNK(current_lstat.st_mode)
            or not stat.S_ISDIR(current_lstat.st_mode)
            or current_lstat.st_uid != owner_uid
            or stat.S_IMODE(current_lstat.st_mode) != 0o700
        ):
            raise LinuxRuntimeError(
                f"proxy socket parent must be a current-user 0700 real directory: {current}"
            )
        current = current.parent
    return resolved


_WORKSPACE_SYMLINK_METADATA_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _validate_workspace_symlink_boundary(workspace: pathlib.Path) -> None:
    """Reject model-visible links that can resolve outside the frozen workspace."""

    symlink_count = 0
    try:
        candidates = workspace.rglob("*")
        for candidate in candidates:
            before = candidate.lstat()
            if not stat.S_ISLNK(before.st_mode):
                continue
            symlink_count += 1
            if symlink_count > WORKSPACE_SYMLINK_LIMIT:
                raise LinuxRuntimeInspectionInconclusive(
                    "Claude Linux workspace exceeds its symlink inspection limit"
                )
            target_before = os.readlink(candidate)
            relative = pathlib.PurePosixPath(
                candidate.relative_to(workspace).as_posix()
            )
            if not symlink_target_stays_within_workspace(relative, target_before):
                raise LinuxRuntimeUnsafe(
                    "Claude Linux workspace symlink escapes the model-visible "
                    f"workspace: {candidate}"
                )
            try:
                resolved = candidate.resolve(strict=False)
            except RuntimeError as error:
                raise LinuxRuntimeUnsafe(
                    f"Claude Linux workspace contains a symlink loop: {candidate}"
                ) from error
            target_after = os.readlink(candidate)
            after = candidate.lstat()
            if target_before != target_after or any(
                getattr(before, field) != getattr(after, field)
                for field in _WORKSPACE_SYMLINK_METADATA_FIELDS
            ):
                raise LinuxRuntimeInspectionInconclusive(
                    "Claude Linux workspace symlink changed during inspection: "
                    f"{candidate}"
                )
            if not _is_relative_to(resolved, workspace):
                raise LinuxRuntimeUnsafe(
                    "Claude Linux workspace symlink escapes the model-visible "
                    f"workspace: {candidate}"
                )
    except LinuxRuntimeError:
        raise
    except OSError as error:
        raise LinuxRuntimeInspectionInconclusive(
            f"cannot inspect Claude Linux workspace symlinks: {error}"
        ) from error


def _validate_sandbox_spec(spec: SandboxSpec) -> SandboxSpec:
    require_supported_host(spec.host)
    owner_uid = os.getuid()
    helper_root = _validate_private_directory(spec.helper_root, owner_uid=owner_uid)
    workspace = spec.workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise LinuxRuntimeError(f"review workspace is not a directory: {workspace}")
    _validate_workspace_symlink_boundary(workspace)
    if _is_relative_to(helper_root, workspace) or _is_relative_to(
        workspace, helper_root
    ):
        raise LinuxRuntimeError("workspace and helper private root must not overlap")
    private_paths = tuple(
        _validate_private_directory(path, owner_uid=owner_uid)
        for path in (spec.helper_home, spec.helper_tmp, spec.config_dir)
    )
    if any(not _is_relative_to(path, helper_root) for path in private_paths):
        raise LinuxRuntimeError(
            "helper writable directories must stay below helper_root"
        )
    config_root = _validate_private_directory(
        private_paths[2].parent,
        owner_uid=owner_uid,
    )
    if (
        private_paths[2].name != "config"
        or config_root.parent != helper_root
    ):
        raise LinuxRuntimeError(
            "Claude writable config must be nested in a dedicated carrier root"
        )
    if any(
        _is_relative_to(config_root, writable_role)
        or _is_relative_to(writable_role, config_root)
        for writable_role in private_paths[:2]
    ):
        raise LinuxRuntimeError(
            "Claude authentication carrier must not overlap another helper "
            "writable role"
        )
    proxy_socket = _validate_private_socket(
        spec.proxy_socket,
        helper_root=helper_root,
        owner_uid=owner_uid,
        host=spec.host,
    )
    claude_info = validate_claude_executable(spec.claude, spec.host)
    launcher_info = inspect_elf(spec.launcher)
    if launcher_info.arch != spec.host.arch:
        raise LinuxRuntimeError("launcher ELF architecture does not match the host")
    if not os.access(claude_info.path, os.X_OK) or not os.access(
        launcher_info.path, os.X_OK
    ):
        raise LinuxRuntimeError("Claude and launcher must be executable")
    libraries = tuple(
        _validate_runtime_mount(mount, spec.host) for mount in spec.runtime_libraries
    )
    ca_bundle: pathlib.Path | None = None
    ca_bundle_identity: TrustedPathIdentity | None = None
    if not isinstance(spec.node_extra_ca_certs_configured, bool):
        raise LinuxRuntimeError(
            "Claude Node extra CA configuration state must be boolean"
        )
    if spec.ca_bundle is not None:
        reject_wsl_windows_path(spec.ca_bundle, spec.host)
        ca_bundle_identity = _capture_trusted_path_identity(
            spec.ca_bundle,
            trusted_owner_uids=frozenset({0, owner_uid}),
        )
        ca_bundle = ca_bundle_identity.path
        if ca_bundle_identity.components[-1].size <= 0:
            raise LinuxRuntimeError("Claude CA bundle is not a non-empty regular file")
    if spec.node_extra_ca_certs_configured and ca_bundle is None:
        raise LinuxRuntimeError(
            "Claude Node extra CA configuration requires a private CA bundle"
        )
    return SandboxSpec(
        host=spec.host,
        toolchain=spec.toolchain,
        claude=claude_info.path,
        launcher=launcher_info.path,
        workspace=workspace,
        helper_root=helper_root,
        helper_home=private_paths[0],
        helper_tmp=private_paths[1],
        config_dir=private_paths[2],
        proxy_socket=proxy_socket,
        runtime_libraries=libraries,
        ca_bundle=ca_bundle,
        ca_bundle_identity=ca_bundle_identity,
        node_extra_ca_certs_configured=spec.node_extra_ca_certs_configured,
    )


def _mount_directories(
    file_paths: Iterable[pathlib.PurePosixPath],
    directory_paths: Iterable[pathlib.PurePosixPath],
) -> tuple[pathlib.PurePosixPath, ...]:
    directories: set[pathlib.PurePosixPath] = set()
    for path in file_paths:
        current = path.parent
        while current != pathlib.PurePosixPath("/"):
            directories.add(current)
            current = current.parent
    for path in directory_paths:
        current = path
        while current != pathlib.PurePosixPath("/"):
            directories.add(current)
            current = current.parent
    return tuple(sorted(directories, key=lambda path: (len(path.parts), str(path))))


def _unique_option_value(arguments: Sequence[str], option: str) -> str:
    indexes = tuple(index for index, value in enumerate(arguments) if value == option)
    if len(indexes) != 1 or indexes[0] + 1 >= len(arguments):
        raise LinuxRuntimeUnsafe(
            f"Claude Linux review requires exactly one {option} value"
        )
    return arguments[indexes[0] + 1]


def _strict_json_object(raw: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        payload = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise LinuxRuntimeUnsafe(
            "Claude Linux review settings are not strict JSON"
        ) from error
    if not isinstance(payload, dict):
        raise LinuxRuntimeUnsafe("Claude Linux review settings must be a JSON object")
    return payload


def _top_level_sandbox_root(path: pathlib.PurePosixPath) -> pathlib.PurePosixPath:
    if not path.is_absolute() or len(path.parts) < 2:
        raise LinuxRuntimeUnsafe(f"invalid synthetic-root destination: {path}")
    return pathlib.PurePosixPath("/") / path.parts[1]


def _validate_linux_review_tool_boundary(
    arguments: Sequence[str],
    destinations: Iterable[pathlib.PurePosixPath],
) -> None:
    destinations = tuple(destinations)
    if "--add-dir" in arguments:
        raise LinuxRuntimeUnsafe("Claude Linux review must not add file-tool roots")
    if _unique_option_value(arguments, "--setting-sources") != "":
        raise LinuxRuntimeUnsafe(
            "Claude Linux review must disable inherited setting sources"
        )
    if (
        _unique_option_value(arguments, "--permission-mode")
        != CLAUDE_LINUX_REVIEW_PERMISSION_MODE
    ):
        raise LinuxRuntimeUnsafe(
            "Claude Linux review must deny file-tool requests that are not allowed"
        )
    if (
        _unique_option_value(arguments, "--tools")
        != CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS
    ):
        raise LinuxRuntimeUnsafe(
            "Claude Linux review exposes an unexpected built-in tool set"
        )
    if (
        _unique_option_value(arguments, "--allowedTools")
        != CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS
    ):
        raise LinuxRuntimeUnsafe(
            "Claude Linux review allow rule is not workspace-relative"
        )
    if (
        _unique_option_value(arguments, "--disallowedTools")
        != CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS
    ):
        raise LinuxRuntimeUnsafe(
            "Claude Linux review CLI deny rules do not protect the synthetic root"
        )

    settings = _strict_json_object(_unique_option_value(arguments, "--settings"))
    if set(settings) != {"disableAllHooks", "permissions"} or settings.get(
        "disableAllHooks"
    ) is not True:
        raise LinuxRuntimeUnsafe(
            "Claude Linux review settings contain an unexpected capability"
        )
    permissions = settings.get("permissions")
    if not isinstance(permissions, dict) or set(permissions) != {"deny"}:
        raise LinuxRuntimeUnsafe(
            "Claude Linux review permissions must contain only deny rules"
        )
    deny = permissions.get("deny")
    if (
        not isinstance(deny, list)
        or any(not isinstance(rule, str) for rule in deny)
        or len(deny) != len(set(deny))
    ):
        raise LinuxRuntimeUnsafe(
            "Claude Linux review permission deny rules are malformed"
        )
    missing_rules = set(CLAUDE_LINUX_FILE_TOOL_DENY_RULES).difference(deny)
    if missing_rules:
        raise LinuxRuntimeUnsafe(
            "Claude Linux review settings omit synthetic-root file-tool denies"
        )

    nested_workspace_destinations = {
        destination
        for destination in destinations
        if destination != SANDBOX_WORKSPACE
        and _pure_is_relative_to(destination, SANDBOX_WORKSPACE)
    }
    if nested_workspace_destinations:
        rendered = ", ".join(
            str(path) for path in sorted(nested_workspace_destinations, key=str)
        )
        raise LinuxRuntimeUnsafe(
            "Claude Linux review must not add a separate mount below the allowed "
            f"workspace: {rendered}"
        )

    mounted_roots = {
        _top_level_sandbox_root(destination) for destination in destinations
    }
    mounted_roots.discard(SANDBOX_WORKSPACE)
    uncovered_roots = mounted_roots.difference(CLAUDE_LINUX_FILE_TOOL_DENIED_ROOTS)
    if uncovered_roots:
        rendered = ", ".join(str(path) for path in sorted(uncovered_roots, key=str))
        raise LinuxRuntimeUnsafe(
            f"Claude Linux review exposes an uncovered synthetic-root path: {rendered}"
        )


def build_probe_command(
    host: LinuxHost,
    toolchain: NativeToolchain,
    claude: pathlib.Path,
    probe_home: pathlib.Path,
    runtime_libraries: Sequence[RuntimeMount],
    args: Sequence[str],
    *,
    library_roots: Sequence[pathlib.Path] = (),
) -> tuple[str, ...]:
    """Build a no-network bootstrap command for version/help capability probes."""

    require_supported_host(host)
    claude_info = validate_claude_executable(claude, host)
    home = _validate_private_directory(probe_home, owner_uid=os.getuid())
    libraries = tuple(
        _validate_runtime_mount(mount, host) for mount in runtime_libraries
    )
    root_mounts: list[tuple[TrustedPathIdentity, pathlib.PurePosixPath]] = []
    for lexical_root in library_roots:
        if not lexical_root.is_absolute() or lexical_root == pathlib.Path("/"):
            raise LinuxRuntimeUnsafe(
                f"bootstrap library root is not narrowly absolute: {lexical_root}"
            )
        reject_wsl_windows_path(lexical_root, host)
        identity = _capture_trusted_path_identity(
            lexical_root,
            expected_kind="directory",
        )
        destination = pathlib.PurePosixPath(str(lexical_root))
        if not any(
            _pure_is_relative_to(destination, allowed) or destination == allowed
            for allowed in _ALLOWED_LIBRARY_DESTINATIONS
        ):
            raise LinuxRuntimeUnsafe(
                f"bootstrap library root has an unsafe destination: {lexical_root}"
            )
        root_mounts.append((identity, destination))
    if any("\x00" in argument for argument in args):
        raise LinuxRuntimeError("Claude bootstrap probe argument contains NUL")
    file_mounts = [RuntimeMount(claude_info.path, SANDBOX_CLAUDE), *libraries]
    file_destinations = [mount.destination for mount in file_mounts]
    directory_destinations = (
        SANDBOX_HOME,
        SANDBOX_TMP,
        pathlib.PurePosixPath("/proc"),
        pathlib.PurePosixPath("/dev"),
        *(destination for _identity, destination in root_mounts),
    )
    command: list[str] = [
        str(toolchain.bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--clearenv",
        "--tmpfs",
        "/",
    ]
    for directory in _mount_directories(file_destinations, directory_destinations):
        command.extend(("--dir", str(directory)))
    command.extend(("--proc", "/proc", "--dev", "/dev"))
    command.extend(("--ro-bind", str(home), str(SANDBOX_HOME)))
    command.extend(("--tmpfs", str(SANDBOX_TMP)))
    seen_destinations: set[pathlib.PurePosixPath] = set()
    for mount in file_mounts:
        if mount.destination in seen_destinations:
            raise LinuxRuntimeError(
                f"duplicate bootstrap runtime destination: {mount.destination}"
            )
        seen_destinations.add(mount.destination)
        if mount.identity is not None:
            _revalidate_trusted_path_identity(mount.identity)
        command.extend(("--ro-bind", str(mount.source), str(mount.destination)))
    for identity, destination in root_mounts:
        if destination in seen_destinations:
            raise LinuxRuntimeError(
                f"duplicate bootstrap runtime destination: {destination}"
            )
        seen_destinations.add(destination)
        source = _revalidate_trusted_path_identity(identity)
        command.extend(("--ro-bind", str(source), str(destination)))
    command.extend(("--remount-ro", "/"))
    for key, value in (
        ("HOME", str(SANDBOX_HOME)),
        ("TMPDIR", str(SANDBOX_TMP)),
        ("CLAUDE_CONFIG_DIR", str(SANDBOX_HOME)),
        ("PATH", str(SANDBOX_BIN)),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
    ):
        command.extend(("--setenv", key, value))
    command.extend(
        (
            "--chdir",
            str(SANDBOX_HOME),
            "--",
            str(SANDBOX_CLAUDE),
            "--safe-mode",
            *args,
        )
    )
    return tuple(command)


def build_sandbox_command(
    spec: SandboxSpec,
    claude_arguments: Sequence[str],
    *,
    auth_env: Mapping[str, str] | None = None,
    workload_override: Sequence[str] | None = None,
) -> SandboxCommand:
    """Build a synthetic-root bwrap command; no host shell is mounted or invoked."""

    validated = _validate_sandbox_spec(spec)
    for argument in claude_arguments:
        if "\x00" in argument:
            raise LinuxRuntimeError("Claude argument contains NUL")
    environment = dict(auth_env or {})
    unexpected = set(environment).difference(_AUTH_ENV_KEYS)
    if unexpected:
        raise LinuxRuntimeError(
            f"unsupported Claude authentication environment keys: {sorted(unexpected)}"
        )
    if any(
        not isinstance(value, str) or "\x00" in value for value in environment.values()
    ):
        raise LinuxRuntimeError("Claude authentication environment value is invalid")
    executable_mounts = (
        RuntimeMount(validated.claude, SANDBOX_CLAUDE),
        RuntimeMount(validated.launcher, SANDBOX_LAUNCHER),
        RuntimeMount(validated.toolchain.socat, SANDBOX_SOCAT),
        RuntimeMount(validated.toolchain.rg, SANDBOX_RG),
    )
    all_file_mounts = list(executable_mounts) + list(validated.runtime_libraries)
    if validated.ca_bundle is not None:
        if (
            validated.ca_bundle_identity is None
            or validated.ca_bundle_identity.path != validated.ca_bundle
        ):
            raise LinuxRuntimeUnsafe("Claude CA bundle lacks a trusted path identity")
        all_file_mounts.append(
            RuntimeMount(
                validated.ca_bundle,
                SANDBOX_CA_BUNDLE,
                validated.ca_bundle_identity,
            )
        )
    file_destinations = [mount.destination for mount in all_file_mounts]
    file_destinations.append(SANDBOX_PROXY_SOCKET)
    directory_destinations = (
        SANDBOX_WORKSPACE,
        SANDBOX_HOME,
        SANDBOX_TMP,
        SANDBOX_AUTH_ROOT,
        SANDBOX_CONFIG,
        pathlib.PurePosixPath("/proc"),
        pathlib.PurePosixPath("/dev"),
    )
    if workload_override is None:
        _validate_linux_review_tool_boundary(
            claude_arguments,
            (*file_destinations, *directory_destinations),
        )
    command: list[str] = [
        str(validated.toolchain.bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--tmpfs",
        "/",
    ]
    if not environment:
        command.insert(command.index("--tmpfs"), "--clearenv")
    for directory in _mount_directories(file_destinations, directory_destinations):
        command.extend(("--dir", str(directory)))
    command.extend(("--proc", "/proc", "--dev", "/dev"))
    command.extend(("--ro-bind", str(validated.workspace), str(SANDBOX_WORKSPACE)))
    command.extend(("--bind", str(validated.helper_home), str(SANDBOX_HOME)))
    command.extend(("--bind", str(validated.helper_tmp), str(SANDBOX_TMP)))
    command.extend(
        (
            "--bind",
            str(validated.config_dir.parent),
            str(SANDBOX_AUTH_ROOT),
        )
    )
    command.extend(
        ("--ro-bind", str(validated.proxy_socket), str(SANDBOX_PROXY_SOCKET))
    )
    seen_destinations: set[pathlib.PurePosixPath] = set()
    for mount in all_file_mounts:
        if mount.destination in seen_destinations:
            raise LinuxRuntimeError(
                f"duplicate sandbox runtime destination: {mount.destination}"
            )
        seen_destinations.add(mount.destination)
        if mount.identity is not None:
            _revalidate_trusted_path_identity(mount.identity)
        command.extend(("--ro-bind", str(mount.source), str(mount.destination)))
    command.extend(("--remount-ro", "/"))
    fixed_environment = {
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_SAFE_MODE": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "HOME": str(SANDBOX_HOME),
        "TMPDIR": str(SANDBOX_TMP),
        "CLAUDE_CONFIG_DIR": str(SANDBOX_CONFIG),
        "PATH": str(SANDBOX_BIN),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HTTP_PROXY": "http://127.0.0.1:3128",
        "HTTPS_PROXY": "http://127.0.0.1:3128",
        "http_proxy": "http://127.0.0.1:3128",
        "https_proxy": "http://127.0.0.1:3128",
        "NO_PROXY": "",
        "no_proxy": "",
    }
    if validated.ca_bundle is not None:
        fixed_environment["SSL_CERT_FILE"] = str(SANDBOX_CA_BUNDLE)
    # Caller inputs stay separate through validation. The final Linux sandbox
    # intentionally reuses one private bundle; only explicit caller state
    # enables Node's process-startup additive CA input.
    if validated.node_extra_ca_certs_configured:
        fixed_environment["NODE_EXTRA_CA_CERTS"] = str(SANDBOX_CA_BUNDLE)
    for key, value in sorted(fixed_environment.items()):
        if "\x00" in value:
            raise LinuxRuntimeError(f"sandbox environment value contains NUL: {key}")
        command.extend(("--setenv", key, value))
    command.extend(("--chdir", str(SANDBOX_WORKSPACE), "--"))
    workload = (
        tuple(workload_override)
        if workload_override is not None
        else (str(SANDBOX_CLAUDE), *claude_arguments)
    )
    if not workload or any("\x00" in item for item in workload):
        raise LinuxRuntimeError("sandbox workload is empty or contains NUL")
    command.extend(
        (
            str(SANDBOX_LAUNCHER),
            "--proxy",
            str(SANDBOX_PROXY_SOCKET),
            "--socat",
            str(SANDBOX_SOCAT),
            "--",
            *workload,
        )
    )
    return SandboxCommand(
        tuple(command),
        environment,
        SANDBOX_WORKSPACE,
        SANDBOX_HOME,
        SANDBOX_TMP,
        SANDBOX_CONFIG,
    )


def run_isolation_probe(
    spec: SandboxSpec,
    workspace_read_path: pathlib.Path,
    *,
    host_home: pathlib.Path | None = None,
    runner: Runner = run_bounded_capture,
) -> None:
    """Verify the real synthetic-root, writable areas, bridge, and network denial."""

    workspace = spec.workspace.resolve(strict=True)
    marker = workspace_read_path.resolve(strict=True)
    if not marker.is_file() or not _is_relative_to(marker, workspace):
        raise LinuxRuntimeError(
            "isolation probe marker must be a file inside workspace"
        )
    relative_marker = marker.relative_to(workspace)
    hidden_home = (host_home if host_home is not None else pathlib.Path.home()).resolve(
        strict=True
    )
    if str(hidden_home) == str(SANDBOX_HOME):
        hidden_home = next(
            (
                candidate
                for name in (".ssh", ".claude", ".config", ".profile")
                if (candidate := hidden_home / name).exists()
            ),
            None,
        )
        if hidden_home is None:
            raise LinuxRuntimeError(
                "host-home isolation probe needs an existing path distinct from sandbox HOME"
            )
    sandbox_marker = SANDBOX_WORKSPACE.joinpath(*relative_marker.parts)
    probe_workload = (
        str(SANDBOX_LAUNCHER),
        "--probe",
        str(sandbox_marker),
        str(SANDBOX_WORKSPACE),
        str(SANDBOX_HOME),
        str(SANDBOX_TMP),
        str(hidden_home),
    )
    command = build_sandbox_command(
        spec,
        (),
        workload_override=probe_workload,
    )
    result = _run_tool_probe(
        runner,
        command.argv,
        timeout_seconds=PROBE_TIMEOUT_SECONDS,
    )
    if result.returncode != 0 or bytes(result.stdout) != PROBE_SUCCESS:
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise LinuxIsolationUnavailable(
            "Claude Linux isolation probe rejected the runtime: "
            f"{detail or 'unexpected probe result'}"
        )


__all__ = [
    "CLAUDE_LINUX_FILE_TOOL_DENIED_ROOTS",
    "CLAUDE_LINUX_FILE_TOOL_DENY_RULES",
    "CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS",
    "CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS",
    "CLAUDE_LINUX_REVIEW_PERMISSION_MODE",
    "CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS",
    "ElfInfo",
    "HostRuntimeClosure",
    "HostRuntimeDependency",
    "LAUNCHER_SOURCE",
    "LinuxCredentialError",
    "LinuxCredentialUnavailable",
    "LinuxCredentialUnsafe",
    "LinuxHost",
    "LinuxHostDependencyUnavailable",
    "LinuxHostKind",
    "LinuxIsolationUnavailable",
    "LinuxRuntimeError",
    "LinuxRuntimeInspectionInconclusive",
    "LinuxRuntimeUnsafe",
    "LinuxUnsupportedHost",
    "NativeToolchain",
    "PathComponentIdentity",
    "RuntimeMount",
    "SandboxCommand",
    "SandboxSpec",
    "StagedCredential",
    "TrustedPathIdentity",
    "build_probe_command",
    "build_sandbox_command",
    "collect_host_runtime_closure",
    "collect_runtime_libraries",
    "compile_launcher",
    "detect_host",
    "discover_native_toolchain",
    "fixed_host_tool_environment",
    "inspect_elf",
    "probe_bwrap",
    "revalidate_host_runtime_closure",
    "revalidate_runtime_libraries",
    "reject_wsl_windows_path",
    "reject_wsl_windows_paths",
    "require_supported_host",
    "run_isolation_probe",
    "stage_claude_credentials",
    "validate_claude_executable",
]
