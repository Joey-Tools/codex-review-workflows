from __future__ import annotations

import errno
import fcntl
import functools
import hashlib
import json
import os
import pathlib
import platform
import resource
import select
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping, Protocol, Sequence

from .codex_executable import (
    CodexExecutableRetentionRequired,
    ExecutableRevalidationEvidence,
    ExtendedMetadataEvidence,
    FdExecutionEvidence,
    NodeIdentity,
    OperationIdentityEvidence,
    OwnerSnapshotLaunchAttestation,
    PathComponentEvidence,
    SnapshotCopyEvidence,
    SnapshotEvidence,
    build_snapshot_seatbelt_policy,
    verify_macos_filesystem_metadata,
)
from .process import process_start_identity
from .prompt import prove_exec_budget


SANDBOX_EXEC = pathlib.Path("/usr/bin/sandbox-exec")
SEATBELT_PROFILE_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 2
MAX_EXECUTABLE_BYTES = 1 << 30
MAX_WRITABLE_ROOTS = 8
MAX_SEATBELT_PROFILE_BYTES = 32 * 1024
PROBE_TIMEOUT_SECONDS = 5.0
PROBE_DETAIL_OUTER_SEATBELT_DENIED = "nested-seatbelt-denied-by-outer-sandbox"
PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING = "probe-leader-exited-before-binding"
PROBE_DETAIL_KILLED_BEFORE_EVIDENCE = "probe-killed-before-evidence"
_LAUNCH_LEADER_RECEIPT_MAGIC = b"NCLPID1\0"
_LAUNCH_LEADER_RECEIPT = struct.Struct("!8sQ")


@dataclass(frozen=True)
class RuntimePin:
    macos_product_version: str
    macos_build_version: str
    darwin_release: str
    sandbox_exec_sha256: str
    python_major: int = 3
    python_minor: int = 13
    seatbelt_profile_version: int = SEATBELT_PROFILE_VERSION

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


# This pin must be deliberately revised after every relevant macOS update.
PINNED_RUNTIME = RuntimePin(
    macos_product_version="26.5.2",
    macos_build_version="25F84",
    darwin_release="25.5.0",
    sandbox_exec_sha256=(
        "8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16"
    ),
)


@dataclass(frozen=True)
class RuntimeFingerprint:
    platform: str
    system: str
    macos_product_version: str | None
    macos_build_version: str | None
    darwin_release: str | None
    python_version: tuple[int, int, int]
    python_executable: str
    effective_uid: int | None

    def to_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["python_version"] = list(self.python_version)
        return value


@dataclass(frozen=True)
class ExecutableIdentity:
    path: str
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str
    flags: int = 0
    generation: int = 0

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def object_identity_key(self) -> tuple[int, int, int, int]:
        return (
            self.device,
            self.inode,
            stat.S_IFMT(self.mode),
            self.generation,
        )

    def content_key(self) -> tuple[int, str]:
        return (self.size, self.sha256)

    def access_policy_key(self) -> tuple[int, int, int, int]:
        return (
            self.uid,
            self.gid,
            stat.S_IMODE(self.mode),
            self.flags,
        )


@dataclass(frozen=True, slots=True)
class PathExecutedExecutableAttestation:
    executable: ExecutableIdentity
    components: tuple[PathComponentEvidence, ...]


@dataclass(frozen=True)
class ProbeObservation:
    layer: str
    action: str
    outcome: str
    error_number: int | None = None
    detail: str = ""
    child_pid: int | None = None
    child_process_group: int | None = None
    child_session: int | None = None
    child_start_identity: str | None = None
    profile_sha256: str | None = None
    pre_exec_setsid_succeeded: bool | None = None
    pre_exec_pid: int | None = None
    pre_exec_process_group: int | None = None
    pre_exec_session: int | None = None
    pre_exec_nproc_soft: int | None = None
    pre_exec_nproc_hard: int | None = None
    nproc_soft: int | None = None
    nproc_hard: int | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CompatibilityEvidence:
    schema_version: int
    runtime_pin: RuntimePin
    runtime: RuntimeFingerprint
    sandbox_exec: ExecutableIdentity | None
    probe_executable: ExecutableIdentity | None
    alternate_executable: ExecutableIdentity | None
    seatbelt_profile_sha256: str | None
    parent_nproc_before: tuple[int, int] | None
    parent_nproc_after: tuple[int, int] | None
    observations: tuple[ProbeObservation, ...]
    blockers: tuple[str, ...]

    @property
    def compatible(self) -> bool:
        return not self.blockers

    @property
    def production_capable(self) -> bool:
        return self.compatible and self.runtime_pin == PINNED_RUNTIME

    def observation(self, layer: str, action: str) -> ProbeObservation | None:
        for item in self.observations:
            if item.layer == layer and item.action == action:
                return item
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runtime_pin": self.runtime_pin.to_json(),
            "runtime": self.runtime.to_json(),
            "sandbox_exec": (
                self.sandbox_exec.to_json() if self.sandbox_exec else None
            ),
            "probe_executable": (
                self.probe_executable.to_json() if self.probe_executable else None
            ),
            "alternate_executable": (
                self.alternate_executable.to_json()
                if self.alternate_executable
                else None
            ),
            "seatbelt_profile_sha256": self.seatbelt_profile_sha256,
            "parent_nproc_before": (
                list(self.parent_nproc_before) if self.parent_nproc_before else None
            ),
            "parent_nproc_after": (
                list(self.parent_nproc_after) if self.parent_nproc_after else None
            ),
            "observations": [item.to_json() for item in self.observations],
            "blockers": list(self.blockers),
            "compatible": self.compatible,
            "production_capable": self.production_capable,
        }


class NoChildProfileError(RuntimeError):
    pass


class NoChildProfileUnavailable(NoChildProfileError):
    def __init__(self, evidence: CompatibilityEvidence) -> None:
        detail = ", ".join(evidence.blockers) or "unknown incompatibility"
        super().__init__(f"no-child-process profile is unavailable: {detail}")
        self.evidence = evidence


class ExecutableAuthenticationError(NoChildProfileError):
    pass


@dataclass(frozen=True, slots=True)
class NoChildLaunchClosureEvidence:
    leader_pid: int | None
    fork_call_started: bool
    fork_call_completed: bool
    pipe_ownership_published: bool
    leader_receipt_received: bool
    exec_acknowledged: bool
    leader_binding_complete: bool
    leader_reaped: bool
    process_group_empty: bool
    control_pipes_closed: bool
    reason: str


class NoChildLaunchClosureUnproven(CodexExecutableRetentionRequired):
    def __init__(self, *, evidence: NoChildLaunchClosureEvidence) -> None:
        self.evidence = evidence
        super().__init__(
            "no-child launch failed after fork and exact leader, process-group, "
            "or control-pipe closure could not be proved; launch controls must "
            "be retained",
            code="no-child-launch-closure-unproven",
        )
        self.retain_recovery_evidence(evidence)


@dataclass(frozen=True, slots=True)
class ProbeControlDescriptorCloseEvidence:
    role: str
    descriptor: int
    outcome: str


@dataclass(frozen=True, slots=True)
class NoChildProbeClosureEvidence:
    leader_pid: int
    worker_release_attempted: bool
    worker_released: bool
    communicate_completed: bool
    leader_binding_complete: bool
    process_group_bound: bool
    leader_reaped: bool
    process_group_empty: bool
    control_pipes_closed: bool
    output_pipes_closed: bool
    control_descriptor_close_evidence: tuple[
        ProbeControlDescriptorCloseEvidence,
        ...,
    ]
    reason: str


class NoChildProbeClosureUnproven(CodexExecutableRetentionRequired):
    def __init__(self, *, evidence: NoChildProbeClosureEvidence) -> None:
        self.evidence = evidence
        super().__init__(
            "no-child compatibility probe cleanup could not prove worker and "
            "pipe closure; probe controls must be retained",
            code="no-child-probe-closure-unproven",
        )


@dataclass(frozen=True, slots=True)
class NoChildProbeSpawnOwnershipEvidence:
    popen_call_started: bool
    popen_call_completed: bool
    ownership_published: bool
    leader_pid: int | None
    control_pipes_closed: bool
    output_pipes_closed: bool
    control_descriptor_close_evidence: tuple[
        ProbeControlDescriptorCloseEvidence,
        ...,
    ]
    reason: str


class NoChildProbeSpawnOwnershipUnproven(CodexExecutableRetentionRequired):
    def __init__(self, *, evidence: NoChildProbeSpawnOwnershipEvidence) -> None:
        self.evidence = evidence
        super().__init__(
            "no-child compatibility probe spawn ownership could not be "
            "proved; probe controls must be retained",
            code="no-child-probe-spawn-ownership-unproven",
        )


@dataclass(frozen=True)
class PreparedNoChildProfile:
    executable: ExecutableIdentity
    expected_sha256: str
    seatbelt_profile: str
    evidence: CompatibilityEvidence
    additional_seatbelt_rules: str = ""
    owner_snapshot_attestation: OwnerSnapshotLaunchAttestation | None = None
    writable_roots: tuple[WritableRootAttestation, ...] = ()
    sandboxed_target: ExecutableIdentity | None = None
    sandboxed_target_attestation: PathExecutedExecutableAttestation | None = None


@dataclass(frozen=True)
class WritableRootAttestation:
    """FD-bound authority for one private filesystem write root.

    The caller owns ``directory_fd``. It must be a non-inheritable, read-only
    directory descriptor for ``path`` and remain open until launch returns. The
    directory must stay owned by the effective user with exact mode 0700.
    """

    path: str
    directory_fd: int
    identity: NodeIdentity
    filesystem_metadata: ExtendedMetadataEvidence
    path_components: tuple[PathComponentEvidence, ...]


@dataclass(frozen=True)
class LaunchedNoChildProcess:
    pid: int
    pgid: int
    session_id: int
    start_identity: str
    profile_sha256: str
    passed_fd_numbers: tuple[int, ...]
    executable: ExecutableIdentity
    evidence: CompatibilityEvidence
    parent_nproc_before: tuple[int, int]
    parent_nproc_after: tuple[int, int]


class NoChildLaunchResultOwner(Protocol):
    """Caller-side ownership publisher for one exact bound leader result."""

    def publish(self, launched: LaunchedNoChildProcess) -> None: ...

    def owns(self, launched: LaunchedNoChildProcess) -> bool: ...


_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xbe\xba\xfe\xca",
    b"\xbf\xba\xfe\xca",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
}
_DENIAL_ERRNOS = {errno.EAGAIN, errno.EPERM}
_CREATION_ACTIONS = ("fork", "posix_spawn", "popen", "double_fork")
_SEATBELT_ACTIONS = (*_CREATION_ACTIONS, "setsid", "setpgid", "exec")


_PROBE_WORKER = r"""
import json
import os
import resource
import subprocess
import sys

action = sys.argv[1]
alternate = sys.argv[2]
release_fd = int(sys.argv[3])
if os.read(release_fd, 1) != b"G":
    raise SystemExit(90)
os.close(release_fd)
initial_pid = os.getpid()
initial_process_group = os.getpgrp()
initial_session = os.getsid(0)


def emit(outcome, error_number=None, detail=""):
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    payload = {
        "action": action,
        "outcome": outcome,
        "error_number": error_number,
        "detail": detail,
        "child_pid": initial_pid,
        "child_process_group": initial_process_group,
        "child_session": initial_session,
        "nproc_soft": soft,
        "nproc_hard": hard,
    }
    print(json.dumps(payload, sort_keys=True), flush=True)


if action == "baseline":
    emit("observed")
elif action in {"fork", "double_fork"}:
    try:
        pid = os.fork()
    except OSError as error:
        emit("denied", error.errno)
    else:
        if pid == 0:
            os._exit(73)
        os.waitpid(pid, 0)
        emit("allowed", detail="first fork completed")
elif action == "posix_spawn":
    try:
        pid = os.posix_spawn(alternate, [alternate], dict(os.environ))
    except OSError as error:
        emit("denied", error.errno)
    else:
        os.waitpid(pid, 0)
        emit("allowed", detail="posix_spawn completed")
elif action == "popen":
    try:
        process = subprocess.Popen(
            [alternate],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError as error:
        emit("denied", error.errno)
    else:
        process.wait(timeout=2.0)
        emit("allowed", detail="subprocess.Popen completed")
elif action == "setsid":
    try:
        os.setsid()
    except OSError as error:
        emit("denied", error.errno)
    else:
        emit("allowed", detail="setsid completed")
elif action == "setpgid":
    try:
        os.setpgid(0, 0)
    except OSError as error:
        emit("denied", error.errno)
    else:
        emit("allowed", detail="setpgid completed")
elif action == "exec":
    try:
        os.execv(alternate, [alternate])
    except OSError as error:
        emit("denied", error.errno)
else:
    emit("ambiguous", detail="unknown probe action")
"""


def _bounded_text(value: bytes | str, *, limit: int = 1024) -> str:
    if isinstance(value, bytes):
        result = value.decode("utf-8", "replace")
    else:
        result = value
    return result[:limit].replace("\x00", "\\0").strip()


def _sw_vers(flag: str) -> str | None:
    try:
        completed = subprocess.run(
            ["/usr/bin/sw_vers", flag],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = completed.stdout.strip()
    if completed.returncode != 0 or not 1 <= len(output) <= 128:
        return None
    try:
        return output.decode("ascii", "strict")
    except UnicodeDecodeError:
        return None


def _runtime_fingerprint() -> RuntimeFingerprint:
    is_darwin = sys.platform == "darwin" and platform.system() == "Darwin"
    return RuntimeFingerprint(
        platform=sys.platform,
        system=platform.system(),
        macos_product_version=_sw_vers("-productVersion") if is_darwin else None,
        macos_build_version=_sw_vers("-buildVersion") if is_darwin else None,
        darwin_release=platform.release() if is_darwin else None,
        python_version=(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        ),
        python_executable=sys.executable,
        effective_uid=os.geteuid() if hasattr(os, "geteuid") else None,
    )


def _validate_digest(expected_sha256: str) -> None:
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or expected_sha256.lower() != expected_sha256
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ExecutableAuthenticationError(
            "expected executable SHA-256 must be 64 lowercase hexadecimal characters"
        )


def _canonical_absolute_path(path: os.PathLike[str] | str) -> pathlib.Path:
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        raise ExecutableAuthenticationError("executable path must be absolute")
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot resolve executable path: {error}"
        ) from error
    if canonical != candidate:
        raise ExecutableAuthenticationError(
            "executable path and every path component must be canonical and symlink-free"
        )
    if any(ord(character) < 32 for character in str(canonical)):
        raise ExecutableAuthenticationError(
            "executable path contains a control character"
        )
    try:
        str(canonical).encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ExecutableAuthenticationError(
            "executable path must be ASCII for the pinned Seatbelt profile"
        ) from error
    return canonical


def python_runtime_executable() -> pathlib.Path:
    if sys.version_info[:2] != (3, 13):
        raise ExecutableAuthenticationError("Python 3.13 is required")
    if sys.platform == "darwin":
        runtime = (
            pathlib.Path(sys.base_prefix)
            / "Resources"
            / "Python.app"
            / "Contents"
            / "MacOS"
            / "Python"
        )
        try:
            if runtime.is_file():
                return runtime.resolve(strict=True)
        except OSError as error:
            raise ExecutableAuthenticationError(
                "cannot resolve the Python 3.13 app runtime"
            ) from error
    return pathlib.Path(sys.executable).resolve(strict=True)


def _read_executable_identity(
    path: os.PathLike[str] | str,
) -> ExecutableIdentity:
    return _authenticate_path_executed_executable(path).executable


def _fd_digest_and_magic(fd: int, *, size: int) -> tuple[str, bytes]:
    if size < 4 or size > MAX_EXECUTABLE_BYTES:
        raise ExecutableAuthenticationError("executable size is outside policy")
    digest = hashlib.sha256()
    magic = b""
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1 << 20, size - offset), offset)
        if not chunk:
            raise ExecutableAuthenticationError(
                "custodied snapshot ended before its attested size"
            )
        if len(magic) < 4:
            magic = (magic + chunk)[:4]
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(fd, 1, size):
        raise ExecutableAuthenticationError(
            "custodied snapshot exceeds its attested size"
        )
    return digest.hexdigest(), magic


def _path_execution_access_policy_key(
    identity: NodeIdentity,
    *,
    kind: str,
) -> tuple[int | None, ...]:
    link_count = identity.link_count if kind == "file" else None
    return (*identity.access_policy_key(), link_count)


def _require_safe_path_execution_component(
    *,
    path: pathlib.Path,
    kind: str,
    identity: NodeIdentity,
    filesystem_metadata: ExtendedMetadataEvidence,
    trusted_uid: int,
) -> None:
    if not isinstance(filesystem_metadata, ExtendedMetadataEvidence):
        raise ExecutableAuthenticationError(
            "path-executed target access-policy evidence is malformed"
        )
    if path == pathlib.Path("/"):
        if identity.uid != 0:
            raise ExecutableAuthenticationError(
                "path-executed target filesystem-root access policy has an "
                "untrusted owner"
            )
    elif identity.uid not in {0, trusted_uid}:
        raise ExecutableAuthenticationError(
            "path-executed target component access policy has an untrusted "
            f"owner: {path}"
        )
    if identity.mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ExecutableAuthenticationError(
            "path-executed target component access policy permits an "
            f"untrusted writer: {path}"
        )
    if identity.mode & (stat.S_ISUID | stat.S_ISGID):
        raise ExecutableAuthenticationError(
            f"path-executed target component has set-id permission: {path}"
        )
    if kind == "directory":
        if not stat.S_ISDIR(identity.mode):
            raise ExecutableAuthenticationError(
                f"path-executed target ancestor is not a directory: {path}"
            )
        return
    if kind != "file" or not stat.S_ISREG(identity.mode):
        raise ExecutableAuthenticationError(
            "path-executed target is not a regular file"
        )
    if identity.link_count != 1:
        raise ExecutableAuthenticationError(
            "path-executed target access policy has an unsafe hard-link count"
        )
    if identity.mode & 0o111 == 0:
        raise ExecutableAuthenticationError(
            "path-executed target has no execute mode bit"
        )


def _inspect_path_execution_component(
    descriptor: int,
    *,
    path: pathlib.Path,
    kind: str,
    trusted_uid: int,
) -> tuple[PathComponentEvidence, ExecutableIdentity | None]:
    try:
        before = NodeIdentity.from_stat(os.fstat(descriptor))
        path_before = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot bind path-executed target component: {error}"
        ) from error
    if before.object_identity_key() != path_before.object_identity_key():
        raise ExecutableAuthenticationError(
            f"path-executed target component object identity raced: {path}"
        )
    if _path_execution_access_policy_key(
        before,
        kind=kind,
    ) != _path_execution_access_policy_key(path_before, kind=kind):
        raise ExecutableAuthenticationError(
            f"path-executed target component access policy raced: {path}"
        )
    try:
        filesystem_metadata = verify_macos_filesystem_metadata(
            descriptor,
            path,
            kind,
        )
    except (OSError, ValueError) as error:
        raise ExecutableAuthenticationError(
            f"path-executed target access policy is unsafe: {path}: {error}"
        ) from error
    try:
        middle = NodeIdentity.from_stat(os.fstat(descriptor))
        first_digest: str | None = None
        first_magic: bytes | None = None
        second_digest: str | None = None
        second_magic: bytes | None = None
        if kind == "file":
            first_digest, first_magic = _fd_digest_and_magic(
                descriptor,
                size=middle.size,
            )
            digest_middle = NodeIdentity.from_stat(os.fstat(descriptor))
            second_digest, second_magic = _fd_digest_and_magic(
                descriptor,
                size=digest_middle.size,
            )
        else:
            digest_middle = middle
        after = NodeIdentity.from_stat(os.fstat(descriptor))
        path_after = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
    except ExecutableAuthenticationError as error:
        raise ExecutableAuthenticationError(
            f"path-executed target content could not be stabilized: {path}: {error}"
        ) from error
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot revalidate path-executed target component: {path}: {error}"
        ) from error
    identities = (before, path_before, middle, digest_middle, after, path_after)
    object_keys = {identity.object_identity_key() for identity in identities}
    if len(object_keys) != 1:
        raise ExecutableAuthenticationError(
            f"path-executed target component object identity changed: {path}"
        )
    access_policy_keys = {
        _path_execution_access_policy_key(identity, kind=kind)
        for identity in identities
    }
    if len(access_policy_keys) != 1:
        raise ExecutableAuthenticationError(
            f"path-executed target component access policy changed: {path}"
        )
    _require_safe_path_execution_component(
        path=path,
        kind=kind,
        identity=after,
        filesystem_metadata=filesystem_metadata,
        trusted_uid=trusted_uid,
    )
    evidence = PathComponentEvidence(
        path=str(path),
        kind=kind,
        identity=after,
        extended_metadata=filesystem_metadata,
    )
    if kind == "directory":
        return evidence, None
    sizes = {identity.size for identity in identities}
    if (
        len(sizes) != 1
        or first_digest is None
        or second_digest is None
        or first_digest != second_digest
        or first_magic is None
        or second_magic is None
        or first_magic != second_magic
    ):
        raise ExecutableAuthenticationError(
            f"path-executed target content changed during authentication: {path}"
        )
    if second_magic not in _MACHO_MAGICS:
        raise ExecutableAuthenticationError(
            "path-executed target is not a native Mach-O executable"
        )
    return evidence, ExecutableIdentity(
        path=str(path),
        device=after.device,
        inode=after.inode,
        mode=after.mode,
        uid=after.uid,
        gid=after.gid,
        size=after.size,
        mtime_ns=after.mtime_ns,
        ctime_ns=after.ctime_ns,
        sha256=second_digest,
        flags=after.flags,
        generation=after.generation,
    )


def _require_path_execution_attestation_consistent(
    attestation: PathExecutedExecutableAttestation,
) -> None:
    if not isinstance(attestation, PathExecutedExecutableAttestation):
        raise ExecutableAuthenticationError(
            "path-executed target attestation is malformed"
        )
    executable = attestation.executable
    if (
        not isinstance(executable, ExecutableIdentity)
        or not isinstance(attestation.components, tuple)
        or any(
            not isinstance(component, PathComponentEvidence)
            for component in attestation.components
        )
    ):
        raise ExecutableAuthenticationError(
            "path-executed target attestation is malformed"
        )
    path = pathlib.Path(executable.path)
    if not path.is_absolute() or not attestation.components:
        raise ExecutableAuthenticationError(
            "path-executed target attestation is malformed"
        )
    expected_paths: list[str] = ["/"]
    current = pathlib.Path("/")
    for component in path.parts[1:]:
        current /= component
        expected_paths.append(str(current))
    expected_kinds = [
        "file" if index == len(expected_paths) - 1 else "directory"
        for index in range(len(expected_paths))
    ]
    observed_paths = [component.path for component in attestation.components]
    observed_kinds = [component.kind for component in attestation.components]
    if observed_paths != expected_paths or observed_kinds != expected_kinds:
        raise ExecutableAuthenticationError(
            "path-executed target path binding is malformed"
        )
    trusted_uid = os.geteuid()
    for component in attestation.components:
        _require_safe_path_execution_component(
            path=pathlib.Path(component.path),
            kind=component.kind,
            identity=component.identity,
            filesystem_metadata=component.extended_metadata,
            trusted_uid=trusted_uid,
        )
    leaf = attestation.components[-1].identity
    if executable.object_identity_key() != leaf.object_identity_key():
        raise ExecutableAuthenticationError(
            "path-executed target attestation object identity is inconsistent"
        )
    if executable.content_key()[0] != leaf.size:
        raise ExecutableAuthenticationError(
            "path-executed target attestation content length is inconsistent"
        )
    if executable.access_policy_key() != leaf.access_policy_key():
        raise ExecutableAuthenticationError(
            "path-executed target attestation access policy is inconsistent"
        )
    _validate_digest(executable.sha256)


def _authenticate_path_executed_executable(
    path: os.PathLike[str] | str,
) -> PathExecutedExecutableAttestation:
    """Bind a path execution to one object, content digest, and access policy.

    Root and the effective UID are the trusted subjects. Group/world write
    permission, untrusted ownership, extended ACLs, and unsafe hard links are
    rejected before descending through each component, so an untrusted subject
    cannot replace the target in the revalidation-to-exec window.
    """

    if os.geteuid() == 0:
        raise ExecutableAuthenticationError(
            "root execution is outside the no-child-process threat model"
        )
    canonical = _canonical_absolute_path(path)
    if not canonical.parts[1:] or len(canonical.parts) > 128:
        raise ExecutableAuthenticationError(
            "path-executed target component count is outside policy"
        )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    components: list[PathComponentEvidence] = []
    executable: ExecutableIdentity | None = None
    trusted_uid = os.geteuid()
    try:
        descriptors.append(os.open("/", directory_flags))
        root_evidence, _ = _inspect_path_execution_component(
            descriptors[-1],
            path=pathlib.Path("/"),
            kind="directory",
            trusted_uid=trusted_uid,
        )
        components.append(root_evidence)
        current = pathlib.Path("/")
        parts = canonical.parts[1:]
        for index, component in enumerate(parts):
            current /= component
            leaf = index == len(parts) - 1
            flags = file_flags if leaf else directory_flags
            descriptors.append(
                os.open(
                    os.fsencode(component),
                    flags,
                    dir_fd=descriptors[-1],
                )
            )
            evidence, observed_executable = _inspect_path_execution_component(
                descriptors[-1],
                path=current,
                kind="file" if leaf else "directory",
                trusted_uid=trusted_uid,
            )
            components.append(evidence)
            if observed_executable is not None:
                executable = observed_executable
        if executable is None:
            raise ExecutableAuthenticationError(
                "path-executed target did not resolve to an executable"
            )
        for component in components:
            try:
                visible = NodeIdentity.from_stat(
                    os.stat(component.path, follow_symlinks=False)
                )
            except OSError as error:
                raise ExecutableAuthenticationError(
                    "path-executed target path binding became unreadable: "
                    f"{component.path}: {error}"
                ) from error
            if (
                visible.object_identity_key()
                != component.identity.object_identity_key()
            ):
                raise ExecutableAuthenticationError(
                    "path-executed target path object identity changed: "
                    f"{component.path}"
                )
            if _path_execution_access_policy_key(
                visible,
                kind=component.kind,
            ) != _path_execution_access_policy_key(
                component.identity,
                kind=component.kind,
            ):
                raise ExecutableAuthenticationError(
                    f"path-executed target path access policy changed: {component.path}"
                )
            if component.kind == "file" and visible.size != executable.size:
                raise ExecutableAuthenticationError(
                    "path-executed target path content length changed"
                )
        attestation = PathExecutedExecutableAttestation(
            executable=executable,
            components=tuple(components),
        )
        _require_path_execution_attestation_consistent(attestation)
        return attestation
    except ExecutableAuthenticationError:
        raise
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot authenticate path-executed target: {error}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _require_same_path_execution_attestation(
    expected: PathExecutedExecutableAttestation,
    current: PathExecutedExecutableAttestation,
) -> None:
    _require_path_execution_attestation_consistent(expected)
    _require_path_execution_attestation_consistent(current)
    expected_components = expected.components
    current_components = current.components
    if expected.executable.path != current.executable.path or tuple(
        (component.path, component.kind) for component in expected_components
    ) != tuple((component.path, component.kind) for component in current_components):
        raise ExecutableAuthenticationError(
            "path-executed target path binding changed after preparation"
        )
    if expected.executable.object_identity_key() != (
        current.executable.object_identity_key()
    ) or any(
        left.identity.object_identity_key() != right.identity.object_identity_key()
        for left, right in zip(
            expected_components,
            current_components,
            strict=True,
        )
    ):
        raise ExecutableAuthenticationError(
            "path-executed target object identity changed after preparation"
        )
    if expected.executable.content_key() != current.executable.content_key():
        raise ExecutableAuthenticationError(
            "path-executed target content changed after preparation"
        )
    if expected.executable.access_policy_key() != (
        current.executable.access_policy_key()
    ) or any(
        (
            _path_execution_access_policy_key(
                left.identity,
                kind=left.kind,
            ),
            left.extended_metadata,
        )
        != (
            _path_execution_access_policy_key(
                right.identity,
                kind=right.kind,
            ),
            right.extended_metadata,
        )
        for left, right in zip(
            expected_components,
            current_components,
            strict=True,
        )
    ):
        raise ExecutableAuthenticationError(
            "path-executed target access policy changed after preparation"
        )


def _revalidate_path_executed_executable(
    expected: PathExecutedExecutableAttestation,
) -> ExecutableIdentity:
    _require_path_execution_attestation_consistent(expected)
    current = _authenticate_path_executed_executable(expected.executable.path)
    _require_same_path_execution_attestation(expected, current)
    return current.executable


def _authenticate_owner_snapshot_attestation(
    attestation: OwnerSnapshotLaunchAttestation,
) -> ExecutableIdentity:
    if not isinstance(attestation, OwnerSnapshotLaunchAttestation):
        raise ExecutableAuthenticationError(
            "owner snapshot launch attestation is malformed"
        )
    if (
        not isinstance(attestation.snapshot, SnapshotEvidence)
        or not isinstance(
            attestation.revalidation,
            ExecutableRevalidationEvidence,
        )
        or not isinstance(
            attestation.revalidation.operation,
            OperationIdentityEvidence,
        )
        or not isinstance(
            attestation.revalidation.fd_execution,
            FdExecutionEvidence,
        )
        or not isinstance(attestation.snapshot.copy, SnapshotCopyEvidence)
        or not isinstance(attestation.snapshot.directory_identity, NodeIdentity)
        or not isinstance(attestation.snapshot.executable_identity, NodeIdentity)
        or not isinstance(attestation.snapshot.directory_components, tuple)
        or not isinstance(attestation.snapshot.executable_components, tuple)
        or any(
            not isinstance(component, PathComponentEvidence)
            for component in (
                *attestation.snapshot.directory_components,
                *attestation.snapshot.executable_components,
            )
        )
    ):
        raise ExecutableAuthenticationError(
            "owner snapshot launch attestation is malformed"
        )
    _validate_digest(attestation.expected_sha256)
    snapshot = attestation.snapshot
    executable_path = _canonical_absolute_path(snapshot.executable_path)
    directory_path = _canonical_absolute_path(snapshot.directory_path)
    if executable_path.parent != directory_path:
        raise ExecutableAuthenticationError(
            "custodied snapshot is not inside its attested directory"
        )
    try:
        expected_policy = build_snapshot_seatbelt_policy(directory_path)
    except ValueError as error:
        raise ExecutableAuthenticationError(
            f"custodied snapshot Seatbelt policy is invalid: {error}"
        ) from error
    if snapshot.seatbelt_policy != expected_policy:
        raise ExecutableAuthenticationError(
            "custodied snapshot Seatbelt policy changed after authentication"
        )
    if (
        type(attestation.executable_fd) is not int
        or type(attestation.directory_fd) is not int
        or attestation.executable_fd < 0
        or attestation.directory_fd < 0
        or attestation.executable_fd == attestation.directory_fd
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot descriptors are malformed"
        )
    if os.geteuid() == 0:
        raise ExecutableAuthenticationError(
            "root execution is outside the no-child-process threat model"
        )
    try:
        if os.get_inheritable(attestation.executable_fd) or os.get_inheritable(
            attestation.directory_fd
        ):
            raise ExecutableAuthenticationError(
                "custodied snapshot descriptors must be close-on-exec"
            )
        executable_flags = fcntl.fcntl(attestation.executable_fd, fcntl.F_GETFL)
        directory_flags = fcntl.fcntl(attestation.directory_fd, fcntl.F_GETFL)
        if executable_flags & os.O_ACCMODE != os.O_RDONLY:
            raise ExecutableAuthenticationError(
                "custodied snapshot executable descriptor must be read-only"
            )
        if directory_flags & os.O_ACCMODE != os.O_RDONLY:
            raise ExecutableAuthenticationError(
                "custodied snapshot directory descriptor must be read-only"
            )
        directory_before = NodeIdentity.from_stat(os.fstat(attestation.directory_fd))
        executable_before = NodeIdentity.from_stat(os.fstat(attestation.executable_fd))
        directory_path_before = NodeIdentity.from_stat(
            os.stat(directory_path, follow_symlinks=False)
        )
        executable_path_before = NodeIdentity.from_stat(
            os.stat(executable_path, follow_symlinks=False)
        )
        executable_at_before = NodeIdentity.from_stat(
            os.stat(
                os.fsencode(executable_path.name),
                dir_fd=attestation.directory_fd,
                follow_symlinks=False,
            )
        )
        digest, magic = _fd_digest_and_magic(
            attestation.executable_fd,
            size=executable_before.size,
        )
        directory_after = NodeIdentity.from_stat(os.fstat(attestation.directory_fd))
        executable_after = NodeIdentity.from_stat(os.fstat(attestation.executable_fd))
        directory_path_after = NodeIdentity.from_stat(
            os.stat(directory_path, follow_symlinks=False)
        )
        executable_path_after = NodeIdentity.from_stat(
            os.stat(executable_path, follow_symlinks=False)
        )
        executable_at_after = NodeIdentity.from_stat(
            os.stat(
                os.fsencode(executable_path.name),
                dir_fd=attestation.directory_fd,
                follow_symlinks=False,
            )
        )
    except ExecutableAuthenticationError:
        raise
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot revalidate custodied snapshot descriptors: {error}"
        ) from error
    expected_directory = snapshot.directory_identity
    expected_executable = snapshot.executable_identity
    if not (
        directory_before.directory_object_key()
        == directory_after.directory_object_key()
        == expected_directory.directory_object_key()
        and directory_path_before.directory_object_key()
        == directory_path_after.directory_object_key()
        == expected_directory.directory_object_key()
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot directory identity changed"
        )
    current_executable_views = (
        executable_before,
        executable_after,
        executable_path_before,
        executable_path_after,
        executable_at_before,
        executable_at_after,
    )
    if any(identity.link_count != 1 for identity in current_executable_views):
        raise ExecutableAuthenticationError(
            "custodied snapshot executable access policy has an unsafe hard-link count"
        )
    if not (
        executable_before.file_protected_key()
        == executable_after.file_protected_key()
        == expected_executable.file_protected_key()
        and executable_path_before.file_protected_key()
        == executable_path_after.file_protected_key()
        == expected_executable.file_protected_key()
        and executable_at_before.file_protected_key()
        == executable_at_after.file_protected_key()
        == expected_executable.file_protected_key()
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot executable identity changed"
        )
    if (
        not snapshot.directory_components
        or snapshot.directory_components[-1].identity.directory_object_key()
        != expected_directory.directory_object_key()
        or not snapshot.executable_components
        or snapshot.executable_components[-1].identity.file_protected_key()
        != expected_executable.file_protected_key()
        or snapshot.copy.destination_identity.file_protected_key()
        != expected_executable.file_protected_key()
        or snapshot.copy.size != expected_executable.size
        or snapshot.copy.sha256 != attestation.expected_sha256
        or snapshot.copy.max_bytes < snapshot.copy.size
        or not snapshot.copy.source_fd_only
        or not snapshot.copy.file_fsynced
        or not snapshot.copy.directory_fsynced
        or attestation.revalidation.identity.file_protected_key()
        != expected_executable.file_protected_key()
        or attestation.revalidation.sha256 != attestation.expected_sha256
        or attestation.revalidation.operation.before.file_protected_key()
        != expected_executable.file_protected_key()
        or attestation.revalidation.operation.after.file_protected_key()
        != expected_executable.file_protected_key()
        or attestation.revalidation.fd_execution.supported
        or attestation.revalidation.fd_execution.mechanism != "unsupported-on-macos"
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot evidence is internally inconsistent"
        )
    attested_component_keys = tuple(
        (component.identity.device, component.identity.inode)
        for component in snapshot.directory_components
    )
    component_keys_before = _path_component_keys(directory_path)
    component_keys_after = _path_component_keys(directory_path)
    if not (component_keys_before == component_keys_after == attested_component_keys):
        raise ExecutableAuthenticationError(
            "custodied snapshot directory ancestry changed"
        )
    if (
        not stat.S_ISDIR(expected_directory.mode)
        or expected_directory.uid != os.geteuid()
        or stat.S_IMODE(expected_directory.mode) != 0o700
        or not stat.S_ISREG(expected_executable.mode)
        or expected_executable.uid != os.geteuid()
        or stat.S_IMODE(expected_executable.mode) != 0o500
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot is not an owner-only 0700/0500 pair"
        )
    if expected_executable.link_count != 1:
        raise ExecutableAuthenticationError(
            "custodied snapshot attested access policy has an unsafe hard-link count"
        )
    if digest != attestation.expected_sha256:
        raise ExecutableAuthenticationError(
            "custodied snapshot SHA-256 does not match its attestation"
        )
    if magic not in _MACHO_MAGICS:
        raise ExecutableAuthenticationError(
            "custodied snapshot is not a native Mach-O executable"
        )
    return ExecutableIdentity(
        path=str(executable_path),
        device=expected_executable.device,
        inode=expected_executable.inode,
        mode=expected_executable.mode,
        uid=expected_executable.uid,
        gid=expected_executable.gid,
        size=expected_executable.size,
        mtime_ns=expected_executable.mtime_ns,
        ctime_ns=expected_executable.ctime_ns,
        sha256=digest,
        flags=expected_executable.flags,
        generation=expected_executable.generation,
    )


def _revalidate_writable_root(
    attestation: WritableRootAttestation,
) -> WritableRootAttestation:
    if not isinstance(attestation, WritableRootAttestation):
        raise ExecutableAuthenticationError("writable root attestation is malformed")
    if (
        not isinstance(attestation.identity, NodeIdentity)
        or not isinstance(attestation.filesystem_metadata, ExtendedMetadataEvidence)
        or not isinstance(attestation.path_components, tuple)
        or not attestation.path_components
        or any(
            not isinstance(component, PathComponentEvidence)
            for component in attestation.path_components
        )
    ):
        raise ExecutableAuthenticationError("writable root attestation is malformed")
    path = _canonical_absolute_path(attestation.path)
    if type(attestation.directory_fd) is not int or attestation.directory_fd < 0:
        raise ExecutableAuthenticationError("writable root descriptor is malformed")
    if os.geteuid() == 0:
        raise ExecutableAuthenticationError(
            "root execution is outside the no-child-process threat model"
        )
    try:
        if os.get_inheritable(attestation.directory_fd):
            raise ExecutableAuthenticationError(
                "writable root descriptor must be close-on-exec"
            )
        flags = fcntl.fcntl(attestation.directory_fd, fcntl.F_GETFL)
        if flags & os.O_ACCMODE != os.O_RDONLY:
            raise ExecutableAuthenticationError(
                "writable root descriptor must be read-only"
            )
        path_components = _stable_writable_root_path_components(path)
        before = NodeIdentity.from_stat(os.fstat(attestation.directory_fd))
        path_before = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
        filesystem_metadata = verify_macos_filesystem_metadata(
            attestation.directory_fd,
            path,
            "directory",
        )
        after = NodeIdentity.from_stat(os.fstat(attestation.directory_fd))
        path_after = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
    except ExecutableAuthenticationError:
        raise
    except (OSError, ValueError) as error:
        raise ExecutableAuthenticationError(
            f"cannot revalidate writable root: {error}"
        ) from error
    if not (
        before.directory_object_key()
        == after.directory_object_key()
        == path_before.directory_object_key()
        == path_after.directory_object_key()
    ):
        raise ExecutableAuthenticationError("writable root identity changed")
    if (
        before.directory_object_key() != attestation.identity.directory_object_key()
        or filesystem_metadata != attestation.filesystem_metadata
        or _writable_root_component_property_keys(path_components)
        != _writable_root_component_property_keys(attestation.path_components)
    ):
        raise ExecutableAuthenticationError(
            "writable root no longer matches its attestation"
        )
    if (
        not stat.S_ISDIR(before.mode)
        or before.uid != os.geteuid()
        or stat.S_IMODE(before.mode) != 0o700
    ):
        raise ExecutableAuthenticationError(
            "writable root must be owned by the effective user with mode 0700"
        )
    return attestation


def attest_writable_root(
    directory_path: os.PathLike[str] | str,
    *,
    directory_fd: int,
) -> WritableRootAttestation:
    """Authenticate one caller-owned writable root without taking FD ownership.

    ``directory_fd`` must already identify ``directory_path`` as a read-only,
    close-on-exec directory FD. The exact FD must stay open and unchanged through
    ``launch_prepared_no_child_process``. Only current-user mode-0700 directories
    are accepted; raw path strings never grant write authority.
    """

    path = _canonical_absolute_path(directory_path)
    if type(directory_fd) is not int or directory_fd < 0:
        raise ExecutableAuthenticationError("writable root descriptor is malformed")
    try:
        path_components = _stable_writable_root_path_components(path)
        identity = NodeIdentity.from_stat(os.fstat(directory_fd))
        filesystem_metadata = verify_macos_filesystem_metadata(
            directory_fd,
            path,
            "directory",
        )
    except (OSError, ValueError) as error:
        raise ExecutableAuthenticationError(
            f"cannot inspect writable root descriptor: {error}"
        ) from error
    return _revalidate_writable_root(
        WritableRootAttestation(
            path=str(path),
            directory_fd=directory_fd,
            identity=identity,
            filesystem_metadata=filesystem_metadata,
            path_components=path_components,
        )
    )


def _require_safe_writable_root_component(
    component: PathComponentEvidence,
    *,
    leaf: bool,
) -> None:
    identity = component.identity
    metadata = component.extended_metadata
    path = pathlib.Path(component.path)
    trusted_uid = os.geteuid()
    if component.kind != "directory" or not stat.S_ISDIR(identity.mode):
        raise ExecutableAuthenticationError(
            "writable root path contains a non-directory component"
        )
    if not isinstance(metadata, ExtendedMetadataEvidence):
        raise ExecutableAuthenticationError(
            "writable root ancestor access-policy evidence is malformed"
        )
    if path == pathlib.Path("/"):
        if identity.uid != 0:
            raise ExecutableAuthenticationError(
                "writable root filesystem root has an untrusted owner"
            )
    elif identity.uid not in {0, trusted_uid}:
        raise ExecutableAuthenticationError(
            f"writable root ancestor has an untrusted owner: {path}"
        )
    if identity.mode & (stat.S_ISUID | stat.S_ISGID):
        raise ExecutableAuthenticationError(
            f"writable root ancestor has set-id permission: {path}"
        )
    untrusted_write = identity.mode & (stat.S_IWGRP | stat.S_IWOTH)
    sticky_exception = bool(identity.mode & stat.S_ISVTX) and identity.uid in {
        0,
        trusted_uid,
    }
    if untrusted_write and not sticky_exception:
        raise ExecutableAuthenticationError(
            f"writable root ancestor permits an untrusted writer: {path}"
        )
    if leaf and (identity.uid != trusted_uid or stat.S_IMODE(identity.mode) != 0o700):
        raise ExecutableAuthenticationError(
            "writable root must be owned by the effective user with mode 0700"
        )


def _inspect_writable_root_component(
    descriptor: int,
    *,
    path: pathlib.Path,
    leaf: bool,
) -> PathComponentEvidence:
    try:
        before = NodeIdentity.from_stat(os.fstat(descriptor))
        path_before = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
        filesystem_metadata = verify_macos_filesystem_metadata(
            descriptor,
            path,
            "directory",
        )
        after = NodeIdentity.from_stat(os.fstat(descriptor))
        path_after = NodeIdentity.from_stat(os.stat(path, follow_symlinks=False))
    except (OSError, ValueError) as error:
        raise ExecutableAuthenticationError(
            f"cannot inspect writable root ancestor access policy: {path}: {error}"
        ) from error
    identities = (before, path_before, after, path_after)
    if len({identity.directory_object_key() for identity in identities}) != 1:
        raise ExecutableAuthenticationError(
            f"writable root ancestor identity changed: {path}"
        )
    if len({identity.access_policy_key() for identity in identities}) != 1:
        raise ExecutableAuthenticationError(
            f"writable root ancestor access policy changed: {path}"
        )
    evidence = PathComponentEvidence(
        path=str(path),
        kind="directory",
        identity=after,
        extended_metadata=filesystem_metadata,
    )
    _require_safe_writable_root_component(evidence, leaf=leaf)
    return evidence


def _writable_root_component_property_keys(
    components: tuple[PathComponentEvidence, ...],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            component.path,
            component.kind,
            component.identity.object_identity_key(),
            component.identity.access_policy_key(),
            component.extended_metadata,
        )
        for component in components
    )


def _writable_root_path_components_once(
    path: pathlib.Path,
) -> tuple[PathComponentEvidence, ...]:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptors: list[int] = []
    components: list[PathComponentEvidence] = []
    try:
        descriptors.append(os.open("/", directory_flags))
        parts = path.parts[1:]
        components.append(
            _inspect_writable_root_component(
                descriptors[-1],
                path=pathlib.Path("/"),
                leaf=not parts,
            )
        )
        current = pathlib.Path("/")
        for index, component in enumerate(parts):
            current /= component
            descriptors.append(
                os.open(
                    os.fsencode(component),
                    directory_flags,
                    dir_fd=descriptors[-1],
                )
            )
            components.append(
                _inspect_writable_root_component(
                    descriptors[-1],
                    path=current,
                    leaf=index == len(parts) - 1,
                )
            )
        return tuple(components)
    except ExecutableAuthenticationError:
        raise
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot authenticate writable root ancestry: {error}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _stable_writable_root_path_components(
    path: pathlib.Path,
) -> tuple[PathComponentEvidence, ...]:
    first = _writable_root_path_components_once(path)
    second = _writable_root_path_components_once(path)
    if _writable_root_component_property_keys(
        first
    ) != _writable_root_component_property_keys(second):
        raise ExecutableAuthenticationError(
            "writable root ancestry changed during authentication"
        )
    return second


def _path_component_keys(path: pathlib.Path) -> tuple[tuple[int, int], ...]:
    current = pathlib.Path("/")
    try:
        root_metadata = os.stat(current, follow_symlinks=False)
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot inspect writable root path component: {error}"
        ) from error
    keys: list[tuple[int, int]] = [(root_metadata.st_dev, root_metadata.st_ino)]
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError as error:
            raise ExecutableAuthenticationError(
                f"cannot inspect writable root path component: {error}"
            ) from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise ExecutableAuthenticationError(
                "writable root path contains a non-directory component"
            )
        keys.append((metadata.st_dev, metadata.st_ino))
    return tuple(keys)


def _validated_writable_roots(
    roots: Sequence[WritableRootAttestation],
    *,
    snapshot: OwnerSnapshotLaunchAttestation,
) -> tuple[WritableRootAttestation, ...]:
    if isinstance(roots, (str, bytes)) or len(roots) > MAX_WRITABLE_ROOTS:
        raise ExecutableAuthenticationError(
            "writable root attestations exceed their bound"
        )
    validated = tuple(_revalidate_writable_root(root) for root in roots)
    snapshot_component_keys = {
        (component.identity.device, component.identity.inode)
        for component in snapshot.snapshot.directory_components
    }
    snapshot_directory_key = (
        snapshot.snapshot.directory_identity.device,
        snapshot.snapshot.directory_identity.inode,
    )
    root_components: list[tuple[tuple[int, int], ...]] = []
    root_keys: list[tuple[int, int]] = []
    for root in validated:
        first_components = tuple(
            (component.identity.device, component.identity.inode)
            for component in root.path_components
        )
        root_key = (root.identity.device, root.identity.inode)
        if (
            root_key in snapshot_component_keys
            or snapshot_directory_key in first_components
        ):
            raise ExecutableAuthenticationError(
                "writable root overlaps the protected snapshot through a path alias"
            )
        root_components.append(first_components)
        root_keys.append(root_key)
    if len(set(root_keys)) != len(root_keys):
        raise ExecutableAuthenticationError("writable root attestations are duplicated")
    for index, root_key in enumerate(root_keys):
        for other_index, components in enumerate(root_components):
            if index != other_index and root_key in components:
                raise ExecutableAuthenticationError(
                    "writable root attestations overlap"
                )
    return validated


def _validated_sandboxed_writable_roots(
    roots: Sequence[WritableRootAttestation],
    *,
    protected_component_keys: frozenset[tuple[int, int]],
) -> tuple[WritableRootAttestation, ...]:
    if isinstance(roots, (str, bytes)) or len(roots) > MAX_WRITABLE_ROOTS:
        raise ExecutableAuthenticationError(
            "writable root attestations exceed their bound"
        )
    if not protected_component_keys:
        raise ExecutableAuthenticationError(
            "sandboxed target has no protected component identity"
        )
    validated = tuple(_revalidate_writable_root(root) for root in roots)
    root_components: list[tuple[tuple[int, int], ...]] = []
    root_keys: list[tuple[int, int]] = []
    root_paths: set[str] = set()
    for root in validated:
        first_components = tuple(
            (component.identity.device, component.identity.inode)
            for component in root.path_components
        )
        root_key = (root.identity.device, root.identity.inode)
        if first_components[-1] != root_key:
            raise ExecutableAuthenticationError(
                "writable root path does not identify its attested object"
            )
        if root_key in protected_component_keys:
            raise ExecutableAuthenticationError(
                "writable root overlaps the sandboxed target through a path alias"
            )
        if root.path in root_paths or root_key in root_keys:
            raise ExecutableAuthenticationError(
                "writable root attestations are duplicated"
            )
        root_paths.add(root.path)
        root_components.append(first_components)
        root_keys.append(root_key)
    for index, root_key in enumerate(root_keys):
        for other_index, components in enumerate(root_components):
            if index != other_index and root_key in components:
                raise ExecutableAuthenticationError(
                    "writable root attestations overlap"
                )
    return validated


def _require_protected_path(
    attestation: PathExecutedExecutableAttestation,
) -> None:
    """Require the singleton safe ACL state for a root-protected path.

    ACL evidence is intentionally not copied into ``ExecutableIdentity``:
    every authentication and revalidation rejects every ACL before the
    identity is eligible, so the accepted ACL policy has only one state.
    """

    if os.geteuid() == 0:
        raise ExecutableAuthenticationError(
            "root execution is outside the no-child-process threat model"
        )
    _require_path_execution_attestation_consistent(attestation)
    for component in attestation.components:
        metadata = component.extended_metadata
        if (
            component.identity.uid != 0
            or component.identity.mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not isinstance(metadata, ExtendedMetadataEvidence)
            or metadata.acl_entry_count != 0
            or metadata.acl_entries
        ):
            raise ExecutableAuthenticationError(
                "executable path component is not root-owned and immutable "
                f"or has an extended ACL: {component.path}"
            )


def _authenticate_root_protected_executable(
    path: os.PathLike[str] | str,
) -> PathExecutedExecutableAttestation:
    attestation = _authenticate_path_executed_executable(path)
    _require_protected_path(attestation)
    return attestation


def authenticate_executable(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
) -> ExecutableIdentity:
    _validate_digest(expected_sha256)
    attestation = _authenticate_root_protected_executable(path)
    identity = attestation.executable
    if identity.sha256 != expected_sha256:
        raise ExecutableAuthenticationError("executable SHA-256 does not match the pin")
    return identity


def _executable_protected_key(identity: ExecutableIdentity) -> tuple[object, ...]:
    return (
        identity.path,
        identity.object_identity_key(),
        identity.content_key(),
        identity.access_policy_key(),
    )


def _optional_executable_protected_key(
    identity: ExecutableIdentity | None,
) -> tuple[object, ...] | None:
    return None if identity is None else _executable_protected_key(identity)


def _sbpl_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True, slots=True)
class _SbplStringLiteral:
    value: str


_SBPL_ATOM_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_*+./:=<>!?$%@"
)
_MAX_SBPL_NESTING_DEPTH = 32


def _skip_sbpl_horizontal_space(value: str, offset: int) -> int:
    while offset < len(value) and value[offset] in {" ", "\t"}:
        offset += 1
    return offset


def _parse_sbpl_string(
    value: str,
    offset: int,
) -> tuple[_SbplStringLiteral, int]:
    decoded: list[str] = []
    offset += 1
    while offset < len(value):
        character = value[offset]
        if character == '"':
            return _SbplStringLiteral("".join(decoded)), offset + 1
        if character == "\\":
            offset += 1
            if offset >= len(value) or value[offset] not in {'"', "\\"}:
                raise NoChildProfileError(
                    "additional Seatbelt rules contain an invalid string escape"
                )
            character = value[offset]
        if ord(character) < 32 or ord(character) == 127:
            raise NoChildProfileError(
                "additional Seatbelt rules contain a control character"
            )
        decoded.append(character)
        offset += 1
    raise NoChildProfileError("additional Seatbelt rules contain an open string")


def _parse_sbpl_expression(
    value: str,
    offset: int,
    *,
    depth: int = 0,
) -> tuple[tuple[object, ...], int]:
    if depth > _MAX_SBPL_NESTING_DEPTH:
        raise NoChildProfileError(
            "additional Seatbelt rules exceed the expression nesting bound"
        )
    if offset >= len(value) or value[offset] != "(":
        raise NoChildProfileError(
            "additional Seatbelt rules must contain complete expressions"
        )
    offset += 1
    items: list[object] = []
    while True:
        offset = _skip_sbpl_horizontal_space(value, offset)
        if offset >= len(value):
            raise NoChildProfileError(
                "additional Seatbelt rules contain an open expression"
            )
        character = value[offset]
        if character == ")":
            if not items:
                raise NoChildProfileError(
                    "additional Seatbelt rules contain an empty expression"
                )
            return tuple(items), offset + 1
        if character == "(":
            item, offset = _parse_sbpl_expression(
                value,
                offset,
                depth=depth + 1,
            )
            items.append(item)
            continue
        if character == '"':
            item, offset = _parse_sbpl_string(value, offset)
            items.append(item)
            continue
        atom_start = offset
        while offset < len(value) and value[offset] not in {
            " ",
            "\t",
            "(",
            ")",
        }:
            if value[offset] not in _SBPL_ATOM_CHARACTERS:
                raise NoChildProfileError(
                    "additional Seatbelt rules contain forbidden syntax"
                )
            offset += 1
        if atom_start == offset:
            raise NoChildProfileError("additional Seatbelt rules are malformed")
        items.append(value[atom_start:offset])


def _expression_contains_allow(expression: tuple[object, ...]) -> bool:
    for item in expression:
        if isinstance(item, str) and item.casefold() == "allow":
            return True
        if isinstance(item, tuple) and _expression_contains_allow(item):
            return True
    return False


def _expression_has_valid_heads(expression: tuple[object, ...]) -> bool:
    if not expression or not isinstance(expression[0], str):
        return False
    return all(
        not isinstance(item, tuple) or _expression_has_valid_heads(item)
        for item in expression[1:]
    )


def _validate_sbpl_deny_line(line: str) -> None:
    expression, offset = _parse_sbpl_expression(line, 0)
    offset = _skip_sbpl_horizontal_space(line, offset)
    if offset != len(line):
        raise NoChildProfileError(
            "additional Seatbelt rules must contain one expression per line"
        )
    if (
        len(expression) < 2
        or expression[0] != "deny"
        or not isinstance(expression[1], str)
        or not _expression_has_valid_heads(expression)
        or _expression_contains_allow(expression)
    ):
        raise NoChildProfileError("additional Seatbelt rules must be deny-only")


def _validate_additional_seatbelt_rules(value: str) -> str:
    if not isinstance(value, str):
        raise NoChildProfileError("additional Seatbelt rules are malformed")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError:
        raise NoChildProfileError("additional Seatbelt rules are malformed") from None
    if len(encoded) > 8192 or any(
        character not in {"\n", "\t"} and (ord(character) < 32 or ord(character) == 127)
        for character in value
    ):
        raise NoChildProfileError("additional Seatbelt rules are malformed")
    for line in value.splitlines():
        if line:
            _validate_sbpl_deny_line(line)
    return value.rstrip("\n")


def _render_seatbelt_profile(
    executable_paths: Sequence[pathlib.Path],
    *,
    additional_rules: str = "",
    writable_root_paths: Sequence[pathlib.Path] = (),
) -> str:
    if not executable_paths:
        raise NoChildProfileError("Seatbelt profile has no executable target")
    canonical_executables = tuple(
        _canonical_absolute_path(path) for path in executable_paths
    )
    if len(set(canonical_executables)) != len(canonical_executables):
        raise NoChildProfileError("Seatbelt executable targets are duplicated")
    lines = [
        f"(version {SEATBELT_PROFILE_VERSION})",
        "(allow default)",
        "(deny process-fork)",
        "(deny process-exec*)",
    ]
    lines.extend(
        f"(allow process-exec (literal {_sbpl_string(str(path))}))"
        for path in canonical_executables
    )
    extra = _validate_additional_seatbelt_rules(additional_rules)
    if extra:
        lines.extend(extra.splitlines())
    if writable_root_paths:
        # file-link is independent from file-write*. Without this denial a child
        # can hard-link protected content into an allowed writable root.
        lines.append("(deny file-link)")
    lines.extend(
        f"(allow file-write* (subpath {_sbpl_string(str(path))}))"
        for path in writable_root_paths
    )
    lines.append("")
    rendered = "\n".join(lines)
    if len(rendered.encode("ascii", "strict")) > MAX_SEATBELT_PROFILE_BYTES:
        raise NoChildProfileError("Seatbelt profile exceeds its byte bound")
    return rendered


def build_seatbelt_profile(
    executable_path: os.PathLike[str] | str,
    *,
    additional_rules: str = "",
) -> str:
    return _render_seatbelt_profile(
        (_canonical_absolute_path(executable_path),),
        additional_rules=additional_rules,
    )


def _build_custodied_snapshot_seatbelt_profile(
    snapshot: OwnerSnapshotLaunchAttestation,
    writable_roots: Sequence[WritableRootAttestation],
) -> tuple[ExecutableIdentity, tuple[WritableRootAttestation, ...], str]:
    executable = _authenticate_owner_snapshot_attestation(snapshot)
    validated_roots = _validated_writable_roots(
        writable_roots,
        snapshot=snapshot,
    )
    policy_rules = snapshot.snapshot.seatbelt_policy.rules
    if "(deny file-write*)" not in policy_rules.splitlines():
        raise NoChildProfileError(
            "custodied snapshot policy lacks default-deny filesystem writes"
        )
    profile = _render_seatbelt_profile(
        (pathlib.Path(executable.path), SANDBOX_EXEC),
        additional_rules=policy_rules,
        writable_root_paths=tuple(pathlib.Path(root.path) for root in validated_roots),
    )
    return executable, validated_roots, profile


def _set_zero_nproc_limit() -> None:
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    if resource.getrlimit(resource.RLIMIT_NPROC) != (0, 0):
        raise OSError(errno.EPERM, "RLIMIT_NPROC did not become hard zero")


def _establish_preexec_state(
    *,
    status_write_fd: int,
    set_nproc_zero: bool,
) -> None:
    try:
        pid = os.getpid()
        if pid == os.getpgrp():
            raise OSError(
                errno.EPERM,
                "forked child unexpectedly started as a process-group leader",
            )
        os.setsid()
        process_group = os.getpgrp()
        session_id = os.getsid(0)
        if process_group != pid or session_id != pid:
            raise OSError(
                errno.EPERM,
                "setsid did not establish the child leader invariant",
            )
        if set_nproc_zero:
            _set_zero_nproc_limit()
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        payload = {
            "ok": True,
            "setsid_succeeded": True,
            "pid": pid,
            "process_group": process_group,
            "session_id": session_id,
            "nproc_soft": soft,
            "nproc_hard": hard,
            "error_number": None,
            "detail": "",
        }
    except BaseException as error:
        payload = {
            "ok": False,
            "setsid_succeeded": False,
            "pid": os.getpid(),
            "process_group": os.getpgrp(),
            "session_id": os.getsid(0),
            "nproc_soft": resource.getrlimit(resource.RLIMIT_NPROC)[0],
            "nproc_hard": resource.getrlimit(resource.RLIMIT_NPROC)[1],
            "error_number": getattr(error, "errno", None),
            "detail": _bounded_text(str(error), limit=256),
        }
        try:
            os.write(
                status_write_fd,
                json.dumps(payload, sort_keys=True).encode("utf-8"),
            )
            os.close(status_write_fd)
        except BaseException:
            pass
        raise
    os.write(
        status_write_fd,
        json.dumps(payload, sort_keys=True).encode("utf-8"),
    )
    os.close(status_write_fd)


def _read_bounded_pipe(fd: int, *, deadline: float) -> bytes:
    payload = bytearray()
    os.set_blocking(fd, False)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded pipe deadline expired")
        readable, _, _ = select.select([fd], [], [], min(remaining, 0.1))
        if not readable:
            continue
        chunk = os.read(fd, 4096 - len(payload))
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) >= 4096:
            raise ValueError("bounded pipe record is oversized")


def _parse_preexec_state(payload: bytes) -> dict[str, Any]:
    try:
        state = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"pre-exec state is not valid JSON: {error}") from error
    expected_keys = {
        "ok",
        "setsid_succeeded",
        "pid",
        "process_group",
        "session_id",
        "nproc_soft",
        "nproc_hard",
        "error_number",
        "detail",
    }
    if not isinstance(state, dict) or set(state) != expected_keys:
        raise ValueError("pre-exec state schema is invalid")
    integer_keys = (
        "pid",
        "process_group",
        "session_id",
        "nproc_soft",
        "nproc_hard",
    )
    if any(type(state[key]) is not int for key in integer_keys):
        raise ValueError("pre-exec state contains a non-integer kernel value")
    if type(state["ok"]) is not bool or type(state["setsid_succeeded"]) is not bool:
        raise ValueError("pre-exec state booleans are invalid")
    if state["error_number"] is not None and type(state["error_number"]) is not int:
        raise ValueError("pre-exec state errno is invalid")
    if not isinstance(state["detail"], str) or len(state["detail"]) > 256:
        raise ValueError("pre-exec state detail is invalid")
    return state


def _parse_probe_output(
    *,
    layer: str,
    action: str,
    completed: subprocess.CompletedProcess[bytes],
) -> ProbeObservation:
    output = completed.stdout.strip()
    if (
        not output
        and completed.returncode == 71
        and completed.stderr.strip()
        == b"sandbox-exec: sandbox_apply: Operation not permitted"
    ):
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail=PROBE_DETAIL_OUTER_SEATBELT_DENIED,
        )
    if (
        not output
        and not completed.stderr.strip()
        and completed.returncode == -signal.SIGKILL
    ):
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail=PROBE_DETAIL_KILLED_BEFORE_EVIDENCE,
        )
    if not output:
        if action == "exec" and completed.returncode == 0:
            return ProbeObservation(
                layer=layer,
                action=action,
                outcome="allowed",
                detail="alternate executable replaced the probe process",
            )
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail=(
                f"probe exited {completed.returncode} without evidence; "
                f"stderr={_bounded_text(completed.stderr)!r}"
            ),
        )
    if len(output) > 4096 or b"\n" in output:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe output is oversized or contains multiple records",
        )
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail=f"probe output is not canonical JSON: {error}",
        )
    expected_keys = {
        "action",
        "outcome",
        "error_number",
        "detail",
        "child_pid",
        "child_process_group",
        "child_session",
        "nproc_soft",
        "nproc_hard",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe JSON schema is invalid",
        )
    if payload["action"] != action or payload["outcome"] not in {
        "observed",
        "denied",
        "allowed",
        "ambiguous",
    }:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe JSON action or outcome is invalid",
        )
    integer_keys = (
        "child_pid",
        "child_process_group",
        "child_session",
        "nproc_soft",
        "nproc_hard",
    )
    if any(type(payload[key]) is not int for key in integer_keys):
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe JSON contains a non-integer kernel value",
        )
    error_number = payload["error_number"]
    if error_number is not None and type(error_number) is not int:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe JSON errno is invalid",
        )
    if not isinstance(payload["detail"], str) or len(payload["detail"]) > 256:
        return ProbeObservation(
            layer=layer,
            action=action,
            outcome="ambiguous",
            detail="probe JSON detail is invalid",
        )
    return ProbeObservation(
        layer=layer,
        action=action,
        outcome=payload["outcome"],
        error_number=error_number,
        detail=payload["detail"],
        child_pid=payload["child_pid"],
        child_process_group=payload["child_process_group"],
        child_session=payload["child_session"],
        nproc_soft=payload["nproc_soft"],
        nproc_hard=payload["nproc_hard"],
    )


def _leader_binding_error_detail(error: OSError | ValueError) -> str:
    if isinstance(error, OSError) and error.errno == errno.ESRCH:
        return PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
    return _bounded_text(f"cannot bind live leader identity: {error}")


def _open_probe_control_pipes() -> tuple[int, int, int, int]:
    descriptors: list[int] = []
    try:
        release_read, release_write = os.pipe()
        descriptors.extend((release_read, release_write))
        status_read, status_write = os.pipe()
        descriptors.extend((status_read, status_write))
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        return release_read, release_write, status_read, status_write
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _probe_worker_environment(*, python_home: str) -> dict[str, str]:
    return {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHOME": python_home,
        "PYTHONNOUSERSITE": "1",
    }


@dataclass
class _ProbePopenOwner:
    process: subprocess.Popen[bytes] | None = None
    popen_call_started: bool = False
    popen_call_completed: bool = False
    ownership_published: bool = False
    popen_failure: BaseException | None = None


@dataclass(slots=True)
class _ProbeControlDescriptorOwner:
    descriptors: set[int]
    descriptor_roles: dict[int, str]
    close_outcomes: dict[int, str]
    close_errors: dict[int, BaseException]

    @classmethod
    def from_role_pairs(
        cls,
        role_pairs: Sequence[tuple[str, int]],
    ) -> _ProbeControlDescriptorOwner:
        descriptors: set[int] = set()
        descriptor_roles: dict[int, str] = {}
        for role, descriptor in role_pairs:
            if not role or type(descriptor) is not int or descriptor < 0:
                raise ValueError("probe control descriptor custody is malformed")
            if descriptor in descriptors:
                raise ValueError("probe control descriptor custody contains duplicates")
            descriptors.add(descriptor)
            descriptor_roles[descriptor] = role
        return cls(
            descriptors=descriptors,
            descriptor_roles=descriptor_roles,
            close_outcomes={descriptor: "owned" for descriptor in descriptors},
            close_errors={},
        )

    @property
    def control_pipes_closed(self) -> bool:
        return not self.descriptors and all(
            outcome in {"closed", "missing"} for outcome in self.close_outcomes.values()
        )

    def close_evidence(self) -> tuple[ProbeControlDescriptorCloseEvidence, ...]:
        return tuple(
            ProbeControlDescriptorCloseEvidence(
                role=self.descriptor_roles[descriptor],
                descriptor=descriptor,
                outcome=self.close_outcomes[descriptor],
            )
            for descriptor in sorted(self.descriptor_roles)
        )

    def close_descriptor(
        self,
        descriptor: int,
        failures: list[str] | None = None,
    ) -> bool:
        if descriptor not in self.descriptor_roles:
            detail = f"close-fd-{descriptor}:descriptor-not-owned"
            if failures is None:
                raise ChildProcessError(detail)
            failures.append(detail)
            return False
        outcome = self.close_outcomes[descriptor]
        if outcome in {"closed", "missing"}:
            self.descriptors.discard(descriptor)
            return True
        if outcome == "close-outcome-unproven":
            if failures is not None:
                failures.append(f"close-fd-{descriptor}:close-outcome-unproven")
            return False
        if outcome != "owned" or descriptor not in self.descriptors:
            detail = f"close-fd-{descriptor}:invalid-close-state:{outcome}"
            if failures is None:
                raise ChildProcessError(detail)
            failures.append(detail)
            return False

        # Publish uncertainty before close. If an exception is delivered after
        # the syscall returned, this integer may already name a reused FD.
        self.close_outcomes[descriptor] = "close-outcome-unproven"
        try:
            os.close(descriptor)
        except BaseException as error:
            self.close_errors[descriptor] = error
            if failures is None:
                try:
                    setattr(error, "no_child_probe_control_descriptor_owner", self)
                except BaseException:
                    pass
                raise
            failures.append(
                f"close-fd-{descriptor}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            return False
        self.close_outcomes[descriptor] = "closed"
        self.close_errors.pop(descriptor, None)
        self.descriptors.discard(descriptor)
        return True

    def close_all(self, failures: list[str]) -> bool:
        for descriptor in tuple(self.descriptors):
            self.close_descriptor(descriptor, failures)
        return self.control_pipes_closed

    def close_descriptors_for_recovery(self) -> None:
        failures: list[str] = []
        if not self.close_all(failures):
            raise ChildProcessError(
                "probe control descriptor closure remains unproven: "
                + ";".join(failures)
            )


class _OwnedProbePopen(subprocess.Popen):
    """Publish cleanup ownership before Popen can create a child."""

    def __init__(
        self,
        owner: _ProbePopenOwner,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        owner.process = self
        owner.ownership_published = True
        owner.popen_call_started = True
        try:
            super().__init__(*args, **kwargs)
        except (OSError, subprocess.SubprocessError) as error:
            owner.popen_failure = error
            raise
        owner.popen_call_completed = True


def _spawn_owned_probe_process(
    owner: _ProbePopenOwner,
    *args: Any,
    **kwargs: Any,
) -> subprocess.Popen[bytes]:
    return _OwnedProbePopen(owner, *args, **kwargs)


def _close_probe_control_descriptors(
    owner: _ProbeControlDescriptorOwner,
    failures: list[str],
) -> bool:
    return owner.close_all(failures)


def _close_probe_output_pipes(
    process: subprocess.Popen[bytes],
    failures: list[str],
) -> bool:
    closed = True
    for label in ("stdout", "stderr"):
        try:
            stream = getattr(process, label, None)
        except BaseException as error:
            failures.append(
                f"inspect-{label}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            closed = False
            continue
        if stream is None:
            continue
        try:
            stream.close()
        except BaseException as error:
            failures.append(
                f"close-{label}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            closed = False
            continue
        try:
            if not stream.closed:
                failures.append(f"close-{label}:stream-remained-open")
                closed = False
        except BaseException as error:
            failures.append(
                f"inspect-{label}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            closed = False
    return closed


def _probe_process_group_empty(
    process_group: int,
    *,
    failures: list[str],
) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return True
    except BaseException as error:
        failures.append(
            f"inspect-process-group:{type(error).__name__}:"
            f"{_bounded_text(str(error), limit=128)}"
        )
        return False
    failures.append("inspect-process-group:group-remained-live")
    return False


def _cleanup_probe_after_popen(
    process: subprocess.Popen[bytes],
    *,
    control_descriptors: _ProbeControlDescriptorOwner,
    worker_release_attempted: bool,
    worker_released: bool,
    communicate_completed: bool,
    leader_binding_complete: bool,
    process_group_bound: bool,
    trigger: BaseException,
) -> NoChildProbeClosureEvidence:
    failures = [
        f"trigger:{type(trigger).__name__}:{_bounded_text(str(trigger), limit=128)}"
    ]
    completed_before_cleanup = False
    try:
        completed_before_cleanup = process.poll() is not None
    except BaseException as error:
        failures.append(
            f"poll-leader:{type(error).__name__}:{_bounded_text(str(error), limit=128)}"
        )
    if not communicate_completed:
        try:
            if process_group_bound:
                os.killpg(process.pid, signal.SIGKILL)
            elif not completed_before_cleanup:
                os.kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            failures.append(
                f"terminate-worker:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
    if not completed_before_cleanup:
        try:
            process.wait(timeout=PROBE_TIMEOUT_SECONDS)
        except BaseException as error:
            failures.append(
                f"reap-leader:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
    leader_reaped = process.returncode is not None
    if communicate_completed:
        process_group_empty = leader_reaped
    elif leader_reaped and process_group_bound:
        process_group_empty = _probe_process_group_empty(
            process.pid,
            failures=failures,
        )
    elif leader_reaped and not worker_release_attempted:
        process_group_empty = True
    else:
        process_group_empty = False
        failures.append("process-group-closure-unproven")
    control_pipes_closed = _close_probe_control_descriptors(
        control_descriptors,
        failures,
    )
    output_pipes_closed = _close_probe_output_pipes(process, failures)
    return NoChildProbeClosureEvidence(
        leader_pid=process.pid,
        worker_release_attempted=worker_release_attempted,
        worker_released=worker_released,
        communicate_completed=communicate_completed,
        leader_binding_complete=leader_binding_complete,
        process_group_bound=process_group_bound,
        leader_reaped=leader_reaped,
        process_group_empty=process_group_empty,
        control_pipes_closed=control_pipes_closed,
        output_pipes_closed=output_pipes_closed,
        control_descriptor_close_evidence=control_descriptors.close_evidence(),
        reason=";".join(failures)[:1024],
    )


def _raise_for_unproven_probe_closure(
    evidence: NoChildProbeClosureEvidence,
    *,
    process: subprocess.Popen[bytes],
    control_descriptors: _ProbeControlDescriptorOwner,
    cause: BaseException,
) -> None:
    if (
        evidence.leader_reaped
        and evidence.process_group_empty
        and evidence.control_pipes_closed
        and evidence.output_pipes_closed
    ):
        return
    retained = NoChildProbeClosureUnproven(evidence=evidence)
    retained.retain_resource(process)
    retained.retain_resource(control_descriptors)
    if not evidence.output_pipes_closed:
        for label in ("stdout", "stderr"):
            try:
                stream = getattr(process, label, None)
            except BaseException:
                continue
            if stream is not None:
                retained.retain_resource(stream)
    retained.retain_recovery_evidence(evidence)
    raise retained from cause


def _probe_owner_leader_pid(owner: _ProbePopenOwner) -> int | None:
    process = owner.process
    if process is None:
        return None
    try:
        pid = process.pid
    except BaseException:
        return None
    if type(pid) is not int or pid <= 0:
        return None
    return pid


def _raise_probe_spawn_ownership_unproven(
    owner: _ProbePopenOwner,
    *,
    control_descriptors: _ProbeControlDescriptorOwner,
    cause: BaseException,
    detail: str,
) -> None:
    failures = [
        f"trigger:{type(cause).__name__}:{_bounded_text(str(cause), limit=128)}",
        detail,
    ]
    control_pipes_closed = _close_probe_control_descriptors(
        control_descriptors,
        failures,
    )
    process = owner.process
    output_pipes_closed = (
        True if process is None else _close_probe_output_pipes(process, failures)
    )
    evidence = NoChildProbeSpawnOwnershipEvidence(
        popen_call_started=owner.popen_call_started,
        popen_call_completed=owner.popen_call_completed,
        ownership_published=owner.ownership_published,
        leader_pid=_probe_owner_leader_pid(owner),
        control_pipes_closed=control_pipes_closed,
        output_pipes_closed=output_pipes_closed,
        control_descriptor_close_evidence=control_descriptors.close_evidence(),
        reason=";".join(failures)[:1024],
    )
    retained = NoChildProbeSpawnOwnershipUnproven(evidence=evidence)
    retained.retain_resource(owner)
    retained.retain_resource(control_descriptors)
    if process is not None:
        retained.retain_resource(process)
        if not output_pipes_closed:
            for label in ("stdout", "stderr"):
                try:
                    stream = getattr(process, label, None)
                except BaseException:
                    continue
                if stream is not None:
                    retained.retain_resource(stream)
    retained.retain_recovery_evidence(evidence)
    raise retained from cause


def _settle_owned_probe_after_base_exception(
    owner: _ProbePopenOwner,
    *,
    process: subprocess.Popen[bytes] | None,
    control_descriptors: _ProbeControlDescriptorOwner,
    worker_release_attempted: bool,
    worker_released: bool,
    communicate_completed: bool,
    leader_binding_complete: bool,
    process_group_bound: bool,
    cause: BaseException,
) -> None:
    candidate = process if process is not None else owner.process
    if candidate is not None and _probe_owner_leader_pid(owner) is not None:
        closure = _cleanup_probe_after_popen(
            candidate,
            control_descriptors=control_descriptors,
            worker_release_attempted=worker_release_attempted,
            worker_released=worker_released,
            communicate_completed=communicate_completed,
            leader_binding_complete=leader_binding_complete,
            process_group_bound=process_group_bound,
            trigger=cause,
        )
        _raise_for_unproven_probe_closure(
            closure,
            process=candidate,
            control_descriptors=control_descriptors,
            cause=cause,
        )
        return
    if owner.popen_call_started:
        _raise_probe_spawn_ownership_unproven(
            owner,
            control_descriptors=control_descriptors,
            cause=cause,
            detail="popen-call-started-without-a-cleanup-capable-leader",
        )
    failures: list[str] = []
    controls_closed = _close_probe_control_descriptors(
        control_descriptors,
        failures,
    )
    outputs_closed = (
        True if candidate is None else _close_probe_output_pipes(candidate, failures)
    )
    if not controls_closed or not outputs_closed:
        _raise_probe_spawn_ownership_unproven(
            owner,
            control_descriptors=control_descriptors,
            cause=cause,
            detail="pre-spawn-resources-could-not-be-closed",
        )


def _run_probe_case(
    *,
    layer: str,
    action: str,
    probe_executable_attestation: PathExecutedExecutableAttestation,
    alternate_executable: ExecutableIdentity,
    profile: str,
    python_home: str,
) -> ProbeObservation:
    probe_executable = probe_executable_attestation.executable
    current_probe = _revalidate_path_executed_executable(probe_executable_attestation)
    if _executable_protected_key(current_probe) != _executable_protected_key(
        probe_executable
    ):
        raise ExecutableAuthenticationError(
            "compatibility probe Python changed before launch"
        )
    current_alternate = _read_executable_identity(alternate_executable.path)
    if _executable_protected_key(current_alternate) != _executable_protected_key(
        alternate_executable
    ):
        raise ExecutableAuthenticationError(
            "compatibility probe alternate executable changed before launch"
        )
    release_read, release_write, status_read, status_write = _open_probe_control_pipes()
    control_descriptors = _ProbeControlDescriptorOwner.from_role_pairs(
        (
            ("release-read", release_read),
            ("release-write", release_write),
            ("status-read", status_read),
            ("status-write", status_write),
        )
    )

    def close_control(descriptor: int) -> None:
        if not control_descriptors.close_descriptor(descriptor):
            raise ChildProcessError(
                f"probe control descriptor {descriptor} closure remains unproven"
            )

    worker_argv = [
        probe_executable.path,
        "-I",
        "-B",
        "-S",
        "-c",
        _PROBE_WORKER,
        action,
        alternate_executable.path,
        str(release_read),
    ]
    argv = worker_argv
    if layer in {"seatbelt", "combined"}:
        argv = [str(SANDBOX_EXEC), "-p", profile, *worker_argv]
    environment = _probe_worker_environment(python_home=python_home)
    profile_sha256 = (
        hashlib.sha256(profile.encode("utf-8")).hexdigest()
        if layer in {"seatbelt", "combined"}
        else None
    )
    preexec_fn = functools.partial(
        _establish_preexec_state,
        status_write_fd=status_write,
        set_nproc_zero=layer in {"rlimit", "combined"},
    )
    worker_release_attempted = False
    worker_released = False
    communicate_completed = False
    leader_binding_complete = False
    process_group_bound = False
    child_process_group: int | None = None
    child_session: int | None = None
    child_start_identity: str | None = None
    state: dict[str, Any] | None = None
    process: subprocess.Popen[bytes] | None = None
    popen_owner = _ProbePopenOwner()
    try:
        current_probe = _revalidate_path_executed_executable(
            probe_executable_attestation
        )
        if _executable_protected_key(current_probe) != _executable_protected_key(
            probe_executable
        ):
            raise ExecutableAuthenticationError(
                "compatibility probe Python changed immediately before exec"
            )
        process = _spawn_owned_probe_process(
            popen_owner,
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd="/",
            close_fds=True,
            pass_fds=(release_read, status_write),
            preexec_fn=preexec_fn,
        )
    except (OSError, subprocess.SubprocessError) as error:
        try:
            close_control(release_read)
            close_control(release_write)
            close_control(status_write)
            try:
                state_payload = _read_bounded_pipe(
                    status_read,
                    deadline=time.monotonic() + 0.5,
                )
                state = _parse_preexec_state(state_payload) if state_payload else None
            except (OSError, TimeoutError, ValueError):
                state = None
            detail = "pre-exec leader setup failed"
            if state is not None and state["detail"]:
                detail += f": {state['detail']}"
            return ProbeObservation(
                layer=layer,
                action=action,
                outcome="ambiguous",
                error_number=(
                    state["error_number"]
                    if state is not None
                    else getattr(error, "errno", None)
                ),
                detail=_bounded_text(detail),
                pre_exec_setsid_succeeded=(
                    state["setsid_succeeded"] if state is not None else False
                ),
                pre_exec_pid=state["pid"] if state is not None else None,
                pre_exec_process_group=(
                    state["process_group"] if state is not None else None
                ),
                pre_exec_session=(state["session_id"] if state is not None else None),
                pre_exec_nproc_soft=(
                    state["nproc_soft"] if state is not None else None
                ),
                pre_exec_nproc_hard=(
                    state["nproc_hard"] if state is not None else None
                ),
                nproc_soft=state["nproc_soft"] if state is not None else None,
                nproc_hard=state["nproc_hard"] if state is not None else None,
                profile_sha256=profile_sha256,
            )
        finally:
            failures: list[str] = []
            controls_closed = _close_probe_control_descriptors(
                control_descriptors,
                failures,
            )
            outputs_closed = (
                True
                if popen_owner.process is None
                else _close_probe_output_pipes(popen_owner.process, failures)
            )
            if not controls_closed or not outputs_closed:
                _raise_probe_spawn_ownership_unproven(
                    popen_owner,
                    control_descriptors=control_descriptors,
                    cause=error,
                    detail=(
                        "popen-error-path-resources-could-not-be-closed:"
                        + ";".join(failures)
                    ),
                )
    except BaseException as error:
        _settle_owned_probe_after_base_exception(
            popen_owner,
            process=process,
            control_descriptors=control_descriptors,
            worker_release_attempted=worker_release_attempted,
            worker_released=worker_released,
            communicate_completed=communicate_completed,
            leader_binding_complete=leader_binding_complete,
            process_group_bound=process_group_bound,
            cause=error,
        )
        raise

    try:
        assert process is not None
        close_control(release_read)
        close_control(status_write)
        try:
            state_payload = _read_bounded_pipe(
                status_read,
                deadline=time.monotonic() + PROBE_TIMEOUT_SECONDS,
            )
            state = _parse_preexec_state(state_payload)
        except (OSError, TimeoutError, ValueError) as error:
            state_error = _bounded_text(f"pre-exec state is ambiguous: {error}")
        else:
            state_error = "" if state["ok"] else _bounded_text(state["detail"])
            process_group_bound = (
                state["pid"] == process.pid
                and state["process_group"] == process.pid
                and state["session_id"] == process.pid
            )
        finally:
            close_control(status_read)

        leader_error = ""
        try:
            child_process_group = os.getpgid(process.pid)
            child_session = os.getsid(process.pid)
            process_group_bound = process_group_bound or (
                child_process_group == process.pid and child_session == process.pid
            )
            child_start_identity = process_start_identity(process.pid)
            leader_binding_complete = (
                child_process_group == process.pid
                and child_session == process.pid
                and bool(child_start_identity)
            )
        except (OSError, ValueError) as error:
            leader_error = _leader_binding_error_detail(error)
        try:
            worker_release_attempted = True
            written = os.write(release_write, b"G")
            if written != 1:
                raise OSError(errno.EIO, "probe release gate write was partial")
            worker_released = True
        except OSError as error:
            if not leader_error:
                leader_error = _bounded_text(f"cannot release probe worker: {error}")
        finally:
            close_control(release_write)

        try:
            stdout, stderr = process.communicate(timeout=PROBE_TIMEOUT_SECONDS)
            communicate_completed = True
        except subprocess.TimeoutExpired as error:
            closure = _cleanup_probe_after_popen(
                process,
                control_descriptors=control_descriptors,
                worker_release_attempted=worker_release_attempted,
                worker_released=worker_released,
                communicate_completed=communicate_completed,
                leader_binding_complete=leader_binding_complete,
                process_group_bound=process_group_bound,
                trigger=error,
            )
            _raise_for_unproven_probe_closure(
                closure,
                process=process,
                control_descriptors=control_descriptors,
                cause=error,
            )
            return ProbeObservation(
                layer=layer,
                action=action,
                outcome="ambiguous",
                detail="probe deadline expired",
                child_pid=process.pid,
                child_process_group=child_process_group,
                child_session=child_session,
                child_start_identity=child_start_identity,
                profile_sha256=profile_sha256,
                pre_exec_setsid_succeeded=(
                    state["setsid_succeeded"] if state is not None else None
                ),
                pre_exec_pid=state["pid"] if state is not None else None,
                pre_exec_process_group=(
                    state["process_group"] if state is not None else None
                ),
                pre_exec_session=(state["session_id"] if state is not None else None),
                pre_exec_nproc_soft=(
                    state["nproc_soft"] if state is not None else None
                ),
                pre_exec_nproc_hard=(
                    state["nproc_hard"] if state is not None else None
                ),
                nproc_soft=state["nproc_soft"] if state is not None else None,
                nproc_hard=state["nproc_hard"] if state is not None else None,
            )
        completed = subprocess.CompletedProcess(
            argv,
            process.returncode,
            stdout,
            stderr,
        )
        observation = _parse_probe_output(
            layer=layer,
            action=action,
            completed=completed,
        )
        if state_error or leader_error:
            detail = state_error or leader_error
            if (
                not state_error
                and leader_error == PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
                and observation.detail == PROBE_DETAIL_OUTER_SEATBELT_DENIED
            ):
                detail = PROBE_DETAIL_OUTER_SEATBELT_DENIED
            result = replace(
                observation,
                outcome="ambiguous",
                detail=detail,
                child_pid=process.pid,
                child_process_group=child_process_group,
                child_session=child_session,
                child_start_identity=child_start_identity,
                profile_sha256=profile_sha256,
                pre_exec_setsid_succeeded=(
                    state["setsid_succeeded"] if state is not None else None
                ),
                pre_exec_pid=state["pid"] if state is not None else None,
                pre_exec_process_group=(
                    state["process_group"] if state is not None else None
                ),
                pre_exec_session=(state["session_id"] if state is not None else None),
                pre_exec_nproc_soft=(
                    state["nproc_soft"] if state is not None else None
                ),
                pre_exec_nproc_hard=(
                    state["nproc_hard"] if state is not None else None
                ),
            )
        else:
            assert state is not None
            worker_identity = (
                observation.child_pid,
                observation.child_process_group,
                observation.child_session,
            )
            bound_identity = (process.pid, child_process_group, child_session)
            pre_exec_identity = (
                state["pid"],
                state["process_group"],
                state["session_id"],
            )
            if observation.child_pid is not None and (
                worker_identity != bound_identity
                or worker_identity != pre_exec_identity
            ):
                result = replace(
                    observation,
                    outcome="ambiguous",
                    detail=("pre-exec, parent, and post-exec leader identities differ"),
                    child_start_identity=child_start_identity,
                    profile_sha256=profile_sha256,
                    pre_exec_setsid_succeeded=state["setsid_succeeded"],
                    pre_exec_pid=state["pid"],
                    pre_exec_process_group=state["process_group"],
                    pre_exec_session=state["session_id"],
                    pre_exec_nproc_soft=state["nproc_soft"],
                    pre_exec_nproc_hard=state["nproc_hard"],
                )
            else:
                result = replace(
                    observation,
                    child_pid=process.pid,
                    child_process_group=child_process_group,
                    child_session=child_session,
                    child_start_identity=child_start_identity,
                    profile_sha256=profile_sha256,
                    pre_exec_setsid_succeeded=state["setsid_succeeded"],
                    pre_exec_pid=state["pid"],
                    pre_exec_process_group=state["process_group"],
                    pre_exec_session=state["session_id"],
                    pre_exec_nproc_soft=state["nproc_soft"],
                    pre_exec_nproc_hard=state["nproc_hard"],
                    nproc_soft=(
                        observation.nproc_soft
                        if observation.nproc_soft is not None
                        else state["nproc_soft"]
                    ),
                    nproc_hard=(
                        observation.nproc_hard
                        if observation.nproc_hard is not None
                        else state["nproc_hard"]
                    ),
                )
        close_failures: list[str] = []
        controls_closed = _close_probe_control_descriptors(
            control_descriptors,
            close_failures,
        )
        outputs_closed = _close_probe_output_pipes(process, close_failures)
        if not controls_closed or not outputs_closed:
            raise NoChildProfileError(
                "probe pipes could not be closed: " + ";".join(close_failures)
            )
        return result
    except NoChildProbeClosureUnproven:
        raise
    except BaseException as error:
        closure = _cleanup_probe_after_popen(
            process,
            control_descriptors=control_descriptors,
            worker_release_attempted=worker_release_attempted,
            worker_released=worker_released,
            communicate_completed=communicate_completed,
            leader_binding_complete=leader_binding_complete,
            process_group_bound=process_group_bound,
            trigger=error,
        )
        _raise_for_unproven_probe_closure(
            closure,
            process=process,
            control_descriptors=control_descriptors,
            cause=error,
        )
        raise


def _runtime_blockers(
    runtime: RuntimeFingerprint,
    pin: RuntimePin,
    sandbox_exec: ExecutableIdentity | None,
) -> list[str]:
    blockers: list[str] = []
    if runtime.platform != "darwin" or runtime.system != "Darwin":
        blockers.append("unsupported-platform")
        return blockers
    if runtime.effective_uid in {None, 0}:
        blockers.append("non-root-runtime-required")
    if runtime.python_version[:2] != (pin.python_major, pin.python_minor):
        blockers.append("unsupported-python-runtime")
    if runtime.macos_product_version != pin.macos_product_version:
        blockers.append("unapproved-macos-product-version")
    if runtime.macos_build_version != pin.macos_build_version:
        blockers.append("unapproved-macos-build-version")
    if runtime.darwin_release != pin.darwin_release:
        blockers.append("unapproved-darwin-release")
    if pin.seatbelt_profile_version != SEATBELT_PROFILE_VERSION:
        blockers.append("unapproved-seatbelt-profile-version")
    if sandbox_exec is None:
        blockers.append("sandbox-exec-unavailable")
    else:
        if sandbox_exec.path != str(SANDBOX_EXEC):
            blockers.append("sandbox-exec-path-mismatch")
        if sandbox_exec.sha256 != pin.sandbox_exec_sha256:
            blockers.append("sandbox-exec-digest-mismatch")
        if sandbox_exec.uid != 0 or sandbox_exec.mode & 0o022:
            blockers.append("sandbox-exec-is-not-root-protected")
    if not hasattr(resource, "RLIMIT_NPROC"):
        blockers.append("rlimit-nproc-unavailable")
    return blockers


def _probe_blockers(
    observations: Sequence[ProbeObservation],
    *,
    parent_nproc: tuple[int, int] | None,
    profile_sha256: str | None,
) -> list[str]:
    blockers: list[str] = []
    indexed = {(item.layer, item.action): item for item in observations}
    if len(indexed) != len(observations):
        blockers.append("duplicate-probe-observation")

    expected_actions = ("baseline", *_SEATBELT_ACTIONS)
    for layer in ("rlimit", "seatbelt", "combined"):
        expected_limit = parent_nproc if layer == "seatbelt" else (0, 0)
        expected_profile = profile_sha256 if layer != "rlimit" else None
        for action in expected_actions:
            item = indexed.get((layer, action))
            if item is None:
                blockers.append(f"{layer}-{action}-evidence-is-missing")
                continue
            prefix = f"{layer}-{action}"
            pre_exec_identity = (
                item.pre_exec_pid,
                item.pre_exec_process_group,
                item.pre_exec_session,
            )
            child_identity = (
                item.child_pid,
                item.child_process_group,
                item.child_session,
            )
            if item.pre_exec_setsid_succeeded is not True:
                blockers.append(f"{prefix}-pre-exec-setsid-not-proven")
            if (
                type(item.pre_exec_pid) is not int
                or item.pre_exec_pid <= 1
                or len(set(pre_exec_identity)) != 1
            ):
                blockers.append(f"{prefix}-pre-exec-leader-invariant-invalid")
            if child_identity != pre_exec_identity:
                blockers.append(f"{prefix}-post-exec-leader-binding-invalid")
            if not item.child_start_identity:
                blockers.append(f"{prefix}-start-identity-is-missing")
            if item.profile_sha256 != expected_profile:
                blockers.append(f"{prefix}-profile-digest-mismatch")
            if (
                item.pre_exec_nproc_soft,
                item.pre_exec_nproc_hard,
            ) != expected_limit:
                blockers.append(f"{prefix}-pre-exec-rlimit-is-invalid")
            if (item.nproc_soft, item.nproc_hard) != expected_limit:
                blockers.append(f"{prefix}-post-exec-rlimit-is-invalid")

    for layer in ("rlimit", "seatbelt", "combined"):
        baseline = indexed.get((layer, "baseline"))
        if baseline is None or baseline.outcome != "observed":
            blockers.append(f"{layer}-baseline-not-observed")
        elif layer in {"rlimit", "combined"} and (
            baseline.nproc_soft,
            baseline.nproc_hard,
        ) != (0, 0):
            blockers.append(f"{layer}-rlimit-nproc-not-zero")
        elif (
            layer == "seatbelt"
            and (
                baseline.nproc_soft,
                baseline.nproc_hard,
            )
            != parent_nproc
        ):
            blockers.append("seatbelt-baseline-rlimit-is-ambiguous")

    for action in _CREATION_ACTIONS:
        item = indexed.get(("rlimit", action))
        if (
            item is None
            or item.outcome != "denied"
            or item.error_number != errno.EAGAIN
        ):
            blockers.append(f"rlimit-{action}-not-denied")

    for action in ("setsid", "setpgid"):
        item = indexed.get(("rlimit", action))
        if item is None or item.outcome != "denied" or item.error_number != errno.EPERM:
            blockers.append(f"rlimit-{action}-leader-escape-not-denied")

    for layer in ("seatbelt", "combined"):
        for action in _CREATION_ACTIONS:
            item = indexed.get((layer, action))
            accepted_errno = {errno.EPERM} if layer == "seatbelt" else _DENIAL_ERRNOS
            if (
                item is None
                or item.outcome != "denied"
                or item.error_number not in accepted_errno
            ):
                blockers.append(f"{layer}-{action}-not-denied")

        for action in ("setsid", "setpgid", "exec"):
            item = indexed.get((layer, action))
            if (
                item is None
                or item.outcome != "denied"
                or item.error_number != errno.EPERM
            ):
                blockers.append(f"{layer}-{action}-not-denied")

    rlimit_exec = indexed.get(("rlimit", "exec"))
    if rlimit_exec is None or rlimit_exec.outcome != "allowed":
        blockers.append("rlimit-exec-scope-is-ambiguous")

    for item in observations:
        if item.outcome == "ambiguous":
            blockers.append(f"ambiguous-{item.layer}-{item.action}")
    return blockers


def probe_compatibility(
    *,
    pin: RuntimePin = PINNED_RUNTIME,
    probe_executable_path: os.PathLike[str] | str | None = None,
    alternate_executable_path: os.PathLike[str] | str = "/usr/bin/true",
    python_home: str | None = None,
) -> CompatibilityEvidence:
    runtime = _runtime_fingerprint()
    sandbox_identity: ExecutableIdentity | None = None
    probe_attestation: PathExecutedExecutableAttestation | None = None
    probe_identity: ExecutableIdentity | None = None
    alternate_identity: ExecutableIdentity | None = None
    profile: str | None = None
    parent_before: tuple[int, int] | None = None
    parent_after: tuple[int, int] | None = None
    observations: list[ProbeObservation] = []

    if runtime.platform == "darwin" and runtime.system == "Darwin":
        try:
            sandbox_identity = _authenticate_root_protected_executable(
                SANDBOX_EXEC
            ).executable
        except ExecutableAuthenticationError:
            sandbox_identity = None
    blockers = _runtime_blockers(runtime, pin, sandbox_identity)
    if blockers:
        return CompatibilityEvidence(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            runtime_pin=pin,
            runtime=runtime,
            sandbox_exec=sandbox_identity,
            probe_executable=None,
            alternate_executable=None,
            seatbelt_profile_sha256=None,
            parent_nproc_before=None,
            parent_nproc_after=None,
            observations=(),
            blockers=tuple(dict.fromkeys(blockers)),
        )

    try:
        probe_path = probe_executable_path or python_runtime_executable()
        probe_attestation = _authenticate_path_executed_executable(probe_path)
        probe_identity = probe_attestation.executable
        alternate_identity = _read_executable_identity(alternate_executable_path)
        profile = build_seatbelt_profile(probe_identity.path)
        parent_before = resource.getrlimit(resource.RLIMIT_NPROC)
        home = python_home or sys.base_prefix
        for layer in ("rlimit", "seatbelt", "combined"):
            for action in ("baseline", *_SEATBELT_ACTIONS):
                observations.append(
                    _run_probe_case(
                        layer=layer,
                        action=action,
                        probe_executable_attestation=probe_attestation,
                        alternate_executable=alternate_identity,
                        profile=profile,
                        python_home=home,
                    )
                )
        if _executable_protected_key(
            _revalidate_path_executed_executable(probe_attestation)
        ) != _executable_protected_key(probe_identity):
            blockers.append("probe-executable-changed-during-probe")
        if _executable_protected_key(
            _read_executable_identity(alternate_identity.path)
        ) != _executable_protected_key(alternate_identity):
            blockers.append("alternate-executable-changed-during-probe")
        parent_after = resource.getrlimit(resource.RLIMIT_NPROC)
    except (ExecutableAuthenticationError, OSError) as error:
        blockers.append(f"probe-setup-failed:{_bounded_text(str(error), limit=256)}")
    if parent_before is not None and parent_after != parent_before:
        blockers.append("parent-rlimit-nproc-changed")
    profile_sha256 = (
        hashlib.sha256(profile.encode("utf-8")).hexdigest() if profile else None
    )
    blockers.extend(
        _probe_blockers(
            observations,
            parent_nproc=parent_before,
            profile_sha256=profile_sha256,
        )
    )
    return CompatibilityEvidence(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        runtime_pin=pin,
        runtime=runtime,
        sandbox_exec=sandbox_identity,
        probe_executable=probe_identity,
        alternate_executable=alternate_identity,
        seatbelt_profile_sha256=profile_sha256,
        parent_nproc_before=parent_before,
        parent_nproc_after=parent_after,
        observations=tuple(observations),
        blockers=tuple(dict.fromkeys(blockers)),
    )


def require_compatible(evidence: CompatibilityEvidence) -> None:
    blockers = list(evidence.blockers)
    if evidence.schema_version != EVIDENCE_SCHEMA_VERSION:
        blockers.append("unsupported-evidence-schema")
    blockers.extend(
        _runtime_blockers(
            evidence.runtime,
            evidence.runtime_pin,
            evidence.sandbox_exec,
        )
    )
    if evidence.parent_nproc_before is None:
        blockers.append("parent-rlimit-before-is-missing")
    if evidence.parent_nproc_after != evidence.parent_nproc_before:
        blockers.append("parent-rlimit-nproc-changed")
    if evidence.probe_executable is None:
        blockers.append("probe-executable-identity-is-missing")
    if evidence.alternate_executable is None:
        blockers.append("alternate-executable-identity-is-missing")
    if evidence.seatbelt_profile_sha256 is None:
        blockers.append("seatbelt-profile-digest-is-missing")
    elif evidence.probe_executable is not None:
        try:
            expected_profile = build_seatbelt_profile(evidence.probe_executable.path)
        except ExecutableAuthenticationError:
            blockers.append("probe-seatbelt-profile-cannot-be-rebuilt")
        else:
            expected_profile_sha256 = hashlib.sha256(
                expected_profile.encode("utf-8")
            ).hexdigest()
            if expected_profile_sha256 != evidence.seatbelt_profile_sha256:
                blockers.append("seatbelt-profile-digest-mismatch")
    blockers.extend(
        _probe_blockers(
            evidence.observations,
            parent_nproc=evidence.parent_nproc_before,
            profile_sha256=evidence.seatbelt_profile_sha256,
        )
    )
    blockers = list(dict.fromkeys(blockers))
    if blockers:
        raise NoChildProfileUnavailable(replace(evidence, blockers=tuple(blockers)))


def _require_live_runtime(evidence: CompatibilityEvidence) -> None:
    if not evidence.production_capable:
        raise NoChildProfileError(
            "no-child launch requires the exact production runtime pin"
        )
    blockers: list[str] = []
    if _runtime_fingerprint() != evidence.runtime:
        blockers.append("runtime-changed-after-probe")
    try:
        sandbox_exec = _authenticate_root_protected_executable(SANDBOX_EXEC).executable
    except ExecutableAuthenticationError as error:
        sandbox_exec = None
        sandbox_error = error
    else:
        sandbox_error = None
    if sandbox_error is not None and evidence.sandbox_exec is not None:
        blockers.append("sandbox-exec-revalidation-failed-after-probe")
    elif _optional_executable_protected_key(
        sandbox_exec
    ) != _optional_executable_protected_key(evidence.sandbox_exec):
        blockers.append("sandbox-exec-changed-after-probe")
    if evidence.probe_executable is not None:
        try:
            probe_executable = _read_executable_identity(evidence.probe_executable.path)
        except ExecutableAuthenticationError:
            blockers.append("probe-executable-revalidation-failed-after-probe")
        else:
            if _executable_protected_key(probe_executable) != _executable_protected_key(
                evidence.probe_executable
            ):
                blockers.append("probe-executable-changed-after-probe")
    if evidence.alternate_executable is not None:
        try:
            alternate_executable = _read_executable_identity(
                evidence.alternate_executable.path
            )
        except ExecutableAuthenticationError:
            blockers.append("alternate-executable-revalidation-failed-after-probe")
        else:
            if _executable_protected_key(
                alternate_executable
            ) != _executable_protected_key(evidence.alternate_executable):
                blockers.append("alternate-executable-changed-after-probe")
    if blockers:
        raise NoChildProfileUnavailable(
            replace(
                evidence,
                blockers=tuple(dict.fromkeys((*evidence.blockers, *blockers))),
            )
        )


def prepare_no_child_profile(
    executable_path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
    additional_seatbelt_rules: str = "",
) -> PreparedNoChildProfile:
    evidence = probe_compatibility()
    require_compatible(evidence)
    executable = authenticate_executable(
        executable_path,
        expected_sha256=expected_sha256,
    )
    return PreparedNoChildProfile(
        executable=executable,
        expected_sha256=expected_sha256,
        seatbelt_profile=build_seatbelt_profile(
            executable.path,
            additional_rules=additional_seatbelt_rules,
        ),
        evidence=evidence,
        additional_seatbelt_rules=additional_seatbelt_rules,
    )


def prepare_sandboxed_python_no_child_profile(
    *,
    additional_seatbelt_rules: str = "",
    runtime_pin: RuntimePin = PINNED_RUNTIME,
    writable_roots: Sequence[WritableRootAttestation] = (),
) -> PreparedNoChildProfile:
    """Prepare the current path-bound Python behind the sandbox loader.

    Writable roots require FD-bound attestations and an explicit global
    ``file-write*`` denial. The caller retains every attested descriptor
    through launch.
    """

    if runtime_pin != PINNED_RUNTIME:
        raise NoChildProfileError(
            "custom no-child runtime pins are probe-only and cannot authorize launch"
        )
    evidence = probe_compatibility(pin=runtime_pin)
    require_compatible(evidence)
    sandbox_exec = authenticate_executable(
        SANDBOX_EXEC,
        expected_sha256=evidence.runtime_pin.sandbox_exec_sha256,
    )
    target_attestation = _authenticate_path_executed_executable(
        python_runtime_executable()
    )
    target = target_attestation.executable
    target_component_keys = frozenset(
        {
            (target.device, target.inode),
            *(
                (component.identity.device, component.identity.inode)
                for component in target_attestation.components
            ),
        }
    )
    validated_roots = _validated_sandboxed_writable_roots(
        writable_roots,
        protected_component_keys=target_component_keys,
    )
    if (
        validated_roots
        and "(deny file-write*)" not in additional_seatbelt_rules.splitlines()
    ):
        raise NoChildProfileError(
            "sandboxed writable roots require default-deny filesystem writes"
        )
    return PreparedNoChildProfile(
        executable=sandbox_exec,
        expected_sha256=sandbox_exec.sha256,
        seatbelt_profile=_render_seatbelt_profile(
            (pathlib.Path(target.path),),
            additional_rules=additional_seatbelt_rules,
            writable_root_paths=tuple(
                pathlib.Path(root.path) for root in validated_roots
            ),
        ),
        evidence=evidence,
        additional_seatbelt_rules=additional_seatbelt_rules,
        writable_roots=validated_roots,
        sandboxed_target=target,
        sandboxed_target_attestation=target_attestation,
    )


def prepare_custodied_snapshot_no_child_profile(
    snapshot_attestation: OwnerSnapshotLaunchAttestation,
    *,
    writable_roots: Sequence[WritableRootAttestation],
) -> PreparedNoChildProfile:
    """Prepare an authenticated owner-only snapshot for a no-child launch.

    ``snapshot_attestation`` must come from
    ``CodexExecutableCustody.attest_owner_snapshot_launch()``. Its executable and
    directory FDs remain custody-owned and must stay open and non-inheritable
    through launch. Every entry in ``writable_roots`` must come from
    :func:`attest_writable_root`; those caller-owned FDs have the same lifetime
    requirement. The API revalidates all paths, FDs, inode identities, modes, the
    executable digest, the Mach-O magic, and non-overlap before rendering a
    profile. No raw writable path and no ordinary owner-writable executable is
    accepted as authority.
    """

    evidence = probe_compatibility()
    require_compatible(evidence)
    executable, validated_roots, seatbelt_profile = (
        _build_custodied_snapshot_seatbelt_profile(
            snapshot_attestation,
            writable_roots,
        )
    )
    return PreparedNoChildProfile(
        executable=executable,
        expected_sha256=snapshot_attestation.expected_sha256,
        seatbelt_profile=seatbelt_profile,
        evidence=evidence,
        additional_seatbelt_rules=snapshot_attestation.snapshot.seatbelt_policy.rules,
        owner_snapshot_attestation=snapshot_attestation,
        writable_roots=validated_roots,
    )


def _maximum_fd() -> int:
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return 1_048_576
    return min(int(soft), 1_048_576)


def _validated_environment(
    environment: Mapping[str, str] | None,
) -> dict[str, str]:
    source = os.environ if environment is None else environment
    result: dict[str, str] = {}
    for key, value in source.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in value
        ):
            raise ValueError("environment must contain valid NUL-free strings")
        if key.startswith(("DYLD_", "LD_", "__XPC_DYLD_")):
            raise ValueError("dynamic-loader environment overrides are forbidden")
        result[key] = value
    return result


def _revalidate_prepared_profile(
    prepared: PreparedNoChildProfile,
) -> ExecutableIdentity:
    if prepared.owner_snapshot_attestation is None:
        if prepared.sandboxed_target is None and prepared.writable_roots:
            raise NoChildProfileError(
                "ordinary executable profile contains writable-root authority"
            )
        if (
            prepared.sandboxed_target is None
            and prepared.sandboxed_target_attestation is not None
        ):
            raise NoChildProfileError(
                "ordinary executable profile contains path-executed target authority"
            )
        current = authenticate_executable(
            prepared.executable.path,
            expected_sha256=prepared.expected_sha256,
        )
        if prepared.sandboxed_target is None:
            expected_profile = build_seatbelt_profile(
                prepared.executable.path,
                additional_rules=prepared.additional_seatbelt_rules,
            )
        else:
            if pathlib.Path(prepared.executable.path) != SANDBOX_EXEC:
                raise NoChildProfileError(
                    "sandboxed target does not use the authenticated sandbox loader"
                )
            target_attestation = prepared.sandboxed_target_attestation
            if target_attestation is None:
                raise NoChildProfileError(
                    "sandboxed target is missing its path-execution attestation"
                )
            _require_path_execution_attestation_consistent(target_attestation)
            if _executable_protected_key(
                prepared.sandboxed_target
            ) != _executable_protected_key(target_attestation.executable):
                raise ExecutableAuthenticationError(
                    "sandboxed target authority was modified after preparation"
                )
            target = _revalidate_path_executed_executable(target_attestation)
            target_component_keys = frozenset(
                {
                    (target.device, target.inode),
                    *(
                        (component.identity.device, component.identity.inode)
                        for component in target_attestation.components
                    ),
                }
            )
            writable_roots = _validated_sandboxed_writable_roots(
                prepared.writable_roots,
                protected_component_keys=target_component_keys,
            )
            if (
                writable_roots
                and "(deny file-write*)"
                not in prepared.additional_seatbelt_rules.splitlines()
            ):
                raise NoChildProfileError(
                    "sandboxed writable roots require default-deny filesystem writes"
                )
            expected_profile = _render_seatbelt_profile(
                (pathlib.Path(target.path),),
                additional_rules=prepared.additional_seatbelt_rules,
                writable_root_paths=tuple(
                    pathlib.Path(root.path) for root in writable_roots
                ),
            )
            if writable_roots != prepared.writable_roots:
                raise NoChildProfileError(
                    "prepared writable-root authority was modified"
                )
    else:
        if (
            prepared.sandboxed_target is not None
            or prepared.sandboxed_target_attestation is not None
        ):
            raise NoChildProfileError(
                "owner snapshot profile contains a sandboxed target"
            )
        attestation = prepared.owner_snapshot_attestation
        if (
            prepared.expected_sha256 != attestation.expected_sha256
            or prepared.additional_seatbelt_rules
            != attestation.snapshot.seatbelt_policy.rules
        ):
            raise NoChildProfileError("prepared owner snapshot authority was modified")
        current, writable_roots, expected_profile = (
            _build_custodied_snapshot_seatbelt_profile(
                attestation,
                prepared.writable_roots,
            )
        )
        if writable_roots != prepared.writable_roots:
            raise NoChildProfileError(
                "prepared writable-root attestations were modified"
            )
    if _executable_protected_key(current) != _executable_protected_key(
        prepared.executable
    ):
        raise ExecutableAuthenticationError(
            "authenticated executable identity changed after preparation"
        )
    if prepared.seatbelt_profile != expected_profile:
        raise NoChildProfileError("prepared Seatbelt profile was modified")
    return current


def _launch_child(
    prepared: PreparedNoChildProfile,
    sandbox_argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: Mapping[str, str],
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    pass_fds: Sequence[int],
    error_write_fd: int,
) -> None:
    error_target = 3 + len(pass_fds)
    failure_fd = error_write_fd
    try:
        _revalidate_prepared_profile(prepared)
        sources = (stdin_fd, stdout_fd, stderr_fd, *pass_fds, error_write_fd)
        duplicates = [
            fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 64) for source in sources
        ]
        failure_fd = duplicates[-1]
        for target, source in zip((0, 1, 2), duplicates[:3], strict=True):
            os.dup2(source, target, inheritable=True)
        offset = 3
        for target, source in zip(
            range(3, 3 + len(pass_fds)),
            duplicates[offset : offset + len(pass_fds)],
            strict=True,
        ):
            os.dup2(source, target, inheritable=True)
        os.dup2(duplicates[-1], error_target, inheritable=False)
        failure_fd = error_target
        os.closerange(error_target + 1, _maximum_fd())
        os.chdir(cwd)
        os.setsid()
        pid = os.getpid()
        if os.getpgrp() != pid or os.getsid(0) != pid:
            raise OSError(
                errno.EPERM,
                "setsid did not establish the launch leader invariant",
            )
        _set_zero_nproc_limit()
        os.execve(SANDBOX_EXEC, sandbox_argv, dict(environment))
    except BaseException as error:
        try:
            payload = (
                f"{getattr(error, 'errno', errno.EIO)}:{type(error).__name__}:{error}"
            ).encode("utf-8", "replace")[:4096]
            os.write(failure_fd, payload)
        except BaseException:
            pass
        os._exit(127)


@dataclass(slots=True)
class _NoChildLaunchReceipt:
    creator_pid: int
    error_read_fd: int
    error_write_fd: int
    pipe_call_started: bool = False
    pipe_call_completed: bool = False
    pipe_failure_proven: bool = False
    fork_call_started: bool = False
    fork_call_completed: bool = False
    fork_failure_proven: bool = False
    returned_pid: int | None = None
    leader_pid: int | None = None
    child_receipt_attempted: bool = False
    child_receipt_published: bool = False
    child_receipt_error: BaseException | None = None
    leader_receipt_received: bool = False
    error_read_close_outcome: str = "owned"
    error_write_close_outcome: str = "owned"

    @property
    def in_child_process(self) -> bool:
        return os.getpid() != self.creator_pid

    @property
    def control_pipes_closed(self) -> bool:
        if (
            self.pipe_call_started
            and not self.pipe_call_completed
            and not self.pipe_failure_proven
        ):
            return False
        closed_outcomes = {"closed", "missing", "not-created"}
        return (
            self.error_read_fd < 0
            and self.error_write_fd < 0
            and self.error_read_close_outcome in closed_outcomes
            and self.error_write_close_outcome in closed_outcomes
        )

    def close_error_read(self, failures: list[str] | None = None) -> bool:
        return self._close_descriptor("error_read_fd", failures)

    def close_error_write(self, failures: list[str] | None = None) -> bool:
        return self._close_descriptor("error_write_fd", failures)

    def _close_descriptor(
        self,
        attribute: str,
        failures: list[str] | None,
    ) -> bool:
        descriptor = getattr(self, attribute)
        outcome_attribute = f"{attribute.removesuffix('_fd')}_close_outcome"
        outcome = getattr(self, outcome_attribute)
        if descriptor < 0:
            return outcome in {"closed", "missing", "not-created"}
        if outcome in {"closed", "missing"}:
            setattr(self, attribute, -1)
            return True
        if outcome == "close-outcome-unproven":
            return False
        if outcome != "owned":
            detail = f"close-fd-{descriptor}:invalid-close-state:{outcome}"
            if failures is None:
                raise ChildProcessError(detail)
            failures.append(detail)
            return False
        # Keep the integer as descriptor evidence. An exception may arrive
        # before or after the syscall, so publish uncertainty first and never
        # retry this integer unless closure was proved.
        setattr(self, outcome_attribute, "close-outcome-unproven")
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                setattr(self, outcome_attribute, "missing")
                setattr(self, attribute, -1)
                return True
            if failures is None:
                setattr(error, "no_child_launch_receipt", self)
                raise
            failures.append(
                f"close-fd-{descriptor}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            return False
        except BaseException as error:
            if failures is None:
                setattr(error, "no_child_launch_receipt", self)
                raise
            failures.append(
                f"close-fd-{descriptor}:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
            return False
        setattr(self, outcome_attribute, "closed")
        setattr(self, attribute, -1)
        return True


@dataclass(slots=True)
class _NoChildLaunchReceiptOwner:
    receipt: _NoChildLaunchReceipt | None = None
    ownership_published: bool = False

    def publish(self, receipt: _NoChildLaunchReceipt) -> None:
        if self.receipt is None:
            self.receipt = receipt
        elif self.receipt is not receipt:
            raise ValueError("no-child launch receipt owner was rebound")
        self.ownership_published = True

    def owns(self, receipt: _NoChildLaunchReceipt) -> bool:
        return self.ownership_published and self.receipt is receipt

    def require_receipt(self) -> _NoChildLaunchReceipt:
        receipt = self.receipt
        if receipt is None or not self.owns(receipt):
            raise ChildProcessError("no-child launch receipt was not published")
        return receipt


@dataclass(slots=True)
class _NoChildLaunchPipeWorker:
    receipt: _NoChildLaunchReceipt
    error: BaseException | None = None
    completed: bool = False

    def run(self) -> None:
        try:
            self.receipt.pipe_call_started = True
            try:
                pipe_result = os.pipe()
            except OSError:
                self.receipt.pipe_failure_proven = True
                raise
            self.receipt.error_read_fd = pipe_result[0]
            self.receipt.error_write_fd = pipe_result[1]
            self.receipt.error_read_close_outcome = "owned"
            self.receipt.error_write_close_outcome = "owned"
            self.receipt.pipe_call_completed = True
            os.set_inheritable(self.receipt.error_read_fd, False)
            os.set_inheritable(self.receipt.error_write_fd, False)
        except BaseException as error:
            self.error = error
        finally:
            self.completed = True


def _finish_launch_pipe_worker(
    worker_thread: threading.Thread,
    *,
    started: bool,
) -> None:
    if not started and worker_thread.ident is None:
        return
    while worker_thread.is_alive():
        worker_thread.join()
    worker_thread.join()


def _close_launch_pipe_after_failure(
    owner: _NoChildLaunchReceiptOwner,
    trigger: BaseException,
) -> None:
    receipt = owner.receipt
    if receipt is None:
        return
    failures: list[str] = []
    receipt.close_error_read(failures)
    receipt.close_error_write(failures)
    if receipt.control_pipes_closed:
        return
    try:
        setattr(trigger, "no_child_launch_receipt_owner", owner)
        setattr(trigger, "no_child_launch_pipe_close_failures", tuple(failures))
    except BaseException:
        pass


def _open_launch_error_pipe(
    owner: _NoChildLaunchReceiptOwner,
) -> _NoChildLaunchReceipt:
    receipt = _NoChildLaunchReceipt(
        creator_pid=os.getpid(),
        error_read_fd=-1,
        error_write_fd=-1,
        error_read_close_outcome="not-created",
        error_write_close_outcome="not-created",
    )
    owner.publish(receipt)
    if not owner.owns(receipt):
        raise ChildProcessError(
            "no-child launch receipt owner did not retain the pending pipe"
        )

    worker = _NoChildLaunchPipeWorker(receipt=receipt)
    worker_thread = threading.Thread(
        target=worker.run,
        name="no-child-launch-pipe",
        daemon=False,
    )
    started = False
    try:
        worker_thread.start()
        started = True
        worker_thread.join()
    except BaseException as trigger:
        _finish_launch_pipe_worker(worker_thread, started=started)
        _close_launch_pipe_after_failure(owner, trigger)
        raise

    if not worker.completed:
        error = ChildProcessError("no-child launch pipe worker did not complete")
        _close_launch_pipe_after_failure(owner, error)
        raise error
    if worker.error is not None:
        _close_launch_pipe_after_failure(owner, worker.error)
        raise worker.error
    if (
        receipt.error_read_fd < 0
        or receipt.error_write_fd < 0
        or receipt.error_read_close_outcome != "owned"
        or receipt.error_write_close_outcome != "owned"
    ):
        error = ChildProcessError(
            "no-child launch pipe worker returned incomplete descriptor custody"
        )
        _close_launch_pipe_after_failure(owner, error)
        raise error
    return receipt


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "launch receipt write made no progress")
        offset += written


def _read_launch_leader_receipt(
    descriptor: int,
    *,
    deadline: float,
) -> int:
    payload = bytearray()
    while len(payload) < _LAUNCH_LEADER_RECEIPT.size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fork leader receipt deadline expired")
        readable, _, _ = select.select(
            [descriptor],
            [],
            [],
            min(remaining, 0.1),
        )
        if not readable:
            continue
        chunk = os.read(descriptor, _LAUNCH_LEADER_RECEIPT.size - len(payload))
        if not chunk:
            raise ChildProcessError("fork leader receipt pipe closed early")
        payload.extend(chunk)
    magic, leader_pid = _LAUNCH_LEADER_RECEIPT.unpack(payload)
    if magic != _LAUNCH_LEADER_RECEIPT_MAGIC or leader_pid <= 0:
        raise ChildProcessError("fork leader receipt is invalid")
    return leader_pid


def _publish_child_launch_receipt(receipt: _NoChildLaunchReceipt) -> None:
    leader_pid = os.getpid()
    _write_all(
        receipt.error_write_fd,
        _LAUNCH_LEADER_RECEIPT.pack(
            _LAUNCH_LEADER_RECEIPT_MAGIC,
            leader_pid,
        ),
    )
    receipt.leader_pid = leader_pid
    receipt.child_receipt_published = True


_FORK_RECEIPT_CONTEXT = threading.local()
_FORK_RECEIPT_HOOK_LOCK = threading.Lock()
_FORK_RECEIPT_HOOK_REGISTERED = False


def _active_fork_receipt() -> _NoChildLaunchReceipt | None:
    receipt = getattr(_FORK_RECEIPT_CONTEXT, "receipt", None)
    return receipt if isinstance(receipt, _NoChildLaunchReceipt) else None


def _after_receipted_fork_in_parent() -> None:
    receipt = _active_fork_receipt()
    if receipt is not None:
        receipt.fork_call_completed = True


def _after_receipted_fork_in_child() -> None:
    receipt = _active_fork_receipt()
    if receipt is None:
        return
    receipt.fork_call_completed = True
    if receipt.child_receipt_attempted:
        return
    receipt.child_receipt_attempted = True
    try:
        _publish_child_launch_receipt(receipt)
    except BaseException as error:
        receipt.child_receipt_error = error


def _ensure_receipted_fork_hooks() -> None:
    global _FORK_RECEIPT_HOOK_REGISTERED

    if _FORK_RECEIPT_HOOK_REGISTERED:
        return
    with _FORK_RECEIPT_HOOK_LOCK:
        if _FORK_RECEIPT_HOOK_REGISTERED:
            return
        os.register_at_fork(
            after_in_parent=_after_receipted_fork_in_parent,
            after_in_child=_after_receipted_fork_in_child,
        )
        _FORK_RECEIPT_HOOK_REGISTERED = True


def _clear_active_fork_receipt(receipt: _NoChildLaunchReceipt) -> None:
    if _active_fork_receipt() is receipt:
        del _FORK_RECEIPT_CONTEXT.receipt


def _fork_with_launch_error_pipe(
    owner: _NoChildLaunchReceiptOwner,
) -> tuple[int, int, int]:
    receipt = _open_launch_error_pipe(owner)
    if not owner.owns(receipt):
        raise ChildProcessError(
            "no-child launch receipt owner did not retain the pipes"
        )
    error_read = receipt.error_read_fd
    error_write = receipt.error_write_fd
    _ensure_receipted_fork_hooks()
    try:
        _FORK_RECEIPT_CONTEXT.receipt = receipt
        receipt.fork_call_started = True
        try:
            pid = os.fork()
        except OSError:
            if not receipt.fork_call_completed:
                receipt.fork_failure_proven = True
                failures = []
                receipt.close_error_read(failures)
                receipt.close_error_write(failures)
            raise
    finally:
        _clear_active_fork_receipt(receipt)
    receipt.fork_call_completed = True
    if pid < 0:
        receipt.fork_failure_proven = True
        failures = []
        receipt.close_error_read(failures)
        receipt.close_error_write(failures)
        raise OSError(errno.EAGAIN, "fork returned an invalid process identifier")
    if pid == 0:
        if receipt.child_receipt_error is not None:
            _exit_child_launch_failure(error_write, receipt.child_receipt_error)
        if not receipt.child_receipt_published:
            receipt.child_receipt_attempted = True
            _publish_child_launch_receipt(receipt)
        return pid, error_read, error_write
    receipt.returned_pid = pid
    leader_pid = _read_launch_leader_receipt(
        error_read,
        deadline=time.monotonic() + PROBE_TIMEOUT_SECONDS,
    )
    receipt.leader_pid = leader_pid
    receipt.leader_receipt_received = True
    if leader_pid != pid:
        raise ChildProcessError(
            "fork returned a leader that does not match the child receipt"
        )
    return pid, error_read, error_write


def _terminate_and_reap(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while True:
        try:
            reaped_pid, _ = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            reaped_pid = 0
        if reaped_pid == pid:
            break
        if reaped_pid != 0:
            raise ChildProcessError(
                f"waitpid reaped {reaped_pid}, expected exact leader {pid}"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(f"process leader {pid} did not exit before deadline")
        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    if reaped_pid != pid:
        raise ChildProcessError(
            f"waitpid reaped {reaped_pid}, expected exact leader {pid}"
        )
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return
    raise ChildProcessError(f"process group {pid} remained live after leader reap")


def _exit_child_launch_failure(error_write_fd: int, error: BaseException) -> None:
    try:
        payload = (
            f"{getattr(error, 'errno', errno.EIO)}:{type(error).__name__}:{error}"
        ).encode("utf-8", "replace")[:4096]
        os.write(error_write_fd, payload)
    except BaseException:
        pass
    os._exit(127)


def _settle_owned_launch_after_base_exception(
    owner: _NoChildLaunchReceiptOwner,
    *,
    prepared: PreparedNoChildProfile,
    exec_acknowledged: bool,
    leader_binding_complete: bool,
    trigger: BaseException,
    result_owner_query_error: BaseException | None = None,
    uncertain_result_owner: NoChildLaunchResultOwner | None = None,
    launched_result: LaunchedNoChildProcess | None = None,
) -> None:
    receipt = owner.receipt
    if receipt is None:
        return
    failures = [
        f"trigger:{type(trigger).__name__}:{_bounded_text(str(trigger), limit=128)}"
    ]
    if result_owner_query_error is not None:
        failures.append(
            "result-owner-ownership-query:"
            f"{type(result_owner_query_error).__name__}:"
            f"{_bounded_text(str(result_owner_query_error), limit=128)}"
        )
    may_have_child = receipt.fork_call_started and not receipt.fork_failure_proven
    leader_pid = (
        receipt.returned_pid
        if receipt.returned_pid is not None and receipt.returned_pid > 0
        else receipt.leader_pid
    )
    leader_reaped = not may_have_child
    process_group_empty = not may_have_child

    receipt.close_error_write(failures)
    if may_have_child and leader_pid is None and receipt.error_read_fd >= 0:
        try:
            leader_pid = _read_launch_leader_receipt(
                receipt.error_read_fd,
                deadline=time.monotonic() + PROBE_TIMEOUT_SECONDS,
            )
        except BaseException as error:
            failures.append(
                f"recover-leader-receipt:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
        else:
            receipt.leader_pid = leader_pid
            receipt.leader_receipt_received = True

    if may_have_child and leader_pid is not None:
        try:
            _terminate_and_reap(leader_pid)
        except BaseException as error:
            failures.append(
                f"terminate-reap-leader:{type(error).__name__}:"
                f"{_bounded_text(str(error), limit=128)}"
            )
        else:
            leader_reaped = True
            process_group_empty = True

    if not may_have_child or leader_pid is not None:
        receipt.close_error_read(failures)
    control_pipes_closed = receipt.control_pipes_closed
    if leader_reaped and process_group_empty and control_pipes_closed:
        return

    evidence = NoChildLaunchClosureEvidence(
        leader_pid=leader_pid,
        fork_call_started=receipt.fork_call_started,
        fork_call_completed=receipt.fork_call_completed,
        pipe_ownership_published=owner.owns(receipt),
        leader_receipt_received=receipt.leader_receipt_received,
        exec_acknowledged=exec_acknowledged,
        leader_binding_complete=leader_binding_complete,
        leader_reaped=leader_reaped,
        process_group_empty=process_group_empty,
        control_pipes_closed=control_pipes_closed,
        reason=";".join(failures)[:1024],
    )
    retained = NoChildLaunchClosureUnproven(evidence=evidence)
    retained.retain_resource(prepared)
    retained.retain_resource(owner)
    retained.retain_resource(receipt)
    if uncertain_result_owner is not None:
        retained.retain_resource(uncertain_result_owner)
    if launched_result is not None:
        retained.retain_resource(launched_result)
    for descriptor in (receipt.error_read_fd, receipt.error_write_fd):
        if descriptor >= 0:
            retained.retain_resource(descriptor)
    raise retained from trigger


def launch_prepared_no_child_process(
    prepared: PreparedNoChildProfile,
    argv: Sequence[str],
    *,
    cwd: os.PathLike[str] | str,
    environment: Mapping[str, str] | None = None,
    stdin_fd: int = 0,
    stdout_fd: int = 1,
    stderr_fd: int = 2,
    pass_fds: Sequence[int] = (),
    result_owner: NoChildLaunchResultOwner | None = None,
) -> LaunchedNoChildProcess:
    """Launch one prepared target after parent and child-side revalidation.

    Custody and writable-root FDs attested during preparation must still be
    open, read-only, and non-inheritable. They are used again in the forked
    child immediately before ``sandbox-exec`` and are never included in the
    target's inherited descriptor set. Only ``pass_fds`` are remapped to
    consecutive descriptors beginning at 3.
    """

    require_compatible(prepared.evidence)
    _require_live_runtime(prepared.evidence)
    target = (
        prepared.executable
        if prepared.sandboxed_target is None
        else prepared.sandboxed_target
    )
    if not argv or argv[0] != target.path:
        raise ValueError("argv[0] must be the exact authenticated executable path")
    if any(not isinstance(argument, str) or "\x00" in argument for argument in argv):
        raise ValueError("argv entries must be NUL-free strings")
    launch_fds = (stdin_fd, stdout_fd, stderr_fd, *pass_fds)
    if any(type(descriptor) is not int or descriptor < 0 for descriptor in launch_fds):
        raise ValueError("launch descriptors must be non-negative integers")
    if len(set(pass_fds)) != len(pass_fds):
        raise ValueError("pass_fds must not contain duplicates")
    protected_fds = {root.directory_fd for root in prepared.writable_roots}
    if prepared.owner_snapshot_attestation is not None:
        protected_fds.update(
            {
                prepared.owner_snapshot_attestation.executable_fd,
                prepared.owner_snapshot_attestation.directory_fd,
            }
        )
    if protected_fds.intersection(launch_fds):
        raise ValueError("custody and writable-root descriptors cannot be inherited")
    _revalidate_prepared_profile(prepared)
    child_environment = _validated_environment(environment)
    sandbox_argv = (
        str(SANDBOX_EXEC),
        "-p",
        prepared.seatbelt_profile,
        *argv,
    )
    prove_exec_budget(sandbox_argv, environment=child_environment)
    parent_before = resource.getrlimit(resource.RLIMIT_NPROC)
    launch_receipt_owner = _NoChildLaunchReceiptOwner()
    exec_acknowledged = False
    leader_binding_complete = False
    launched_result: LaunchedNoChildProcess | None = None
    try:
        pid, error_read, error_write = _fork_with_launch_error_pipe(
            launch_receipt_owner
        )
        launch_receipt = launch_receipt_owner.require_receipt()
        if (
            launch_receipt.error_read_fd != error_read
            or launch_receipt.error_write_fd != error_write
        ):
            raise ChildProcessError(
                "no-child launch helper returned pipes outside the receipt owner"
            )
        if pid == 0:
            try:
                launch_receipt.close_error_read()
            except BaseException as error:
                _exit_child_launch_failure(error_write, error)
            _launch_child(
                prepared,
                sandbox_argv,
                cwd=pathlib.Path(cwd),
                environment=child_environment,
                stdin_fd=stdin_fd,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
                pass_fds=pass_fds,
                error_write_fd=error_write,
            )
            os._exit(127)
        if (
            launch_receipt.returned_pid != pid
            or launch_receipt.leader_pid != pid
            or not launch_receipt.leader_receipt_received
        ):
            raise ChildProcessError(
                "no-child launch helper returned an unpublished leader"
            )
        try:
            launch_receipt.close_error_write()
            deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
            payload = bytearray()
            os.set_blocking(launch_receipt.error_read_fd, False)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sandbox-exec acknowledgement deadline expired")
                readable, _, _ = select.select(
                    [error_read],
                    [],
                    [],
                    min(remaining, 0.1),
                )
                if not readable:
                    continue
                chunk = os.read(
                    launch_receipt.error_read_fd,
                    4096 - len(payload),
                )
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) >= 4096:
                    raise ChildProcessError("launch failure record is oversized")
            if payload:
                raise ChildProcessError(
                    "no-child-process launch failed: "
                    + payload.decode("utf-8", "replace")
                )
            exec_acknowledged = True
        finally:
            launch_receipt.close_error_read()
        parent_after = resource.getrlimit(resource.RLIMIT_NPROC)
        if parent_after != parent_before:
            raise NoChildProfileError("parent RLIMIT_NPROC changed during launch")
        try:
            pgid = os.getpgid(pid)
            session_id = os.getsid(pid)
            start_identity = process_start_identity(pid)
        except (OSError, ValueError) as error:
            raise ChildProcessError(
                f"cannot bind launched no-child-process leader: {error}"
            ) from error
        leader_binding_complete = True
        if pgid != pid or session_id != pid:
            raise ChildProcessError(
                "launched process does not satisfy pid == pgid == session invariant"
            )
        profile_sha256 = hashlib.sha256(
            prepared.seatbelt_profile.encode("utf-8")
        ).hexdigest()
        launched_result = LaunchedNoChildProcess(
            pid=pid,
            pgid=pgid,
            session_id=session_id,
            start_identity=start_identity,
            profile_sha256=profile_sha256,
            passed_fd_numbers=tuple(range(3, 3 + len(pass_fds))),
            executable=target,
            evidence=prepared.evidence,
            parent_nproc_before=parent_before,
            parent_nproc_after=parent_after,
        )
        if result_owner is not None:
            result_owner.publish(launched_result)
            if not result_owner.owns(launched_result):
                raise ChildProcessError(
                    "no-child launch result owner did not retain the exact leader"
                )
        return launched_result
    except BaseException as error:
        launch_receipt = launch_receipt_owner.receipt
        if launch_receipt is not None and launch_receipt.in_child_process:
            if launch_receipt.error_write_fd >= 0:
                _exit_child_launch_failure(
                    launch_receipt.error_write_fd,
                    error,
                )
            os._exit(127)
        result_ownership_proved = False
        result_owner_query_error: BaseException | None = None
        if launched_result is not None and result_owner is not None:
            try:
                result_ownership_proved = result_owner.owns(launched_result)
            except BaseException as query_error:
                result_owner_query_error = query_error
        if result_ownership_proved:
            raise
        _settle_owned_launch_after_base_exception(
            launch_receipt_owner,
            prepared=prepared,
            exec_acknowledged=exec_acknowledged,
            leader_binding_complete=leader_binding_complete,
            trigger=error,
            result_owner_query_error=result_owner_query_error,
            uncertain_result_owner=result_owner,
            launched_result=launched_result,
        )
        raise
