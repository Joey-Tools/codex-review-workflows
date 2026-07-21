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
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping, Sequence

from .codex_executable import (
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


SANDBOX_EXEC = pathlib.Path("/usr/bin/sandbox-exec")
SEATBELT_PROFILE_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 2
MAX_EXECUTABLE_BYTES = 1 << 30
MAX_WRITABLE_ROOTS = 8
MAX_SEATBELT_PROFILE_BYTES = 32 * 1024
PROBE_TIMEOUT_SECONDS = 5.0


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

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


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
        return self.compatible

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


@dataclass(frozen=True)
class PreparedNoChildProfile:
    executable: ExecutableIdentity
    expected_sha256: str
    seatbelt_profile: str
    evidence: CompatibilityEvidence
    additional_seatbelt_rules: str = ""
    owner_snapshot_attestation: OwnerSnapshotLaunchAttestation | None = None
    writable_roots: tuple[WritableRootAttestation, ...] = ()


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
    canonical = _canonical_absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(canonical, flags)
    except OSError as error:
        raise ExecutableAuthenticationError(
            f"cannot open executable without following symlinks: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ExecutableAuthenticationError("executable is not a regular file")
        if before.st_size < 4 or before.st_size > MAX_EXECUTABLE_BYTES:
            raise ExecutableAuthenticationError("executable size is outside policy")
        if before.st_mode & 0o111 == 0:
            raise ExecutableAuthenticationError("executable has no execute mode bit")
        digest = hashlib.sha256()
        magic = b""
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            if len(magic) < 4:
                magic = (magic + chunk)[:4]
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ExecutableAuthenticationError(
                "executable metadata changed while it was authenticated"
            )
        current = os.stat(canonical, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
            raise ExecutableAuthenticationError(
                "executable path changed while it was authenticated"
            )
        if magic not in _MACHO_MAGICS:
            raise ExecutableAuthenticationError(
                "only a native Mach-O executable can be the authenticated target"
            )
        return ExecutableIdentity(
            path=str(canonical),
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
            uid=after.st_uid,
            gid=after.st_gid,
            size=after.st_size,
            mtime_ns=after.st_mtime_ns,
            ctime_ns=after.st_ctime_ns,
            sha256=digest.hexdigest(),
        )
    finally:
        os.close(descriptor)


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
        directory_before == directory_after == expected_directory
        and directory_path_before == directory_path_after == expected_directory
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot directory identity changed"
        )
    if not (
        executable_before == executable_after == expected_executable
        and executable_path_before == executable_path_after == expected_executable
        and executable_at_before == executable_at_after == expected_executable
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot executable identity changed"
        )
    if (
        not snapshot.directory_components
        or snapshot.directory_components[-1].identity != expected_directory
        or not snapshot.executable_components
        or snapshot.executable_components[-1].identity != expected_executable
        or snapshot.copy.destination_identity != expected_executable
        or snapshot.copy.size != expected_executable.size
        or snapshot.copy.sha256 != attestation.expected_sha256
        or snapshot.copy.max_bytes < snapshot.copy.size
        or not snapshot.copy.source_fd_only
        or not snapshot.copy.file_fsynced
        or not snapshot.copy.directory_fsynced
        or attestation.revalidation.identity != expected_executable
        or attestation.revalidation.sha256 != attestation.expected_sha256
        or attestation.revalidation.operation.before != expected_executable
        or attestation.revalidation.operation.after != expected_executable
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
        or expected_executable.link_count != 1
    ):
        raise ExecutableAuthenticationError(
            "custodied snapshot is not an owner-only 0700/0500 pair"
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
    )


def _revalidate_writable_root(
    attestation: WritableRootAttestation,
) -> WritableRootAttestation:
    if not isinstance(attestation, WritableRootAttestation):
        raise ExecutableAuthenticationError("writable root attestation is malformed")
    if not isinstance(attestation.identity, NodeIdentity) or not isinstance(
        attestation.filesystem_metadata,
        ExtendedMetadataEvidence,
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
        )
    )


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
        path = pathlib.Path(root.path)
        first_components = _path_component_keys(path)
        second_components = _path_component_keys(path)
        if first_components != second_components:
            raise ExecutableAuthenticationError(
                "writable root path changed during authentication"
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


def _require_protected_path(identity: ExecutableIdentity) -> None:
    if os.geteuid() == 0:
        raise ExecutableAuthenticationError(
            "root execution is outside the no-child-process threat model"
        )
    current = pathlib.Path("/")
    for component in pathlib.Path(identity.path).parts[1:]:
        current /= component
        metadata = os.stat(current, follow_symlinks=False)
        is_target = str(current) == identity.path
        if is_target and not stat.S_ISREG(metadata.st_mode):
            raise ExecutableAuthenticationError("target stopped being a regular file")
        if not is_target and not stat.S_ISDIR(metadata.st_mode):
            raise ExecutableAuthenticationError(
                "an executable path ancestor is not a directory"
            )
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ExecutableAuthenticationError(
                f"executable path component is not root-owned and immutable: {current}"
            )
        access_mode = os.W_OK if is_target else os.W_OK | os.X_OK
        if os.access(current, access_mode) and os.access(current, os.W_OK):
            raise ExecutableAuthenticationError(
                f"effective user can modify executable path component: {current}"
            )


def authenticate_executable(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
) -> ExecutableIdentity:
    _validate_digest(expected_sha256)
    identity = _read_executable_identity(path)
    if identity.sha256 != expected_sha256:
        raise ExecutableAuthenticationError("executable SHA-256 does not match the pin")
    _require_protected_path(identity)
    return identity


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
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
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
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
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


def _run_probe_case(
    *,
    layer: str,
    action: str,
    probe_executable: ExecutableIdentity,
    alternate_executable: ExecutableIdentity,
    profile: str,
    python_home: str,
) -> ProbeObservation:
    release_read, release_write = os.pipe()
    status_read, status_write = os.pipe()
    for descriptor in (release_read, release_write, status_read, status_write):
        os.set_inheritable(descriptor, False)
    worker_argv = [
        probe_executable.path,
        "-c",
        _PROBE_WORKER,
        action,
        alternate_executable.path,
        str(release_read),
    ]
    argv = worker_argv
    if layer in {"seatbelt", "combined"}:
        argv = [str(SANDBOX_EXEC), "-p", profile, *worker_argv]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("DYLD_", "LD_", "__XPC_DYLD_", "PYTHON"))
    }
    environment["PYTHONHOME"] = python_home
    environment["PYTHONNOUSERSITE"] = "1"
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
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            pass_fds=(release_read, status_write),
            preexec_fn=preexec_fn,
        )
    except (OSError, subprocess.SubprocessError) as error:
        os.close(release_read)
        os.close(release_write)
        os.close(status_write)
        try:
            state_payload = _read_bounded_pipe(
                status_read,
                deadline=time.monotonic() + 0.5,
            )
            state = _parse_preexec_state(state_payload) if state_payload else None
        except (OSError, TimeoutError, ValueError):
            state = None
        finally:
            os.close(status_read)
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
            pre_exec_session=state["session_id"] if state is not None else None,
            pre_exec_nproc_soft=(state["nproc_soft"] if state is not None else None),
            pre_exec_nproc_hard=(state["nproc_hard"] if state is not None else None),
            nproc_soft=state["nproc_soft"] if state is not None else None,
            nproc_hard=state["nproc_hard"] if state is not None else None,
            profile_sha256=profile_sha256,
        )

    os.close(release_read)
    os.close(status_write)
    try:
        state_payload = _read_bounded_pipe(
            status_read,
            deadline=time.monotonic() + PROBE_TIMEOUT_SECONDS,
        )
        state = _parse_preexec_state(state_payload)
    except (OSError, TimeoutError, ValueError) as error:
        state = None
        state_error = _bounded_text(f"pre-exec state is ambiguous: {error}")
    else:
        state_error = "" if state["ok"] else _bounded_text(state["detail"])
    finally:
        os.close(status_read)

    leader_error = ""
    child_process_group: int | None = None
    child_session: int | None = None
    child_start_identity: str | None = None
    try:
        child_process_group = os.getpgid(process.pid)
        child_session = os.getsid(process.pid)
        child_start_identity = process_start_identity(process.pid)
    except (OSError, ValueError) as error:
        leader_error = _bounded_text(f"cannot bind live leader identity: {error}")
    try:
        os.write(release_write, b"G")
    except OSError as error:
        if not leader_error:
            leader_error = _bounded_text(f"cannot release probe worker: {error}")
    finally:
        os.close(release_write)

    try:
        stdout, stderr = process.communicate(timeout=PROBE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
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
            pre_exec_session=state["session_id"] if state is not None else None,
            pre_exec_nproc_soft=(state["nproc_soft"] if state is not None else None),
            pre_exec_nproc_hard=(state["nproc_hard"] if state is not None else None),
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
        return replace(
            observation,
            outcome="ambiguous",
            detail=state_error or leader_error,
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
            pre_exec_session=state["session_id"] if state is not None else None,
            pre_exec_nproc_soft=(state["nproc_soft"] if state is not None else None),
            pre_exec_nproc_hard=(state["nproc_hard"] if state is not None else None),
        )
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
        worker_identity != bound_identity or worker_identity != pre_exec_identity
    ):
        return replace(
            observation,
            outcome="ambiguous",
            detail="pre-exec, parent, and post-exec leader identities differ",
            child_start_identity=child_start_identity,
            profile_sha256=profile_sha256,
            pre_exec_setsid_succeeded=state["setsid_succeeded"],
            pre_exec_pid=state["pid"],
            pre_exec_process_group=state["process_group"],
            pre_exec_session=state["session_id"],
            pre_exec_nproc_soft=state["nproc_soft"],
            pre_exec_nproc_hard=state["nproc_hard"],
        )
    return replace(
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
    probe_identity: ExecutableIdentity | None = None
    alternate_identity: ExecutableIdentity | None = None
    profile: str | None = None
    parent_before: tuple[int, int] | None = None
    parent_after: tuple[int, int] | None = None
    observations: list[ProbeObservation] = []

    if runtime.platform == "darwin" and runtime.system == "Darwin":
        try:
            sandbox_identity = _read_executable_identity(SANDBOX_EXEC)
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
        probe_identity = _read_executable_identity(probe_path)
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
                        probe_executable=probe_identity,
                        alternate_executable=alternate_identity,
                        profile=profile,
                        python_home=home,
                    )
                )
        if _read_executable_identity(probe_identity.path) != probe_identity:
            blockers.append("probe-executable-changed-during-probe")
        if _read_executable_identity(alternate_identity.path) != alternate_identity:
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
    blockers: list[str] = []
    if _runtime_fingerprint() != evidence.runtime:
        blockers.append("runtime-changed-after-probe")
    try:
        sandbox_exec = _read_executable_identity(SANDBOX_EXEC)
    except ExecutableAuthenticationError:
        sandbox_exec = None
    if sandbox_exec != evidence.sandbox_exec:
        blockers.append("sandbox-exec-changed-after-probe")
    if evidence.probe_executable is not None:
        try:
            probe_executable = _read_executable_identity(evidence.probe_executable.path)
        except ExecutableAuthenticationError:
            probe_executable = None
        if probe_executable != evidence.probe_executable:
            blockers.append("probe-executable-changed-after-probe")
    if evidence.alternate_executable is not None:
        try:
            alternate_executable = _read_executable_identity(
                evidence.alternate_executable.path
            )
        except ExecutableAuthenticationError:
            alternate_executable = None
        if alternate_executable != evidence.alternate_executable:
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
        if prepared.writable_roots:
            raise NoChildProfileError(
                "ordinary executable profile contains writable-root authority"
            )
        current = authenticate_executable(
            prepared.executable.path,
            expected_sha256=prepared.expected_sha256,
        )
        expected_profile = build_seatbelt_profile(
            prepared.executable.path,
            additional_rules=prepared.additional_seatbelt_rules,
        )
    else:
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
    if current != prepared.executable:
        raise ExecutableAuthenticationError(
            "authenticated executable identity changed after preparation"
        )
    if prepared.seatbelt_profile != expected_profile:
        raise NoChildProfileError("prepared Seatbelt profile was modified")
    return current


def _launch_child(
    prepared: PreparedNoChildProfile,
    argv: Sequence[str],
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
        sandbox_argv = [
            str(SANDBOX_EXEC),
            "-p",
            prepared.seatbelt_profile,
            *argv,
        ]
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


def _close_fd_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _open_launch_error_pipe() -> tuple[int, int]:
    error_read: int | None = None
    error_write: int | None = None
    try:
        error_read, error_write = os.pipe()
        os.set_inheritable(error_read, False)
        os.set_inheritable(error_write, False)
        return error_read, error_write
    except BaseException:
        if error_read is not None:
            _close_fd_quietly(error_read)
        if error_write is not None:
            _close_fd_quietly(error_write)
        raise


def _fork_with_launch_error_pipe() -> tuple[int, int, int]:
    error_read, error_write = _open_launch_error_pipe()
    try:
        pid = os.fork()
    except BaseException:
        _close_fd_quietly(error_read)
        _close_fd_quietly(error_write)
        raise
    if pid < 0:
        _close_fd_quietly(error_read)
        _close_fd_quietly(error_write)
        raise OSError(errno.EAGAIN, "fork returned an invalid process identifier")
    return pid, error_read, error_write


def _terminate_and_reap(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _exit_child_launch_failure(error_write_fd: int, error: BaseException) -> None:
    try:
        payload = (
            f"{getattr(error, 'errno', errno.EIO)}:{type(error).__name__}:{error}"
        ).encode("utf-8", "replace")[:4096]
        os.write(error_write_fd, payload)
    except BaseException:
        pass
    os._exit(127)


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
) -> LaunchedNoChildProcess:
    """Launch one prepared target after parent and child-side revalidation.

    For a custodied snapshot, the custody and writable-root FDs attested during
    preparation must still be open, read-only, and non-inheritable. They are used
    again in the forked child immediately before ``sandbox-exec`` and are never
    included in the target's inherited descriptor set. Only ``pass_fds`` are
    remapped to consecutive descriptors beginning at 3.
    """

    require_compatible(prepared.evidence)
    _require_live_runtime(prepared.evidence)
    if not argv or argv[0] != prepared.executable.path:
        raise ValueError("argv[0] must be the exact authenticated executable path")
    if any(not isinstance(argument, str) or "\x00" in argument for argument in argv):
        raise ValueError("argv entries must be NUL-free strings")
    launch_fds = (stdin_fd, stdout_fd, stderr_fd, *pass_fds)
    if any(type(descriptor) is not int or descriptor < 0 for descriptor in launch_fds):
        raise ValueError("launch descriptors must be non-negative integers")
    if len(set(pass_fds)) != len(pass_fds):
        raise ValueError("pass_fds must not contain duplicates")
    if prepared.owner_snapshot_attestation is not None:
        protected_fds = {
            prepared.owner_snapshot_attestation.executable_fd,
            prepared.owner_snapshot_attestation.directory_fd,
            *(root.directory_fd for root in prepared.writable_roots),
        }
        if protected_fds.intersection(launch_fds):
            raise ValueError(
                "custody and writable-root descriptors cannot be inherited"
            )
    _revalidate_prepared_profile(prepared)
    child_environment = _validated_environment(environment)
    parent_before = resource.getrlimit(resource.RLIMIT_NPROC)
    pid, error_read, error_write = _fork_with_launch_error_pipe()
    if pid == 0:
        try:
            os.close(error_read)
        except BaseException as error:
            _exit_child_launch_failure(error_write, error)
        _launch_child(
            prepared,
            argv,
            cwd=pathlib.Path(cwd),
            environment=child_environment,
            stdin_fd=stdin_fd,
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            pass_fds=pass_fds,
            error_write_fd=error_write,
        )
        os._exit(127)

    try:
        os.close(error_write)
    except BaseException:
        _terminate_and_reap(pid)
        _close_fd_quietly(error_read)
        raise
    try:
        deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
        payload = bytearray()
        os.set_blocking(error_read, False)
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
            chunk = os.read(error_read, 4096 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) >= 4096:
                raise ChildProcessError("launch failure record is oversized")
        if payload:
            os.waitpid(pid, 0)
            raise ChildProcessError(
                "no-child-process launch failed: " + payload.decode("utf-8", "replace")
            )
    except BaseException:
        _terminate_and_reap(pid)
        raise
    finally:
        os.close(error_read)
    parent_after = resource.getrlimit(resource.RLIMIT_NPROC)
    if parent_after != parent_before:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
        raise NoChildProfileError("parent RLIMIT_NPROC changed during launch")
    try:
        pgid = os.getpgid(pid)
        session_id = os.getsid(pid)
        start_identity = process_start_identity(pid)
    except (OSError, ValueError) as error:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        raise ChildProcessError(
            f"cannot bind launched no-child-process leader: {error}"
        ) from error
    if pgid != pid or session_id != pid:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        raise ChildProcessError(
            "launched process does not satisfy pid == pgid == session invariant"
        )
    profile_sha256 = hashlib.sha256(
        prepared.seatbelt_profile.encode("utf-8")
    ).hexdigest()
    return LaunchedNoChildProcess(
        pid=pid,
        pgid=pgid,
        session_id=session_id,
        start_identity=start_identity,
        profile_sha256=profile_sha256,
        passed_fd_numbers=tuple(range(3, 3 + len(pass_fds))),
        executable=prepared.executable,
        evidence=prepared.evidence,
        parent_nproc_before=parent_before,
        parent_nproc_after=parent_after,
    )
