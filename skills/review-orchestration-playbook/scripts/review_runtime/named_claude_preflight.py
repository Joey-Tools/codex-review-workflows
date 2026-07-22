from __future__ import annotations

import errno
import json
import os
import pathlib
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence, TextIO

from .claude_capabilities import (
    CLAUDE_REQUIRED_OPTIONS,
    CLAUDE_VERSION_LINE,
    ClaudeCapabilityError,
    ClaudeSafetyContractInvalid,
    validate_claude_help,
)
from .claude_provenance import (
    CLAUDE_RELEASE_KEY_FINGERPRINT,
    ClaudeReleaseArtifact,
    ClaudeProvenanceDependencyUnavailable,
    ClaudeProvenanceInconclusive,
    ClaudeProvenanceInvalid,
    ClaudeProvenanceUnavailable,
    materialize_verified_executable,
    release_artifact_urls,
    verify_claude_release,
    verify_release_executable,
)
from .claude_stream_contract import (
    ClaudeStreamContractBinding,
    ClaudeStreamContractError,
    load_stream_contract,
)
from .claude_version_policy import (
    CLAUDE_COMPATIBILITY_SPEC,
    ClaudeVersionPolicyError,
    parse_compatible_release_version,
    parse_release_version,
)
from .common import (
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    run_bounded_capture,
)


SIDE_BY_SIDE_RELATIVE_ROOT = pathlib.Path(".local/share/claude/versions")
SIDE_BY_SIDE_ENTRY_LIMIT = 1024
ACTIVE_HOME_RELATIVE_PATH = pathlib.Path(".local/bin/claude")
TRUSTED_ACTIVE_PATHS = tuple(
    pathlib.Path(value)
    for value in (
        "/opt/homebrew/bin/claude",
        "/usr/local/bin/claude",
    )
)
PROVENANCE_TEMP_ROOT = pathlib.Path("/tmp")
CAPABILITY_PROBE_CWD = pathlib.Path("/")
CAPABILITY_PROBE_TIMEOUT_SECONDS = 10.0
VERSION_PROBE_OUTPUT_LIMIT_BYTES = 16 * 1024
HELP_PROBE_OUTPUT_LIMIT_BYTES = 256 * 1024
MACHINE_OUTPUT_LIMIT_BYTES = 16 * 1024
CAPABILITY_PROBE_ENV: Mapping[str, str] = {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "CLAUDE_CODE_SAFE_MODE": "1",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PATH": "/usr/bin:/bin",
}


@dataclass(frozen=True)
class Candidate:
    path: pathlib.Path
    source: str
    version_hint: str | None = None
    path_identity: Mapping[str, int] | None = None


@dataclass(frozen=True)
class VerifiedCandidate:
    resolved_path: pathlib.Path
    artifact: ClaudeReleaseArtifact
    identity: Mapping[str, int]
    manifest_url: str
    signature_url: str
    version_probe_result: ProbeResult
    help_probe_result: ProbeResult


@dataclass(frozen=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _BoundDirectoryComponent:
    parent_descriptor: int
    name: str
    descriptor: int
    identity: Mapping[str, int]


VersionProbe = Callable[[pathlib.Path], ProbeResult]
HelpProbe = Callable[[pathlib.Path], ProbeResult]
CandidateVerifier = Callable[
    [pathlib.Path, str, VersionProbe, HelpProbe], VerifiedCandidate
]


class _ArgumentError(ValueError):
    pass


class _CandidateUnavailable(ValueError):
    pass


class _CandidateInspectionInconclusive(RuntimeError):
    pass


class _VersionProbeInconclusive(RuntimeError):
    pass


class _CapabilityProbeInconclusive(RuntimeError):
    pass


def _result(
    classification: str,
    reason: str,
    *,
    candidate: Candidate | None = None,
    resolved_path: pathlib.Path | None = None,
    declared_version: str | None = None,
    observed_version: str | None = None,
    verified: VerifiedCandidate | None = None,
    stream_contract: ClaudeStreamContractBinding | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "classification": classification,
        "reason": reason,
        "compatible_version_range": CLAUDE_COMPATIBILITY_SPEC,
    }
    if candidate is not None:
        value["source"] = candidate.source
    if resolved_path is not None:
        value["resolved_path"] = str(resolved_path)
    if declared_version is not None:
        value["declared_version"] = declared_version
    if observed_version is not None:
        value["observed_version"] = observed_version
    if verified is not None:
        value["publisher_verification"] = {
            "artifact_size": verified.artifact.size,
            "binary": verified.artifact.binary,
            "checksum": verified.artifact.checksum,
            "manifest_url": verified.manifest_url,
            "platform": verified.artifact.platform_key,
            "release_version": verified.artifact.version,
            "signature_url": verified.signature_url,
            "signer_fingerprint": CLAUDE_RELEASE_KEY_FINGERPRINT,
        }
        value["identity"] = dict(verified.identity)
        value["capability_contract"] = {
            "required_options": list(CLAUDE_REQUIRED_OPTIONS),
            "status": "accepted" if classification == "accepted" else "unaccepted",
        }
        if classification == "accepted":
            value["selected_version"] = verified.artifact.version
    if stream_contract is not None:
        value["stream_contract"] = {
            "baseline_digest": stream_contract.baseline_digest,
            "capability_digest": stream_contract.capability_digest,
            "compatibility_digest": stream_contract.compatibility_digest,
            "digest": stream_contract.digest,
            "schema_id": stream_contract.schema_id,
        }
    return value


def _identity(path: pathlib.Path) -> dict[str, int]:
    metadata = path.stat(follow_symlinks=False)
    return _identity_from_stat(metadata)


def _identity_from_stat(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "file_type": stat.S_IFMT(metadata.st_mode),
        "mode": metadata.st_mode,
        "nlink": metadata.st_nlink,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _stable_descriptor_identity(path: pathlib.Path) -> dict[str, int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        before = path.stat(follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity_from_stat(
            opened
        ) != _identity_from_stat(before):
            raise _CandidateInspectionInconclusive(
                f"candidate identity changed while binding {path}"
            )
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise _CandidateInspectionInconclusive(
            f"cannot bind a stable candidate identity for {path}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identities = {
        tuple(_identity_from_stat(value).values()) for value in (before, opened, after)
    }
    if len(identities) != 1:
        raise _CandidateInspectionInconclusive(
            f"candidate identity changed while binding {path}"
        )
    return _identity_from_stat(opened)


def _identity_from_tuple(identity: tuple[int, ...]) -> dict[str, int]:
    names = (
        "device",
        "inode",
        "file_type",
        "mode",
        "nlink",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    )
    if len(identity) != len(names):
        raise _CandidateInspectionInconclusive(
            "publisher verifier returned an invalid source identity"
        )
    return dict(zip(names, identity, strict=True))


def _verified_source_matches_signed_artifact(
    resolved: pathlib.Path,
    verified: VerifiedCandidate,
) -> bool:
    """Rehash the mutable source before accepting its preflight evidence."""

    try:
        revalidated = verify_release_executable(resolved, verified.artifact)
        current_identity = _identity(revalidated)
    except (
        ClaudeProvenanceInconclusive,
        ClaudeProvenanceInvalid,
        ClaudeProvenanceUnavailable,
        OSError,
    ):
        return False
    return revalidated == resolved and current_identity == verified.identity


def _candidate_exists(path: pathlib.Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except NotADirectoryError as error:
        raise _CandidateInspectionInconclusive(
            f"candidate path contains a non-directory ancestor: {path}"
        ) from error
    except OSError as error:
        raise _CandidateInspectionInconclusive(
            f"cannot inspect candidate path {path}"
        ) from error
    return True


def _revalidate_home_chain(
    *,
    home: pathlib.Path,
    resolved_home: pathlib.Path,
    home_descriptor: int,
    home_identity: Mapping[str, int],
    components: Sequence[_BoundDirectoryComponent],
) -> None:
    reopened_home = -1
    try:
        reopened_home = os.open(
            home,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        if any(
            _identity_from_stat(metadata) != home_identity
            for metadata in (
                os.fstat(home_descriptor),
                os.fstat(reopened_home),
                home.stat(),
                resolved_home.stat(follow_symlinks=False),
            )
        ):
            raise _CandidateInspectionInconclusive(
                "Claude Code install home changed during inspection"
            )
        if home.resolve(strict=True) != resolved_home:
            raise _CandidateInspectionInconclusive(
                "Claude Code install home resolved target changed during inspection"
            )
        for component in components:
            named = os.stat(
                component.name,
                dir_fd=component.parent_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(component.descriptor)
            if any(
                _identity_from_stat(metadata) != component.identity
                for metadata in (named, opened)
            ):
                raise _CandidateInspectionInconclusive(
                    "Claude Code install path changed during inspection"
                )
    except _CandidateInspectionInconclusive:
        raise
    except OSError as error:
        raise _CandidateInspectionInconclusive(
            "cannot revalidate the Claude Code install path"
        ) from error
    finally:
        if reopened_home >= 0:
            try:
                os.close(reopened_home)
            except OSError as error:
                raise _CandidateInspectionInconclusive(
                    "cannot close the revalidated Claude Code install home"
                ) from error


def _confirm_exact_missing_home(home: pathlib.Path) -> None:
    if not home.is_absolute() or not home.name:
        raise _CandidateInspectionInconclusive(
            f"cannot verify that Claude Code install home is absent: {home}"
        )
    parent = home.parent
    descriptor = -1
    operation_error: BaseException | None = None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        try:
            parent_before = parent.stat()
            resolved_parent = parent.resolve(strict=True)
            resolved_before = resolved_parent.stat(follow_symlinks=False)
            descriptor = os.open(parent, flags)
            opened = os.fstat(descriptor)
            parent_after = parent.stat()
        except (OSError, RuntimeError) as error:
            raise _CandidateInspectionInconclusive(
                f"cannot inspect the parent of Claude Code install home {home}"
            ) from error
        parent_identity = _identity_from_stat(opened)
        if (
            any(
                _identity_from_stat(metadata) != parent_identity
                for metadata in (parent_before, resolved_before, parent_after)
            )
            or parent.resolve(strict=True) != resolved_parent
        ):
            raise _CandidateInspectionInconclusive(
                "Claude Code install home parent changed during inspection"
            )
        for _attempt in range(2):
            try:
                os.stat(
                    home.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise _CandidateInspectionInconclusive(
                        f"cannot confirm that Claude Code install home is absent: {home}"
                    ) from error
            else:
                raise _CandidateInspectionInconclusive(
                    "Claude Code install home has a dangling or unstable path entry"
                )
            _revalidate_home_chain(
                home=parent,
                resolved_home=resolved_parent,
                home_descriptor=descriptor,
                home_identity=parent_identity,
                components=(),
            )
    except _CandidateInspectionInconclusive as error:
        operation_error = error
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                if operation_error is not None:
                    operation_error.add_note(
                        "the Claude Code install home parent descriptor could not be closed"
                    )
                else:
                    raise _CandidateInspectionInconclusive(
                        "cannot close the Claude Code install home parent"
                    ) from error


def _confirm_missing_home_component(
    *,
    name: str,
    parent_descriptor: int,
    home: pathlib.Path,
    resolved_home: pathlib.Path,
    home_descriptor: int,
    home_identity: Mapping[str, int],
    components: Sequence[_BoundDirectoryComponent],
) -> None:
    _revalidate_home_chain(
        home=home,
        resolved_home=resolved_home,
        home_descriptor=home_descriptor,
        home_identity=home_identity,
        components=components,
    )
    try:
        os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise _CandidateInspectionInconclusive(
                "cannot confirm that a Claude Code install path is absent"
            ) from error
        _revalidate_home_chain(
            home=home,
            resolved_home=resolved_home,
            home_descriptor=home_descriptor,
            home_identity=home_identity,
            components=components,
        )
        return
    raise _CandidateInspectionInconclusive(
        "a Claude Code install path appeared during absence verification"
    )


def _revalidate_absolute_chain(
    *,
    root_descriptor: int,
    root_identity: Mapping[str, int],
    components: Sequence[_BoundDirectoryComponent],
) -> None:
    try:
        if any(
            _identity_from_stat(metadata) != root_identity
            for metadata in (os.fstat(root_descriptor), os.stat("/"))
        ):
            raise _CandidateInspectionInconclusive(
                "trusted Claude Code install root changed during inspection"
            )
        for component in components:
            named = os.stat(
                component.name,
                dir_fd=component.parent_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(component.descriptor)
            if any(
                _identity_from_stat(metadata) != component.identity
                for metadata in (named, opened)
            ):
                raise _CandidateInspectionInconclusive(
                    "trusted Claude Code install path changed during inspection"
                )
    except _CandidateInspectionInconclusive:
        raise
    except OSError as error:
        raise _CandidateInspectionInconclusive(
            "cannot revalidate the trusted Claude Code install path"
        ) from error


def _confirm_missing_absolute_component(
    *,
    name: str,
    parent_descriptor: int,
    root_descriptor: int,
    root_identity: Mapping[str, int],
    components: Sequence[_BoundDirectoryComponent],
) -> None:
    _revalidate_absolute_chain(
        root_descriptor=root_descriptor,
        root_identity=root_identity,
        components=components,
    )
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise _CandidateInspectionInconclusive(
                "cannot confirm that a trusted Claude Code install path is absent"
            ) from error
        _revalidate_absolute_chain(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            components=components,
        )
        return
    raise _CandidateInspectionInconclusive(
        "a trusted Claude Code install path appeared during absence verification"
    )


def _select_trusted_candidate(path: pathlib.Path) -> Candidate | None:
    parts = path.parts
    if not path.is_absolute() or len(parts) < 2 or parts[0] != "/":
        raise _CandidateInspectionInconclusive(
            f"trusted Claude Code install path is not canonical: {path}"
        )
    names = parts[1:]
    if any(name in {"", ".", ".."} for name in names):
        raise _CandidateInspectionInconclusive(
            f"trusted Claude Code install path is not canonical: {path}"
        )
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    )
    component_flags = directory_flags | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    components: list[_BoundDirectoryComponent] = []
    operation_error: BaseException | None = None
    try:
        try:
            root_descriptor = os.open("/", directory_flags)
            descriptors.append(root_descriptor)
            root_identity = _identity_from_stat(os.fstat(root_descriptor))
        except OSError as error:
            raise _CandidateInspectionInconclusive(
                "cannot open the trusted Claude Code install root"
            ) from error

        for name in names[:-1]:
            parent_descriptor = descriptors[-1]
            try:
                before = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                if error.errno == errno.ENOENT:
                    _confirm_missing_absolute_component(
                        name=name,
                        parent_descriptor=parent_descriptor,
                        root_descriptor=root_descriptor,
                        root_identity=root_identity,
                        components=components,
                    )
                    return None
                raise _CandidateInspectionInconclusive(
                    f"cannot inspect trusted Claude Code install path {path}"
                ) from error
            if not stat.S_ISDIR(before.st_mode):
                raise _CandidateInspectionInconclusive(
                    "trusted Claude Code install path contains a non-directory component"
                )
            try:
                descriptor = os.open(
                    name,
                    component_flags,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(descriptor)
                opened = os.fstat(descriptor)
                after = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise _CandidateInspectionInconclusive(
                    f"cannot open trusted Claude Code install path {path}"
                ) from error
            identity = _identity_from_stat(opened)
            if any(
                _identity_from_stat(metadata) != identity
                for metadata in (before, after)
            ) or not stat.S_ISDIR(opened.st_mode):
                raise _CandidateInspectionInconclusive(
                    "trusted Claude Code install path changed while opening"
                )
            components.append(
                _BoundDirectoryComponent(
                    parent_descriptor=parent_descriptor,
                    name=name,
                    descriptor=descriptor,
                    identity=identity,
                )
            )

        candidate_name = names[-1]
        parent_descriptor = descriptors[-1]
        try:
            candidate_metadata = os.stat(
                candidate_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                _confirm_missing_absolute_component(
                    name=candidate_name,
                    parent_descriptor=parent_descriptor,
                    root_descriptor=root_descriptor,
                    root_identity=root_identity,
                    components=components,
                )
                return None
            raise _CandidateInspectionInconclusive(
                f"cannot inspect trusted Claude Code candidate {path}"
            ) from error
        candidate_identity = _identity_from_stat(candidate_metadata)
        _revalidate_absolute_chain(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            components=components,
        )
        try:
            candidate_after = os.stat(
                candidate_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _CandidateInspectionInconclusive(
                f"cannot revalidate trusted Claude Code candidate {path}"
            ) from error
        if _identity_from_stat(candidate_after) != candidate_identity:
            raise _CandidateInspectionInconclusive(
                "trusted Claude Code candidate changed during selection"
            )
        return Candidate(
            path,
            "active-installed",
            path_identity=candidate_identity,
        )
    except _CandidateInspectionInconclusive as error:
        operation_error = error
        raise
    finally:
        cleanup_error: OSError | None = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_error = error
        if cleanup_error is not None:
            if operation_error is not None:
                operation_error.add_note(
                    "a trusted Claude Code path descriptor could not be closed"
                )
            else:
                raise _CandidateInspectionInconclusive(
                    "cannot close the trusted Claude Code install path"
                ) from cleanup_error


def _active_home_candidate(
    *,
    home: pathlib.Path,
    resolved_home: pathlib.Path,
    home_descriptor: int,
    home_identity: Mapping[str, int],
    component_flags: int,
    priority_components: Sequence[_BoundDirectoryComponent],
) -> Candidate | None:
    descriptors: list[int] = []
    components: list[_BoundDirectoryComponent] = []
    operation_error: BaseException | None = None
    try:
        parent_descriptor = home_descriptor
        for name in ACTIVE_HOME_RELATIVE_PATH.parts[:-1]:
            try:
                before = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                if error.errno == errno.ENOENT:
                    _confirm_missing_home_component(
                        name=name,
                        parent_descriptor=parent_descriptor,
                        home=home,
                        resolved_home=resolved_home,
                        home_descriptor=home_descriptor,
                        home_identity=home_identity,
                        components=(*priority_components, *components),
                    )
                    return None
                raise _CandidateInspectionInconclusive(
                    "cannot inspect the active Claude Code install path"
                ) from error
            if not stat.S_ISDIR(before.st_mode):
                raise _CandidateInspectionInconclusive(
                    "the active Claude Code install path contains a "
                    "non-directory component"
                )
            try:
                descriptor = os.open(
                    name,
                    component_flags,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(descriptor)
                opened = os.fstat(descriptor)
                after = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise _CandidateInspectionInconclusive(
                    "cannot open the active Claude Code install path"
                ) from error
            identity = _identity_from_stat(opened)
            if any(
                _identity_from_stat(metadata) != identity
                for metadata in (before, after)
            ) or not stat.S_ISDIR(opened.st_mode):
                raise _CandidateInspectionInconclusive(
                    "the active Claude Code install path changed while opening"
                )
            components.append(
                _BoundDirectoryComponent(
                    parent_descriptor=parent_descriptor,
                    name=name,
                    descriptor=descriptor,
                    identity=identity,
                )
            )
            parent_descriptor = descriptor

        candidate_name = ACTIVE_HOME_RELATIVE_PATH.name
        try:
            candidate_metadata = os.stat(
                candidate_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                _confirm_missing_home_component(
                    name=candidate_name,
                    parent_descriptor=parent_descriptor,
                    home=home,
                    resolved_home=resolved_home,
                    home_descriptor=home_descriptor,
                    home_identity=home_identity,
                    components=(*priority_components, *components),
                )
                return None
            raise _CandidateInspectionInconclusive(
                "cannot inspect the active Claude Code candidate"
            ) from error
        candidate_identity = _identity_from_stat(candidate_metadata)
        _revalidate_home_chain(
            home=home,
            resolved_home=resolved_home,
            home_descriptor=home_descriptor,
            home_identity=home_identity,
            components=(*priority_components, *components),
        )
        try:
            candidate_after = os.stat(
                candidate_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _CandidateInspectionInconclusive(
                "cannot revalidate the active Claude Code candidate"
            ) from error
        if _identity_from_stat(candidate_after) != candidate_identity:
            raise _CandidateInspectionInconclusive(
                "the active Claude Code candidate changed during selection"
            )
        return Candidate(
            resolved_home / ACTIVE_HOME_RELATIVE_PATH,
            "active-installed",
            path_identity=candidate_identity,
        )
    except _CandidateInspectionInconclusive as error:
        operation_error = error
        raise
    finally:
        cleanup_error: OSError | None = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_error = error
        if cleanup_error is not None:
            if operation_error is not None:
                operation_error.add_note(
                    "an active Claude Code path descriptor could not be closed"
                )
            else:
                raise _CandidateInspectionInconclusive(
                    "cannot close the active Claude Code install path"
                ) from cleanup_error


def _select_home_candidate(home: pathlib.Path) -> Candidate | None:
    if not home.is_absolute():
        raise _CandidateInspectionInconclusive(
            f"Claude Code install home must be absolute: {home}"
        )
    home_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    )
    component_flags = home_flags | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    components: list[_BoundDirectoryComponent] = []
    operation_error: BaseException | None = None
    try:
        try:
            home_before = home.stat()
        except OSError as error:
            if error.errno == errno.ENOENT:
                _confirm_exact_missing_home(home)
                return None
            raise _CandidateInspectionInconclusive(
                f"cannot inspect Claude Code install home {home}"
            ) from error
        if not stat.S_ISDIR(home_before.st_mode):
            raise _CandidateInspectionInconclusive(
                f"Claude Code install home is not a directory: {home}"
            )
        try:
            home_descriptor = os.open(home, home_flags)
            descriptors.append(home_descriptor)
            home_opened = os.fstat(home_descriptor)
            home_after = home.stat()
        except OSError as error:
            raise _CandidateInspectionInconclusive(
                f"cannot open Claude Code install home {home}"
            ) from error
        home_identity = _identity_from_stat(home_opened)
        try:
            resolved_home = home.resolve(strict=True)
            resolved_metadata = resolved_home.stat(follow_symlinks=False)
        except (OSError, RuntimeError) as error:
            raise _CandidateInspectionInconclusive(
                "cannot resolve the Claude Code install home"
            ) from error
        if any(
            _identity_from_stat(metadata) != home_identity
            for metadata in (home_before, home_after, resolved_metadata)
        ):
            raise _CandidateInspectionInconclusive(
                "Claude Code install home changed while opening"
            )
        root = resolved_home / SIDE_BY_SIDE_RELATIVE_ROOT

        for name in SIDE_BY_SIDE_RELATIVE_ROOT.parts:
            parent_descriptor = descriptors[-1]
            try:
                before = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                if error.errno == errno.ENOENT:
                    _confirm_missing_home_component(
                        name=name,
                        parent_descriptor=parent_descriptor,
                        home=home,
                        resolved_home=resolved_home,
                        home_descriptor=home_descriptor,
                        home_identity=home_identity,
                        components=components,
                    )
                    return _active_home_candidate(
                        home=home,
                        resolved_home=resolved_home,
                        home_descriptor=home_descriptor,
                        home_identity=home_identity,
                        component_flags=component_flags,
                        priority_components=components,
                    )
                raise _CandidateInspectionInconclusive(
                    f"cannot inspect side-by-side Claude Code installs under {root}"
                ) from error
            if not stat.S_ISDIR(before.st_mode):
                raise _CandidateInspectionInconclusive(
                    "side-by-side Claude Code install path contains a "
                    "non-directory component"
                )
            try:
                descriptor = os.open(
                    name,
                    component_flags,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(descriptor)
                opened = os.fstat(descriptor)
                after = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise _CandidateInspectionInconclusive(
                    f"cannot open side-by-side Claude Code installs under {root}"
                ) from error
            identity = _identity_from_stat(opened)
            if any(
                _identity_from_stat(metadata) != identity
                for metadata in (before, after)
            ) or not stat.S_ISDIR(opened.st_mode):
                raise _CandidateInspectionInconclusive(
                    "side-by-side Claude Code install path changed while opening"
                )
            components.append(
                _BoundDirectoryComponent(
                    parent_descriptor=parent_descriptor,
                    name=name,
                    descriptor=descriptor,
                    identity=identity,
                )
            )

        compatible: list[
            tuple[tuple[int, int, int], pathlib.Path, Mapping[str, int]]
        ] = []
        count = 0
        with os.scandir(descriptors[-1]) as entries:
            for entry in entries:
                count += 1
                if count > SIDE_BY_SIDE_ENTRY_LIMIT:
                    raise _CandidateInspectionInconclusive(
                        "side-by-side Claude Code install count exceeds the bounded limit"
                    )
                try:
                    parsed = parse_compatible_release_version(entry.name)
                except ClaudeVersionPolicyError:
                    continue
                try:
                    entry_metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise _CandidateInspectionInconclusive(
                        "cannot inspect a side-by-side Claude Code candidate"
                    ) from error
                compatible.append(
                    (parsed, root / entry.name, _identity_from_stat(entry_metadata))
                )
        _revalidate_home_chain(
            home=home,
            resolved_home=resolved_home,
            home_descriptor=home_descriptor,
            home_identity=home_identity,
            components=components,
        )
        if not compatible:
            return _active_home_candidate(
                home=home,
                resolved_home=resolved_home,
                home_descriptor=home_descriptor,
                home_identity=home_identity,
                component_flags=component_flags,
                priority_components=components,
            )
        _parsed, selected, selected_identity = max(
            compatible,
            key=lambda item: item[0],
        )
        try:
            selected_after = os.stat(
                selected.name,
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
        except OSError as error:
            raise _CandidateInspectionInconclusive(
                "cannot revalidate the selected side-by-side Claude Code candidate"
            ) from error
        if _identity_from_stat(selected_after) != selected_identity:
            raise _CandidateInspectionInconclusive(
                "the selected side-by-side Claude Code candidate changed"
            )
        return Candidate(
            selected,
            "side-by-side-compatible",
            selected.name,
            selected_identity,
        )
    except _CandidateInspectionInconclusive as error:
        operation_error = error
        raise
    except OSError as error:
        inconclusive = _CandidateInspectionInconclusive(
            f"cannot enumerate side-by-side Claude Code installs under {root}"
        )
        operation_error = inconclusive
        raise inconclusive from error
    finally:
        cleanup_error: OSError | None = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_error = error
        if cleanup_error is not None:
            if operation_error is not None:
                operation_error.add_note(
                    "a side-by-side Claude Code path descriptor could not be closed"
                )
            else:
                raise _CandidateInspectionInconclusive(
                    "cannot close the side-by-side Claude Code install path"
                ) from cleanup_error


def select_candidate(
    *,
    explicit_path: pathlib.Path | None,
    explicit_version: str | None = None,
    home: pathlib.Path | None,
) -> Candidate | None:
    if explicit_path is not None:
        if not explicit_path.is_absolute():
            raise _ArgumentError("--claude-path must be absolute")
        return Candidate(explicit_path, "explicit-override", explicit_version)
    if explicit_version is not None:
        raise _ArgumentError("--claude-version requires --claude-path")

    if home is not None:
        home_candidate = _select_home_candidate(home)
        if home_candidate is not None:
            return home_candidate

    for active in TRUSTED_ACTIVE_PATHS:
        trusted_candidate = _select_trusted_candidate(active)
        if trusted_candidate is not None:
            return trusted_candidate
    return None


def _resolve_candidate(candidate: Candidate) -> pathlib.Path:
    if not _candidate_exists(candidate.path):
        if candidate.source != "explicit-override":
            raise _CandidateInspectionInconclusive(str(candidate.path))
        raise _CandidateUnavailable(str(candidate.path))
    try:
        path_before = candidate.path.lstat()
        if (
            candidate.path_identity is not None
            and _identity_from_stat(path_before) != candidate.path_identity
        ):
            raise _CandidateInspectionInconclusive(
                f"selected candidate path identity changed: {candidate.path}"
            )
        resolved = candidate.path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
        path_after = candidate.path.lstat()
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as error:
        raise _CandidateInspectionInconclusive(str(candidate.path)) from error
    except OSError as error:
        raise _CandidateInspectionInconclusive(str(candidate.path)) from error
    if candidate.path_identity is not None and any(
        _identity_from_stat(value) != candidate.path_identity
        for value in (path_before, path_after)
    ):
        raise _CandidateInspectionInconclusive(
            f"selected candidate path identity changed: {candidate.path}"
        )
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise _CandidateUnavailable(str(resolved))
    return resolved


def _declared_installer_version(path: pathlib.Path) -> str | None:
    if path.parent.name != "versions" or not path.name or len(path.name) > 32:
        return None
    try:
        parse_release_version(path.name)
    except ClaudeVersionPolicyError:
        return None
    return path.name


def _darwin_platform_key(path: pathlib.Path) -> str:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        before = path.stat(follow_symlinks=False)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            opened_before = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_before.st_mode) or _identity_from_stat(
                opened_before
            ) != _identity_from_stat(before):
                raise _CandidateInspectionInconclusive(
                    f"candidate identity changed while inspecting {path}"
                )
            header = handle.read(8)
            opened_after = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise _CandidateInspectionInconclusive(str(path)) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identities = {
        tuple(_identity_from_stat(value).values())
        for value in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1:
        raise _CandidateInspectionInconclusive(
            f"candidate identity changed while inspecting {path}"
        )
    if len(header) != 8:
        raise _CandidateUnavailable("truncated native executable")
    if header[:4] == b"\xcf\xfa\xed\xfe":
        byteorder = "little"
    elif header[:4] == b"\xfe\xed\xfa\xcf":
        byteorder = "big"
    else:
        raise _CandidateUnavailable("candidate is not a thin 64-bit Mach-O")
    cpu_type = int.from_bytes(header[4:8], byteorder=byteorder, signed=False)
    if cpu_type == 0x0100000C:
        return "darwin-arm64"
    if cpu_type == 0x01000007:
        return "darwin-x64"
    raise _CandidateUnavailable("candidate has an unsupported Mach-O architecture")


def _platform_key(path: pathlib.Path) -> str:
    if sys.platform == "darwin":
        return _darwin_platform_key(path)
    if sys.platform.startswith("linux"):
        from .claude_linux import (
            LinuxRuntimeError,
            LinuxRuntimeInspectionInconclusive,
            detect_host,
            validate_claude_executable,
        )

        try:
            info = validate_claude_executable(path, detect_host(env={}))
            return info.manifest_platform_key
        except LinuxRuntimeInspectionInconclusive as error:
            raise _CandidateInspectionInconclusive(str(error)) from error
        except LinuxRuntimeError as error:
            raise _CandidateUnavailable(str(error)) from error
    raise _CandidateUnavailable(f"unsupported host platform: {sys.platform}")


def verify_publisher_candidate(
    path: pathlib.Path,
    release_version: str,
    version_probe: VersionProbe,
    help_probe: HelpProbe,
) -> VerifiedCandidate:
    """Verify one compatible signed artifact before probing its private snapshot."""

    parse_compatible_release_version(release_version)
    platform_key = _platform_key(path)
    try:
        provenance_temp_root = PROVENANCE_TEMP_ROOT.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise _CandidateInspectionInconclusive(
            "cannot resolve the provenance temporary root"
        ) from error
    with tempfile.TemporaryDirectory(
        prefix="named-claude-provenance-",
        dir=provenance_temp_root,
    ) as temporary:
        private_root = pathlib.Path(temporary).resolve(strict=True)
        verified = verify_claude_release(
            path,
            version=release_version,
            platform_key=platform_key,
            gpg_temp_root=private_root,
        )
        try:
            expected_resolved = path.resolve(strict=True)
            returned_resolved = verified.executable.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise _CandidateInspectionInconclusive(
                "publisher verifier returned an unresolvable executable path"
            ) from error
        if (
            returned_resolved != expected_resolved
            or verified.artifact.version != release_version
            or verified.artifact.platform_key != platform_key
            or verified.artifact.binary != "claude"
            or (verified.manifest_url, verified.signature_url)
            != release_artifact_urls(release_version)
        ):
            raise ClaudeProvenanceInvalid(
                "publisher verifier returned incoherent release evidence"
            )
        if verified.source_identity is None:
            raise _CandidateInspectionInconclusive(
                "publisher verifier did not return the descriptor-bound source identity"
            )
        resolved = returned_resolved
        source_identity = _identity_from_tuple(verified.source_identity)
        try:
            snapshot = materialize_verified_executable(
                verified,
                private_root / "executable-snapshot",
            )
        except (
            ClaudeProvenanceInconclusive,
            ClaudeProvenanceInvalid,
            ClaudeProvenanceUnavailable,
        ) as error:
            raise ClaudeProvenanceInconclusive(
                "cannot safely materialize the verified executable snapshot"
            ) from error
        try:
            version_completed = version_probe(snapshot.executable)
        except (
            OSError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
            ReviewTimeoutError,
        ) as error:
            raise _VersionProbeInconclusive(str(error)) from error
        except Exception as error:
            raise _VersionProbeInconclusive(str(error)) from error
        try:
            after_probe = verify_release_executable(
                snapshot.executable,
                snapshot.artifact,
            )
        except (
            ClaudeProvenanceInconclusive,
            ClaudeProvenanceInvalid,
            ClaudeProvenanceUnavailable,
        ) as error:
            raise _CandidateInspectionInconclusive(
                "verified executable snapshot changed during the version probe"
            ) from error
        if after_probe != snapshot.executable:
            raise _CandidateInspectionInconclusive(
                "verified executable snapshot path changed during the version probe"
            )
        try:
            help_completed = help_probe(snapshot.executable)
        except (
            OSError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
            ReviewTimeoutError,
        ) as error:
            raise _CapabilityProbeInconclusive(str(error)) from error
        except Exception as error:
            raise _CapabilityProbeInconclusive(str(error)) from error
        try:
            after_help_probe = verify_release_executable(
                snapshot.executable,
                snapshot.artifact,
            )
        except (
            ClaudeProvenanceInconclusive,
            ClaudeProvenanceInvalid,
            ClaudeProvenanceUnavailable,
        ) as error:
            raise _CandidateInspectionInconclusive(
                "verified executable snapshot changed during the capability probe"
            ) from error
        if after_help_probe != snapshot.executable:
            raise _CandidateInspectionInconclusive(
                "verified executable snapshot path changed during the capability probe"
            )
    return VerifiedCandidate(
        resolved_path=resolved,
        artifact=verified.artifact,
        identity=source_identity,
        manifest_url=verified.manifest_url,
        signature_url=verified.signature_url,
        version_probe_result=version_completed,
        help_probe_result=help_completed,
    )


def _probe_verified_command(
    path: pathlib.Path,
    argument: str,
    *,
    output_limit_bytes: int,
) -> ProbeResult:
    completed = run_bounded_capture(
        (str(path), argument),
        cwd=CAPABILITY_PROBE_CWD,
        env=dict(CAPABILITY_PROBE_ENV),
        stdin=None,
        timeout_seconds=CAPABILITY_PROBE_TIMEOUT_SECONDS,
        stdout_limit_bytes=output_limit_bytes,
        stderr_limit_bytes=output_limit_bytes,
    )
    return ProbeResult(
        completed.returncode,
        bytes(completed.stdout),
        bytes(completed.stderr),
    )


def probe_verified_version(path: pathlib.Path) -> ProbeResult:
    return _probe_verified_command(
        path,
        "--version",
        output_limit_bytes=VERSION_PROBE_OUTPUT_LIMIT_BYTES,
    )


def probe_verified_help(path: pathlib.Path) -> ProbeResult:
    return _probe_verified_command(
        path,
        "--help",
        output_limit_bytes=HELP_PROBE_OUTPUT_LIMIT_BYTES,
    )


def _parse_version(stdout: bytes, stderr: bytes) -> str:
    if stderr.strip():
        raise ValueError("version probe wrote to stderr")
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("version probe output is not UTF-8") from error
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    if len(lines) != 1:
        raise ValueError("version probe output must contain exactly one non-empty line")
    match = CLAUDE_VERSION_LINE.fullmatch(lines[0])
    if match is None:
        raise ValueError("version probe output does not match the reviewed format")
    version = ".".join(match.group(name) for name in ("major", "minor", "patch"))
    try:
        parsed = parse_release_version(version)
    except ClaudeVersionPolicyError as error:
        raise ValueError(
            "version probe output does not match the reviewed format"
        ) from error
    return ".".join(str(component) for component in parsed)


def _validate_help_probe(completed: ProbeResult) -> None:
    if completed.returncode != 0 or completed.stderr.strip():
        raise _CapabilityProbeInconclusive("capability probe did not complete cleanly")
    try:
        help_text = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise _CapabilityProbeInconclusive(
            "capability probe output is not UTF-8"
        ) from error
    validate_claude_help(help_text)


def preflight(
    *,
    explicit_path: pathlib.Path | None = None,
    explicit_version: str | None = None,
    home: pathlib.Path | None = None,
    verifier: CandidateVerifier = verify_publisher_candidate,
    version_probe: VersionProbe = probe_verified_version,
    help_probe: HelpProbe = probe_verified_help,
) -> dict[str, object]:
    try:
        candidate = select_candidate(
            explicit_path=explicit_path,
            explicit_version=explicit_version,
            home=home,
        )
    except _CandidateInspectionInconclusive:
        return _result("inconclusive", "candidate-inspection-inconclusive")
    if candidate is None:
        return _result("blocked", "compatible-version-unavailable")

    try:
        resolved = _resolve_candidate(candidate)
    except _CandidateInspectionInconclusive:
        return _result(
            "inconclusive",
            "candidate-inspection-inconclusive",
            candidate=candidate,
        )
    except _CandidateUnavailable:
        return _result(
            "blocked",
            "compatible-version-unavailable",
            candidate=candidate,
        )

    path_version = _declared_installer_version(resolved)
    declared_version = candidate.version_hint or path_version
    version_reason: str | None = None
    if candidate.version_hint is not None and path_version is not None:
        if candidate.version_hint != path_version:
            version_reason = "version-declaration-conflict"
    if declared_version is None:
        version_reason = "version-declaration-unavailable"
    elif version_reason is None:
        try:
            parse_compatible_release_version(declared_version)
        except ClaudeVersionPolicyError:
            version_reason = "unsupported-version"
    if version_reason is not None:
        try:
            bound_identity = _stable_descriptor_identity(resolved)
            after_resolved = _resolve_candidate(candidate)
            after_identity = _stable_descriptor_identity(after_resolved)
        except (_CandidateUnavailable, _CandidateInspectionInconclusive):
            return _result(
                "inconclusive",
                "executable-identity-drift",
                candidate=candidate,
                resolved_path=resolved,
                declared_version=declared_version,
            )
        if after_resolved != resolved or after_identity != bound_identity:
            return _result(
                "inconclusive",
                "executable-identity-drift",
                candidate=candidate,
                resolved_path=resolved,
                declared_version=declared_version,
            )
        return _result(
            "blocked",
            version_reason,
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
        )

    try:
        verified = verifier(
            resolved,
            declared_version,
            version_probe,
            help_probe,
        )
    except _CandidateInspectionInconclusive:
        return _result(
            "inconclusive",
            "candidate-inspection-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
        )
    except _CandidateUnavailable:
        return _result(
            "blocked",
            "compatible-version-unavailable",
            candidate=candidate,
            resolved_path=resolved,
        )
    except _VersionProbeInconclusive:
        return _result(
            "inconclusive",
            "version-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
        )
    except _CapabilityProbeInconclusive:
        return _result(
            "inconclusive",
            "capability-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
        )
    except ClaudeProvenanceInvalid:
        return _result(
            "blocked",
            "publisher-verification-failed",
            candidate=candidate,
            resolved_path=resolved,
        )
    except (
        ClaudeProvenanceDependencyUnavailable,
        ClaudeProvenanceInconclusive,
        ClaudeProvenanceUnavailable,
        OSError,
    ):
        return _result(
            "inconclusive",
            "publisher-verification-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
        )
    except Exception:
        return _result(
            "inconclusive",
            "publisher-verification-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
        )
    try:
        identity_matches = verified.identity == _identity(resolved)
    except Exception:
        identity_matches = False
    if verified.resolved_path != resolved or not identity_matches:
        return _result(
            "inconclusive",
            "executable-identity-drift",
            candidate=candidate,
            resolved_path=resolved,
            verified=verified,
        )

    completed = verified.version_probe_result
    if completed.returncode != 0:
        return _result(
            "inconclusive",
            "version-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            verified=verified,
        )
    try:
        observed_version = _parse_version(completed.stdout, completed.stderr)
    except ValueError:
        return _result(
            "inconclusive",
            "version-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            verified=verified,
        )

    try:
        after_resolved = _resolve_candidate(candidate)
    except (_CandidateUnavailable, _CandidateInspectionInconclusive):
        after_resolved = pathlib.Path()
    if after_resolved != resolved or not _verified_source_matches_signed_artifact(
        after_resolved,
        verified,
    ):
        return _result(
            "inconclusive",
            "executable-identity-drift",
            candidate=candidate,
            resolved_path=resolved,
            observed_version=observed_version,
            verified=verified,
        )
    if (
        verified.artifact.version != declared_version
        or observed_version != declared_version
    ):
        return _result(
            "blocked",
            "signed-version-identity-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
            observed_version=observed_version,
            verified=verified,
        )
    try:
        _validate_help_probe(verified.help_probe_result)
    except _CapabilityProbeInconclusive:
        return _result(
            "inconclusive",
            "capability-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
            observed_version=observed_version,
            verified=verified,
        )
    except (ClaudeCapabilityError, ClaudeSafetyContractInvalid):
        return _result(
            "blocked",
            "capability-contract-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
            observed_version=observed_version,
            verified=verified,
        )
    try:
        stream_contract, _compatibility_raw, _baseline_raw = load_stream_contract()
    except ClaudeStreamContractError:
        return _result(
            "inconclusive",
            "stream-contract-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
            observed_version=observed_version,
            verified=verified,
        )
    return _result(
        "accepted",
        "compatible-version-selected",
        candidate=candidate,
        resolved_path=resolved,
        declared_version=declared_version,
        observed_version=observed_version,
        verified=verified,
        stream_contract=stream_contract,
    )


def _parse_args(argv: Sequence[str]) -> tuple[pathlib.Path | None, str | None]:
    if not argv:
        return None, None
    if len(argv) not in (2, 4) or len(set(argv[::2])) != len(argv[::2]):
        raise _ArgumentError(
            "expected no arguments or --claude-path ABSOLUTE_PATH "
            "[--claude-version RELEASE]"
        )
    values = dict(zip(argv[::2], argv[1::2], strict=True))
    if frozenset(values) - {"--claude-path", "--claude-version"}:
        raise _ArgumentError("unknown argument")
    raw_path = values.get("--claude-path")
    if not raw_path:
        raise _ArgumentError("--claude-path is required for an explicit candidate")
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        raise _ArgumentError("--claude-path must be absolute")
    version = values.get("--claude-version")
    if version == "":
        raise _ArgumentError("--claude-version must not be empty")
    return candidate, version


def _machine_json(value: Mapping[str, object]) -> bytes:
    encoded = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if len(encoded) <= MACHINE_OUTPUT_LIMIT_BYTES:
        return encoded
    return b'{"classification":"inconclusive","reason":"output-limit"}\n'


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    selection_home: pathlib.Path | None = None,
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    destination = sys.stdout if stdout is None else stdout
    try:
        explicit_path, explicit_version = _parse_args(arguments)
        home_value = os.environ.get("HOME") if selection_home is None else None
        home = (
            selection_home
            if selection_home is not None
            else (pathlib.Path(home_value) if home_value else None)
        )
        value = preflight(
            explicit_path=explicit_path,
            explicit_version=explicit_version,
            home=home,
        )
    except _ArgumentError:
        value = _result("inconclusive", "invalid-arguments")
    except Exception:
        value = _result("inconclusive", "preflight-internal-error")
    payload = _machine_json(value).decode("utf-8")
    destination.write(payload)
    classification = value.get("classification")
    if classification == "accepted":
        return 0
    if classification == "blocked":
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover - wrapper is the public entry point
    raise SystemExit(main())
