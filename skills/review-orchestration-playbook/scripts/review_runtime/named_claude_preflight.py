from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence, TextIO

from .claude_capabilities import (
    ClaudeCapabilityError,
    ClaudeCapabilities,
    ClaudeSafetyContractInvalid,
    validate_claude_capabilities,
)
from .claude_provenance import (
    CLAUDE_MAXIMUM_RELEASE,
    CLAUDE_MINIMUM_RELEASE,
    ClaudeReleaseArtifact,
    VerifiedClaudeExecutable,
    ClaudeProvenanceDependencyUnavailable,
    ClaudeProvenanceInconclusive,
    ClaudeProvenanceInvalid,
    ClaudeProvenanceUnavailable,
    materialize_verified_executable,
    require_supported_release_version,
    verify_claude_release,
    verify_release_executable,
)
from .common import (
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    run_bounded_capture,
)


SUPPORTED_CLAUDE_VERSION_MINIMUM = ".".join(
    str(component) for component in CLAUDE_MINIMUM_RELEASE
)
SUPPORTED_CLAUDE_VERSION_MAXIMUM_EXCLUSIVE = ".".join(
    str(component) for component in CLAUDE_MAXIMUM_RELEASE
)
ACTIVE_HOME_RELATIVE_PATH = pathlib.Path(".local/bin/claude")
TRUSTED_ACTIVE_PATHS = tuple(
    pathlib.Path(value)
    for value in (
        "/opt/homebrew/bin/claude",
        "/usr/local/bin/claude",
    )
)
PROVENANCE_TEMP_ROOT = pathlib.Path("/tmp")
VERSION_PROBE_CWD = pathlib.Path("/")
VERSION_PROBE_TIMEOUT_SECONDS = 10.0
VERSION_PROBE_OUTPUT_LIMIT_BYTES = 16 * 1024
CAPABILITY_PROBE_TIMEOUT_SECONDS = 10.0
CAPABILITY_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
MACHINE_OUTPUT_LIMIT_BYTES = 16 * 1024
VERSION_PROBE_ENV: Mapping[str, str] = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PATH": "/usr/bin:/bin",
}
_VERSION_OUTPUT = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:[ \t]+\(Claude Code\))?[ \t]*\n?$"
)
_RELEASE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


@dataclass(frozen=True)
class Candidate:
    path: pathlib.Path
    source: str
    version_hint: str | None = None


@dataclass(frozen=True)
class VerifiedCandidate:
    resolved_path: pathlib.Path
    version: str
    platform_key: str
    checksum: str
    artifact_size: int
    identity: Mapping[str, int]
    probe_result: ProbeResult
    capabilities: ClaudeCapabilities | None


@dataclass(frozen=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes


VersionProbe = Callable[[pathlib.Path], ProbeResult]
CapabilityProbe = Callable[[pathlib.Path], ProbeResult]
CandidateVerifier = Callable[
    [pathlib.Path, str, VersionProbe, CapabilityProbe], VerifiedCandidate
]


class _ArgumentError(ValueError):
    pass


class _CandidateUnavailable(ValueError):
    pass


class _CandidateInspectionInconclusive(RuntimeError):
    pass


class _ExecutableIdentityDrift(RuntimeError):
    pass


class _VersionProbeInconclusive(RuntimeError):
    pass


class _CapabilityProbeInconclusive(RuntimeError):
    pass


class _CapabilityContractRejected(RuntimeError):
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
) -> dict[str, object]:
    value: dict[str, object] = {
        "classification": classification,
        "reason": reason,
        "supported_version_range": {
            "minimum": SUPPORTED_CLAUDE_VERSION_MINIMUM,
            "maximum_exclusive": SUPPORTED_CLAUDE_VERSION_MAXIMUM_EXCLUSIVE,
        },
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
            "artifact_size": verified.artifact_size,
            "checksum": verified.checksum,
            "platform": verified.platform_key,
            "version": verified.version,
        }
        value["identity"] = dict(verified.identity)
        if verified.capabilities is not None:
            value["capability_verification"] = {
                "required_options": list(verified.capabilities.required_options),
                "safe_mode": "accepted",
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
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = path.stat(follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
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

    artifact = ClaudeReleaseArtifact(
        version=verified.version,
        platform_key=verified.platform_key,
        binary="claude",
        checksum=verified.checksum,
        size=verified.artifact_size,
    )
    try:
        revalidated = verify_release_executable(resolved, artifact)
        current_identity = _identity(revalidated)
    except (
        ClaudeProvenanceInconclusive,
        ClaudeProvenanceInvalid,
        ClaudeProvenanceUnavailable,
        OSError,
    ):
        return False
    return revalidated == resolved and current_identity == verified.identity


def _revalidate_probe_sources(
    *,
    snapshot: VerifiedClaudeExecutable,
    resolved_source: pathlib.Path,
    source_identity: Mapping[str, int],
    probe_name: str,
) -> None:
    """Revalidate immutable and mutable probe inputs before reading probe output."""

    try:
        current_snapshot = verify_release_executable(
            snapshot.executable,
            snapshot.artifact,
        )
        current_source = verify_release_executable(
            resolved_source,
            snapshot.artifact,
        )
        current_source_identity = _identity(current_source)
    except (
        ClaudeProvenanceInconclusive,
        ClaudeProvenanceInvalid,
        ClaudeProvenanceUnavailable,
        OSError,
    ) as error:
        raise _ExecutableIdentityDrift(
            f"verified executable changed during the {probe_name} probe"
        ) from error
    if (
        current_snapshot != snapshot.executable
        or current_source != resolved_source
        or current_source_identity != source_identity
    ):
        raise _ExecutableIdentityDrift(
            f"verified executable changed during the {probe_name} probe"
        )


def _candidate_exists(path: pathlib.Path) -> bool:
    try:
        path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        raise _CandidateInspectionInconclusive(
            f"cannot inspect candidate path {path}"
        ) from error
    return True


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

    if home is not None:
        active_home = home / ACTIVE_HOME_RELATIVE_PATH
        if _candidate_exists(active_home):
            return Candidate(active_home, "active-installed")

    for active in TRUSTED_ACTIVE_PATHS:
        if _candidate_exists(active):
            return Candidate(active, "active-installed")
    return None


def _resolve_candidate(candidate: Candidate) -> pathlib.Path:
    if not _candidate_exists(candidate.path):
        if candidate.source != "explicit-override":
            raise _CandidateInspectionInconclusive(str(candidate.path))
        raise _CandidateUnavailable(str(candidate.path))
    try:
        resolved = candidate.path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as error:
        raise _CandidateInspectionInconclusive(str(candidate.path)) from error
    except OSError as error:
        raise _CandidateInspectionInconclusive(str(candidate.path)) from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise _CandidateUnavailable(str(resolved))
    return resolved


def _declared_installer_version(path: pathlib.Path) -> str | None:
    if path.parent.name != "versions" or _RELEASE_VERSION.fullmatch(path.name) is None:
        return None
    return path.name


def _darwin_platform_key(path: pathlib.Path) -> str:
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except OSError as error:
        raise _CandidateInspectionInconclusive(str(path)) from error
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
    version: str,
    version_probe: VersionProbe,
    capability_probe: CapabilityProbe,
) -> VerifiedCandidate:
    """Verify the selected signed 2.x artifact before executing the candidate."""

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
            version=version,
            platform_key=platform_key,
            gpg_temp_root=private_root,
        )
        if verified.source_identity is None:
            raise _CandidateInspectionInconclusive(
                "publisher verifier did not return the descriptor-bound source identity"
            )
        resolved = verified.executable.resolve(strict=True)
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
            completed = version_probe(snapshot.executable)
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
        _revalidate_probe_sources(
            snapshot=snapshot,
            resolved_source=resolved,
            source_identity=source_identity,
            probe_name="version",
        )
        if completed.returncode != 0 or completed.stderr.strip():
            raise _VersionProbeInconclusive(
                "Claude Code version probe did not complete cleanly"
            )
        try:
            observed_version = _parse_version(completed.stdout, completed.stderr)
        except ValueError as error:
            raise _VersionProbeInconclusive(str(error)) from error
        if observed_version != version:
            return VerifiedCandidate(
                resolved_path=resolved,
                version=version,
                platform_key=verified.artifact.platform_key,
                checksum=verified.artifact.checksum,
                artifact_size=verified.artifact.size,
                identity=source_identity,
                probe_result=completed,
                capabilities=None,
            )
        try:
            capability_completed = capability_probe(snapshot.executable)
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
        _revalidate_probe_sources(
            snapshot=snapshot,
            resolved_source=resolved,
            source_identity=source_identity,
            probe_name="capability",
        )
        if capability_completed.returncode != 0 or capability_completed.stderr.strip():
            raise _CapabilityProbeInconclusive(
                "Claude Code capability probe did not complete cleanly"
            )
        try:
            version_text = completed.stdout.decode("utf-8", errors="strict")
            help_text = capability_completed.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise _CapabilityProbeInconclusive(
                "Claude Code capability evidence is not strict UTF-8"
            ) from error
        try:
            capabilities = validate_claude_capabilities(
                version_text,
                help_text,
                expected_version=version,
            )
        except ClaudeSafetyContractInvalid as error:
            raise _CapabilityContractRejected(str(error)) from error
        except ClaudeCapabilityError as error:
            raise _CapabilityContractRejected(str(error)) from error
    return VerifiedCandidate(
        resolved_path=resolved,
        version=version,
        platform_key=verified.artifact.platform_key,
        checksum=verified.artifact.checksum,
        artifact_size=verified.artifact.size,
        identity=source_identity,
        probe_result=completed,
        capabilities=capabilities,
    )


def probe_verified_version(path: pathlib.Path) -> ProbeResult:
    completed = run_bounded_capture(
        (str(path), "--version"),
        cwd=VERSION_PROBE_CWD,
        env=dict(VERSION_PROBE_ENV),
        stdin=None,
        timeout_seconds=VERSION_PROBE_TIMEOUT_SECONDS,
        stdout_limit_bytes=VERSION_PROBE_OUTPUT_LIMIT_BYTES,
        stderr_limit_bytes=VERSION_PROBE_OUTPUT_LIMIT_BYTES,
    )
    return ProbeResult(
        completed.returncode,
        bytes(completed.stdout),
        bytes(completed.stderr),
    )


def probe_verified_capabilities(path: pathlib.Path) -> ProbeResult:
    completed = run_bounded_capture(
        (str(path), "--help"),
        cwd=VERSION_PROBE_CWD,
        env=dict(VERSION_PROBE_ENV),
        stdin=None,
        timeout_seconds=CAPABILITY_PROBE_TIMEOUT_SECONDS,
        stdout_limit_bytes=CAPABILITY_PROBE_OUTPUT_LIMIT_BYTES,
        stderr_limit_bytes=CAPABILITY_PROBE_OUTPUT_LIMIT_BYTES,
    )
    return ProbeResult(
        completed.returncode,
        bytes(completed.stdout),
        bytes(completed.stderr),
    )


def _parse_version(stdout: bytes, stderr: bytes) -> str:
    if stderr.strip():
        raise ValueError("version probe wrote to stderr")
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("version probe output is not UTF-8") from error
    match = _VERSION_OUTPUT.fullmatch(text)
    if match is None:
        raise ValueError("version probe output does not match the reviewed format")
    return ".".join((match.group("major"), match.group("minor"), match.group("patch")))


def preflight(
    *,
    explicit_path: pathlib.Path | None = None,
    explicit_version: str | None = None,
    home: pathlib.Path | None = None,
    verifier: CandidateVerifier = verify_publisher_candidate,
    version_probe: VersionProbe = probe_verified_version,
    capability_probe: CapabilityProbe = probe_verified_capabilities,
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
        return _result("blocked", "supported-version-unavailable")

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
            "supported-version-unavailable",
            candidate=candidate,
        )
    installed_version = _declared_installer_version(resolved)
    declared_version = candidate.version_hint or installed_version
    if declared_version is None:
        return _result(
            "blocked",
            "version-unavailable",
            candidate=candidate,
            resolved_path=resolved,
        )
    if (
        candidate.version_hint is not None
        and installed_version is not None
        and candidate.version_hint != installed_version
    ):
        return _result(
            "blocked",
            "version-hint-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
        )
    try:
        require_supported_release_version(declared_version)
    except ClaudeProvenanceInvalid:
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
            "unsupported-version",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
        )

    try:
        verified = verifier(
            resolved,
            declared_version,
            version_probe,
            capability_probe,
        )
    except _ExecutableIdentityDrift:
        return _result(
            "inconclusive",
            "executable-identity-drift",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
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
            "supported-version-unavailable",
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
    except _CapabilityContractRejected:
        return _result(
            "blocked",
            "capability-contract-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
        )
    except _CapabilityProbeInconclusive:
        return _result(
            "inconclusive",
            "capability-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
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
    if (
        verified.resolved_path != resolved
        or verified.version != declared_version
        or not identity_matches
    ):
        return _result(
            "inconclusive",
            "executable-identity-drift",
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
            verified=verified,
        )

    completed = verified.probe_result
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

    if observed_version != declared_version:
        return _result(
            "blocked",
            "version-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            observed_version=observed_version,
            verified=verified,
        )
    if verified.capabilities is None:
        return _result(
            "inconclusive",
            "capability-probe-inconclusive",
            candidate=candidate,
            resolved_path=resolved,
            observed_version=observed_version,
            verified=verified,
        )
    try:
        final_resolved = _resolve_candidate(candidate)
    except (_CandidateUnavailable, _CandidateInspectionInconclusive):
        final_resolved = pathlib.Path()
    if final_resolved != resolved or not _verified_source_matches_signed_artifact(
        final_resolved,
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
    return _result(
        "accepted",
        "supported-version-selected",
        candidate=candidate,
        resolved_path=resolved,
        observed_version=observed_version,
        verified=verified,
    )


def _parse_args(argv: Sequence[str]) -> tuple[pathlib.Path | None, str | None]:
    if not argv:
        return None, None
    if len(argv) not in (2, 4) or len(argv) % 2:
        raise _ArgumentError(
            "expected --claude-path ABSOLUTE_PATH and optional --claude-version VERSION"
        )
    values: dict[str, str] = {}
    for index in range(0, len(argv), 2):
        name, value = argv[index : index + 2]
        if name not in ("--claude-path", "--claude-version") or not value:
            raise _ArgumentError("invalid named Claude preflight arguments")
        if name in values:
            raise _ArgumentError("duplicate named Claude preflight argument")
        values[name] = value
    if "--claude-path" not in values:
        raise _ArgumentError("--claude-version requires --claude-path")
    candidate = pathlib.Path(values["--claude-path"])
    if not candidate.is_absolute():
        raise _ArgumentError("--claude-path must be absolute")
    version = values.get("--claude-version")
    if version is not None and _RELEASE_VERSION.fullmatch(version) is None:
        raise _ArgumentError("--claude-version must be strict release semver")
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
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    destination = sys.stdout if stdout is None else stdout
    try:
        explicit_path, explicit_version = _parse_args(arguments)
        home_value = os.environ.get("HOME")
        home = pathlib.Path(home_value) if home_value else None
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
