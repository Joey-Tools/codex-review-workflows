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

from .claude_provenance import (
    ClaudeProvenanceDependencyUnavailable,
    ClaudeProvenanceInconclusive,
    ClaudeProvenanceInvalid,
    ClaudeProvenanceUnavailable,
    materialize_verified_executable,
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


REQUIRED_CLAUDE_VERSION = "2.1.212"
SIDE_BY_SIDE_RELATIVE_PATH = (
    pathlib.Path(".local/share/claude/versions") / REQUIRED_CLAUDE_VERSION
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


@dataclass(frozen=True)
class VerifiedCandidate:
    resolved_path: pathlib.Path
    platform_key: str
    checksum: str
    artifact_size: int
    identity: Mapping[str, int]
    probe_result: ProbeResult


@dataclass(frozen=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes


VersionProbe = Callable[[pathlib.Path], ProbeResult]
CandidateVerifier = Callable[[pathlib.Path, VersionProbe], VerifiedCandidate]


class _ArgumentError(ValueError):
    pass


class _CandidateUnavailable(ValueError):
    pass


class _CandidateInspectionInconclusive(RuntimeError):
    pass


class _VersionProbeInconclusive(RuntimeError):
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
        "required_version": REQUIRED_CLAUDE_VERSION,
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
        }
        value["identity"] = dict(verified.identity)
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
    home: pathlib.Path | None,
) -> Candidate | None:
    if explicit_path is not None:
        if not explicit_path.is_absolute():
            raise _ArgumentError("--claude-path must be absolute")
        return Candidate(explicit_path, "explicit-override")

    if home is not None:
        side_by_side = home / SIDE_BY_SIDE_RELATIVE_PATH
        if _candidate_exists(side_by_side):
            return Candidate(side_by_side, "side-by-side-exact")
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
    version_probe: VersionProbe,
) -> VerifiedCandidate:
    """Verify the exact signed 2.1.212 artifact before executing the candidate."""

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
            version=REQUIRED_CLAUDE_VERSION,
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
    return VerifiedCandidate(
        resolved_path=resolved,
        platform_key=verified.artifact.platform_key,
        checksum=verified.artifact.checksum,
        artifact_size=verified.artifact.size,
        identity=source_identity,
        probe_result=completed,
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
    home: pathlib.Path | None = None,
    verifier: CandidateVerifier = verify_publisher_candidate,
    version_probe: VersionProbe = probe_verified_version,
) -> dict[str, object]:
    try:
        candidate = select_candidate(explicit_path=explicit_path, home=home)
    except _CandidateInspectionInconclusive:
        return _result("inconclusive", "candidate-inspection-inconclusive")
    if candidate is None:
        return _result("blocked", "exact-version-unavailable")

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
            "exact-version-unavailable",
            candidate=candidate,
        )
    declared_version = _declared_installer_version(resolved)
    if declared_version is not None and declared_version != REQUIRED_CLAUDE_VERSION:
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
            "exact-version-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            declared_version=declared_version,
        )

    try:
        verified = verifier(resolved, version_probe)
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
            "exact-version-unavailable",
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

    try:
        after_resolved = _resolve_candidate(candidate)
        after_identity = _identity(after_resolved)
    except (_CandidateUnavailable, _CandidateInspectionInconclusive):
        after_resolved = pathlib.Path()
        after_identity = {}
    if after_resolved != resolved or after_identity != verified.identity:
        return _result(
            "inconclusive",
            "executable-identity-drift",
            candidate=candidate,
            resolved_path=resolved,
            observed_version=observed_version,
            verified=verified,
        )
    if observed_version != REQUIRED_CLAUDE_VERSION:
        return _result(
            "blocked",
            "exact-version-mismatch",
            candidate=candidate,
            resolved_path=resolved,
            observed_version=observed_version,
            verified=verified,
        )
    return _result(
        "accepted",
        "exact-version-selected",
        candidate=candidate,
        resolved_path=resolved,
        observed_version=observed_version,
        verified=verified,
    )


def _parse_args(argv: Sequence[str]) -> pathlib.Path | None:
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == "--claude-path" and argv[1]:
        candidate = pathlib.Path(argv[1])
        if not candidate.is_absolute():
            raise _ArgumentError("--claude-path must be absolute")
        return candidate
    raise _ArgumentError("expected no arguments or --claude-path ABSOLUTE_PATH")


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
        explicit_path = _parse_args(arguments)
        home_value = os.environ.get("HOME")
        home = pathlib.Path(home_value) if home_value else None
        value = preflight(explicit_path=explicit_path, home=home)
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
