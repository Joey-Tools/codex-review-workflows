from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import sys
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from review_supervisor import no_child_profile as profile

from .support import owned_temporary_directory
from .test_no_child_profile import (
    GITHUB_HOSTED_RUNTIME_PINS,
)

RUNNER_ENVIRONMENT_ENV = "CODEX_REVIEW_RUNNER_ENVIRONMENT"
RUNNER_ARCH_ENV = "CODEX_REVIEW_RUNNER_ARCH"
PROBE_ACTIONS = (
    "baseline",
    "fork",
    "posix_spawn",
    "popen",
    "double_fork",
    "setsid",
    "setpgid",
    "exec",
)
CREATION_ACTIONS = ("fork", "posix_spawn", "popen", "double_fork")
NATIVE_SUPPORTED_ARCHITECTURES = frozenset({"arm64", "x86_64"})
NATIVE_SUPPORTED_PYTHON = (3, 13)
NATIVE_MAX_EVIDENCE_BYTES = 64 * 1024


class NativeProbeError(RuntimeError):
    pass


class NativeProbeCapabilityUnavailable(NativeProbeError):
    pass


class NativeProbeValidationError(NativeProbeError):
    pass


def _select_hosted_runtime_profile(
    runtime: profile.RuntimeFingerprint,
) -> tuple[str, profile.RuntimePin] | None:
    matches = [
        (name, pin)
        for name, pin in GITHUB_HOSTED_RUNTIME_PINS.items()
        if (
            runtime.macos_product_version == pin.macos_product_version
            and runtime.macos_build_version == pin.macos_build_version
            and runtime.darwin_release == pin.darwin_release
            and runtime.python_version[:2] == (pin.python_major, pin.python_minor)
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _expected_hosted_fail_closed_blockers(
    evidence: profile.CompatibilityEvidence,
) -> set[str]:
    blockers: set[str] = set()
    for action in PROBE_ACTIONS:
        prefix = f"rlimit-{action}"
        blockers.add(f"ambiguous-rlimit-{action}")
        item = evidence.observation("rlimit", action)
        if (
            item is not None
            and item.detail == profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
        ):
            child_identity = (
                item.child_pid,
                item.child_process_group,
                item.child_session,
            )
            pre_exec_identity = (
                item.pre_exec_pid,
                item.pre_exec_process_group,
                item.pre_exec_session,
            )
            if child_identity != pre_exec_identity:
                blockers.add(f"{prefix}-post-exec-leader-binding-invalid")
            if not item.child_start_identity:
                blockers.add(f"{prefix}-start-identity-is-missing")
            if (item.nproc_soft, item.nproc_hard) != (0, 0):
                blockers.add(f"{prefix}-post-exec-rlimit-is-invalid")
    for layer in ("seatbelt", "combined"):
        for action in PROBE_ACTIONS:
            blockers.add(f"ambiguous-{layer}-{action}")
    for layer in ("rlimit", "seatbelt", "combined"):
        blockers.add(f"{layer}-baseline-not-observed")
    for action in CREATION_ACTIONS:
        blockers.add(f"rlimit-{action}-not-denied")
    for action in ("setsid", "setpgid"):
        blockers.add(f"rlimit-{action}-leader-escape-not-denied")
    for layer in ("seatbelt", "combined"):
        for action in (*CREATION_ACTIONS, "setsid", "setpgid", "exec"):
            blockers.add(f"{layer}-{action}-not-denied")
    blockers.add("rlimit-exec-scope-is-ambiguous")
    return blockers


def _matches_hosted_fail_closed_observations(
    evidence: profile.CompatibilityEvidence,
) -> bool:
    indexed = {(item.layer, item.action): item for item in evidence.observations}
    expected_keys = {
        (layer, action)
        for layer in ("rlimit", "seatbelt", "combined")
        for action in PROBE_ACTIONS
    }
    if set(indexed) != expected_keys or len(indexed) != len(evidence.observations):
        return False
    if evidence.parent_nproc_before is None or evidence.seatbelt_profile_sha256 is None:
        return False
    for (layer, _action), item in indexed.items():
        expected_limit = evidence.parent_nproc_before if layer == "seatbelt" else (0, 0)
        expected_profile = (
            None if layer == "rlimit" else evidence.seatbelt_profile_sha256
        )
        if (
            item.outcome != "ambiguous"
            or item.error_number is not None
            or item.pre_exec_setsid_succeeded is not True
            or type(item.pre_exec_pid) is not int
            or item.pre_exec_pid <= 1
            or item.pre_exec_process_group != item.pre_exec_pid
            or item.pre_exec_session != item.pre_exec_pid
            or item.child_pid != item.pre_exec_pid
            or item.profile_sha256 != expected_profile
            or (item.pre_exec_nproc_soft, item.pre_exec_nproc_hard) != expected_limit
        ):
            return False
        if layer == "rlimit":
            sampled_numeric_identity = (
                item.child_process_group,
                item.child_session,
            )
            unbound = (
                item.detail == profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
                and sampled_numeric_identity in (
                    (None, None),
                    (item.pre_exec_pid, None),
                    (item.pre_exec_pid, item.pre_exec_pid),
                )
                and item.child_start_identity is None
                and item.nproc_soft is None
                and item.nproc_hard is None
            )
            bound_then_killed = (
                item.detail == profile.PROBE_DETAIL_KILLED_BEFORE_EVIDENCE
                and item.child_process_group == item.pre_exec_pid
                and item.child_session == item.pre_exec_pid
                and isinstance(item.child_start_identity, str)
                and item.child_start_identity.startswith("darwin-proc-start:")
                and (item.nproc_soft, item.nproc_hard) == expected_limit
            )
            if not (unbound or bound_then_killed):
                return False
        elif (
            item.detail != profile.PROBE_DETAIL_KILLED_BEFORE_EVIDENCE
            or item.child_process_group != item.pre_exec_pid
            or item.child_session != item.pre_exec_pid
            or not isinstance(item.child_start_identity, str)
            or not item.child_start_identity.startswith("darwin-proc-start:")
            or (item.nproc_soft, item.nproc_hard) != expected_limit
        ):
            return False
    return True


def _signature_diagnostics(
    evidence: profile.CompatibilityEvidence,
    *,
    expected_blockers: set[str],
    runtime_matches: bool,
    observation_signature_matches: bool,
) -> dict[str, object]:
    missing_evidence = []
    for name in (
        "sandbox_exec",
        "probe_executable",
        "alternate_executable",
        "seatbelt_profile_sha256",
    ):
        if getattr(evidence, name) is None:
            missing_evidence.append(name)
    return {
        "blockers_match": set(evidence.blockers) == expected_blockers
        and len(evidence.blockers) == len(expected_blockers),
        "expected_blockers": sorted(expected_blockers),
        "missing_evidence": missing_evidence,
        "observation_signature_matches": observation_signature_matches,
        "observations": [item.to_json() for item in evidence.observations],
        "observed_blockers": list(evidence.blockers),
        "parent_nproc_after": (
            list(evidence.parent_nproc_after)
            if evidence.parent_nproc_after is not None
            else None
        ),
        "parent_nproc_before": (
            list(evidence.parent_nproc_before)
            if evidence.parent_nproc_before is not None
            else None
        ),
        "parent_nproc_stable": (
            evidence.parent_nproc_before == evidence.parent_nproc_after
        ),
        "runtime_matches": runtime_matches,
    }


def _run_hosted_ci() -> int:
    required_environment = {
        RUNNER_ENVIRONMENT_ENV: "github-hosted",
        RUNNER_ARCH_ENV: "ARM64",
    }
    for name, expected in required_environment.items():
        observed = os.environ.get(name)
        if observed != expected:
            print(
                f"{name} must be {expected!r}, observed {observed!r}",
                file=sys.stderr,
            )
            return 2
    if platform.machine() != "arm64":
        print("hosted no-child probe requires an actual arm64 process", file=sys.stderr)
        return 2
    observed_runtime = profile._runtime_fingerprint()
    selected = _select_hosted_runtime_profile(observed_runtime)
    if selected is None:
        print(
            "GitHub hosted no-child runtime is not in the reviewed profile catalog: "
            f"product={observed_runtime.macos_product_version!r} "
            f"build={observed_runtime.macos_build_version!r} "
            f"darwin={observed_runtime.darwin_release!r} "
            f"python={observed_runtime.python_version[:2]!r}",
            file=sys.stderr,
        )
        return 2
    runtime_profile, runtime_pin = selected

    with owned_temporary_directory("hosted-no-child-probe-") as root:
        root.chmod(0o700)
        synthetic_python = root / "synthetic-python3.13"
        synthetic_alternate = root / "synthetic-alternate"
        shutil.copyfile(profile.python_runtime_executable(), synthetic_python)
        shutil.copyfile("/usr/bin/true", synthetic_alternate)
        synthetic_python.chmod(0o755)
        synthetic_alternate.chmod(0o755)
        evidence = profile.probe_compatibility(
            pin=runtime_pin,
            probe_executable_path=synthetic_python,
            alternate_executable_path=synthetic_alternate,
            python_home=sys.base_prefix,
        )
    expected_blockers = _expected_hosted_fail_closed_blockers(evidence)
    blockers = set(evidence.blockers)
    runtime = evidence.runtime
    runtime_matches = (
        evidence.runtime_pin == runtime_pin
        and runtime.platform == "darwin"
        and runtime.system == "Darwin"
        and runtime.macos_product_version == runtime_pin.macos_product_version
        and runtime.macos_build_version == runtime_pin.macos_build_version
        and runtime.darwin_release == runtime_pin.darwin_release
        and runtime.python_version[:2]
        == (
            runtime_pin.python_major,
            runtime_pin.python_minor,
        )
        and runtime.effective_uid not in {None, 0}
        and evidence.sandbox_exec is not None
        and evidence.sandbox_exec.path == str(profile.SANDBOX_EXEC)
        and evidence.sandbox_exec.sha256 == runtime_pin.sandbox_exec_sha256
    )
    observation_signature_matches = _matches_hosted_fail_closed_observations(evidence)
    signature_matches = (
        not evidence.compatible
        and not evidence.production_capable
        and runtime_matches
        and observation_signature_matches
        and blockers == expected_blockers
        and len(blockers) == len(evidence.blockers)
        and evidence.parent_nproc_before == evidence.parent_nproc_after
        and evidence.probe_executable is not None
        and evidence.alternate_executable is not None
        and evidence.seatbelt_profile_sha256 is not None
    )
    summary: dict[str, object] = {
        "compatible": evidence.compatible,
        "production_capable": evidence.production_capable,
        "reviewed_fail_closed_signature": signature_matches,
        "runtime_profile": runtime_profile,
    }
    if not signature_matches:
        summary["signature_diagnostics"] = _signature_diagnostics(
            evidence,
            expected_blockers=expected_blockers,
            runtime_matches=runtime_matches,
            observation_signature_matches=observation_signature_matches,
        )
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    if evidence.compatible or evidence.production_capable:
        print(
            "GitHub hosted no-child profile unexpectedly became capable; "
            "reassess the CI architecture",
            file=sys.stderr,
        )
        return 1
    if not signature_matches:
        print(
            "GitHub hosted no-child profile no longer matches the reviewed "
            "fail-closed signature",
            file=sys.stderr,
        )
        return 1
    return 0


def _require_supported_native_runtime(
    runtime: profile.RuntimeFingerprint,
    *,
    machine: str,
) -> None:
    if runtime.platform != "darwin" or runtime.system != "Darwin":
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe requires Darwin; "
            f"observed platform={runtime.platform!r}, system={runtime.system!r}"
        )
    if machine not in NATIVE_SUPPORTED_ARCHITECTURES:
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe does not support this architecture: "
            f"observed={machine!r}, "
            f"supported={sorted(NATIVE_SUPPORTED_ARCHITECTURES)!r}"
        )
    if runtime.python_version[:2] != NATIVE_SUPPORTED_PYTHON:
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe requires Python 3.13; "
            f"observed={runtime.python_version[:2]!r}"
        )
    if runtime.effective_uid in {None, 0}:
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe requires a non-root process"
        )
    if not all(
        isinstance(value, str) and value
        for value in (
            runtime.macos_product_version,
            runtime.macos_build_version,
            runtime.darwin_release,
        )
    ):
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe requires a complete Darwin runtime fingerprint"
        )


def _native_runtime_pin(
    runtime: profile.RuntimeFingerprint,
    sandbox_exec: profile.ExecutableIdentity,
) -> profile.RuntimePin:
    """Build an execution-local observation pin, never a production policy pin."""

    if (
        runtime.macos_product_version is None
        or runtime.macos_build_version is None
        or runtime.darwin_release is None
    ):
        raise NativeProbeCapabilityUnavailable(
            "native no-child probe cannot pin an incomplete Darwin fingerprint"
        )
    return profile.RuntimePin(
        macos_product_version=runtime.macos_product_version,
        macos_build_version=runtime.macos_build_version,
        darwin_release=runtime.darwin_release,
        sandbox_exec_sha256=sandbox_exec.sha256,
        python_major=runtime.python_version[0],
        python_minor=runtime.python_version[1],
        seatbelt_profile_version=profile.SEATBELT_PROFILE_VERSION,
    )


def _complete_executable_identity(
    identity: profile.ExecutableIdentity | None,
) -> bool:
    if identity is None:
        return False
    if (
        not isinstance(identity.path, str)
        or not identity.path.startswith("/")
        or not identity.path.isascii()
        or any(ord(character) < 32 for character in identity.path)
        or type(identity.device) is not int
        or type(identity.inode) is not int
        or type(identity.mode) is not int
        or identity.device < 0
        or identity.inode <= 0
        or not stat.S_ISREG(identity.mode)
        or type(identity.size) is not int
        or identity.size <= 0
        or identity.mode & 0o111 == 0
        or identity.mode & 0o022 != 0
        or type(identity.uid) is not int
        or type(identity.gid) is not int
        or not isinstance(identity.sha256, str)
        or len(identity.sha256) != 64
        or identity.sha256.lower() != identity.sha256
        or any(character not in "0123456789abcdef" for character in identity.sha256)
    ):
        return False
    return True


def _validate_native_probe_evidence(
    evidence: profile.CompatibilityEvidence,
    *,
    machine: str,
) -> dict[str, Any]:
    """Validate the complete live matrix and classify its real profile result."""

    _require_supported_native_runtime(evidence.runtime, machine=machine)
    try:
        raw_evidence = json.dumps(
            evidence.to_json(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise NativeProbeValidationError(
            f"native probe evidence cannot be serialized: {error}"
        ) from error
    if len(raw_evidence) > NATIVE_MAX_EVIDENCE_BYTES:
        raise NativeProbeValidationError(
            "native probe evidence exceeds its bounded output limit: "
            f"bytes={len(raw_evidence)}, limit={NATIVE_MAX_EVIDENCE_BYTES}"
        )
    if evidence.schema_version != profile.EVIDENCE_SCHEMA_VERSION:
        raise NativeProbeValidationError(
            f"native probe evidence schema is unsupported: {evidence.schema_version}"
        )
    if (
        evidence.runtime_pin.macos_product_version
        != evidence.runtime.macos_product_version
        or evidence.runtime_pin.macos_build_version
        != evidence.runtime.macos_build_version
        or evidence.runtime_pin.darwin_release != evidence.runtime.darwin_release
        or (evidence.runtime_pin.python_major, evidence.runtime_pin.python_minor)
        != evidence.runtime.python_version[:2]
    ):
        raise NativeProbeValidationError(
            "native observation pin does not match the live runtime fingerprint"
        )
    if not _complete_executable_identity(evidence.sandbox_exec):
        raise NativeProbeValidationError(
            "native probe is missing a complete authenticated sandbox-exec identity"
        )
    assert evidence.sandbox_exec is not None
    if (
        evidence.sandbox_exec.path != str(profile.SANDBOX_EXEC)
        or evidence.sandbox_exec.uid != 0
        or evidence.sandbox_exec.sha256 != evidence.runtime_pin.sandbox_exec_sha256
    ):
        raise NativeProbeValidationError(
            "native probe sandbox-exec identity does not match its observation pin"
        )
    if not _complete_executable_identity(evidence.probe_executable):
        raise NativeProbeValidationError(
            "native probe is missing a complete probe executable byte identity"
        )
    if not _complete_executable_identity(evidence.alternate_executable):
        raise NativeProbeValidationError(
            "native probe is missing a complete alternate executable byte identity"
        )
    assert evidence.probe_executable is not None
    assert evidence.alternate_executable is not None
    if (
        evidence.probe_executable.uid != evidence.runtime.effective_uid
        or evidence.probe_executable.path == evidence.alternate_executable.path
        or evidence.probe_executable.path == evidence.sandbox_exec.path
        or evidence.alternate_executable.path == evidence.sandbox_exec.path
    ):
        raise NativeProbeValidationError(
            "native probe executable identities are not distinct runner-owned inputs"
        )
    if evidence.parent_nproc_before is None or (
        evidence.parent_nproc_after != evidence.parent_nproc_before
    ):
        raise NativeProbeValidationError(
            "native probe did not preserve the parent RLIMIT_NPROC"
        )
    if evidence.seatbelt_profile_sha256 is None or (
        len(evidence.seatbelt_profile_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in evidence.seatbelt_profile_sha256
        )
    ):
        raise NativeProbeValidationError(
            "native probe is missing its complete Seatbelt profile digest"
        )

    indexed = {(item.layer, item.action): item for item in evidence.observations}
    expected_keys = {
        (layer, action)
        for layer in ("rlimit", "seatbelt", "combined")
        for action in PROBE_ACTIONS
    }
    if len(evidence.observations) != len(expected_keys) or set(indexed) != expected_keys:
        raise NativeProbeValidationError(
            "native probe did not produce the complete unique 24-observation matrix"
        )
    observation_blockers = tuple(
        dict.fromkeys(
            profile._probe_blockers(
                evidence.observations,
                parent_nproc=evidence.parent_nproc_before,
                profile_sha256=evidence.seatbelt_profile_sha256,
            )
        )
    )
    if evidence.blockers != observation_blockers:
        raise NativeProbeValidationError(
            "native probe blocker list does not exactly match its raw observations"
        )
    if profile._runtime_blockers(
        evidence.runtime,
        evidence.runtime_pin,
        evidence.sandbox_exec,
    ):
        raise NativeProbeValidationError(
            "native observation pin did not admit the captured runtime fingerprint"
        )
    try:
        profile.require_compatible(evidence)
    except profile.NoChildProfileUnavailable as error:
        gate_blockers = tuple(error.evidence.blockers)
        if not observation_blockers or gate_blockers != observation_blockers:
            raise NativeProbeValidationError(
                "observational compatibility gate refusal does not exactly match "
                "the raw probe blockers"
            ) from error
    else:
        if observation_blockers:
            raise NativeProbeValidationError(
                "observational compatibility gate accepted evidence with "
                "probe blockers"
            )
    return {
        "decision": "compatible" if not observation_blockers else "fail-closed",
        "evidence_bytes": len(raw_evidence),
        "observation_blockers": list(observation_blockers),
    }


def _production_gate_result(
    evidence: profile.CompatibilityEvidence,
    *,
    probe_decision: str,
) -> dict[str, Any]:
    """Report the actual compatibility gate result and whether its input is hypothetical."""

    actual_input = evidence.runtime_pin == profile.PINNED_RUNTIME
    gate_evidence = (
        evidence
        if actual_input
        else replace(evidence, runtime_pin=profile.PINNED_RUNTIME)
    )
    expected_runtime_blockers = tuple(
        profile._runtime_blockers(
            evidence.runtime,
            profile.PINNED_RUNTIME,
            evidence.sandbox_exec,
        )
    )
    expected_blockers = tuple(
        dict.fromkeys((*evidence.blockers, *expected_runtime_blockers))
    )
    try:
        profile.require_compatible(gate_evidence)
    except profile.NoChildProfileUnavailable as error:
        blockers = tuple(error.evidence.blockers)
        if not expected_blockers or blockers != expected_blockers:
            raise NativeProbeValidationError(
                "production compatibility gate refusal does not exactly match "
                "the observation and runtime blockers"
            ) from error
        return {
            "decision": "refused",
            "evidence_scope": (
                "native-observation"
                if actual_input
                else "hypothetical-production-runtime-pin"
            ),
            "blockers": list(blockers),
            "production_capable": evidence.production_capable,
        }
    if expected_blockers or probe_decision != "compatible":
        raise NativeProbeValidationError(
            "production compatibility gate accepted evidence despite expected "
            "blockers or a fail-closed observation result"
        )
    return {
        "decision": "accepted",
        "evidence_scope": (
            "native-observation"
            if actual_input
            else "hypothetical-production-runtime-pin"
        ),
        "blockers": [],
        "production_capable": evidence.production_capable,
    }


def _emit_native_failure(
    message: str,
    *,
    evidence: profile.CompatibilityEvidence | None = None,
) -> None:
    if evidence is not None:
        try:
            raw = json.dumps(
                evidence.to_json(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raw = b""
        if raw and len(raw) <= NATIVE_MAX_EVIDENCE_BYTES:
            print(
                json.dumps(
                    {
                        "mode": "native-ci",
                        "decision": "invalid",
                        "error": message,
                        "probe_evidence": evidence.to_json(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
    print(message, file=sys.stderr)


def _run_native_ci() -> int:
    observed_runtime = profile._runtime_fingerprint()
    machine = platform.machine()
    evidence: profile.CompatibilityEvidence | None = None
    decision: dict[str, Any] | None = None
    production_gate: dict[str, Any] | None = None
    try:
        _require_supported_native_runtime(observed_runtime, machine=machine)
        sandbox_exec = profile._authenticate_root_protected_executable(
            profile.SANDBOX_EXEC
        ).executable
        runtime_pin = _native_runtime_pin(observed_runtime, sandbox_exec)
        with owned_temporary_directory("native-no-child-probe-") as root:
            root.chmod(0o700)
            synthetic_python = root / "synthetic-python"
            synthetic_alternate = root / "synthetic-alternate"
            shutil.copyfile(profile.python_runtime_executable(), synthetic_python)
            shutil.copyfile("/usr/bin/true", synthetic_alternate)
            synthetic_python.chmod(0o755)
            synthetic_alternate.chmod(0o755)
            evidence = profile.probe_compatibility(
                pin=runtime_pin,
                probe_executable_path=synthetic_python,
                alternate_executable_path=synthetic_alternate,
                python_home=sys.base_prefix,
            )
            decision = _validate_native_probe_evidence(evidence, machine=machine)
            production_gate = _production_gate_result(
                evidence,
                probe_decision=decision["decision"],
            )
    except NativeProbeCapabilityUnavailable as error:
        _emit_native_failure(
            f"native no-child probe unavailable: {error}", evidence=evidence
        )
        return 2 if evidence is None else 1
    except (profile.ExecutableAuthenticationError, OSError) as error:
        _emit_native_failure(
            f"native no-child probe setup failed: {error}", evidence=evidence
        )
        return 2
    except NativeProbeError as error:
        _emit_native_failure(str(error), evidence=evidence)
        return 1

    assert evidence is not None
    assert decision is not None
    assert production_gate is not None

    summary = {
        "architecture": machine,
        "decision": decision["decision"],
        "evidence_bytes": decision["evidence_bytes"],
        "mode": "native-ci",
        "observation_blockers": decision["observation_blockers"],
        "production_gate": production_gate,
        "probe_evidence": evidence.to_json(),
        "runtime_pin_scope": "execution-local-observation-only",
        "supported_python": f"{NATIVE_SUPPORTED_PYTHON[0]}.{NATIVE_SUPPORTED_PYTHON[1]}",
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the hosted fail-closed or native no-child profile path."
    )
    parser.add_argument(
        "--native-ci",
        action="store_true",
        help="run the native Darwin probe using an execution-local observation pin",
    )
    arguments = parser.parse_args(argv)
    if arguments.native_ci:
        return _run_native_ci()
    return _run_hosted_ci()


if __name__ == "__main__":
    raise SystemExit(main())
