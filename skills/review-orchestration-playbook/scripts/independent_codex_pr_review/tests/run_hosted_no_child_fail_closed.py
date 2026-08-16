from __future__ import annotations

import json
import os
import platform
import shutil
import sys

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


def main() -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
