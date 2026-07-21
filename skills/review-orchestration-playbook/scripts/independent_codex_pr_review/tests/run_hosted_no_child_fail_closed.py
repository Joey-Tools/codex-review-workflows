from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import sys
import tempfile

from review_supervisor import no_child_profile as profile

from .test_no_child_profile import (
    GITHUB_HOSTED_RUNTIME_PIN,
    GITHUB_HOSTED_RUNTIME_PROFILE,
)

LIVE_RUNTIME_PROFILE_ENV = "CODEX_REVIEW_LIVE_NO_CHILD_RUNTIME_PROFILE"
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


def _expected_outer_sandbox_blockers() -> set[str]:
    blockers: set[str] = set()
    for layer in ("rlimit", "seatbelt", "combined"):
        for action in PROBE_ACTIONS:
            prefix = f"{layer}-{action}"
            blockers.update(
                {
                    f"{prefix}-post-exec-leader-binding-invalid",
                    f"{prefix}-start-identity-is-missing",
                    f"{prefix}-post-exec-rlimit-is-invalid",
                    f"ambiguous-{layer}-{action}",
                }
            )
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


def _matches_outer_sandbox_observations(
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
    if evidence.parent_nproc_before is None:
        return False
    for (layer, _action), item in indexed.items():
        expected_limit = evidence.parent_nproc_before if layer == "seatbelt" else (0, 0)
        expected_profile = (
            None if layer == "rlimit" else evidence.seatbelt_profile_sha256
        )
        expected_detail = (
            profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
            if layer == "rlimit"
            else profile.PROBE_DETAIL_OUTER_SEATBELT_DENIED
        )
        if (
            item.outcome != "ambiguous"
            or item.detail != expected_detail
            or item.pre_exec_setsid_succeeded is not True
            or type(item.pre_exec_pid) is not int
            or item.pre_exec_pid <= 1
            or item.pre_exec_process_group != item.pre_exec_pid
            or item.pre_exec_session != item.pre_exec_pid
            or item.child_pid != item.pre_exec_pid
            or item.child_process_group is not None
            or item.child_session is not None
            or item.child_start_identity is not None
            or item.profile_sha256 != expected_profile
            or (item.pre_exec_nproc_soft, item.pre_exec_nproc_hard) != expected_limit
            or item.nproc_soft is not None
            or item.nproc_hard is not None
        ):
            return False
    return True


def main() -> int:
    required_environment = {
        LIVE_RUNTIME_PROFILE_ENV: GITHUB_HOSTED_RUNTIME_PROFILE,
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

    tests_directory = pathlib.Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(
        prefix=".hosted-no-child-probe-",
        dir=tests_directory,
    ) as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        synthetic_python = root / "synthetic-python3.13"
        synthetic_alternate = root / "synthetic-alternate"
        shutil.copyfile(profile.python_runtime_executable(), synthetic_python)
        shutil.copyfile("/usr/bin/true", synthetic_alternate)
        synthetic_python.chmod(0o755)
        synthetic_alternate.chmod(0o755)
        evidence = profile.probe_compatibility(
            pin=GITHUB_HOSTED_RUNTIME_PIN,
            probe_executable_path=synthetic_python,
            alternate_executable_path=synthetic_alternate,
            python_home=sys.base_prefix,
        )
    expected_blockers = _expected_outer_sandbox_blockers()
    blockers = set(evidence.blockers)
    runtime = evidence.runtime
    runtime_matches = (
        evidence.runtime_pin == GITHUB_HOSTED_RUNTIME_PIN
        and runtime.platform == "darwin"
        and runtime.system == "Darwin"
        and runtime.macos_product_version
        == GITHUB_HOSTED_RUNTIME_PIN.macos_product_version
        and runtime.macos_build_version == GITHUB_HOSTED_RUNTIME_PIN.macos_build_version
        and runtime.darwin_release == GITHUB_HOSTED_RUNTIME_PIN.darwin_release
        and runtime.python_version[:2]
        == (
            GITHUB_HOSTED_RUNTIME_PIN.python_major,
            GITHUB_HOSTED_RUNTIME_PIN.python_minor,
        )
        and runtime.effective_uid not in {None, 0}
        and evidence.sandbox_exec is not None
        and evidence.sandbox_exec.path == str(profile.SANDBOX_EXEC)
        and evidence.sandbox_exec.sha256
        == GITHUB_HOSTED_RUNTIME_PIN.sandbox_exec_sha256
    )
    signature_matches = (
        runtime_matches
        and _matches_outer_sandbox_observations(evidence)
        and blockers == expected_blockers
        and len(blockers) == len(evidence.blockers)
        and evidence.parent_nproc_before == evidence.parent_nproc_after
        and evidence.probe_executable is not None
        and evidence.alternate_executable is not None
        and evidence.seatbelt_profile_sha256 is not None
    )
    print(
        json.dumps(
            {
                "compatible": evidence.compatible,
                "production_capable": evidence.production_capable,
                "reviewed_fail_closed_signature": signature_matches,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
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
