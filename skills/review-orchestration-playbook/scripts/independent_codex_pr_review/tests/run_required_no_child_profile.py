from __future__ import annotations

import os
import sys
import unittest

from .test_no_child_profile import (
    GITHUB_HOSTED_RUNTIME_PIN,
    GITHUB_HOSTED_RUNTIME_PROFILE,
    NoChildProfileDarwinIntegrationTests,
    REQUIRE_LIVE_NO_CHILD_PROFILE_ENV,
)

LIVE_RUNTIME_PROFILE_ENV = "CODEX_REVIEW_LIVE_NO_CHILD_RUNTIME_PROFILE"
RUNNER_ENVIRONMENT_ENV = "CODEX_REVIEW_RUNNER_ENVIRONMENT"
RUNNER_ARCH_ENV = "CODEX_REVIEW_RUNNER_ARCH"
REQUIRED_TEST_METHODS = (
    "test_every_probe_preserves_the_ordered_launch_binding",
    "test_probe_uses_exact_synthetic_macho_executables",
    "test_public_launcher_returns_bound_leader_evidence",
    "test_rlimit_zero_denies_every_creation_api_and_spares_parent",
    "test_seatbelt_and_combined_profile_deny_every_escape_path",
    "test_secure_owner_snapshot_profile_enforces_exec_and_write_boundaries",
)


class GitHubHostedNoChildProfileIntegrationTests(NoChildProfileDarwinIntegrationTests):
    RUNTIME_PIN = GITHUB_HOSTED_RUNTIME_PIN
    EXPECTED_MACHINE = "arm64"
    PRODUCTION_EVIDENCE_EXPECTED = False


def main() -> int:
    if os.environ.get(REQUIRE_LIVE_NO_CHILD_PROFILE_ENV) != "1":
        print(
            f"{REQUIRE_LIVE_NO_CHILD_PROFILE_ENV}=1 is required",
            file=sys.stderr,
        )
        return 2
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

    suite = unittest.TestSuite(
        GitHubHostedNoChildProfileIntegrationTests(method)
        for method in REQUIRED_TEST_METHODS
    )
    expected_count = len(REQUIRED_TEST_METHODS)
    if expected_count != 6 or suite.countTestCases() != expected_count:
        print("required live no-child profile suite shape is invalid", file=sys.stderr)
        return 2
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != expected_count:
        print(
            f"required live no-child profile suite ran {result.testsRun} "
            f"of {expected_count} tests",
            file=sys.stderr,
        )
        return 1
    nonpassing_outcomes = (
        result.skipped,
        result.expectedFailures,
        result.unexpectedSuccesses,
        result.errors,
        result.failures,
    )
    if any(nonpassing_outcomes):
        print(
            "required live no-child profile suite contained a non-passing outcome",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
