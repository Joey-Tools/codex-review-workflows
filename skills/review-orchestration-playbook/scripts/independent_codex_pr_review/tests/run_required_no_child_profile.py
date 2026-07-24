from __future__ import annotations

import os
import sys
import unittest

from .test_codex_executable import CodexExecutableAuthenticationTests
from .test_no_child_profile import (
    NoChildProfileDarwinIntegrationTests,
    REQUIRE_LIVE_NO_CHILD_PROFILE_ENV,
)
from .test_direct_gate import SnapshotMutationProbeTests

REQUIRED_NO_CHILD_TEST_METHODS = (
    "test_every_probe_preserves_the_ordered_launch_binding",
    "test_probe_uses_exact_synthetic_macho_executables",
    "test_public_launcher_returns_bound_leader_evidence",
    "test_rlimit_zero_denies_every_creation_api_and_spares_parent",
    "test_seatbelt_and_combined_profile_deny_every_escape_path",
    "test_secure_owner_snapshot_profile_enforces_exec_and_write_boundaries",
)
REQUIRED_TEST_CASES = tuple(
    (NoChildProfileDarwinIntegrationTests, method)
    for method in REQUIRED_NO_CHILD_TEST_METHODS
) + (
    (
        CodexExecutableAuthenticationTests,
        "test_seatbelt_default_denies_firmlink_alias_and_preserves_stdout",
    ),
    (
        CodexExecutableAuthenticationTests,
        "test_bounded_preflight_cannot_leave_child_after_closing_stdio",
    ),
    (
        SnapshotMutationProbeTests,
        "test_live_probe_denies_every_snapshot_mutation",
    ),
)
REQUIRED_TEST_KEYS = frozenset(
    (test_class.__module__, test_class.__name__, method)
    for test_class, method in REQUIRED_TEST_CASES
)


def main() -> int:
    if os.environ.get(REQUIRE_LIVE_NO_CHILD_PROFILE_ENV) != "1":
        print(
            f"{REQUIRE_LIVE_NO_CHILD_PROFILE_ENV}=1 is required",
            file=sys.stderr,
        )
        return 2
    suite = unittest.TestSuite(
        test_class(method) for test_class, method in REQUIRED_TEST_CASES
    )
    expected_count = len(REQUIRED_TEST_CASES)
    if (
        expected_count != 9
        or len(REQUIRED_TEST_KEYS) != expected_count
        or suite.countTestCases() != expected_count
    ):
        print("required live isolation suite shape is invalid", file=sys.stderr)
        return 2
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != expected_count:
        print(
            f"required live isolation suite ran {result.testsRun} "
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
            "required live isolation suite contained a non-passing outcome",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
