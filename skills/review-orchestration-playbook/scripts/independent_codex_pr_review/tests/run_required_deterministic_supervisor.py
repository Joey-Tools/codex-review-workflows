from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest
from collections.abc import Iterator

from .run_required_no_child_profile import REQUIRED_TEST_KEYS

EXPECTED_TEST_COUNT = 604
# Update this only after reviewing the complete discovered test-identity change.
EXPECTED_TEST_ID_SHA256 = (
    "b62309210d115ed54e9e6dc3c37f1f26ecdcbfbfc97f22cd8ba55ebb94403175"
)


def _flatten_suite(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten_suite(item)
        else:
            yield item


def _test_key(test: unittest.TestCase) -> tuple[str, str, str]:
    return (
        test.__class__.__module__,
        test.__class__.__name__,
        test._testMethodName,
    )


def main() -> int:
    tests_directory = pathlib.Path(__file__).resolve().parent
    discovered = unittest.defaultTestLoader.discover(
        str(tests_directory),
        pattern="test_*.py",
        top_level_dir=str(tests_directory.parent),
    )
    selected: list[unittest.TestCase] = []
    excluded_keys: set[tuple[str, str, str]] = set()
    discovered_keys: set[tuple[str, str, str]] = set()
    duplicate_keys: set[tuple[str, str, str]] = set()
    for test in _flatten_suite(discovered):
        key = _test_key(test)
        if key in discovered_keys:
            duplicate_keys.add(key)
        discovered_keys.add(key)
        if key in REQUIRED_TEST_KEYS:
            excluded_keys.add(key)
        else:
            selected.append(test)

    if duplicate_keys:
        print(
            f"deterministic supervisor suite discovered duplicate tests: "
            f"{sorted(duplicate_keys)!r}",
            file=sys.stderr,
        )
        return 2
    if excluded_keys != REQUIRED_TEST_KEYS:
        print(
            "deterministic supervisor suite did not find the exact live exclusion set",
            file=sys.stderr,
        )
        return 2
    expected_discovered_count = EXPECTED_TEST_COUNT + len(REQUIRED_TEST_KEYS)
    if len(discovered_keys) != expected_discovered_count:
        print(
            f"deterministic supervisor suite discovered {len(discovered_keys)} "
            f"unique tests; expected {expected_discovered_count}",
            file=sys.stderr,
        )
        return 2
    selected_keys = discovered_keys - REQUIRED_TEST_KEYS
    selected_identity = json.dumps(
        sorted(selected_keys),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    selected_identity_sha256 = hashlib.sha256(selected_identity).hexdigest()
    if selected_identity_sha256 != EXPECTED_TEST_ID_SHA256:
        print(
            "deterministic supervisor test identity digest changed: "
            f"observed={selected_identity_sha256}",
            file=sys.stderr,
        )
        return 2
    if len(selected) != EXPECTED_TEST_COUNT:
        print(
            f"deterministic supervisor suite selected {len(selected)} tests; "
            f"expected {EXPECTED_TEST_COUNT}",
            file=sys.stderr,
        )
        return 2

    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    if result.testsRun != EXPECTED_TEST_COUNT:
        print(
            f"deterministic supervisor suite ran {result.testsRun} "
            f"of {EXPECTED_TEST_COUNT} tests",
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
            "deterministic supervisor suite contained a non-passing outcome",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
