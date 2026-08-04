from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest
from collections.abc import Iterator

from .run_required_deterministic_supervisor import (
    EXPECTED_TEST_COUNT as EXPECTED_DETERMINISTIC_TEST_COUNT,
)
from .run_required_no_child_profile import REQUIRED_TEST_KEYS
from .readonly_no_child_contract import (
    EXPECTED_TEST_COUNT,
    EXPECTED_TEST_ID_SHA256,
    SUCCESS_RECORD,
)


READONLY_NO_CHILD_MODULES = frozenset(
    {
        "tests.test_appserver_protocol",
        "tests.test_appserver_runtime",
        "tests.test_auth_carrier",
        "tests.test_checkout",
        "tests.test_codex_executable",
        "tests.test_direct_gate",
        "tests.test_evidence",
        "tests.test_frozen_source",
        "tests.test_ledger",
        "tests.test_lfs",
        "tests.test_logs",
        "tests.test_prompt",
        "tests.test_secureio",
        "tests.test_settlement_state",
        "tests.test_wire",
    }
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
    discovered_keys: set[tuple[str, str, str]] = set()
    duplicate_keys: set[tuple[str, str, str]] = set()
    selected_modules: set[str] = set()
    for test in _flatten_suite(discovered):
        key = _test_key(test)
        if key in discovered_keys:
            duplicate_keys.add(key)
        discovered_keys.add(key)
        if key not in REQUIRED_TEST_KEYS and key[0] in READONLY_NO_CHILD_MODULES:
            selected.append(test)
            selected_modules.add(key[0])

    if duplicate_keys:
        print(
            "read-only no-child suite discovered duplicate tests: "
            f"{sorted(duplicate_keys)!r}",
            file=sys.stderr,
        )
        return 2
    expected_discovered_count = EXPECTED_DETERMINISTIC_TEST_COUNT + len(
        REQUIRED_TEST_KEYS
    )
    if len(discovered_keys) != expected_discovered_count:
        print(
            f"read-only no-child suite discovered {len(discovered_keys)} "
            f"unique tests; expected {expected_discovered_count}",
            file=sys.stderr,
        )
        return 2
    if selected_modules != READONLY_NO_CHILD_MODULES:
        print(
            "read-only no-child suite did not find its exact module set",
            file=sys.stderr,
        )
        return 2

    selected_identity = json.dumps(
        sorted(_test_key(test) for test in selected),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    selected_identity_sha256 = hashlib.sha256(selected_identity).hexdigest()
    if (
        len(selected) != EXPECTED_TEST_COUNT
        or selected_identity_sha256 != EXPECTED_TEST_ID_SHA256
    ):
        print(
            "read-only no-child test identity changed: "
            f"count={len(selected)},sha256={selected_identity_sha256}",
            file=sys.stderr,
        )
        return 2

    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    if result.testsRun != EXPECTED_TEST_COUNT:
        print(
            f"read-only no-child suite ran {result.testsRun} "
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
            "read-only no-child suite contained a non-passing outcome",
            file=sys.stderr,
        )
        return 1
    if not result.wasSuccessful():
        return 1
    print(SUCCESS_RECORD, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
