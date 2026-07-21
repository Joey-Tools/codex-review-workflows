from __future__ import annotations

import os
import sys
import unittest

from .test_no_child_profile import (
    NoChildProfileDarwinIntegrationTests,
    REQUIRE_LIVE_NO_CHILD_PROFILE_ENV,
)


def main() -> int:
    if os.environ.get(REQUIRE_LIVE_NO_CHILD_PROFILE_ENV) != "1":
        print(
            f"{REQUIRE_LIVE_NO_CHILD_PROFILE_ENV}=1 is required",
            file=sys.stderr,
        )
        return 2

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        NoChildProfileDarwinIntegrationTests
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(
            f"required live no-child profile suite skipped {len(result.skipped)} test(s)",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
