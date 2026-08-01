from __future__ import annotations

import json


EXPECTED_TEST_COUNT = 275
EXPECTED_TEST_ID_SHA256 = (
    "c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b"
)
SUCCESS_RECORD = json.dumps(
    {
        "selected_identity_sha256": EXPECTED_TEST_ID_SHA256,
        "status": "complete",
        "tests_run": EXPECTED_TEST_COUNT,
    },
    ensure_ascii=True,
    separators=(",", ":"),
    sort_keys=True,
)
