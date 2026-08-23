"""Process-only fixture for the supervisor's authenticated internal workers."""

from __future__ import annotations

import pathlib
import sys


_ALLOWED_INTERNAL_MODES = frozenset(
    {
        "_attempt-supervisor",
        "_authorization-helper",
        "_checkout-worker",
        "_custody-helper",
        "_fifo-reader",
        "_phase-helper",
        "_prompt-helper",
        "_prompt-verifier",
    }
)

values = tuple(sys.argv[1:])
if not values or values[0] not in _ALLOWED_INTERNAL_MODES:
    sys.stderr.write("internal supervisor child fixture rejects public commands\n")
    raise SystemExit(64)

tool_root = pathlib.Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(tool_root))

from review_supervisor.cli import _run_internal  # noqa: E402

raise SystemExit(_run_internal(values[0], values[1:]))
