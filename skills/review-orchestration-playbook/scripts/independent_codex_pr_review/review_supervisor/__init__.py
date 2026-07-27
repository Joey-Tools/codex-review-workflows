"""Independent Codex PR review supervisor."""

import sys

# CPython may cache this module before executing it, so callers must opt out first.
if not sys.dont_write_bytecode:
    raise RuntimeError(
        "review_supervisor requires bytecode to be disabled before import"
    )

from .constants import VERSION  # noqa: E402

__all__ = ["VERSION"]
