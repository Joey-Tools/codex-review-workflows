"""Test-only argv harness for the retained legacy review supervisor."""

from __future__ import annotations

import pathlib
import sys


def _main() -> int:
    tool_root = pathlib.Path(__file__).resolve().parent.parent
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(tool_root))

    from review_supervisor.cli import main

    return main(entrypoint=pathlib.Path(__file__))


if __name__ == "__main__":
    raise SystemExit(_main())
