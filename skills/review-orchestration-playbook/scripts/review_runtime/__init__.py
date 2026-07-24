"""Runtime support for the isolated review helper."""

import sys

# CPython may cache this module before executing it, so callers must opt out first.
if not sys.dont_write_bytecode:
    raise RuntimeError("review_runtime requires bytecode to be disabled before import")


def main(argv: list[str] | None = None) -> int:
    """Run the compatibility CLI without importing it for named-lane consumers."""
    from .cli import main as cli_main

    return cli_main(argv)


__all__ = ["main"]
