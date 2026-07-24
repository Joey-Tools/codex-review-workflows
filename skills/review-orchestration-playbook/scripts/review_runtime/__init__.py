"""Runtime support for the isolated review helper."""

import sys

sys.dont_write_bytecode = True


def main(argv: list[str] | None = None) -> int:
    """Run the compatibility CLI without importing it for named-lane consumers."""
    from .cli import main as cli_main

    return cli_main(argv)


__all__ = ["main"]
