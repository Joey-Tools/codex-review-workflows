"""Runtime support for the isolated review helper."""


def main(argv: list[str] | None = None) -> int:
    """Run the compatibility CLI without importing it for named-lane consumers."""
    from .cli import main as cli_main

    return cli_main(argv)


__all__ = ["main"]
