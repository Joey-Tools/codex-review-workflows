from __future__ import annotations

import os
import pathlib
import sys


SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import write_text_atomic  # noqa: E402
from review_runtime.state import load_review_state  # noqa: E402
from review_runtime.workspace import cleanup_workspace  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        return 2
    state_dir = pathlib.Path(arguments[0]).expanduser().resolve()
    cleanup_error_path = state_dir / "cleanup-error.txt"
    try:
        lock_fd = int(arguments[1])
        os.fstat(lock_fd)
        _state, review = load_review_state(state_dir)
        cleanup_error = cleanup_workspace(review, keep_container=True)
        if not cleanup_error:
            cleanup_error_path.unlink(missing_ok=True)
    except BaseException as error:
        write_text_atomic(
            cleanup_error_path,
            f"cleanup worker failed: {error}\n",
        )
        return 1
    if cleanup_error:
        write_text_atomic(cleanup_error_path, cleanup_error + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
