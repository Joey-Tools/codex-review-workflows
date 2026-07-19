from __future__ import annotations

import os
import pathlib
import sys


SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import write_text_atomic  # noqa: E402
from review_runtime.state import load_review_state  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    LegacyReviewWorkspace,
    ReviewWorkspace,
    cleanup_legacy_workspace,
    cleanup_workspace,
    remove_bound_review_text,
    write_bound_review_text,
)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 2:
        return 2
    state_dir = pathlib.Path(arguments[0]).expanduser().resolve()
    cleanup_error_path = state_dir / "cleanup-error.txt"
    review: ReviewWorkspace | LegacyReviewWorkspace | None = None
    try:
        lock_fds = tuple(int(argument) for argument in arguments[1:])
        for lock_fd in lock_fds:
            os.fstat(lock_fd)
        _state, review = load_review_state(state_dir)
        if isinstance(review, LegacyReviewWorkspace):
            cleanup_error = cleanup_legacy_workspace(review, keep_container=True)
        else:
            cleanup_error = cleanup_workspace(review, keep_container=True)
        if not cleanup_error:
            if isinstance(review, ReviewWorkspace):
                remove_error = remove_bound_review_text(
                    state_dir,
                    expected=review.private_cleanup,
                    name="cleanup-error.txt",
                )
                if remove_error:
                    raise RuntimeError(
                        f"cannot clear resolved cleanup error: {remove_error}"
                    )
            else:
                cleanup_error_path.unlink(missing_ok=True)
    except BaseException as error:
        diagnostic = f"cleanup worker failed: {error}\n"
        if isinstance(review, ReviewWorkspace):
            diagnostic_error = write_bound_review_text(
                state_dir,
                expected=review.private_cleanup,
                name="cleanup-error.txt",
                text=diagnostic,
            )
            if diagnostic_error:
                print(
                    diagnostic.rstrip("\n")
                    + f"; cleanup diagnostic was not persisted: {diagnostic_error}",
                    file=sys.stderr,
                )
        elif isinstance(review, LegacyReviewWorkspace):
            write_text_atomic(cleanup_error_path, diagnostic)
        else:
            print(diagnostic.rstrip("\n"), file=sys.stderr)
        return 1
    if cleanup_error:
        if isinstance(review, ReviewWorkspace):
            diagnostic_error = write_bound_review_text(
                state_dir,
                expected=review.private_cleanup,
                name="cleanup-error.txt",
                text=cleanup_error + "\n",
            )
            if diagnostic_error:
                print(
                    cleanup_error
                    + f"; cleanup diagnostic was not persisted: {diagnostic_error}",
                    file=sys.stderr,
                )
        else:
            write_text_atomic(cleanup_error_path, cleanup_error + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
