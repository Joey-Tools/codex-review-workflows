from __future__ import annotations

import pathlib
import sys


SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import ReviewError, write_text_atomic  # noqa: E402
from review_runtime.state import (  # noqa: E402
    load_review_state,
    validate_cleanup_worker_lock_leases,
)
from review_runtime.workspace import (  # noqa: E402
    LegacyReviewWorkspace,
    ReviewWorkspace,
    cleanup_workspace,
    remove_bound_review_text,
    validate_retained_cleanup_postcondition,
    write_bound_review_text,
)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3:
        return 2
    try:
        lock_fds = tuple(int(argument) for argument in arguments[1:])
    except ValueError:
        return 2
    if any(descriptor < 0 for descriptor in lock_fds) or len(set(lock_fds)) != 2:
        return 2
    state_dir = pathlib.Path(arguments[0]).expanduser().resolve()
    cleanup_error_path = state_dir / "cleanup-error.txt"
    review: ReviewWorkspace | LegacyReviewWorkspace | None = None
    try:
        validate_cleanup_worker_lock_leases(state_dir, lock_fds)
        _state, review = load_review_state(state_dir)
        if isinstance(review, LegacyReviewWorkspace):
            raise ReviewError("legacy review state cannot run automatic cleanup worker")
        cleanup_error = cleanup_workspace(review, keep_container=True)
        if not cleanup_error:
            cleanup_error = validate_retained_cleanup_postcondition(review)
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
