from __future__ import annotations

from dataclasses import dataclass


SECONDARY_ERROR_NOTE_PREFIX = "review-supervisor-secondary-error: "


def record_secondary_error(
    primary_error: BaseException,
    *,
    label: str,
    secondary_error: BaseException,
) -> None:
    primary_error.add_note(
        f"{SECONDARY_ERROR_NOTE_PREFIX}{label}: "
        f"{type(secondary_error).__name__}: {secondary_error}"
    )


@dataclass(frozen=True)
class Failure:
    status: str
    stage: str
    code: str
    message: str
    review_status: str = "not-run"


class SupervisorError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: str = "inconclusive",
        stage: str = "preflight",
        code: str = "fail-closed",
        review_status: str = "not-run",
    ) -> None:
        super().__init__(message)
        self.failure = Failure(
            status=status,
            stage=stage,
            code=code,
            message=message,
            review_status=review_status,
        )


class UnprovenDirectHelperClosure(RuntimeError):
    """Marks a direct helper whose exact child-process closure is unknown."""


def blocked(message: str, *, stage: str, code: str) -> SupervisorError:
    return SupervisorError(message, status="blocked", stage=stage, code=code)


def inconclusive(message: str, *, stage: str, code: str) -> SupervisorError:
    return SupervisorError(message, status="inconclusive", stage=stage, code=code)
