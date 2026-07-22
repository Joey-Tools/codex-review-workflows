"""Classify one already-accepted review result without rewriting it."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Literal, Sequence


ASCII_WHITESPACE = " \t\n\r\v\f"
CLEAN_SENTINEL = "No findings."
MAX_RESULT_BYTES = 8 * 1024 * 1024

ContentAssessment = Literal[
    "summary-only",
    "actionable-findings",
    "undetermined",
]
ReviewOutcome = Literal["clean", "findings", "undetermined"]
ReviewPresentation = Literal[
    "canonical-clean",
    "extended-clean",
    "findings",
    "contradictory",
    "ambiguous",
    "nonconforming",
]

_CONTENT_ASSESSMENTS = frozenset(
    {"summary-only", "actionable-findings", "undetermined"}
)
_ASCII_LINE_SEPARATOR = re.compile(r"\r\n|\n|\r")


@dataclass(frozen=True)
class ReviewResultDisposition:
    raw_result: str
    review_outcome: ReviewOutcome
    presentation: ReviewPresentation


def classify_review_result(
    raw_result: str,
    *,
    content_assessment: ContentAssessment,
) -> ReviewResultDisposition:
    """Classify one already-accepted review result without rewriting it."""

    if not isinstance(raw_result, str):
        raise TypeError("raw_result must be a string")
    if not raw_result.strip(ASCII_WHITESPACE):
        raise ValueError("raw_result must contain non-ASCII-whitespace content")
    if content_assessment not in _CONTENT_ASSESSMENTS:
        raise ValueError(f"unsupported content_assessment: {content_assessment!r}")

    outer_trimmed = raw_result.strip(ASCII_WHITESPACE)
    if outer_trimmed == CLEAN_SENTINEL:
        return ReviewResultDisposition(
            raw_result=raw_result,
            review_outcome="clean",
            presentation="canonical-clean",
        )

    logical_lines = _ASCII_LINE_SEPARATOR.split(outer_trimmed)
    sentinel_count = sum(line == CLEAN_SENTINEL for line in logical_lines)
    has_terminal_sentinel = logical_lines[-1] == CLEAN_SENTINEL

    if has_terminal_sentinel and content_assessment == "actionable-findings":
        return ReviewResultDisposition(
            raw_result=raw_result,
            review_outcome="findings",
            presentation="contradictory",
        )

    if has_terminal_sentinel and sentinel_count == 1:
        if content_assessment == "summary-only":
            return ReviewResultDisposition(
                raw_result=raw_result,
                review_outcome="clean",
                presentation="extended-clean",
            )
        return ReviewResultDisposition(
            raw_result=raw_result,
            review_outcome="undetermined",
            presentation="ambiguous",
        )

    if content_assessment == "actionable-findings":
        return ReviewResultDisposition(
            raw_result=raw_result,
            review_outcome="findings",
            presentation="findings",
        )

    return ReviewResultDisposition(
        raw_result=raw_result,
        review_outcome="undetermined",
        presentation="nonconforming",
    )


def _read_bounded_result() -> str:
    payload = sys.stdin.buffer.read(MAX_RESULT_BYTES + 1)
    if len(payload) > MAX_RESULT_BYTES:
        raise ValueError("raw_result exceeds the 8 MiB input limit")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("raw_result must be valid UTF-8") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--content-assessment",
        choices=sorted(_CONTENT_ASSESSMENTS),
        required=True,
    )
    args = parser.parse_args(argv)
    try:
        disposition = classify_review_result(
            _read_bounded_result(),
            content_assessment=args.content_assessment,
        )
    except (TypeError, ValueError) as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "presentation": disposition.presentation,
                "raw_result": disposition.raw_result,
                "review_outcome": disposition.review_outcome,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
