from __future__ import annotations

import re


CLAUDE_COMPATIBILITY_SPEC = ">=2.1.211,<3.0.0"
CLAUDE_MINIMUM_VERSION = (2, 1, 211)
CLAUDE_MAXIMUM_VERSION = (3, 0, 0)
CLAUDE_VERSION_COMPONENT_MAX_DIGITS = 9
_VERSION_COMPONENT = rf"(?:0|[1-9][0-9]{{0,{CLAUDE_VERSION_COMPONENT_MAX_DIGITS - 1}}})"
CLAUDE_RELEASE_VERSION = re.compile(
    rf"^(?P<major>{_VERSION_COMPONENT})\."
    rf"(?P<minor>{_VERSION_COMPONENT})\."
    rf"(?P<patch>{_VERSION_COMPONENT})$"
)


class ClaudeVersionPolicyError(ValueError):
    pass


def parse_release_version(version: str) -> tuple[int, int, int]:
    """Parse one bounded, canonical, stable three-component release."""

    if not isinstance(version, str) or len(version) > 32:
        raise ClaudeVersionPolicyError(
            "Claude Code version must be a bounded release semver string"
        )
    match = CLAUDE_RELEASE_VERSION.fullmatch(version)
    if match is None:
        raise ClaudeVersionPolicyError(
            f"Claude Code version is not strict release semver: {version!r}"
        )
    parsed = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
    return (parsed[0], parsed[1], parsed[2])


def parse_compatible_release_version(version: str) -> tuple[int, int, int]:
    """Parse one stable release admitted by the canonical Claude policy."""

    typed = parse_release_version(version)
    if not CLAUDE_MINIMUM_VERSION <= typed < CLAUDE_MAXIMUM_VERSION:
        raise ClaudeVersionPolicyError(
            "Claude Code version is outside the supported range "
            f"{CLAUDE_COMPATIBILITY_SPEC}: {version}"
        )
    return typed


def is_compatible_release_version(version: str) -> bool:
    try:
        parse_compatible_release_version(version)
    except ClaudeVersionPolicyError:
        return False
    return True
