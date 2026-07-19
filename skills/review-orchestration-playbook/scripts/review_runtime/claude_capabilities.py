from __future__ import annotations

import re
from dataclasses import dataclass


CLAUDE_MINIMUM_VERSION = (2, 1, 211)
CLAUDE_NEXT_MAJOR_VERSION = (3, 0, 0)
CLAUDE_VERSION_COMPONENT_MAX_DIGITS = 9
_CLAUDE_VERSION_COMPONENT = (
    rf"(?:0|[1-9][0-9]{{0,{CLAUDE_VERSION_COMPONENT_MAX_DIGITS - 1}}})"
)
CLAUDE_VERSION_LINE = re.compile(
    rf"^(?P<major>{_CLAUDE_VERSION_COMPONENT})\."
    rf"(?P<minor>{_CLAUDE_VERSION_COMPONENT})\."
    rf"(?P<patch>{_CLAUDE_VERSION_COMPONENT}) \(Claude Code\)$"
)
CLAUDE_HELP_OPTION_START = re.compile(
    r"^  (?:-[A-Za-z], )?(--[A-Za-z0-9][A-Za-z0-9-]*)\b"
)
CLAUDE_HELP_OPTION_DECLARATION = re.compile(
    r"^  (?P<options>(?:-[A-Za-z], )?"
    r"--[A-Za-z0-9][A-Za-z0-9-]*"
    r"(?:, --[A-Za-z0-9][A-Za-z0-9-]*)*)"
)
CLAUDE_HELP_OPTION_TOKEN = re.compile(
    r"(?<![A-Za-z0-9-])--[A-Za-z0-9][A-Za-z0-9-]*"
)
CLAUDE_DONT_ASK_CHOICE = re.compile(r"(?<![a-z0-9])dontask(?![a-z0-9])")
# These are the exact public options used by the helper's authenticated Claude
# commands. Help text is not treated as an ABI: option descriptions may change,
# but removal of an option that the helper invokes must fail closed.
CLAUDE_REQUIRED_OPTIONS = (
    "--print",
    "--model",
    "--effort",
    "--permission-mode",
    "--output-format",
    "--no-session-persistence",
    "--safe-mode",
    "--no-chrome",
    "--disable-slash-commands",
    "--strict-mcp-config",
    "--mcp-config",
    "--setting-sources",
    "--settings",
    "--tools",
    "--allowedTools",
    "--disallowedTools",
)

CLAUDE_SAFE_MODE_CUSTOMIZATION_CLAIM = (
    ("all customizations",),
    ("claude.md",),
    ("skills",),
    ("plugins",),
    ("hooks",),
    ("mcp",),
    ("custom commands",),
    ("agents",),
    ("output styles",),
    ("workflows",),
    ("themes",),
    ("keybindings",),
    ("disabled",),
)
CLAUDE_SAFE_MODE_POLICY_CLAIM = (
    ("admin-managed", "managed policy", "policy settings"),
    ("still apply", "remain active"),
)
CLAUDE_SAFE_MODE_RUNTIME_CLAIM = (
    ("auth", "authentication"),
    ("model selection",),
    ("built-in tools",),
    ("permissions",),
    ("work normally", "remain available", "still work"),
)
CLAUDE_SAFE_MODE_ENVIRONMENT_TERM = (("claude_code_safe_mode=1",),)
CLAUDE_SAFE_MODE_REQUIRED_TERMS = (
    *CLAUDE_SAFE_MODE_CUSTOMIZATION_CLAIM,
    *CLAUDE_SAFE_MODE_POLICY_CLAIM,
    *CLAUDE_SAFE_MODE_RUNTIME_CLAIM,
    *CLAUDE_SAFE_MODE_ENVIRONMENT_TERM,
)
CLAUDE_SAFE_MODE_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
# Natural-language safety claims are accepted only when their whole sentence is
# unconditional. This intentionally rejects wording that would require semantic
# interpretation (exceptions, contrasts, modality, or hedging).
CLAUDE_SAFE_MODE_CLAIM_AMBIGUITY = re.compile(
    r"\b(?:not|never|no|neither|nor|without|rarely|seldom|cannot|hardly|scarcely)\b"
    r"|\b(?:unless|except(?:ion(?:s)?|ed|ing)?|excluding|excluded)\b"
    r"|\b(?:apart\s+from|other\s+than|anything\s+but|by\s+no\s+means)\b"
    r"|\b(?:but|however|yet|although|though|nevertheless|nonetheless|whereas|while)\b"
    r"|\b(?:may|might|can|could|should|would|must|perhaps|possibly)\b"
    r"|\b(?:if|when|whenever|once|until|provided|assuming|depending|otherwise)\b"
    r"|\b(?:only|default|initially|temporarily|eventually|later|briefly)\b"
    r"|\b(?:before|after|during|then|subsequently|thereafter|afterwards?)\b"
    r"|\b(?:sometimes|usually|generally|typically|mostly|partly|partially)\b"
    r"|\b(?:subject\s+to|for\s+now|at\s+first|where\s+possible)\b"
    r"|\b[a-z]+n['\N{RIGHT SINGLE QUOTATION MARK}]t\b"
    r"|\bfails?\s+to\b"
)
CLAUDE_SAFE_MODE_LEADING_CONTRAST = re.compile(
    r"^(?:but|however|yet|although|though|nevertheless|nonetheless)\b"
)
CLAUDE_SAFE_MODE_ANAPHORIC_CONTINUATION = re.compile(
    r"^[\s\"'\N{LEFT DOUBLE QUOTATION MARK}\N{LEFT SINGLE QUOTATION MARK}(\[]*"
    r"(?:it|they|this|that|these|those|such|the\s+former|the\s+latter)\b"
)
CLAUDE_SAFE_MODE_ANAPHORIC_REFERENCE = re.compile(
    r"(?<![a-z0-9])(?:it|this|that|the\s+mode)(?![a-z0-9])"
)
CLAUDE_SAFE_MODE_CUSTOMIZATION_FORBIDDEN_STATE = re.compile(
    r"\b(?:enabled?|enables|enabling|active|available)\b"
    r"|\b(?:load|loads|loaded|loading|run|runs|running)\b"
    r"|\b(?:apply|applies|applied|applying|execute|executes|executed|executing)\b"
    r"|\b(?:restore(?:d|s|ing)?|re-?enable(?:d|s|ing)?|"
    r"reactivate(?:d|s|ing)?|resume(?:d|s|ing)?|reinstate(?:d|s|ing)?)\b"
)
_CLAUDE_SAFE_MODE_CUSTOMIZATION_ITEM = (
    r"(?:claude\.md|skills|plugins|hooks|mcp(?:\s+servers)?|"
    r"custom\s+commands|agents|output\s+styles|workflows|"
    r"(?:custom\s+)?themes|keybindings|more)"
)
_CLAUDE_SAFE_MODE_CUSTOMIZATION_LIST = (
    _CLAUDE_SAFE_MODE_CUSTOMIZATION_ITEM
    + r"(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)"
    + _CLAUDE_SAFE_MODE_CUSTOMIZATION_ITEM
    + r")*"
)
_CLAUDE_SAFE_MODE_CUSTOMIZATION_DURATION = (
    r"(?:"
    r"(?:throughout|during)\s+(?:the\s+)?"
    r"(?:review(?:\s+session)?|session|run|invocation|safe\s+mode)"
    r"|for\s+(?:the\s+)?(?:entire\s+)?"
    r"(?:review(?:\s+session)?|session|run|invocation|"
    r"duration\s+of\s+(?:the\s+)?review(?:\s+session)?)"
    r")"
)
_CLAUDE_SAFE_MODE_CUSTOMIZATION_BENIGN_PURPOSE = (
    r"—\s+useful\s+for\s+troubleshooting\s+a\s+broken\s+configuration"
)
CLAUDE_SAFE_MODE_CUSTOMIZATION_POSITIVE_CLAIM = re.compile(
    r"^(?:"
    r"start(?:s)?\s+with\s+all\s+customizations\s*\(\s*"
    + _CLAUDE_SAFE_MODE_CUSTOMIZATION_LIST
    + r"\s*\)\s+disabled"
    r"|all\s+customizations\s*\(\s*"
    + _CLAUDE_SAFE_MODE_CUSTOMIZATION_LIST
    + r"\s*\)\s+(?:are|remain|stay)\s+disabled"
    r")"
    r"(?:\s+(?:"
    + _CLAUDE_SAFE_MODE_CUSTOMIZATION_DURATION
    + r"|"
    + _CLAUDE_SAFE_MODE_CUSTOMIZATION_BENIGN_PURPOSE
    + r"))?[.!?]?$"
)
CLAUDE_SAFE_MODE_POSITIVE_CUSTOMIZATION_ANAPHOR = re.compile(
    r"^they\s+(?:are|remain|stay)\s+disabled[.!?]?$"
)
_CLAUDE_SAFE_MODE_POLICY_SUBJECT = (
    r"(?:admin-managed(?:\s+\(policy\))?(?:\s+policy)?\s+settings"
    r"|managed\s+policy\s+settings|policy\s+settings)"
)
CLAUDE_SAFE_MODE_POLICY_POSITIVE_CLAIM = re.compile(
    r"^"
    + _CLAUDE_SAFE_MODE_POLICY_SUBJECT
    + r"\s+(?:still\s+appl(?:y|ies)|remain(?:s)?\s+active)[.!?]?$"
)
_CLAUDE_SAFE_MODE_RUNTIME_TARGET = (
    r"(?:auth(?:entication)?|model\s+selection|built-in\s+tools|permissions)"
)
_CLAUDE_SAFE_MODE_RUNTIME_TARGETS = (
    _CLAUDE_SAFE_MODE_RUNTIME_TARGET
    + r"(?:\s*(?:,\s*(?:and\s+)?|and\s+)"
    + _CLAUDE_SAFE_MODE_RUNTIME_TARGET
    + r")*"
)
CLAUDE_SAFE_MODE_RUNTIME_POSITIVE_CLAIM = re.compile(
    r"^"
    + _CLAUDE_SAFE_MODE_RUNTIME_TARGETS
    + r"\s+(?:work\s+normally|remain\s+available|still\s+work)[.!?]?$"
)
CLAUDE_SAFE_MODE_ENVIRONMENT_POSITIVE_CLAIM = re.compile(
    r"^(?:sets\s+)?claude_code_safe_mode=1[.!?]?$"
)
_CLAUDE_SAFE_MODE_INFORMATION_TOPIC = (
    r"(?:safe(?:\s+|-)mode|customizations|project\s+instructions)"
)
CLAUDE_SAFE_MODE_HARMLESS_INFORMATION = re.compile(
    r"^(?:documentation|information)"
    r"\s+about\s+"
    + _CLAUDE_SAFE_MODE_INFORMATION_TOPIC
    + r"\s+(?:is|remains)\s+available\s+online[.!?]?$"
)
CLAUDE_SAFE_MODE_POLICY_FORBIDDEN_STATE = re.compile(
    r"\b(?:disabled|inactive|ignored|unavailable|blocked|overridden|bypassed)\b"
    r"|\b(?:fail|fails|failed|failing)\b"
)
CLAUDE_SAFE_MODE_RUNTIME_FORBIDDEN_STATE = re.compile(
    r"\b(?:disabled|inactive|ignored|unavailable|blocked|restricted|limited)\b"
    r"|\b(?:broken|degraded|unusable|fail|fails|failed|failing)\b"
)
CLAUDE_SAFE_MODE_ENVIRONMENT_FORBIDDEN_STATE = re.compile(
    r"\b(?:unset|disabled|cleared|reset|overridden|changed)\b"
)
CLAUDE_SAFE_MODE_ENVIRONMENT_NAME = re.compile(
    r"(?<![a-z0-9_])claude_code_safe_mode(?![a-z0-9_])"
)
CLAUDE_SAFE_MODE_ENVIRONMENT_ASSIGNMENT = re.compile(
    r"(?<![a-z0-9_])claude_code_safe_mode=1"
    r"(?=$|[\s,;:!?)\]}]|\.(?=\s|$))"
)
_CLAUDE_SAFE_MODE_NAME = (
    r"(?<![a-z0-9-])(?:safe(?:\s+|-)mode|--safe-mode)(?![a-z0-9-])"
)
CLAUDE_SAFE_MODE_SELF_REFERENCE = re.compile(_CLAUDE_SAFE_MODE_NAME)
CLAUDE_SAFE_MODE_DECLARATION_PREFIX = re.compile(
    r"^(?:-[a-z],\s+)?--safe-mode\b"
    r"(?:\s+(?:<[^>]{1,64}>|\[[^\]]{1,64}\]))?\s*"
)
_CLAUDE_SAFE_MODE_SUBJECT = (
    r"(?:the\s+)?"
    + _CLAUDE_SAFE_MODE_NAME
    + r"(?:(?:\s+(?:itself|enforcement|protection|isolation))|"
    r"(?:['\N{RIGHT SINGLE QUOTATION MARK}]s\s+"
    r"(?:enforcement|protection|isolation)))?"
)
_CLAUDE_SAFE_MODE_PREFIX = (
    r"^[\s`\"'\N{LEFT DOUBLE QUOTATION MARK}\N{LEFT SINGLE QUOTATION MARK}(\[]*"
    r"(?:(?:currently|now|by\s+design|in\s+this\s+release|"
    r"for\s+this\s+version)\s*,\s*)?"
)
_CLAUDE_SAFE_MODE_WEAKENING_ACTION = (
    r"(?:disabled|turned\s+off|switched\s+off|bypassed|ignored|removed|"
    r"deprecated|overridden|deactivated)"
)
_CLAUDE_SAFE_MODE_WEAKENING_ACTIONS = (
    _CLAUDE_SAFE_MODE_WEAKENING_ACTION
    + r"(?:\s+(?:and|or)\s+"
    + _CLAUDE_SAFE_MODE_WEAKENING_ACTION
    + r")*"
)
_CLAUDE_SAFE_MODE_PREVENTED_PREDICATE = (
    r"(?:"
    r"(?:cannot|can['\N{RIGHT SINGLE QUOTATION MARK}]t|could\s+not|"
    r"couldn['\N{RIGHT SINGLE QUOTATION MARK}]t|must\s+not|may\s+not|"
    r"will\s+not|won['\N{RIGHT SINGLE QUOTATION MARK}]t)\s+(?:be\s+)?"
    + _CLAUDE_SAFE_MODE_WEAKENING_ACTIONS
    + r"|(?:has\s+not|hasn['\N{RIGHT SINGLE QUOTATION MARK}]t|had\s+not|"
    r"hadn['\N{RIGHT SINGLE QUOTATION MARK}]t)\s+(?:ever\s+)?(?:been\s+)?"
    + _CLAUDE_SAFE_MODE_WEAKENING_ACTIONS
    + r"|(?:is|remains?)\s+never\s+"
    + _CLAUDE_SAFE_MODE_WEAKENING_ACTIONS
    + r")"
)
_CLAUDE_SAFE_MODE_POSITIVE_STATUS = (
    r"(?:"
    r"(?:is|remains?|stays?|continues\s+to\s+be)\s+"
    r"(?:(?:fully|strictly|always|currently|actively|explicitly)\s+){0,3}"
    r"(?:enabled|enforced|active|effective|supported|available|required|mandatory)"
    r"|(?:is|remains?|stays?)\s+not\s+(?:optional|advisory|bypassable))"
)
_CLAUDE_SAFE_MODE_POSITIVE_PREDICATE = (
    r"(?:"
    + _CLAUDE_SAFE_MODE_POSITIVE_STATUS
    + r"(?:\s+and\s+"
    + _CLAUDE_SAFE_MODE_PREVENTED_PREDICATE
    + r")?|"
    + _CLAUDE_SAFE_MODE_PREVENTED_PREDICATE
    + r"|(?:does\s+not|doesn['\N{RIGHT SINGLE QUOTATION MARK}]t|never)\s+"
    r"(?:fail\s+open|stop\s+working))"
)
CLAUDE_SAFE_MODE_POSITIVE_SELF_CLAIM = re.compile(
    _CLAUDE_SAFE_MODE_PREFIX
    + _CLAUDE_SAFE_MODE_SUBJECT
    + r"\s+"
    + _CLAUDE_SAFE_MODE_POSITIVE_PREDICATE
    + r"[.!?]?$"
)
CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_CLAIM = re.compile(
    r"^[\s`\"'\N{LEFT DOUBLE QUOTATION MARK}\N{LEFT SINGLE QUOTATION MARK}(\[]*"
    r"(?:it|this|that|the\s+former|the\s+latter)\s+"
    + _CLAUDE_SAFE_MODE_POSITIVE_PREDICATE
    + r"[.!?]?$"
)
_CLAUDE_SAFE_MODE_PRESERVED_TARGET = (
    r"(?:auth(?:entication)?|model\s+selection|built-in\s+tools|permissions|"
    r"admin-managed(?:\s+policy)?(?:\s+settings)?|"
    r"managed\s+policy(?:\s+settings)?|policy\s+settings)"
)
_CLAUDE_SAFE_MODE_PRESERVED_TARGETS = (
    _CLAUDE_SAFE_MODE_PRESERVED_TARGET
    + r"(?:\s*(?:,\s*(?:(?:and|or)\s+)?|(?:and|or)\s+)"
    + _CLAUDE_SAFE_MODE_PRESERVED_TARGET
    + r")*"
)
CLAUDE_SAFE_MODE_PRESERVED_SCOPE_CLAIM = re.compile(
    _CLAUDE_SAFE_MODE_PREFIX
    + _CLAUDE_SAFE_MODE_SUBJECT
    + r"\s+(?:"
    r"has\s+no\s+effect\s+(?:on|to)\s+"
    r"|(?:does\s+not|doesn['\N{RIGHT SINGLE QUOTATION MARK}]t|will\s+not|"
    r"won['\N{RIGHT SINGLE QUOTATION MARK}]t)\s+"
    r"(?:apply\s+to|affect|change|disable|restrict|override|remove|bypass)\s+"
    r"|never\s+(?:applies\s+to|affects|changes|disables|restricts|overrides|"
    r"removes|bypasses)\s+)"
    + _CLAUDE_SAFE_MODE_PRESERVED_TARGETS
    + r"[.!?]?$"
)
CLAUDE_SAFE_MODE_DIRECT_REQUIRED_ACTION_CLAIM = re.compile(
    _CLAUDE_SAFE_MODE_PREFIX
    + _CLAUDE_SAFE_MODE_SUBJECT
    + r"\s+(?:disables?\s+all\s+customizations|keeps?\s+"
    + _CLAUDE_SAFE_MODE_PRESERVED_TARGETS
    + r"\s+(?:working\s+normally|available|active|enabled))[.!?]?$"
)
_CLAUDE_SAFE_MODE_ACTION = (
    r"(?:disable|bypass|ignore|remove|deprecate|override|deactivate|"
    r"turn\s+off|switch\s+off)"
)
_CLAUDE_SAFE_MODE_ACTOR = (
    r"(?:administrators?|process(?:es)?|users?|operators?|callers?|plugins?|"
    r"extensions?|hooks?|they|you)"
)
CLAUDE_SAFE_MODE_PREVENTED_WEAKENING_CLAIM = re.compile(
    r"^(?:"
    r"(?:disabling|bypassing|ignoring|removing|deprecating|overriding|"
    r"deactivating|turning\s+off|switching\s+off)\s+"
    r"(?:the\s+)?"
    + _CLAUDE_SAFE_MODE_NAME
    + r"\s+"
    r"(?:is|remains?)\s+(?:not\s+supported|unsupported|unavailable|prohibited|"
    r"forbidden|impossible|blocked|disallowed)"
    r"|(?:no\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"|no\s+one|nobody)\s+(?:can|could|may|will|would)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+(?:the\s+)?"
    + _CLAUDE_SAFE_MODE_NAME
    + r"|neither\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+nor\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+"
    r"(?:can|could|may|will|would)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+(?:the\s+)?"
    + _CLAUDE_SAFE_MODE_NAME
    + r"|"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+(?:cannot|can['\N{RIGHT SINGLE QUOTATION MARK}]t|"
    r"could\s+not|couldn['\N{RIGHT SINGLE QUOTATION MARK}]t|may\s+not|"
    r"must\s+not|will\s+not|won['\N{RIGHT SINGLE QUOTATION MARK}]t|"
    r"(?:is|are)\s+not\s+allowed\s+to|(?:is|are)\s+prohibited\s+from)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+(?:the\s+)?"
    + _CLAUDE_SAFE_MODE_NAME
    + r")[.!?]?$"
)
_CLAUDE_SAFE_MODE_ANAPHORIC_OBJECT = r"(?:it|this|that|the\s+mode)"
CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_OBJECT_CLAIM = re.compile(
    r"^(?:"
    r"(?:no\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"|no\s+one|nobody)\s+(?:can|could|may|will|would)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+"
    + _CLAUDE_SAFE_MODE_ANAPHORIC_OBJECT
    + r"|neither\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+nor\s+"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+(?:can|could|may|will|would)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+"
    + _CLAUDE_SAFE_MODE_ANAPHORIC_OBJECT
    + r"|"
    + _CLAUDE_SAFE_MODE_ACTOR
    + r"\s+(?:cannot|can['\N{RIGHT SINGLE QUOTATION MARK}]t|could\s+not|"
    r"couldn['\N{RIGHT SINGLE QUOTATION MARK}]t|may\s+not|must\s+not|"
    r"will\s+not|won['\N{RIGHT SINGLE QUOTATION MARK}]t|"
    r"(?:is|are)\s+not\s+allowed\s+to|(?:is|are)\s+prohibited\s+from)\s+"
    + _CLAUDE_SAFE_MODE_ACTION
    + r"\s+"
    + _CLAUDE_SAFE_MODE_ANAPHORIC_OBJECT
    + r")[.!?]?$"
)

CLAUDE_SAFE_MODE_CONTRADICTIONS = (
    "customizations enabled",
    "customizations still load",
    "hooks enabled",
    "hooks still load",
    "hooks remain enabled",
    "mcp enabled",
    "mcp servers still load",
    "mcp servers remain enabled",
    "auth disabled",
    "authentication disabled",
    "permissions disabled",
    "claude_code_safe_mode=0",
)


class ClaudeCapabilityError(ValueError):
    """Claude Code does not satisfy the helper's public CLI contract."""


class ClaudeCapabilityUnavailable(ClaudeCapabilityError):
    """A supported release does not expose a required public CLI option."""


class ClaudeSafetyContractInvalid(ClaudeCapabilityError):
    """Claude Code makes an ambiguous or unsafe safe-mode claim."""


@dataclass(frozen=True)
class ClaudeVersion:
    text: str
    parts: tuple[int, int, int]


@dataclass(frozen=True)
class ClaudeCapabilities:
    version: ClaudeVersion
    required_options: tuple[str, ...]
    safe_mode_summary: str


def parse_claude_version(output: str) -> ClaudeVersion:
    lines = tuple(line.strip() for line in output.splitlines() if line.strip())
    if len(lines) != 1:
        raise ClaudeCapabilityError(
            "Claude Code version output must contain exactly one non-empty line"
        )
    match = CLAUDE_VERSION_LINE.fullmatch(lines[0])
    if match is None:
        raise ClaudeCapabilityError(
            "Claude Code version output is not a stable three-component release"
        )
    try:
        parts = tuple(
            int(match.group(name)) for name in ("major", "minor", "patch")
        )
    except (ValueError, OverflowError) as error:
        raise ClaudeCapabilityError(
            "Claude Code version contains an invalid numeric component"
        ) from error
    assert len(parts) == 3
    typed_parts = (parts[0], parts[1], parts[2])
    if not CLAUDE_MINIMUM_VERSION <= typed_parts < CLAUDE_NEXT_MAJOR_VERSION:
        raise ClaudeCapabilityError(
            "Claude Code version is outside the supported >=2.1.211,<3 range"
        )
    return ClaudeVersion(".".join(str(part) for part in typed_parts), typed_parts)


def _help_option_blocks(help_text: str, option: str) -> tuple[str, ...]:
    blocks: list[str] = []
    current: list[str] | None = None
    current_option = ""
    for line in help_text.splitlines():
        match = CLAUDE_HELP_OPTION_START.match(line)
        if match:
            if current is not None and current_option == option:
                blocks.append(" ".join(" ".join(current).lower().split()))
            current = [line.strip()]
            current_option = match.group(1)
        elif current is not None:
            current.append(line.strip())
    if current is not None and current_option == option:
        blocks.append(" ".join(" ".join(current).lower().split()))
    return tuple(blocks)


def _declared_options(help_text: str) -> tuple[str, ...]:
    result: list[str] = []
    for line in help_text.splitlines():
        declaration = CLAUDE_HELP_OPTION_DECLARATION.match(line)
        if declaration is None:
            continue
        # Only the declaration line is inspected. Description continuations are
        # deliberately ignored because they can mention unrelated options.
        result.extend(
            CLAUDE_HELP_OPTION_TOKEN.findall(declaration.group("options"))
        )
    return tuple(result)


def _has_semantic_term(text: str, term: str) -> bool:
    return re.search(
        rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])",
        text,
    ) is not None


def _has_positive_safe_mode_claim(
    sentences: tuple[str, ...],
    required_terms: tuple[tuple[str, ...], ...],
    subject_terms: tuple[tuple[str, ...], ...],
    forbidden_state: re.Pattern[str],
    *,
    positive_claim: re.Pattern[str] | None = None,
) -> bool:
    claim_sentences = tuple(
        (
            CLAUDE_SAFE_MODE_DECLARATION_PREFIX.sub("", sentence, count=1)
            if index == 0
            else sentence
        )
        for index, sentence in enumerate(sentences)
    )
    relevant_sentences = tuple(
        sentence
        for sentence in claim_sentences
        if any(
            _has_semantic_term(sentence, term)
            for alternatives in subject_terms
            for term in alternatives
        )
    )
    if positive_claim is not None:
        primary_claims = tuple(
            sentence
            for sentence in relevant_sentences
            if positive_claim.fullmatch(sentence) is not None
        )
        return bool(primary_claims) and all(
            positive_claim.fullmatch(sentence) is not None
            or _is_allowed_safe_mode_self_claim(sentence)
            or CLAUDE_SAFE_MODE_HARMLESS_INFORMATION.fullmatch(sentence) is not None
            for sentence in relevant_sentences
        ) and any(
            all(
                any(_has_semantic_term(sentence, term) for term in alternatives)
                for alternatives in required_terms
            )
            for sentence in primary_claims
        )
    unsafe_relevant_sentences = tuple(
        sentence
        for sentence in relevant_sentences
        if not _is_allowed_safe_mode_self_claim(sentence)
    )
    if any(
        (
            CLAUDE_SAFE_MODE_CLAIM_AMBIGUITY.search(sentence) is not None
            and CLAUDE_SAFE_MODE_PRESERVED_SCOPE_CLAIM.fullmatch(sentence) is None
        )
        or forbidden_state.search(sentence) is not None
        for sentence in unsafe_relevant_sentences
    ):
        return False
    return any(
        all(
            any(_has_semantic_term(sentence, term) for term in alternatives)
            for alternatives in required_terms
        )
        for sentence in relevant_sentences
    )


def _has_unambiguous_safe_mode_environment_claim(
    block: str,
    sentences: tuple[str, ...],
) -> bool:
    names = tuple(CLAUDE_SAFE_MODE_ENVIRONMENT_NAME.finditer(block))
    assignments = tuple(CLAUDE_SAFE_MODE_ENVIRONMENT_ASSIGNMENT.finditer(block))
    if len(names) != 1 or len(assignments) != 1:
        return False
    return any(
        CLAUDE_SAFE_MODE_ENVIRONMENT_ASSIGNMENT.search(sentence) is not None
        and CLAUDE_SAFE_MODE_CLAIM_AMBIGUITY.search(sentence) is None
        and CLAUDE_SAFE_MODE_ENVIRONMENT_FORBIDDEN_STATE.search(sentence) is None
        for sentence in sentences
    )


def _is_allowed_safe_mode_self_claim(sentence: str) -> bool:
    return any(
        pattern.fullmatch(sentence) is not None
        for pattern in (
            CLAUDE_SAFE_MODE_CUSTOMIZATION_POSITIVE_CLAIM,
            CLAUDE_SAFE_MODE_POSITIVE_SELF_CLAIM,
            CLAUDE_SAFE_MODE_PRESERVED_SCOPE_CLAIM,
            CLAUDE_SAFE_MODE_DIRECT_REQUIRED_ACTION_CLAIM,
            CLAUDE_SAFE_MODE_PREVENTED_WEAKENING_CLAIM,
        )
    )


def _safe_mode_claim_sentences(sentences: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        (
            CLAUDE_SAFE_MODE_DECLARATION_PREFIX.sub("", sentence, count=1)
            if index == 0
            else sentence
        )
        for index, sentence in enumerate(sentences)
    )


def _has_only_allowed_safe_mode_sentences(sentences: tuple[str, ...]) -> bool:
    """Require every sentence to match one bounded positive grammar."""
    customization_antecedent_active = False
    self_antecedent_active = False
    for sentence in _safe_mode_claim_sentences(sentences):
        if not sentence:
            return False
        if CLAUDE_SAFE_MODE_CUSTOMIZATION_POSITIVE_CLAIM.fullmatch(sentence):
            customization_antecedent_active = True
            continue
        if (
            customization_antecedent_active
            and CLAUDE_SAFE_MODE_POSITIVE_CUSTOMIZATION_ANAPHOR.fullmatch(sentence)
        ):
            customization_antecedent_active = False
            continue
        customization_antecedent_active = False
        if CLAUDE_SAFE_MODE_POLICY_POSITIVE_CLAIM.fullmatch(sentence):
            continue
        if CLAUDE_SAFE_MODE_RUNTIME_POSITIVE_CLAIM.fullmatch(sentence):
            continue
        if CLAUDE_SAFE_MODE_ENVIRONMENT_POSITIVE_CLAIM.fullmatch(sentence):
            continue
        if _is_allowed_safe_mode_self_claim(sentence):
            self_antecedent_active = True
            continue
        if CLAUDE_SAFE_MODE_HARMLESS_INFORMATION.fullmatch(sentence):
            continue
        if self_antecedent_active and (
            CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_CLAIM.fullmatch(sentence)
            or CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_OBJECT_CLAIM.fullmatch(sentence)
        ):
            continue
        return False
    return True


def _has_unsafe_safe_mode_self_reference(sentences: tuple[str, ...]) -> bool:
    for index, sentence in enumerate(sentences):
        candidate = sentence
        if index == 0:
            candidate = CLAUDE_SAFE_MODE_DECLARATION_PREFIX.sub("", candidate, count=1)
        if CLAUDE_SAFE_MODE_SELF_REFERENCE.search(candidate) is None:
            continue
        if (
            _is_allowed_safe_mode_self_claim(candidate)
            or CLAUDE_SAFE_MODE_HARMLESS_INFORMATION.fullmatch(candidate)
        ):
            continue
        return True
    return False


def _has_unsafe_safe_mode_continuation(sentences: tuple[str, ...]) -> bool:
    claim_kinds = (
        (
            CLAUDE_SAFE_MODE_CUSTOMIZATION_CLAIM[:-1],
            CLAUDE_SAFE_MODE_CUSTOMIZATION_FORBIDDEN_STATE,
        ),
        (
            CLAUDE_SAFE_MODE_POLICY_CLAIM[:1],
            CLAUDE_SAFE_MODE_POLICY_FORBIDDEN_STATE,
        ),
        (
            CLAUDE_SAFE_MODE_RUNTIME_CLAIM[:-1],
            CLAUDE_SAFE_MODE_RUNTIME_FORBIDDEN_STATE,
        ),
    )
    self_antecedent_active = False
    for index, sentence in enumerate(sentences):
        self_reference_candidate = sentence
        if index == 0:
            self_reference_candidate = CLAUDE_SAFE_MODE_DECLARATION_PREFIX.sub(
                "",
                sentence,
                count=1,
            )
        if CLAUDE_SAFE_MODE_SELF_REFERENCE.search(self_reference_candidate) is not None:
            self_antecedent_active = True
            continue
        if not self_antecedent_active:
            continue
        if CLAUDE_SAFE_MODE_ANAPHORIC_REFERENCE.search(sentence) is None:
            continue
        if not (
            CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_CLAIM.fullmatch(sentence) is not None
            or CLAUDE_SAFE_MODE_POSITIVE_ANAPHORIC_OBJECT_CLAIM.fullmatch(sentence)
            is not None
        ):
            return True

    for previous, continuation in zip(sentences, sentences[1:]):
        relevant_forbidden_states = tuple(
            forbidden_state
            for subject_terms, forbidden_state in claim_kinds
            if any(
                _has_semantic_term(previous, term)
                for alternatives in subject_terms
                for term in alternatives
            )
        )
        previous_is_environment_claim = (
            CLAUDE_SAFE_MODE_ENVIRONMENT_NAME.search(previous) is not None
        )
        if previous_is_environment_claim:
            relevant_forbidden_states = (
                *relevant_forbidden_states,
                CLAUDE_SAFE_MODE_ENVIRONMENT_FORBIDDEN_STATE,
            )
        if not relevant_forbidden_states and not previous_is_environment_claim:
            continue
        if CLAUDE_SAFE_MODE_ANAPHORIC_CONTINUATION.search(continuation) is None:
            continue
        if CLAUDE_SAFE_MODE_CLAIM_AMBIGUITY.search(continuation) is not None or any(
            forbidden_state.search(continuation) is not None
            for forbidden_state in relevant_forbidden_states
        ):
            return True
    return False


def validate_claude_help(help_text: str) -> tuple[tuple[str, ...], str]:
    declared = _declared_options(help_text)
    missing = tuple(option for option in CLAUDE_REQUIRED_OPTIONS if option not in declared)
    duplicates = tuple(
        option for option in CLAUDE_REQUIRED_OPTIONS if declared.count(option) != 1
    )
    if missing:
        raise ClaudeCapabilityUnavailable(
            "Claude Code help does not uniquely declare every required review option"
            f": {', '.join(missing)}"
        )
    if duplicates:
        raise ClaudeSafetyContractInvalid(
            "Claude Code help ambiguously declares required review options"
            f": {', '.join(duplicates)}"
        )

    permission_mode_blocks = _help_option_blocks(help_text, "--permission-mode")
    if len(permission_mode_blocks) != 1 or CLAUDE_DONT_ASK_CHOICE.search(
        permission_mode_blocks[0]
    ) is None:
        raise ClaudeCapabilityUnavailable(
            "Claude Code --permission-mode does not advertise the required dontAsk "
            "choice"
        )

    safe_mode_blocks = _help_option_blocks(help_text, "--safe-mode")
    if len(safe_mode_blocks) != 1:
        raise ClaudeSafetyContractInvalid(
            "Claude Code does not expose one uniquely declared --safe-mode option"
        )
    block = safe_mode_blocks[0]
    sentences = tuple(CLAUDE_SAFE_MODE_SENTENCE_BOUNDARY.split(block))
    missing_semantics = tuple(
        alternatives[0]
        for alternatives in CLAUDE_SAFE_MODE_REQUIRED_TERMS
        if not any(_has_semantic_term(block, term) for term in alternatives)
    )
    missing_claims = tuple(
        label
        for label, required_terms, subject_terms, forbidden_state, positive_claim in (
            (
                "customizations disabled",
                CLAUDE_SAFE_MODE_CUSTOMIZATION_CLAIM,
                CLAUDE_SAFE_MODE_CUSTOMIZATION_CLAIM[:-1],
                CLAUDE_SAFE_MODE_CUSTOMIZATION_FORBIDDEN_STATE,
                CLAUDE_SAFE_MODE_CUSTOMIZATION_POSITIVE_CLAIM,
            ),
            (
                "managed policy remains active",
                CLAUDE_SAFE_MODE_POLICY_CLAIM,
                CLAUDE_SAFE_MODE_POLICY_CLAIM[:1],
                CLAUDE_SAFE_MODE_POLICY_FORBIDDEN_STATE,
                None,
            ),
            (
                "review runtime remains available",
                CLAUDE_SAFE_MODE_RUNTIME_CLAIM,
                CLAUDE_SAFE_MODE_RUNTIME_CLAIM[:-1],
                CLAUDE_SAFE_MODE_RUNTIME_FORBIDDEN_STATE,
                None,
            ),
        )
        if not _has_positive_safe_mode_claim(
            sentences,
            required_terms,
            subject_terms,
            forbidden_state,
            positive_claim=positive_claim,
        )
    )
    if not _has_unambiguous_safe_mode_environment_claim(block, sentences):
        missing_claims = (*missing_claims, "safe-mode environment enabled")
    if not _has_only_allowed_safe_mode_sentences(sentences):
        missing_claims = (*missing_claims, "every safe-mode sentence remains bounded")
    if any(CLAUDE_SAFE_MODE_LEADING_CONTRAST.search(sentence) for sentence in sentences):
        missing_claims = (*missing_claims, "unambiguous safe-mode continuation")
    if _has_unsafe_safe_mode_continuation(sentences):
        missing_claims = (*missing_claims, "safe-mode continuation remains positive")
    if _has_unsafe_safe_mode_self_reference(sentences):
        missing_claims = (*missing_claims, "safe mode itself remains enforced")
    contradictions = tuple(
        fragment
        for fragment in CLAUDE_SAFE_MODE_CONTRADICTIONS
        if _has_semantic_term(block, fragment)
    )
    if missing_semantics or missing_claims or contradictions:
        detail = ", ".join((*missing_semantics, *missing_claims, *contradictions))
        raise ClaudeSafetyContractInvalid(
            "Claude Code --safe-mode semantics do not satisfy the review contract"
            + (f": {detail}" if detail else "")
        )
    return CLAUDE_REQUIRED_OPTIONS, block


def validate_claude_capabilities(
    version_output: str,
    help_text: str,
) -> ClaudeCapabilities:
    version = parse_claude_version(version_output)
    required_options, safe_mode_summary = validate_claude_help(help_text)
    return ClaudeCapabilities(version, required_options, safe_mode_summary)
