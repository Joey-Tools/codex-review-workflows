#!/usr/bin/env python3
"""Fail-closed validator for canonical Claude Code 2.1.212 JSONL streams."""

from __future__ import annotations

import argparse
import io
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Mapping


CLAUDE_CODE_VERSION = "2.1.212"
EXPECTED_TOOLS = frozenset(("Read", "Grep", "Glob", "Bash"))
EMPTY_INIT_SURFACES = ("mcp_servers", "slash_commands", "skills", "plugins")
ACCEPTED_API_KEY_SOURCES = frozenset(("none", "ANTHROPIC_API_KEY"))
SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "references"
    / "claude-2.1.212-stream-schema.json"
)
MAX_SCHEMA_BYTES = 256 * 1024

TERMINAL_REQUIRED_FIELDS = frozenset(("type", "subtype", "is_error"))
TERMINAL_VARIANT_FIELDS = frozenset(("result", "modelUsage"))
TERMINAL_OPTIONAL_FIELDS = frozenset(
    (
        "duration_ms",
        "duration_api_ms",
        "num_turns",
        "session_id",
        "total_cost_usd",
        "usage",
        "uuid",
        "stop_reason",
        "structured_output",
        "error",
        "errors",
        "api_error_status",
        "permission_denials",
    )
)
INIT_REQUIRED_FIELDS = frozenset(
    (
        "type",
        "subtype",
        "cwd",
        "permissionMode",
        "tools",
        "mcp_servers",
        "slash_commands",
        "skills",
        "plugins",
        "model",
        "claude_code_version",
        "apiKeySource",
    )
)


@dataclass(frozen=True)
class StreamLimits:
    max_bytes: int = 8 * 1024 * 1024
    max_lines: int = 10_000
    max_line_bytes: int = 1024 * 1024


DEFAULT_STREAM_LIMITS = StreamLimits()


class _DuplicateKeyError(ValueError):
    pass


class _NonstandardConstantError(ValueError):
    pass


class _ContractError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise _NonstandardConstantError(value)


def _strict_json_loads(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonstandard_constant,
    )


def _contains_unpaired_surrogate(value: Any) -> bool:
    pending = [value]
    while pending:
        current = pending.pop()
        if type(current) is str:
            index = 0
            while index < len(current):
                code_point = ord(current[index])
                if 0xD800 <= code_point <= 0xDBFF:
                    if index + 1 >= len(current):
                        return True
                    next_code_point = ord(current[index + 1])
                    if not 0xDC00 <= next_code_point <= 0xDFFF:
                        return True
                    index += 2
                    continue
                if 0xDC00 <= code_point <= 0xDFFF:
                    return True
                index += 1
        elif type(current) is list:
            pending.extend(current)
        elif type(current) is dict:
            pending.extend(current)
            pending.extend(current.values())
    return False


def _unique_string_set(value: Any, *, label: str) -> frozenset[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise _ContractError(f"{label} must be a string array")
    if len(value) != len(set(value)):
        raise _ContractError(f"{label} must not contain duplicates")
    return frozenset(value)


def _load_contract() -> dict[str, Any]:
    try:
        with SCHEMA_PATH.open("rb") as stream:
            raw = stream.read(MAX_SCHEMA_BYTES + 1)
    except OSError as error:
        raise _ContractError("schema is unreadable") from error
    if len(raw) > MAX_SCHEMA_BYTES:
        raise _ContractError("schema exceeds its size bound")
    try:
        text = raw.decode("utf-8", errors="strict")
        contract = _strict_json_loads(text)
    except Exception as error:
        raise _ContractError("schema is not strict UTF-8 JSON") from error
    if _contains_unpaired_surrogate(contract):
        raise _ContractError("schema contains an unpaired Unicode surrogate")
    if type(contract) is not dict:
        raise _ContractError("schema root must be an object")
    if contract.get("claude_code_version") != CLAUDE_CODE_VERSION:
        raise _ContractError("schema version is not exact")

    stream_contract = contract.get("stream_contract")
    if type(stream_contract) is not dict:
        raise _ContractError("stream contract is missing")
    expected_stream_contract = {
        "encoding": "utf-8",
        "format": "jsonl",
        "blank_lines": "ignored",
        "top_level": "object",
        "duplicate_keys": "reject",
        "nonstandard_constants": "reject",
        "unpaired_surrogates": "reject",
        "max_bytes": DEFAULT_STREAM_LIMITS.max_bytes,
        "max_lines": DEFAULT_STREAM_LIMITS.max_lines,
        "max_line_bytes": DEFAULT_STREAM_LIMITS.max_line_bytes,
        "first_nonblank_event": {"type": "system", "subtype": "init"},
        "last_nonblank_event": {"type": "result"},
        "init_event_count": 1,
        "result_event_count": 1,
    }
    if stream_contract != expected_stream_contract:
        raise _ContractError("stream contract does not match the validator")

    init_contract = contract.get("init_event")
    if type(init_contract) is not dict:
        raise _ContractError("init contract is missing")
    if (
        _unique_string_set(
            init_contract.get("required_fields"), label="init required_fields"
        )
        != INIT_REQUIRED_FIELDS
    ):
        raise _ContractError("init required fields do not match the validator")
    if init_contract.get("additional_fields") is not True:
        raise _ContractError("init additional-field policy does not match")
    field_contracts = init_contract.get("field_contracts")
    if (
        type(field_contracts) is not dict
        or frozenset(field_contracts) != INIT_REQUIRED_FIELDS
    ):
        raise _ContractError("init field contracts are incomplete")
    if field_contracts.get("permissionMode", {}).get("value") != "dontAsk":
        raise _ContractError("permission mode contract does not match")
    if (
        _unique_string_set(
            field_contracts.get("tools", {}).get("values"), label="init tools"
        )
        != EXPECTED_TOOLS
    ):
        raise _ContractError("tool contract does not match")
    if (
        field_contracts.get("claude_code_version", {}).get("value")
        != CLAUDE_CODE_VERSION
    ):
        raise _ContractError("init version contract does not match")
    if (
        _unique_string_set(
            field_contracts.get("apiKeySource", {}).get("accepted_arguments"),
            label="apiKeySource accepted_arguments",
        )
        != ACCEPTED_API_KEY_SOURCES
    ):
        raise _ContractError("authentication-source contract does not match")

    terminal_contract = contract.get("terminal_result")
    if type(terminal_contract) is not dict:
        raise _ContractError("terminal contract is missing")
    if terminal_contract.get("additional_fields") is not False:
        raise _ContractError("terminal additional-field policy does not match")
    if (
        _unique_string_set(
            terminal_contract.get("required_fields"), label="terminal required_fields"
        )
        != TERMINAL_REQUIRED_FIELDS
    ):
        raise _ContractError("terminal required fields do not match")
    if (
        _unique_string_set(
            terminal_contract.get("optional_fields"), label="terminal optional_fields"
        )
        != TERMINAL_VARIANT_FIELDS | TERMINAL_OPTIONAL_FIELDS
    ):
        raise _ContractError("terminal optional fields do not match")
    optional_contracts = terminal_contract.get("optional_field_contracts")
    if (
        type(optional_contracts) is not dict
        or frozenset(optional_contracts)
        != TERMINAL_VARIANT_FIELDS | TERMINAL_OPTIONAL_FIELDS
    ):
        raise _ContractError("terminal optional contracts are incomplete")
    expected_variants = {
        "success": {
            "match": {"subtype": "success", "is_error": False},
            "required_fields": ["result", "modelUsage"],
            "field_contracts": {
                "result": {
                    "rule": "nonempty_string",
                    "failure": "inconclusive",
                },
                "modelUsage": {
                    "rule": "requested_model_usage",
                    "failure": "classify",
                },
            },
        },
        "failure": {
            "match": {
                "subtype": {"rule": "string_not_equal", "value": "success"},
                "is_error": True,
            },
            "required_fields": [],
            "optional_fields": ["result", "modelUsage"],
            "field_contracts": {
                "result": {"rule": "string", "failure": "inconclusive"},
                "modelUsage": {
                    "rule": "requested_model_usage",
                    "failure": "classify",
                },
            },
            "unclassified_failure": "inconclusive",
        },
    }
    if terminal_contract.get("variants") != expected_variants:
        raise _ContractError("terminal variants do not match the validator")

    identities = contract.get("model_identity")
    expected_identities = {
        "claude-opus-4-8": {
            "init_model": "claude-opus-4-8",
            "accepted_model_usage_keys": ["claude-opus-4-8", "claude-opus-4.8"],
        },
        "claude-opus-4-7": {
            "init_model": "claude-opus-4-7",
            "accepted_model_usage_keys": ["claude-opus-4-7", "claude-opus-4.7"],
        },
    }
    if identities != expected_identities:
        raise _ContractError("model identities do not match the validator")
    if contract.get("accepted_auxiliary_model_usage_keys") != [
        "claude-haiku-4-5-20251001"
    ]:
        raise _ContractError("auxiliary model identities do not match")
    return contract


@dataclass
class _Envelope:
    first: dict[str, Any] | None = None
    last: dict[str, Any] | None = None
    nonblank_count: int = 0
    init_count: int = 0
    result_count: int = 0


@dataclass
class _Evidence:
    blocked: set[str] = field(default_factory=set)
    authentication: set[str] = field(default_factory=set)
    inconclusive: set[str] = field(default_factory=set)


def _failure(classification: str, reasons: set[str] | list[str]) -> dict[str, Any]:
    return {"classification": classification, "reasons": sorted(reasons)}


def _read_envelope(
    stream: BinaryIO, limits: StreamLimits
) -> tuple[_Envelope | None, dict[str, Any] | None]:
    envelope = _Envelope()
    total_bytes = 0
    raw_lines = 0
    while True:
        remaining = limits.max_bytes - total_bytes
        read_limit = min(limits.max_line_bytes + 1, remaining + 1)
        try:
            raw_line = stream.readline(read_limit)
        except (AttributeError, OSError, TypeError, ValueError) as error:
            del error
            return None, _failure("inconclusive", {"stream.read-error"})
        if type(raw_line) is not bytes:
            return None, _failure("inconclusive", {"stream.non-binary-input"})
        if not raw_line:
            break
        total_bytes += len(raw_line)
        raw_lines += 1
        if total_bytes > limits.max_bytes:
            return None, _failure("inconclusive", {"stream.byte-limit-exceeded"})
        if raw_lines > limits.max_lines:
            return None, _failure("inconclusive", {"stream.line-limit-exceeded"})
        if len(raw_line) > limits.max_line_bytes:
            return None, _failure("inconclusive", {"stream.line-byte-limit-exceeded"})
        try:
            line = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None, _failure("inconclusive", {"stream.invalid-utf8"})
        if not line.strip(" \t\r\n"):
            continue
        try:
            event = _strict_json_loads(line)
        except _DuplicateKeyError:
            return None, _failure("inconclusive", {"stream.duplicate-json-key"})
        except _NonstandardConstantError:
            return None, _failure("inconclusive", {"stream.nonstandard-json-constant"})
        except json.JSONDecodeError:
            return None, _failure("inconclusive", {"stream.invalid-json"})
        except Exception:
            return None, _failure("inconclusive", {"stream.invalid-json"})
        if _contains_unpaired_surrogate(event):
            return None, _failure("inconclusive", {"stream.unpaired-surrogate"})
        if type(event) is not dict:
            return None, _failure("inconclusive", {"stream.non-object-event"})
        envelope.nonblank_count += 1
        if envelope.first is None:
            envelope.first = event
        envelope.last = event
        if event.get("type") == "system" and event.get("subtype") == "init":
            envelope.init_count += 1
        if event.get("type") == "result":
            envelope.result_count += 1
    return envelope, None


def _validate_envelope(envelope: _Envelope, evidence: _Evidence) -> bool:
    if envelope.nonblank_count == 0:
        evidence.inconclusive.add("stream.no-events")
        return False
    first_is_init = bool(
        envelope.first
        and envelope.first.get("type") == "system"
        and envelope.first.get("subtype") == "init"
    )
    if not first_is_init:
        evidence.inconclusive.add("stream.init-not-first")
    if envelope.init_count == 0:
        evidence.inconclusive.add("stream.init-missing")
    elif envelope.init_count > 1:
        evidence.inconclusive.add("stream.init-duplicate")
    if envelope.result_count == 0:
        evidence.inconclusive.add("stream.result-missing")
    elif envelope.result_count > 1:
        evidence.inconclusive.add("stream.result-duplicate")
    if not envelope.last or envelope.last.get("type") != "result":
        evidence.inconclusive.add("stream.result-not-last")
    return not evidence.inconclusive


def _validate_exact_string(
    event: Mapping[str, Any],
    field_name: str,
    expected: str,
    evidence: _Evidence,
) -> None:
    if field_name not in event:
        evidence.inconclusive.add(f"init.{field_name}.missing")
        return
    value = event[field_name]
    if type(value) is not str:
        evidence.inconclusive.add(f"init.{field_name}.malformed")
    elif value != expected:
        evidence.blocked.add(f"init.{field_name}.mismatch")


def _validate_init(
    event: Mapping[str, Any],
    *,
    expected_cwd: str,
    requested_model: str,
    api_key_source: str,
    evidence: _Evidence,
) -> None:
    missing = INIT_REQUIRED_FIELDS - frozenset(event)
    for field_name in missing:
        evidence.inconclusive.add(f"init.{field_name}.missing")
    _validate_exact_string(event, "cwd", expected_cwd, evidence)
    _validate_exact_string(event, "permissionMode", "dontAsk", evidence)
    _validate_exact_string(event, "model", requested_model, evidence)
    _validate_exact_string(event, "claude_code_version", CLAUDE_CODE_VERSION, evidence)
    _validate_exact_string(event, "apiKeySource", api_key_source, evidence)

    if "tools" in event:
        tools = event["tools"]
        if type(tools) is not list or any(type(tool) is not str for tool in tools):
            evidence.inconclusive.add("init.tools.malformed")
        else:
            if len(tools) != len(set(tools)):
                evidence.blocked.add("init.tools.duplicate")
            if frozenset(tools) != EXPECTED_TOOLS:
                evidence.blocked.add("init.tools.mismatch")

    for field_name in EMPTY_INIT_SURFACES:
        if field_name not in event:
            continue
        value = event[field_name]
        if type(value) is not list:
            evidence.inconclusive.add(f"init.{field_name}.malformed")
        elif value:
            evidence.blocked.add(f"init.{field_name}.nonempty")


def _validate_model_usage(
    value: Any,
    *,
    requested_model: str,
    contract: Mapping[str, Any],
    evidence: _Evidence,
) -> None:
    if type(value) is not dict or not value:
        evidence.inconclusive.add("terminal.modelUsage.malformed")
        return
    if any(not key.strip() or type(item) is not dict for key, item in value.items()):
        evidence.inconclusive.add("terminal.modelUsage.malformed")
        return

    identities = contract["model_identity"]
    requested_keys = frozenset(identities[requested_model]["accepted_model_usage_keys"])
    all_primary_keys = frozenset(
        key
        for identity in identities.values()
        for key in identity["accepted_model_usage_keys"]
    )
    other_primary_keys = all_primary_keys - requested_keys
    auxiliary_keys = frozenset(contract["accepted_auxiliary_model_usage_keys"])
    observed_keys = frozenset(value)
    unknown_keys = observed_keys - requested_keys - other_primary_keys - auxiliary_keys
    if observed_keys & other_primary_keys:
        evidence.blocked.add("terminal.modelUsage.primary-model-substitution")
    if not observed_keys & requested_keys:
        evidence.blocked.add("terminal.modelUsage.requested-model-missing")
    if unknown_keys:
        evidence.inconclusive.add("terminal.modelUsage.unknown-model")


def _is_explicitly_empty(value: Any) -> bool:
    if value is None:
        return True
    if type(value) is str:
        return not value.strip()
    if type(value) in (list, dict):
        return not value
    return False


_HTTP_401 = re.compile(
    r"\b(?:"
    r"http(?:/\d+(?:\.\d+)?)?(?:[\s_-]+status(?:[\s_-]+code)?)?"
    r"|status(?:[\s_-]+code)?"
    r"|code"
    r")\b\s*[:=]?\s*401\b"
)
_REFRESH_FAILURE = re.compile(
    r"\brefresh\b.*\b(?:fail(?:ed|ure)?|error|expired|invalid|unauthorized)\b"
)


def _is_authentication_error(message: str) -> bool:
    normalized = " ".join(message.casefold().split())
    return bool(
        "login expired" in normalized
        or _HTTP_401.search(normalized)
        or _REFRESH_FAILURE.search(normalized)
    )


def _collect_error_messages(event: Mapping[str, Any], evidence: _Evidence) -> list[str]:
    messages: list[str] = []
    for field_name in ("error", "errors"):
        if field_name not in event:
            continue
        value = event[field_name]
        if _is_explicitly_empty(value):
            continue
        if type(value) is str:
            messages.append(value)
        elif (
            type(value) is list
            and value
            and all(type(item) is str and item.strip() for item in value)
        ):
            messages.extend(value)
        else:
            evidence.inconclusive.add(f"terminal.{field_name}.malformed")
    if "api_error_status" in event:
        value = event["api_error_status"]
        if value is None or (type(value) is str and not value.strip()):
            pass
        elif type(value) is str:
            messages.append(f"status {value}")
        else:
            evidence.inconclusive.add("terminal.api_error_status.malformed")
    return messages


def _is_nonnegative_finite_number(value: Any) -> bool:
    if type(value) not in (int, float) or value < 0:
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _validate_optional_terminal_fields(
    event: Mapping[str, Any], evidence: _Evidence
) -> None:
    for field_name in ("duration_ms", "duration_api_ms"):
        if field_name in event:
            value = event[field_name]
            if type(value) is not int or value < 0:
                evidence.inconclusive.add(f"terminal.{field_name}.malformed")
    if "num_turns" in event:
        value = event["num_turns"]
        if type(value) is not int or value <= 0:
            evidence.inconclusive.add("terminal.num_turns.malformed")
    if "total_cost_usd" in event:
        value = event["total_cost_usd"]
        if not _is_nonnegative_finite_number(value):
            evidence.inconclusive.add("terminal.total_cost_usd.malformed")
    for field_name in ("session_id", "uuid"):
        if field_name in event:
            value = event[field_name]
            if type(value) is not str or not value.strip():
                evidence.inconclusive.add(f"terminal.{field_name}.malformed")
    if "usage" in event and type(event["usage"]) is not dict:
        evidence.inconclusive.add("terminal.usage.malformed")
    if "stop_reason" in event:
        value = event["stop_reason"]
        if value is not None and value != "end_turn":
            evidence.blocked.add("terminal.stop_reason.unaccepted")
    if "structured_output" in event and event["structured_output"] is not None:
        evidence.inconclusive.add("terminal.structured_output.nonnull")
    if "permission_denials" in event:
        value = event["permission_denials"]
        if type(value) is not list:
            evidence.inconclusive.add("terminal.permission_denials.malformed")
        elif value:
            evidence.blocked.add("terminal.permission_denials.nonempty")


def _validate_terminal(
    event: Mapping[str, Any],
    *,
    requested_model: str,
    contract: Mapping[str, Any],
    evidence: _Evidence,
) -> str | None:
    allowed_fields = (
        TERMINAL_REQUIRED_FIELDS | TERMINAL_VARIANT_FIELDS | TERMINAL_OPTIONAL_FIELDS
    )
    if frozenset(event) - allowed_fields:
        evidence.inconclusive.add("terminal.unknown-field")

    subtype = event.get("subtype")
    is_error = event.get("is_error")
    if type(subtype) is not str:
        evidence.inconclusive.add("terminal.subtype.malformed")
    if type(is_error) is not bool:
        evidence.inconclusive.add("terminal.is_error.malformed")
    success_claim = subtype == "success" and is_error is False
    failure_claim = type(subtype) is str and subtype != "success" and is_error is True
    if not success_claim and not failure_claim:
        evidence.inconclusive.add("terminal.status.contradictory")

    findings: str | None = None
    if success_claim:
        if "result" not in event:
            evidence.inconclusive.add("terminal.result.missing")
        elif type(event["result"]) is not str or not event["result"].strip():
            evidence.inconclusive.add("terminal.result.malformed")
        else:
            findings = event["result"]
        if "modelUsage" not in event:
            evidence.inconclusive.add("terminal.modelUsage.missing")
        else:
            _validate_model_usage(
                event["modelUsage"],
                requested_model=requested_model,
                contract=contract,
                evidence=evidence,
            )
    else:
        if "modelUsage" in event:
            _validate_model_usage(
                event["modelUsage"],
                requested_model=requested_model,
                contract=contract,
                evidence=evidence,
            )
        if "result" in event and type(event["result"]) is not str:
            evidence.inconclusive.add("terminal.result.malformed")

    terminal_blocked_before = set(evidence.blocked)
    _validate_optional_terminal_fields(event, evidence)
    messages = _collect_error_messages(event, evidence)
    if success_claim and messages:
        evidence.inconclusive.add("terminal.success-with-error")
    elif failure_claim:
        authentication_messages = [
            message for message in messages if _is_authentication_error(message)
        ]
        if authentication_messages and len(authentication_messages) == len(messages):
            evidence.authentication.add("terminal.authentication-error")
        elif messages:
            evidence.inconclusive.add("terminal.unclassified-error")
        terminal_blocked = evidence.blocked - terminal_blocked_before
        if not messages and not terminal_blocked:
            evidence.inconclusive.add("terminal.non-success-unclassified")
    return findings


def _classify(evidence: _Evidence, findings: str | None) -> dict[str, Any]:
    if evidence.inconclusive or (evidence.blocked and evidence.authentication):
        reasons = evidence.inconclusive | evidence.blocked | evidence.authentication
        return _failure("inconclusive", reasons)
    if evidence.authentication:
        return _failure("blocked-authentication", evidence.authentication)
    if evidence.blocked:
        return _failure("blocked", evidence.blocked)
    if findings is None:
        return _failure("inconclusive", {"terminal.findings-unavailable"})
    return {"classification": "accepted", "findings": findings}


def validate_claude_stream(
    stream: BinaryIO,
    *,
    expected_cwd: str | Path,
    requested_model: str,
    api_key_source: str,
    limits: StreamLimits | None = None,
) -> dict[str, Any]:
    """Validate one raw Claude stream without ever returning partial findings."""

    try:
        contract = _load_contract()
    except (_ContractError, AttributeError, KeyError, TypeError):
        return _failure("inconclusive", {"validator.contract-invalid"})
    try:
        resolved_cwd = Path(expected_cwd).resolve(strict=True)
        if not resolved_cwd.is_dir():
            raise OSError("cwd is not a directory")
    except (OSError, RuntimeError, TypeError, ValueError):
        return _failure("inconclusive", {"validator.expected-cwd-invalid"})
    if (
        type(requested_model) is not str
        or requested_model not in contract["model_identity"]
    ):
        return _failure("inconclusive", {"validator.requested-model-invalid"})
    if (
        type(api_key_source) is not str
        or api_key_source not in ACCEPTED_API_KEY_SOURCES
    ):
        return _failure("inconclusive", {"validator.api-key-source-invalid"})

    selected_limits = limits or DEFAULT_STREAM_LIMITS
    if type(selected_limits) is not StreamLimits:
        return _failure("inconclusive", {"validator.limits-invalid"})
    values = (
        selected_limits.max_bytes,
        selected_limits.max_lines,
        selected_limits.max_line_bytes,
    )
    defaults = (
        DEFAULT_STREAM_LIMITS.max_bytes,
        DEFAULT_STREAM_LIMITS.max_lines,
        DEFAULT_STREAM_LIMITS.max_line_bytes,
    )
    if any(type(value) is not int or value <= 0 for value in values) or any(
        value > default for value, default in zip(values, defaults)
    ):
        return _failure("inconclusive", {"validator.limits-invalid"})

    envelope, read_failure = _read_envelope(stream, selected_limits)
    if read_failure is not None:
        return read_failure
    if envelope is None:
        return _failure("inconclusive", {"stream.envelope-unavailable"})
    evidence = _Evidence()
    if not _validate_envelope(envelope, evidence):
        return _classify(evidence, None)
    if envelope.first is None or envelope.last is None:
        return _failure("inconclusive", {"stream.envelope-unavailable"})
    _validate_init(
        envelope.first,
        expected_cwd=str(resolved_cwd),
        requested_model=requested_model,
        api_key_source=api_key_source,
        evidence=evidence,
    )
    findings = _validate_terminal(
        envelope.last,
        requested_model=requested_model,
        contract=contract,
        evidence=evidence,
    )
    return _classify(evidence, findings)


def validate_claude_stream_bytes(
    raw_stream: bytes,
    *,
    expected_cwd: str | Path,
    requested_model: str,
    api_key_source: str,
    limits: StreamLimits | None = None,
) -> dict[str, Any]:
    """Bytes convenience wrapper for callers that already captured bounded output."""

    if type(raw_stream) is not bytes:
        return _failure("inconclusive", {"stream.non-binary-input"})
    return validate_claude_stream(
        io.BytesIO(raw_stream),
        expected_cwd=expected_cwd,
        requested_model=requested_model,
        api_key_source=api_key_source,
        limits=limits,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate canonical Claude Code 2.1.212 stream-json output."
    )
    parser.add_argument("--cwd", required=True, help="Expected resolved review cwd")
    parser.add_argument(
        "--model",
        required=True,
        choices=("claude-opus-4-8", "claude-opus-4-7"),
        help="Concrete model passed to Claude Code",
    )
    parser.add_argument(
        "--api-key-source",
        required=True,
        choices=("none", "ANTHROPIC_API_KEY"),
        help="Authentication source selected before launch",
    )
    parser.add_argument(
        "--input",
        default="-",
        help="Raw stream-json file, or - for stdin",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    stream: BinaryIO
    close_stream = False
    if args.input == "-":
        stream = sys.stdin.buffer
    else:
        try:
            stream = Path(args.input).open("rb")
            close_stream = True
        except OSError:
            result = _failure("inconclusive", {"stream.input-unreadable"})
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 3
    try:
        result = validate_claude_stream(
            stream,
            expected_cwd=args.cwd,
            requested_model=args.model,
            api_key_source=args.api_key_source,
        )
    finally:
        if close_stream:
            stream.close()
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return {
        "accepted": 0,
        "blocked": 1,
        "blocked-authentication": 2,
        "inconclusive": 3,
    }[result["classification"]]


if __name__ == "__main__":
    raise SystemExit(main())
