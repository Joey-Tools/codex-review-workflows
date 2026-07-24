"""Generate bindings and validate cross-field read-only PR report semantics."""

from __future__ import annotations

import errno
import json
import math
import os
import re
import secrets
import stat
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

MAX_REPORT_BYTES = 1 << 20
MAX_BINDING_ATTEMPTS = 128
MAX_ERROR_CHARS = 240
MAX_INTEGER_DIGITS = 128
MAX_NUMBER_CHARS = 256
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 16_384
MAX_JSON_STRUCTURE_MARKERS = MAX_JSON_NODES * 2
READ_CHUNK_BYTES = 64 * 1024
IDENTIFIER_RE = re.compile(
    r"^(?P<kind>report|target|snapshot|observation):(?P<value>[0-9a-f]{32})$"
)
EVIDENCE_NAMES = {
    "pr_selection": "pr-selection",
    "pr_lifecycle": "pr-lifecycle",
    "ci_status": "ci-status",
    "conversation_state": "conversation-state",
    "base_and_head": "base-and-head",
}


def new_bindings() -> dict[str, str]:
    """Return four independently generated report-instance bindings."""

    bindings: dict[str, str] = {}
    used_tokens: set[str] = set()
    for field, kind in (
        ("report_id", "report"),
        ("target_binding", "target"),
        ("snapshot_binding", "snapshot"),
        ("snapshot_id", "observation"),
    ):
        for _ in range(MAX_BINDING_ATTEMPTS):
            token = secrets.token_hex(16)
            if re.fullmatch(r"[0-9a-f]{32}", token) and token not in used_tokens:
                used_tokens.add(token)
                bindings[field] = f"{kind}:{token}"
                break
        else:
            raise RuntimeError("unable to generate unique report bindings")
    return bindings


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: object) -> Sequence[Any] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _identifier(
    errors: list[str],
    value: object,
    expected_kind: str,
    location: str,
) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{location} must be a {expected_kind} identifier")
        return None
    match = IDENTIFIER_RE.fullmatch(value)
    if match is None or match.group("kind") != expected_kind:
        errors.append(f"{location} must be a {expected_kind} identifier")
        return None
    return match.group("value")


def _observed_record(
    errors: list[str],
    evidence: Mapping[str, Any],
    location: str,
) -> Mapping[str, Any] | None:
    observed = _sequence(evidence.get("observed"))
    if observed is None:
        errors.append(f"{location}.observed must be an array")
        return None
    status = evidence.get("status")
    if status == "observed":
        if len(observed) != 1 or _mapping(observed[0]) is None:
            errors.append(f"{location} must contain exactly one observed record")
            return None
        return _mapping(observed[0])
    if observed:
        errors.append(f"{location} must not retain a non-observed record")
    return None


def semantic_errors(report: object) -> list[str]:
    """Return cross-field errors after the closed JSON Schema has passed."""

    errors: list[str] = []
    root = _mapping(report)
    if root is None:
        return ["report must be an object"]

    report_token = _identifier(errors, root.get("report_id"), "report", "report_id")
    target = _mapping(root.get("target"))
    snapshot = _mapping(root.get("snapshot"))
    evidence = _mapping(root.get("evidence"))
    if target is None:
        errors.append("target must be an object")
    if snapshot is None:
        errors.append("snapshot must be an object")
    if evidence is None:
        errors.append("evidence must be an object")
    if target is None or snapshot is None or evidence is None:
        return errors

    target_token = _identifier(
        errors, target.get("binding_id"), "target", "target.binding_id"
    )
    snapshot_token = _identifier(
        errors, snapshot.get("binding_id"), "snapshot", "snapshot.binding_id"
    )
    observation_token = _identifier(
        errors, snapshot.get("snapshot_id"), "observation", "snapshot.snapshot_id"
    )
    tokens = [
        token
        for token in (
            report_token,
            target_token,
            snapshot_token,
            observation_token,
        )
        if token is not None
    ]
    if len(tokens) == 4 and len(set(tokens)) != 4:
        errors.append("report, target, snapshot, and observation IDs must be unique")

    report_id = root.get("report_id")
    target_binding = target.get("binding_id")
    snapshot_binding = snapshot.get("binding_id")
    if target.get("report_binding") != report_id:
        errors.append("target.report_binding must equal report_id")
    if snapshot.get("report_binding") != report_id:
        errors.append("snapshot.report_binding must equal report_id")
    if snapshot.get("target_binding") != target_binding:
        errors.append("snapshot.target_binding must equal target.binding_id")

    evidence_records: dict[str, Mapping[str, Any]] = {}
    for field in EVIDENCE_NAMES:
        item = _mapping(evidence.get(field))
        if item is None:
            errors.append(f"evidence.{field} must be an object")
            continue
        evidence_records[field] = item
        if item.get("report_binding") != report_id:
            errors.append(f"evidence.{field}.report_binding must equal report_id")
        if item.get("target_binding") != target_binding:
            errors.append(
                f"evidence.{field}.target_binding must equal target.binding_id"
            )
        if item.get("snapshot_binding") != snapshot_binding:
            errors.append(
                f"evidence.{field}.snapshot_binding must equal snapshot.binding_id"
            )
        _observed_record(errors, item, f"evidence.{field}")

    if set(evidence_records) != set(EVIDENCE_NAMES):
        return errors
    sources = _sequence(snapshot.get("sources"))
    if sources is None:
        errors.append("snapshot.sources must be an array")
    elif (
        any(item.get("status") == "observed" for item in evidence_records.values())
        and not sources
    ):
        errors.append("observed evidence requires at least one snapshot source")

    non_observed = {
        external
        for field, external in EVIDENCE_NAMES.items()
        if evidence_records[field].get("status") != "observed"
    }
    unavailable = _sequence(root.get("unavailable_evidence"))
    if unavailable is None or set(unavailable) != non_observed:
        errors.append(
            "unavailable_evidence must exactly name every non-observed evidence kind"
        )
    blockers = _sequence(root.get("blockers"))
    blocker_names: list[object] = []
    if blockers is None:
        errors.append("blockers must be an array")
    else:
        for blocker in blockers:
            blocker_record = _mapping(blocker)
            blocker_names.append(
                blocker_record.get("evidence") if blocker_record is not None else None
            )
        if (
            len(blocker_names) != len(set(blocker_names))
            or set(blocker_names) != non_observed
        ):
            errors.append(
                "blockers must contain exactly one entry for each non-observed kind"
            )

    selection = evidence_records["pr_selection"]
    selection_record = _observed_record([], selection, "evidence.pr_selection")
    selection_outcome: object = None
    if selection_record is not None:
        selection_outcome = selection_record.get("outcome")
        method = selection_record.get("selection_method")
        count = selection_record.get("candidate_count")
        if method not in {"explicit", "unique-open-head"}:
            errors.append("selection_method is unknown")
        if not _is_nonnegative_int(count):
            errors.append("candidate_count must be a non-negative integer")
        elif selection_outcome == "selected" and count != 1:
            errors.append("selected PR evidence requires candidate_count == 1")
        elif selection_outcome == "no-match" and count != 0:
            errors.append("no-match PR evidence requires candidate_count == 0")
        elif selection_outcome == "ambiguous" and count < 2:
            errors.append("ambiguous PR evidence requires candidate_count >= 2")
        elif selection_outcome not in {"selected", "no-match", "ambiguous"}:
            errors.append("selection outcome is unknown")
        if method == "explicit" and selection_outcome == "ambiguous":
            errors.append("explicit PR selection cannot be ambiguous")

    terminal_state = root.get("terminal_state")
    target_state = target.get("state")
    downstream = (
        "pr_lifecycle",
        "ci_status",
        "conversation_state",
        "base_and_head",
    )
    if terminal_state == "pre-target":
        if target_state != "pre-target":
            errors.append("pre-target terminal requires a pre-target binding")
        if selection_outcome not in {"no-match", "ambiguous"}:
            errors.append("pre-target terminal requires a conclusive no-target result")
        if any(
            evidence_records[field].get("status") == "observed" for field in downstream
        ):
            errors.append(
                "pre-target terminal cannot contain target-scoped observations"
            )
    elif terminal_state == "pre-target-blocked":
        if target_state != "pre-target":
            errors.append("pre-target-blocked terminal requires a pre-target binding")
        if selection.get("status") == "observed":
            errors.append(
                "pre-target-blocked terminal requires unavailable or blocked selection"
            )
        if any(
            evidence_records[field].get("status") == "observed" for field in downstream
        ):
            errors.append(
                "pre-target-blocked terminal cannot contain target-scoped observations"
            )
    elif terminal_state == "target-resolution-blocked":
        if target_state != "pr-selected":
            errors.append(
                "target-resolution-blocked terminal requires a selected PR target"
            )
        if selection_outcome != "selected":
            errors.append(
                "target-resolution-blocked terminal requires selected PR evidence"
            )
        if evidence_records["base_and_head"].get("status") == "observed":
            errors.append(
                "target-resolution-blocked terminal requires non-observed base/head"
            )
    elif terminal_state == "target-snapshot":
        if target_state != "range-resolved":
            errors.append("target-snapshot terminal requires a resolved range target")
        if selection_outcome != "selected":
            errors.append("target-snapshot terminal requires selected PR evidence")
        if evidence_records["base_and_head"].get("status") != "observed":
            errors.append("target-snapshot terminal requires observed base/head")
    else:
        errors.append("terminal_state is unknown")

    lifecycle_record = _observed_record(
        [], evidence_records["pr_lifecycle"], "evidence.pr_lifecycle"
    )
    if lifecycle_record is not None:
        lifecycle_tuple = (
            lifecycle_record.get("state"),
            lifecycle_record.get("merged"),
            lifecycle_record.get("merged_at"),
        )
        lifecycle_valid = (
            lifecycle_tuple == ("open", False, None)
            or lifecycle_tuple == ("closed", False, None)
            or (
                lifecycle_tuple[0] == "closed"
                and lifecycle_tuple[1] is True
                and isinstance(lifecycle_tuple[2], str)
            )
        )
        if not lifecycle_valid:
            errors.append("lifecycle state, merged, and merged_at contradict")

    ci_record = _observed_record(
        [], evidence_records["ci_status"], "evidence.ci_status"
    )
    if ci_record is not None:
        checks = _sequence(ci_record.get("checks"))
        if checks is None:
            errors.append("CI checks must be an array")
        else:
            names: list[object] = []
            actual = {"success": 0, "failure": 0, "pending": 0, "cancelled": 0}
            for check in checks:
                check_record = _mapping(check)
                if check_record is None:
                    errors.append("each CI check must be an object")
                    continue
                names.append(check_record.get("name"))
                conclusion = check_record.get("conclusion")
                if conclusion not in actual:
                    errors.append("CI check conclusion is unknown")
                else:
                    actual[conclusion] += 1
            if len(names) != len(set(names)):
                errors.append("CI check names must be unique")
            reported = {
                "success": ci_record.get("successful"),
                "failure": ci_record.get("failed"),
                "pending": ci_record.get("pending"),
                "cancelled": ci_record.get("cancelled"),
            }
            if any(not _is_nonnegative_int(value) for value in reported.values()):
                errors.append("CI aggregate counts must be non-negative integers")
            elif reported != actual:
                errors.append("CI aggregate counts do not match check results")
            total = ci_record.get("total")
            if not _is_nonnegative_int(total) or total != len(checks):
                errors.append("CI total does not match check results")
            expected_state = (
                "no-checks"
                if not checks
                else "failure"
                if actual["failure"]
                else "pending"
                if actual["pending"]
                else "cancelled"
                if actual["cancelled"]
                else "success"
            )
            if ci_record.get("state") != expected_state:
                errors.append("CI aggregate state contradicts check results")

    conversation_record = _observed_record(
        [],
        evidence_records["conversation_state"],
        "evidence.conversation_state",
    )
    if conversation_record is not None:
        total_threads = conversation_record.get("total_threads")
        unresolved_threads = conversation_record.get("unresolved_threads")
        if not _is_nonnegative_int(total_threads) or not _is_nonnegative_int(
            unresolved_threads
        ):
            errors.append("conversation counts must be non-negative integers")
        elif unresolved_threads > total_threads:
            errors.append("unresolved_threads cannot exceed total_threads")

    range_record = _observed_record(
        [], evidence_records["base_and_head"], "evidence.base_and_head"
    )
    if range_record is not None:
        base_present = range_record.get("base_object_present")
        head_present = range_record.get("head_object_present")
        merge_base_count = range_record.get("merge_base_count")
        merge_base_oid = range_record.get("merge_base_oid")
        if not isinstance(base_present, bool) or not isinstance(head_present, bool):
            errors.append("endpoint object-presence fields must be booleans")
        if not _is_nonnegative_int(merge_base_count):
            errors.append("merge_base_count must be a non-negative integer")
        else:
            if (not base_present or not head_present) and (
                merge_base_count != 0 or merge_base_oid is not None
            ):
                errors.append(
                    "missing endpoint objects cannot have merge-base evidence"
                )
            elif merge_base_count == 1 and not isinstance(merge_base_oid, str):
                errors.append("one merge base requires merge_base_oid")
            elif merge_base_count != 1 and merge_base_oid is not None:
                errors.append("non-unique merge base must not claim merge_base_oid")

    return errors


def validate_semantics(report: object) -> None:
    """Raise ValueError when semantic or instance-binding validation fails."""

    errors = semantic_errors(report)
    if errors:
        raise ValueError("; ".join(errors))


def _secure_open_flags() -> int:
    required = ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
    values = [getattr(os, name, None) for name in required]
    if any(not isinstance(value, int) for value in values):
        raise OSError(errno.ENOTSUP, "required secure-open flags are unavailable")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _os_error_code(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno, "OS_ERROR")


def _file_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _validate_regular_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("report path must identify a regular file")
    if info.st_size < 0 or info.st_size > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")


def _read_descriptor_once(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while retained <= MAX_REPORT_BYTES:
        chunk = os.read(
            descriptor,
            min(READ_CHUNK_BYTES, MAX_REPORT_BYTES + 1 - retained),
        )
        if not chunk:
            break
        chunks.append(chunk)
        retained += len(chunk)
    if retained > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")
    return b"".join(chunks)


def _read_regular_path(path: str) -> bytes:
    """Retain bytes while proving path object identity and content stability.

    Object identity is device, inode, and file type. Content stability is exact
    size plus two identical complete reads. Permission bits, timestamps, and
    link count are outside these protected properties.
    """

    try:
        flags = _secure_open_flags()
    except OSError as exc:
        raise ValueError(
            f"secure report descriptor open is unavailable ({_os_error_code(exc)})"
        ) from exc
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError("report path is missing at descriptor admission") from exc
    except OSError as exc:
        raise ValueError(f"report path open failed ({_os_error_code(exc)})") from exc
    try:
        try:
            initial = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor admission failed ({_os_error_code(exc)})"
            ) from exc
        _validate_regular_file(initial)
        identity = _file_identity(initial)

        try:
            first = _read_descriptor_once(descriptor)
            after_first = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor first read failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(after_first) != identity:
            raise ValueError("report descriptor identity changed during first read")
        if after_first.st_size != initial.st_size or len(first) != initial.st_size:
            raise ValueError("report file size changed during first read")

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_descriptor_once(descriptor)
            final = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor revalidation failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(final) != identity:
            raise ValueError(
                "report descriptor identity changed during content revalidation"
            )
        if final.st_size != initial.st_size or len(second) != initial.st_size:
            raise ValueError("report file size changed during content revalidation")
        if second != first:
            raise ValueError("report file content changed during validation")

        try:
            path_info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ValueError(
                "report path disappeared during final revalidation"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"report path final revalidation failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(path_info) != identity:
            raise ValueError("report path identity changed during validation")
        if path_info.st_size != initial.st_size:
            raise ValueError("report path size changed during validation")
        return first
    finally:
        os.close(descriptor)


def _json_structure_preflight(text: str) -> None:
    depth = 0
    markers = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            markers += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("report JSON exceeds the nesting-depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("report JSON structure is malformed")
        elif character in ",:":
            markers += 1
        if markers > MAX_JSON_STRUCTURE_MARKERS:
            raise ValueError("report JSON exceeds the structure-node limit")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("report JSON contains a duplicate object key")
        result[key] = value
    return result


def _parse_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValueError("report JSON integer exceeds the digit limit")
    return int(value)


def _parse_float(value: str) -> float:
    if len(value) > MAX_NUMBER_CHARS:
        raise ValueError("report JSON number exceeds the length limit")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("report JSON number must be finite")
    return parsed


def _reject_nonfinite_constant(_value: str) -> None:
    raise ValueError("report JSON number must be finite")


def _validate_json_shape(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ValueError("report JSON root must be an object")

    nodes = 0
    stack: list[tuple[object, int]] = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("report JSON exceeds the nesting-depth limit")
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("report JSON exceeds the structure-node limit")
        if isinstance(value, dict):
            nodes += len(value)
            if nodes > MAX_JSON_NODES:
                raise ValueError("report JSON exceeds the structure-node limit")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="strict")
    _json_structure_preflight(text)
    payload = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite_constant,
        parse_float=_parse_float,
        parse_int=_parse_integer,
    )
    _validate_json_shape(payload)
    return payload


def _read_payload(path: str) -> object:
    """Read one bounded report.

    File paths use nonblocking descriptor admission and stable retained bytes.
    Standard input is byte-capped only; blocking and deadlines for stdin belong
    to the caller's transport.
    """

    if path == "-":
        raw = sys.stdin.buffer.read(MAX_REPORT_BYTES + 1)
    else:
        raw = _read_regular_path(path)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")
    return _strict_json_object(raw)


def _safe_error_text(exc: BaseException) -> str:
    if isinstance(exc, MemoryError):
        return "validation resource limit exceeded"
    if isinstance(exc, UnicodeDecodeError):
        return "report is not valid UTF-8"
    if isinstance(exc, json.JSONDecodeError):
        return f"report is not valid JSON at line {exc.lineno}, column {exc.colno}"
    if isinstance(exc, RecursionError):
        return "report nesting exceeds the validation limit"
    if isinstance(exc, OSError):
        code = errno.errorcode.get(exc.errno, "OS_ERROR")
        return f"report input read failed ({code})"

    raw = str(exc)
    truncated = len(raw) > MAX_ERROR_CHARS
    sample = raw[:MAX_ERROR_CHARS]
    cleaned = "".join(
        " "
        if character.isspace() or unicodedata.category(character).startswith("C")
        else character
        for character in sample
    )
    cleaned = " ".join(cleaned.split()) or type(exc).__name__
    if truncated:
        cleaned = f"{cleaned[: MAX_ERROR_CHARS - 3]}..."
    return cleaned[:MAX_ERROR_CHARS]


def _emit_rejection(exc: BaseException) -> int:
    print(
        json.dumps(
            {
                "classification": "rejected",
                "error": _safe_error_text(exc),
            },
            sort_keys=True,
        )
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["new-bindings"]:
        try:
            bindings = new_bindings()
        except OSError as exc:
            return _emit_rejection(
                ValueError(f"report binding generation failed ({_os_error_code(exc)})")
            )
        except (
            MemoryError,
            RuntimeError,
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            return _emit_rejection(exc)
        print(json.dumps(bindings, sort_keys=True))
        return 0
    if len(args) == 2 and args[0] == "validate-semantics":
        try:
            payload = _read_payload(args[1])
            validate_semantics(payload)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            MemoryError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as exc:
            return _emit_rejection(exc)
        print(json.dumps({"classification": "accepted"}, sort_keys=True))
        return 0
    print(
        "usage: read_only_pr_report.py "
        "{new-bindings|validate-semantics <report.json|->}",
        file=sys.stderr,
    )
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
