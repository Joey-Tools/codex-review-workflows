"""Validate read-only PR reports from retained trusted control bytes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import types
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .catalog_bootstrap import (
    _BindingTransaction,
    _BoundTextSink,
    _require_canonical_absolute,
    _require_safe_primitives,
)


PROFILE = "validate-read-only-pr-report"
PROFILE_VERSION = 1
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_ERROR_CHARS = 240
MANIFEST_LEAF = "read-only-pr-report-control-manifest.json"
GUARD_RELATIVE_PATH = "scripts/named_lane_guard"
RUNTIME_INIT_RELATIVE_PATH = "scripts/review_runtime/__init__.py"
RUNTIME_RELATIVE_PATH = "scripts/review_runtime/read_only_report_guard.py"
BOOTSTRAP_RELATIVE_PATH = "scripts/review_runtime/catalog_bootstrap.py"
RECEIVER_RELATIVE_PATH = "scripts/read_only_pr_report.py"
SCHEMA_RELATIVE_PATH = "references/pr-readiness-read-only-report.schema.json"


class ReadOnlyReportGuardError(RuntimeError):
    """Reject an unsafe or inconsistent report validation launch."""


def _strict_manifest(payload: bytes, expected_sha256: str) -> Mapping[str, Any]:
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ReadOnlyReportGuardError(
            "control manifest does not match the trusted guard"
        )

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReadOnlyReportGuardError(
                    "control manifest contains a duplicate key"
                )
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ReadOnlyReportGuardError("control manifest contains a non-finite number")

    def reject_float(_value: str) -> None:
        raise ReadOnlyReportGuardError(
            "control manifest contains an unsupported floating-point number"
        )

    try:
        manifest = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=reject_float,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise ReadOnlyReportGuardError(
            "control manifest is not valid strict JSON"
        ) from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "profile",
        "external_trust_root",
        "loader",
        "control_sources",
        "artifacts",
    }:
        raise ReadOnlyReportGuardError(
            "control manifest root does not match the closed contract"
        )
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("profile") != PROFILE
    ):
        raise ReadOnlyReportGuardError("control manifest profile is invalid")
    if manifest.get("external_trust_root") != {
        "path": GUARD_RELATIVE_PATH,
        "authority": "prior-trusted-canonical-bundle",
    }:
        raise ReadOnlyReportGuardError(
            "control manifest external trust root is invalid"
        )
    expected_loader = {
        "path": GUARD_RELATIVE_PATH,
        "profile_version": PROFILE_VERSION,
        "python_flags": ["-I", "-B", "-S"],
        "runtime": RUNTIME_RELATIVE_PATH,
        "runtime_version": PROFILE_VERSION,
        "schema_evaluator": "closed-draft-2020-12-v1",
    }
    loader = manifest.get("loader")
    if (
        not isinstance(loader, dict)
        or type(loader.get("profile_version")) is not int
        or type(loader.get("runtime_version")) is not int
        or loader != expected_loader
    ):
        raise ReadOnlyReportGuardError(
            "control manifest loader/version binding is invalid"
        )

    expected_sets = (
        (
            "control_sources",
            (
                (RUNTIME_INIT_RELATIVE_PATH, "runtime-package"),
                (BOOTSTRAP_RELATIVE_PATH, "binding-runtime"),
                (RUNTIME_RELATIVE_PATH, "report-guard-runtime"),
            ),
        ),
        (
            "artifacts",
            (
                (SCHEMA_RELATIVE_PATH, "schema"),
                (RECEIVER_RELATIVE_PATH, "receiver"),
            ),
        ),
    )
    records: dict[str, str] = {}
    for field, expected in expected_sets:
        values = manifest.get(field)
        if not isinstance(values, list) or len(values) != len(expected):
            raise ReadOnlyReportGuardError(f"control manifest {field} set is invalid")
        for artifact, (expected_path, expected_role) in zip(
            values,
            expected,
            strict=True,
        ):
            if not isinstance(artifact, dict) or set(artifact) != {
                "path",
                "role",
                "sha256",
            }:
                raise ReadOnlyReportGuardError(
                    f"control manifest {field} record is invalid"
                )
            path = artifact.get("path")
            role = artifact.get("role")
            digest = artifact.get("sha256")
            if path != expected_path or role != expected_role:
                raise ReadOnlyReportGuardError(
                    f"control manifest {field} ordering/role is invalid"
                )
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ReadOnlyReportGuardError(
                    f"control manifest {field} digest is invalid"
                )
            records[path] = digest
    return records


def _safe_error_text(error: BaseException) -> str:
    if isinstance(error, MemoryError):
        return "validation resource limit exceeded"
    raw = str(error)
    sample = raw[:MAX_ERROR_CHARS]
    cleaned = "".join(
        " "
        if character.isspace() or unicodedata.category(character).startswith("C")
        else character
        for character in sample
    )
    return (" ".join(cleaned.split()) or type(error).__name__)[:MAX_ERROR_CHARS]


def _emit_rejection(error: BaseException) -> int:
    sys.stdout.write(
        json.dumps(
            {
                "classification": "rejected",
                "error": _safe_error_text(error),
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 2


def _validate_inputs(
    *,
    trusted_review_skill_root: Path,
    trusted_guard_path: Path,
    trusted_runtime_init_path: Path,
    trusted_runtime_path: Path,
    trusted_bootstrap_path: Path,
    trusted_manifest_path: Path,
    trusted_receiver_path: Path,
    trusted_schema_path: Path,
    trusted_payloads: tuple[bytes, ...],
    trusted_manifest_sha256: str,
) -> None:
    _require_canonical_absolute(
        trusted_review_skill_root,
        label="trusted review skill root",
    )
    expected = (
        (
            trusted_guard_path,
            trusted_review_skill_root / GUARD_RELATIVE_PATH,
            "trusted named-lane guard",
        ),
        (
            trusted_runtime_init_path,
            trusted_review_skill_root / RUNTIME_INIT_RELATIVE_PATH,
            "trusted report runtime package",
        ),
        (
            trusted_runtime_path,
            trusted_review_skill_root / RUNTIME_RELATIVE_PATH,
            "trusted report guard runtime",
        ),
        (
            trusted_bootstrap_path,
            trusted_review_skill_root / BOOTSTRAP_RELATIVE_PATH,
            "trusted binding runtime",
        ),
        (
            trusted_manifest_path,
            trusted_review_skill_root / "references" / MANIFEST_LEAF,
            "trusted report control manifest",
        ),
        (
            trusted_receiver_path,
            trusted_review_skill_root / RECEIVER_RELATIVE_PATH,
            "trusted report receiver",
        ),
        (
            trusted_schema_path,
            trusted_review_skill_root / SCHEMA_RELATIVE_PATH,
            "trusted report schema",
        ),
    )
    for actual, wanted, label in expected:
        _require_canonical_absolute(actual, label=label)
        if actual != wanted:
            raise ReadOnlyReportGuardError(f"{label} path is not canonical")
    if any(type(payload) is not bytes for payload in trusted_payloads):
        raise ReadOnlyReportGuardError("trusted report control bytes are invalid")
    if (
        not isinstance(trusted_manifest_sha256, str)
        or len(trusted_manifest_sha256) != 64
        or any(
            character not in "0123456789abcdef" for character in trusted_manifest_sha256
        )
    ):
        raise ReadOnlyReportGuardError(
            "trusted report control manifest digest is invalid"
        )


def _main(
    argv: Sequence[str] | None = None,
    *,
    trusted_review_skill_root: Path | None = None,
    trusted_guard_path: Path | None = None,
    trusted_guard_bytes: bytes | None = None,
    trusted_runtime_init_path: Path | None = None,
    trusted_runtime_init_bytes: bytes | None = None,
    trusted_runtime_path: Path | None = None,
    trusted_runtime_bytes: bytes | None = None,
    trusted_bootstrap_path: Path | None = None,
    trusted_bootstrap_bytes: bytes | None = None,
    trusted_manifest_path: Path | None = None,
    trusted_manifest_bytes: bytes | None = None,
    trusted_manifest_sha256: str | None = None,
    trusted_receiver_path: Path | None = None,
    trusted_receiver_bytes: bytes | None = None,
    trusted_schema_path: Path | None = None,
    trusted_schema_bytes: bytes | None = None,
) -> int:
    _require_safe_primitives()
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or not isinstance(arguments[0], str) or not arguments[0]:
        raise ReadOnlyReportGuardError(
            "usage: named_lane_guard validate-read-only-pr-report <report.json|->"
        )
    required = (
        trusted_review_skill_root,
        trusted_guard_path,
        trusted_guard_bytes,
        trusted_runtime_init_path,
        trusted_runtime_init_bytes,
        trusted_runtime_path,
        trusted_runtime_bytes,
        trusted_bootstrap_path,
        trusted_bootstrap_bytes,
        trusted_manifest_path,
        trusted_manifest_bytes,
        trusted_manifest_sha256,
        trusted_receiver_path,
        trusted_receiver_bytes,
        trusted_schema_path,
        trusted_schema_bytes,
    )
    if any(value is None for value in required):
        raise ReadOnlyReportGuardError(
            "report guard requires manifest-bound parent inputs"
        )
    assert trusted_review_skill_root is not None
    assert trusted_guard_path is not None
    assert trusted_guard_bytes is not None
    assert trusted_runtime_init_path is not None
    assert trusted_runtime_init_bytes is not None
    assert trusted_runtime_path is not None
    assert trusted_runtime_bytes is not None
    assert trusted_bootstrap_path is not None
    assert trusted_bootstrap_bytes is not None
    assert trusted_manifest_path is not None
    assert trusted_manifest_bytes is not None
    assert trusted_manifest_sha256 is not None
    assert trusted_receiver_path is not None
    assert trusted_receiver_bytes is not None
    assert trusted_schema_path is not None
    assert trusted_schema_bytes is not None
    trusted_payloads = (
        trusted_guard_bytes,
        trusted_runtime_init_bytes,
        trusted_runtime_bytes,
        trusted_bootstrap_bytes,
        trusted_manifest_bytes,
        trusted_receiver_bytes,
        trusted_schema_bytes,
    )
    _validate_inputs(
        trusted_review_skill_root=trusted_review_skill_root,
        trusted_guard_path=trusted_guard_path,
        trusted_runtime_init_path=trusted_runtime_init_path,
        trusted_runtime_path=trusted_runtime_path,
        trusted_bootstrap_path=trusted_bootstrap_path,
        trusted_manifest_path=trusted_manifest_path,
        trusted_receiver_path=trusted_receiver_path,
        trusted_schema_path=trusted_schema_path,
        trusted_payloads=trusted_payloads,
        trusted_manifest_sha256=trusted_manifest_sha256,
    )
    records = _strict_manifest(
        trusted_manifest_bytes,
        trusted_manifest_sha256,
    )

    transaction = _BindingTransaction()
    captured_stdout = _BoundTextSink(label="trusted report receiver stdout")
    captured_stderr = _BoundTextSink(label="trusted report receiver stderr")
    accepted: str | None = None
    failure: BaseException | None = None
    bindings = (
        (
            trusted_guard_path,
            trusted_guard_bytes,
            "trusted named-lane guard",
            MAX_SOURCE_BYTES,
        ),
        (
            trusted_runtime_init_path,
            trusted_runtime_init_bytes,
            "trusted report runtime package",
            MAX_SOURCE_BYTES,
        ),
        (
            trusted_runtime_path,
            trusted_runtime_bytes,
            "trusted report guard runtime",
            MAX_SOURCE_BYTES,
        ),
        (
            trusted_bootstrap_path,
            trusted_bootstrap_bytes,
            "trusted binding runtime",
            MAX_SOURCE_BYTES,
        ),
        (
            trusted_manifest_path,
            trusted_manifest_bytes,
            "trusted report control manifest",
            MAX_MANIFEST_BYTES,
        ),
        (
            trusted_receiver_path,
            trusted_receiver_bytes,
            "trusted report receiver",
            MAX_SOURCE_BYTES,
        ),
        (
            trusted_schema_path,
            trusted_schema_bytes,
            "trusted report schema",
            MAX_SOURCE_BYTES,
        ),
    )
    try:
        bound_files: dict[Path, object] = {}
        for path, payload, label, limit in bindings:
            parent = transaction.bind_parent_chain(
                path.parent,
                label=f"{label} absolute parent chain",
            )
            bound_files[path] = transaction.bind_file(
                path,
                label=label,
                limit=limit,
                parent=parent,
                expected_payload=payload,
            )
        receiver_bound = bound_files[trusted_receiver_path]
        schema_bound = bound_files[trusted_schema_path]
        for path, relative_path, label in (
            (
                trusted_runtime_init_path,
                RUNTIME_INIT_RELATIVE_PATH,
                "trusted report runtime package",
            ),
            (
                trusted_runtime_path,
                RUNTIME_RELATIVE_PATH,
                "trusted report guard runtime",
            ),
            (
                trusted_bootstrap_path,
                BOOTSTRAP_RELATIVE_PATH,
                "trusted binding runtime",
            ),
        ):
            if getattr(bound_files[path], "sha256", None) != records[relative_path]:
                raise ReadOnlyReportGuardError(
                    f"{label} digest does not match the control manifest"
                )
        receiver_sha256 = getattr(receiver_bound, "sha256", None)
        schema_sha256 = getattr(schema_bound, "sha256", None)
        if receiver_sha256 != records[RECEIVER_RELATIVE_PATH]:
            raise ReadOnlyReportGuardError(
                "trusted report receiver digest does not match the control manifest"
            )
        if schema_sha256 != records[SCHEMA_RELATIVE_PATH]:
            raise ReadOnlyReportGuardError(
                "trusted report schema digest does not match the control manifest"
            )
        try:
            code = compile(
                trusted_receiver_bytes,
                str(trusted_receiver_path),
                "exec",
                dont_inherit=True,
            )
        except Exception as error:
            raise ReadOnlyReportGuardError(
                "trusted report receiver cannot compile"
            ) from error
        receiver = types.ModuleType("_trusted_read_only_pr_report")
        receiver.__dict__.update(
            {
                "__file__": str(trusted_receiver_path),
                "__package__": "",
                "__cached__": None,
            }
        )
        with (
            contextlib.redirect_stdout(captured_stdout),
            contextlib.redirect_stderr(captured_stderr),
        ):
            exec(code, receiver.__dict__)
            if (
                receiver.__dict__.get("REPORT_GUARD_PROFILE_VERSION") != PROFILE_VERSION
                or receiver.__dict__.get("REPORT_SCHEMA_BYTES") is not None
            ):
                raise ReadOnlyReportGuardError(
                    "trusted report receiver binding hooks are incompatible"
                )
            receiver.__dict__["REPORT_SCHEMA_BYTES"] = trusted_schema_bytes
            read_payload = receiver.__dict__.get("_read_payload")
            validate_report = receiver.__dict__.get("validate_report")
            if not callable(read_payload) or not callable(validate_report):
                raise ReadOnlyReportGuardError(
                    "trusted report receiver entrypoint is missing"
                )
            report = read_payload(arguments[0])
            validate_report(report)
        if captured_stdout.value() or captured_stderr.value():
            raise ReadOnlyReportGuardError(
                "trusted report receiver emitted unexpected output"
            )
        accepted = json.dumps(
            {
                "classification": "accepted",
                "control": {
                    "manifest_sha256": trusted_manifest_sha256,
                    "profile": PROFILE,
                    "profile_version": PROFILE_VERSION,
                    "receiver_sha256": receiver_sha256,
                    "schema_sha256": schema_sha256,
                },
            },
            sort_keys=True,
        )
    except BaseException as error:
        failure = error
    try:
        transaction.close(revalidate=True)
    except BaseException as error:
        failure = error
    if failure is not None:
        return _emit_rejection(failure)
    if accepted is None:
        return _emit_rejection(
            ReadOnlyReportGuardError("report validation produced no terminal result")
        )
    sys.stdout.write(accepted + "\n")
    return 0


def main(
    argv: Sequence[str] | None = None,
    **trusted_inputs: object,
) -> int:
    """Return a bounded machine rejection for all control failures."""
    try:
        return _main(argv, **trusted_inputs)
    except BaseException as error:
        return _emit_rejection(error)


__all__ = ["ReadOnlyReportGuardError", "main"]
