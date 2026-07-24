from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import os
import pathlib
from typing import BinaryIO

from .appserver_protocol import (
    AppServerProtocol,
    AppServerProtocolError,
    AppServerSessionConfig,
    AppServerSessionResult,
    encode_json_line,
    validate_prelaunch_turn_start_record,
)
from .constants import (
    APP_SERVER_MAX_RECORD_BYTES,
    MAX_EVIDENCE_CONTEXT_FILES,
    PRIMARY_DIFF_RELATIVE_PATH,
)
from .evidence import (
    AuthenticatedManifest,
    EvidenceBundle,
    EvidenceBundleSizeError,
    EvidenceError,
    build_evidence_bundle,
    build_primary_evidence_bundle,
)
from .prompt import AppServerPromptSizeError, render_appserver_prompt


@dataclass(frozen=True)
class PreparedAppServerInput:
    prompt: bytes
    evidence_bundle: EvidenceBundle
    nearby_paths: tuple[str, ...] = ()


class PrelaunchInputSizeError(ValueError):
    """The complete prompt or its final turn/start record exceeds a hard bound."""


def _prepare_bundle_input(
    *,
    bundle: EvidenceBundle,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    forbidden_paths: tuple[pathlib.Path, ...],
    nearby_paths: tuple[str, ...],
) -> PreparedAppServerInput:
    try:
        prompt = render_appserver_prompt(
            pr_url=pr_url,
            base_sha=base_sha,
            head_sha=head_sha,
            evidence_bundle=bundle,
            forbidden_paths=forbidden_paths,
        )
        validate_prelaunch_turn_start_record(prompt)
    except (EvidenceBundleSizeError, AppServerPromptSizeError) as error:
        raise PrelaunchInputSizeError(
            "complete app-server input exceeds its byte budget"
        ) from error
    except AppServerProtocolError as error:
        if error.code not in {"prompt-size", "record-size"}:
            raise
        raise PrelaunchInputSizeError(
            "complete app-server turn/start record exceeds its byte budget"
        ) from error
    return PreparedAppServerInput(
        prompt=prompt,
        evidence_bundle=bundle,
        nearby_paths=nearby_paths,
    )


def build_primary_preflight_appserver_input(
    content: bytes,
    *,
    expected_sha256: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    forbidden_paths: Iterable[pathlib.Path],
) -> PreparedAppServerInput:
    """Prove the mandatory primary artifact fits the final app-server record."""

    forbidden = tuple(forbidden_paths)
    try:
        bundle = build_primary_evidence_bundle(
            content,
            expected_sha256=expected_sha256,
        )
    except EvidenceBundleSizeError as error:
        raise PrelaunchInputSizeError(
            "mandatory evidence bundle exceeds its byte budget"
        ) from error
    return _prepare_bundle_input(
        bundle=bundle,
        pr_url=pr_url,
        base_sha=base_sha,
        head_sha=head_sha,
        forbidden_paths=forbidden,
        nearby_paths=(),
    )


def _normalize_nearby_paths(
    manifest: AuthenticatedManifest,
    nearby_paths: Iterable[str],
) -> tuple[str, ...]:
    if isinstance(nearby_paths, (str, bytes)):
        raise EvidenceError("nearby evidence paths must be an explicit sequence")
    requested = tuple(nearby_paths)
    if len(requested) > MAX_EVIDENCE_CONTEXT_FILES:
        raise EvidenceError("too many nearby evidence files were requested")
    if any(not isinstance(path, str) for path in requested):
        raise EvidenceError("nearby evidence path is not a string")
    if len(set(requested)) != len(requested):
        raise EvidenceError("nearby evidence paths contain duplicates")
    manifest_paths = manifest.by_path()
    for path in requested:
        entry = manifest_paths.get(path)
        if path == PRIMARY_DIFF_RELATIVE_PATH or entry is None:
            raise EvidenceError("nearby evidence path is not manifest-authenticated")
        if entry.kind != "regular":
            raise EvidenceError("nearby evidence path is not a regular file")
    return tuple(sorted(requested, key=os.fsencode))


def build_prelaunch_appserver_input(
    *,
    root_fd: int,
    manifest: AuthenticatedManifest,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    forbidden_paths: Iterable[pathlib.Path],
    nearby_paths: Iterable[str] = (),
) -> PreparedAppServerInput:
    forbidden = tuple(forbidden_paths)
    requested = _normalize_nearby_paths(manifest, nearby_paths)
    lower = 0
    upper = len(requested)
    selected: PreparedAppServerInput | None = None
    last_size_error: PrelaunchInputSizeError | None = None
    while lower <= upper:
        count = (lower + upper) // 2
        selected_paths = requested[:count]
        try:
            bundle = build_evidence_bundle(
                root_fd=root_fd,
                manifest=manifest,
                nearby_paths=selected_paths,
            )
            candidate = _prepare_bundle_input(
                bundle=bundle,
                pr_url=pr_url,
                base_sha=base_sha,
                head_sha=head_sha,
                forbidden_paths=forbidden,
                nearby_paths=selected_paths,
            )
        except (PrelaunchInputSizeError, EvidenceBundleSizeError) as error:
            last_size_error = (
                error
                if isinstance(error, PrelaunchInputSizeError)
                else PrelaunchInputSizeError(
                    "complete evidence bundle exceeds its byte budget"
                )
            )
            upper = count - 1
        else:
            selected = candidate
            lower = count + 1
    if selected is None:
        if last_size_error is None:
            raise PrelaunchInputSizeError(
                "mandatory app-server input cannot be prepared"
            )
        raise last_size_error
    return selected


def run_appserver_stdio_session(
    *,
    reader: BinaryIO,
    writer: BinaryIO,
    prompt: bytes,
    config: AppServerSessionConfig,
) -> AppServerSessionResult:
    """Drive one app-server session over injected streams without spawning a process."""

    protocol = AppServerProtocol(prompt=prompt, config=config)
    _write_messages(writer, protocol.start())
    while True:
        record = reader.readline(APP_SERVER_MAX_RECORD_BYTES + 2)
        if record == b"":
            return protocol.finish_eof()
        if len(record) > APP_SERVER_MAX_RECORD_BYTES + 1:
            raise AppServerProtocolError(
                "protocol record exceeds its byte limit",
                code="record-size",
            )
        outbound = protocol.accept_line(record)
        _write_messages(writer, outbound)


def _write_messages(writer: BinaryIO, messages: Iterable[dict[str, object]]) -> None:
    wrote_any = False
    for message in messages:
        encoded = encode_json_line(message)
        written = writer.write(encoded)
        if written is not None and written != len(encoded):
            raise AppServerProtocolError(
                "app-server stdin accepted a short write",
                code="short-write",
            )
        wrote_any = True
    if wrote_any:
        flush = getattr(writer, "flush", None)
        if flush is not None:
            flush()
