from __future__ import annotations

from collections.abc import Iterable
import pathlib
from dataclasses import dataclass
from typing import BinaryIO

from .appserver_protocol import (
    AppServerProtocol,
    AppServerProtocolError,
    AppServerSessionConfig,
    AppServerSessionResult,
    encode_json_line,
    validate_prelaunch_turn_start_record,
)
from .constants import APP_SERVER_MAX_RECORD_BYTES
from .evidence import AuthenticatedManifest, EvidenceBundle, build_evidence_bundle
from .prompt import render_appserver_prompt


@dataclass(frozen=True)
class PreparedAppServerInput:
    prompt: bytes
    evidence_bundle: EvidenceBundle


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
    bundle = build_evidence_bundle(
        root_fd=root_fd,
        manifest=manifest,
        nearby_paths=nearby_paths,
    )
    prompt = render_appserver_prompt(
        pr_url=pr_url,
        base_sha=base_sha,
        head_sha=head_sha,
        evidence_bundle=bundle,
        forbidden_paths=tuple(forbidden_paths),
    )
    validate_prelaunch_turn_start_record(prompt)
    return PreparedAppServerInput(prompt=prompt, evidence_bundle=bundle)


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
