from __future__ import annotations

import io
import os
import pathlib
import unittest
from unittest import mock

from review_supervisor.appserver_protocol import (
    AppServerProtocolError,
    AppServerSessionConfig,
    decode_json_line,
    encode_json_line,
)
from review_supervisor.appserver_runtime import (
    PreparedAppServerInput,
    PrelaunchInputSizeError,
    build_prelaunch_appserver_input,
    run_appserver_stdio_session,
)
from review_supervisor.evidence import (
    AuthenticatedManifest,
    EvidenceArtifact,
    EvidenceBundle,
    EvidenceError,
    ManifestEntry,
    build_evidence_bundle,
    manifest_sha256,
)
from review_supervisor.appserver_protocol import validate_prelaunch_turn_start_record
from review_supervisor.prompt import render_appserver_prompt
from review_supervisor.secureio import sha256_bytes

from tests.test_appserver_protocol import (
    CODEX_HOME,
    NEUTRAL_CWD,
    final_item,
    in_progress_turn,
    initialize_result,
    safe_config_result,
    thread_start_result,
    user_message,
)
from tests.support import owned_temporary_directory


def valid_transcript(
    config: AppServerSessionConfig,
    *,
    prompt: str = "self-contained evidence",
) -> bytes:
    thread_result = thread_start_result(config)
    turn = in_progress_turn()
    prompt_item = user_message(prompt)
    item = final_item()
    messages = (
        {"id": 1, "result": initialize_result()},
        {"id": 2, "result": safe_config_result()},
        {
            "id": 3,
            "result": {
                "data": [
                    {
                        "cwd": NEUTRAL_CWD,
                        "errors": [],
                        "hooks": [],
                        "warnings": [],
                    }
                ]
            },
        },
        {"method": "thread/started", "params": {"thread": thread_result["thread"]}},
        {"id": 4, "result": thread_result},
        {"id": 5, "result": {"turn": turn}},
        {
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": turn},
        },
        {
            "method": "item/started",
            "params": {
                "item": prompt_item,
                "startedAtMs": 997,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/completed",
            "params": {
                "completedAtMs": 998,
                "item": prompt_item,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/started",
            "params": {
                "item": item,
                "startedAtMs": 999,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/completed",
            "params": {
                "completedAtMs": 1000,
                "item": item,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [],
                    "itemsView": "notLoaded",
                    "status": "completed",
                },
            },
        },
    )
    return b"".join(encode_json_line(message) for message in messages)


class ShortWriter(io.BytesIO):
    def write(self, value: bytes) -> int:
        super().write(value[:-1])
        return len(value) - 1


class AppServerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
        )

    def test_drives_fake_streams_to_exact_terminal_result(self) -> None:
        reader = io.BytesIO(valid_transcript(self.config))
        writer = io.BytesIO()
        result = run_appserver_stdio_session(
            reader=reader,
            writer=writer,
            prompt=b"self-contained evidence",
            config=self.config,
        )
        self.assertEqual(result.review_status, "clean")
        self.assertEqual(result.final_text, "No findings.")

        outbound = [
            decode_json_line(line)
            for line in writer.getvalue().splitlines(keepends=True)
        ]
        self.assertEqual(
            [message["method"] for message in outbound],
            [
                "initialize",
                "initialized",
                "config/read",
                "hooks/list",
                "thread/start",
                "turn/start",
            ],
        )
        self.assertNotIn(b"jsonrpc", writer.getvalue())
        thread_request = outbound[4]
        self.assertEqual(thread_request["params"]["dynamicTools"], [])
        self.assertFalse(thread_request["params"]["allowProviderModelFallback"])
        self.assertNotIn("/worktree", writer.getvalue().decode())

    def test_builds_complete_model_input_before_any_stream_activity(self) -> None:
        with owned_temporary_directory("appserver-input-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff = b"diff --git a/a.py b/a.py\n+fixed\n"
            (control / "review.diff").write_bytes(diff)
            entry = ManifestEntry(
                path=".codex-review/review.diff",
                kind="regular",
                size=len(diff),
                sha256=sha256_bytes(diff),
            )
            manifest = AuthenticatedManifest.authenticate(
                (entry,),
                expected_sha256=manifest_sha256((entry,)),
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                prepared = build_prelaunch_appserver_input(
                    root_fd=root_fd,
                    manifest=manifest,
                    pr_url="https://github.example/owner/repo/pull/1",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    forbidden_paths=(root,),
                )
            finally:
                os.close(root_fd)
        self.assertEqual(prepared.evidence_bundle.artifacts[0].content.encode(), diff)
        self.assertIn(b'"role":"primary_diff"', prepared.prompt)
        self.assertNotIn(str(root).encode(), prepared.prompt)

    def test_rejects_escaped_turn_record_before_stream_activity(self) -> None:
        with owned_temporary_directory("appserver-input-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff = b"diff --git a/a.py b/a.py\n+fixed\n"
            (control / "review.diff").write_bytes(diff)
            entry = ManifestEntry(
                path=".codex-review/review.diff",
                kind="regular",
                size=len(diff),
                sha256=sha256_bytes(diff),
            )
            manifest = AuthenticatedManifest.authenticate(
                (entry,),
                expected_sha256=manifest_sha256((entry,)),
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch(
                    "review_supervisor.appserver_runtime.render_appserver_prompt",
                    return_value=b"\\" * (4 * 1024 * 1024),
                ):
                    with self.assertRaises(PrelaunchInputSizeError):
                        build_prelaunch_appserver_input(
                            root_fd=root_fd,
                            manifest=manifest,
                            pr_url="https://github.example/owner/repo/pull/1",
                            base_sha="1" * 40,
                            head_sha="2" * 40,
                            forbidden_paths=(root,),
                        )
            finally:
                os.close(root_fd)

    def test_drops_optional_context_to_fit_final_turn_record(self) -> None:
        with owned_temporary_directory("appserver-context-budget-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff = b"\\" * 2_050_000
            context = b"\\" * (64 * 1024)
            (control / "review.diff").write_bytes(diff)
            (root / "context.py").write_bytes(context)
            entries = (
                ManifestEntry(
                    path=".codex-review/review.diff",
                    kind="regular",
                    size=len(diff),
                    sha256=sha256_bytes(diff),
                ),
                ManifestEntry(
                    path="context.py",
                    kind="regular",
                    size=len(context),
                    sha256=sha256_bytes(context),
                ),
            )
            manifest = AuthenticatedManifest.authenticate(
                entries,
                expected_sha256=manifest_sha256(entries),
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                full_bundle = build_evidence_bundle(
                    root_fd=root_fd,
                    manifest=manifest,
                    nearby_paths=("context.py",),
                )
                full_prompt = render_appserver_prompt(
                    pr_url="https://github.example/owner/repo/pull/1",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    evidence_bundle=full_bundle,
                    forbidden_paths=(root,),
                )
                with self.assertRaises(AppServerProtocolError) as raised:
                    validate_prelaunch_turn_start_record(full_prompt)
                self.assertEqual(raised.exception.code, "record-size")

                prepared = build_prelaunch_appserver_input(
                    root_fd=root_fd,
                    manifest=manifest,
                    pr_url="https://github.example/owner/repo/pull/1",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    forbidden_paths=(root,),
                    nearby_paths=("context.py",),
                )
            finally:
                os.close(root_fd)

        self.assertEqual(prepared.nearby_paths, ())
        self.assertEqual(
            [artifact.role for artifact in prepared.evidence_bundle.artifacts],
            ["primary_diff"],
        )
        validate_prelaunch_turn_start_record(prepared.prompt)

    def test_budget_prefix_uses_authenticated_raw_path_order(self) -> None:
        raw_name = os.fsdecode(b"\x80.py")
        utf8_name = os.fsdecode(b"\xe2\x82\xac.py")
        with owned_temporary_directory("appserver-raw-path-order-") as root:
            diff = b"diff --git a/a.py b/a.py\n+fixed\n"
            entries = (
                ManifestEntry(
                    path=".codex-review/review.diff",
                    kind="regular",
                    size=len(diff),
                    sha256=sha256_bytes(diff),
                ),
                ManifestEntry(
                    path=raw_name,
                    kind="regular",
                    size=len(b"raw-byte-first"),
                    sha256=sha256_bytes(b"raw-byte-first"),
                ),
                ManifestEntry(
                    path=utf8_name,
                    kind="regular",
                    size=len(b"utf8-second"),
                    sha256=sha256_bytes(b"utf8-second"),
                ),
            )
            manifest = AuthenticatedManifest.authenticate(
                entries,
                expected_sha256=manifest_sha256(entries),
            )
            content_by_path = {
                raw_name: b"raw-byte-first",
                utf8_name: b"utf8-second",
            }

            def enforce_one_path(**kwargs):
                if len(kwargs["nearby_paths"]) > 1:
                    raise PrelaunchInputSizeError("test budget admits one path")
                return PreparedAppServerInput(
                    prompt=b"bounded",
                    evidence_bundle=kwargs["bundle"],
                    nearby_paths=kwargs["nearby_paths"],
                )

            def build_bundle(**kwargs):
                artifacts = [
                    EvidenceArtifact(
                        label="artifact-0000",
                        role="primary_diff",
                        content=diff.decode(),
                        length=len(diff),
                        sha256=sha256_bytes(diff),
                    )
                ]
                for index, path in enumerate(kwargs["nearby_paths"], start=1):
                    content = content_by_path[path]
                    artifacts.append(
                        EvidenceArtifact(
                            label=f"artifact-{index:04d}",
                            role="nearby_context",
                            content=content.decode(),
                            length=len(content),
                            sha256=sha256_bytes(content),
                        )
                    )
                return EvidenceBundle(
                    artifacts=tuple(artifacts),
                    manifest_sha256=manifest.sha256,
                    total_content_bytes=sum(artifact.length for artifact in artifacts),
                )

            with (
                mock.patch(
                    "review_supervisor.appserver_runtime.build_evidence_bundle",
                    side_effect=build_bundle,
                ),
                mock.patch(
                    "review_supervisor.appserver_runtime._prepare_bundle_input",
                    side_effect=enforce_one_path,
                ),
            ):
                prepared = build_prelaunch_appserver_input(
                    root_fd=-1,
                    manifest=manifest,
                    pr_url="https://github.example/owner/repo/pull/1",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    forbidden_paths=(root,),
                    nearby_paths=(utf8_name, raw_name),
                )

        self.assertEqual((raw_name,), prepared.nearby_paths)
        self.assertEqual(
            b"raw-byte-first",
            prepared.evidence_bundle.artifacts[1].content.encode(),
        )

    def test_rejects_malformed_optional_paths_before_budget_selection(self) -> None:
        diff = b"diff --git a/a.py b/a.py\n+fixed\n"
        entry = ManifestEntry(
            path=".codex-review/review.diff",
            kind="regular",
            size=len(diff),
            sha256=sha256_bytes(diff),
        )
        manifest = AuthenticatedManifest.authenticate(
            (entry,),
            expected_sha256=manifest_sha256((entry,)),
        )
        with self.assertRaisesRegex(EvidenceError, "not a string"):
            build_prelaunch_appserver_input(
                root_fd=-1,
                manifest=manifest,
                pr_url="https://github.example/owner/repo/pull/1",
                base_sha="1" * 40,
                head_sha="2" * 40,
                forbidden_paths=(pathlib.Path("/private/review/worktree"),),
                nearby_paths=([],),
            )

    def test_rejects_abnormal_eof_trailing_record_and_short_write(self) -> None:
        with self.assertRaises(AppServerProtocolError) as raised:
            run_appserver_stdio_session(
                reader=io.BytesIO(),
                writer=io.BytesIO(),
                prompt=b"evidence",
                config=self.config,
            )
        self.assertEqual(raised.exception.code, "abnormal-eof")

        transcript = valid_transcript(
            self.config, prompt="evidence"
        ) + encode_json_line({"method": "warning", "params": {}})
        with self.assertRaises(AppServerProtocolError) as raised:
            run_appserver_stdio_session(
                reader=io.BytesIO(transcript),
                writer=io.BytesIO(),
                prompt=b"evidence",
                config=self.config,
            )
        self.assertEqual(raised.exception.code, "trailing-record")

        with self.assertRaises(AppServerProtocolError) as raised:
            run_appserver_stdio_session(
                reader=io.BytesIO(valid_transcript(self.config, prompt="evidence")),
                writer=ShortWriter(),
                prompt=b"evidence",
                config=self.config,
            )
        self.assertEqual(raised.exception.code, "short-write")


if __name__ == "__main__":
    unittest.main()
