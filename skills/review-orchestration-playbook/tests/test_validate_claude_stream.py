from __future__ import annotations

import copy
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
VALIDATOR = SCRIPTS / "validate_claude_stream.py"
SCHEMA = SKILL_ROOT / "references/claude-2.1.212-stream-schema.json"
sys.path.insert(0, str(SCRIPTS))

import validate_claude_stream as validator  # noqa: E402
from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_provenance,
    claude_stream_contract,
    claude_version_policy,
)


class ClaudeStreamValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.temporary_root = Path(temporary_directory.name).resolve()
        self.cwd = self.temporary_root / "review-workspace"
        self.cwd.mkdir(mode=0o700)
        self.parent_state = self.temporary_root / "parent-state"
        self.parent_state.mkdir(mode=0o700)
        self.preflight_path = self.parent_state / "named-claude-preflight.json"
        self._write_preflight_evidence(self.preflight_path)
        self.init_event = {
            "type": "system",
            "subtype": "init",
            "cwd": str(self.cwd),
            "permissionMode": "dontAsk",
            "tools": ["Read", "Grep", "Glob", "Bash"],
            "mcp_servers": [],
            "slash_commands": [],
            "skills": [],
            "plugins": [],
            "model": "claude-opus-4-8",
            "claude_code_version": "2.1.212",
            "apiKeySource": "none",
            "session_id": "init-session",
        }
        self.progress_event = {
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "working"}]},
        }
        self.result_event = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": "\nNo findings.\n",
            "modelUsage": {"claude-opus-4-8": {"inputTokens": 1}},
            "duration_ms": 10,
            "duration_api_ms": 5,
            "num_turns": 1,
            "session_id": "init-session",
            "total_cost_usd": 0.01,
            "usage": {},
            "uuid": "result-uuid",
            "stop_reason": "end_turn",
            "structured_output": None,
            "error": None,
            "errors": [],
            "api_error_status": None,
            "permission_denials": [],
        }

    @staticmethod
    def _preflight_evidence(version: str = "2.1.212") -> dict[str, object]:
        binding, _compatibility_raw, _baseline_raw = (
            claude_stream_contract.load_stream_contract()
        )
        manifest_url, signature_url = claude_provenance.release_artifact_urls(version)
        artifact_size = 128
        return {
            "capability_contract": {
                "required_options": list(claude_capabilities.CLAUDE_REQUIRED_OPTIONS),
                "status": "accepted",
            },
            "classification": "accepted",
            "compatible_version_range": (
                claude_version_policy.CLAUDE_COMPATIBILITY_SPEC
            ),
            "declared_version": version,
            "identity": {
                "device": 1,
                "inode": 2,
                "file_type": stat.S_IFREG,
                "mode": stat.S_IFREG | 0o500,
                "nlink": 1,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "size": artifact_size,
                "mtime_ns": 3,
                "ctime_ns": 4,
            },
            "observed_version": version,
            "publisher_verification": {
                "artifact_size": artifact_size,
                "binary": "claude",
                "checksum": "a" * 64,
                "manifest_url": manifest_url,
                "platform": "darwin-arm64",
                "release_version": version,
                "signature_url": signature_url,
                "signer_fingerprint": (
                    claude_provenance.CLAUDE_RELEASE_KEY_FINGERPRINT
                ),
            },
            "reason": "compatible-version-selected",
            "resolved_path": "/trusted/claude",
            "selected_version": version,
            "source": "side-by-side-compatible",
            "stream_contract": {
                "baseline_digest": binding.baseline_digest,
                "capability_digest": binding.capability_digest,
                "compatibility_digest": binding.compatibility_digest,
                "digest": binding.digest,
                "schema_id": binding.schema_id,
            },
        }

    def _write_preflight_evidence(
        self,
        path: Path,
        *,
        version: str = "2.1.212",
        evidence: dict[str, object] | None = None,
    ) -> None:
        path.write_text(
            json.dumps(
                evidence if evidence is not None else self._preflight_evidence(version),
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    @staticmethod
    def _raw(events: list[object], *, blank_edges: bool = False) -> bytes:
        lines = [
            json.dumps(
                event, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            )
            for event in events
        ]
        body = "\n".join(lines) + "\n"
        if blank_edges:
            body = "\n \t\r\n" + body + "\t\n"
        return body.encode("utf-8")

    def _full_events(self) -> list[dict[str, object]]:
        return [
            copy.deepcopy(self.init_event),
            copy.deepcopy(self.progress_event),
            copy.deepcopy(self.result_event),
        ]

    def _validate(
        self,
        events: list[object] | None = None,
        *,
        raw: bytes | None = None,
        requested_model: str = "claude-opus-4-8",
        api_key_source: str = "none",
        selected_version: str = "2.1.212",
        preflight_result: Path | None = None,
        process_returncode: object = 0,
        limits: validator.StreamLimits | None = None,
    ) -> dict[str, object]:
        if raw is None:
            raw = self._raw(events if events is not None else self._full_events())
        if preflight_result is None:
            if selected_version == "2.1.212":
                preflight_result = self.preflight_path
            else:
                preflight_result = self.parent_state / (
                    f"named-claude-preflight-{selected_version}.json"
                )
                self._write_preflight_evidence(
                    preflight_result,
                    version=selected_version,
                )
        return validator.validate_claude_stream_bytes(
            raw,
            expected_cwd=self.cwd,
            requested_model=requested_model,
            api_key_source=api_key_source,
            preflight_result=preflight_result,
            process_returncode=process_returncode,
            limits=limits,
        )

    def assert_fail_closed(
        self, outcome: dict[str, object], classification: str | None = None
    ) -> None:
        self.assertNotEqual(outcome["classification"], "accepted")
        if classification is not None:
            self.assertEqual(outcome["classification"], classification)
        self.assertNotIn("findings", outcome)
        self.assertTrue(outcome["reasons"])

    def assert_raises_without_blocking_on_fifo(
        self,
        *,
        fifo: Path,
        action: Callable[[], object],
        expected_error: type[BaseException],
    ) -> None:
        returned: list[object] = []
        errors: list[BaseException] = []
        finished = threading.Event()

        def invoke() -> None:
            try:
                returned.append(action())
            except BaseException as error:  # pragma: no cover - diagnostic only
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=invoke, daemon=True)
        thread.start()
        blocked = not finished.wait(1.0)
        if blocked:
            descriptor = os.open(fifo, os.O_RDWR | getattr(os, "O_NONBLOCK", 0))
            try:
                os.write(descriptor, b"{}\n")
            finally:
                os.close(descriptor)
            finished.wait(1.0)
        thread.join(timeout=0.1)

        self.assertFalse(blocked, f"{action!r} blocked while opening FIFO evidence")
        self.assertFalse(thread.is_alive(), "FIFO reader thread remained alive")
        self.assertEqual(returned, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], expected_error)

    def test_machine_schema_defines_complete_init_and_stream_bounds(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(schema["claude_code_version"], "2.1.212")
        self.assertEqual(
            schema["process_returncode"], validator.PROCESS_RETURNCODE_CONTRACT
        )
        self.assertEqual(
            schema["stream_contract"],
            {
                "encoding": "utf-8",
                "format": "jsonl",
                "blank_lines": "ignored",
                "top_level": "object",
                "duplicate_keys": "reject",
                "nonstandard_constants": "reject",
                "unpaired_surrogates": "reject",
                "max_integer_digits": 128,
                "floating_number_representation": "decimal",
                "max_float_characters": 256,
                "max_float_significand_digits": 128,
                "max_float_explicit_exponent_magnitude": 308,
                "max_bytes": 8388608,
                "max_lines": 10000,
                "max_line_bytes": 1048576,
                "first_nonblank_event": {"type": "system", "subtype": "init"},
                "last_nonblank_event": {"type": "result"},
                "init_event_count": 1,
                "result_event_count": 1,
                "matching_session_id_when_both_present": True,
            },
        )
        init_contract = schema["init_event"]
        self.assertEqual(
            set(init_contract["required_fields"]), validator.INIT_REQUIRED_FIELDS
        )
        self.assertEqual(
            set(init_contract["field_contracts"]), validator.INIT_REQUIRED_FIELDS
        )
        self.assertFalse(init_contract["additional_fields"])
        self.assertEqual(
            set(init_contract["optional_fields"]), validator.INIT_OPTIONAL_FIELDS
        )
        self.assertEqual(
            init_contract["optional_field_contracts"],
            {
                "session_id": {
                    "rule": "nonempty_string",
                    "failure": "inconclusive",
                }
            },
        )
        terminal_contract = schema["terminal_result"]
        self.assertFalse(terminal_contract["additional_fields"])
        self.assertEqual(
            set(terminal_contract["required_fields"]),
            {"type", "subtype", "is_error"},
        )
        self.assertEqual(
            terminal_contract["variants"]["success"]["match"],
            {"subtype": "success", "is_error": False},
        )
        self.assertEqual(
            set(terminal_contract["variants"]["success"]["required_fields"]),
            {"result", "modelUsage"},
        )
        self.assertEqual(
            terminal_contract["variants"]["failure"]["match"],
            {
                "subtype": {"rule": "string_not_equal", "value": "success"},
                "is_error": True,
            },
        )
        self.assertEqual(
            terminal_contract["variants"]["failure"]["required_fields"], []
        )
        self.assertEqual(
            set(terminal_contract["variants"]["failure"]["optional_fields"]),
            {"result", "modelUsage"},
        )

    def test_compatibility_profile_keeps_exact_baseline_separate_from_range(
        self,
    ) -> None:
        profile = json.loads(
            claude_stream_contract.COMPATIBILITY_PATH.read_text(encoding="utf-8")
        )
        binding, _compatibility_raw, _baseline_raw = (
            claude_stream_contract.load_stream_contract()
        )

        self.assertEqual(profile["baseline_version"], "2.1.212")
        self.assertEqual(
            profile["version_policy"],
            "review_runtime.claude_version_policy.CLAUDE_COMPATIBILITY_SPEC",
        )
        self.assertEqual(
            claude_version_policy.CLAUDE_COMPATIBILITY_SPEC,
            ">=2.1.211,<3.0.0",
        )
        self.assertEqual(binding.schema_id, "claude-code-stream-compatible-v1")
        self.assertEqual(len(binding.capability_digest), 64)
        self.assertNotIn("required_version", profile)

    def test_loader_rejects_process_returncode_contract_drift(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema["process_returncode"]["nonzero_precedence"]["blocked"] = "inconclusive"
        schema_path = self.cwd / "invalid-stream-schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")

        with (
            mock.patch.object(validator, "SCHEMA_PATH", schema_path),
            self.assertRaises(validator._ContractError),
        ):
            validator._load_contract()

    def test_validator_rejects_unknown_root_and_ignored_field_rule_drift(
        self,
    ) -> None:
        baseline = json.loads(SCHEMA.read_text(encoding="utf-8"))

        def add_unknown_root(schema: dict[str, object]) -> None:
            schema["unknown_root_contract"] = {"rule": "accept"}

        def weaken_init_rule(schema: dict[str, object]) -> None:
            schema["init_event"]["field_contracts"]["tools"]["mismatch_failure"] = (
                "inconclusive"
            )

        def weaken_terminal_rule(schema: dict[str, object]) -> None:
            schema["terminal_result"]["optional_field_contracts"]["duration_ms"][
                "rule"
            ] = "positive_integer"

        cases: dict[str, Callable[[dict[str, object]], None]] = {
            "unknown-root": add_unknown_root,
            "ignored-init-field-rule": weaken_init_rule,
            "ignored-terminal-field-rule": weaken_terminal_rule,
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                schema = copy.deepcopy(baseline)
                mutate(schema)
                schema_path = self.parent_state / f"{name}.json"
                schema_path.write_text(json.dumps(schema), encoding="utf-8")
                with mock.patch.object(validator, "SCHEMA_PATH", schema_path):
                    self.assertEqual(
                        self._validate(),
                        {
                            "classification": "inconclusive",
                            "reasons": ["validator.contract-invalid"],
                        },
                    )

    def test_accepts_complete_stream_and_preserves_findings_verbatim(self) -> None:
        outcome = self._validate(raw=self._raw(self._full_events(), blank_edges=True))

        self.assertEqual(
            outcome,
            {"classification": "accepted", "findings": "\nNo findings.\n"},
        )

    def test_accepts_compatible_selected_versions_and_binds_init_exactly(self) -> None:
        for version in ("2.1.211", "2.1.216", "2.99.999"):
            with self.subTest(version=version):
                events = self._full_events()
                events[0]["claude_code_version"] = version
                self.assertEqual(
                    self._validate(events, selected_version=version),
                    {
                        "classification": "accepted",
                        "findings": "\nNo findings.\n",
                    },
                )

        mismatched = self._full_events()
        mismatched[0]["claude_code_version"] = "2.1.211"
        outcome = self._validate(mismatched, selected_version="2.1.216")
        self.assertEqual(outcome["classification"], "blocked")
        self.assertIn("init.claude_code_version.mismatch", outcome["reasons"])
        self.assertNotIn("findings", outcome)

    def test_future_compatible_version_unknown_shapes_fail_closed(self) -> None:
        for surface in ("init", "terminal"):
            with self.subTest(surface=surface):
                events = self._full_events()
                events[0]["claude_code_version"] = "2.1.216"
                target = events[0] if surface == "init" else events[-1]
                target["future_field"] = True

                outcome = self._validate(events, selected_version="2.1.216")

                self.assertEqual(outcome["classification"], "inconclusive")
                self.assertNotIn("findings", outcome)

    def test_tampered_preflight_evidence_never_releases_findings(self) -> None:
        def update_nested(
            key: str,
            values: dict[str, object],
        ) -> Callable[[dict[str, object]], None]:
            def mutate(evidence: dict[str, object]) -> None:
                nested = evidence[key]
                assert isinstance(nested, dict)
                nested.update(values)

            return mutate

        cases: dict[str, Callable[[dict[str, object]], None]] = {
            "extra-field": lambda evidence: evidence.update({"unexpected": True}),
            "range": lambda evidence: evidence.update(
                {"compatible_version_range": "==2.1.212"}
            ),
            "selected-version": lambda evidence: evidence.update(
                {"selected_version": "2.1.217"}
            ),
            "retired-source": lambda evidence: evidence.update(
                {"source": "side-by-side-exact"}
            ),
            "identity-size": update_nested("identity", {"size": 129}),
            "publisher-version": update_nested(
                "publisher_verification",
                {"release_version": "2.1.211"},
            ),
            "capability": update_nested(
                "capability_contract",
                {"status": "unaccepted"},
            ),
            "stream-digest": update_nested(
                "stream_contract",
                {"digest": "0" * 64},
            ),
            "capability-digest": update_nested(
                "stream_contract",
                {"capability_digest": "0" * 64},
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                evidence = self._preflight_evidence("2.1.216")
                mutate(evidence)
                preflight_result = self.parent_state / f"tampered-{name}.json"
                self._write_preflight_evidence(
                    preflight_result,
                    evidence=evidence,
                )
                events = self._full_events()
                events[0]["claude_code_version"] = "2.1.216"

                self.assertEqual(
                    self._validate(events, preflight_result=preflight_result),
                    {
                        "classification": "inconclusive",
                        "reasons": ["validator.preflight-evidence-invalid"],
                    },
                )

    def test_preflight_evidence_file_must_be_parent_private_and_not_a_symlink(
        self,
    ) -> None:
        public_path = self.parent_state / "public-preflight.json"
        self._write_preflight_evidence(public_path)
        public_path.chmod(0o644)
        self.assertEqual(
            self._validate(preflight_result=public_path),
            {
                "classification": "inconclusive",
                "reasons": ["validator.preflight-evidence-invalid"],
            },
        )

        alias = self.parent_state / "preflight-alias.json"
        alias.symlink_to(self.preflight_path)
        self.assertEqual(
            self._validate(preflight_result=alias),
            {
                "classification": "inconclusive",
                "reasons": ["validator.preflight-evidence-invalid"],
            },
        )

    def test_preflight_evidence_inside_review_workspace_fails_closed(self) -> None:
        workspace_local = self.cwd / "workspace-local-preflight.json"
        self._write_preflight_evidence(workspace_local)

        self.assertEqual(
            self._validate(preflight_result=workspace_local),
            {
                "classification": "inconclusive",
                "reasons": ["validator.preflight-evidence-invalid"],
            },
        )

    def test_hardlinked_preflight_evidence_fails_closed(self) -> None:
        hardlink = self.parent_state / "hardlinked-preflight.json"
        os.link(self.preflight_path, hardlink)

        self.assertEqual(
            self._validate(preflight_result=hardlink),
            {
                "classification": "inconclusive",
                "reasons": ["validator.preflight-evidence-invalid"],
            },
        )

    def test_fifo_contract_inputs_fail_closed_without_blocking(self) -> None:
        preflight_fifo = self.parent_state / "preflight.fifo"
        os.mkfifo(preflight_fifo, mode=0o600)
        self.assert_raises_without_blocking_on_fifo(
            fifo=preflight_fifo,
            action=lambda: validator._read_preflight_evidence(
                preflight_fifo,
                reviewer_cwd=self.cwd,
            ),
            expected_error=validator._ContractError,
        )

        compatibility_fifo = self.parent_state / "compatibility.fifo"
        os.mkfifo(compatibility_fifo, mode=0o600)
        self.assert_raises_without_blocking_on_fifo(
            fifo=compatibility_fifo,
            action=lambda: claude_stream_contract.load_stream_contract(
                compatibility_path=compatibility_fifo,
                baseline_path=claude_stream_contract.BASELINE_PATH,
            ),
            expected_error=claude_stream_contract.ClaudeStreamContractError,
        )

    def test_accepts_init_without_optional_session_id(self) -> None:
        events = self._full_events()
        del events[0]["session_id"]

        self.assertEqual(self._validate(events)["classification"], "accepted")

    def test_rejects_conflicting_init_and_terminal_session_ids(self) -> None:
        events = self._full_events()
        events[-1]["session_id"] = "different-session"

        self.assertEqual(
            self._validate(events),
            {
                "classification": "inconclusive",
                "reasons": ["stream.session_id.mismatch"],
            },
        )

    def test_nonzero_success_is_inconclusive_and_returncode_must_be_exact_int(
        self,
    ) -> None:
        for process_returncode in (1, -9, 401):
            with self.subTest(process_returncode=process_returncode):
                self.assertEqual(
                    self._validate(process_returncode=process_returncode),
                    {
                        "classification": "inconclusive",
                        "reasons": ["process.returncode.nonzero"],
                    },
                )

        for process_returncode in (None, False, True, 0.0, "0", [], {}):
            with self.subTest(invalid_process_returncode=process_returncode):
                self.assertEqual(
                    self._validate(process_returncode=process_returncode),
                    {
                        "classification": "inconclusive",
                        "reasons": ["process.returncode.invalid"],
                    },
                )

        self.assertEqual(
            validator.validate_claude_stream_bytes(
                self._raw(self._full_events()),
                expected_cwd=self.cwd,
                requested_model="claude-opus-4-8",
                api_key_source="none",
                preflight_result=self.preflight_path,
            ),
            {
                "classification": "inconclusive",
                "reasons": ["process.returncode.invalid"],
            },
        )

    def test_bare_401_with_nonzero_returncode_is_inconclusive(self) -> None:
        self.assertEqual(
            self._validate(raw=b"401\n", process_returncode=401),
            {
                "classification": "inconclusive",
                "reasons": [
                    "process.returncode.nonzero",
                    "stream.non-object-event",
                ],
            },
        )

    def test_nonzero_preserves_deterministic_structured_blocked_outcomes(
        self,
    ) -> None:
        init_blocked = self._full_events()
        init_blocked[0]["permissionMode"] = "default"
        terminal_blocked = [
            copy.deepcopy(self.init_event),
            {
                "type": "result",
                "subtype": "error",
                "is_error": True,
                "modelUsage": {"claude-opus-4-7": {}},
            },
        ]

        self.assertEqual(
            self._validate(init_blocked, process_returncode=1),
            {
                "classification": "blocked",
                "reasons": ["init.permissionMode.mismatch"],
            },
        )
        self.assertEqual(
            self._validate(terminal_blocked, process_returncode=401),
            {
                "classification": "blocked",
                "reasons": [
                    "terminal.modelUsage.primary-model-substitution",
                    "terminal.modelUsage.requested-model-missing",
                ],
            },
        )

    def test_accepts_reviewed_model_alias_and_auxiliary_usage(self) -> None:
        events = self._full_events()
        events[-1]["modelUsage"] = {
            "claude-opus-4.8": {},
            "claude-haiku-4-5-20251001": {},
        }

        outcome = self._validate(events)

        self.assertEqual(outcome["classification"], "accepted")

    def test_accepts_explicit_api_key_source_when_init_matches(self) -> None:
        events = self._full_events()
        events[0]["apiKeySource"] = "ANTHROPIC_API_KEY"

        outcome = self._validate(events, api_key_source="ANTHROPIC_API_KEY")

        self.assertEqual(outcome["classification"], "accepted")

    def test_rejects_malformed_raw_streams(self) -> None:
        valid = self._full_events()
        init = self._raw([valid[0]])
        terminal = self._raw([valid[-1]])
        malformed_cases = {
            "invalid-utf8": init + b"\xff\n" + terminal,
            "invalid-json": init + b"not-json\n" + terminal,
            "non-object": init + b"[]\n" + terminal,
            "nonstandard-constant": init
            + b'{"type":"assistant","value":NaN}\n'
            + terminal,
            "infinite-constant": init
            + b'{"type":"assistant","value":Infinity}\n'
            + terminal,
            "duplicate-json-key": init
            + b'{"type":"assistant","type":"assistant"}\n'
            + terminal,
        }

        for name, raw in malformed_cases.items():
            with self.subTest(name=name):
                self.assert_fail_closed(self._validate(raw=raw), "inconclusive")

        outcome = validator.validate_claude_stream(
            io.StringIO("not binary"),
            expected_cwd=self.cwd,
            requested_model="claude-opus-4-8",
            api_key_source="none",
            preflight_result=self.preflight_path,
            process_returncode=0,
        )
        self.assert_fail_closed(outcome, "inconclusive")

    def test_json_parser_exceptions_fail_closed(self) -> None:
        contract_with_binding = validator._load_contract_with_binding()
        parser_errors = (
            ValueError("integer conversion limit"),
            RecursionError("maximum recursion depth exceeded"),
            OverflowError("parser overflow"),
        )

        for error in parser_errors:
            with self.subTest(error=type(error).__name__):
                with (
                    mock.patch.object(
                        validator,
                        "_load_contract_with_binding",
                        return_value=contract_with_binding,
                    ),
                    mock.patch.object(
                        validator,
                        "_read_preflight_evidence",
                        return_value=self._preflight_evidence(),
                    ),
                    mock.patch.object(
                        validator, "_strict_json_loads", side_effect=error
                    ),
                ):
                    outcome = self._validate(raw=b"{}\n")
                self.assertEqual(
                    outcome,
                    {
                        "classification": "inconclusive",
                        "reasons": ["stream.invalid-json"],
                    },
                )

        for error in parser_errors:
            with self.subTest(schema_error=type(error).__name__):
                with mock.patch.object(
                    validator, "_strict_json_loads", side_effect=error
                ):
                    outcome = self._validate()
                self.assertEqual(
                    outcome,
                    {
                        "classification": "inconclusive",
                        "reasons": ["validator.contract-invalid"],
                    },
                )

    def test_json_integer_digit_bound_is_explicit(self) -> None:
        accepted_progress = (
            b'{"type":"assistant","value":'
            + b"1" * validator.MAX_JSON_INTEGER_DIGITS
            + b"}\n"
        )
        rejected_progress = (
            b'{"type":"assistant","value":'
            + b"1" * (validator.MAX_JSON_INTEGER_DIGITS + 1)
            + b"}\n"
        )
        valid = self._full_events()
        init = self._raw([valid[0]])
        terminal = self._raw([valid[-1]])

        self.assertEqual(
            self._validate(raw=init + accepted_progress + terminal)["classification"],
            "accepted",
        )
        self.assertEqual(
            self._validate(raw=init + rejected_progress + terminal),
            {
                "classification": "inconclusive",
                "reasons": ["stream.invalid-json"],
            },
        )

    def test_rejects_unpaired_surrogates(self) -> None:
        valid = self._full_events()
        raw = (
            self._raw([valid[0]])
            + b'{"type":"assistant","value":"\\ud800"}\n'
            + self._raw([valid[-1]])
        )

        outcome = self._validate(raw=raw)

        self.assertEqual(
            outcome,
            {
                "classification": "inconclusive",
                "reasons": ["stream.unpaired-surrogate"],
            },
        )

    def test_enforces_caller_tightened_stream_bounds(self) -> None:
        raw = self._raw(self._full_events())
        cases = {
            "bytes": validator.StreamLimits(
                max_bytes=len(raw) - 1,
                max_lines=10_000,
                max_line_bytes=1024 * 1024,
            ),
            "lines": validator.StreamLimits(
                max_bytes=8 * 1024 * 1024,
                max_lines=2,
                max_line_bytes=1024 * 1024,
            ),
            "line-bytes": validator.StreamLimits(
                max_bytes=8 * 1024 * 1024,
                max_lines=10_000,
                max_line_bytes=32,
            ),
        }

        for name, limits in cases.items():
            with self.subTest(name=name):
                self.assert_fail_closed(
                    self._validate(raw=raw, limits=limits), "inconclusive"
                )

    def test_rejects_missing_envelope_and_required_fields(self) -> None:
        missing_init = [
            copy.deepcopy(self.progress_event),
            copy.deepcopy(self.result_event),
        ]
        missing_result = [
            copy.deepcopy(self.init_event),
            copy.deepcopy(self.progress_event),
        ]
        init_missing_cwd = self._full_events()
        del init_missing_cwd[0]["cwd"]
        result_missing_usage = self._full_events()
        del result_missing_usage[-1]["modelUsage"]
        result_missing_subtype = self._full_events()
        del result_missing_subtype[-1]["subtype"]
        cases = {
            "empty": [],
            "init": missing_init,
            "result": missing_result,
            "init-field": init_missing_cwd,
            "result-field": result_missing_usage,
            "result-status": result_missing_subtype,
        }

        for name, events in cases.items():
            with self.subTest(name=name):
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_rejects_duplicate_contract_events_and_tools(self) -> None:
        duplicate_init = self._full_events()
        duplicate_init.insert(1, copy.deepcopy(self.init_event))
        duplicate_result = self._full_events()
        duplicate_result.append(copy.deepcopy(self.result_event))
        duplicate_tools = self._full_events()
        duplicate_tools[0]["tools"] = ["Read", "Grep", "Glob", "Bash", "Read"]

        self.assert_fail_closed(self._validate(duplicate_init), "inconclusive")
        self.assert_fail_closed(self._validate(duplicate_result), "inconclusive")
        outcome = self._validate(duplicate_tools)
        self.assert_fail_closed(outcome, "inconclusive")
        self.assertIn("init.tools.duplicate", outcome["reasons"])

    def test_rejects_misordered_or_trailing_contract_events(self) -> None:
        init_not_first = [
            copy.deepcopy(self.progress_event),
            copy.deepcopy(self.init_event),
            copy.deepcopy(self.result_event),
        ]
        result_not_last = self._full_events() + [copy.deepcopy(self.progress_event)]
        result_before_init = [
            copy.deepcopy(self.result_event),
            copy.deepcopy(self.init_event),
        ]

        for name, events in {
            "init-not-first": init_not_first,
            "result-not-last": result_not_last,
            "result-before-init": result_before_init,
        }.items():
            with self.subTest(name=name):
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_rejects_malformed_init_field_types(self) -> None:
        malformed_values = {
            "cwd": 1,
            "permissionMode": ["dontAsk"],
            "tools": ["Read", "Grep", "Glob", 4],
            "mcp_servers": {},
            "slash_commands": None,
            "skills": "",
            "plugins": {},
            "model": ["claude-opus-4-8"],
            "claude_code_version": 212,
            "apiKeySource": None,
            "session_id": " ",
        }

        for field_name, value in malformed_values.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_rejects_hooks_agents_and_arbitrary_unknown_init_fields(self) -> None:
        unknown_fields = {
            "hooks": [{"matcher": "Bash"}],
            "agents": [{"name": "reviewer"}],
            "future_field": True,
        }

        for field_name, value in unknown_fields.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                self.assertEqual(
                    self._validate(events),
                    {
                        "classification": "inconclusive",
                        "reasons": ["init.unknown-field"],
                    },
                )

    def test_rejects_well_formed_init_mismatches_as_blocked(self) -> None:
        mismatch_values = {
            "cwd": str(self.cwd / "other"),
            "permissionMode": "default",
            "tools": ["Read", "Grep", "Glob"],
            "mcp_servers": ["server"],
            "slash_commands": ["review"],
            "skills": ["skill"],
            "plugins": ["plugin"],
            "model": "claude-opus-4-7",
            "claude_code_version": "2.1.211",
            "apiKeySource": "ANTHROPIC_API_KEY",
        }

        for field_name, value in mismatch_values.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                self.assert_fail_closed(self._validate(events), "blocked")

    def test_rejects_terminal_type_and_shape_violations(self) -> None:
        mutations = {
            "result-type": ("result", []),
            "modelUsage-type": ("modelUsage", []),
            "duration-bool": ("duration_ms", True),
            "turns-zero": ("num_turns", 0),
            "cost-bool": ("total_cost_usd", True),
            "cost-negative": ("total_cost_usd", -1),
            "cost-string": ("total_cost_usd", "0.01"),
            "session-empty": ("session_id", " "),
            "usage-array": ("usage", []),
            "uuid-empty": ("uuid", ""),
            "structured-output": ("structured_output", {}),
            "permission-denials-type": ("permission_denials", {}),
        }

        for name, (field_name, value) in mutations.items():
            with self.subTest(name=name):
                events = self._full_events()
                events[-1][field_name] = value
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_total_cost_uses_bounded_exact_decimal_parsing(self) -> None:
        huge_integer = 10**400
        huge_integer_events = self._full_events()
        huge_integer_events[-1]["total_cost_usd"] = huge_integer

        self.assertEqual(
            self._validate(huge_integer_events),
            {
                "classification": "inconclusive",
                "reasons": ["stream.invalid-json"],
            },
        )

        bounded_cases = {
            "negative-within-bound": (
                b"-1e-308",
                "terminal.total_cost_usd.malformed",
            ),
            "negative-underflow-lexeme": (b"-1e-999999", "stream.invalid-json"),
            "positive-exponent-over-bound": (b"1e309", "stream.invalid-json"),
            "negative-exponent-over-bound": (b"1e-309", "stream.invalid-json"),
            "significand-over-bound": (
                b"0." + (b"1" * 128),
                "stream.invalid-json",
            ),
            "token-over-character-bound": (
                b"1e" + (b"0" * 256) + b"1",
                "stream.invalid-json",
            ),
        }
        raw = self._raw(self._full_events())
        for name, (replacement, reason) in bounded_cases.items():
            with self.subTest(name=name):
                candidate = raw.replace(
                    b'"total_cost_usd":0.01', b'"total_cost_usd":' + replacement
                )
                self.assertEqual(
                    self._validate(raw=candidate),
                    {"classification": "inconclusive", "reasons": [reason]},
                )

        max_exponent = raw.replace(b'"total_cost_usd":0.01', b'"total_cost_usd":1e308')
        self.assertEqual(
            self._validate(raw=max_exponent),
            {"classification": "accepted", "findings": "\nNo findings.\n"},
        )

    def test_classifies_closed_terminal_model_and_stop_mismatches(self) -> None:
        other_model = self._full_events()
        other_model[-1]["modelUsage"] = {"claude-opus-4-7": {}}
        mixed_models = self._full_events()
        mixed_models[-1]["modelUsage"] = {
            "claude-opus-4-8": {},
            "claude-opus-4-7": {},
        }
        unknown_model = self._full_events()
        unknown_model[-1]["modelUsage"] = {
            "claude-opus-4-8": {},
            "claude-future": {},
        }
        unknown_field = self._full_events()
        unknown_field[-1]["future_field"] = True
        abnormal_stop = self._full_events()
        abnormal_stop[-1]["stop_reason"] = "max_tokens"
        permission_denial = self._full_events()
        permission_denial[-1]["permission_denials"] = [{"tool": "Read"}]

        self.assert_fail_closed(self._validate(other_model), "blocked")
        self.assert_fail_closed(self._validate(mixed_models), "blocked")
        self.assert_fail_closed(self._validate(unknown_model), "inconclusive")
        self.assert_fail_closed(self._validate(unknown_field), "inconclusive")
        self.assert_fail_closed(self._validate(abnormal_stop), "blocked")
        self.assert_fail_closed(self._validate(permission_denial), "blocked")

    def test_classifies_only_strict_terminal_authentication_errors(self) -> None:
        def failure_with(**fields: object) -> list[dict[str, object]]:
            return [
                copy.deepcopy(self.init_event),
                {
                    "type": "result",
                    "subtype": "error",
                    "is_error": True,
                    **fields,
                },
            ]

        authentication_messages = (
            "Login expired",
            "HTTP 401 Unauthorized",
            "HTTP/1.1 401 Unauthorized",
            "status 401",
            "status code: 401",
            "refresh token failed",
            "OAuth refresh failed",
            "token refresh failure",
            "credential refresh error",
            "authentication refresh invalid",
            "failed to refresh login token",
            "access token invalid",
            "unauthorized bearer token",
            "API key invalid",
        )
        for message in authentication_messages:
            with self.subTest(authentication_message=message):
                self.assert_fail_closed(
                    self._validate(failure_with(error=message)),
                    "blocked-authentication",
                )

        non_authentication_messages = (
            "401",
            "request 401 failed",
            "error code=401",
            "child exit code 401",
            "abc401",
            "1401",
            "HTTP 1401",
            "upstream request failed",
            "refresh failed",
            "cache refresh failed",
            "display refresh error",
            "Failed to count tokens",
            "token counting error",
            "token usage error",
            "token budget failure",
            "token limit error",
            "API key usage limit error",
            "API key rate limit error",
            "OAuth capacity error",
            "OAuth rate limit error",
            "authentication budget failure",
            "authentication quota failure",
            "error reading credentials file",
            "credential I/O error",
            "credentials file read error",
        )
        for message in non_authentication_messages:
            with self.subTest(non_authentication_message=message):
                self.assert_fail_closed(
                    self._validate(failure_with(error=message)), "inconclusive"
                )

        self.assert_fail_closed(
            self._validate(failure_with(api_error_status="401")),
            "blocked-authentication",
        )
        self.assert_fail_closed(
            self._validate(
                failure_with(errors=["HTTP 401 Unauthorized", "child exit code 1"])
            ),
            "inconclusive",
        )
        contradictory_success = self._full_events()
        contradictory_success[-1]["error"] = "HTTP 401"

        self.assert_fail_closed(self._validate(contradictory_success), "inconclusive")

    def test_nonzero_preserves_valid_structured_authentication_failures(self) -> None:
        authentication_messages = (
            "Login expired",
            "HTTP 401 Unauthorized",
            "OAuth error",
            "token expired",
            "credential invalid",
            "login unauthorized",
            "authentication failed",
            "auth error",
        )
        for process_returncode in (1, 401):
            for message in authentication_messages:
                with self.subTest(
                    process_returncode=process_returncode, message=message
                ):
                    events = [
                        copy.deepcopy(self.init_event),
                        {
                            "type": "result",
                            "subtype": "error",
                            "is_error": True,
                            "error": message,
                        },
                    ]
                    self.assertEqual(
                        self._validate(events, process_returncode=process_returncode),
                        {
                            "classification": "blocked-authentication",
                            "reasons": ["terminal.authentication-error"],
                        },
                    )

    def test_classifies_only_strict_model_fallback_denials(self) -> None:
        def failure_with(messages: list[str]) -> list[dict[str, object]]:
            return [
                copy.deepcopy(self.init_event),
                {
                    "type": "result",
                    "subtype": "error",
                    "is_error": True,
                    "errors": messages,
                },
            ]

        accepted = {
            "Model entitlement denied": "terminal.model-entitlement-denial",
            "Not entitled to use model": "terminal.model-entitlement-denial",
            "Model access is denied": "terminal.model-entitlement-denial",
            "Model is not available for your account": (
                "terminal.model-entitlement-denial"
            ),
            "Model is not available on your current plan": (
                "terminal.model-entitlement-denial"
            ),
            "You do not have access to this model": (
                "terminal.model-entitlement-denial"
            ),
            "model_not_enabled": "terminal.model-entitlement-denial",
            "Organization policy denied model": ("terminal.organization-policy-denial"),
            "Model is disallowed by organizational policy": (
                "terminal.organization-policy-denial"
            ),
        }
        for message, reason in accepted.items():
            with self.subTest(message=message):
                self.assertEqual(
                    self._validate(failure_with([message]), process_returncode=1),
                    {"classification": "blocked", "reasons": [reason]},
                )

        self.assertEqual(
            self._validate(
                failure_with(
                    [
                        "Model entitlement denied",
                        "Organization policy denied model",
                    ]
                )
            ),
            {
                "classification": "blocked",
                "reasons": [
                    "terminal.model-entitlement-denial",
                    "terminal.organization-policy-denial",
                ],
            },
        )
        for messages in (
            ["Model entitlement denied", "upstream request failed"],
            ["Organization policy denied model", "HTTP 401 Unauthorized"],
            ["Model entitlement denied because quota is exhausted"],
            ["Model entitlement denied because capacity is exhausted"],
            ["Model entitlement denied due to rate limit"],
            ["Model entitlement denied because authentication failed"],
            ["Organization policy denied model because usage is exhausted"],
            ["Model is not available for your account because quota is exhausted"],
            ["Policy error"],
            ["Model unavailable"],
        ):
            with self.subTest(mixed_or_ambiguous=messages):
                self.assert_fail_closed(
                    self._validate(failure_with(messages)), "inconclusive"
                )

    def test_non_success_preserves_deterministic_init_blockers(self) -> None:
        terminal = {
            "type": "result",
            "subtype": "error",
            "is_error": True,
        }
        cases = {
            "permission-mode": (
                {"permissionMode": "default"},
                ["init.permissionMode.mismatch"],
            ),
            "tool-set": (
                {"tools": ["Read", "Grep", "Glob", "Bash", "Write"]},
                ["init.tools.mismatch"],
            ),
        }
        for name, (init_update, reasons) in cases.items():
            with self.subTest(case=name):
                init = copy.deepcopy(self.init_event)
                init.update(init_update)
                self.assertEqual(
                    self._validate([init, copy.deepcopy(terminal)]),
                    {"classification": "blocked", "reasons": reasons},
                )

    def test_non_success_model_mismatch_is_blocked_without_unclassified_reason(
        self,
    ) -> None:
        events = [
            copy.deepcopy(self.init_event),
            {
                "type": "result",
                "subtype": "error",
                "is_error": True,
                "modelUsage": {"claude-opus-4-7": {}},
            },
        ]

        self.assertEqual(
            self._validate(events),
            {
                "classification": "blocked",
                "reasons": [
                    "terminal.modelUsage.primary-model-substitution",
                    "terminal.modelUsage.requested-model-missing",
                ],
            },
        )

    def test_cli_parser_and_surrogate_failures_emit_one_json_without_traceback(
        self,
    ) -> None:
        valid = self._full_events()
        init = self._raw([valid[0]])
        terminal = self._raw([valid[-1]])
        malformed_lines = {
            "oversized-integer": b'{"type":"assistant","value":' + b"1" * 5000 + b"}\n",
            "recursive-json": b'{"type":"assistant","value":'
            + b"[" * 200_000
            + b"0"
            + b"]" * 200_000
            + b"}\n",
            "unpaired-surrogate": b'{"type":"assistant","value":"\\ud800"}\n',
        }

        for name, malformed_line in malformed_lines.items():
            with self.subTest(name=name):
                input_path = self.cwd / f"{name}.jsonl"
                input_path.write_bytes(init + malformed_line + terminal)
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(VALIDATOR),
                        "--cwd",
                        str(self.cwd),
                        "--model",
                        "claude-opus-4-8",
                        "--preflight-result",
                        str(self.preflight_path),
                        "--api-key-source",
                        "none",
                        "--process-returncode",
                        "0",
                        "--input",
                        str(input_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                    env={**os.environ, "PYTHONINTMAXSTRDIGITS": "4300"},
                )

                self.assertEqual(completed.returncode, 3)
                self.assertEqual(completed.stderr, b"")
                stdout_lines = completed.stdout.decode("utf-8").splitlines()
                self.assertEqual(len(stdout_lines), 1)
                outcome = json.loads(stdout_lines[0])
                self.assertEqual(outcome["classification"], "inconclusive")
                self.assertEqual(len(outcome["reasons"]), 1)

    def test_cli_is_executable_and_emits_one_machine_readable_result(self) -> None:
        self.assertTrue(os.access(VALIDATOR, os.X_OK))
        input_path = self.cwd / "claude-stream.jsonl"
        input_path.write_bytes(self._raw(self._full_events()))

        completed = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
                "--input",
                str(input_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        stdout_lines = completed.stdout.decode("utf-8").splitlines()
        self.assertEqual(len(stdout_lines), 1)
        self.assertEqual(
            json.loads(stdout_lines[0]),
            {"classification": "accepted", "findings": "\nNo findings.\n"},
        )
        self.assertEqual(completed.stderr, b"")

    def test_cli_rejects_success_stdout_when_process_returncode_is_nonzero(
        self,
    ) -> None:
        input_path = self.cwd / "successful-stream-nonzero-process.jsonl"
        input_path.write_bytes(self._raw(self._full_events()))

        completed = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "401",
                "--input",
                str(input_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "classification": "inconclusive",
                "reasons": ["process.returncode.nonzero"],
            },
        )

    def test_cli_exit_zero_is_unique_to_accepted_output(self) -> None:
        blocked = self._full_events()
        blocked[0]["permissionMode"] = "default"
        authentication = [
            copy.deepcopy(self.init_event),
            {
                "type": "result",
                "subtype": "error",
                "is_error": True,
                "error": "HTTP 401 Unauthorized",
            },
        ]
        inconclusive = self._full_events()
        inconclusive[-1]["result"] = " "
        cases = {
            "blocked": (blocked, 1),
            "blocked-authentication": (authentication, 2),
            "inconclusive": (inconclusive, 3),
        }

        for expected_classification, (events, expected_returncode) in cases.items():
            with self.subTest(classification=expected_classification):
                input_path = self.cwd / f"{expected_classification}.jsonl"
                input_path.write_bytes(self._raw(events))
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(VALIDATOR),
                        "--cwd",
                        str(self.cwd),
                        "--model",
                        "claude-opus-4-8",
                        "--preflight-result",
                        str(self.preflight_path),
                        "--api-key-source",
                        "none",
                        "--process-returncode",
                        "0",
                        "--input",
                        str(input_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )

                self.assertEqual(completed.returncode, expected_returncode)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, b"")
                stdout_lines = completed.stdout.decode("utf-8").splitlines()
                self.assertEqual(len(stdout_lines), 1)
                self.assertEqual(
                    json.loads(stdout_lines[0])["classification"],
                    expected_classification,
                )

    def test_cli_argument_failures_emit_one_inconclusive_json_on_stdout(self) -> None:
        cases = {
            "short-help": ["-h"],
            "long-help": ["--help"],
            "missing-cwd": [
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
            ],
            "missing-process-returncode": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
            ],
            "invalid-process-returncode": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "not-an-integer",
            ],
            "invalid-choice": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-future",
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
            ],
            "unknown-option": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
                "--future-option",
            ],
        }

        for name, arguments in cases.items():
            with self.subTest(name=name):
                completed = subprocess.run(
                    [sys.executable, str(VALIDATOR), *arguments],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )

                self.assertEqual(completed.returncode, 3)
                self.assertEqual(completed.stderr, b"")
                stdout_lines = completed.stdout.decode("utf-8").splitlines()
                self.assertEqual(len(stdout_lines), 1)
                self.assertEqual(
                    json.loads(stdout_lines[0]),
                    {
                        "classification": "inconclusive",
                        "reasons": ["validator.arguments-invalid"],
                    },
                )

    def test_cli_integer_bound_applies_when_runtime_limit_is_disabled(self) -> None:
        valid = self._full_events()
        init = self._raw([valid[0]])
        terminal = self._raw([valid[-1]])
        oversized_integer = b'{"type":"assistant","value":' + b"1" * 5_000 + b"}\n"
        input_path = self.cwd / "explicit-integer-bound.jsonl"
        input_path.write_bytes(init + oversized_integer + terminal)

        completed = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
                "--input",
                str(input_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={**os.environ, "PYTHONINTMAXSTRDIGITS": "0"},
        )

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stderr, b"")
        stdout_lines = completed.stdout.decode("utf-8").splitlines()
        self.assertEqual(len(stdout_lines), 1)
        self.assertEqual(
            json.loads(stdout_lines[0]),
            {
                "classification": "inconclusive",
                "reasons": ["stream.invalid-json"],
            },
        )

    def test_cli_oversized_integer_total_cost_fails_closed_without_traceback(
        self,
    ) -> None:
        events = self._full_events()
        events[-1]["total_cost_usd"] = 10**400
        input_path = self.cwd / "huge-integer-total-cost.jsonl"
        input_path.write_bytes(self._raw(events))

        completed = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.preflight_path),
                "--api-key-source",
                "none",
                "--process-returncode",
                "0",
                "--input",
                str(input_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stderr, b"")
        stdout_lines = completed.stdout.decode("utf-8").splitlines()
        self.assertEqual(len(stdout_lines), 1)
        self.assertEqual(
            json.loads(stdout_lines[0]),
            {
                "classification": "inconclusive",
                "reasons": ["stream.invalid-json"],
            },
        )


if __name__ == "__main__":
    unittest.main()
