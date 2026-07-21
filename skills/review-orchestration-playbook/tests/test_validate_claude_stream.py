from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
VALIDATOR = SCRIPTS / "validate_claude_stream.py"
SCHEMA = SKILL_ROOT / "references/claude-2.1.212-stream-schema.json"
sys.path.insert(0, str(SCRIPTS))

import validate_claude_stream as validator  # noqa: E402


class ClaudeStreamValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.cwd = Path(temporary_directory.name).resolve()
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
            "session_id": "result-session",
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
        limits: validator.StreamLimits | None = None,
    ) -> dict[str, object]:
        if raw is None:
            raw = self._raw(events if events is not None else self._full_events())
        return validator.validate_claude_stream_bytes(
            raw,
            expected_cwd=self.cwd,
            requested_model=requested_model,
            api_key_source=api_key_source,
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

    def test_machine_schema_defines_complete_init_and_stream_bounds(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(schema["claude_code_version"], "2.1.212")
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
                "max_bytes": 8388608,
                "max_lines": 10000,
                "max_line_bytes": 1048576,
                "first_nonblank_event": {"type": "system", "subtype": "init"},
                "last_nonblank_event": {"type": "result"},
                "init_event_count": 1,
                "result_event_count": 1,
            },
        )
        init_contract = schema["init_event"]
        self.assertEqual(
            set(init_contract["required_fields"]), validator.INIT_REQUIRED_FIELDS
        )
        self.assertEqual(
            set(init_contract["field_contracts"]), validator.INIT_REQUIRED_FIELDS
        )
        self.assertTrue(init_contract["additional_fields"])
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

    def test_accepts_complete_stream_and_preserves_findings_verbatim(self) -> None:
        outcome = self._validate(raw=self._raw(self._full_events(), blank_edges=True))

        self.assertEqual(
            outcome,
            {"classification": "accepted", "findings": "\nNo findings.\n"},
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
        )
        self.assert_fail_closed(outcome, "inconclusive")

    def test_json_parser_exceptions_fail_closed(self) -> None:
        contract = validator._load_contract()
        parser_errors = (
            ValueError("integer conversion limit"),
            RecursionError("maximum recursion depth exceeded"),
            OverflowError("parser overflow"),
        )

        for error in parser_errors:
            with self.subTest(error=type(error).__name__):
                with (
                    mock.patch.object(
                        validator, "_load_contract", return_value=contract
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
        self.assert_fail_closed(self._validate(duplicate_tools), "blocked")

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
        }

        for field_name, value in malformed_values.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                self.assert_fail_closed(self._validate(events), "inconclusive")

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

    def test_rejects_nonfinite_and_oversized_integer_total_costs(self) -> None:
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

        nonfinite_raw = self._raw(self._full_events()).replace(
            b'"total_cost_usd":0.01', b'"total_cost_usd":1e400'
        )
        self.assertEqual(
            self._validate(raw=nonfinite_raw),
            {
                "classification": "inconclusive",
                "reasons": ["terminal.total_cost_usd.malformed"],
            },
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
            "error code=401",
            "refresh token failed",
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
            "abc401",
            "1401",
            "HTTP 1401",
            "upstream request failed",
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
        contradictory_success = self._full_events()
        contradictory_success[-1]["error"] = "HTTP 401"

        self.assert_fail_closed(self._validate(contradictory_success), "inconclusive")

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
                        "--api-key-source",
                        "none",
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
                "--api-key-source",
                "none",
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

    def test_cli_argument_failures_emit_one_inconclusive_json_on_stdout(self) -> None:
        cases = {
            "missing-required": ["--model", "claude-opus-4-8"],
            "invalid-choice": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-future",
                "--api-key-source",
                "none",
            ],
            "unknown-option": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--api-key-source",
                "none",
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
                "--api-key-source",
                "none",
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
                "--api-key-source",
                "none",
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
