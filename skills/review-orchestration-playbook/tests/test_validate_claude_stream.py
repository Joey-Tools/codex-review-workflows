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
SCHEMA = SKILL_ROOT / "references/claude-stream-schema.json"
sys.path.insert(0, str(SCRIPTS))

import validate_claude_stream as validator  # noqa: E402
from review_runtime import claude_provenance  # noqa: E402


class ClaudeStreamValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.cwd = Path(temporary_directory.name).resolve()
        self.claude_code_version = "2.1.216"
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
            "claude_code_version": self.claude_code_version,
            "apiKeySource": "none",
            "session_id": "init-session",
            "output_style": "default",
            "agents": ["claude", "Explore", "general-purpose", "Plan"],
            "capabilities": ["interrupt_receipt_v1", "msg_lifecycle_v1"],
            "analytics_disabled": True,
            "product_feedback_disabled": False,
            "uuid": "22222222-2222-4222-8222-222222222222",
            "fast_mode_state": "off",
        }
        self.progress_event = {
            "type": "assistant",
            "message": {
                "content": [{"type": "text", "text": "working"}],
                "context_management": None,
                "id": "msg-synthetic",
                "model": "claude-opus-4-8",
                "role": "assistant",
                "stop_details": None,
                "stop_reason": None,
                "stop_sequence": None,
                "type": "message",
                "usage": {},
            },
            "parent_tool_use_id": None,
            "request_id": "req-synthetic",
            "session_id": "init-session",
            "timestamp": "2026-01-01T00:00:00.000Z",
            "uuid": "33333333-3333-4333-8333-333333333333",
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
            "fast_mode_state": "off",
            "terminal_reason": "completed",
            "time_to_request_ms": 1,
            "ttft_ms": 2,
            "ttft_stream_ms": 3,
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

    def _assistant_event(self, block: dict[str, object]) -> dict[str, object]:
        event = copy.deepcopy(self.progress_event)
        message = event["message"]
        assert isinstance(message, dict)
        message["content"] = [block]
        return event

    def _reviewed_intermediate_events(self) -> list[dict[str, object]]:
        return [
            {
                "type": "system",
                "subtype": "thinking_tokens",
                "estimated_tokens": 7,
                "estimated_tokens_delta": 2,
                "session_id": "init-session",
                "uuid": "44444444-4444-4444-8444-444444444444",
            },
            self._assistant_event(
                {
                    "type": "thinking",
                    "signature": "synthetic-signature",
                    "thinking": "synthetic thought",
                }
            ),
            self._assistant_event({"type": "text", "text": "working"}),
            self._assistant_event(
                {
                    "type": "tool_use",
                    "caller": {"type": "direct"},
                    "id": "toolu-synthetic",
                    "input": {"file_path": "/synthetic/review.py"},
                    "name": "Read",
                }
            ),
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "content": "synthetic tool output",
                            "tool_use_id": "toolu-synthetic",
                            "is_error": False,
                        }
                    ],
                    "role": "user",
                },
                "parent_tool_use_id": None,
                "session_id": "init-session",
                "timestamp": "2026-01-01T00:00:01.000Z",
                "tool_use_result": {"status": "synthetic"},
                "uuid": "55555555-5555-4555-8555-555555555555",
            },
            {
                "type": "rate_limit_event",
                "rate_limit_info": {
                    "status": "allowed",
                    "resetsAt": 10,
                    "rateLimitType": "synthetic-window",
                    "overageStatus": "allowed",
                    "overageResetsAt": 20,
                    "isUsingOverage": False,
                    "overageInUse": False,
                },
                "session_id": "init-session",
                "uuid": "66666666-6666-4666-8666-666666666666",
            },
        ]

    def _legacy_events(self, version: str = "2.1.211") -> list[dict[str, object]]:
        events = self._full_events()
        events[0]["claude_code_version"] = version
        for field_name in validator.EXTENDED_INIT_REQUIRED_FIELDS:
            del events[0][field_name]
        for field_name in validator.EXTENDED_TERMINAL_FIELDS:
            del events[-1][field_name]
        return events

    def _validate(
        self,
        events: list[object] | None = None,
        *,
        raw: bytes | None = None,
        requested_model: str = "claude-opus-4-8",
        claude_code_version: str | None = None,
        authentication_source: str = "local-login",
        process_returncode: object = 0,
        limits: validator.StreamLimits | None = None,
    ) -> dict[str, object]:
        if raw is None:
            raw = self._raw(events if events is not None else self._full_events())
        return validator.validate_claude_stream_bytes(
            raw,
            expected_cwd=self.cwd,
            requested_model=requested_model,
            claude_code_version=(
                self.claude_code_version
                if claude_code_version is None
                else claude_code_version
            ),
            authentication_source=authentication_source,
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

    def test_machine_schema_defines_complete_init_and_stream_bounds(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            schema["claude_code_version"],
            validator.CLAUDE_CODE_VERSION_CONTRACT,
        )
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
        self.assertEqual(init_contract["profiles"], validator.INIT_PROFILE_CONTRACT)
        self.assertEqual(
            schema["intermediate_events"],
            validator.INTERMEDIATE_EVENT_CONTRACT,
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
                "subtype": {
                    "rule": "profile_enum",
                    "profile_field": "failure_subtypes",
                },
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
        self.assertEqual(
            terminal_contract["profiles"], validator.TERMINAL_PROFILE_CONTRACT
        )
        for profile_name, failure_subtypes in terminal_contract["profiles"][
            "variants"
        ].items():
            with self.subTest(profile=profile_name):
                self.assertEqual(failure_subtypes["failure_subtypes"], ["error"])

    def test_version_range_matches_provenance_preflight_and_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            validator.CLAUDE_CODE_MINIMUM_VERSION,
            claude_provenance.CLAUDE_MINIMUM_RELEASE,
        )
        self.assertEqual(
            validator.CLAUDE_CODE_MAXIMUM_VERSION,
            claude_provenance.CLAUDE_MAXIMUM_RELEASE,
        )
        self.assertEqual(
            schema["claude_code_version"],
            validator.CLAUDE_CODE_VERSION_CONTRACT,
        )

    def test_loader_accepts_current_contract_and_rejects_profile_drift(self) -> None:
        self.assertEqual(
            validator._load_contract()["init_event"]["profiles"],
            validator.INIT_PROFILE_CONTRACT,
        )

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema["init_event"]["profiles"]["variants"]["extended-2x"]["field_contracts"][
            "fast_mode_state"
        ]["value"] = "on"
        schema_path = self.cwd / "invalid-profile-schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")

        with (
            mock.patch.object(validator, "SCHEMA_PATH", schema_path),
            self.assertRaises(validator._ContractError),
        ):
            validator._load_contract()

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema["terminal_result"]["profiles"]["variants"]["legacy-base"][
            "failure_subtypes"
        ].append("future_error")
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with (
            mock.patch.object(validator, "SCHEMA_PATH", schema_path),
            self.assertRaises(validator._ContractError),
        ):
            validator._load_contract()

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema["intermediate_events"]["profiles"]["legacy-base"]["event_contract"] = (
            "unknown"
        )
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with (
            mock.patch.object(validator, "SCHEMA_PATH", schema_path),
            self.assertRaises(validator._ContractError),
        ):
            validator._load_contract()

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema["terminal_result"]["profiles"]["variants"]["extended-2x"]["success"][
            "field_contracts"
        ]["terminal_reason"]["value"] = "future"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with (
            mock.patch.object(validator, "SCHEMA_PATH", schema_path),
            self.assertRaises(validator._ContractError),
        ):
            validator._load_contract()

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

    def test_accepts_complete_stream_and_preserves_findings_verbatim(self) -> None:
        outcome = self._validate(raw=self._raw(self._full_events(), blank_edges=True))

        self.assertEqual(
            outcome,
            {"classification": "accepted", "findings": "\nNo findings.\n"},
        )

    def test_accepts_all_reviewed_intermediate_shapes_for_supported_2x(self) -> None:
        for version in ("2.1.211", "2.1.216", "2.9.999"):
            with self.subTest(version=version):
                if version < "2.1.216":
                    init, _, result = self._legacy_events(version)
                else:
                    init = copy.deepcopy(self.init_event)
                    init["claude_code_version"] = version
                    result = copy.deepcopy(self.result_event)
                events = [
                    init,
                    *copy.deepcopy(self._reviewed_intermediate_events()),
                    result,
                ]
                self.assertEqual(
                    self._validate(events, claude_code_version=version),
                    {"classification": "accepted", "findings": "\nNo findings.\n"},
                )

    def test_accepts_each_reviewed_tool_and_tool_result_representation(self) -> None:
        for tool_name in validator.EXPECTED_TOOLS:
            with self.subTest(tool_name=tool_name):
                tool_event = self._assistant_event(
                    {
                        "type": "tool_use",
                        "caller": {"type": "direct"},
                        "id": "toolu-synthetic",
                        "input": {},
                        "name": tool_name,
                    }
                )
                events = [
                    copy.deepcopy(self.init_event),
                    tool_event,
                    copy.deepcopy(self.result_event),
                ]
                self.assertEqual(self._validate(events)["classification"], "accepted")

        user_event = copy.deepcopy(self._reviewed_intermediate_events()[-2])
        user_event["tool_use_result"] = "synthetic tool output"
        message = user_event["message"]
        assert isinstance(message, dict)
        content = message["content"]
        assert isinstance(content, list)
        del content[0]["is_error"]
        self.assertEqual(
            self._validate(
                [
                    copy.deepcopy(self.init_event),
                    user_event,
                    copy.deepcopy(self.result_event),
                ]
            )["classification"],
            "accepted",
        )

    def test_accepts_legacy_and_floating_extended_release_profiles(self) -> None:
        cases = {
            "legacy-minimum": ("2.1.211", self._legacy_events()),
            "legacy-2.1.212": ("2.1.212", self._legacy_events()),
            "legacy-upper-bound": ("2.1.215", self._legacy_events()),
            "extended-current": ("2.1.216", self._full_events()),
            "extended-future-2x": ("2.9.999", self._full_events()),
        }

        for name, (version, events) in cases.items():
            with self.subTest(name=name):
                events[0]["claude_code_version"] = version
                self.assertEqual(
                    self._validate(events, claude_code_version=version)[
                        "classification"
                    ],
                    "accepted",
                )

    def test_rejects_out_of_range_and_nonrelease_version_arguments(self) -> None:
        for version in ("2.1.210", "3.0.0", "2.1.216-beta.1", "v2.1.216"):
            with self.subTest(version=version):
                self.assertEqual(
                    self._validate(claude_code_version=version),
                    {
                        "classification": "inconclusive",
                        "reasons": ["validator.claude-code-version-invalid"],
                    },
                )

    def test_accepts_init_without_optional_session_id(self) -> None:
        events = self._full_events()
        del events[0]["session_id"]
        del events[1]

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

    def test_rejects_unknown_policy_and_error_intermediate_events(self) -> None:
        unknown_events = {
            "policy-subtype": {
                "type": "system",
                "subtype": "policy",
                "session_id": "init-session",
            },
            "error-type": {
                "type": "error",
                "error": "synthetic error",
                "session_id": "init-session",
            },
        }
        for name, intermediate in unknown_events.items():
            with self.subTest(name=name):
                events = [
                    copy.deepcopy(self.init_event),
                    intermediate,
                    copy.deepcopy(self.result_event),
                ]
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_rejects_unknown_intermediate_fields_sessions_and_tools(self) -> None:
        extra_top_level = copy.deepcopy(self.progress_event)
        extra_top_level["permissionMode"] = "dontAsk"
        extra_nested = copy.deepcopy(self.progress_event)
        message = extra_nested["message"]
        assert isinstance(message, dict)
        message["future_security_context"] = {"allow": True}
        unknown_tool = self._assistant_event(
            {
                "type": "tool_use",
                "caller": {"type": "direct"},
                "id": "toolu-synthetic",
                "input": {},
                "name": "Write",
            }
        )
        cases = {
            "extra-top-level": extra_top_level,
            "extra-nested": extra_nested,
            "unknown-tool": unknown_tool,
        }
        for name, intermediate in cases.items():
            with self.subTest(name=name):
                events = [
                    copy.deepcopy(self.init_event),
                    intermediate,
                    copy.deepcopy(self.result_event),
                ]
                self.assert_fail_closed(self._validate(events), "inconclusive")

        for intermediate in self._reviewed_intermediate_events():
            with self.subTest(session_event_type=intermediate["type"]):
                intermediate["session_id"] = "different-session"
                events = [
                    copy.deepcopy(self.init_event),
                    intermediate,
                    copy.deepcopy(self.result_event),
                ]
                self.assertEqual(
                    self._validate(events),
                    {
                        "classification": "inconclusive",
                        "reasons": ["stream.session_id.mismatch"],
                    },
                )

        unbound = self._full_events()
        del unbound[0]["session_id"]
        self.assertEqual(
            self._validate(unbound),
            {
                "classification": "inconclusive",
                "reasons": ["stream.session_id.unbound"],
            },
        )

    def test_rejects_malformed_intermediate_nested_shapes(self) -> None:
        cases: dict[str, dict[str, object]] = {}
        assistant_usage = copy.deepcopy(self.progress_event)
        message = assistant_usage["message"]
        assert isinstance(message, dict)
        message["usage"] = []
        cases["assistant-usage"] = assistant_usage

        user_content = copy.deepcopy(self._reviewed_intermediate_events()[-2])
        user_message = user_content["message"]
        assert isinstance(user_message, dict)
        user_message["content"] = []
        cases["user-content"] = user_content

        rate_info = copy.deepcopy(self._reviewed_intermediate_events()[-1])
        info = rate_info["rate_limit_info"]
        assert isinstance(info, dict)
        info["resetsAt"] = True
        cases["rate-limit-timestamp"] = rate_info

        thinking_tokens = copy.deepcopy(self._reviewed_intermediate_events()[0])
        thinking_tokens["estimated_tokens_delta"] = -1
        cases["thinking-token-count"] = thinking_tokens

        for name, intermediate in cases.items():
            with self.subTest(name=name):
                self.assert_fail_closed(
                    self._validate(
                        [
                            copy.deepcopy(self.init_event),
                            intermediate,
                            copy.deepcopy(self.result_event),
                        ]
                    ),
                    "inconclusive",
                )

    def test_accepts_closed_allowed_warning_rate_limit_variant(self) -> None:
        warning = copy.deepcopy(self._reviewed_intermediate_events()[-1])
        info = warning["rate_limit_info"]
        assert isinstance(info, dict)
        info.update(
            {
                "status": "allowed_warning",
                "utilization": 0.75,
                "surpassedThreshold": 0.75,
            }
        )
        del info["overageStatus"]
        del info["overageResetsAt"]

        outcome = self._validate(
            [
                copy.deepcopy(self.init_event),
                warning,
                copy.deepcopy(self.result_event),
            ]
        )

        self.assertEqual(
            outcome,
            {"classification": "accepted", "findings": "\nNo findings.\n"},
        )

    def test_rejects_nonclosed_rate_limit_variants(self) -> None:
        allowed = copy.deepcopy(self._reviewed_intermediate_events()[-1])
        allowed_info = allowed["rate_limit_info"]
        assert isinstance(allowed_info, dict)
        del allowed_info["overageStatus"]

        warning = copy.deepcopy(self._reviewed_intermediate_events()[-1])
        warning_info = warning["rate_limit_info"]
        assert isinstance(warning_info, dict)
        warning_info.update(
            {
                "status": "allowed_warning",
                "utilization": 1.1,
                "surpassedThreshold": 0.75,
            }
        )
        del warning_info["overageStatus"]
        del warning_info["overageResetsAt"]

        unknown = copy.deepcopy(self._reviewed_intermediate_events()[-1])
        unknown_info = unknown["rate_limit_info"]
        assert isinstance(unknown_info, dict)
        unknown_info["status"] = "future_status"

        for label, event, reason in (
            (
                "allowed missing field",
                allowed,
                "intermediate.rate-limit-event.rate_limit_info.overageStatus.missing",
            ),
            (
                "warning invalid ratio",
                warning,
                "intermediate.rate-limit-event.rate_limit_info.utilization.malformed",
            ),
            (
                "unknown status",
                unknown,
                "intermediate.rate-limit-event.rate_limit_info.status.unrecognized",
            ),
        ):
            with self.subTest(label=label):
                outcome = self._validate(
                    [
                        copy.deepcopy(self.init_event),
                        event,
                        copy.deepcopy(self.result_event),
                    ]
                )
                self.assert_fail_closed(outcome, "inconclusive")
                self.assertIn(reason, outcome["reasons"])

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
                claude_code_version=self.claude_code_version,
                authentication_source="local-login",
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

    def test_authentication_source_maps_to_exact_init_api_key_source(self) -> None:
        cases = {
            "api-key": "ANTHROPIC_API_KEY",
            "oauth-token": "none",
            "local-login": "none",
        }

        for authentication_source, init_api_key_source in cases.items():
            with self.subTest(authentication_source=authentication_source):
                events = self._full_events()
                events[0]["apiKeySource"] = init_api_key_source
                self.assertEqual(
                    self._validate(
                        events,
                        authentication_source=authentication_source,
                    )["classification"],
                    "accepted",
                )

    def test_authentication_source_rejects_init_mapping_mismatch(self) -> None:
        cases = {
            "api-key": "none",
            "oauth-token": "ANTHROPIC_API_KEY",
            "local-login": "ANTHROPIC_API_KEY",
        }

        for authentication_source, init_api_key_source in cases.items():
            with self.subTest(authentication_source=authentication_source):
                events = self._full_events()
                events[0]["apiKeySource"] = init_api_key_source
                outcome = self._validate(
                    events,
                    authentication_source=authentication_source,
                )

                self.assertEqual(outcome["classification"], "blocked")
                self.assertEqual(outcome["reasons"], ["init.apiKeySource.mismatch"])

    def test_rejects_unknown_authentication_source_argument(self) -> None:
        self.assertEqual(
            self._validate(authentication_source="none"),
            {
                "classification": "inconclusive",
                "reasons": ["validator.authentication-source-invalid"],
            },
        )

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
            claude_code_version=self.claude_code_version,
            authentication_source="local-login",
            process_returncode=0,
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
        progress = self._raw([self.progress_event])
        accepted_progress = progress.replace(
            b'"usage":{}',
            b'"usage":{"synthetic":' + b"1" * validator.MAX_JSON_INTEGER_DIGITS + b"}",
        )
        rejected_progress = progress.replace(
            b'"usage":{}',
            b'"usage":{"synthetic":'
            + b"1" * (validator.MAX_JSON_INTEGER_DIGITS + 1)
            + b"}",
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
            "output_style": 1,
            "agents": {"claude": True},
            "capabilities": ["interrupt_receipt_v1", 2],
            "analytics_disabled": 1,
            "product_feedback_disabled": "false",
            "uuid": " ",
            "fast_mode_state": ["off"],
        }

        for field_name, value in malformed_values.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_rejects_hooks_and_arbitrary_unknown_init_fields(self) -> None:
        unknown_fields = {
            "hooks": [{"matcher": "Bash"}],
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

    def test_extended_profile_requires_every_field(self) -> None:
        for field_name in validator.EXTENDED_INIT_REQUIRED_FIELDS:
            with self.subTest(field=field_name):
                events = self._full_events()
                del events[0][field_name]

                self.assertEqual(
                    self._validate(events),
                    {
                        "classification": "inconclusive",
                        "reasons": [f"init.{field_name}.missing"],
                    },
                )

    def test_extended_profile_rejects_value_and_order_drift_as_inconclusive(
        self,
    ) -> None:
        mismatch_values = {
            "output_style": "compact",
            "agents": ["Explore", "claude", "general-purpose", "Plan"],
            "capabilities": ["msg_lifecycle_v1", "interrupt_receipt_v1"],
            "analytics_disabled": False,
            "fast_mode_state": "on",
        }

        for field_name, value in mismatch_values.items():
            with self.subTest(field=field_name):
                events = self._full_events()
                events[0][field_name] = value
                outcome = self._validate(events)

                self.assertEqual(outcome["classification"], "inconclusive")
                self.assertIn(f"init.{field_name}.mismatch", outcome["reasons"])
                self.assertNotIn("findings", outcome)

    def test_extended_profile_accepts_either_feedback_boolean(self) -> None:
        events = self._full_events()
        events[0]["product_feedback_disabled"] = True

        self.assertEqual(self._validate(events)["classification"], "accepted")

    def test_legacy_profile_rejects_extended_shape(self) -> None:
        events = self._full_events()
        events[0]["claude_code_version"] = "2.1.215"

        self.assertEqual(
            self._validate(events, claude_code_version="2.1.215"),
            {
                "classification": "inconclusive",
                "reasons": ["init.unknown-field", "terminal.unknown-field"],
            },
        )

    def test_extended_success_requires_every_terminal_profile_field(self) -> None:
        for field_name in validator.EXTENDED_TERMINAL_FIELDS:
            with self.subTest(field=field_name):
                events = self._full_events()
                del events[-1][field_name]
                self.assertEqual(
                    self._validate(events),
                    {
                        "classification": "inconclusive",
                        "reasons": [f"terminal.{field_name}.missing"],
                    },
                )

    def test_extended_terminal_profile_rejects_malformed_and_value_drift(
        self,
    ) -> None:
        malformed_values = {
            "fast_mode_state": None,
            "terminal_reason": [],
            "time_to_request_ms": True,
            "ttft_ms": -1,
            "ttft_stream_ms": "3",
        }
        drift_values = {
            "fast_mode_state": "on",
            "terminal_reason": "api_error",
        }
        for field_name, value in {**malformed_values, **drift_values}.items():
            with self.subTest(field=field_name, value=value):
                events = self._full_events()
                events[-1][field_name] = value
                self.assert_fail_closed(self._validate(events), "inconclusive")

    def test_extended_failure_strictly_validates_optional_terminal_profile_fields(
        self,
    ) -> None:
        terminal = {
            "type": "result",
            "subtype": "error",
            "is_error": True,
            "error": "HTTP 401 Unauthorized",
            "fast_mode_state": "off",
            "terminal_reason": "api_error",
            "time_to_request_ms": 0,
            "ttft_ms": 1,
            "ttft_stream_ms": 2,
        }
        events = [copy.deepcopy(self.init_event), terminal]
        self.assertEqual(
            self._validate(events),
            {
                "classification": "blocked-authentication",
                "reasons": ["terminal.authentication-error"],
            },
        )

        malformed = copy.deepcopy(events)
        malformed[-1]["terminal_reason"] = "unknown"
        self.assert_fail_closed(self._validate(malformed), "inconclusive")

    def test_failure_subtype_is_closed_for_every_version_profile(self) -> None:
        cases = (
            ("legacy-base", "2.1.215", self._legacy_events("2.1.215")),
            ("extended-2x", "2.1.216", self._full_events()),
        )
        for profile_name, version, events in cases:
            with self.subTest(profile=profile_name, subtype="error"):
                known_failure = copy.deepcopy(events)
                known_failure[-1].update(
                    {
                        "subtype": "error",
                        "is_error": True,
                        "error": "HTTP 401 Unauthorized",
                    }
                )
                self.assertEqual(
                    self._validate(
                        known_failure,
                        claude_code_version=version,
                    ),
                    {
                        "classification": "blocked-authentication",
                        "reasons": ["terminal.authentication-error"],
                    },
                )

            with self.subTest(profile=profile_name, subtype="future_error"):
                unknown_failure = copy.deepcopy(events)
                unknown_failure[-1].update(
                    {
                        "subtype": "future_error",
                        "is_error": True,
                        "error": "HTTP 401 Unauthorized",
                    }
                )
                outcome = self._validate(
                    unknown_failure,
                    claude_code_version=version,
                )
                self.assert_fail_closed(outcome, "inconclusive")
                self.assertIn("terminal.subtype.unrecognized", outcome["reasons"])
                self.assertNotIn("terminal.authentication-error", outcome["reasons"])

    def test_legacy_terminal_forbids_extended_profile_fields(self) -> None:
        for field_name, value in {
            "fast_mode_state": "off",
            "terminal_reason": "completed",
            "time_to_request_ms": 0,
            "ttft_ms": 0,
            "ttft_stream_ms": 0,
        }.items():
            with self.subTest(field=field_name):
                events = self._legacy_events("2.1.215")
                events[-1][field_name] = value
                self.assertEqual(
                    self._validate(events, claude_code_version="2.1.215"),
                    {
                        "classification": "inconclusive",
                        "reasons": ["terminal.unknown-field"],
                    },
                )

    def test_rejects_well_formed_init_mismatches_as_blocked(self) -> None:
        mismatch_values = {
            "cwd": str(self.cwd / "other"),
            "permissionMode": "default",
            "tools": ["Read", "Grep", "Glob", "Bash", "Task"],
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
                        "--claude-code-version",
                        self.claude_code_version,
                        "--authentication-source",
                        "local-login",
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
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
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
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
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
                        "--claude-code-version",
                        self.claude_code_version,
                        "--authentication-source",
                        "local-login",
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
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
            ],
            "missing-claude-code-version": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
            ],
            "missing-process-returncode": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
            ],
            "invalid-process-returncode": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "not-an-integer",
            ],
            "invalid-choice": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-future",
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
            ],
            "version-below-range": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--claude-code-version",
                "2.1.210",
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
            ],
            "version-at-upper-bound": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--claude-code-version",
                "3.0.0",
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
            ],
            "unknown-option": [
                "--cwd",
                str(self.cwd),
                "--model",
                "claude-opus-4-8",
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
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
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
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
                "--claude-code-version",
                self.claude_code_version,
                "--authentication-source",
                "local-login",
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
