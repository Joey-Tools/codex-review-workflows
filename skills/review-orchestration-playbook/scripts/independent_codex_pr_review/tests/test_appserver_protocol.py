from __future__ import annotations

import copy
import unittest
from unittest import mock

from review_supervisor.appserver_protocol import (
    AppServerProtocol,
    AppServerProtocolError,
    AppServerRemoteError,
    AppServerSessionConfig,
    ExternalChatGPTAuth,
    ModelFallbackAuthorization,
    decode_json_line,
    encode_json_line,
    validate_prelaunch_turn_start_record,
)
from review_supervisor.constants import (
    APP_SERVER_CLI_VERSION,
    APP_SERVER_CLIENT_NAME,
    APP_SERVER_MAX_RECORD_BYTES,
    APP_SERVER_SESSION_SOURCE,
    MODEL,
)


NEUTRAL_CWD = "/private/supervisor-neutral"
CODEX_HOME = "/private/codex-home"
NO_EXECUTION_FEATURES = frozenset(
    {
        "apps",
        "artifact",
        "auth_elicitation",
        "browser_use",
        "browser_use_external",
        "browser_use_full_cdp_access",
        "code_mode",
        "code_mode_host",
        "code_mode_only",
        "computer_use",
        "default_mode_request_user_input",
        "deferred_executor",
        "enable_fanout",
        "enable_mcp_apps",
        "exec_permission_approvals",
        "external_agent_memory_import",
        "goals",
        "guardian_approval",
        "hooks",
        "image_generation",
        "in_app_browser",
        "memories",
        "mentions_v2",
        "multi_agent",
        "multi_agent_v2",
        "network_proxy",
        "plugin_sharing",
        "plugins",
        "realtime_conversation",
        "remote_control",
        "remote_plugin",
        "request_permissions_tool",
        "secret_auth_storage",
        "shell_snapshot",
        "shell_tool",
        "shell_zsh_fork",
        "skill_mcp_dependency_install",
        "skill_search",
        "standalone_web_search",
        "tool_call_mcp_elicitation",
        "tool_suggest",
        "unified_exec",
        "unified_exec_zsh_fork",
        "use_agent_identity",
        "workspace_dependencies",
    }
)


def synthetic_external_access_token() -> str:
    return ".".join(("header", "payload", "signature"))


def initialize_result() -> dict[str, object]:
    return {
        "codexHome": "/private/codex-home",
        "platformFamily": "unix",
        "platformOs": "macos",
        "userAgent": f"codex/{APP_SERVER_CLI_VERSION}",
    }


def no_execution_config() -> dict[str, object]:
    return {
        "agents": {"enabled": False},
        "allow_login_shell": False,
        "analytics": {"enabled": False},
        "apps": {
            "_default": {
                "approvals_reviewer": "user",
                "default_tools_approval_mode": "prompt",
                "destructive_enabled": False,
                "enabled": False,
                "open_world_enabled": False,
            }
        },
        "check_for_update_on_startup": False,
        "developer_instructions": "",
        "experimental_use_unified_exec_tool": False,
        "features": {name: False for name in sorted(NO_EXECUTION_FEATURES)},
        "history": {"persistence": "none"},
        "hooks": {},
        "include_apps_instructions": False,
        "include_collaboration_mode_instructions": False,
        "include_environment_context": False,
        "include_permissions_instructions": False,
        "instructions": "",
        "marketplaces": {},
        "mcp_servers": {},
        "notify": [],
        "plugins": {},
        "project_doc_fallback_filenames": [],
        "project_doc_max_bytes": 0,
        "shell_environment_policy": {"inherit": "none"},
        "skills": {},
        "tools": {},
        "web_search": "disabled",
    }


def config_origin_keys(
    value: dict[str, object],
    *,
    prefix: tuple[str, ...] = (),
) -> set[str]:
    result: set[str] = set()
    for key, child in value.items():
        path = (*prefix, key)
        if isinstance(child, dict):
            result.update(config_origin_keys(child, prefix=path))
        elif isinstance(child, list) and not child:
            continue
        else:
            result.add(".".join(path))
    return result


def safe_config_result() -> dict[str, object]:
    config = no_execution_config()
    metadata = {"name": {"type": "sessionFlags"}, "version": "1"}
    return {
        "config": copy.deepcopy(config),
        "layers": [
            {
                "config": copy.deepcopy(config),
                "name": {"type": "sessionFlags"},
                "version": "1",
            },
            {
                "config": {},
                "name": {
                    "file": f"{CODEX_HOME}/config.toml",
                    "profile": None,
                    "type": "user",
                },
                "version": "1",
            },
            {
                "config": {},
                "name": {
                    "file": "/Library/Application Support/OpenAI/Codex/config.toml",
                    "type": "system",
                },
                "version": "1",
            },
        ],
        "origins": {key: copy.deepcopy(metadata) for key in config_origin_keys(config)},
    }


def thread_value(
    config: AppServerSessionConfig,
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "cliVersion": config.expected_cli_version,
        "createdAt": 100,
        "cwd": config.neutral_cwd,
        "ephemeral": True,
        "id": "thread-1",
        "modelProvider": config.expected_model_provider,
        "path": None,
        "preview": "review",
        "sessionId": "session-1",
        "source": APP_SERVER_SESSION_SOURCE,
        "status": {"type": "idle"},
        "turns": [],
        "updatedAt": 100,
        "threadSource": APP_SERVER_CLIENT_NAME,
    }
    value.update(overrides)
    return value


def thread_start_result(
    config: AppServerSessionConfig,
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "cwd": config.neutral_cwd,
        "instructionSources": [],
        "model": config.expected_model,
        "modelProvider": config.expected_model_provider,
        "reasoningEffort": config.expected_reasoning_effort,
        "runtimeWorkspaceRoots": [],
        "sandbox": {"networkAccess": False, "type": "readOnly"},
        "thread": thread_value(config),
    }
    value.update(overrides)
    return value


def in_progress_turn() -> dict[str, object]:
    return {
        "id": "turn-1",
        "items": [],
        "itemsView": "notLoaded",
        "status": "inProgress",
    }


def final_item(text: str = "No findings.") -> dict[str, object]:
    return {
        "id": "item-1",
        "phase": "final_answer",
        "text": text,
        "type": "agentMessage",
    }


def user_message(text: str = "review evidence") -> dict[str, object]:
    return {
        "clientId": None,
        "content": [{"text": text, "text_elements": [], "type": "text"}],
        "id": "user-message-1",
        "type": "userMessage",
    }


def reasoning_item(
    *,
    content: list[str] | None = None,
    summary: list[str] | None = None,
) -> dict[str, object]:
    return {
        "content": content or [],
        "id": "reasoning-1",
        "summary": summary or [],
        "type": "reasoning",
    }


def advance_to_thread_request(
    protocol: AppServerProtocol,
    *,
    config_result: dict[str, object] | None = None,
    hooks: list[object] | None = None,
) -> dict[str, object]:
    initialize = protocol.start()[0]
    assert initialize["method"] == "initialize"
    after_initialize = protocol.accept_message(
        {"id": initialize["id"], "result": initialize_result()}
    )
    assert after_initialize[0] == {"method": "initialized"}
    config_request = after_initialize[1]
    hooks_request = protocol.accept_message(
        {
            "id": config_request["id"],
            "result": config_result
            if config_result is not None
            else safe_config_result(),
        }
    )[0]
    hook_sets = (
        hooks
        if hooks is not None
        else [{"cwd": NEUTRAL_CWD, "errors": [], "hooks": [], "warnings": []}]
    )
    return protocol.accept_message(
        {"id": hooks_request["id"], "result": {"data": hook_sets}}
    )[0]


def advance_to_running(
    protocol: AppServerProtocol,
    config: AppServerSessionConfig,
) -> None:
    thread_request = advance_to_thread_request(protocol)
    thread_result = thread_start_result(config)
    self_notification = {
        "method": "thread/started",
        "params": {"thread": thread_result["thread"]},
    }
    assert protocol.accept_message(self_notification) == ()
    turn_request = protocol.accept_message(
        {"id": thread_request["id"], "result": thread_result}
    )[0]
    turn = in_progress_turn()
    assert (
        protocol.accept_message({"id": turn_request["id"], "result": {"turn": turn}})
        == ()
    )
    assert (
        protocol.accept_message(
            {
                "method": "turn/started",
                "params": {"threadId": "thread-1", "turn": turn},
            }
        )
        == ()
    )


def complete(
    protocol: AppServerProtocol,
    item: dict[str, object] | None = None,
    *,
    start_item: bool = True,
    prior_items: tuple[dict[str, object], ...] = (),
    terminal_items: tuple[dict[str, object], ...] | None = None,
    terminal_items_view: str | None = None,
) -> None:
    item = item or final_item()
    if start_item:
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": item,
                    "startedAtMs": 999,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
    protocol.accept_message(
        {
            "method": "item/completed",
            "params": {
                "completedAtMs": 1000,
                "item": item,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        }
    )
    turn: dict[str, object] = {
        "id": "turn-1",
        "items": (
            [*prior_items, item] if terminal_items is None else list(terminal_items)
        ),
        "status": "completed",
    }
    if terminal_items_view is not None:
        turn["itemsView"] = terminal_items_view
    protocol.accept_message(
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turn": turn,
            },
        }
    )


class JsonLineTests(unittest.TestCase):
    def test_round_trip_has_no_jsonrpc_field(self) -> None:
        encoded = encode_json_line({"id": 1, "method": "initialize", "params": {}})
        self.assertEqual(
            decode_json_line(encoded),
            {"id": 1, "method": "initialize", "params": {}},
        )
        self.assertNotIn(b"jsonrpc", encoded)

    def test_rejects_duplicate_keys_size_depth_and_noncanonical_framing(self) -> None:
        rejected = (
            b'{"id":1,"id":2}\n',
            b'{"id":1}\r\n',
            b' {"id":1}\n',
            b'{"id":1}',
            b"[]\n",
            b'{"value":NaN}\n',
            b'{"value":"\\ud800"}\n',
        )
        for record in rejected:
            with self.subTest(record=record), self.assertRaises(AppServerProtocolError):
                decode_json_line(record)
        with self.assertRaises(AppServerProtocolError):
            decode_json_line(b'{"long":true}\n', max_bytes=4)
        nested: object = None
        for _ in range(40):
            nested = [nested]
        with self.assertRaises(AppServerProtocolError):
            decode_json_line(encode_json_line({"nested": nested}))
        with (
            mock.patch(
                "review_supervisor.appserver_protocol.json.loads",
                side_effect=RecursionError,
            ),
            self.assertRaises(AppServerProtocolError) as raised,
        ):
            decode_json_line(b'{"nested":[]}\n')
        self.assertEqual(raised.exception.code, "json-depth")

    def test_rejects_oversized_integer_before_python_digit_conversion(self) -> None:
        record = b'{"id":' + (b"9" * 5000) + b"}\n"
        with self.assertRaises(AppServerProtocolError) as raised:
            decode_json_line(record)
        self.assertEqual(raised.exception.code, "invalid-json-number")

    def test_rejects_every_float_token_before_conversion(self) -> None:
        tokens = (
            b"0.0",
            b"-0.0",
            b"1.7976931348623157e308",
            b"2.2250738585072014e-308",
            b"5e-324",
            b"1e-324",
            b"1e309",
            b"1e999999",
            b"1e-999999",
        )
        for token in tokens:
            with (
                self.subTest(token=token),
                self.assertRaises(AppServerProtocolError) as raised,
            ):
                decode_json_line(b'{"value":' + token + b"}\n")
            self.assertEqual(raised.exception.code, "invalid-json-number")

        framing = len(b'{"value":0.}\n')
        huge_mantissa = (
            b'{"value":0.' + b"1" * (APP_SERVER_MAX_RECORD_BYTES + 1 - framing) + b"}\n"
        )
        self.assertEqual(len(huge_mantissa), APP_SERVER_MAX_RECORD_BYTES + 1)
        with self.assertRaises(AppServerProtocolError) as raised:
            decode_json_line(huge_mantissa)
        self.assertEqual(raised.exception.code, "invalid-json-number")

    def test_outbound_protocol_rejects_floats(self) -> None:
        for value in (0.0, 1.5, float("inf"), float("nan")):
            with (
                self.subTest(value=value),
                self.assertRaises(AppServerProtocolError) as raised,
            ):
                encode_json_line({"value": value})
            self.assertEqual(raised.exception.code, "invalid-json-number")

    def test_does_not_reclassify_unrelated_json_value_errors(self) -> None:
        with (
            mock.patch(
                "review_supervisor.appserver_protocol.json.loads",
                side_effect=ValueError("synthetic non-parser failure"),
            ),
            self.assertRaisesRegex(
                ValueError, "synthetic non-parser failure"
            ) as raised,
        ):
            decode_json_line(b'{"id":1}\n')
        self.assertNotIsInstance(raised.exception, AppServerProtocolError)

    def test_prelaunch_turn_start_budget_includes_json_escaping(self) -> None:
        self.assertGreater(validate_prelaunch_turn_start_record(b"evidence"), 0)

        prompt = b"\\" * (APP_SERVER_MAX_RECORD_BYTES // 2)
        with self.assertRaises(AppServerProtocolError) as raised:
            validate_prelaunch_turn_start_record(prompt)
        self.assertEqual(raised.exception.code, "record-size")


class AppServerProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
        )

    def protocol(
        self, *, config: AppServerSessionConfig | None = None
    ) -> AppServerProtocol:
        return AppServerProtocol(
            prompt=b"review evidence", config=config or self.config
        )

    def test_exact_handshake_requests_and_final_cross_check(self) -> None:
        protocol = self.protocol()
        initialize = protocol.start()[0]
        self.assertEqual(initialize["id"], 1)
        self.assertEqual(initialize["method"], "initialize")
        after_initialize = protocol.accept_message(
            {"id": 1, "result": initialize_result()}
        )
        self.assertEqual(after_initialize[0], {"method": "initialized"})
        self.assertEqual(
            after_initialize[1],
            {
                "id": 2,
                "method": "config/read",
                "params": {"cwd": NEUTRAL_CWD, "includeLayers": True},
            },
        )
        hooks_request = protocol.accept_message(
            {"id": 2, "result": safe_config_result()}
        )[0]
        self.assertEqual(hooks_request["method"], "hooks/list")
        thread_request = protocol.accept_message(
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
            }
        )[0]
        params = thread_request["params"]
        self.assertEqual(params["model"], MODEL)
        expected_thread_config = no_execution_config()
        expected_thread_config["model_reasoning_effort"] = "xhigh"
        self.assertEqual(params["config"], expected_thread_config)
        self.assertFalse(params["allowProviderModelFallback"])
        self.assertEqual(params["dynamicTools"], [])
        self.assertEqual(params["environments"], [])
        self.assertEqual(params["multiAgentMode"], "explicitRequestOnly")
        self.assertEqual(params["runtimeWorkspaceRoots"], [])
        self.assertEqual(params["selectedCapabilityRoots"], [])
        self.assertEqual(params["cwd"], NEUTRAL_CWD)

        attestation = thread_start_result(self.config)
        protocol.accept_message(
            {"method": "thread/started", "params": {"thread": attestation["thread"]}}
        )
        turn_request = protocol.accept_message({"id": 4, "result": attestation})[0]
        self.assertEqual(turn_request["method"], "turn/start")
        turn_params = turn_request["params"]
        self.assertEqual(turn_params["model"], MODEL)
        self.assertEqual(turn_params["effort"], "xhigh")
        self.assertEqual(turn_params["additionalContext"], {})
        self.assertEqual(turn_params["environments"], [])
        self.assertEqual(turn_params["multiAgentMode"], "explicitRequestOnly")
        self.assertEqual(turn_params["responsesapiClientMetadata"], {})
        self.assertEqual(
            turn_params["sandboxPolicy"],
            {"networkAccess": False, "type": "readOnly"},
        )
        self.assertEqual(turn_params["input"][0]["text"], "review evidence")

        turn = in_progress_turn()
        protocol.accept_message({"id": 5, "result": {"turn": turn}})
        protocol.accept_message(
            {
                "method": "turn/started",
                "params": {"threadId": "thread-1", "turn": turn},
            }
        )
        prompt_item = user_message()
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": prompt_item,
                    "startedAtMs": 997,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/completed",
                "params": {
                    "completedAtMs": 998,
                    "item": prompt_item,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        item = final_item()
        complete(
            protocol,
            item,
            prior_items=(prompt_item,),
            terminal_items=(),
            terminal_items_view="notLoaded",
        )
        result = protocol.finish_eof()
        self.assertEqual(result.review_status, "clean")
        self.assertEqual(result.final_text, "No findings.")
        self.assertEqual(result.attestation["model"], MODEL)
        self.assertEqual(result.attestation["model_attempt"], "primary")
        self.assertEqual(result.attestation["reasoning_effort"], "xhigh")
        self.assertEqual(result.attestation["thread_path"], None)

    def test_accepts_bounded_reasoning_and_telemetry_but_retains_only_final(
        self,
    ) -> None:
        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        protocol.accept_message(
            {
                "method": "thread/status/changed",
                "params": {
                    "status": {"activeFlags": [], "type": "active"},
                    "threadId": "thread-1",
                },
            }
        )
        token_breakdown = {
            "cachedInputTokens": 1,
            "inputTokens": 2,
            "outputTokens": 3,
            "reasoningOutputTokens": 4,
            "totalTokens": 9,
        }
        protocol.accept_message(
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread-1",
                    "tokenUsage": {
                        "last": token_breakdown,
                        "modelContextWindow": 100_000,
                        "total": token_breakdown,
                    },
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "account/rateLimits/updated",
                "params": {
                    "rateLimits": {
                        "credits": {
                            "balance": None,
                            "hasCredits": True,
                            "unlimited": False,
                        },
                        "planType": "pro",
                        "primary": {"usedPercent": 1},
                    }
                },
            }
        )
        started = reasoning_item()
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": started,
                    "startedAtMs": 100,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/reasoning/summaryPartAdded",
                "params": {
                    "itemId": "reasoning-1",
                    "summaryIndex": 0,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/reasoning/summaryTextDelta",
                "params": {
                    "delta": "inspection",
                    "itemId": "reasoning-1",
                    "summaryIndex": 0,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/reasoning/textDelta",
                "params": {
                    "contentIndex": 0,
                    "delta": "ephemeral rationale",
                    "itemId": "reasoning-1",
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        completed_reasoning = reasoning_item(
            content=["ephemeral rationale"],
            summary=["inspection"],
        )
        protocol.accept_message(
            {
                "method": "item/completed",
                "params": {
                    "completedAtMs": 101,
                    "item": completed_reasoning,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        complete(protocol, prior_items=(completed_reasoning,))
        trailing_notifications = (
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread-1",
                    "tokenUsage": {
                        "last": token_breakdown,
                        "modelContextWindow": 100_000,
                        "total": token_breakdown,
                    },
                    "turnId": "turn-1",
                },
            },
            {
                "method": "account/rateLimits/updated",
                "params": {"rateLimits": {}},
            },
            {
                "method": "thread/status/changed",
                "params": {"status": {"type": "idle"}, "threadId": "thread-1"},
            },
        )
        for notification in trailing_notifications:
            with (
                self.subTest(method=notification["method"]),
                self.assertRaises(AppServerProtocolError) as trailing,
            ):
                protocol.accept_message(notification)
            self.assertEqual(trailing.exception.code, "trailing-record")
        result = protocol.finish_eof()
        self.assertEqual(result.final_text, "No findings.")
        self.assertNotIn("ephemeral rationale", repr(result))

    def test_rejects_reasoning_stream_mismatch_unknown_items_and_bad_telemetry(
        self,
    ) -> None:
        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        with self.assertRaises(AppServerProtocolError) as forbidden:
            protocol.accept_message(
                {
                    "method": "item/started",
                    "params": {
                        "item": {"id": "tool-1", "type": "commandExecution"},
                        "startedAtMs": 1,
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(forbidden.exception.code, "tool-or-item-forbidden")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        started = reasoning_item()
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": started,
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        with self.assertRaises(AppServerProtocolError) as skipped:
            protocol.accept_message(
                {
                    "method": "item/reasoning/summaryTextDelta",
                    "params": {
                        "delta": "unannounced",
                        "itemId": "reasoning-1",
                        "summaryIndex": 0,
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(skipped.exception.code, "protocol-order")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        with self.assertRaises(AppServerProtocolError) as telemetry:
            protocol.accept_message(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "tokenUsage": {"last": {}, "total": {}},
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(telemetry.exception.code, "record-schema")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        with self.assertRaises(AppServerProtocolError) as waiting:
            protocol.accept_message(
                {
                    "method": "thread/status/changed",
                    "params": {
                        "status": {
                            "activeFlags": ["waitingOnApproval"],
                            "type": "active",
                        },
                        "threadId": "thread-1",
                    },
                }
            )
        self.assertEqual(waiting.exception.code, "tool-or-item-forbidden")

    def test_external_auth_is_in_memory_only_and_never_retained_in_attestation(
        self,
    ) -> None:
        token = synthetic_external_access_token()
        external_auth = ExternalChatGPTAuth(
            access_token=token,
            chatgpt_account_id="account-1",
            chatgpt_plan_type="pro",
        )
        config = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
            external_auth=external_auth,
        )
        self.assertNotIn(token, repr(config))
        protocol = self.protocol(config=config)
        initialize = protocol.start()[0]
        after_initialize = protocol.accept_message(
            {"id": initialize["id"], "result": initialize_result()}
        )
        self.assertEqual(after_initialize[0], {"method": "initialized"})
        auth_request = after_initialize[1]
        self.assertEqual(auth_request["method"], "account/login/start")
        self.assertEqual(auth_request["params"]["accessToken"], token)
        protocol.accept_message(
            {
                "method": "remoteControl/status/changed",
                "params": {
                    "environmentId": None,
                    "installationId": "install-1",
                    "serverName": "local",
                    "status": "disabled",
                },
            }
        )
        config_request = protocol.accept_message(
            {"id": auth_request["id"], "result": {"type": "chatgptAuthTokens"}}
        )[0]
        protocol.accept_message(
            {
                "method": "account/login/completed",
                "params": {"error": None, "loginId": None, "success": True},
            }
        )
        protocol.accept_message(
            {
                "method": "account/updated",
                "params": {"authMode": "chatgptAuthTokens", "planType": "pro"},
            }
        )
        hooks_request = protocol.accept_message(
            {
                "id": config_request["id"],
                "result": safe_config_result(),
            }
        )[0]
        thread_request = protocol.accept_message(
            {
                "id": hooks_request["id"],
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
            }
        )[0]
        attestation = thread_start_result(config)
        protocol.accept_message(
            {"method": "thread/started", "params": {"thread": attestation["thread"]}}
        )
        turn_request = protocol.accept_message(
            {"id": thread_request["id"], "result": attestation}
        )[0]
        turn = in_progress_turn()
        protocol.accept_message({"id": turn_request["id"], "result": {"turn": turn}})
        protocol.accept_message(
            {
                "method": "turn/started",
                "params": {"threadId": "thread-1", "turn": turn},
            }
        )
        complete(protocol)
        result = protocol.finish_eof()
        self.assertEqual(result.attestation["external_auth"], "accepted")
        self.assertEqual(
            result.attestation["remote_control"],
            "disabled-notification-observed",
        )
        self.assertNotIn(token, repr(result))

        with self.assertRaises(AppServerProtocolError):
            ExternalChatGPTAuth(
                access_token="-".join(("not", "a", "jwt")),
                chatgpt_account_id="account-1",
            )
        with self.assertRaises(AppServerProtocolError) as non_ascii:
            ExternalChatGPTAuth(
                access_token=".".join(
                    (
                        "header",
                        "payload",
                        "signatur\N{LATIN SMALL LETTER E WITH ACUTE}",
                    )
                ),
                chatgpt_account_id="account-1",
            )
        self.assertEqual(non_ascii.exception.code, "external-auth")

    def test_model_is_explicit_per_attempt_and_never_silently_substituted(self) -> None:
        authorization = ModelFallbackAuthorization(
            denial_category="model_entitlement",
            denial_record_sha256="a" * 64,
        )
        explicit = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
            expected_model="gpt-5.5",
            fallback_authorization=authorization,
        )
        protocol = self.protocol(config=explicit)
        thread_request = advance_to_thread_request(protocol)
        self.assertEqual(thread_request["params"]["model"], "gpt-5.5")
        explicit_result = thread_start_result(explicit)
        protocol.accept_message(
            {
                "method": "thread/started",
                "params": {"thread": explicit_result["thread"]},
            }
        )
        protocol.accept_message({"id": 4, "result": explicit_result})
        turn = in_progress_turn()
        protocol.accept_message({"id": 5, "result": {"turn": turn}})
        protocol.accept_message(
            {
                "method": "turn/started",
                "params": {"threadId": "thread-1", "turn": turn},
            }
        )
        complete(protocol)
        fallback_attestation = protocol.finish_eof().attestation
        self.assertEqual(fallback_attestation["model_attempt"], "explicit_fallback")
        self.assertEqual(
            fallback_attestation["model_fallback_authorization"],
            authorization.to_json(),
        )

        primary = self.protocol()
        advance_to_thread_request(primary)
        substituted = thread_start_result(self.config, model="gpt-5.5")
        with self.assertRaises(AppServerProtocolError) as raised:
            primary.accept_message({"id": 4, "result": substituted})
        self.assertEqual(raised.exception.code, "thread-attestation-mismatch")

        with self.assertRaises(AppServerProtocolError) as raised:
            AppServerSessionConfig(
                neutral_cwd=NEUTRAL_CWD,
                expected_codex_home=CODEX_HOME,
                expected_model="gpt-5.5",
            )
        self.assertEqual(raised.exception.code, "model-policy")
        with self.assertRaises(AppServerProtocolError):
            ModelFallbackAuthorization(
                denial_category="transient_outage",  # type: ignore[arg-type]
                denial_record_sha256="a" * 64,
            )
        with self.assertRaises(AppServerProtocolError):
            ModelFallbackAuthorization(
                denial_category="account",
                denial_record_sha256="not-a-digest",
            )
        for override in (
            {"expected_reasoning_effort": "low"},
            {"expected_model_provider": "fallback-provider"},
            {"expected_cli_version": "0.144.0"},
        ):
            with (
                self.subTest(override=override),
                self.assertRaises(AppServerProtocolError),
            ):
                AppServerSessionConfig(
                    neutral_cwd=NEUTRAL_CWD,
                    expected_codex_home=CODEX_HOME,
                    **override,
                )

    def test_every_security_attestation_is_required_and_exact(self) -> None:
        mutations = {
            "approvalPolicy": "on-request",
            "approvalsReviewer": "auto_review",
            "cwd": "/private/other",
            "instructionSources": ["AGENTS.md"],
            "model": "substituted-model",
            "modelProvider": "fallback-provider",
            "reasoningEffort": "low",
            "runtimeWorkspaceRoots": ["/private/worktree"],
            "sandbox": {"networkAccess": True, "type": "readOnly"},
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                protocol = self.protocol()
                advance_to_thread_request(protocol)
                result = thread_start_result(self.config, **{key: value})
                with self.assertRaises(AppServerProtocolError) as raised:
                    protocol.accept_message({"id": 4, "result": result})
                self.assertEqual(raised.exception.code, "thread-attestation-mismatch")

        thread_mutations = {
            "cliVersion": "0.144.0",
            "cwd": "/private/other",
            "ephemeral": False,
            "modelProvider": "fallback-provider",
            "path": "/private/persisted.jsonl",
            "source": "vscode",
            "status": {"type": "active", "activeFlags": []},
            "turns": [{}],
        }
        for key, value in thread_mutations.items():
            with self.subTest(thread_key=key):
                protocol = self.protocol()
                advance_to_thread_request(protocol)
                result = thread_start_result(
                    self.config,
                    thread=thread_value(self.config, **{key: value}),
                )
                with self.assertRaises(AppServerProtocolError):
                    protocol.accept_message({"id": 4, "result": result})

    def test_preflight_rejects_ambient_instructions_and_hooks(self) -> None:
        config_result = safe_config_result()
        config = config_result["config"]
        self.assertIsInstance(config, dict)
        config["instructions"] = "ambient"
        protocol = self.protocol()
        initialize = protocol.start()[0]
        config_request = protocol.accept_message(
            {"id": initialize["id"], "result": initialize_result()}
        )[1]
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "id": config_request["id"],
                    "result": config_result,
                }
            )
        self.assertEqual(raised.exception.code, "ambient-instructions")

        hooks_protocol = self.protocol()
        with self.assertRaises(AppServerProtocolError) as raised:
            advance_to_thread_request(hooks_protocol, hooks=[{"name": "unsafe"}])
        self.assertEqual(raised.exception.code, "hooks-present")

    def test_preflight_rejects_ambient_execution_config(self) -> None:
        cases = (
            ("web search", "web_search", "live"),
            (
                "MCP server",
                "mcp_servers",
                {"ambient": {"command": "/bin/echo"}},
            ),
            (
                "tool config",
                "tools",
                {"web_search": {"allowed_domains": ["example.com"]}},
            ),
            ("skills", "skills", {"config": [{"enabled": True}]}),
            (
                "hooks config",
                "hooks",
                {"PreToolUse": [{"command": "/bin/echo"}]},
            ),
            ("unknown field", "future_executor", {"enabled": True}),
        )
        for label, key, value in cases:
            with self.subTest(label=label):
                config_result = safe_config_result()
                config = config_result["config"]
                self.assertIsInstance(config, dict)
                config[key] = value
                protocol = self.protocol()
                initialize = protocol.start()[0]
                config_request = protocol.accept_message(
                    {"id": initialize["id"], "result": initialize_result()}
                )[1]
                with self.assertRaises(AppServerProtocolError) as raised:
                    protocol.accept_message(
                        {"id": config_request["id"], "result": config_result}
                    )
                self.assertEqual(raised.exception.code, "unsafe-effective-config")

        config_result = safe_config_result()
        config = config_result["config"]
        self.assertIsInstance(config, dict)
        features = config["features"]
        self.assertIsInstance(features, dict)
        features["shell_tool"] = True
        protocol = self.protocol()
        initialize = protocol.start()[0]
        config_request = protocol.accept_message(
            {"id": initialize["id"], "result": initialize_result()}
        )[1]
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {"id": config_request["id"], "result": config_result}
            )
        self.assertEqual(raised.exception.code, "unsafe-effective-config")

    def test_preflight_rejects_unknown_and_nonisolated_layers(self) -> None:
        with self.subTest("unknown layer"):
            config_result = safe_config_result()
            layers = config_result["layers"]
            self.assertIsInstance(layers, list)
            session_layer = layers[0]
            self.assertIsInstance(session_layer, dict)
            session_layer["name"] = {"type": "futureLayer"}
            protocol = self.protocol()
            initialize = protocol.start()[0]
            config_request = protocol.accept_message(
                {"id": initialize["id"], "result": initialize_result()}
            )[1]
            with self.assertRaises(AppServerProtocolError) as raised:
                protocol.accept_message(
                    {"id": config_request["id"], "result": config_result}
                )
            self.assertEqual(raised.exception.code, "unsafe-config-layer")

        with self.subTest("ambient user layer"):
            config_result = safe_config_result()
            layers = config_result["layers"]
            self.assertIsInstance(layers, list)
            user_layer = layers[1]
            self.assertIsInstance(user_layer, dict)
            user_layer["config"] = {"web_search": "live"}
            protocol = self.protocol()
            initialize = protocol.start()[0]
            config_request = protocol.accept_message(
                {"id": initialize["id"], "result": initialize_result()}
            )[1]
            with self.assertRaises(AppServerProtocolError) as raised:
                protocol.accept_message(
                    {"id": config_request["id"], "result": config_result}
                )
            self.assertEqual(raised.exception.code, "unsafe-config-layer")

    def test_rejects_all_server_requests_and_diagnostic_notifications(self) -> None:
        for request in (
            {
                "id": "server-1",
                "method": "item/tool/call",
                "params": {
                    "arguments": {},
                    "callId": "call-1",
                    "namespace": "evidence",
                    "threadId": "thread-1",
                    "tool": "read",
                    "turnId": "turn-1",
                },
            },
            {"id": 90, "method": "unknown/request", "params": {}},
        ):
            protocol = self.protocol()
            protocol.start()
            with (
                self.subTest(method=request["method"]),
                self.assertRaises(AppServerProtocolError) as raised,
            ):
                protocol.accept_message(request)
            self.assertIn(
                raised.exception.code,
                {"tool-request-forbidden", "server-request-forbidden"},
            )

        for method in ("error", "warning", "configWarning", "hook/started", "unknown"):
            protocol = self.protocol()
            protocol.start()
            with self.subTest(method=method), self.assertRaises(AppServerProtocolError):
                protocol.accept_message({"method": method, "params": {}})

    def test_rejects_wrong_response_id_schema_and_remote_failure(self) -> None:
        for response_id, expected_code in (
            (2, "response-id"),
            (1.0, "invalid-json-number"),
            (True, "response-id"),
            ("1", "response-id"),
        ):
            protocol = self.protocol()
            protocol.start()
            with (
                self.subTest(response_id=response_id),
                self.assertRaises(AppServerProtocolError) as raised,
            ):
                protocol.accept_message(
                    {"id": response_id, "result": initialize_result()}
                )
            self.assertEqual(raised.exception.code, expected_code)

        protocol = self.protocol()
        protocol.start()
        with self.assertRaises(AppServerProtocolError):
            protocol.accept_message(
                {"id": 1, "jsonrpc": "2.0", "result": initialize_result()}
            )

        protocol = self.protocol()
        protocol.start()
        with self.assertRaises(AppServerRemoteError) as raised:
            protocol.accept_message(
                {
                    "error": {
                        "code": -32001,
                        "data": {"category": "model_entitlement"},
                        "message": "model is not entitled",
                    },
                    "id": 1,
                }
            )
        self.assertEqual(raised.exception.request_method, "initialize")
        self.assertEqual(raised.exception.remote_code, -32001)
        self.assertEqual(
            raised.exception.remote_data,
            {"category": "model_entitlement"},
        )

    def test_final_lifecycle_rejects_null_phase_tools_duplicates_and_mismatch(
        self,
    ) -> None:
        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        mismatched_prompt = user_message("different evidence")
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "item/started",
                    "params": {
                        "item": mismatched_prompt,
                        "startedAtMs": 0,
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(raised.exception.code, "final-cross-check")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "item/completed",
                    "params": {
                        "completedAtMs": 1,
                        "item": final_item(),
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(raised.exception.code, "protocol-order")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        invalid_phase = final_item()
        invalid_phase["phase"] = None
        with self.assertRaises(AppServerProtocolError) as raised:
            complete(protocol, invalid_phase)
        self.assertEqual(raised.exception.code, "invalid-message-phase")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        tool_shaped = final_item()
        tool_shaped["type"] = "commandExecution"
        with self.assertRaises(AppServerProtocolError) as raised:
            complete(protocol, tool_shaped)
        self.assertEqual(raised.exception.code, "tool-or-item-forbidden")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        item = final_item()
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": item,
                    "startedAtMs": 0,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/completed",
                "params": {
                    "completedAtMs": 1,
                    "item": item,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "item/completed",
                    "params": {
                        "completedAtMs": 2,
                        "item": item,
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                }
            )
        self.assertEqual(raised.exception.code, "duplicate-final")

        mismatched = copy.deepcopy(item)
        mismatched["text"] = "[P1] mismatch"
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {
                            "id": "turn-1",
                            "items": [mismatched],
                            "itemsView": "notLoaded",
                            "status": "completed",
                        },
                    },
                }
            )
        self.assertEqual(raised.exception.code, "final-cross-check")

        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {
                            "id": "turn-1",
                            "items": [],
                            "itemsView": "full",
                            "status": "completed",
                        },
                    },
                }
            )
        self.assertEqual(raised.exception.code, "final-cross-check")

    def test_streamed_commentary_is_bounded_and_cross_checked(self) -> None:
        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        started = final_item("")
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": started,
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        with mock.patch(
            "review_supervisor.appserver_protocol.APP_SERVER_COMMENTARY_BYTES", 3
        ):
            with self.assertRaises(AppServerProtocolError) as raised:
                protocol.accept_message(
                    {
                        "method": "item/agentMessage/delta",
                        "params": {
                            "delta": "four",
                            "itemId": "item-1",
                            "threadId": "thread-1",
                            "turnId": "turn-1",
                        },
                    }
                )
        self.assertEqual(raised.exception.code, "commentary-size")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": final_item(""),
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/agentMessage/delta",
                "params": {
                    "delta": "No findings.",
                    "itemId": "item-1",
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        complete(protocol, start_item=False)
        self.assertEqual(protocol.finish_eof().streamed_message_bytes, 12)

    def test_abnormal_eof_trailing_records_and_failed_turn_are_rejected(self) -> None:
        protocol = self.protocol()
        protocol.start()
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.finish_eof()
        self.assertEqual(raised.exception.code, "abnormal-eof")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        complete(protocol)
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message({"method": "warning", "params": {}})
        self.assertEqual(raised.exception.code, "trailing-record")

        protocol = self.protocol()
        advance_to_running(protocol, self.config)
        protocol.accept_message(
            {
                "method": "item/started",
                "params": {
                    "item": final_item(),
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        protocol.accept_message(
            {
                "method": "item/completed",
                "params": {
                    "completedAtMs": 1,
                    "item": final_item(),
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            }
        )
        with self.assertRaises(AppServerProtocolError) as raised:
            protocol.accept_message(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {
                            "error": {"message": "denied"},
                            "id": "turn-1",
                            "items": [final_item()],
                            "status": "failed",
                        },
                    },
                }
            )
        self.assertEqual(raised.exception.code, "turn-failed")


if __name__ == "__main__":
    unittest.main()
