from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from .constants import (
    APP_SERVER_CLI_VERSION,
    APP_SERVER_BASE_INSTRUCTIONS,
    APP_SERVER_CLIENT_NAME,
    APP_SERVER_COMMENTARY_BYTES,
    APP_SERVER_DEVELOPER_INSTRUCTIONS,
    APP_SERVER_MAX_IDENTIFIER_BYTES,
    APP_SERVER_MAX_JSON_DEPTH,
    APP_SERVER_MAX_REASONING_ITEMS,
    APP_SERVER_MAX_REASONING_PARTS,
    APP_SERVER_MAX_RECORD_BYTES,
    APP_SERVER_MAX_TELEMETRY_NOTIFICATIONS,
    APP_SERVER_MODEL_PROVIDER,
    APP_SERVER_SESSION_SOURCE,
    EXPLICIT_FALLBACK_MODEL,
    FINAL_MESSAGE_BYTES,
    MAX_APP_SERVER_PROMPT_BYTES,
    MODEL,
    REASONING_EFFORT,
    VERSION,
)
from .prompt import validate_final_message


_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_MAX_PROTOCOL_PATH_BYTES = 4096
_MAX_MODEL_NAME_BYTES = 128
_JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
_THREAD_RESPONSE_KEYS = frozenset(
    {
        "activePermissionProfile",
        "approvalPolicy",
        "approvalsReviewer",
        "cwd",
        "instructionSources",
        "model",
        "modelProvider",
        "multiAgentMode",
        "reasoningEffort",
        "runtimeWorkspaceRoots",
        "sandbox",
        "serviceTier",
        "thread",
    }
)
_THREAD_KEYS = frozenset(
    {
        "agentNickname",
        "agentRole",
        "cliVersion",
        "createdAt",
        "cwd",
        "ephemeral",
        "extra",
        "forkedFromId",
        "gitInfo",
        "historyMode",
        "id",
        "modelProvider",
        "name",
        "parentThreadId",
        "path",
        "preview",
        "recencyAt",
        "sessionId",
        "source",
        "status",
        "threadSource",
        "turns",
        "updatedAt",
    }
)
_TURN_KEYS = frozenset(
    {
        "completedAt",
        "durationMs",
        "error",
        "id",
        "items",
        "itemsView",
        "startedAt",
        "status",
    }
)
_CONFIG_KEYS_0_145_0_ALPHA_18 = frozenset(
    {
        "agents",
        "allow_login_shell",
        "analytics",
        "approval_policy",
        "approvals_reviewer",
        "apps",
        "apps_mcp_product_sku",
        "audio",
        "auto_review",
        "background_terminal_max_timeout",
        "chatgpt_base_url",
        "check_for_update_on_startup",
        "cli_auth_credentials_store",
        "compact_prompt",
        "debug",
        "default_permissions",
        "desktop",
        "developer_instructions",
        "disable_paste_burst",
        "experimental_compact_prompt_file",
        "experimental_realtime_start_instructions",
        "experimental_realtime_webrtc_call_base_url",
        "experimental_realtime_ws_backend_prompt",
        "experimental_realtime_ws_base_url",
        "experimental_realtime_ws_model",
        "experimental_realtime_ws_startup_context",
        "experimental_thread_config_endpoint",
        "experimental_thread_store",
        "experimental_thread_store_endpoint",
        "experimental_use_unified_exec_tool",
        "features",
        "feedback",
        "file_opener",
        "forced_chatgpt_workspace_id",
        "forced_login_method",
        "ghost_snapshot",
        "hide_agent_reasoning",
        "history",
        "hooks",
        "include_apps_instructions",
        "include_collaboration_mode_instructions",
        "include_environment_context",
        "include_permissions_instructions",
        "instructions",
        "js_repl_node_module_dirs",
        "js_repl_node_path",
        "log_dir",
        "marketplaces",
        "mcp_oauth_callback_port",
        "mcp_oauth_callback_url",
        "mcp_oauth_credentials_store",
        "mcp_servers",
        "memories",
        "model",
        "model_auto_compact_token_limit",
        "model_auto_compact_token_limit_scope",
        "model_catalog_json",
        "model_context_window",
        "model_instructions_file",
        "model_provider",
        "model_providers",
        "model_reasoning_effort",
        "model_reasoning_summary",
        "model_verbosity",
        "notice",
        "notify",
        "openai_base_url",
        "orchestrator",
        "oss_provider",
        "otel",
        "permissions",
        "personality",
        "plan_mode_reasoning_effort",
        "plugins",
        "profile",
        "profiles",
        "project_doc_fallback_filenames",
        "project_doc_max_bytes",
        "project_root_markers",
        "projects",
        "realtime",
        "review_model",
        "sandbox_mode",
        "sandbox_workspace_write",
        "service_tier",
        "shell_environment_policy",
        "show_raw_agent_reasoning",
        "skills",
        "sqlite_home",
        "suppress_unstable_features_warning",
        "tool_output_token_limit",
        "tool_suggest",
        "tools",
        "tui",
        "web_search",
        "windows",
    }
)
_NO_EXECUTION_FEATURES = frozenset(
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
_NO_EXECUTION_CONFIG_KEYS = frozenset(
    {
        "agents",
        "allow_login_shell",
        "analytics",
        "apps",
        "check_for_update_on_startup",
        "developer_instructions",
        "experimental_use_unified_exec_tool",
        "features",
        "history",
        "hooks",
        "include_apps_instructions",
        "include_collaboration_mode_instructions",
        "include_environment_context",
        "include_permissions_instructions",
        "instructions",
        "marketplaces",
        "mcp_servers",
        "notify",
        "plugins",
        "project_doc_fallback_filenames",
        "project_doc_max_bytes",
        "shell_environment_policy",
        "skills",
        "tools",
        "web_search",
    }
)
_AGENT_CONFIG_KEYS = frozenset(
    {
        "default_subagent_model",
        "default_subagent_reasoning_effort",
        "enabled",
        "interrupt_message",
        "job_max_runtime_seconds",
        "max_concurrent_threads_per_session",
        "max_depth",
    }
)
_HOOK_EVENT_KEYS = frozenset(
    {
        "PermissionRequest",
        "PostCompact",
        "PostToolUse",
        "PreCompact",
        "PreToolUse",
        "SessionStart",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
    }
)
_SHELL_ENVIRONMENT_POLICY_KEYS = frozenset(
    {
        "exclude",
        "experimental_use_profile",
        "ignore_default_excludes",
        "include_only",
        "inherit",
        "set",
    }
)
_NO_EXECUTION_CONFIG_OVERRIDES = (
    "agents.enabled=false",
    "allow_login_shell=false",
    "analytics.enabled=false",
    'apps._default.approvals_reviewer="user"',
    'apps._default.default_tools_approval_mode="prompt"',
    "apps._default.destructive_enabled=false",
    "apps._default.enabled=false",
    "apps._default.open_world_enabled=false",
    "check_for_update_on_startup=false",
    'developer_instructions=""',
    "experimental_use_unified_exec_tool=false",
    *(f"features.{name}=false" for name in sorted(_NO_EXECUTION_FEATURES)),
    'history.persistence="none"',
    "hooks={}",
    "include_apps_instructions=false",
    "include_collaboration_mode_instructions=false",
    "include_environment_context=false",
    "include_permissions_instructions=false",
    'instructions=""',
    "marketplaces={}",
    "mcp_servers={}",
    "notify=[]",
    "plugins={}",
    "project_doc_fallback_filenames=[]",
    "project_doc_max_bytes=0",
    'shell_environment_policy.inherit="none"',
    "skills={}",
    "tools={}",
    'web_search="disabled"',
)
APP_SERVER_NO_EXECUTION_CONFIG_ARGS = tuple(
    argument
    for override in _NO_EXECUTION_CONFIG_OVERRIDES
    for argument in ("-c", override)
)


class AppServerProtocolError(ValueError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class AppServerRemoteError(AppServerProtocolError):
    def __init__(
        self,
        *,
        request_method: str,
        remote_code: int,
        remote_message: str,
        remote_data: Any = None,
    ) -> None:
        super().__init__(
            f"app-server rejected {request_method}: {remote_message}",
            code="server-response-error",
        )
        self.request_method = request_method
        self.remote_code = remote_code
        self.remote_message = remote_message
        self.remote_data = remote_data


@dataclass(frozen=True)
class ModelFallbackAuthorization:
    denial_category: Literal[
        "account",
        "plan",
        "org_policy",
        "model_entitlement",
    ]
    denial_record_sha256: str
    denied_model: str = MODEL
    selected_model: str = EXPLICIT_FALLBACK_MODEL

    def __post_init__(self) -> None:
        if not isinstance(self.denial_category, str) or self.denial_category not in {
            "account",
            "plan",
            "org_policy",
            "model_entitlement",
        }:
            raise AppServerProtocolError(
                "fallback denial category is not policy-authorized",
                code="model-policy",
            )
        if not _is_sha256(self.denial_record_sha256):
            raise AppServerProtocolError(
                "fallback denial record digest is invalid",
                code="model-policy",
            )
        if self.denied_model != MODEL or self.selected_model != EXPLICIT_FALLBACK_MODEL:
            raise AppServerProtocolError(
                "fallback model transition is not policy-authorized",
                code="model-policy",
            )

    def to_json(self) -> dict[str, str]:
        return {
            "denial_category": self.denial_category,
            "denial_record_sha256": self.denial_record_sha256,
            "denied_model": self.denied_model,
            "selected_model": self.selected_model,
        }


@dataclass(frozen=True)
class ExternalChatGPTAuth:
    access_token: str = field(repr=False)
    chatgpt_account_id: str
    chatgpt_plan_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.access_token, str):
            raise AppServerProtocolError(
                "external access token is not a bounded JWT",
                code="external-auth",
            )
        try:
            encoded_token = self.access_token.encode("ascii", "strict")
        except UnicodeEncodeError as error:
            raise AppServerProtocolError(
                "external access token is not a bounded JWT",
                code="external-auth",
            ) from error
        if (
            not 1 <= len(encoded_token) <= 32 * 1024
            or _JWT_PATTERN.fullmatch(self.access_token) is None
        ):
            raise AppServerProtocolError(
                "external access token is not a bounded JWT",
                code="external-auth",
            )
        _bounded_string(
            self.chatgpt_account_id,
            "external ChatGPT account ID",
            limit=512,
        )
        if self.chatgpt_plan_type is not None:
            _bounded_string(
                self.chatgpt_plan_type,
                "external ChatGPT plan type",
                limit=64,
            )


@dataclass(frozen=True)
class AppServerSessionConfig:
    neutral_cwd: str
    expected_codex_home: str
    expected_model: str = MODEL
    expected_reasoning_effort: str = REASONING_EFFORT
    expected_model_provider: str = APP_SERVER_MODEL_PROVIDER
    expected_cli_version: str = APP_SERVER_CLI_VERSION
    fallback_authorization: ModelFallbackAuthorization | None = None
    external_auth: ExternalChatGPTAuth | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _validate_absolute_normalized_path(self.neutral_cwd, "neutral cwd")
        _validate_absolute_normalized_path(
            self.expected_codex_home,
            "expected Codex home",
        )
        _bounded_string(
            self.expected_model,
            "expected model",
            limit=_MAX_MODEL_NAME_BYTES,
        )
        _bounded_string(
            self.expected_reasoning_effort,
            "expected reasoning effort",
            limit=64,
        )
        _bounded_string(
            self.expected_model_provider,
            "expected model provider",
            limit=128,
        )
        _bounded_string(
            self.expected_cli_version,
            "expected CLI version",
            limit=128,
        )
        if self.expected_reasoning_effort != REASONING_EFFORT:
            raise AppServerProtocolError(
                "review attempts must use the pinned reasoning effort",
                code="model-policy",
            )
        if self.expected_model_provider != APP_SERVER_MODEL_PROVIDER:
            raise AppServerProtocolError(
                "review attempts must use the pinned model provider",
                code="model-policy",
            )
        if self.expected_cli_version != APP_SERVER_CLI_VERSION:
            raise AppServerProtocolError(
                "review attempts must use the pinned CLI version",
                code="model-policy",
            )
        if self.expected_model == MODEL:
            if self.fallback_authorization is not None:
                raise AppServerProtocolError(
                    "a primary-model attempt cannot carry fallback authorization",
                    code="model-policy",
                )
        elif (
            self.expected_model != EXPLICIT_FALLBACK_MODEL
            or not isinstance(
                self.fallback_authorization,
                ModelFallbackAuthorization,
            )
            or self.fallback_authorization.selected_model != self.expected_model
        ):
            raise AppServerProtocolError(
                "non-primary model requires explicit proven-denial authorization",
                code="model-policy",
            )


@dataclass(frozen=True)
class AppServerSessionResult:
    review_status: str
    final_text: str
    attestation: dict[str, Any]
    streamed_message_bytes: int


def decode_json_line(
    record: bytes,
    *,
    max_bytes: int = APP_SERVER_MAX_RECORD_BYTES,
) -> dict[str, Any]:
    if not isinstance(record, bytes):
        raise AppServerProtocolError("protocol record is not bytes", code="record-type")
    if not record.endswith(b"\n"):
        raise AppServerProtocolError(
            "protocol record is not newline terminated",
            code="record-termination",
        )
    if not 1 < len(record) <= max_bytes + 1:
        raise AppServerProtocolError(
            "protocol record length is outside the accepted range",
            code="record-size",
        )
    payload = record[:-1]
    if not payload or payload.endswith(b"\r") or payload != payload.strip():
        raise AppServerProtocolError(
            "protocol record framing is not canonical",
            code="record-framing",
        )

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AppServerProtocolError(
                    f"duplicate JSON key: {key}",
                    code="duplicate-json-key",
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise AppServerProtocolError(
            f"non-finite JSON number is forbidden: {value}",
            code="invalid-json-number",
        )

    def parse_int64(value: str) -> int:
        negative = value.startswith("-")
        digits = value[1:] if negative else value
        limit = b"9223372036854775808" if negative else b"9223372036854775807"
        encoded = digits.encode("ascii", "strict")
        if len(encoded) > len(limit) or (
            len(encoded) == len(limit) and encoded > limit
        ):
            raise AppServerProtocolError(
                "protocol JSON integer is outside int64 bounds",
                code="invalid-json-number",
            )
        return int(value)

    def reject_float(_value: str) -> None:
        raise AppServerProtocolError(
            "protocol JSON floating-point numbers are forbidden",
            code="invalid-json-number",
        )

    try:
        text = payload.decode("utf-8", "strict")
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=reject_float,
            parse_int=parse_int64,
        )
    except AppServerProtocolError:
        raise
    except RecursionError as error:
        raise AppServerProtocolError(
            "protocol JSON exceeds its nesting-depth limit",
            code="json-depth",
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AppServerProtocolError(
            "protocol record is not strict UTF-8 JSON",
            code="malformed-json",
        ) from error
    if not isinstance(parsed, dict):
        raise AppServerProtocolError(
            "protocol record is not an object",
            code="record-schema",
        )
    _validate_json_tree(parsed)
    return parsed


def encode_json_line(
    value: dict[str, Any],
    *,
    max_bytes: int = APP_SERVER_MAX_RECORD_BYTES,
) -> bytes:
    _validate_json_tree(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise AppServerProtocolError(
            "outbound protocol record is not JSON serializable",
            code="outbound-schema",
        ) from error
    if len(encoded) > max_bytes:
        raise AppServerProtocolError(
            "outbound protocol record exceeds its byte limit",
            code="record-size",
        )
    return encoded + b"\n"


def validate_prelaunch_turn_start_record(prompt: bytes) -> int:
    """Validate the largest legal encoded turn/start record for this prompt."""

    prompt_text = _decode_appserver_prompt(prompt)
    record = _request_record(
        request_id=_INT64_MAX,
        method="turn/start",
        params=_turn_start_params(
            prompt=prompt_text,
            neutral_cwd=_max_expansion_path(_MAX_PROTOCOL_PATH_BYTES),
            model=_max_expansion_text(_MAX_MODEL_NAME_BYTES),
            reasoning_effort=REASONING_EFFORT,
            thread_id=_max_expansion_text(APP_SERVER_MAX_IDENTIFIER_BYTES),
        ),
    )
    return len(encode_json_line(record))


def _decode_appserver_prompt(prompt: bytes) -> str:
    if not isinstance(prompt, bytes):
        raise AppServerProtocolError(
            "app-server prompt is not bytes",
            code="prompt-type",
        )
    if not 1 <= len(prompt) <= MAX_APP_SERVER_PROMPT_BYTES:
        raise AppServerProtocolError(
            "app-server prompt length is outside the accepted range",
            code="prompt-size",
        )
    if b"\x00" in prompt:
        raise AppServerProtocolError(
            "app-server prompt contains NUL",
            code="prompt",
        )
    try:
        return prompt.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise AppServerProtocolError(
            "app-server prompt is not UTF-8",
            code="prompt",
        ) from error


def _max_expansion_text(byte_limit: int) -> str:
    # U+0080 is accepted by bounded strings and expands from two UTF-8 bytes
    # to six ASCII JSON bytes under ensure_ascii=True. A trailing backslash
    # gives the maximum two-byte JSON expansion for an odd byte allowance.
    pairs, remainder = divmod(byte_limit, 2)
    return "\u0080" * pairs + ("\\" if remainder else "")


def _max_expansion_path(byte_limit: int) -> str:
    return "/" + _max_expansion_text(byte_limit - 1)


def _request_record(
    *,
    request_id: int,
    method: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    return {"id": request_id, "method": method, "params": params}


def _turn_start_params(
    *,
    prompt: str,
    neutral_cwd: str,
    model: str,
    reasoning_effort: str,
    thread_id: str,
) -> dict[str, Any]:
    return {
        "additionalContext": {},
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "cwd": neutral_cwd,
        "effort": reasoning_effort,
        "environments": [],
        "input": [{"text": prompt, "text_elements": [], "type": "text"}],
        "model": model,
        "multiAgentMode": "explicitRequestOnly",
        "responsesapiClientMetadata": {},
        "runtimeWorkspaceRoots": [],
        "sandboxPolicy": {"networkAccess": False, "type": "readOnly"},
        "threadId": thread_id,
    }


def _no_execution_config(*, reasoning_effort: str | None = None) -> dict[str, Any]:
    config: dict[str, Any] = {
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
        "features": {name: False for name in sorted(_NO_EXECUTION_FEATURES)},
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
    if reasoning_effort is not None:
        config["model_reasoning_effort"] = reasoning_effort
    return config


class AppServerProtocol:
    def __init__(self, *, prompt: bytes, config: AppServerSessionConfig) -> None:
        self._prompt = _decode_appserver_prompt(prompt)
        self.config = config
        self._state = "new"
        self._next_request_id = 1
        self._pending_id: int | None = None
        self._pending_method: str | None = None
        self._thread_response: dict[str, Any] | None = None
        self._thread_notification: dict[str, Any] | None = None
        self._turn_response: dict[str, Any] | None = None
        self._turn_notification: dict[str, Any] | None = None
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._active_item: dict[str, Any] | None = None
        self._completed_items: list[dict[str, Any]] = []
        self._final_item: dict[str, Any] | None = None
        self._streamed_parts: list[str] = []
        self._streamed_bytes = 0
        self._reasoning_content: list[str] = []
        self._reasoning_summary: list[str] = []
        self._reasoning_bytes = 0
        self._telemetry_notifications = 0
        self._result: AppServerSessionResult | None = None
        self._external_auth_accepted = False
        self._login_completed_notified = False
        self._account_updated_notified = False
        self._remote_control_notified = False

    @property
    def terminal(self) -> bool:
        return self._state == "terminal"

    def start(self) -> tuple[dict[str, Any], ...]:
        if self._state != "new":
            raise AppServerProtocolError(
                "protocol session was started more than once",
                code="protocol-order",
            )
        self._state = "initialize"
        return (
            self._request(
                "initialize",
                {
                    "capabilities": {"experimentalApi": True},
                    "clientInfo": {
                        "name": APP_SERVER_CLIENT_NAME,
                        "title": "Independent Codex PR Review",
                        "version": VERSION,
                    },
                },
            ),
        )

    def accept_line(self, record: bytes) -> tuple[dict[str, Any], ...]:
        return self.accept_message(decode_json_line(record))

    def accept_message(self, message: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        if self._state == "new":
            raise AppServerProtocolError(
                "protocol record arrived outside an active session",
                code="protocol-order",
            )
        if not isinstance(message, dict):
            raise AppServerProtocolError(
                "protocol record is not an object",
                code="record-schema",
            )
        _validate_json_tree(message)
        if "id" in message and "method" in message:
            self._reject_server_request(message)
        if "id" in message:
            if self._state == "terminal":
                raise AppServerProtocolError(
                    "response arrived after the terminal review result",
                    code="trailing-record",
                )
            return self._accept_response(message)
        if "method" in message:
            return self._accept_notification(message)
        raise AppServerProtocolError(
            "protocol record is neither a response nor a notification",
            code="record-schema",
        )

    def finish_eof(self) -> AppServerSessionResult:
        if self._state != "terminal" or self._result is None:
            raise AppServerProtocolError(
                "app-server stdout ended before a trustworthy terminal result",
                code="abnormal-eof",
            )
        return self._result

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._pending_id is not None:
            raise AppServerProtocolError(
                "a second request was issued while one was outstanding",
                code="protocol-order",
            )
        request_id = self._next_request_id
        self._next_request_id += 1
        self._pending_id = request_id
        self._pending_method = method
        return _request_record(
            request_id=request_id,
            method=method,
            params=params,
        )

    def _accept_response(self, message: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        if self._pending_id is None or self._pending_method is None:
            raise AppServerProtocolError(
                "response arrived with no outstanding request",
                code="response-id",
            )
        response_id = message.get("id")
        if (
            isinstance(response_id, bool)
            or not isinstance(response_id, int)
            or response_id != self._pending_id
        ):
            raise AppServerProtocolError(
                "response ID does not match the outstanding request",
                code="response-id",
            )
        method = self._pending_method
        if "error" in message:
            self._raise_remote_error(message, method)
        _exact_keys(message, required={"id", "result"}, label="response")
        result = _object(message["result"], f"{method} result")
        self._pending_id = None
        self._pending_method = None

        if method == "initialize" and self._state == "initialize":
            _validate_initialize_response(result, self.config)
            if self.config.external_auth is not None:
                self._state = "auth"
                return (
                    {"method": "initialized"},
                    self._request(
                        "account/login/start",
                        {
                            "accessToken": self.config.external_auth.access_token,
                            "chatgptAccountId": (
                                self.config.external_auth.chatgpt_account_id
                            ),
                            "chatgptPlanType": (
                                self.config.external_auth.chatgpt_plan_type
                            ),
                            "type": "chatgptAuthTokens",
                        },
                    ),
                )
            self._state = "config"
            return ({"method": "initialized"}, self._config_request())
        if method == "account/login/start" and self._state == "auth":
            _exact_keys(result, required={"type"}, label="account/login/start result")
            if result["type"] != "chatgptAuthTokens":
                raise AppServerProtocolError(
                    "app-server did not accept external ChatGPT authentication",
                    code="external-auth",
                )
            self._external_auth_accepted = True
            self._state = "config"
            return (self._config_request(),)
        if method == "config/read" and self._state == "config":
            _validate_config_response(result, self.config)
            self._state = "hooks"
            return (
                self._request(
                    "hooks/list",
                    {"cwds": [self.config.neutral_cwd]},
                ),
            )
        if method == "hooks/list" and self._state == "hooks":
            _validate_hooks_response(result, self.config.neutral_cwd)
            self._state = "thread"
            return (self._request("thread/start", self._thread_start_params()),)
        if method == "thread/start" and self._state == "thread":
            self._thread_response = _validate_thread_start_response(result, self.config)
            self._thread_id = self._thread_response["thread"]["id"]
            return self._maybe_start_turn()
        if method == "turn/start" and self._state == "turn":
            self._turn_response = _validate_turn_start_response(
                result,
                expected_thread_id=_required_id(self._thread_id, "thread ID"),
            )
            self._turn_id = self._turn_response["turn"]["id"]
            self._maybe_enter_running()
            return ()
        raise AppServerProtocolError(
            f"response for {method} arrived in state {self._state}",
            code="protocol-order",
        )

    def _accept_notification(
        self, message: dict[str, Any]
    ) -> tuple[dict[str, Any], ...]:
        _exact_keys(message, required={"method", "params"}, label="notification")
        method = _bounded_string(message["method"], "notification method", limit=128)
        if self._state == "terminal":
            raise AppServerProtocolError(
                f"notification arrived after the terminal review result: {method}",
                code="trailing-record",
            )
        params = _object(message["params"], f"{method} params")

        if method == "thread/tokenUsage/updated":
            self._accept_token_usage_updated(params)
            return ()
        if method == "account/rateLimits/updated":
            self._accept_rate_limits_updated(params)
            return ()
        if method == "thread/status/changed":
            self._accept_thread_status_changed(params)
            return ()

        if method == "remoteControl/status/changed":
            self._accept_remote_control_status(params)
            return self._maybe_start_turn()
        if method == "account/login/completed":
            self._accept_login_completed(params)
            return self._maybe_start_turn()
        if method == "account/updated":
            self._accept_account_updated(params)
            return self._maybe_start_turn()

        if method == "thread/started":
            if self._state != "thread" or self._thread_notification is not None:
                raise AppServerProtocolError(
                    "thread/started notification is out of order or duplicated",
                    code="protocol-order",
                )
            _exact_keys(params, required={"thread"}, label="thread/started params")
            thread = _validate_thread(
                _object(params["thread"], "thread/started thread"),
                self.config,
            )
            self._thread_notification = thread
            self._thread_id = thread["id"]
            return self._maybe_start_turn()

        if method == "turn/started":
            if self._state != "turn" or self._turn_notification is not None:
                raise AppServerProtocolError(
                    "turn/started notification is out of order or duplicated",
                    code="protocol-order",
                )
            expected_thread_id = _required_id(self._thread_id, "thread ID")
            _exact_keys(
                params,
                required={"threadId", "turn"},
                label="turn/started params",
            )
            if (
                _identifier(params["threadId"], "turn/started thread ID")
                != expected_thread_id
            ):
                raise AppServerProtocolError(
                    "turn/started thread ID does not match",
                    code="protocol-id",
                )
            turn = _validate_turn(
                _object(params["turn"], "turn/started turn"),
                expected_status="inProgress",
                expected_items=[],
                expected_items_view="notLoaded",
            )
            self._turn_notification = turn
            self._turn_id = turn["id"]
            self._maybe_enter_running()
            return ()

        if method == "item/started":
            self._accept_item_started(params)
            return ()
        if method == "item/agentMessage/delta":
            self._accept_message_delta(params)
            return ()
        if method == "item/reasoning/summaryPartAdded":
            self._accept_reasoning_summary_part_added(params)
            return ()
        if method == "item/reasoning/summaryTextDelta":
            self._accept_reasoning_summary_delta(params)
            return ()
        if method == "item/reasoning/textDelta":
            self._accept_reasoning_text_delta(params)
            return ()
        if method == "item/completed":
            self._accept_item_completed(params)
            return ()
        if method == "turn/completed":
            self._accept_turn_completed(params)
            return ()

        if method in {"error", "warning", "configWarning"}:
            raise AppServerProtocolError(
                f"forbidden app-server notification: {method}",
                code="forbidden-diagnostic-notification",
            )
        if method.startswith("hook/"):
            raise AppServerProtocolError(
                f"forbidden hook notification: {method}",
                code="forbidden-hook-notification",
            )
        raise AppServerProtocolError(
            f"unexpected app-server notification: {method}",
            code="unknown-notification",
        )

    def _maybe_start_turn(self) -> tuple[dict[str, Any], ...]:
        if self._state != "thread":
            return ()
        if self._thread_response is None or self._thread_notification is None:
            return ()
        if self.config.external_auth is not None and not (
            self._external_auth_accepted
            and self._login_completed_notified
            and self._account_updated_notified
            and self._remote_control_notified
        ):
            return ()
        response_thread = self._thread_response["thread"]
        if response_thread != self._thread_notification:
            raise AppServerProtocolError(
                "thread/start response and thread/started notification differ",
                code="thread-attestation-mismatch",
            )
        self._state = "turn"
        thread_id = _required_id(self._thread_id, "thread ID")
        return (
            self._request(
                "turn/start",
                _turn_start_params(
                    prompt=self._prompt,
                    neutral_cwd=self.config.neutral_cwd,
                    model=self.config.expected_model,
                    reasoning_effort=self.config.expected_reasoning_effort,
                    thread_id=thread_id,
                ),
            ),
        )

    def _config_request(self) -> dict[str, Any]:
        return self._request(
            "config/read",
            {"cwd": self.config.neutral_cwd, "includeLayers": True},
        )

    def _accept_remote_control_status(self, params: dict[str, Any]) -> None:
        if self._state not in {"auth", "config", "hooks", "thread"}:
            raise AppServerProtocolError(
                "remote-control notification arrived after review launch",
                code="protocol-order",
            )
        if self._remote_control_notified:
            raise AppServerProtocolError(
                "remote-control notification was duplicated",
                code="protocol-order",
            )
        _exact_keys(
            params,
            required={"installationId", "serverName", "status"},
            optional={"environmentId"},
            label="remote-control status",
        )
        _bounded_string(params["installationId"], "installation ID", limit=512)
        _bounded_string(params["serverName"], "remote-control server", limit=512)
        if params.get("environmentId") is not None:
            _bounded_string(params["environmentId"], "environment ID", limit=512)
        if params["status"] != "disabled":
            raise AppServerProtocolError(
                "remote control is not disabled",
                code="remote-control-enabled",
            )
        self._remote_control_notified = True

    def _accept_login_completed(self, params: dict[str, Any]) -> None:
        if self.config.external_auth is None or self._state not in {
            "auth",
            "config",
            "hooks",
            "thread",
        }:
            raise AppServerProtocolError(
                "unexpected external-auth completion notification",
                code="protocol-order",
            )
        if self._login_completed_notified:
            raise AppServerProtocolError(
                "external-auth completion notification was duplicated",
                code="protocol-order",
            )
        _exact_keys(
            params,
            required={"success"},
            optional={"error", "loginId"},
            label="account/login/completed params",
        )
        if (
            params["success"] is not True
            or params.get("error") is not None
            or params.get("loginId") is not None
        ):
            raise AppServerProtocolError(
                "external ChatGPT authentication did not complete cleanly",
                code="external-auth",
            )
        self._login_completed_notified = True

    def _accept_account_updated(self, params: dict[str, Any]) -> None:
        if self.config.external_auth is None or self._state not in {
            "auth",
            "config",
            "hooks",
            "thread",
        }:
            raise AppServerProtocolError(
                "unexpected account update notification",
                code="protocol-order",
            )
        if self._account_updated_notified:
            raise AppServerProtocolError(
                "account update notification was duplicated",
                code="protocol-order",
            )
        _exact_keys(
            params,
            required=set(),
            optional={"authMode", "planType"},
            label="account/updated params",
        )
        if params.get("authMode") != "chatgptAuthTokens":
            raise AppServerProtocolError(
                "account update did not attest external ChatGPT authentication",
                code="external-auth",
            )
        if params.get("planType") is not None:
            _bounded_string(params["planType"], "account plan type", limit=64)
        self._account_updated_notified = True

    def _maybe_enter_running(self) -> None:
        if self._turn_response is None or self._turn_notification is None:
            return
        response_turn = self._turn_response["turn"]
        if response_turn != self._turn_notification:
            raise AppServerProtocolError(
                "turn/start response and turn/started notification differ",
                code="turn-attestation-mismatch",
            )
        self._state = "running"

    def _accept_item_started(self, params: dict[str, Any]) -> None:
        if (
            self._state != "running"
            or self._active_item is not None
            or self._final_item is not None
        ):
            raise AppServerProtocolError(
                "item/started is out of order, overlaps another item, or follows final",
                code="duplicate-final"
                if self._final_item is not None
                else "protocol-order",
            )
        _exact_keys(
            params,
            required={"item", "startedAtMs", "threadId", "turnId"},
            label="item/started params",
        )
        self._validate_lifecycle_ids(params, "item/started")
        _int64(params["startedAtMs"], "item/started timestamp", nonnegative=True)
        raw_item = _object(params["item"], "item/started item")
        item_type = _bounded_string(
            raw_item.get("type"),
            "item/started item type",
            limit=64,
        )
        if item_type == "userMessage":
            if self._completed_items:
                raise AppServerProtocolError(
                    "user message lifecycle item is not first in the turn",
                    code="protocol-order",
                )
            item = _validate_user_message(raw_item, expected_prompt=self._prompt)
        elif item_type == "reasoning":
            reasoning_count = sum(
                item["type"] == "reasoning" for item in self._completed_items
            )
            if reasoning_count >= APP_SERVER_MAX_REASONING_ITEMS:
                raise AppServerProtocolError(
                    "reasoning item count exceeds its limit",
                    code="commentary-size",
                )
            item = _validate_reasoning_item(raw_item)
            self._reasoning_content = list(item["content"])
            self._reasoning_summary = list(item["summary"])
            self._reasoning_bytes += _string_list_bytes(
                self._reasoning_content
            ) + _string_list_bytes(self._reasoning_summary)
            self._require_reasoning_budget()
        elif item_type == "agentMessage":
            item = _validate_final_agent_message(raw_item)
            self._streamed_parts = []
        else:
            raise AppServerProtocolError(
                f"forbidden thread item type: {item_type!r}",
                code="tool-or-item-forbidden",
            )
        if any(completed["id"] == item["id"] for completed in self._completed_items):
            raise AppServerProtocolError(
                "item ID was reused within the review turn",
                code="protocol-id",
            )
        self._active_item = item

    def _accept_message_delta(self, params: dict[str, Any]) -> None:
        if (
            self._state != "running"
            or self._active_item is None
            or self._active_item["type"] != "agentMessage"
        ):
            raise AppServerProtocolError(
                "agent message delta has no active final item",
                code="protocol-order",
            )
        if self._final_item is not None:
            raise AppServerProtocolError(
                "agent message delta followed the completed item",
                code="protocol-order",
            )
        _exact_keys(
            params,
            required={"delta", "itemId", "threadId", "turnId"},
            label="agent message delta params",
        )
        self._validate_lifecycle_ids(params, "agent message delta")
        if (
            _identifier(params["itemId"], "agent message delta item ID")
            != self._active_item["id"]
        ):
            raise AppServerProtocolError(
                "agent message delta item ID does not match",
                code="protocol-id",
            )
        delta = _text(params["delta"], "agent message delta")
        self._streamed_bytes += len(delta.encode("utf-8", "strict"))
        if self._streamed_bytes > APP_SERVER_COMMENTARY_BYTES:
            raise AppServerProtocolError(
                "streamed agent commentary exceeds its byte limit",
                code="commentary-size",
            )
        self._streamed_parts.append(delta)

    def _accept_reasoning_summary_part_added(self, params: dict[str, Any]) -> None:
        self._require_active_reasoning(
            params,
            label="reasoning summary part",
            required={"itemId", "summaryIndex", "threadId", "turnId"},
        )
        index = _int64(
            params["summaryIndex"],
            "reasoning summary index",
            nonnegative=True,
        )
        if (
            index != len(self._reasoning_summary)
            or index >= APP_SERVER_MAX_REASONING_PARTS
        ):
            raise AppServerProtocolError(
                "reasoning summary part index is not the next bounded index",
                code="protocol-order",
            )
        self._reasoning_summary.append("")

    def _accept_reasoning_summary_delta(self, params: dict[str, Any]) -> None:
        self._require_active_reasoning(
            params,
            label="reasoning summary delta",
            required={"delta", "itemId", "summaryIndex", "threadId", "turnId"},
        )
        index = _int64(
            params["summaryIndex"],
            "reasoning summary delta index",
            nonnegative=True,
        )
        if index >= len(self._reasoning_summary):
            raise AppServerProtocolError(
                "reasoning summary delta has no announced part",
                code="protocol-order",
            )
        delta = _text(params["delta"], "reasoning summary delta")
        self._reasoning_bytes += len(delta.encode("utf-8", "strict"))
        self._require_reasoning_budget()
        self._reasoning_summary[index] += delta

    def _accept_reasoning_text_delta(self, params: dict[str, Any]) -> None:
        self._require_active_reasoning(
            params,
            label="reasoning text delta",
            required={"contentIndex", "delta", "itemId", "threadId", "turnId"},
        )
        index = _int64(
            params["contentIndex"],
            "reasoning content index",
            nonnegative=True,
        )
        if index == len(self._reasoning_content):
            if index >= APP_SERVER_MAX_REASONING_PARTS:
                raise AppServerProtocolError(
                    "reasoning content part count exceeds its limit",
                    code="commentary-size",
                )
            self._reasoning_content.append("")
        elif index > len(self._reasoning_content):
            raise AppServerProtocolError(
                "reasoning text delta skipped a content index",
                code="protocol-order",
            )
        delta = _text(params["delta"], "reasoning text delta")
        self._reasoning_bytes += len(delta.encode("utf-8", "strict"))
        self._require_reasoning_budget()
        self._reasoning_content[index] += delta

    def _require_active_reasoning(
        self,
        params: dict[str, Any],
        *,
        label: str,
        required: set[str],
    ) -> None:
        if (
            self._state != "running"
            or self._active_item is None
            or self._active_item["type"] != "reasoning"
        ):
            raise AppServerProtocolError(
                f"{label} has no active reasoning item",
                code="protocol-order",
            )
        _exact_keys(params, required=required, label=f"{label} params")
        self._validate_lifecycle_ids(params, label)
        if _identifier(params["itemId"], f"{label} item ID") != self._active_item["id"]:
            raise AppServerProtocolError(
                f"{label} item ID does not match",
                code="protocol-id",
            )

    def _require_reasoning_budget(self) -> None:
        if self._reasoning_bytes > APP_SERVER_COMMENTARY_BYTES:
            raise AppServerProtocolError(
                "reasoning output exceeds its byte limit",
                code="commentary-size",
            )

    def _accept_token_usage_updated(self, params: dict[str, Any]) -> None:
        if self._state != "running":
            raise AppServerProtocolError(
                "token-usage notification arrived outside the active turn",
                code="protocol-order",
            )
        self._count_telemetry_notification()
        _exact_keys(
            params,
            required={"threadId", "tokenUsage", "turnId"},
            label="thread/tokenUsage/updated params",
        )
        self._validate_lifecycle_ids(params, "token-usage notification")
        _validate_token_usage(
            _object(params["tokenUsage"], "token-usage notification payload")
        )

    def _accept_rate_limits_updated(self, params: dict[str, Any]) -> None:
        if self._state not in {
            "auth",
            "config",
            "hooks",
            "thread",
            "turn",
            "running",
        }:
            raise AppServerProtocolError(
                "rate-limit notification arrived before initialization",
                code="protocol-order",
            )
        self._count_telemetry_notification()
        _exact_keys(
            params,
            required={"rateLimits"},
            label="account/rateLimits/updated params",
        )
        _validate_rate_limit_snapshot(
            _object(params["rateLimits"], "rate-limit snapshot")
        )

    def _accept_thread_status_changed(self, params: dict[str, Any]) -> None:
        if self._state not in {"thread", "turn", "running"}:
            raise AppServerProtocolError(
                "thread-status notification arrived before thread creation",
                code="protocol-order",
            )
        self._count_telemetry_notification()
        _exact_keys(
            params,
            required={"status", "threadId"},
            label="thread/status/changed params",
        )
        if _identifier(params["threadId"], "thread-status thread ID") != _required_id(
            self._thread_id,
            "thread ID",
        ):
            raise AppServerProtocolError(
                "thread-status thread ID does not match",
                code="protocol-id",
            )
        status = _object(params["status"], "thread status")
        status_type = _bounded_string(
            status.get("type"),
            "thread status type",
            limit=64,
        )
        if status_type == "idle":
            _exact_keys(status, required={"type"}, label="idle thread status")
            return
        if status_type == "active":
            _exact_keys(
                status,
                required={"activeFlags", "type"},
                label="active thread status",
            )
            if status["activeFlags"] != []:
                raise AppServerProtocolError(
                    "thread is waiting on approval or user input",
                    code="tool-or-item-forbidden",
                )
            return
        raise AppServerProtocolError(
            f"forbidden thread status: {status_type!r}",
            code="turn-failed",
        )

    def _count_telemetry_notification(self) -> None:
        self._telemetry_notifications += 1
        if self._telemetry_notifications > APP_SERVER_MAX_TELEMETRY_NOTIFICATIONS:
            raise AppServerProtocolError(
                "telemetry notification count exceeds its limit",
                code="record-size",
            )

    def _accept_item_completed(self, params: dict[str, Any]) -> None:
        if self._state != "running" or self._active_item is None:
            raise AppServerProtocolError(
                "item/completed is out of order or lacks a start record",
                code="duplicate-final"
                if self._final_item is not None
                else "protocol-order",
            )
        _exact_keys(
            params,
            required={"completedAtMs", "item", "threadId", "turnId"},
            label="item/completed params",
        )
        self._validate_lifecycle_ids(params, "item/completed")
        _int64(params["completedAtMs"], "item/completed timestamp", nonnegative=True)
        raw_item = _object(params["item"], "item/completed item")
        item_type = _bounded_string(
            raw_item.get("type"),
            "item/completed item type",
            limit=64,
        )
        if item_type != self._active_item["type"]:
            raise AppServerProtocolError(
                "completed item type does not match the started item",
                code="final-cross-check",
            )
        if item_type == "userMessage":
            item = _validate_user_message(raw_item, expected_prompt=self._prompt)
        elif item_type == "reasoning":
            item = _validate_reasoning_item(raw_item)
        elif item_type == "agentMessage":
            item = _validate_final_agent_message(raw_item)
        else:
            raise AppServerProtocolError(
                f"forbidden thread item type: {item_type!r}",
                code="tool-or-item-forbidden",
            )
        if item["id"] != self._active_item["id"]:
            raise AppServerProtocolError(
                "completed item ID does not match the started item",
                code="protocol-id",
            )
        if item_type == "userMessage":
            if item != self._active_item:
                raise AppServerProtocolError(
                    "completed user message differs from its start record",
                    code="final-cross-check",
                )
        elif item_type == "reasoning":
            if (
                item["content"] != self._reasoning_content
                or item["summary"] != self._reasoning_summary
            ):
                raise AppServerProtocolError(
                    "completed reasoning differs from its bounded stream",
                    code="final-cross-check",
                )
        elif item_type == "agentMessage":
            streamed = self._active_item["text"] + "".join(self._streamed_parts)
            if self._streamed_parts and item["text"] != streamed:
                raise AppServerProtocolError(
                    "completed item text differs from streamed text",
                    code="final-cross-check",
                )
            if not self._streamed_parts and self._active_item["text"] not in {
                "",
                item["text"],
            }:
                raise AppServerProtocolError(
                    "completed item text differs from its start record",
                    code="final-cross-check",
                )
            if self._final_item is not None:
                raise AppServerProtocolError(
                    "review turn produced more than one final item",
                    code="duplicate-final",
                )
            self._final_item = item
        self._completed_items.append(item)
        self._active_item = None

    def _accept_turn_completed(self, params: dict[str, Any]) -> None:
        if (
            self._state != "running"
            or self._active_item is not None
            or self._final_item is None
        ):
            raise AppServerProtocolError(
                "turn/completed arrived before all items and the unique final item completed",
                code="protocol-order",
            )
        _exact_keys(
            params,
            required={"threadId", "turn"},
            label="turn/completed params",
        )
        expected_thread_id = _required_id(self._thread_id, "thread ID")
        if (
            _identifier(params["threadId"], "turn/completed thread ID")
            != expected_thread_id
        ):
            raise AppServerProtocolError(
                "turn/completed thread ID does not match",
                code="protocol-id",
            )
        turn = _validate_turn(
            _object(params["turn"], "turn/completed turn"),
            expected_status="completed",
            expected_items=[],
            expected_items_view="notLoaded",
            alternative_full_items=self._completed_items,
        )
        if turn["id"] != _required_id(self._turn_id, "turn ID"):
            raise AppServerProtocolError(
                "turn/completed turn ID does not match",
                code="protocol-id",
            )
        final_bytes = self._final_item["text"].encode("utf-8", "strict")
        try:
            review_status, final_text = validate_final_message(final_bytes)
        except ValueError as error:
            raise AppServerProtocolError(
                f"final message validation failed: {error}",
                code="invalid-final",
            ) from error
        thread_response = _object(self._thread_response, "thread attestation")
        self._result = AppServerSessionResult(
            review_status=review_status,
            final_text=final_text,
            attestation={
                "approval_policy": thread_response["approvalPolicy"],
                "approvals_reviewer": thread_response["approvalsReviewer"],
                "cli_version": thread_response["thread"]["cliVersion"],
                "ephemeral": thread_response["thread"]["ephemeral"],
                "external_auth": (
                    "accepted" if self._external_auth_accepted else "not-requested"
                ),
                "instruction_sources": list(thread_response["instructionSources"]),
                "model": thread_response["model"],
                "model_attempt": (
                    "explicit_fallback"
                    if self.config.fallback_authorization is not None
                    else "primary"
                ),
                "model_fallback_authorization": (
                    self.config.fallback_authorization.to_json()
                    if self.config.fallback_authorization is not None
                    else None
                ),
                "model_provider": thread_response["modelProvider"],
                "reasoning_effort": thread_response["reasoningEffort"],
                "runtime_workspace_roots": list(
                    thread_response["runtimeWorkspaceRoots"]
                ),
                "remote_control": (
                    "disabled-notification-observed"
                    if self._remote_control_notified
                    else "no-notification"
                ),
                "sandbox": dict(thread_response["sandbox"]),
                "session_source": thread_response["thread"]["source"],
                "thread_path": thread_response["thread"]["path"],
            },
            streamed_message_bytes=self._streamed_bytes,
        )
        self._state = "terminal"

    def _validate_lifecycle_ids(self, params: dict[str, Any], label: str) -> None:
        if _identifier(params["threadId"], f"{label} thread ID") != _required_id(
            self._thread_id,
            "thread ID",
        ):
            raise AppServerProtocolError(
                f"{label} thread ID does not match",
                code="protocol-id",
            )
        if _identifier(params["turnId"], f"{label} turn ID") != _required_id(
            self._turn_id,
            "turn ID",
        ):
            raise AppServerProtocolError(
                f"{label} turn ID does not match",
                code="protocol-id",
            )

    def _reject_server_request(self, message: dict[str, Any]) -> None:
        _exact_keys(
            message,
            required={"id", "method", "params"},
            label="server request",
        )
        _request_id(message["id"], "server request ID")
        method = _bounded_string(message["method"], "server request method", limit=128)
        _object(message["params"], "server request params")
        code = (
            "tool-request-forbidden"
            if method == "item/tool/call"
            else "server-request-forbidden"
        )
        raise AppServerProtocolError(
            f"server request is forbidden in artifact-only review: {method}",
            code=code,
        )

    def _raise_remote_error(self, message: dict[str, Any], method: str) -> None:
        _exact_keys(message, required={"error", "id"}, label="error response")
        error = _object(message["error"], "error response payload")
        _exact_keys(
            error,
            required={"code", "message"},
            optional={"data"},
            label="error response payload",
        )
        remote_code = _int64(error["code"], "remote error code")
        remote_message = _bounded_string(
            error["message"],
            "remote error message",
            limit=4096,
        )
        raise AppServerRemoteError(
            request_method=method,
            remote_code=remote_code,
            remote_message=remote_message,
            remote_data=error.get("data"),
        )

    def _thread_start_params(self) -> dict[str, Any]:
        return {
            "allowProviderModelFallback": False,
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "baseInstructions": APP_SERVER_BASE_INSTRUCTIONS,
            "config": _no_execution_config(
                reasoning_effort=self.config.expected_reasoning_effort
            ),
            "cwd": self.config.neutral_cwd,
            "developerInstructions": APP_SERVER_DEVELOPER_INSTRUCTIONS,
            "dynamicTools": [],
            "environments": [],
            "ephemeral": True,
            "experimentalRawEvents": False,
            "historyMode": "legacy",
            "model": self.config.expected_model,
            "modelProvider": self.config.expected_model_provider,
            "multiAgentMode": "explicitRequestOnly",
            "runtimeWorkspaceRoots": [],
            "sandbox": "read-only",
            "selectedCapabilityRoots": [],
            "threadSource": APP_SERVER_CLIENT_NAME,
        }


def _validate_initialize_response(
    result: dict[str, Any],
    config: AppServerSessionConfig,
) -> None:
    _exact_keys(
        result,
        required={"codexHome", "platformFamily", "platformOs", "userAgent"},
        label="initialize result",
    )
    _validate_absolute_normalized_path(result["codexHome"], "initialize codexHome")
    if result["codexHome"] != config.expected_codex_home:
        raise AppServerProtocolError(
            "initialize used an unexpected Codex home",
            code="codex-home-mismatch",
        )
    _bounded_string(result["platformFamily"], "platform family", limit=64)
    _bounded_string(result["platformOs"], "platform OS", limit=64)
    _bounded_string(result["userAgent"], "user agent", limit=512)


def _validate_config_response(
    result: dict[str, Any],
    session_config: AppServerSessionConfig,
) -> None:
    _exact_keys(
        result,
        required={"config", "layers", "origins"},
        label="config/read result",
    )
    config = _object(result["config"], "config/read config")
    _validate_no_execution_config(config, label="effective config", layer=False)
    layers = result["layers"]
    if not isinstance(layers, list):
        raise AppServerProtocolError(
            "config/read omitted the requested layer inventory",
            code="result-schema",
        )
    layer_types: list[str] = []
    session_layer: dict[str, Any] | None = None
    session_metadata: dict[str, Any] | None = None
    for layer_value in layers:
        layer = _object(layer_value, "config layer")
        _exact_keys(
            layer,
            required={"config", "name", "version"},
            optional={"disabledReason"},
            label="config layer",
        )
        layer_config = _object(layer["config"], "config layer config")
        source_type = _validate_config_layer_source(layer["name"])
        version = _bounded_string(layer["version"], "config layer version", limit=128)
        if layer.get("disabledReason") is not None:
            raise AppServerProtocolError(
                "config/read reported a disabled or ambiguous config layer",
                code="unsafe-config-layer",
            )
        if source_type == "sessionFlags":
            if session_layer is not None:
                raise AppServerProtocolError(
                    "config/read reported duplicate session config layers",
                    code="unsafe-config-layer",
                )
            _validate_no_execution_config(
                layer_config,
                label="session config layer",
                layer=True,
            )
            session_layer = layer_config
            session_metadata = {"name": layer["name"], "version": version}
        elif source_type in {"user", "system"}:
            if layer_config:
                raise AppServerProtocolError(
                    f"ambient {source_type} config layer is not empty",
                    code="unsafe-config-layer",
                )
            if source_type == "user":
                source = _object(layer["name"], "user config layer source")
                expected_file = os.path.join(
                    session_config.expected_codex_home,
                    "config.toml",
                )
                if source["file"] != expected_file or source.get("profile") is not None:
                    raise AppServerProtocolError(
                        "user config layer is not bound to the isolated Codex home",
                        code="unsafe-config-layer",
                    )
        else:
            raise AppServerProtocolError(
                f"config layer source is forbidden for artifact-only review: {source_type}",
                code="unsafe-config-layer",
            )
        layer_types.append(source_type)
    if layer_types != ["sessionFlags", "user", "system"]:
        raise AppServerProtocolError(
            "config layer inventory does not match the pinned isolated contract",
            code="unsafe-config-layer",
        )
    if session_layer is None or session_metadata is None:
        raise AppServerProtocolError(
            "safe session config layer is unavailable",
            code="unsafe-config-layer",
        )

    origins = _object(result["origins"], "config/read origins")
    expected_origins = _config_leaf_origin_keys(session_layer)
    if set(origins) != expected_origins:
        raise AppServerProtocolError(
            "config origins do not exactly bind the safe session layer",
            code="unsafe-config-layer",
        )
    for origin_key, metadata_value in origins.items():
        _bounded_string(origin_key, "config origin key", limit=4096)
        metadata = _object(metadata_value, "config origin metadata")
        _exact_keys(
            metadata,
            required={"name", "version"},
            label="config origin metadata",
        )
        _validate_config_layer_source(metadata["name"])
        _bounded_string(metadata["version"], "config origin version", limit=128)
        if metadata != session_metadata:
            raise AppServerProtocolError(
                "config origin is not bound to the safe session layer",
                code="unsafe-config-layer",
            )


def _validate_no_execution_config(
    config: dict[str, Any],
    *,
    label: str,
    layer: bool,
) -> None:
    unknown = set(config) - _CONFIG_KEYS_0_145_0_ALPHA_18
    if unknown:
        raise AppServerProtocolError(
            f"{label} contains unknown fields: {sorted(unknown)!r}",
            code="unsafe-effective-config",
        )
    if layer:
        if set(config) != _NO_EXECUTION_CONFIG_KEYS:
            raise AppServerProtocolError(
                f"{label} is not the exact no-execution profile",
                code="unsafe-effective-config",
            )
    elif not _NO_EXECUTION_CONFIG_KEYS <= set(config):
        raise AppServerProtocolError(
            f"{label} omits required no-execution settings",
            code="unsafe-effective-config",
        )

    agents = _object(config["agents"], f"{label} agents")
    if (
        not set(agents) <= _AGENT_CONFIG_KEYS
        or agents.get("enabled") is not False
        or any(value is not None for key, value in agents.items() if key != "enabled")
    ):
        raise AppServerProtocolError(
            f"{label} enables agent execution",
            code="unsafe-effective-config",
        )
    if layer and agents != {"enabled": False}:
        raise AppServerProtocolError(
            f"{label} agent settings are not canonical",
            code="unsafe-effective-config",
        )
    if config["analytics"] != {"enabled": False}:
        raise AppServerProtocolError(
            f"{label} does not disable analytics",
            code="unsafe-effective-config",
        )
    expected_apps = {
        "_default": {
            "approvals_reviewer": "user",
            "default_tools_approval_mode": "prompt",
            "destructive_enabled": False,
            "enabled": False,
            "open_world_enabled": False,
        }
    }
    if config["apps"] != expected_apps:
        raise AppServerProtocolError(
            f"{label} does not disable apps and app tools",
            code="unsafe-effective-config",
        )
    for key in (
        "allow_login_shell",
        "check_for_update_on_startup",
        "experimental_use_unified_exec_tool",
        "include_apps_instructions",
        "include_collaboration_mode_instructions",
        "include_environment_context",
        "include_permissions_instructions",
    ):
        if config[key] is not False:
            raise AppServerProtocolError(
                f"{label} does not disable {key}",
                code="unsafe-effective-config",
            )
    for key in ("developer_instructions", "instructions"):
        if config[key] != "":
            raise AppServerProtocolError(
                f"{label} contains ambient {key}",
                code="ambient-instructions",
            )
    features = _object(config["features"], f"{label} features")
    if set(features) != _NO_EXECUTION_FEATURES or any(
        value is not False for value in features.values()
    ):
        raise AppServerProtocolError(
            f"{label} does not exactly disable execution features",
            code="unsafe-effective-config",
        )
    history = _object(config["history"], f"{label} history")
    if history.get("persistence") != "none" or any(
        value is not None for key, value in history.items() if key != "persistence"
    ):
        raise AppServerProtocolError(
            f"{label} enables persistent history",
            code="unsafe-effective-config",
        )
    if layer and history != {"persistence": "none"}:
        raise AppServerProtocolError(
            f"{label} history settings are not canonical",
            code="unsafe-effective-config",
        )
    hooks = _object(config["hooks"], f"{label} hooks")
    if not set(hooks) <= _HOOK_EVENT_KEYS or any(
        value != [] for value in hooks.values()
    ):
        raise AppServerProtocolError(
            f"{label} enables hooks",
            code="unsafe-effective-config",
        )
    if layer and hooks:
        raise AppServerProtocolError(
            f"{label} hook settings are not canonical",
            code="unsafe-effective-config",
        )
    for key in ("marketplaces", "mcp_servers", "plugins", "skills"):
        if config[key] != {}:
            raise AppServerProtocolError(
                f"{label} enables {key}",
                code="unsafe-effective-config",
            )
    if config["notify"] != []:
        raise AppServerProtocolError(
            f"{label} enables notification hooks",
            code="unsafe-effective-config",
        )
    if config["project_doc_fallback_filenames"] != [] or not (
        type(config["project_doc_max_bytes"]) is int
        and config["project_doc_max_bytes"] == 0
    ):
        raise AppServerProtocolError(
            f"{label} enables project instructions",
            code="unsafe-effective-config",
        )
    shell_policy = _object(
        config["shell_environment_policy"],
        f"{label} shell environment policy",
    )
    if (
        not set(shell_policy) <= _SHELL_ENVIRONMENT_POLICY_KEYS
        or shell_policy.get("inherit") != "none"
        or any(
            value is not None for key, value in shell_policy.items() if key != "inherit"
        )
    ):
        raise AppServerProtocolError(
            f"{label} exposes a shell environment",
            code="unsafe-effective-config",
        )
    if layer and shell_policy != {"inherit": "none"}:
        raise AppServerProtocolError(
            f"{label} shell environment settings are not canonical",
            code="unsafe-effective-config",
        )
    tools = _object(config["tools"], f"{label} tools")
    if tools not in ({}, {"web_search": None}) or (layer and tools):
        raise AppServerProtocolError(
            f"{label} enables configured tools",
            code="unsafe-effective-config",
        )
    if config["web_search"] != "disabled":
        raise AppServerProtocolError(
            f"{label} enables web search",
            code="unsafe-effective-config",
        )

    for key, value in config.items():
        if key in _NO_EXECUTION_CONFIG_KEYS:
            continue
        if value is None or value is False or value == {} or value == []:
            continue
        raise AppServerProtocolError(
            f"{label} contains non-passive ambient config at {key}",
            code="unsafe-effective-config",
        )


def _config_leaf_origin_keys(
    value: dict[str, Any],
    *,
    prefix: tuple[str, ...] = (),
) -> set[str]:
    result: set[str] = set()
    for key, child in value.items():
        path = (*prefix, key)
        if isinstance(child, dict):
            result.update(_config_leaf_origin_keys(child, prefix=path))
        elif isinstance(child, list) and not child:
            continue
        else:
            result.add(".".join(path))
    return result


def _validate_config_layer_source(value: Any) -> str:
    source = _object(value, "config layer source")
    source_type = _bounded_string(
        source.get("type"), "config layer source type", limit=64
    )
    schemas: dict[str, tuple[set[str], set[str]]] = {
        "mdm": ({"domain", "key", "type"}, set()),
        "system": ({"file", "type"}, set()),
        "enterpriseManaged": ({"id", "name", "type"}, set()),
        "user": ({"file", "type"}, {"profile"}),
        "project": ({"dotCodexFolder", "type"}, set()),
        "sessionFlags": ({"type"}, set()),
        "legacyManagedConfigTomlFromFile": ({"file", "type"}, set()),
        "legacyManagedConfigTomlFromMdm": ({"type"}, set()),
    }
    schema = schemas.get(source_type)
    if schema is None:
        raise AppServerProtocolError(
            "config layer source type is unknown",
            code="unsafe-config-layer",
        )
    _exact_keys(
        source, required=schema[0], optional=schema[1], label="config layer source"
    )
    for key, child in source.items():
        if key == "type" or child is None:
            continue
        if key in {"dotCodexFolder", "file"}:
            _validate_absolute_normalized_path(child, f"config layer source {key}")
        else:
            _bounded_string(child, f"config layer source {key}", limit=4096)
    return source_type


def _validate_hooks_response(result: dict[str, Any], neutral_cwd: str) -> None:
    _exact_keys(result, required={"data"}, label="hooks/list result")
    expected = [
        {
            "cwd": neutral_cwd,
            "errors": [],
            "hooks": [],
            "warnings": [],
        }
    ]
    if result["data"] != expected:
        raise AppServerProtocolError(
            "hooks/list reported hooks, diagnostics, or an unexpected cwd",
            code="hooks-present",
        )


def _validate_thread_start_response(
    result: dict[str, Any],
    config: AppServerSessionConfig,
) -> dict[str, Any]:
    _exact_keys(
        result,
        required={
            "approvalPolicy",
            "approvalsReviewer",
            "cwd",
            "instructionSources",
            "model",
            "modelProvider",
            "reasoningEffort",
            "runtimeWorkspaceRoots",
            "sandbox",
            "thread",
        },
        optional=_THREAD_RESPONSE_KEYS
        - {
            "approvalPolicy",
            "approvalsReviewer",
            "cwd",
            "instructionSources",
            "model",
            "modelProvider",
            "reasoningEffort",
            "runtimeWorkspaceRoots",
            "sandbox",
            "thread",
        },
        label="thread/start result",
    )
    expected = {
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "cwd": config.neutral_cwd,
        "instructionSources": [],
        "model": config.expected_model,
        "modelProvider": config.expected_model_provider,
        "reasoningEffort": config.expected_reasoning_effort,
        "runtimeWorkspaceRoots": [],
        "sandbox": {"networkAccess": False, "type": "readOnly"},
    }
    for key, expected_value in expected.items():
        if result[key] != expected_value:
            raise AppServerProtocolError(
                f"thread/start attestation mismatch for {key}",
                code="thread-attestation-mismatch",
            )
    if result.get("activePermissionProfile") is not None:
        raise AppServerProtocolError(
            "thread/start selected an unexpected permission profile",
            code="thread-attestation-mismatch",
        )
    if result.get("multiAgentMode", "explicitRequestOnly") != "explicitRequestOnly":
        raise AppServerProtocolError(
            "thread/start enabled an unexpected multi-agent mode",
            code="thread-attestation-mismatch",
        )
    if result.get("serviceTier") is not None:
        _bounded_string(result["serviceTier"], "service tier", limit=128)
    thread = _validate_thread(_object(result["thread"], "thread/start thread"), config)
    return {**result, "thread": thread}


def _validate_thread(
    thread: dict[str, Any],
    config: AppServerSessionConfig,
) -> dict[str, Any]:
    required = {
        "cliVersion",
        "createdAt",
        "cwd",
        "ephemeral",
        "id",
        "modelProvider",
        "path",
        "preview",
        "sessionId",
        "source",
        "status",
        "turns",
        "updatedAt",
    }
    _exact_keys(
        thread,
        required=required,
        optional=_THREAD_KEYS - required,
        label="thread",
    )
    exact_values = {
        "cliVersion": config.expected_cli_version,
        "cwd": config.neutral_cwd,
        "ephemeral": True,
        "modelProvider": config.expected_model_provider,
        "path": None,
        "source": APP_SERVER_SESSION_SOURCE,
        "status": {"type": "idle"},
        "turns": [],
    }
    for key, expected in exact_values.items():
        if thread[key] != expected:
            raise AppServerProtocolError(
                f"thread attestation mismatch for {key}",
                code="thread-attestation-mismatch",
            )
    _identifier(thread["id"], "thread ID")
    _identifier(thread["sessionId"], "session ID")
    _text(thread["preview"], "thread preview")
    created = _int64(thread["createdAt"], "thread createdAt", nonnegative=True)
    updated = _int64(thread["updatedAt"], "thread updatedAt", nonnegative=True)
    if updated < created:
        raise AppServerProtocolError(
            "thread update timestamp predates creation",
            code="result-schema",
        )
    for key in (
        "agentNickname",
        "agentRole",
        "forkedFromId",
        "gitInfo",
        "parentThreadId",
    ):
        if thread.get(key) is not None:
            raise AppServerProtocolError(
                f"thread field {key} is forbidden for a primary ephemeral review",
                code="thread-attestation-mismatch",
            )
    if thread.get("extra") is not None and thread["extra"] != {}:
        raise AppServerProtocolError(
            "thread extra data is not empty",
            code="thread-attestation-mismatch",
        )
    if thread.get("historyMode", "legacy") != "legacy":
        raise AppServerProtocolError(
            "thread history mode is not ephemeral-compatible",
            code="thread-attestation-mismatch",
        )
    if thread.get("name") is not None:
        _bounded_string(thread["name"], "thread name", limit=512)
    if thread.get("recencyAt") is not None:
        _int64(thread["recencyAt"], "thread recencyAt", nonnegative=True)
    if thread.get("threadSource") is not None:
        if thread["threadSource"] != APP_SERVER_CLIENT_NAME:
            raise AppServerProtocolError(
                "thread source is not bound to the independent review client",
                code="thread-attestation-mismatch",
            )
    return thread


def _validate_turn_start_response(
    result: dict[str, Any],
    *,
    expected_thread_id: str,
) -> dict[str, Any]:
    _exact_keys(result, required={"turn"}, label="turn/start result")
    turn = _validate_turn(
        _object(result["turn"], "turn/start turn"),
        expected_status="inProgress",
        expected_items=[],
        expected_items_view="notLoaded",
    )
    if not expected_thread_id:
        raise AppServerProtocolError("thread ID is unavailable", code="protocol-id")
    return {"turn": turn}


def _validate_turn(
    turn: dict[str, Any],
    *,
    expected_status: str,
    expected_items: list[dict[str, Any]],
    expected_items_view: str = "full",
    alternative_full_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    required = {"id", "items", "status"}
    _exact_keys(turn, required=required, optional=_TURN_KEYS - required, label="turn")
    _identifier(turn["id"], "turn ID")
    if turn["status"] != expected_status:
        raise AppServerProtocolError(
            f"turn status is {turn['status']!r}, expected {expected_status!r}",
            code="turn-failed"
            if turn["status"] in {"failed", "interrupted"}
            else "result-schema",
        )
    items_view = turn.get("itemsView", "full")
    items_match = items_view == expected_items_view and turn["items"] == expected_items
    if alternative_full_items is not None:
        items_match = items_match or (
            items_view == "full" and turn["items"] == alternative_full_items
        )
    if not items_match:
        raise AppServerProtocolError(
            "turn items and itemsView do not match the observed lifecycle",
            code="final-cross-check",
        )
    if turn.get("error") is not None:
        raise AppServerProtocolError(
            "turn contains an error payload",
            code="turn-failed",
        )
    for key in ("startedAt", "completedAt", "durationMs"):
        if turn.get(key) is not None:
            _int64(turn[key], f"turn {key}", nonnegative=True)
    return turn


def _validate_reasoning_item(item: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        item,
        required={"id", "type"},
        optional={"content", "summary"},
        label="reasoning item",
    )
    if item["type"] != "reasoning":
        raise AppServerProtocolError(
            f"forbidden thread item type: {item['type']!r}",
            code="tool-or-item-forbidden",
        )
    _identifier(item["id"], "reasoning item ID")
    content = _validate_string_list(item.get("content", []), "reasoning content")
    summary = _validate_string_list(item.get("summary", []), "reasoning summary")
    if (
        _string_list_bytes(content) + _string_list_bytes(summary)
        > APP_SERVER_COMMENTARY_BYTES
    ):
        raise AppServerProtocolError(
            "reasoning item exceeds its byte limit",
            code="commentary-size",
        )
    return {
        "content": content,
        "id": item["id"],
        "summary": summary,
        "type": "reasoning",
    }


def _validate_user_message(
    item: dict[str, Any],
    *,
    expected_prompt: str,
) -> dict[str, Any]:
    _exact_keys(
        item,
        required={"content", "id", "type"},
        optional={"clientId"},
        label="user message item",
    )
    if item["type"] != "userMessage":
        raise AppServerProtocolError(
            f"forbidden thread item type: {item['type']!r}",
            code="tool-or-item-forbidden",
        )
    _identifier(item["id"], "user message item ID")
    if item.get("clientId") is not None:
        _bounded_string(item["clientId"], "user message client ID", limit=512)
    content = item["content"]
    if not isinstance(content, list) or len(content) != 1:
        raise AppServerProtocolError(
            "user message must contain exactly one text input",
            code="final-cross-check",
        )
    text_input = _object(content[0], "user message text input")
    _exact_keys(
        text_input,
        required={"text", "type"},
        optional={"text_elements"},
        label="user message text input",
    )
    if text_input["type"] != "text" or text_input.get("text_elements", []) != []:
        raise AppServerProtocolError(
            "user message contains non-text or decorated input",
            code="tool-or-item-forbidden",
        )
    if _text(text_input["text"], "user message text") != expected_prompt:
        raise AppServerProtocolError(
            "user message does not match the submitted review prompt",
            code="final-cross-check",
        )
    return item


def _validate_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > APP_SERVER_MAX_REASONING_PARTS:
        raise AppServerProtocolError(
            f"{label} is not a bounded array",
            code="record-schema",
        )
    return [_text(part, f"{label} part") for part in value]


def _string_list_bytes(value: list[str]) -> int:
    return sum(len(part.encode("utf-8", "strict")) for part in value)


def _validate_token_usage(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        required={"last", "total"},
        optional={"modelContextWindow"},
        label="token usage",
    )
    for key in ("last", "total"):
        breakdown = _object(value[key], f"token usage {key}")
        required = {
            "cachedInputTokens",
            "inputTokens",
            "outputTokens",
            "reasoningOutputTokens",
            "totalTokens",
        }
        _exact_keys(
            breakdown,
            required=required,
            optional={"cacheWriteInputTokens"},
            label=f"token usage {key}",
        )
        for token_field in required | {"cacheWriteInputTokens"}:
            if token_field in breakdown:
                _int64(
                    breakdown[token_field],
                    f"token usage {key} {token_field}",
                    nonnegative=True,
                )
    if value.get("modelContextWindow") is not None:
        _int64(
            value["modelContextWindow"],
            "token usage model context window",
            nonnegative=True,
        )


_PLAN_TYPES = frozenset(
    {
        "free",
        "go",
        "plus",
        "pro",
        "prolite",
        "team",
        "self_serve_business_usage_based",
        "business",
        "enterprise_cbp_usage_based",
        "enterprise",
        "edu",
        "unknown",
    }
)
_RATE_LIMIT_REACHED_TYPES = frozenset(
    {
        "rate_limit_reached",
        "workspace_owner_credits_depleted",
        "workspace_member_credits_depleted",
        "workspace_owner_usage_limit_reached",
        "workspace_member_usage_limit_reached",
    }
)


def _validate_rate_limit_snapshot(value: dict[str, Any]) -> None:
    allowed = {
        "credits",
        "individualLimit",
        "limitId",
        "limitName",
        "planType",
        "primary",
        "rateLimitReachedType",
        "secondary",
        "spendControlReached",
    }
    _exact_keys(value, required=set(), optional=allowed, label="rate-limit snapshot")
    for key in ("limitId", "limitName"):
        if value.get(key) is not None:
            _bounded_string(value[key], f"rate-limit {key}", limit=512)
    if value.get("planType") is not None and value["planType"] not in _PLAN_TYPES:
        raise AppServerProtocolError(
            "rate-limit plan type is unknown",
            code="record-schema",
        )
    reached = value.get("rateLimitReachedType")
    if reached is not None and reached not in _RATE_LIMIT_REACHED_TYPES:
        raise AppServerProtocolError(
            "rate-limit reached type is unknown",
            code="record-schema",
        )
    if (
        value.get("spendControlReached") is not None
        and type(value["spendControlReached"]) is not bool
    ):
        raise AppServerProtocolError(
            "rate-limit spend-control state is not boolean",
            code="record-schema",
        )
    if value.get("credits") is not None:
        _validate_credits_snapshot(_object(value["credits"], "credits snapshot"))
    if value.get("individualLimit") is not None:
        _validate_spend_control_snapshot(
            _object(value["individualLimit"], "individual spend-control limit")
        )
    for key in ("primary", "secondary"):
        if value.get(key) is not None:
            _validate_rate_limit_window(_object(value[key], f"rate-limit {key} window"))


def _validate_credits_snapshot(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        required={"hasCredits", "unlimited"},
        optional={"balance"},
        label="credits snapshot",
    )
    for key in ("hasCredits", "unlimited"):
        if type(value[key]) is not bool:
            raise AppServerProtocolError(
                f"credits snapshot {key} is not boolean",
                code="record-schema",
            )
    if value.get("balance") is not None:
        _bounded_string(value["balance"], "credits balance", limit=256)


def _validate_spend_control_snapshot(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        required={"limit", "remainingPercent", "resetsAt", "used"},
        label="individual spend-control limit",
    )
    _bounded_string(value["limit"], "spend-control limit", limit=256)
    _bounded_string(value["used"], "spend-control used", limit=256)
    _int64(value["remainingPercent"], "spend-control remaining percent")
    _int64(value["resetsAt"], "spend-control reset timestamp")


def _validate_rate_limit_window(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        required={"usedPercent"},
        optional={"resetsAt", "windowDurationMins"},
        label="rate-limit window",
    )
    _int64(value["usedPercent"], "rate-limit used percent")
    for key in ("resetsAt", "windowDurationMins"):
        if value.get(key) is not None:
            _int64(value[key], f"rate-limit window {key}")


def _validate_final_agent_message(item: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        item,
        required={"id", "phase", "text", "type"},
        optional={"memoryCitation"},
        label="agent message item",
    )
    if item["type"] != "agentMessage":
        raise AppServerProtocolError(
            f"forbidden thread item type: {item['type']!r}",
            code="tool-or-item-forbidden",
        )
    if item["phase"] != "final_answer":
        raise AppServerProtocolError(
            "agent message phase is not final_answer",
            code="invalid-message-phase",
        )
    if item.get("memoryCitation") is not None:
        raise AppServerProtocolError(
            "memory-backed output is forbidden for artifact-only review",
            code="tool-or-item-forbidden",
        )
    _identifier(item["id"], "agent message item ID")
    text = _text(item["text"], "agent message text")
    if len(text.encode("utf-8", "strict")) > FINAL_MESSAGE_BYTES:
        raise AppServerProtocolError(
            "agent message text exceeds the final-message byte limit",
            code="invalid-final",
        )
    return item


def _validate_json_tree(value: Any, *, depth: int = 1) -> None:
    if depth > APP_SERVER_MAX_JSON_DEPTH:
        raise AppServerProtocolError(
            "protocol JSON exceeds its nesting-depth limit",
            code="json-depth",
        )
    if value is None or isinstance(value, (bool, int)):
        if isinstance(value, int) and not isinstance(value, bool):
            _int64(value, "JSON integer")
        return
    if isinstance(value, float):
        raise AppServerProtocolError(
            "protocol JSON floating-point numbers are forbidden",
            code="invalid-json-number",
        )
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise AppServerProtocolError(
                "protocol JSON contains an unpaired surrogate",
                code="malformed-json",
            ) from error
        return
    if isinstance(value, list):
        for child in value:
            _validate_json_tree(child, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise AppServerProtocolError(
                    "protocol JSON object key is not a string",
                    code="record-schema",
                )
            _validate_json_tree(key, depth=depth + 1)
            _validate_json_tree(child, depth=depth + 1)
        return
    raise AppServerProtocolError(
        f"protocol JSON contains unsupported type {type(value).__name__}",
        code="record-schema",
    )


def _exact_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    label: str,
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - set(optional)
    if missing or extra:
        raise AppServerProtocolError(
            f"{label} keys are invalid; missing={sorted(missing)!r}, extra={sorted(extra)!r}",
            code="record-schema",
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AppServerProtocolError(f"{label} is not an object", code="record-schema")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AppServerProtocolError(f"{label} is not text", code="record-schema")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise AppServerProtocolError(
            f"{label} contains an unpaired surrogate",
            code="record-schema",
        ) from error
    return value


def _bounded_string(value: Any, label: str, *, limit: int) -> str:
    text = _text(value, label)
    encoded = text.encode("utf-8", "strict")
    if not encoded or len(encoded) > limit or "\x00" in text:
        raise AppServerProtocolError(
            f"{label} length is outside the accepted range",
            code="record-schema",
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise AppServerProtocolError(
            f"{label} contains a control character",
            code="record-schema",
        )
    return text


def _identifier(value: Any, label: str) -> str:
    return _bounded_string(value, label, limit=APP_SERVER_MAX_IDENTIFIER_BYTES)


def _required_id(value: str | None, label: str) -> str:
    if value is None:
        raise AppServerProtocolError(f"{label} is unavailable", code="protocol-id")
    return value


def _request_id(value: Any, label: str) -> int | str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AppServerProtocolError(f"{label} is invalid", code="record-schema")
    if isinstance(value, int):
        return _int64(value, label)
    return _identifier(value, label)


def _int64(value: Any, label: str, *, nonnegative: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AppServerProtocolError(f"{label} is not an integer", code="record-schema")
    if not _INT64_MIN <= value <= _INT64_MAX or (nonnegative and value < 0):
        raise AppServerProtocolError(
            f"{label} is outside int64 bounds", code="record-schema"
        )
    return value


def _validate_absolute_normalized_path(value: Any, label: str) -> str:
    path = _bounded_string(value, label, limit=_MAX_PROTOCOL_PATH_BYTES)
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise AppServerProtocolError(
            f"{label} is not an absolute normalized path",
            code="record-schema",
        )
    return path


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
