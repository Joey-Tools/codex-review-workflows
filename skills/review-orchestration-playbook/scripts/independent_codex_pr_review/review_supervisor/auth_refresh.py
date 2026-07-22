from __future__ import annotations

import math
import os
import pathlib
import selectors
import signal
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Protocol

from .appserver_protocol import (
    APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
    AppServerProtocolError,
    decode_json_line,
    encode_json_line,
)
from .constants import APP_SERVER_CLIENT_NAME, VERSION
from .secureio import require_python_313
from .signal_relay import ForwardedHostSignal, HostSignalRelay


READ_CHUNK_BYTES = 64 * 1024
MAX_STDIN_BYTES = 16 * 1024
DEFAULT_STDOUT_BYTES = 256 * 1024
DEFAULT_STDERR_BYTES = 64 * 1024
DEFAULT_RECORD_BYTES = 64 * 1024
DEFAULT_TOTAL_SECONDS = 20.0
DEFAULT_SHUTDOWN_SECONDS = 3.0
DEFAULT_CLEANUP_RESERVE_SECONDS = 3.0
DEFAULT_TERM_GRACE_SECONDS = 0.25

SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

HARD_MAX_STDOUT_BYTES = 1024 * 1024
HARD_MAX_STDERR_BYTES = 256 * 1024
HARD_MAX_RECORD_BYTES = 256 * 1024
HARD_MAX_TOTAL_SECONDS = 60.0
HARD_MAX_SHUTDOWN_SECONDS = 10.0
HARD_MAX_CLEANUP_RESERVE_SECONDS = 10.0

_ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TMPDIR",
    }
)
_FIXED_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PATH": SAFE_PATH,
}
_APP_SERVER_ARGUMENTS = (
    "app-server",
    "--session-source",
    "exec",
    "--strict-config",
    *APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
    "--stdio",
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


class ManagedAuthRefreshError(RuntimeError):
    def __init__(self, message: str, *, stage: str, code: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code


@dataclass(frozen=True, slots=True)
class ManagedAuthRefreshLimits:
    max_stdout_bytes: int = DEFAULT_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_STDERR_BYTES
    max_record_bytes: int = DEFAULT_RECORD_BYTES
    total_seconds: float = DEFAULT_TOTAL_SECONDS
    shutdown_seconds: float = DEFAULT_SHUTDOWN_SECONDS
    cleanup_reserve_seconds: float = DEFAULT_CLEANUP_RESERVE_SECONDS
    term_grace_seconds: float = DEFAULT_TERM_GRACE_SECONDS

    def validate(self) -> None:
        _bounded_integer(
            self.max_stdout_bytes,
            label="stdout byte limit",
            maximum=HARD_MAX_STDOUT_BYTES,
        )
        _bounded_integer(
            self.max_stderr_bytes,
            label="stderr byte limit",
            maximum=HARD_MAX_STDERR_BYTES,
        )
        _bounded_integer(
            self.max_record_bytes,
            label="record byte limit",
            maximum=HARD_MAX_RECORD_BYTES,
        )
        if self.max_record_bytes > self.max_stdout_bytes:
            raise ValueError("record byte limit cannot exceed stdout byte limit")
        _bounded_seconds(
            self.total_seconds,
            label="total duration",
            maximum=HARD_MAX_TOTAL_SECONDS,
        )
        _bounded_seconds(
            self.shutdown_seconds,
            label="shutdown duration",
            maximum=HARD_MAX_SHUTDOWN_SECONDS,
        )
        _bounded_seconds(
            self.cleanup_reserve_seconds,
            label="cleanup reserve",
            maximum=HARD_MAX_CLEANUP_RESERVE_SECONDS,
        )
        _bounded_seconds(
            self.term_grace_seconds,
            label="termination grace",
            maximum=HARD_MAX_CLEANUP_RESERVE_SECONDS,
        )
        if self.cleanup_reserve_seconds >= self.total_seconds:
            raise ValueError("cleanup reserve must be shorter than total duration")
        if self.term_grace_seconds >= self.cleanup_reserve_seconds:
            raise ValueError("termination grace must be shorter than cleanup reserve")


@dataclass(frozen=True, slots=True)
class ManagedAuthRefreshClosureReceipt:
    pid: int
    process_group_id: int
    session_id: int
    profile_sha256: str
    exit_code: int
    leader_reaped: bool
    process_group_empty: bool
    stdio_closed: bool


@dataclass(frozen=True, slots=True)
class ManagedAuthRefreshResult:
    refresh_completed: bool
    managed_auth_verified: bool
    codex_home_verified: bool
    requires_openai_auth: bool
    process_closure: ManagedAuthRefreshClosureReceipt | None = None


@dataclass(frozen=True, slots=True)
class _SanitizedFailure:
    message: str
    stage: str
    code: str
    kind: str = "managed"

    @classmethod
    def from_error(cls, error: ManagedAuthRefreshError) -> _SanitizedFailure:
        return cls(message=str(error), stage=error.stage, code=error.code)

    @classmethod
    def from_exception(cls, error: BaseException) -> _SanitizedFailure:
        if isinstance(error, ManagedAuthRefreshError):
            return cls.from_error(error)
        if isinstance(error, TypeError):
            return cls(str(error), "admission", "invalid-argument", "type")
        if isinstance(error, ValueError):
            return cls(str(error), "admission", "invalid-argument", "value")
        if isinstance(error, KeyboardInterrupt):
            return cls("", "runtime", "interrupted", "keyboard-interrupt")
        if isinstance(error, SystemExit):
            return cls("", "runtime", "interrupted", "system-exit")
        return cls(
            "managed-auth refresh failed at a closed runtime boundary",
            "runtime",
            "runtime-failed",
        )

    def exception(self) -> BaseException:
        if self.kind == "type":
            return TypeError(self.message)
        if self.kind == "value":
            return ValueError(self.message)
        if self.kind == "keyboard-interrupt":
            return KeyboardInterrupt()
        if self.kind == "system-exit":
            return SystemExit(1)
        return ManagedAuthRefreshError(
            self.message,
            stage=self.stage,
            code=self.code,
        )


@dataclass(frozen=True, slots=True)
class _BoundaryOutcome:
    result: ManagedAuthRefreshResult | None = None
    failure: _SanitizedFailure | None = None
    signal_relay: HostSignalRelay | None = None


@dataclass(frozen=True, slots=True)
class ManagedAuthSnapshotIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int
    flags: int = 0
    generation: int = 0

    @classmethod
    def from_stat(cls, value: os.stat_result) -> ManagedAuthSnapshotIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            link_count=value.st_nlink,
            uid=value.st_uid,
            gid=value.st_gid,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
            flags=getattr(value, "st_flags", 0),
            generation=getattr(value, "st_gen", 0),
        )


@dataclass(frozen=True, slots=True)
class ManagedAuthSnapshotEvidence:
    sha256: str
    identity: ManagedAuthSnapshotIdentity


@dataclass(frozen=True, slots=True)
class ManagedAuthRefreshLaunchRequest:
    arguments: tuple[str, ...]
    cwd: pathlib.Path
    environment: Mapping[str, str]
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    deadline_monotonic: float
    expected_snapshot: ManagedAuthSnapshotEvidence
    expected_profile_sha256: str


@dataclass(frozen=True, slots=True)
class ManagedAuthRefreshProcess:
    pid: int
    process_group_id: int
    session_id: int
    snapshot: ManagedAuthSnapshotEvidence
    profile_sha256: str


class ManagedAuthRefreshLaunchCapability(Protocol):
    """Authenticated, profile-bound launcher supplied by the custody layer.

    ``launch`` must honor the request deadline. It must return a live direct-child
    receipt after secure exec acknowledgement, or clean every process and descriptor
    it created before raising. The capability, not this module, owns executable paths.
    """

    @property
    def authenticated_snapshot(self) -> ManagedAuthSnapshotEvidence: ...

    @property
    def profile_sha256(self) -> str: ...

    def launch(
        self,
        request: ManagedAuthRefreshLaunchRequest,
    ) -> ManagedAuthRefreshProcess: ...

    def record_closure(
        self,
        receipt: ManagedAuthRefreshClosureReceipt,
    ) -> None: ...


class _ManagedAuthRefreshProtocol:
    """Require initialize, remote-disabled, and a valid managed account response."""

    def __init__(self, *, expected_codex_home: pathlib.Path) -> None:
        self._expected_codex_home = str(expected_codex_home)
        self._state = "new"
        self._account_update_seen = False
        self._requires_openai_auth: bool | None = None

    @property
    def complete(self) -> bool:
        return self._state == "complete"

    def start(self) -> tuple[dict[str, Any], ...]:
        if self._state != "new":
            raise _protocol_error("protocol-order")
        self._state = "initialize"
        return (
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {"experimentalApi": True},
                    "clientInfo": {
                        "name": APP_SERVER_CLIENT_NAME,
                        "title": "Managed Auth Refresh",
                        "version": VERSION,
                    },
                },
            },
        )

    def accept(self, message: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        if self.complete:
            if message.get("method") == "account/updated":
                self._accept_notification(message)
                return ()
            raise _protocol_error("trailing-record")
        if "id" in message and "method" in message:
            raise _protocol_error("server-request")
        if "id" in message:
            return self._accept_response(message)
        if "method" in message:
            self._accept_notification(message)
            return ()
        raise _protocol_error("record-schema")

    def finish(self) -> ManagedAuthRefreshResult:
        if not self.complete or self._requires_openai_auth is None:
            raise _protocol_error("abnormal-eof")
        return ManagedAuthRefreshResult(
            refresh_completed=True,
            managed_auth_verified=True,
            codex_home_verified=True,
            requires_openai_auth=self._requires_openai_auth,
        )

    def _accept_response(
        self,
        message: dict[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        expected_id = 1 if self._state == "initialize" else 2
        response_id = message.get("id")
        if type(response_id) is not int or response_id != expected_id:
            raise _protocol_error("response-id")
        if "error" in message:
            _exact_keys(message, {"error", "id"})
            raise _protocol_error("remote-error")
        _exact_keys(message, {"id", "result"})
        result = _object(message["result"])
        if self._state == "initialize":
            self._validate_initialize(result)
            self._state = "remote-control-status"
            return (
                {"method": "initialized"},
                {
                    "id": 2,
                    "method": "account/read",
                    "params": {"refreshToken": True},
                },
            )
        if self._state == "remote-control-status":
            raise _protocol_error("remote-control-status-missing")
        if self._state in {"account-update", "account-response"}:
            self._requires_openai_auth = self._validate_account(result)
            self._state = "complete"
            return ()
        raise _protocol_error("protocol-order")

    def _validate_initialize(self, result: dict[str, Any]) -> None:
        _exact_keys(
            result,
            {"codexHome", "platformFamily", "platformOs", "userAgent"},
        )
        if result.get("codexHome") != self._expected_codex_home:
            raise _protocol_error("codex-home-mismatch")
        _bounded_text(result.get("platformFamily"), maximum=64)
        _bounded_text(result.get("platformOs"), maximum=64)
        _bounded_text(result.get("userAgent"), maximum=512)

    def _validate_account(self, result: dict[str, Any]) -> bool:
        _exact_keys(result, {"account", "requiresOpenaiAuth"})
        requires_openai_auth = result.get("requiresOpenaiAuth")
        if type(requires_openai_auth) is not bool:
            raise _protocol_error("account-schema")
        account = _object(result.get("account"))
        _exact_keys(account, {"email", "planType", "type"})
        if account.get("type") != "chatgpt":
            raise _protocol_error("managed-auth-required")
        private_email = account.get("email")
        if private_email is not None:
            _bounded_text(private_email, maximum=512)
        _validate_plan_type(account.get("planType"))
        return requires_openai_auth

    def _accept_notification(self, message: dict[str, Any]) -> None:
        _exact_keys(message, {"method", "params"})
        method = message.get("method")
        if not isinstance(method, str):
            raise _protocol_error("notification-schema")
        params = _object(message.get("params"))
        if method == "account/updated":
            if self._state not in {"account-update", "complete"}:
                raise _protocol_error("protocol-order")
            if self._account_update_seen:
                raise _protocol_error("protocol-order")
            _exact_keys(params, {"authMode"}, optional={"planType"})
            if params.get("authMode") != "chatgpt":
                raise _protocol_error("managed-auth-required")
            if params.get("planType") is not None:
                _validate_plan_type(params["planType"])
            self._account_update_seen = True
            if self._state == "account-update":
                self._state = "account-response"
            return
        if method == "remoteControl/status/changed":
            if self._state != "remote-control-status":
                raise _protocol_error("protocol-order")
            _exact_keys(
                params,
                {"installationId", "serverName", "status"},
                optional={"environmentId"},
            )
            _bounded_text(params.get("installationId"), maximum=512)
            _bounded_text(params.get("serverName"), maximum=512)
            if params.get("environmentId") is not None:
                _bounded_text(params["environmentId"], maximum=512)
            if params.get("status") != "disabled":
                raise _protocol_error("remote-control-enabled")
            self._state = "account-update"
            return
        raise _protocol_error("unknown-notification")


def refresh_managed_auth(
    *,
    launch_capability: ManagedAuthRefreshLaunchCapability,
    expected_snapshot: ManagedAuthSnapshotEvidence,
    expected_profile_sha256: str,
    neutral_cwd: pathlib.Path,
    environment: Mapping[str, str] | None = None,
    expected_codex_home: pathlib.Path | None = None,
    limits: ManagedAuthRefreshLimits = ManagedAuthRefreshLimits(),
    liveness_checkpoint: Callable[[], None] = lambda: None,
) -> ManagedAuthRefreshResult:
    """Refresh managed auth through a caller-authenticated secure launch capability.

    The caller owns snapshot authentication, digest custody, and the no-child launch
    profile. This helper accepts no executable path and never establishes a new
    snapshot baseline, searches PATH, reads auth files, or sends a model request.
    """

    outcome = _refresh_managed_auth_boundary(
        launch_capability=launch_capability,
        expected_snapshot=expected_snapshot,
        expected_profile_sha256=expected_profile_sha256,
        neutral_cwd=neutral_cwd,
        environment=environment,
        expected_codex_home=expected_codex_home,
        limits=limits,
        liveness_checkpoint=liveness_checkpoint,
    )
    del launch_capability, expected_snapshot, expected_profile_sha256, environment
    return _finish_boundary(outcome)


def _refresh_managed_auth_boundary(
    *,
    launch_capability: ManagedAuthRefreshLaunchCapability,
    expected_snapshot: ManagedAuthSnapshotEvidence,
    expected_profile_sha256: str,
    neutral_cwd: pathlib.Path,
    environment: Mapping[str, str] | None,
    expected_codex_home: pathlib.Path | None,
    limits: ManagedAuthRefreshLimits,
    liveness_checkpoint: Callable[[], None],
) -> _BoundaryOutcome:
    relay: HostSignalRelay | None = None
    try:
        require_python_313()
        if not callable(liveness_checkpoint):
            raise TypeError("managed-auth liveness checkpoint must be callable")
        liveness_checkpoint()
        limits.validate()
        _validate_containment_host()
        snapshot = _validated_snapshot_evidence(
            expected_snapshot,
            label="expected snapshot",
        )
        profile_sha256 = _validated_sha256(
            expected_profile_sha256,
            label="expected secure profile digest",
        )
        _validate_launch_capability(
            launch_capability,
            expected_snapshot=snapshot,
            expected_profile_sha256=profile_sha256,
        )
        liveness_checkpoint()
        cwd = _validate_neutral_cwd(neutral_cwd)
        child_environment, normal_codex_home = _validated_environment(environment)
        if expected_codex_home is not None:
            expected = _validate_absolute_normalized_path(
                expected_codex_home,
                label="expected Codex home",
            )
            if expected != normal_codex_home:
                raise ManagedAuthRefreshError(
                    "expected Codex home is not the normal child environment home",
                    stage="admission",
                    code="codex-home-mismatch",
                )

        protocol = _ManagedAuthRefreshProtocol(
            expected_codex_home=normal_codex_home,
        )
        with HostSignalRelay() as relay:
            result = _run_bounded_refresh_process(
                launch_capability=launch_capability,
                expected_snapshot=snapshot,
                expected_profile_sha256=profile_sha256,
                cwd=cwd,
                environment=child_environment,
                protocol=protocol,
                limits=limits,
                relay=relay,
                liveness_checkpoint=liveness_checkpoint,
            )
        if relay.received is not None:
            return _BoundaryOutcome(signal_relay=relay)
        return _BoundaryOutcome(result=result)
    except BaseException as error:
        if relay is not None and relay.received is not None:
            return _BoundaryOutcome(signal_relay=relay)
        return _BoundaryOutcome(failure=_SanitizedFailure.from_exception(error))


def _finish_boundary(outcome: _BoundaryOutcome) -> ManagedAuthRefreshResult:
    if outcome.signal_relay is not None:
        redelivery_failure: str | None = None
        try:
            outcome.signal_relay.redeliver()
        except KeyboardInterrupt:
            redelivery_failure = "keyboard-interrupt"
        except SystemExit:
            redelivery_failure = "system-exit"
        except BaseException:
            redelivery_failure = "failed"
        if redelivery_failure == "keyboard-interrupt":
            raise KeyboardInterrupt() from None
        if redelivery_failure == "system-exit":
            raise SystemExit(1) from None
        if redelivery_failure == "failed":
            raise ManagedAuthRefreshError(
                "managed-auth host signal could not be redelivered safely",
                stage="runtime",
                code="signal-redelivery",
            ) from None
        raise ManagedAuthRefreshError(
            "managed-auth refresh was interrupted by a host signal",
            stage="runtime",
            code="signal-interrupted",
        ) from None
    if outcome.failure is not None:
        raise outcome.failure.exception() from None
    if outcome.result is None:
        raise ManagedAuthRefreshError(
            "managed-auth refresh produced no result",
            stage="runtime",
            code="missing-result",
        ) from None
    return outcome.result


def _run_bounded_refresh_process(
    *,
    launch_capability: ManagedAuthRefreshLaunchCapability,
    expected_snapshot: ManagedAuthSnapshotEvidence,
    expected_profile_sha256: str,
    cwd: pathlib.Path,
    environment: dict[str, str],
    protocol: _ManagedAuthRefreshProtocol,
    limits: ManagedAuthRefreshLimits,
    relay: HostSignalRelay,
    liveness_checkpoint: Callable[[], None],
) -> ManagedAuthRefreshResult:
    start = time.monotonic()
    total_deadline = start + limits.total_seconds
    work_deadline = total_deadline - limits.cleanup_reserve_seconds
    selector: selectors.BaseSelector | None = None
    descriptors: set[int] = set()
    process_pid: int | None = None
    launched: ManagedAuthRefreshProcess | None = None
    process_reaped = False
    process_settled = False
    failure: _SanitizedFailure | BaseException | None = None
    result: ManagedAuthRefreshResult | None = None
    outbound = bytearray()
    stdout_buffer = bytearray()
    stdout_bytes = 0
    stderr_bytes = 0

    try:
        selector = selectors.DefaultSelector()
        stdin_read, stdin_write = _tracked_pipe(descriptors)
        stdout_read, stdout_write = _tracked_pipe(descriptors)
        stderr_read, stderr_write = _tracked_pipe(descriptors)
        _runtime_checkpoint(relay, liveness_checkpoint)
        if time.monotonic() >= work_deadline:
            raise _runtime_error("launch-timeout")
        _validate_launch_capability(
            launch_capability,
            expected_snapshot=expected_snapshot,
            expected_profile_sha256=expected_profile_sha256,
            stage="launch",
        )
        request = ManagedAuthRefreshLaunchRequest(
            arguments=_APP_SERVER_ARGUMENTS,
            cwd=cwd,
            environment=MappingProxyType(environment),
            stdin_fd=stdin_read,
            stdout_fd=stdout_write,
            stderr_fd=stderr_write,
            deadline_monotonic=work_deadline,
            expected_snapshot=expected_snapshot,
            expected_profile_sha256=expected_profile_sha256,
        )
        launched = _launch_refresh_process(launch_capability, request)
        process_pid = _validated_direct_child_pid(launched)
        relay.bind(process_pid)
        _validate_launch_receipt(
            launched,
            expected_snapshot=expected_snapshot,
            expected_profile_sha256=expected_profile_sha256,
        )
        _validate_launch_capability(
            launch_capability,
            expected_snapshot=expected_snapshot,
            expected_profile_sha256=expected_profile_sha256,
            stage="launch",
        )
        _runtime_checkpoint(relay, liveness_checkpoint)
        if time.monotonic() >= work_deadline:
            raise _runtime_error("launch-timeout")
        if _terminal_status(process_pid) is not None:
            raise ManagedAuthRefreshError(
                "authenticated snapshot process exited during secure launch",
                stage="launch",
                code="launch-failed",
            )

        for descriptor in (stdin_read, stdout_write, stderr_write):
            os.close(descriptor)
            descriptors.remove(descriptor)
        for descriptor in (stdin_write, stdout_read, stderr_read):
            os.set_blocking(descriptor, False)
        selector.register(stdout_read, selectors.EVENT_READ, "stdout")
        selector.register(stderr_read, selectors.EVENT_READ, "stderr")
        _queue_messages(outbound, protocol.start(), MAX_STDIN_BYTES)
        selector.register(stdin_write, selectors.EVENT_WRITE, "stdin")

        stdin_open = True
        stdout_open = True
        stderr_open = True
        shutdown_deadline: float | None = None
        while True:
            _runtime_checkpoint(relay, liveness_checkpoint)
            if not stdout_open and not protocol.complete:
                if stdout_buffer:
                    raise _runtime_error("partial-record")
                raise _protocol_error("abnormal-eof")
            terminal = _terminal_status(process_pid)
            if terminal is not None and not stdout_open and not stderr_open:
                break
            now = time.monotonic()
            active_deadline = work_deadline
            if shutdown_deadline is not None:
                active_deadline = min(active_deadline, shutdown_deadline)
            if now >= active_deadline:
                code = (
                    "shutdown-timeout"
                    if shutdown_deadline is not None
                    else "total-timeout"
                )
                raise _runtime_error(code)

            events = selector.select(min(0.05, active_deadline - now))
            _runtime_checkpoint(relay, liveness_checkpoint)
            for key, mask in events:
                if key.data == "stdin" and mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(key.fd, outbound)
                    except (BrokenPipeError, OSError):
                        raise _runtime_error("stdin-closed") from None
                    if written <= 0:
                        raise _runtime_error("stdin-progress")
                    _zero_prefix(outbound, written)
                    if not outbound:
                        selector.unregister(key.fd)
                elif key.data == "stdout" and mask & selectors.EVENT_READ:
                    scratch, count = _read_scratch(
                        key.fd,
                        maximum=limits.max_stdout_bytes,
                        observed=stdout_bytes,
                    )
                    try:
                        if count == 0:
                            selector.unregister(key.fd)
                            os.close(key.fd)
                            descriptors.remove(key.fd)
                            stdout_open = False
                            continue
                        stdout_bytes += count
                        if stdout_bytes > limits.max_stdout_bytes:
                            raise _runtime_error("stdout-limit")
                        stdout_buffer.extend(memoryview(scratch)[:count])
                        _consume_stdout_records(
                            stdout_buffer=stdout_buffer,
                            outbound=outbound,
                            protocol=protocol,
                            limits=limits,
                        )
                        if outbound and stdin_open:
                            try:
                                selector.register(
                                    stdin_write,
                                    selectors.EVENT_WRITE,
                                    "stdin",
                                )
                            except KeyError:
                                pass
                    finally:
                        _zero_bytearray(scratch)
                elif key.data == "stderr" and mask & selectors.EVENT_READ:
                    scratch, count = _read_scratch(
                        key.fd,
                        maximum=limits.max_stderr_bytes,
                        observed=stderr_bytes,
                    )
                    try:
                        if count == 0:
                            selector.unregister(key.fd)
                            os.close(key.fd)
                            descriptors.remove(key.fd)
                            stderr_open = False
                            continue
                        stderr_bytes += count
                        if stderr_bytes > limits.max_stderr_bytes:
                            raise _runtime_error("stderr-limit")
                    finally:
                        _zero_bytearray(scratch)

            if protocol.complete and not outbound and stdin_open:
                try:
                    selector.unregister(stdin_write)
                except KeyError:
                    pass
                os.close(stdin_write)
                descriptors.remove(stdin_write)
                stdin_open = False
                shutdown_deadline = min(
                    work_deadline,
                    time.monotonic() + limits.shutdown_seconds,
                )

        if stdout_buffer:
            raise _runtime_error("partial-record")
        if stdin_open:
            raise _runtime_error("stdin-not-closed")
        result = protocol.finish()
        exit_code = _reap_process(
            process_pid,
            deadline=work_deadline,
            relay=relay,
        )
        process_reaped = True
        closure = _managed_auth_closure_receipt(launched, exit_code)
        launch_capability.record_closure(closure)
        process_settled = True
        if exit_code != 0:
            raise _runtime_error("nonzero-exit")
        result = replace(result, process_closure=closure)
        _runtime_checkpoint(relay, liveness_checkpoint)
    except BaseException as error:
        if isinstance(error, ManagedAuthRefreshError):
            failure = _SanitizedFailure.from_error(error)
        elif isinstance(error, (KeyboardInterrupt, SystemExit)):
            failure = error.with_traceback(None)
        else:
            failure = _SanitizedFailure(
                message="managed-auth refresh failed at a closed runtime boundary",
                stage="runtime",
                code="runtime-failed",
            )
    finally:
        for descriptor in tuple(descriptors):
            if selector is not None:
                try:
                    selector.unregister(descriptor)
                except (KeyError, ValueError):
                    pass
            try:
                os.close(descriptor)
            except OSError:
                pass
            descriptors.discard(descriptor)
        if selector is not None:
            selector.close()
        _zero_bytearray(outbound)
        _zero_bytearray(stdout_buffer)
        if process_pid is not None and process_pid > 0:
            try:
                if not process_settled:
                    exit_code = _cleanup_process(
                        process_pid,
                        reaped=process_reaped,
                        deadline=total_deadline,
                        term_grace_seconds=limits.term_grace_seconds,
                        relay=relay,
                    )
                    if launched is None:
                        raise RuntimeError(
                            "managed-auth cleanup lost its launch receipt"
                        )
                    launch_capability.record_closure(
                        _managed_auth_closure_receipt(launched, exit_code)
                    )
                    process_settled = True
            except BaseException:
                failure = _SanitizedFailure(
                    message=(
                        "app-server process could not be cleaned within its total bound"
                    ),
                    stage="cleanup",
                    code="cleanup-failed",
                )
            finally:
                relay.unbind(process_pid)

    if failure is not None:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise failure.with_traceback(None) from None
        raise failure.exception() from None
    if result is None:
        raise ManagedAuthRefreshError(
            "managed-auth refresh produced no result",
            stage="runtime",
            code="missing-result",
        )
    return result


def _tracked_pipe(descriptors: set[int]) -> tuple[int, int]:
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)
    except BaseException:
        for descriptor in (read_fd, write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise
    descriptors.update((read_fd, write_fd))
    return read_fd, write_fd


def _launch_refresh_process(
    capability: ManagedAuthRefreshLaunchCapability,
    request: ManagedAuthRefreshLaunchRequest,
) -> ManagedAuthRefreshProcess:
    try:
        return capability.launch(request)
    except (KeyboardInterrupt, SystemExit, ForwardedHostSignal):
        raise
    except BaseException:
        raise ManagedAuthRefreshError(
            "secure managed-auth launch capability failed at a closed boundary",
            stage="launch",
            code="launch-failed",
        ) from None


def _validated_direct_child_pid(launched: ManagedAuthRefreshProcess) -> int:
    if not isinstance(launched, ManagedAuthRefreshProcess):
        raise ManagedAuthRefreshError(
            "secure managed-auth launch returned an invalid process receipt",
            stage="launch",
            code="launch-receipt-invalid",
        )
    pid = launched.pid
    if type(pid) is not int or pid <= 1 or pid == os.getpid():
        raise ManagedAuthRefreshError(
            "secure managed-auth launch returned an invalid process receipt",
            stage="launch",
            code="launch-receipt-invalid",
        )
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except (ChildProcessError, OSError):
        raise ManagedAuthRefreshError(
            "secure managed-auth launch did not return a direct child",
            stage="launch",
            code="launch-receipt-invalid",
        ) from None
    return pid


def _validate_launch_receipt(
    launched: ManagedAuthRefreshProcess,
    *,
    expected_snapshot: ManagedAuthSnapshotEvidence,
    expected_profile_sha256: str,
) -> None:
    if launched.snapshot != expected_snapshot:
        raise ManagedAuthRefreshError(
            "secure launch snapshot attestation did not match its expected generation",
            stage="launch",
            code="snapshot-attestation-mismatch",
        )
    if launched.profile_sha256 != expected_profile_sha256:
        raise ManagedAuthRefreshError(
            "secure launch profile attestation did not match its expected digest",
            stage="launch",
            code="profile-attestation-mismatch",
        )
    pid = launched.pid
    if (
        type(launched.process_group_id) is not int
        or type(launched.session_id) is not int
        or launched.process_group_id != pid
        or launched.session_id != pid
    ):
        raise ManagedAuthRefreshError(
            "secure managed-auth launch containment receipt is invalid",
            stage="launch",
            code="launch-containment-invalid",
        )
    try:
        process_group = os.getpgid(pid)
        session_id = os.getsid(pid)
    except OSError:
        raise ManagedAuthRefreshError(
            "secure managed-auth launch containment is unavailable",
            stage="launch",
            code="launch-containment-invalid",
        ) from None
    if process_group != pid or session_id != pid:
        raise ManagedAuthRefreshError(
            "secure managed-auth launch containment is invalid",
            stage="launch",
            code="launch-containment-invalid",
        )


def _consume_stdout_records(
    *,
    stdout_buffer: bytearray,
    outbound: bytearray,
    protocol: _ManagedAuthRefreshProtocol,
    limits: ManagedAuthRefreshLimits,
) -> None:
    while True:
        newline = stdout_buffer.find(b"\n")
        if newline < 0:
            if len(stdout_buffer) > limits.max_record_bytes:
                raise _runtime_error("record-limit")
            return
        if newline > limits.max_record_bytes:
            raise _runtime_error("record-limit")
        record = bytes(stdout_buffer[: newline + 1])
        _zero_prefix(stdout_buffer, newline + 1)
        try:
            try:
                message = decode_json_line(
                    record,
                    max_bytes=limits.max_record_bytes,
                )
            except AppServerProtocolError:
                raise _protocol_error("malformed-record") from None
            messages = protocol.accept(message)
            _queue_messages(outbound, messages, MAX_STDIN_BYTES)
        finally:
            del record


def _queue_messages(
    target: bytearray,
    messages: Sequence[dict[str, Any]],
    maximum: int,
) -> None:
    for message in messages:
        try:
            encoded = encode_json_line(message, max_bytes=maximum)
        except AppServerProtocolError:
            raise _runtime_error("outbound-record") from None
        if len(target) + len(encoded) > maximum:
            raise _runtime_error("stdin-limit")
        target.extend(encoded)


def _read_scratch(fd: int, *, maximum: int, observed: int) -> tuple[bytearray, int]:
    size = min(READ_CHUNK_BYTES, max(1, maximum - observed + 1))
    scratch = bytearray(size)
    try:
        count = os.readv(fd, (scratch,))
    except BaseException:
        _zero_bytearray(scratch)
        raise
    return scratch, count


def _runtime_checkpoint(
    relay: HostSignalRelay,
    liveness_checkpoint: Callable[[], None],
) -> None:
    relay.checkpoint()
    liveness_checkpoint()


def _managed_auth_closure_receipt(
    launched: ManagedAuthRefreshProcess,
    exit_code: int,
) -> ManagedAuthRefreshClosureReceipt:
    if type(exit_code) is not int:
        raise ValueError("managed-auth closure exit code is invalid")
    return ManagedAuthRefreshClosureReceipt(
        pid=launched.pid,
        process_group_id=launched.process_group_id,
        session_id=launched.session_id,
        profile_sha256=launched.profile_sha256,
        exit_code=exit_code,
        leader_reaped=True,
        process_group_empty=True,
        stdio_closed=True,
    )


def _cleanup_process(
    process_pid: int,
    *,
    reaped: bool,
    deadline: float,
    term_grace_seconds: float,
    relay: HostSignalRelay,
) -> int:
    if reaped:
        relay.unbind(process_pid)
        raise RuntimeError("managed-auth cleanup lost an already-reaped exit code")
    if _terminal_status(process_pid) is None:
        _signal_process(process_pid, signal.SIGTERM)
        grace_deadline = min(deadline, time.monotonic() + term_grace_seconds)
        while time.monotonic() < grace_deadline:
            if _terminal_status(process_pid) is not None:
                break
            time.sleep(min(0.01, max(0.0, grace_deadline - time.monotonic())))
    if _terminal_status(process_pid) is None:
        _signal_process(process_pid, signal.SIGKILL)
    while _terminal_status(process_pid) is None:
        if time.monotonic() >= deadline:
            raise TimeoutError("process cleanup deadline expired")
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    return _reap_process(process_pid, deadline=deadline, relay=relay)


def _terminal_status(pid: int) -> int | None:
    try:
        value = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return 0
    if value is None:
        return None
    if value.si_code == os.CLD_EXITED:
        return value.si_status
    return 128 + value.si_status


def _reap_process(
    process_pid: int,
    *,
    deadline: float,
    relay: HostSignalRelay,
) -> int:
    while _terminal_status(process_pid) is None:
        if time.monotonic() >= deadline:
            raise _runtime_error("process-reap-timeout")
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    relay.unbind(process_pid)
    try:
        waited, raw_status = os.waitpid(process_pid, 0)
    except ChildProcessError:
        raise _runtime_error("process-reap") from None
    if waited != process_pid:
        raise _runtime_error("process-reap")
    return os.waitstatus_to_exitcode(raw_status)


def _signal_process(process_pid: int, value: signal.Signals) -> None:
    try:
        process_group = os.getpgid(process_pid)
    except ProcessLookupError:
        return
    if process_group == process_pid:
        try:
            os.killpg(process_group, value)
        except ProcessLookupError:
            return
    else:
        try:
            os.kill(process_pid, value)
        except ProcessLookupError:
            return


def _validated_snapshot_evidence(
    value: ManagedAuthSnapshotEvidence,
    *,
    label: str,
) -> ManagedAuthSnapshotEvidence:
    if not isinstance(value, ManagedAuthSnapshotEvidence):
        raise TypeError(f"{label} must be ManagedAuthSnapshotEvidence")
    _validated_sha256(value.sha256, label=f"{label} digest")
    identity = value.identity
    if not isinstance(identity, ManagedAuthSnapshotIdentity):
        raise TypeError(f"{label} identity must be ManagedAuthSnapshotIdentity")
    fields = (
        identity.device,
        identity.inode,
        identity.mode,
        identity.link_count,
        identity.uid,
        identity.gid,
        identity.size,
        identity.mtime_ns,
        identity.ctime_ns,
        identity.flags,
        identity.generation,
    )
    if any(type(item) is not int for item in fields):
        raise TypeError(f"{label} identity fields must be integers")
    if (
        identity.device < 0
        or identity.inode <= 0
        or identity.link_count != 1
        or identity.uid != os.getuid()
        or identity.size <= 0
        or not stat.S_ISREG(identity.mode)
        or not identity.mode & stat.S_IXUSR
        or identity.mode & (stat.S_ISUID | stat.S_ISGID)
        or identity.mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ManagedAuthRefreshError(
            "expected authenticated snapshot metadata is invalid",
            stage="admission",
            code="snapshot-metadata",
        )
    return value


def _validated_sha256(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_launch_capability(
    capability: ManagedAuthRefreshLaunchCapability,
    *,
    expected_snapshot: ManagedAuthSnapshotEvidence,
    expected_profile_sha256: str,
    stage: str = "admission",
) -> None:
    try:
        launch = capability.launch
        record_closure = capability.record_closure
        authenticated_snapshot = capability.authenticated_snapshot
        profile_sha256 = capability.profile_sha256
    except BaseException:
        raise ManagedAuthRefreshError(
            "secure managed-auth launch capability is unavailable",
            stage=stage,
            code="launch-capability-invalid",
        ) from None
    if not callable(launch) or not callable(record_closure):
        raise ManagedAuthRefreshError(
            "secure managed-auth launch capability is invalid",
            stage=stage,
            code="launch-capability-invalid",
        )
    if authenticated_snapshot != expected_snapshot:
        raise ManagedAuthRefreshError(
            "launch capability snapshot does not match the expected generation",
            stage=stage,
            code="snapshot-attestation-mismatch",
        )
    if profile_sha256 != expected_profile_sha256:
        raise ManagedAuthRefreshError(
            "launch capability profile does not match the expected digest",
            stage=stage,
            code="profile-attestation-mismatch",
        )


def _validated_environment(
    environment: Mapping[str, str] | None,
) -> tuple[dict[str, str], pathlib.Path]:
    source = os.environ if environment is None else environment
    child = {
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": SAFE_PATH,
    }
    if environment is None:
        source_items = (
            (key, source.get(key)) for key in ("CODEX_HOME", "HOME", "TMPDIR")
        )
    else:
        source_items = source.items()
    for key, value in source_items:
        if value is None and environment is None:
            continue
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in value
        ):
            raise ValueError("environment must contain valid NUL-free strings")
        if key not in _ALLOWED_ENVIRONMENT_KEYS:
            raise ManagedAuthRefreshError(
                "child environment contains a forbidden override",
                stage="admission",
                code="unsafe-environment",
            )
        fixed_value = _FIXED_ENVIRONMENT.get(key)
        if fixed_value is not None:
            if value != fixed_value:
                raise ManagedAuthRefreshError(
                    "child environment contains an unsafe fixed override",
                    stage="admission",
                    code="unsafe-environment",
                )
            continue
        child[key] = value
    if "CODEX_HOME" in child:
        if not child["CODEX_HOME"]:
            raise ManagedAuthRefreshError(
                "normal Codex home cannot be empty",
                stage="admission",
                code="codex-home-missing",
            )
        normal = pathlib.Path(child["CODEX_HOME"])
    else:
        home = child.get("HOME")
        if not home:
            raise ManagedAuthRefreshError(
                "normal Codex home cannot be derived from the child environment",
                stage="admission",
                code="codex-home-missing",
            )
        normal = pathlib.Path(home) / ".codex"
    normal = _validate_absolute_normalized_path(normal, label="normal Codex home")
    for key in ("HOME", "TMPDIR"):
        value = child.get(key)
        if value is not None and (not value or not pathlib.Path(value).is_absolute()):
            raise ManagedAuthRefreshError(
                "child environment contains a non-absolute runtime path",
                stage="admission",
                code="unsafe-environment",
            )
    return child, normal


def _validate_containment_host() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "waitid")
        or not hasattr(os, "waitpid")
        or not hasattr(os, "getpgid")
        or not hasattr(os, "getsid")
        or not hasattr(os, "killpg")
        or os.getuid() <= 0
        or os.geteuid() != os.getuid()
    ):
        raise ManagedAuthRefreshError(
            "no-descendant process containment is unavailable on this host",
            stage="admission",
            code="containment-unavailable",
        )
    if threading.current_thread() is not threading.main_thread():
        raise ManagedAuthRefreshError(
            "managed-auth refresh requires main-thread signal ownership",
            stage="admission",
            code="signal-ownership",
        )
    if threading.active_count() != 1:
        raise ManagedAuthRefreshError(
            "managed-auth refresh requires a single-threaded launch host",
            stage="admission",
            code="containment-unavailable",
        )


def _validate_neutral_cwd(path: pathlib.Path) -> pathlib.Path:
    value = _validate_absolute_normalized_path(path, label="neutral cwd")
    try:
        metadata = os.lstat(value)
    except OSError:
        raise ManagedAuthRefreshError(
            "neutral cwd is unavailable",
            stage="admission",
            code="neutral-cwd",
        ) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ManagedAuthRefreshError(
            "neutral cwd metadata is invalid",
            stage="admission",
            code="neutral-cwd",
        )
    with os.scandir(value) as entries:
        if next(entries, None) is not None:
            raise ManagedAuthRefreshError(
                "neutral cwd must be empty",
                stage="admission",
                code="neutral-cwd-not-empty",
            )
    return value


def _validate_absolute_normalized_path(
    path: pathlib.Path,
    *,
    label: str,
) -> pathlib.Path:
    if not isinstance(path, pathlib.Path):
        raise TypeError(f"{label} must be pathlib.Path")
    if not path.is_absolute() or path != pathlib.Path(os.path.normpath(str(path))):
        raise ValueError(f"{label} must be absolute and normalized")
    return path


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _protocol_error("record-schema")
    return value


def _exact_keys(
    value: dict[str, Any],
    required: set[str],
    *,
    optional: frozenset[str] | set[str] = frozenset(),
) -> None:
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise _protocol_error("record-schema")


def _bounded_text(value: Any, *, maximum: int) -> None:
    if not isinstance(value, str):
        raise _protocol_error("record-schema")
    try:
        encoded_size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        raise _protocol_error("record-schema") from None
    if not 1 <= encoded_size <= maximum:
        raise _protocol_error("record-schema")


def _validate_plan_type(value: Any) -> None:
    if not isinstance(value, str) or value not in _PLAN_TYPES:
        raise _protocol_error("account-schema")


def _zero_prefix(value: bytearray, count: int) -> None:
    if count <= 0 or count > len(value):
        raise _runtime_error("stream-progress")
    value[:count] = b"\0" * count
    del value[:count]


def _zero_bytearray(value: bytearray) -> None:
    if value:
        value[:] = b"\0" * len(value)
        value.clear()


def _bounded_integer(value: int, *, label: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{label} is outside its hard bound")


def _bounded_seconds(value: float, *, label: str, maximum: float) -> None:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    if not 0 < value <= maximum:
        raise ValueError(f"{label} is outside its hard bound")


def _protocol_error(code: str) -> ManagedAuthRefreshError:
    return ManagedAuthRefreshError(
        "app-server managed-auth protocol was rejected",
        stage="protocol",
        code=code,
    )


def _runtime_error(code: str) -> ManagedAuthRefreshError:
    return ManagedAuthRefreshError(
        "app-server managed-auth refresh exceeded a runtime boundary",
        stage="runtime",
        code=code,
    )


__all__ = [
    "ManagedAuthRefreshError",
    "ManagedAuthRefreshClosureReceipt",
    "ManagedAuthRefreshLaunchCapability",
    "ManagedAuthRefreshLaunchRequest",
    "ManagedAuthRefreshLimits",
    "ManagedAuthRefreshProcess",
    "ManagedAuthRefreshResult",
    "ManagedAuthSnapshotEvidence",
    "ManagedAuthSnapshotIdentity",
    "refresh_managed_auth",
]
