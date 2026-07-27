from __future__ import annotations

import hashlib
import json
import os
import pathlib
import selectors
import signal
import time
from dataclasses import dataclass
from typing import Any, Callable, cast

from .appserver_protocol import (
    AppServerProtocol,
    AppServerSessionConfig,
    AppServerSessionResult,
    encode_json_line,
)
from .codex_executable import (
    ProcessQuiescenceEvidence,
    SnapshotProtectionEvidence,
    SnapshotSeatbeltPolicy,
    launch_no_child_process_with_result_publisher,
    run_bounded_command,
)
from .constants import (
    APP_SERVER_MAX_RECORD_BYTES,
    MIB,
    PROCESS_TERM_GRACE_SECONDS,
    REVIEWER_RUNTIME_SECONDS,
)
from .no_child_profile import (
    LaunchedNoChildProcess,
    PreparedNoChildProfile,
    launch_prepared_no_child_process,
    prepare_sandboxed_python_no_child_profile,
)
from .signal_relay import ForwardedHostSignal, HostSignalRelay


STDOUT_LIMIT_BYTES = 16 * MIB
STDERR_LIMIT_BYTES = 16 * MIB
STDERR_TAIL_BYTES = 8 * 1024
OUTBOUND_LIMIT_BYTES = 16 * MIB
POST_TERMINAL_DRAIN_SECONDS = 10.0
PROCESS_CLEANUP_SECONDS = 10.0
MUTATION_PROBE_SECONDS = 10.0
MUTATION_PROBE_OUTPUT_BYTES = 4096
_MUTATION_PROBE = r"""
import errno
import json
import os
import sys

source = sys.argv[1]
renamed = source + ".renamed"
denied = {}

def require_denied(name, operation):
    try:
        operation()
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM}:
            denied[name] = True
            return
        denied[name] = False
    else:
        denied[name] = False
    print(json.dumps(denied, sort_keys=True, separators=(",", ":")))
    raise SystemExit(1)

def write_probe():
    descriptor = os.open(
        source + ".write-probe",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    os.close(descriptor)

require_denied("write", write_probe)
require_denied("chmod", lambda: os.chmod(source, 0o500))
require_denied("rename", lambda: os.rename(source, renamed))
require_denied("unlink", lambda: os.unlink(source))
print(json.dumps(denied, sort_keys=True, separators=(",", ":")))
raise SystemExit(0 if all(denied.values()) and len(denied) == 4 else 1)
""".strip()


class DirectGateError(RuntimeError):
    def __init__(self, message: str, *, stage: str, code: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code


@dataclass
class ProcessCustodyState:
    process_id: int | None = None
    process_group_id: int | None = None
    profile_sha256: str | None = None
    leader_reaped: bool = False
    process_group_empty: bool = False
    pipes_closed: bool = False
    exit_code: int | None = None


@dataclass
class _LaunchedProcessCustody:
    process_state: ProcessCustodyState
    launched: LaunchedNoChildProcess | None = None
    transferred: bool = False

    def publish(self, launched: object) -> None:
        if self.launched is not None and self.launched is launched:
            self.process_state.process_id = self.launched.pid
            self.process_state.process_group_id = self.launched.pgid
            self.process_state.profile_sha256 = self.launched.profile_sha256
            self.process_state.leader_reaped = False
            self.process_state.process_group_empty = False
            self.process_state.pipes_closed = False
            return
        if self.launched is not None:
            raise ValueError("app-server launch custody was published more than once")
        self.launched = cast(LaunchedNoChildProcess, launched)
        self.process_state.process_id = self.launched.pid
        self.process_state.process_group_id = self.launched.pgid
        self.process_state.profile_sha256 = self.launched.profile_sha256
        self.process_state.leader_reaped = False
        self.process_state.process_group_empty = False
        self.process_state.pipes_closed = False

    def owns(self, launched: object) -> bool:
        return (
            self.launched is launched
            and self.process_state.process_id == self.launched.pid
            and self.process_state.process_group_id == self.launched.pgid
            and self.process_state.profile_sha256 == self.launched.profile_sha256
            and not self.process_state.leader_reaped
            and not self.process_state.process_group_empty
            and not self.process_state.pipes_closed
        )

    def transfer(self, launched: LaunchedNoChildProcess) -> None:
        if self.launched is not launched or self.transferred:
            raise ValueError("app-server launch custody transfer is inconsistent")
        self.transferred = True


@dataclass(frozen=True)
class AppServerProcessResult:
    session: AppServerSessionResult
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    exit_code: int
    elapsed_seconds: float
    profile_sha256: str


class BoundProtectionVerifier:
    def __init__(self) -> None:
        self._policy_sha256: str | None = None
        self._profile_sha256: str | None = None

    def bind(self, *, policy_sha256: str, profile_sha256: str) -> None:
        if self._policy_sha256 is not None or self._profile_sha256 is not None:
            raise DirectGateError(
                "snapshot protection verifier was bound more than once",
                stage="containment",
                code="protection-rebound",
            )
        self._policy_sha256 = policy_sha256
        self._profile_sha256 = profile_sha256

    def __call__(
        self,
        policy: SnapshotSeatbeltPolicy,
        evidence: SnapshotProtectionEvidence,
    ) -> None:
        if (
            self._policy_sha256 is None
            or self._profile_sha256 is None
            or policy.sha256 != self._policy_sha256
            or evidence.snapshot_policy_sha256 != self._policy_sha256
            or evidence.effective_profile_sha256 != self._profile_sha256
            or not evidence.self_mutation_probe_denied
        ):
            raise ValueError("snapshot protection evidence is not bound to the launch")


def run_bounded_appserver_process(
    *,
    prepared: PreparedNoChildProfile,
    argv: tuple[str, ...],
    cwd: pathlib.Path,
    environment: dict[str, str],
    prompt: bytes,
    config: AppServerSessionConfig,
    process_state: ProcessCustodyState,
    on_launch: Callable[[LaunchedNoChildProcess], None],
    before_external_auth_send: Callable[[], None] = lambda: None,
    liveness_checkpoint: Callable[[], None] = lambda: None,
) -> AppServerProcessResult:
    relay = HostSignalRelay()
    result: AppServerProcessResult | None = None
    failure: BaseException | None = None
    with relay:
        try:
            result = _run_bounded_appserver_process_inner(
                prepared=prepared,
                argv=argv,
                cwd=cwd,
                environment=environment,
                prompt=prompt,
                config=config,
                process_state=process_state,
                on_launch=on_launch,
                before_external_auth_send=before_external_auth_send,
                liveness_checkpoint=liveness_checkpoint,
                signal_relay=relay,
            )
        except ForwardedHostSignal:
            pass
        except BaseException as error:
            failure = error
    if relay.received is not None:
        relay.redeliver()
        raise DirectGateError(
            "app-server review was interrupted by a host signal",
            stage="review-runtime",
            code="signal-interrupted",
        ) from None
    if failure is not None:
        raise failure
    if result is None:
        raise DirectGateError(
            "app-server review produced no result",
            stage="review-runtime",
            code="missing-result",
        )
    return result


def _run_bounded_appserver_process_inner(
    *,
    prepared: PreparedNoChildProfile,
    argv: tuple[str, ...],
    cwd: pathlib.Path,
    environment: dict[str, str],
    prompt: bytes,
    config: AppServerSessionConfig,
    process_state: ProcessCustodyState,
    on_launch: Callable[[LaunchedNoChildProcess], None],
    before_external_auth_send: Callable[[], None],
    liveness_checkpoint: Callable[[], None],
    signal_relay: HostSignalRelay,
) -> AppServerProcessResult:
    protocol = AppServerProtocol(prompt=prompt, config=config)
    stdout_hash = hashlib.sha256()
    stderr_hash = hashlib.sha256()
    stdout_bytes = 0
    stderr_bytes = 0
    stderr_tail = bytearray()
    outbound = bytearray()
    stdout_buffer = bytearray()
    selector: selectors.BaseSelector | None = None
    launched: LaunchedNoChildProcess | None = None
    launch_custody = _LaunchedProcessCustody(process_state)
    descriptors: set[int] = set()
    start = time.monotonic()
    deadline = start + REVIEWER_RUNTIME_SECONDS
    terminal_deadline: float | None = None
    try:
        selector = selectors.DefaultSelector()
        stdin_read, stdin_write = _tracked_pipe(descriptors)
        stdout_read, stdout_write = _tracked_pipe(descriptors)
        stderr_read, stderr_write = _tracked_pipe(descriptors)
        signal_relay.checkpoint()
        liveness_checkpoint()
        launched = launch_no_child_process_with_result_publisher(
            launch_prepared_no_child_process,
            prepared,
            argv,
            result_owner=launch_custody,
            cwd=cwd,
            environment=environment,
            stdin_fd=stdin_read,
            stdout_fd=stdout_write,
            stderr_fd=stderr_write,
        )
        launch_custody.transfer(launched)
        signal_relay.bind(launched.pid)
        signal_relay.checkpoint()
        liveness_checkpoint()
        if (
            launched.profile_sha256
            != hashlib.sha256(
                prepared.seatbelt_profile.encode("utf-8", "strict")
            ).hexdigest()
        ):
            raise DirectGateError(
                "launched Seatbelt profile digest is inconsistent",
                stage="containment",
                code="profile-attestation-mismatch",
            )
        on_launch(launched)
        for descriptor in (stdin_read, stdout_write, stderr_write):
            os.close(descriptor)
            descriptors.remove(descriptor)
        for descriptor in (stdin_write, stdout_read, stderr_read):
            os.set_blocking(descriptor, False)
        selector.register(stdout_read, selectors.EVENT_READ, "stdout")
        selector.register(stderr_read, selectors.EVENT_READ, "stderr")
        _queue_messages(outbound, protocol.start())
        selector.register(stdin_write, selectors.EVENT_WRITE, "stdin")

        stdout_open = True
        stderr_open = True
        stdin_open = True
        while True:
            signal_relay.checkpoint()
            liveness_checkpoint()
            now = time.monotonic()
            active_deadline = deadline
            if terminal_deadline is not None:
                active_deadline = min(active_deadline, terminal_deadline)
            if now >= active_deadline:
                raise DirectGateError(
                    "app-server exceeded its bounded runtime or drain deadline",
                    stage="review-runtime",
                    code="review-timeout",
                )
            status = _terminal_status(launched.pid)
            if status is not None and not stdout_open and not stderr_open:
                break
            if not stdout_open and not stderr_open:
                reaped = _try_reap_process(
                    launched.pid,
                    signal_relay=signal_relay,
                )
                if reaped is not None:
                    process_state.exit_code = reaped
                    process_state.leader_reaped = True
                    process_state.process_group_empty = True
                    break
            events = selector.select(min(0.25, active_deadline - now))
            for key, mask in events:
                if key.data == "stdin" and mask & selectors.EVENT_WRITE:
                    written = os.write(key.fd, outbound)
                    _consume_prefix(outbound, written)
                    if not outbound:
                        selector.unregister(key.fd)
                elif key.data == "stdout" and mask & selectors.EVENT_READ:
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fd)
                        stdout_open = False
                        continue
                    stdout_bytes += len(chunk)
                    stdout_hash.update(chunk)
                    if stdout_bytes >= STDOUT_LIMIT_BYTES:
                        raise DirectGateError(
                            "app-server stdout reached its byte limit",
                            stage="review-runtime",
                            code="stdout-limit",
                        )
                    stdout_buffer.extend(chunk)
                    _consume_stdout_records(
                        stdout_buffer=stdout_buffer,
                        outbound=outbound,
                        protocol=protocol,
                        before_external_auth_send=before_external_auth_send,
                    )
                    if outbound and stdin_open:
                        try:
                            selector.register(
                                stdin_write, selectors.EVENT_WRITE, "stdin"
                            )
                        except KeyError:
                            pass
                elif key.data == "stderr" and mask & selectors.EVENT_READ:
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fd)
                        stderr_open = False
                        continue
                    stderr_bytes += len(chunk)
                    stderr_hash.update(chunk)
                    if stderr_bytes >= STDERR_LIMIT_BYTES:
                        raise DirectGateError(
                            "app-server stderr reached its byte limit",
                            stage="review-runtime",
                            code="stderr-limit",
                        )
                    stderr_tail.extend(chunk)
                    if len(stderr_tail) > STDERR_TAIL_BYTES:
                        del stderr_tail[:-STDERR_TAIL_BYTES]

            if protocol.terminal and not outbound and stdin_open:
                try:
                    selector.unregister(stdin_write)
                except KeyError:
                    pass
                os.close(stdin_write)
                descriptors.remove(stdin_write)
                stdin_open = False
                terminal_deadline = time.monotonic() + POST_TERMINAL_DRAIN_SECONDS

        if stdout_buffer:
            raise DirectGateError(
                "app-server stdout ended with a partial protocol record",
                stage="review-runtime",
                code="partial-record",
            )
        session = protocol.finish_eof()
        if process_state.leader_reaped:
            assert process_state.exit_code is not None
            exit_code = process_state.exit_code
        else:
            exit_code = _reap_process(
                launched.pid,
                signal_relay=signal_relay,
            )
            process_state.exit_code = exit_code
            process_state.leader_reaped = True
            process_state.process_group_empty = True
        if exit_code != 0:
            raise DirectGateError(
                "app-server exited nonzero after bounded output capture",
                stage="review-runtime",
                code=_classify_stderr(bytes(stderr_tail)),
            )
        if not process_state.process_group_empty:
            raise DirectGateError(
                "app-server process group is not quiescent",
                stage="review-runtime",
                code="process-group-not-empty",
            )
        return AppServerProcessResult(
            session=session,
            stdout_bytes=stdout_bytes,
            stdout_sha256=stdout_hash.hexdigest(),
            stderr_bytes=stderr_bytes,
            stderr_sha256=stderr_hash.hexdigest(),
            exit_code=exit_code,
            elapsed_seconds=time.monotonic() - start,
            profile_sha256=launched.profile_sha256,
        )
    finally:
        termination_error: BaseException | None = None
        custodied_launch = launch_custody.launched
        try:
            if custodied_launch is not None and not process_state.leader_reaped:
                process_state.exit_code = _terminate_process(
                    custodied_launch,
                    signal_relay=signal_relay,
                )
                process_state.leader_reaped = True
                process_state.process_group_empty = True
            elif custodied_launch is None:
                process_state.leader_reaped = True
                process_state.process_group_empty = True
        except BaseException as error:
            termination_error = error
        finally:
            if custodied_launch is not None:
                signal_relay.unbind(custodied_launch.pid)
            for descriptor in tuple(descriptors):
                try:
                    if selector is not None:
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
            process_state.pipes_closed = True
            _zero_bytearray(outbound)
            _zero_bytearray(stdout_buffer)
            _zero_bytearray(stderr_tail)
        if termination_error is not None:
            raise termination_error


def _consume_stdout_records(
    *,
    stdout_buffer: bytearray,
    outbound: bytearray,
    protocol: AppServerProtocol,
    before_external_auth_send: Callable[[], None],
) -> None:
    while True:
        newline = stdout_buffer.find(b"\n")
        if newline < 0:
            if len(stdout_buffer) > APP_SERVER_MAX_RECORD_BYTES:
                raise DirectGateError(
                    "app-server protocol record exceeds its byte limit",
                    stage="review-runtime",
                    code="record-limit",
                )
            return
        record = bytes(stdout_buffer[: newline + 1])
        _consume_prefix(stdout_buffer, newline + 1)
        messages = protocol.accept_line(record)
        if any(message.get("method") == "account/login/start" for message in messages):
            before_external_auth_send()
        _queue_messages(outbound, messages)


def _tracked_pipe(descriptors: set[int]) -> tuple[int, int]:
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        read_fd, write_fd = os.pipe()
        descriptors.add(read_fd)
        descriptors.add(write_fd)
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)
        return read_fd, write_fd
    except BaseException:
        if read_fd is not None:
            descriptors.discard(read_fd)
            try:
                os.close(read_fd)
            except OSError:
                pass
        if write_fd is not None:
            descriptors.discard(write_fd)
            try:
                os.close(write_fd)
            except OSError:
                pass
        raise


def _queue_messages(
    target: bytearray,
    messages: tuple[dict[str, Any], ...],
) -> None:
    for message in messages:
        encoded = encode_json_line(message)
        if len(target) + len(encoded) >= OUTBOUND_LIMIT_BYTES:
            raise DirectGateError(
                "app-server stdin queue reached its byte limit",
                stage="review-runtime",
                code="stdin-limit",
            )
        target.extend(encoded)


def _consume_prefix(value: bytearray, count: int) -> None:
    if count <= 0 or count > len(value):
        raise DirectGateError(
            "bounded stream made invalid progress",
            stage="review-runtime",
            code="stream-progress",
        )
    value[:count] = b"\0" * count
    del value[:count]


def _zero_bytearray(value: bytearray) -> None:
    if value:
        value[:] = b"\0" * len(value)
        value.clear()


def _terminal_status(pid: int) -> int | None:
    value = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if value is None:
        return None
    if value.si_code == os.CLD_EXITED:
        return value.si_status
    return 128 + value.si_status


def _reap_process(pid: int, *, signal_relay: HostSignalRelay) -> int:
    while _terminal_status(pid) is None:
        time.sleep(0.02)
    signal_relay.unbind(pid)
    waited, raw = os.waitpid(pid, 0)
    if waited != pid:
        raise DirectGateError(
            "app-server leader could not be reaped exactly",
            stage="review-runtime",
            code="process-reap",
        )
    return os.waitstatus_to_exitcode(raw)


def _try_reap_process(
    pid: int,
    *,
    signal_relay: HostSignalRelay,
) -> int | None:
    if _terminal_status(pid) is None:
        return None
    return _reap_process(pid, signal_relay=signal_relay)


def _terminate_process(
    process: LaunchedNoChildProcess,
    *,
    signal_relay: HostSignalRelay,
) -> int:
    deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
    reaped = _try_reap_process(process.pid, signal_relay=signal_relay)
    if reaped is not None:
        return reaped
    if _terminal_status(process.pid) is None:
        try:
            os.killpg(process.pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        grace = min(deadline, time.monotonic() + PROCESS_TERM_GRACE_SECONDS)
        while time.monotonic() < grace:
            reaped = _try_reap_process(process.pid, signal_relay=signal_relay)
            if reaped is not None:
                return reaped
            if _terminal_status(process.pid) is not None:
                break
            time.sleep(0.02)
        if _terminal_status(process.pid) is None:
            try:
                os.killpg(process.pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    while time.monotonic() < deadline:
        reaped = _try_reap_process(process.pid, signal_relay=signal_relay)
        if reaped is not None:
            return reaped
        if _terminal_status(process.pid) is not None:
            return _reap_process(process.pid, signal_relay=signal_relay)
        time.sleep(0.02)
    raise DirectGateError(
        "app-server leader could not be terminated within the cleanup deadline",
        stage="review-runtime",
        code="process-cleanup-timeout",
    )


def _verify_snapshot_mutation_denials(
    *,
    policy: SnapshotSeatbeltPolicy,
    snapshot_path: pathlib.Path,
) -> None:
    prepared = prepare_sandboxed_python_no_child_profile(
        additional_seatbelt_rules=policy.rules,
    )
    target = prepared.sandboxed_target
    if target is None:
        raise DirectGateError(
            "snapshot mutation probe did not receive a bound Python target",
            stage="containment",
            code="mutation-probe-unbound",
        )
    result = run_bounded_command(
        (
            target.path,
            "-B",
            "-I",
            "-S",
            "-c",
            _MUTATION_PROBE,
            str(snapshot_path),
        ),
        timeout_seconds=MUTATION_PROBE_SECONDS,
        max_output_bytes=MUTATION_PROBE_OUTPUT_BYTES,
        _prepared_no_child_profile=prepared,
    )
    expected = {"chmod": True, "rename": True, "unlink": True, "write": True}
    try:
        observed = json.loads(result.stdout.decode("ascii", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise DirectGateError(
            "snapshot mutation probe emitted malformed evidence",
            stage="containment",
            code="mutation-probe-malformed",
        ) from error
    if result.returncode != 0 or result.stderr or observed != expected:
        raise DirectGateError(
            "snapshot mutation operations were not all denied by Seatbelt",
            stage="containment",
            code="mutation-probe-failed",
        )


def _quiescence_evidence(
    *,
    handoff_token: str | None,
    state: ProcessCustodyState,
    reason: str,
) -> ProcessQuiescenceEvidence:
    return ProcessQuiescenceEvidence(
        handoff_token=handoff_token,
        process_id=state.process_id,
        leader_reaped=state.leader_reaped,
        process_group_empty=state.process_group_empty,
        descendant_handles_closed=state.pipes_closed,
        observed_by_supervisor=True,
        reason=reason,
        launch_state=(
            "bound-launch" if state.process_id is not None else "never-launched-abort"
        ),
    )


def _verify_quiescence(evidence: ProcessQuiescenceEvidence) -> None:
    if evidence.reason not in {
        "bounded-appserver-session-complete",
        "bounded-appserver-session-aborted",
    }:
        raise ValueError("quiescence reason is not owned by the direct gate")


def _isolated_environment(
    *,
    codex_home: pathlib.Path,
    temp_dir: pathlib.Path,
) -> dict[str, str]:
    return {
        "CODEX_HOME": str(codex_home),
        "HOME": str(codex_home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(temp_dir) + "/",
    }


def _classify_stderr(value: bytes) -> str:
    lowered = value.lower()
    if any(marker in lowered for marker in (b"401", b"unauthorized", b"login")):
        return "authentication-failed"
    if any(marker in lowered for marker in (b"rate limit", b"capacity", b"overloaded")):
        return "review-capacity"
    return "review-process-failed"


__all__ = [
    "AppServerProcessResult",
    "BoundProtectionVerifier",
    "DirectGateError",
    "ProcessCustodyState",
    "run_bounded_appserver_process",
]
