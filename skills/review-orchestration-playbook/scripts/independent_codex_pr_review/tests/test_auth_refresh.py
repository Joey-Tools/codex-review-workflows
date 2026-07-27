from __future__ import annotations

import dataclasses
import errno
import hashlib
import inspect
import json
import os
import pathlib
import resource
import select
import signal
import sys
import textwrap
import time
import unittest
from collections.abc import Callable
from unittest import mock

import review_supervisor.auth_refresh as auth_refresh

from review_supervisor.appserver_protocol import APP_SERVER_NO_EXECUTION_CONFIG_ARGS
from review_supervisor.auth_refresh import (
    ManagedAuthRefreshClosureReceipt,
    ManagedAuthRefreshError,
    ManagedAuthRefreshLaunchRequest,
    ManagedAuthRefreshLimits,
    ManagedAuthRefreshProcess,
    ManagedAuthSnapshotEvidence,
    ManagedAuthSnapshotIdentity,
    refresh_managed_auth,
)

from tests.support import owned_temporary_directory


if sys.version_info[:2] != (3, 13):
    raise RuntimeError("managed-auth integration fixtures require Python 3.13")
PYTHON_313 = str(pathlib.Path(sys.executable).resolve(strict=True))
_ORIGINAL_EXECVE = os.execve
_TEST_PROFILE_SHA256 = hashlib.sha256(b"test no-child profile").hexdigest()

_FAKE_APP_SERVER_TEMPLATE = textwrap.dedent(
    """\
    #!__PYTHON_313__
    import json
    import os
    import pathlib
    import signal
    import sys
    import time

    mode = __MODE__
    fake_bytes = __FAKE_BYTES__
    pid_path = pathlib.Path(__PID_PATH__)
    observed_path = pathlib.Path(__OBSERVED_PATH__)
    ready_path = pathlib.Path(__READY_PATH__)
    descendant_status_path = pathlib.Path(__DESCENDANT_STATUS_PATH__)
    pid_path.write_text(str(os.getpid()), encoding="ascii")

    expected_argv = __EXPECTED_ARGV__
    if sys.argv[1:] != expected_argv:
        raise SystemExit(91)

    def read_message():
        record = sys.stdin.buffer.readline()
        if not record:
            raise SystemExit(92)
        return json.loads(record)

    def write_message(value):
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        sys.stdout.buffer.write(encoded + b"\\n")
        sys.stdout.buffer.flush()

    initialize = read_message()
    if mode == "stdout-limit":
        os.write(1, b"x" * fake_bytes)
        time.sleep(60)
    if mode == "record-limit":
        os.write(1, b"x" * fake_bytes)
        time.sleep(60)
    if mode == "stderr-limit":
        os.write(2, b"s" * fake_bytes)
        time.sleep(60)
    if mode == "total-timeout":
        time.sleep(60)
    if mode == "ignore-signals":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        ready_path.write_text("ready", encoding="ascii")
        time.sleep(60)
    if mode == "escape-descendant":
        try:
            child_pid = os.fork()
        except OSError as error:
            descendant_status_path.write_text(
                f"denied:{{error.errno}}",
                encoding="ascii",
            )
        else:
            if child_pid == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGHUP, signal.SIG_IGN)
                os.setsid()
                time.sleep(60)
                raise SystemExit(0)
            descendant_status_path.write_text(
                f"spawned:{{child_pid}}",
                encoding="ascii",
            )
        time.sleep(60)
    if mode == "server-request":
        write_message(
            {{
                "id": 900,
                "method": "item/tool/call",
                "params": {{"private": "sensitive-runtime-marker"}},
            }}
        )
        time.sleep(60)
    if mode == "unknown-notification":
        write_message(
            {{
                "method": "private/unknown",
                "params": {{"private": "sensitive-runtime-marker"}},
            }}
        )
        time.sleep(60)
    if mode == "remote-error":
        os.write(2, b"sensitive-runtime-marker\\n")
        write_message(
            {{
                "id": 1,
                "error": {{
                    "code": -32000,
                    "message": "private-user@example.invalid sensitive-runtime-marker",
                }},
            }}
        )
        time.sleep(60)

    codex_home = os.environ["CODEX_HOME"]
    if mode == "codex-home-mismatch":
        codex_home = "/private/unexpected-codex-home"
    write_message(
        {{
            "id": 1,
            "result": {{
                "codexHome": codex_home,
                "platformFamily": "unix",
                "platformOs": "macos",
                "userAgent": "fake-app-server/1",
            }},
        }}
    )
    initialized = read_message()
    account_read = read_message()
    if mode != "missing-remote-status":
        remote_status = "enabled" if mode == "remote-control-enabled" else "disabled"
        write_message(
            {{
                "method": "remoteControl/status/changed",
                "params": {{
                    "installationId": "install-1",
                    "serverName": "local",
                    "status": remote_status,
                }},
            }}
        )
    notification_plan_type = "plus"
    if mode == "notification-plan-object":
        notification_plan_type = {{"unexpected": "value"}}
    if mode not in {{
        "missing-account-update",
        "missing-remote-status",
        "response-before-account-update",
    }}:
        write_message(
            {{
                "method": "account/updated",
                "params": {{
                    "authMode": "chatgpt",
                    "planType": notification_plan_type,
                }},
            }}
        )
    account_plan_type = "plus"
    if mode == "account-plan-list":
        account_plan_type = ["plus"]
    write_message(
        {{
            "id": 2,
            "result": {{
                "account": {{
                    "email": "private-user@example.invalid",
                    "planType": account_plan_type,
                    "type": "chatgpt",
                }},
                "requiresOpenaiAuth": True,
            }},
        }}
    )
    if mode == "response-before-account-update":
        write_message(
            {{
                "method": "account/updated",
                "params": {{
                    "authMode": "chatgpt",
                    "planType": notification_plan_type,
                }},
            }}
        )
    stdin_tail = sys.stdin.buffer.read()
    observed_path.write_text(
        json.dumps(
            {{
                "account_read": account_read,
                "argv": sys.argv[1:],
                "initialize": initialize,
                "initialized": initialized,
                "environment_keys": sorted(os.environ),
                "stdin_eof": stdin_tail == b"",
            }},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    if mode == "shutdown-timeout":
        time.sleep(60)
    """
)


def _fake_app_server(
    *,
    mode: str,
    fake_bytes: int,
    pid_path: pathlib.Path,
    observed_path: pathlib.Path,
    ready_path: pathlib.Path,
    descendant_status_path: pathlib.Path,
) -> str:
    replacements = {
        "__PYTHON_313__": PYTHON_313,
        "__MODE__": repr(mode),
        "__FAKE_BYTES__": repr(fake_bytes),
        "__PID_PATH__": repr(str(pid_path)),
        "__OBSERVED_PATH__": repr(str(observed_path)),
        "__READY_PATH__": repr(str(ready_path)),
        "__DESCENDANT_STATUS_PATH__": repr(str(descendant_status_path)),
        "__EXPECTED_ARGV__": repr(
            [
                "app-server",
                "--session-source",
                "exec",
                "--strict-config",
                *APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
                "--stdio",
            ]
        ),
    }
    result = _FAKE_APP_SERVER_TEMPLATE
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    return result.replace("{{", "{").replace("}}", "}")


def _maximum_fd() -> int:
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return 1_048_576
    return min(int(soft), 1_048_576)


def _snapshot_evidence(path: pathlib.Path) -> ManagedAuthSnapshotEvidence:
    before = ManagedAuthSnapshotIdentity.from_stat(os.lstat(path))
    payload = path.read_bytes()
    after = ManagedAuthSnapshotIdentity.from_stat(os.lstat(path))
    if before != after:
        raise RuntimeError("test snapshot changed while it was authenticated")
    return ManagedAuthSnapshotEvidence(
        sha256=hashlib.sha256(payload).hexdigest(),
        identity=after,
    )


def _kill_and_reap(pid: int) -> None:
    try:
        process_group = os.getpgid(pid)
    except ProcessLookupError:
        process_group = None
    try:
        if process_group == pid:
            os.killpg(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


class _TestLaunchCapability:
    def __init__(self, snapshot_path: pathlib.Path) -> None:
        self.snapshot_path = snapshot_path
        self.authenticated_snapshot = _snapshot_evidence(snapshot_path)
        self.profile_sha256 = _TEST_PROFILE_SHA256
        self.requests: list[ManagedAuthRefreshLaunchRequest] = []
        self.receipt_snapshot: ManagedAuthSnapshotEvidence | None = None
        self.receipt_profile_sha256: str | None = None
        self.failure: BaseException | None = None
        self.last_pid: int | None = None
        self.closures: list[ManagedAuthRefreshClosureReceipt] = []

    def launch(
        self,
        request: ManagedAuthRefreshLaunchRequest,
    ) -> ManagedAuthRefreshProcess:
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        current = _snapshot_evidence(self.snapshot_path)
        if (
            current != self.authenticated_snapshot
            or current != request.expected_snapshot
        ):
            raise RuntimeError("test launch snapshot attestation changed")
        if request.expected_profile_sha256 != self.profile_sha256:
            raise RuntimeError("test launch profile attestation changed")

        error_read, error_write = os.pipe()
        os.set_inheritable(error_read, False)
        os.set_inheritable(error_write, False)
        pid = os.fork()
        if pid == 0:
            failure_fd = error_write
            try:
                os.close(error_read)
                os.dup2(error_write, 63, inheritable=False)
                failure_fd = 63
                for target, source in zip(
                    (0, 1, 2),
                    (request.stdin_fd, request.stdout_fd, request.stderr_fd),
                    strict=True,
                ):
                    os.dup2(source, target, inheritable=True)
                os.closerange(3, 63)
                os.closerange(64, _maximum_fd())
                signal.signal(signal.SIGHUP, signal.SIG_DFL)
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                signal.signal(signal.SIGQUIT, signal.SIG_DFL)
                os.chdir(request.cwd)
                os.setsid()
                resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
                if _snapshot_evidence(self.snapshot_path) != request.expected_snapshot:
                    raise RuntimeError("test snapshot changed before exec")
                argv = (str(self.snapshot_path), *request.arguments)
                _ORIGINAL_EXECVE(self.snapshot_path, argv, dict(request.environment))
            except BaseException:
                try:
                    os.write(failure_fd, b"E")
                except BaseException:
                    pass
                os._exit(127)

        self.last_pid = pid
        os.close(error_write)
        try:
            while True:
                remaining = request.deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("test secure launch acknowledgement timed out")
                readable, _, _ = select.select(
                    [error_read],
                    [],
                    [],
                    min(0.05, remaining),
                )
                if not readable:
                    continue
                payload = os.read(error_read, 2)
                if payload:
                    raise RuntimeError("test secure launch failed")
                break
        except BaseException:
            _kill_and_reap(pid)
            raise
        finally:
            os.close(error_read)

        return ManagedAuthRefreshProcess(
            pid=pid,
            process_group_id=os.getpgid(pid),
            session_id=os.getsid(pid),
            snapshot=self.receipt_snapshot or self.authenticated_snapshot,
            profile_sha256=self.receipt_profile_sha256 or self.profile_sha256,
        )

    def record_closure(
        self,
        receipt: ManagedAuthRefreshClosureReceipt,
    ) -> None:
        if self.last_pid is not None and receipt.pid != self.last_pid:
            raise RuntimeError("test closure receipt changed leader")
        self.closures.append(receipt)


class _StalledLaunchCapability(_TestLaunchCapability):
    def __init__(
        self,
        snapshot_path: pathlib.Path,
        stalled_pid_path: pathlib.Path,
    ) -> None:
        super().__init__(snapshot_path)
        self.stalled_pid_path = stalled_pid_path

    def launch(
        self,
        request: ManagedAuthRefreshLaunchRequest,
    ) -> ManagedAuthRefreshProcess:
        self.requests.append(request)
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                self.stalled_pid_path.write_text(str(os.getpid()), encoding="ascii")
                time.sleep(60)
            finally:
                os._exit(127)

        while not self.stalled_pid_path.exists():
            if time.monotonic() >= request.deadline_monotonic:
                _kill_and_reap(pid)
                raise TimeoutError("test stalled launch did not establish containment")
            time.sleep(0.005)
        return ManagedAuthRefreshProcess(
            pid=pid,
            process_group_id=os.getpgid(pid),
            session_id=os.getsid(pid),
            snapshot=self.authenticated_snapshot,
            profile_sha256=self.profile_sha256,
        )


class ManagedAuthRefreshTests(unittest.TestCase):
    def _fixture(
        self,
        root: pathlib.Path,
        *,
        mode: str,
        fake_bytes: int = 0,
    ) -> tuple[pathlib.Path, pathlib.Path, dict[str, str], pathlib.Path, pathlib.Path]:
        root.mkdir(mode=0o700)
        snapshot = root / "codex-snapshot"
        neutral = root / "neutral"
        neutral.mkdir(mode=0o700)
        home = root / "home"
        home.mkdir(mode=0o700)
        codex_home = home / ".codex"
        codex_home.mkdir(mode=0o700)
        pid_path = root / "pid"
        observed_path = root / "observed.json"
        ready_path = root / "ready"
        descendant_status_path = root / "descendant-status"
        temp_dir = root / "tmp"
        temp_dir.mkdir(mode=0o700)
        snapshot.write_text(
            _fake_app_server(
                mode=mode,
                fake_bytes=fake_bytes,
                pid_path=pid_path,
                observed_path=observed_path,
                ready_path=ready_path,
                descendant_status_path=descendant_status_path,
            ),
            encoding="utf-8",
        )
        snapshot.chmod(0o500)
        environment = {
            "CODEX_HOME": str(codex_home),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": auth_refresh.SAFE_PATH,
            "TMPDIR": f"{temp_dir}/",
        }
        return snapshot, neutral, environment, pid_path, observed_path

    def _refresh(
        self,
        *,
        snapshot: pathlib.Path,
        neutral_cwd: pathlib.Path,
        environment: dict[str, str] | None = None,
        expected_codex_home: pathlib.Path | None = None,
        limits: ManagedAuthRefreshLimits = ManagedAuthRefreshLimits(),
        capability: _TestLaunchCapability | None = None,
        liveness_checkpoint: Callable[[], None] = lambda: None,
    ) -> auth_refresh.ManagedAuthRefreshResult:
        launch_capability = capability or _TestLaunchCapability(snapshot)
        return refresh_managed_auth(
            launch_capability=launch_capability,
            expected_snapshot=launch_capability.authenticated_snapshot,
            expected_profile_sha256=launch_capability.profile_sha256,
            neutral_cwd=neutral_cwd,
            environment=environment,
            expected_codex_home=expected_codex_home,
            limits=limits,
            liveness_checkpoint=liveness_checkpoint,
        )

    def _limits(self, **changes: object) -> ManagedAuthRefreshLimits:
        baseline = ManagedAuthRefreshLimits(
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            max_record_bytes=2048,
            total_seconds=5.0,
            shutdown_seconds=0.4,
            cleanup_reserve_seconds=0.6,
            term_grace_seconds=0.05,
        )
        return dataclasses.replace(baseline, **changes)

    def _assert_process_gone(self, pid_path: pathlib.Path) -> None:
        pid = int(pid_path.read_text(encoding="ascii"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def _wait_for_path(self, path: pathlib.Path, *, deadline: float) -> None:
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"timed out waiting for {path.name}")
            time.sleep(0.01)

    def _wait_for_child(self, pid: int, *, deadline: float) -> int:
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                return status
            if time.monotonic() >= deadline:
                self.fail("timed out waiting for supervisor child")
            time.sleep(0.01)

    def test_refreshes_managed_auth_without_model_or_sensitive_result(self) -> None:
        with owned_temporary_directory("auth-refresh-success-") as root:
            snapshot, neutral, environment, pid_path, observed_path = self._fixture(
                root / "case",
                mode="success",
            )
            previous_handlers = tuple(
                signal.getsignal(value)
                for value in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
            )
            capability = _TestLaunchCapability(snapshot)
            result = self._refresh(
                snapshot=snapshot,
                neutral_cwd=neutral,
                environment=environment,
                limits=self._limits(total_seconds=5.0),
                capability=capability,
            )
            observed = json.loads(observed_path.read_text(encoding="utf-8"))

            self.assertEqual(
                dataclasses.asdict(result),
                {
                    "codex_home_verified": True,
                    "managed_auth_verified": True,
                    "process_closure": {
                        "exit_code": 0,
                        "leader_reaped": True,
                        "pid": capability.last_pid,
                        "process_group_empty": True,
                        "process_group_id": capability.last_pid,
                        "profile_sha256": capability.profile_sha256,
                        "session_id": capability.last_pid,
                        "stdio_closed": True,
                    },
                    "refresh_completed": True,
                    "requires_openai_auth": True,
                },
            )
            self.assertEqual(observed["initialize"]["method"], "initialize")
            self.assertEqual(observed["initialized"], {"method": "initialized"})
            self.assertEqual(observed["account_read"]["method"], "account/read")
            self.assertEqual(
                observed["account_read"]["params"],
                {"refreshToken": True},
            )
            self.assertEqual(len(capability.requests), 1)
            request = capability.requests[0]
            self.assertEqual(
                request.arguments,
                (
                    "app-server",
                    "--session-source",
                    "exec",
                    "--strict-config",
                    *APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
                    "--stdio",
                ),
            )
            self.assertEqual(
                request.expected_snapshot, capability.authenticated_snapshot
            )
            self.assertEqual(
                request.expected_profile_sha256,
                capability.profile_sha256,
            )
            self.assertNotIn(str(snapshot), request.arguments)
            with self.assertRaises(TypeError):
                request.environment["NEW_KEY"] = "forbidden"  # type: ignore[index]
            self.assertTrue(observed["stdin_eof"])
            observed_environment_keys = set(observed["environment_keys"])
            self.assertTrue(set(environment) <= observed_environment_keys)
            self.assertLessEqual(
                observed_environment_keys - set(environment),
                {"__CF_USER_TEXT_ENCODING"},
            )
            self.assertTrue(
                {"BASH_ENV", "NODE_OPTIONS", "PYTHONPATH"}.isdisjoint(
                    observed_environment_keys
                )
            )
            self.assertNotIn("model", json.dumps(observed, sort_keys=True).lower())
            self.assertNotIn("private-user", repr(result))
            self.assertEqual(capability.closures, [result.process_closure])
            self.assertEqual(list(neutral.iterdir()), [])
            self.assertEqual(
                tuple(
                    signal.getsignal(value)
                    for value in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
                ),
                previous_handlers,
            )
            self._assert_process_gone(pid_path)

    def test_outer_drop_mid_refresh_terminates_reaps_and_reports_closure(self) -> None:
        with owned_temporary_directory("auth-refresh-outer-drop-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="ignore-signals",
            )
            ready_path = pid_path.with_name("ready")
            capability = _TestLaunchCapability(snapshot)

            def require_outer() -> None:
                if ready_path.exists():
                    raise RuntimeError("synthetic outer EOF")

            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                    capability=capability,
                    liveness_checkpoint=require_outer,
                )

            self.assertEqual(raised.exception.code, "runtime-failed")
            self._assert_process_gone(pid_path)
            self.assertEqual(len(capability.closures), 1)
            closure = capability.closures[0]
            self.assertTrue(closure.leader_reaped)
            self.assertTrue(closure.process_group_empty)
            self.assertTrue(closure.stdio_closed)

    def test_public_api_has_no_raw_snapshot_path_or_exec_fallback(self) -> None:
        parameters = inspect.signature(refresh_managed_auth).parameters
        self.assertNotIn("snapshot_executable", parameters)
        self.assertIn("launch_capability", parameters)
        self.assertIn("expected_snapshot", parameters)
        self.assertIn("expected_profile_sha256", parameters)
        self.assertNotIn(
            "snapshot_path",
            ManagedAuthRefreshLaunchRequest.__dataclass_fields__,
        )
        self.assertNotIn(
            "executable",
            ManagedAuthRefreshLaunchRequest.__dataclass_fields__,
        )
        self.assertNotIn("os.execve(", inspect.getsource(auth_refresh))
        self.assertFalse(hasattr(auth_refresh, "_SignalRelay"))

        with owned_temporary_directory("auth-refresh-no-raw-path-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="success",
            )
            with self.assertRaisesRegex(TypeError, "snapshot_executable"):
                refresh_managed_auth(
                    snapshot_executable=snapshot,  # type: ignore[call-arg]
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )
            self.assertFalse(pid_path.exists())

    def test_rejects_rebased_snapshot_and_profile_before_launch(self) -> None:
        with owned_temporary_directory("auth-refresh-rebased-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "snapshot",
                mode="success",
            )
            capability = _TestLaunchCapability(snapshot)
            expected_snapshot = capability.authenticated_snapshot
            expected_profile_sha256 = capability.profile_sha256

            replacement = snapshot.with_name("replacement")
            replacement.write_bytes(snapshot.read_bytes() + b"\n")
            replacement.chmod(0o500)
            os.replace(replacement, snapshot)
            capability.authenticated_snapshot = _snapshot_evidence(snapshot)

            with self.assertRaises(ManagedAuthRefreshError) as snapshot_raised:
                refresh_managed_auth(
                    launch_capability=capability,
                    expected_snapshot=expected_snapshot,
                    expected_profile_sha256=expected_profile_sha256,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )
            self.assertEqual(
                snapshot_raised.exception.code,
                "snapshot-attestation-mismatch",
            )
            self.assertEqual(capability.requests, [])
            self.assertFalse(pid_path.exists())

            capability.authenticated_snapshot = expected_snapshot
            capability.profile_sha256 = "f" * 64
            with self.assertRaises(ManagedAuthRefreshError) as profile_raised:
                refresh_managed_auth(
                    launch_capability=capability,
                    expected_snapshot=expected_snapshot,
                    expected_profile_sha256=expected_profile_sha256,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )
            self.assertEqual(
                profile_raised.exception.code,
                "profile-attestation-mismatch",
            )
            self.assertEqual(capability.requests, [])
            self.assertFalse(pid_path.exists())

    def test_mismatched_launch_receipt_is_rejected_and_child_is_reaped(self) -> None:
        with owned_temporary_directory("auth-refresh-receipt-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="success",
            )
            capability = _TestLaunchCapability(snapshot)
            capability.receipt_snapshot = dataclasses.replace(
                capability.authenticated_snapshot,
                sha256="0" * 64,
            )
            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                    capability=capability,
                )
            self.assertEqual(
                raised.exception.code,
                "snapshot-attestation-mismatch",
            )
            self.assertIsNotNone(capability.last_pid)
            with self.assertRaises(ProcessLookupError):
                os.kill(capability.last_pid or -1, 0)
            if pid_path.exists():
                self._assert_process_gone(pid_path)

    def test_launch_failure_is_sanitized_and_closes_parent_descriptors(self) -> None:
        marker = "sensitive-launch-capability-marker"
        with owned_temporary_directory("auth-refresh-launch-failure-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="success",
            )
            capability = _TestLaunchCapability(snapshot)
            capability.failure = RuntimeError(marker)
            original_pipe = auth_refresh.os.pipe
            opened: list[int] = []

            def capture_pipe() -> tuple[int, int]:
                pair = original_pipe()
                opened.extend(pair)
                return pair

            with (
                mock.patch.object(
                    auth_refresh.os,
                    "pipe",
                    side_effect=capture_pipe,
                ),
                self.assertRaises(ManagedAuthRefreshError) as raised,
            ):
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                    capability=capability,
                )

            self.assertEqual(raised.exception.stage, "launch")
            self.assertEqual(raised.exception.code, "launch-failed")
            self.assertNotIn(marker, repr(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
            self.assertFalse(pid_path.exists())
            traceback_names: list[str] = []
            traceback = raised.exception.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                traceback_names.append(frame.f_code.co_name)
                if frame.f_globals.get("__name__") == "review_supervisor.auth_refresh":
                    self.assertNotIn(marker, repr(frame.f_locals))
                    self.assertFalse(
                        any(value is capability for value in frame.f_locals.values())
                    )
                traceback = traceback.tb_next
            self.assertNotIn("_launch_refresh_process", traceback_names)
            self.assertNotIn("_run_bounded_refresh_process", traceback_names)
            for descriptor in opened:
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_rejects_server_requests_and_unknown_notifications(self) -> None:
        cases = {
            "server-request": "server-request",
            "unknown-notification": "unknown-notification",
        }
        with owned_temporary_directory("auth-refresh-protocol-") as root:
            for mode, expected_code in cases.items():
                with self.subTest(mode=mode):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / mode,
                        mode=mode,
                    )
                    with self.assertRaises(ManagedAuthRefreshError) as raised:
                        self._refresh(
                            snapshot=snapshot,
                            neutral_cwd=neutral,
                            environment=environment,
                            limits=self._limits(),
                        )
                    self.assertEqual(
                        raised.exception.stage,
                        "protocol",
                        raised.exception.code,
                    )
                    self.assertEqual(raised.exception.code, expected_code)
                    self.assertNotIn("sensitive-runtime-marker", str(raised.exception))
                    self._assert_process_gone(pid_path)

    def test_accepts_account_response_without_account_update(self) -> None:
        with owned_temporary_directory("auth-refresh-no-update-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="missing-account-update",
            )
            result = self._refresh(
                snapshot=snapshot,
                neutral_cwd=neutral,
                environment=environment,
                limits=self._limits(),
            )
            self.assertTrue(result.refresh_completed)
            self.assertTrue(result.managed_auth_verified)
            self._assert_process_gone(pid_path)

    def test_accepts_account_update_after_account_response(self) -> None:
        with owned_temporary_directory("auth-refresh-late-update-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="response-before-account-update",
            )
            result = self._refresh(
                snapshot=snapshot,
                neutral_cwd=neutral,
                environment=environment,
                limits=self._limits(),
            )
            self.assertTrue(result.refresh_completed)
            self.assertTrue(result.managed_auth_verified)
            self._assert_process_gone(pid_path)

    def test_requires_remote_disabled_before_account_response(self) -> None:
        cases = {
            "missing-remote-status": "remote-control-status-missing",
            "remote-control-enabled": "remote-control-enabled",
        }
        with owned_temporary_directory("auth-refresh-evidence-") as root:
            for mode, expected_code in cases.items():
                with self.subTest(mode=mode):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / mode,
                        mode=mode,
                    )
                    with self.assertRaises(ManagedAuthRefreshError) as raised:
                        self._refresh(
                            snapshot=snapshot,
                            neutral_cwd=neutral,
                            environment=environment,
                            limits=self._limits(),
                        )
                    self.assertEqual(raised.exception.stage, "protocol")
                    self.assertEqual(raised.exception.code, expected_code)
                    self._assert_process_gone(pid_path)

    def test_enforces_stdout_stderr_record_and_total_limits(self) -> None:
        cases = (
            (
                "stdout-limit",
                256,
                self._limits(max_stdout_bytes=128, max_record_bytes=128),
                "stdout-limit",
            ),
            (
                "stderr-limit",
                256,
                self._limits(max_stderr_bytes=128),
                "stderr-limit",
            ),
            (
                "record-limit",
                256,
                self._limits(max_stdout_bytes=1024, max_record_bytes=128),
                "record-limit",
            ),
            (
                "total-timeout",
                0,
                self._limits(
                    total_seconds=5.0,
                    cleanup_reserve_seconds=0.5,
                    shutdown_seconds=0.2,
                ),
                "total-timeout",
            ),
        )
        with owned_temporary_directory("auth-refresh-bounds-") as root:
            for mode, fake_bytes, limits, expected_code in cases:
                with self.subTest(mode=mode):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / mode,
                        mode=mode,
                        fake_bytes=fake_bytes,
                    )
                    with self.assertRaises(ManagedAuthRefreshError) as raised:
                        self._refresh(
                            snapshot=snapshot,
                            neutral_cwd=neutral,
                            environment=environment,
                            limits=limits,
                        )
                    self.assertEqual(raised.exception.code, expected_code)
                    self._assert_process_gone(pid_path)

    def test_closes_stdin_then_requires_bounded_process_exit(self) -> None:
        with owned_temporary_directory("auth-refresh-shutdown-") as root:
            snapshot, neutral, environment, pid_path, observed_path = self._fixture(
                root / "case",
                mode="shutdown-timeout",
            )
            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(
                        total_seconds=5.0,
                        shutdown_seconds=0.15,
                    ),
                )
            self.assertEqual(raised.exception.code, "shutdown-timeout")
            observed = json.loads(observed_path.read_text(encoding="utf-8"))
            self.assertTrue(observed["stdin_eof"])
            self._assert_process_gone(pid_path)

    def test_remote_error_and_stderr_are_not_disclosed(self) -> None:
        with owned_temporary_directory("auth-refresh-private-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="remote-error",
            )
            environment_marker = "sensitive-environment-frame-marker"
            private_home = root / environment_marker
            private_home.mkdir(mode=0o700)
            environment["HOME"] = str(private_home)
            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )
            rendered = f"{raised.exception!r} {raised.exception}"
            self.assertEqual(raised.exception.code, "remote-error")
            self.assertNotIn("private-user@example.invalid", rendered)
            self.assertNotIn("sensitive-runtime-marker", rendered)
            traceback_names: list[str] = []
            traceback = raised.exception.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                traceback_names.append(frame.f_code.co_name)
                if frame.f_globals.get("__name__") == "review_supervisor.auth_refresh":
                    self.assertNotIn(environment_marker, repr(frame.f_locals))
                    self.assertFalse(
                        any(value is environment for value in frame.f_locals.values())
                    )
                traceback = traceback.tb_next
            self.assertNotIn("_consume_stdout_records", traceback_names)
            self.assertNotIn("_accept_response", traceback_names)
            self.assertNotIn("_refresh_managed_auth_boundary", traceback_names)
            self.assertNotIn("_run_bounded_refresh_process", traceback_names)
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
            self._assert_process_gone(pid_path)

    def test_freezes_environment_once_and_passes_the_validated_object(self) -> None:
        class CountingEnvironment(dict[str, str]):
            items_calls = 0

            def items(self):  # type: ignore[no-untyped-def]
                self.items_calls += 1
                return super().items()

        with owned_temporary_directory("auth-refresh-env-copy-") as root:
            snapshot, neutral, source, _, _ = self._fixture(
                root / "case",
                mode="success",
            )
            environment = CountingEnvironment(source)
            validated: list[dict[str, str]] = []
            launched: list[dict[str, str]] = []
            original_validator = auth_refresh._validated_environment

            def validate_once(value):  # type: ignore[no-untyped-def]
                result = original_validator(value)
                validated.append(result[0])
                return result

            def capture_launch(**kwargs):  # type: ignore[no-untyped-def]
                launched.append(kwargs["environment"])
                return auth_refresh.ManagedAuthRefreshResult(
                    refresh_completed=True,
                    managed_auth_verified=True,
                    codex_home_verified=True,
                    requires_openai_auth=False,
                )

            with (
                mock.patch.object(
                    auth_refresh,
                    "_validated_environment",
                    side_effect=validate_once,
                ),
                mock.patch.object(
                    auth_refresh,
                    "_run_bounded_refresh_process",
                    side_effect=capture_launch,
                ),
            ):
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )

            self.assertEqual(environment.items_calls, 1)
            self.assertEqual(len(validated), 1)
            self.assertEqual(len(launched), 1)
            self.assertIs(launched[0], validated[0])
            self.assertIsNot(launched[0], environment)
            self.assertEqual(environment, source)

    def test_rejects_interpreter_and_shell_injection_environment(self) -> None:
        cases = {
            "BASH_ENV": str(pathlib.Path("/tmp") / "bash-env"),
            "NODE_OPTIONS": "--require=/tmp/injected.js",
            "PYTHONPATH": "/tmp/injected-python",
            "PATH": "/tmp/injected-bin:/usr/bin:/bin",
        }
        with owned_temporary_directory("auth-refresh-env-reject-") as root:
            for key, value in cases.items():
                with self.subTest(key=key):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / key.lower(),
                        mode="success",
                    )
                    environment[key] = value
                    with self.assertRaises(ManagedAuthRefreshError) as raised:
                        self._refresh(
                            snapshot=snapshot,
                            neutral_cwd=neutral,
                            environment=environment,
                            limits=self._limits(),
                        )
                    self.assertEqual(raised.exception.code, "unsafe-environment")
                    self.assertNotIn(value, str(raised.exception))
                    self.assertFalse(pid_path.exists())

    def test_hard_process_limit_denies_escaped_descendants(self) -> None:
        with owned_temporary_directory("auth-refresh-descendant-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="escape-descendant",
            )
            status_path = pid_path.with_name("descendant-status")
            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(
                        total_seconds=5.0,
                        cleanup_reserve_seconds=0.5,
                    ),
                )
            self.assertEqual(raised.exception.code, "total-timeout")
            status = status_path.read_text(encoding="ascii")
            if status.startswith("spawned:"):
                escaped_pid = int(status.partition(":")[2])
                try:
                    os.kill(escaped_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fail("no-descendant process contract allowed an escaped child")
            self.assertEqual(status, f"denied:{errno.EAGAIN}")
            self._assert_process_gone(pid_path)

    def test_capability_launched_stall_is_bounded_and_reaped(self) -> None:
        with owned_temporary_directory("auth-refresh-launch-bound-") as root:
            snapshot, neutral, environment, _, _ = self._fixture(
                root / "case",
                mode="success",
            )
            stalled_pid_path = root / "stalled-child-pid"
            capability = _StalledLaunchCapability(snapshot, stalled_pid_path)
            started = time.monotonic()
            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    capability=capability,
                    limits=self._limits(
                        total_seconds=1.2,
                        cleanup_reserve_seconds=0.4,
                        shutdown_seconds=0.2,
                    ),
                )
            elapsed = time.monotonic() - started
            self.assertEqual(raised.exception.code, "total-timeout")
            self.assertLess(elapsed, 1.8)
            self._assert_process_gone(stalled_pid_path)

    def test_partial_pipe_setup_failure_closes_open_descriptors(self) -> None:
        with owned_temporary_directory("auth-refresh-pipe-failure-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="success",
            )
            original_pipe = auth_refresh.os.pipe
            opened: list[int] = []

            def fail_second_pipe() -> tuple[int, int]:
                if opened:
                    raise OSError(errno.EMFILE, "synthetic pipe limit")
                pair = original_pipe()
                opened.extend(pair)
                return pair

            with (
                mock.patch.object(
                    auth_refresh.os,
                    "pipe",
                    side_effect=fail_second_pipe,
                ),
                self.assertRaises(ManagedAuthRefreshError) as raised,
            ):
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(),
                )
            self.assertEqual(raised.exception.code, "runtime-failed")
            self.assertFalse(pid_path.exists())
            for descriptor in opened:
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_unhashable_plan_types_are_protocol_rejections(self) -> None:
        modes = ("account-plan-list", "notification-plan-object")
        with owned_temporary_directory("auth-refresh-plan-type-") as root:
            for mode in modes:
                with self.subTest(mode=mode):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / mode,
                        mode=mode,
                    )
                    with self.assertRaises(ManagedAuthRefreshError) as raised:
                        self._refresh(
                            snapshot=snapshot,
                            neutral_cwd=neutral,
                            environment=environment,
                            limits=self._limits(),
                        )
                    self.assertEqual(raised.exception.stage, "protocol")
                    self.assertEqual(raised.exception.code, "account-schema")
                    self._assert_process_gone(pid_path)

    def test_host_signals_wait_for_cleanup_then_restore_default_action(self) -> None:
        with owned_temporary_directory("auth-refresh-host-signal-") as root:
            for value in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
                with self.subTest(signal=value.name):
                    snapshot, neutral, environment, pid_path, _ = self._fixture(
                        root / value.name.lower(),
                        mode="ignore-signals",
                    )
                    ready_path = pid_path.with_name("ready")
                    supervisor_pid = os.fork()
                    if supervisor_pid == 0:
                        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                        signal.signal(signal.SIGTERM, signal.SIG_DFL)
                        signal.signal(signal.SIGHUP, signal.SIG_DFL)
                        signal.signal(signal.SIGQUIT, signal.SIG_DFL)
                        try:
                            self._refresh(
                                snapshot=snapshot,
                                neutral_cwd=neutral,
                                environment=environment,
                                limits=self._limits(
                                    total_seconds=4.0,
                                    cleanup_reserve_seconds=1.0,
                                ),
                            )
                        except BaseException:
                            os._exit(97)
                        os._exit(98)

                    status: int | None = None
                    try:
                        self._wait_for_path(
                            ready_path,
                            deadline=time.monotonic() + 3.0,
                        )
                        os.kill(supervisor_pid, value)
                        status = self._wait_for_child(
                            supervisor_pid,
                            deadline=time.monotonic() + 3.0,
                        )
                        expected_signal = (
                            signal.SIGTERM if value == signal.SIGQUIT else value
                        )
                        self.assertEqual(
                            os.waitstatus_to_exitcode(status),
                            -int(expected_signal),
                        )
                        self._assert_process_gone(pid_path)
                    finally:
                        if status is None:
                            try:
                                os.kill(supervisor_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            try:
                                os.waitpid(supervisor_pid, 0)
                            except ChildProcessError:
                                pass

    def test_shared_signal_redelivery_failure_is_sanitized(self) -> None:
        marker = "sensitive-signal-handler-marker"
        relay = auth_refresh.HostSignalRelay()
        outcome = auth_refresh._BoundaryOutcome(signal_relay=relay)
        self.assertEqual(
            auth_refresh.HostSignalRelay.__module__,
            "review_supervisor.signal_relay",
        )
        with (
            mock.patch.object(
                relay,
                "redeliver",
                side_effect=RuntimeError(marker),
            ),
            self.assertRaises(ManagedAuthRefreshError) as raised,
        ):
            auth_refresh._finish_boundary(outcome)
        self.assertEqual(raised.exception.code, "signal-redelivery")
        self.assertNotIn(marker, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_verifies_normal_codex_home_from_child_environment(self) -> None:
        with owned_temporary_directory("auth-refresh-home-") as root:
            snapshot, neutral, environment, pid_path, _ = self._fixture(
                root / "case",
                mode="codex-home-mismatch",
            )
            empty_codex_home = {**environment, "CODEX_HOME": ""}
            with self.assertRaises(ManagedAuthRefreshError) as empty_raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=empty_codex_home,
                    limits=self._limits(),
                )
            self.assertEqual(empty_raised.exception.code, "codex-home-missing")
            self.assertFalse(pid_path.exists())

            with self.assertRaises(ManagedAuthRefreshError) as raised:
                self._refresh(
                    snapshot=snapshot,
                    neutral_cwd=neutral,
                    environment=environment,
                    limits=self._limits(total_seconds=5.0),
                )
            self.assertEqual(raised.exception.code, "codex-home-mismatch")
            self._assert_process_gone(pid_path)


if __name__ == "__main__":
    unittest.main()
