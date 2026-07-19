from __future__ import annotations

import contextlib
import errno
import hashlib
import itertools
import json
import multiprocessing
import os
import pathlib
import re
import signal
import socket
import socketserver
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from unittest import mock

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_linux,
    claude_provenance,
    claude_refresh_lock,
    common,
    providers,
    workspace as workspace_runtime,
)
from review_runtime.common import Completed, ReviewError  # noqa: E402
from review_runtime.workspace import ReviewWorkspace  # noqa: E402


def oauth_credential_fixture(*, expires_in_seconds: float = 7200) -> bytes:
    payload: dict[str, object] = {
        "claudeAiOauth": {
            "access" + "Token": "fixture-" + "access-value",
            "refresh" + "Token": "fixture-" + "refresh-value",
            "expiresAt": (time.time() + expires_in_seconds) * 1000,
        }
    }
    return json.dumps(payload).encode()


CLAUDE_SAFE_MODE_DESCRIPTION = (
    "Start with all customizations (CLAUDE.md, skills, plugins, hooks, MCP "
    "servers, custom commands and agents, output styles, workflows, custom "
    "themes, keybindings, and more) disabled. Admin-managed (policy) settings "
    "still apply. Auth, model selection, built-in tools, and permissions work "
    "normally. Sets CLAUDE_CODE_SAFE_MODE=1."
)


def claude_help_fixture(*, safe_mode: str | None = None) -> bytes:
    safe_mode = safe_mode or CLAUDE_SAFE_MODE_DESCRIPTION
    lines = ["Usage: claude [options]", "", "Options:"]
    for option in claude_capabilities.CLAUDE_REQUIRED_OPTIONS:
        if option == "--safe-mode":
            description = safe_mode
        elif option == "--permission-mode":
            description = "Permission mode (choices: default, dontAsk, plan)."
        else:
            description = "Supported option."
        lines.append(f"  {option} <value>  {description}")
    return ("\n".join(lines) + "\n").encode()


def _blocked_keychain_handler_worker(connection: object, mode: str) -> None:
    send = getattr(connection, "send")
    close = getattr(connection, "close")
    capability = bytes.fromhex("01" * 32)
    credential = bytearray(b"fixture-keychain-credential")
    refreshed = oauth_credential_fixture(expires_in_seconds=7200)
    callback_started = threading.Event()
    block_callback = threading.Event()
    retained_payload: bytes | None = None

    def receive_exact(sock: socket.socket, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            chunk = sock.recv(length - len(result))
            if not chunk:
                raise RuntimeError("keychain broker closed unexpectedly")
            result.extend(chunk)
        return bytes(result)

    def blocked_update(
        _updated: bytearray,
        commit_pending: Callable[[Callable[[], bool]], bool],
        _claim_terminal: Callable[[], bool],
    ) -> bool:
        callback_started.set()
        block_callback.wait()
        return commit_pending(lambda: False)

    def retain_update(updated: bytearray | None) -> BaseException | None:
        nonlocal retained_payload
        if updated is None:
            return None
        if mode == "recovery":
            block_callback.wait()
        retained_payload = bytes(updated)
        failure = providers.ClaudeCredentialInspectionInconclusive(
            "fixture recovery carrier retained"
        )
        setattr(failure, "_codex_claude_refresh_persistence_failed", True)
        return failure

    def recovery_timeout_error() -> BaseException:
        failure = providers.ClaudeCredentialInspectionInconclusive(
            "fixture recovery timeout"
        )
        setattr(failure, "_codex_claude_refresh_persistence_failed", True)
        return failure

    def write_update(port: int) -> None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
                sock.sendall(
                    capability
                    + b"W"
                    + len(refreshed).to_bytes(4, "big")
                    + refreshed
                )
                with contextlib.suppress(OSError):
                    sock.recv(1)
        except OSError:
            pass

    def forward_signal(signum: int, _frame: object) -> None:
        raise providers.ForwardedSignal(signum)

    if mode == "signal":
        signal.signal(signal.SIGTERM, forward_signal)

    try:
        with mock.patch.object(
            providers,
            "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
            0.15,
        ), mock.patch.object(
            providers,
            "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
            0.15,
        ):
            with providers._claude_keychain_credential_server(
                credential,
                capability,
                update_callback=blocked_update,
                quiescence_callbacks=(
                    providers._ClaudeKeychainQuiescenceCallbacks(
                        abandon=lambda: None,
                        recover=retain_update,
                        timeout_error=recovery_timeout_error,
                    )
                ),
            ) as port:
                with socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=2.0,
                ) as sock:
                    sock.sendall(capability + b"R")
                    length = int.from_bytes(receive_exact(sock, 4), "big")
                    receive_exact(sock, length)
                writer = threading.Thread(
                    target=write_update,
                    args=(port,),
                    daemon=True,
                )
                writer.start()
                if not callback_started.wait(timeout=2.0):
                    raise RuntimeError("blocked update callback did not start")
                send(("ready", mode))
                if mode in {"timeout", "recovery"}:
                    raise providers.ReviewTimeoutError("fixture review timeout")
                while True:
                    time.sleep(1.0)
    except BaseException as error:
        send(
            (
                "result",
                type(error).__name__,
                bool(
                    getattr(
                        error,
                        (
                            "_codex_claude_keychain_handler_"
                            "quiescence_unproven"
                        ),
                        False,
                    )
                ),
                bool(
                    getattr(
                        error,
                        "_codex_claude_refresh_persistence_failed",
                        False,
                    )
                ),
                retained_payload == refreshed,
            )
        )
    finally:
        close()


class ProviderPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name).resolve()
        # Security fixtures must not inherit a permissive host or CI umask.
        source_root = root / "source"
        source_root.mkdir(mode=0o700)
        codex_tmp = source_root / ".codex-tmp"
        codex_tmp.mkdir(mode=0o700)
        container = codex_tmp / "isolated-review-test"
        container.mkdir(mode=0o700)
        workspace = container / "workspace"
        workspace.mkdir(mode=0o700)
        control = workspace / ".codex-review"
        control.mkdir(mode=0o700)
        diff_file = control / "review.diff"
        diff_file.write_text("diff --git a/a b/a\n", encoding="utf-8")
        (control / "changed-paths.z").write_bytes(b"")
        (control / "changed-blob-findings.z").write_bytes(b"")
        catalog = workspace_runtime.load_catalog()
        synthetic_manifest = {
            "catalog_schema_version": catalog.schema_version,
            "entries": [],
            "pool_version": catalog.pool_version,
            "schema_version": workspace_runtime.SYNTHETIC_MANIFEST_SCHEMA_VERSION,
            "selected_exemptions": [],
        }
        workspace_runtime._write_bounded_json(
            control / workspace_runtime.SYNTHETIC_MANIFEST_NAME,
            synthetic_manifest,
            label="synthetic secret manifest",
        )
        workspace_runtime._write_bounded_json(
            container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME,
            synthetic_manifest,
            label="synthetic secret helper-private state",
        )
        workspace_runtime._write_bounded_json(
            control / workspace_runtime.SYNTHETIC_CHANGED_EVIDENCE_NAME,
            {"entries": [], "schema_version": 1},
            label="synthetic changed-blob evidence",
        )
        prompt_file = control / "review.prompt"
        prompt_file.write_text("Review this diff.\n", encoding="utf-8")
        self.review = ReviewWorkspace(
            source_root=source_root,
            container_dir=container,
            workspace_root=workspace,
            base_ref="a" * 40,
            head_ref="b" * 40,
            diff_file=diff_file,
            prompt_file=prompt_file,
        )
        self._refresh_control_artifact_state()
        self.claude_broker = (
            container / "claude-runtime" / "keychain-broker" / "security"
        )
        self.claude_broker.parent.parent.mkdir(mode=0o700)
        self.claude_broker.parent.mkdir(mode=0o700)
        self.claude_broker.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        self.claude_broker.chmod(0o700)
        self.claude_keychain_client = root / "host-tools" / "security"
        self.claude_ripgrep = root / "host-tools" / "rg"
        self.claude_keychain_client.parent.mkdir(mode=0o700)
        for fixture in (
            self.claude_keychain_client,
            self.claude_ripgrep,
        ):
            fixture.write_bytes(b"fixture")
            fixture.chmod(0o700)
        self.host_dependency_patchers = (
            mock.patch.object(
                providers,
                "CLAUDE_KEYCHAIN_CLIENT",
                self.claude_keychain_client,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_REVIEW_TOOL_EXECUTABLE_CANDIDATES",
                (self.claude_ripgrep,),
            ),
        )
        for patcher in self.host_dependency_patchers:
            patcher.start()
        self.claude_pwd_home = root / "pwd-home"
        self.claude_pwd_home.mkdir(mode=0o700)
        self.claude_pwd_home_patcher = mock.patch.object(
            providers,
            "_claude_pwd_home",
            return_value=self.claude_pwd_home,
        )
        self.claude_pwd_home_patcher.start()
        self.native_macho_dependencies = providers._native_macho_dependencies
        self.native_dependency_patcher = mock.patch.object(
            providers,
            "_native_macho_dependencies",
            side_effect=lambda path, *, label: tuple(
                dict.fromkeys((path.absolute(), path.resolve()))
            ),
        )
        self.native_dependency_patcher.start()
        self.claude_macos_platform_key = providers._claude_macos_platform_key
        self.macos_platform_patcher = mock.patch.object(
            providers,
            "_claude_macos_platform_key",
            return_value="darwin-arm64",
        )
        self.macos_platform_patcher.start()
        # Generic provider-policy tests exercise the macOS lane. Dedicated Linux
        # tests opt into the Linux runtime explicitly at their narrow call site.
        self.claude_linux_platform_patcher = mock.patch.object(
            providers,
            "_is_claude_linux_host",
            return_value=False,
        )
        self.claude_macos_platform_patcher = mock.patch.object(
            providers,
            "_is_claude_macos_host",
            return_value=True,
        )
        self.claude_linux_platform_patcher.start()
        self.claude_macos_platform_patcher.start()
        self.require_trusted_claude_release = (
            providers._require_trusted_claude_release
        )
        self.trusted_release_patcher = mock.patch.object(
            providers,
            "_require_trusted_claude_release",
        )
        self.trusted_release = self.trusted_release_patcher.start()
        self.prepare_claude_keychain_broker = (
            providers._prepare_claude_keychain_broker
        )
        self.keychain_broker_patcher = mock.patch.object(
            providers,
            "_prepare_claude_keychain_broker",
            side_effect=self.fake_prepare_claude_keychain_broker,
        )
        self.keychain_broker_patcher.start()
        self.claude_keychain_runtime = providers._claude_keychain_runtime
        self.claude_refresh_lock_protocol = (
            claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211
        )
        self.keychain_runtime_patcher = mock.patch.object(
            providers,
            "_claude_keychain_runtime",
            side_effect=self.fake_claude_keychain_runtime,
        )
        self.keychain_runtime_patcher.start()

    def _refresh_control_artifact_state(self) -> None:
        control_dir = self.review.workspace_root / ".codex-review"
        state = workspace_runtime._build_control_artifact_state(
            control_dir=control_dir,
        )
        workspace_runtime._write_bounded_json(
            self.review.container_dir / workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
            state,
            label="helper-private review control state",
        )

    def tearDown(self) -> None:
        self.keychain_runtime_patcher.stop()
        self.keychain_broker_patcher.stop()
        self.trusted_release_patcher.stop()
        self.claude_macos_platform_patcher.stop()
        self.claude_linux_platform_patcher.stop()
        self.macos_platform_patcher.stop()
        self.native_dependency_patcher.stop()
        self.claude_pwd_home_patcher.stop()
        for patcher in reversed(self.host_dependency_patchers):
            patcher.stop()
        self.temporary.cleanup()

    def fake_prepare_claude_keychain_broker(
        self,
        _review: ReviewWorkspace,
        env: dict[str, str],
    ) -> dict[str, str]:
        result = dict(env)
        if not result.get("ANTHROPIC_API_KEY"):
            result["PATH"] = os.pathsep.join(
                value
                for value in (str(self.claude_broker.parent), result.get("PATH"))
                if value
            )
        return result

    @contextlib.contextmanager
    def fake_claude_keychain_runtime(
        self,
        _review: ReviewWorkspace,
        env: dict[str, str],
        _refresh_lock_protocol: providers.ClaudeRefreshLockProtocol | None,
    ):
        result = dict(env)
        if not result.get("ANTHROPIC_API_KEY"):
            result[providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = "43211"
            result[providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV] = "00" * 32
        yield result

    def assert_cleanup_diagnostic_preserves_original_cause(
        self,
        error: BaseException,
        original_cause: BaseException,
    ) -> None:
        direct_cause = error.__cause__
        if direct_cause is original_cause:
            return
        self.assertIsInstance(
            direct_cause,
            providers.ClaudeCredentialCleanupDiagnostic,
        )
        self.assertIs(direct_cause.__cause__, original_cause)

    def assert_persistence_diagnostic_visible(
        self,
        error: BaseException,
    ) -> None:
        pending = [error]
        visited: set[int] = set()
        for _ in range(16):
            if not pending:
                break
            current = pending.pop(0)
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            if any(
                providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC in note
                for note in getattr(current, "__notes__", ())
            ):
                return
            if (
                isinstance(
                    current,
                    providers.ClaudeCredentialPersistenceDiagnostic,
                )
                and providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
                in str(current)
            ):
                return
            for related in (current.__cause__, current.__context__):
                if related is not None:
                    pending.append(related)
        self.fail("Claude persistence diagnostic is missing from the exception chain")

    def test_credential_cleanup_signal_overrides_ordinary_primary(self) -> None:
        primary = providers.ClaudeCredentialInspectionInconclusive(
            "injected credential operation failure"
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with self.assertRaises(providers.ForwardedSignal) as raised:
            providers._raise_or_attach_claude_credential_cleanup(
                primary,
                [forwarded],
                message="injected cleanup failure",
            )

        self.assertIs(raised.exception, forwarded)

    def test_primary_credential_signal_precedes_cleanup_interrupt(self) -> None:
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        cleanup_interrupt = KeyboardInterrupt("injected cleanup interrupt")

        providers._raise_or_attach_claude_credential_cleanup(
            forwarded,
            [cleanup_interrupt],
            message="injected cleanup failure",
        )

        notes = getattr(forwarded, "__notes__", ())
        if notes:
            self.assertTrue(any("cleanup failure" in note for note in notes))
        else:
            self.assertIsInstance(
                forwarded.__cause__,
                providers.ClaudeCredentialCleanupDiagnostic,
            )

    def test_cleanup_representation_uses_only_the_visible_error_chain(
        self,
    ) -> None:
        explicit_cause = RuntimeError("injected explicit cause")
        hidden_context = OSError("injected hidden context")
        explicit_primary = providers.ClaudeCredentialInspectionInconclusive(
            "injected explicit-cause primary"
        )
        explicit_primary.__cause__ = explicit_cause
        explicit_primary.__context__ = hidden_context
        self.assertTrue(
            providers._claude_visible_error_chain_contains(
                explicit_primary,
                explicit_cause,
            )
        )
        self.assertFalse(
            providers._claude_visible_error_chain_contains(
                explicit_primary,
                hidden_context,
            )
        )

        primary = providers.ClaudeCredentialInspectionInconclusive(
            "injected credential operation failure"
        )
        hidden_cleanup = OSError("injected hidden cleanup failure")
        primary.__context__ = hidden_cleanup
        primary.__suppress_context__ = True
        self.assertFalse(
            providers._claude_visible_error_chain_contains(
                primary,
                hidden_cleanup,
            )
        )

        implicit_primary = providers.ClaudeCredentialInspectionInconclusive(
            "injected implicit-context primary"
        )
        visible_context = OSError("injected visible context")
        implicit_primary.__context__ = visible_context
        self.assertTrue(
            providers._claude_visible_error_chain_contains(
                implicit_primary,
                visible_context,
            )
        )

        cycle_first = RuntimeError("injected cycle first")
        cycle_second = RuntimeError("injected cycle second")
        cycle_first.__cause__ = cycle_second
        cycle_second.__cause__ = cycle_first
        self.assertFalse(
            providers._claude_visible_error_chain_contains(
                cycle_first,
                OSError("injected unrelated candidate"),
            )
        )

        providers._raise_or_attach_claude_credential_cleanup(
            primary,
            [hidden_cleanup],
            message="injected cleanup failure",
        )

        notes = getattr(primary, "__notes__", ())
        if notes:
            self.assertTrue(any("cleanup failure" in note for note in notes))
        else:
            self.assertIsInstance(
                primary.__cause__,
                providers.ClaudeCredentialCleanupDiagnostic,
            )

    def test_cleanup_diagnostic_fallback_preserves_original_cause(self) -> None:
        class LegacyInspectionError(
            providers.ClaudeCredentialInspectionInconclusive
        ):
            add_note = None

        primary = LegacyInspectionError("injected legacy primary")
        original_cause = RuntimeError("injected original cause")
        primary.__cause__ = original_cause

        providers._attach_claude_credential_cleanup_failure(
            primary,
            OSError("injected cleanup failure"),
        )

        self.assert_cleanup_diagnostic_preserves_original_cause(
            primary,
            original_cause,
        )

    def test_persistence_diagnostic_fallback_preserves_control_flow(self) -> None:
        class LegacyKeyboardInterrupt(KeyboardInterrupt):
            add_note = None

        persistence_error = providers.ClaudeCredentialInspectionInconclusive(
            "injected persistence failure"
        )
        interruption = LegacyKeyboardInterrupt("injected control flow")

        selected = (
            providers._attach_claude_persistence_failure_preserving_control_flow(
                persistence_error,
                interruption,
            )
        )

        self.assertIs(selected, interruption)
        self.assertTrue(
            getattr(
                interruption,
                "_codex_claude_refresh_persistence_failed",
                False,
            )
        )
        self.assert_persistence_diagnostic_visible(interruption)

    def attempt(
        self,
        runtime: str,
        model: str,
        category: str,
        *,
        final_text: str | None = None,
    ) -> providers.Attempt:
        effort = "xhigh" if runtime == "codex" else "max"
        return providers.Attempt(
            runtime=runtime,
            requested_model=model,
            effective_model=model if final_text else None,
            requested_effort=effort,
            effective_effort=effort if final_text else None,
            returncode=0 if final_text else 1,
            category=category,
            final_text=final_text,
            stdout_path=str(self.review.container_dir / "stdout"),
            stderr_path=str(self.review.container_dir / "stderr"),
        )

    def sample_ca_certificates(self, count: int) -> tuple[bytes, ...]:
        defaults = ssl.get_default_verify_paths()
        for raw in (
            defaults.cafile,
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
        ):
            if not raw:
                continue
            path = pathlib.Path(raw)
            if not path.is_file():
                continue
            blocks = tuple(
                block + b"\n"
                for block in dict.fromkeys(
                    providers.CLAUDE_CERTIFICATE_BLOCK.findall(path.read_bytes())
                )
            )
            if len(blocks) >= count:
                return blocks[:count]
        self.skipTest(f"fewer than {count} system PEM CA certificates are available")

    def sample_ca_certificate(self) -> bytes:
        return self.sample_ca_certificates(1)[0]

    def stable_system_ca_file(self) -> tuple[pathlib.Path, bytes]:
        defaults = ssl.get_default_verify_paths()
        for raw in (
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            defaults.cafile,
        ):
            if not raw:
                continue
            try:
                path = pathlib.Path(raw).resolve(strict=True)
                material = providers._read_ca_source(
                    path,
                    source="test system CA",
                )
            except (OSError, ReviewError):
                continue
            return path, material
        self.skipTest("no stable system PEM CA file is available")

    def write_private_source(self, path: pathlib.Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o600)

    def write_pwd_home_credential(self, payload: bytes) -> pathlib.Path:
        config = self.claude_pwd_home / ".claude"
        config.mkdir(mode=0o700, exist_ok=True)
        config.chmod(0o700)
        credential = config / providers.CLAUDE_CREDENTIAL_FILE_NAME
        self.write_private_source(credential, payload)
        return credential

    def assert_macos_recovery_carrier(
        self,
        error: BaseException,
        expected_credential: bytes,
    ) -> pathlib.Path:
        retained = getattr(
            error,
            "_codex_claude_retained_credential_carrier",
            None,
        )
        self.assertIsInstance(retained, str)
        carrier = pathlib.Path(retained)
        self.assertTrue(carrier.is_absolute())
        self.assertEqual(
            carrier.parent,
            self.review.container_dir / "claude-runtime" / "macos",
        )
        config = carrier / "config"
        credential = config / providers.CLAUDE_CREDENTIAL_FILE_NAME
        self.assertEqual(stat.S_IMODE(carrier.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o600)
        self.assertEqual(credential.stat().st_nlink, 1)
        self.assertEqual(credential.read_bytes(), expected_credential)
        return carrier

    def assert_cleanup_only_macos_recovery_artifact(
        self,
        error: BaseException,
    ) -> pathlib.Path:
        self.assertIsNone(
            getattr(
                error,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                error,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        cleanup_value = getattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        self.assertIsInstance(cleanup_value, str)
        cleanup_artifact = pathlib.Path(cleanup_value)
        self.assertTrue(cleanup_artifact.exists())
        return cleanup_artifact

    @staticmethod
    def host_ca_safety_rejection(error: ReviewError, *, source: str) -> bool:
        detail = str(error)
        return any(
            detail.startswith(prefix)
            and detail.removeprefix(prefix).startswith(source)
            for prefix in (
                "Claude review CA source has an unsafe owner: ",
                "Claude review CA source is group- or world-writable: ",
                "Claude review CA directory has an unsafe owner: ",
                "Claude review CA directory is group- or world-writable: ",
                "Claude review CA directory symlink has an unsafe owner: ",
            )
        )

    def test_capacity_wins_over_unavailable_wording(self) -> None:
        category = providers.classify_failure(
            "",
            "Selected model is temporarily unavailable because it is at capacity",
        )
        self.assertEqual(category, "transient")

    def test_host_ca_skip_guard_requires_expected_source_and_safety_error(
        self,
    ) -> None:
        unsafe_host_source = ReviewError(
            "Claude review CA directory is group- or world-writable: "
            "SSL_CERT_DIR:deadbeef.0"
        )
        unsafe_destination = ReviewError(
            "Claude review CA directory is group- or world-writable: "
            "private destination"
        )
        unrelated_host_failure = ReviewError(
            "Claude review CA symlink path contains a loop: "
            "SSL_CERT_DIR:deadbeef.0"
        )
        adversarial_host_failure = ReviewError(
            "Claude review CA symlink path contains a loop: "
            "SSL_CERT_DIR:unsafe owner.pem"
        )

        self.assertTrue(
            self.host_ca_safety_rejection(
                unsafe_host_source,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                unsafe_destination,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                unrelated_host_failure,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                adversarial_host_failure,
                source="SSL_CERT_DIR:",
            )
        )

    def test_native_macho_dependencies_rejects_interpreter_wrapper(self) -> None:
        wrapper = self.review.source_root / "rg-wrapper"
        wrapper.write_text("#!/bin/sh\nexec /usr/bin/rg \"$@\"\n", encoding="utf-8")
        wrapper.chmod(0o755)

        with self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "native Mach-O executable",
        ):
            self.native_macho_dependencies(wrapper, label="ripgrep")

    def test_native_macho_dependencies_accepts_native_magic(self) -> None:
        executable = self.review.source_root / "native-rg"
        executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        executable.chmod(0o755)

        dependencies = self.native_macho_dependencies(executable, label="ripgrep")

        self.assertEqual(
            dependencies,
            tuple(dict.fromkeys((executable.absolute(), executable.resolve()))),
        )

    def test_claude_macho_platform_key_uses_artifact_architecture(self) -> None:
        executable = self.review.source_root / "claude"
        for cpu_type, expected in (
            (0x0100000C, "darwin-arm64"),
            (0x01000007, "darwin-x64"),
        ):
            with self.subTest(expected=expected):
                executable.write_bytes(
                    b"\xcf\xfa\xed\xfe"
                    + cpu_type.to_bytes(4, byteorder="little")
                    + b"\x00" * 24
                )
                self.assertEqual(
                    self.claude_macos_platform_key(executable),
                    expected,
                )

    def test_claude_macho_platform_key_rejects_wrapper_or_fat_binary(self) -> None:
        executable = self.review.source_root / "claude"
        executable.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 28)

        with self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "thin 64-bit Mach-O",
        ):
            self.claude_macos_platform_key(executable)

    def test_claude_release_provenance_maps_invalid_candidate(self) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceInvalid("bad signature"),
            ),
            self.assertRaisesRegex(
                providers.ClaudePublisherProvenanceInvalid,
                "bad signature",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.202",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_release_provenance_maps_missing_verifier_dependency(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceDependencyUnavailable(
                    "missing trusted GPG"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceVerifierUnavailable,
                "missing trusted GPG",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.202",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_release_provenance_maps_runtime_io_to_inconclusive(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceUnavailable(
                    "cannot write verifier snapshot: ENOSPC"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "ENOSPC",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.202",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_safe_mode_security_failure_is_not_candidate_unavailability(
        self,
    ) -> None:
        with mock.patch.object(
            providers,
            "_run_claude_probe",
            return_value=Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=claude_help_fixture(
                    safe_mode=CLAUDE_SAFE_MODE_DESCRIPTION.replace(
                        "hooks, MCP",
                        "hooks still load, MCP",
                    )
                ),
                stderr=b"",
            ),
        ), self.assertRaises(providers.ClaudeSafeModeContractInvalid):
            providers._require_claude_safe_mode(
                pathlib.Path("/bin/claude"),
                {"HOME": str(self.review.container_dir)},
            )

    def test_native_executable_inspection_race_is_inconclusive(self) -> None:
        missing = self.review.source_root / "disappeared-claude"

        with self.assertRaisesRegex(
            providers.ClaudeExecutableInspectionInconclusive,
            "cannot inspect Claude Code executable",
        ):
            self.native_macho_dependencies(missing, label="Claude Code")

    def test_claude_keychain_broker_compiles_and_rejects_other_queries(self) -> None:
        if (
            sys.platform != "darwin"
            or not providers.CLAUDE_KEYCHAIN_BROKER_COMPILER.is_file()
        ):
            self.skipTest("the native Claude Keychain broker requires macOS clang")

        prepared = self.prepare_claude_keychain_broker(
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "PATH": "/usr/bin",
            },
        )
        broker_dir = pathlib.Path(prepared["PATH"].split(providers.os.pathsep)[0])
        broker = broker_dir / "security"

        self.native_macho_dependencies(broker, label="Claude Keychain broker")
        rejected = providers.run((str(broker), "show-keychain-info"))
        self.assertEqual(rejected.returncode, 64)

    @mock.patch.object(
        providers,
        "_ClaudeKeychainCredentialServer",
        side_effect=PermissionError("bind denied"),
    )
    def test_keychain_broker_bind_failure_is_inconclusive(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "Keychain broker cannot bind loopback",
        ):
            with providers._claude_keychain_credential_server(
                None,
                bytes.fromhex("01" * 32),
            ):
                self.fail("unavailable broker unexpectedly started")

    def test_keychain_broker_resource_bind_failures_are_inconclusive(
        self,
    ) -> None:
        for bind_error in (
            OSError(errno.EMFILE, "descriptor capacity exhausted"),
            OSError(errno.EADDRINUSE, "address temporarily unavailable"),
        ):
            with (
                self.subTest(errno=bind_error.errno),
                mock.patch.object(
                    providers,
                    "_ClaudeKeychainCredentialServer",
                    side_effect=bind_error,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ),
            ):
                with providers._claude_keychain_credential_server(
                    None,
                    bytes.fromhex("01" * 32),
                ):
                    self.fail("failed broker unexpectedly started")

    @mock.patch.object(
        providers,
        "_ClaudeKeychainCredentialServer",
        side_effect=PermissionError(errno.EACCES, "bind denied by policy"),
    )
    def test_keychain_broker_policy_bind_denial_is_runtime_unavailable(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "bind denied by policy",
        ):
            with providers._claude_keychain_credential_server(
                None,
                bytes.fromhex("01" * 32),
            ):
                self.fail("unavailable broker unexpectedly started")

    @mock.patch.object(providers, "_read_claude_keychain_credential")
    @mock.patch.object(
        providers,
        "_claude_keychain_credential_server",
        side_effect=providers.ClaudeCredentialInspectionInconclusive(
            "bind denied"
        ),
    )
    def test_keychain_runtime_zeroes_credential_when_broker_bind_fails(
        self,
        _server: mock.Mock,
        read_credential: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=60 * 60))
        read_credential.return_value = credential

        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "bind denied",
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                self.fail("unavailable broker unexpectedly started")

        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_broker_thread_failure_closes_server_and_zeroes_credential(
        self,
    ) -> None:
        credential = bytearray(b"fixture-value")
        server = mock.Mock()
        thread = mock.Mock()
        thread.start.side_effect = RuntimeError("thread unavailable")

        with (
            mock.patch.object(
                providers,
                "_ClaudeKeychainCredentialServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot start",
            ),
        ):
            with providers._claude_keychain_credential_server(
                credential,
                bytes.fromhex("01" * 32),
            ):
                self.fail("unavailable broker unexpectedly started")

        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_not_called()
        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_broker_start_signal_is_preserved_and_scrubbed(self) -> None:
        credential = bytearray(b"fixture-value")
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        server = mock.Mock()
        server.is_serving.return_value = False
        thread = mock.Mock()
        thread.ident = 123
        thread.is_alive.return_value = False
        thread.start.side_effect = forwarded

        with (
            mock.patch.object(
                providers,
                "_ClaudeKeychainCredentialServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with providers._claude_keychain_credential_server(
                credential,
                bytes.fromhex("01" * 32),
            ):
                self.fail("interrupted broker unexpectedly started")

        self.assertIs(raised.exception, forwarded)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()
        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_broker_thread_construction_failure_closes_server(
        self,
    ) -> None:
        credential = bytearray(b"fixture-value")
        server = mock.Mock()

        with (
            mock.patch.object(
                providers,
                "_ClaudeKeychainCredentialServer",
                return_value=server,
            ),
            mock.patch.object(
                providers.threading,
                "Thread",
                side_effect=RuntimeError("thread construction failed"),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot construct",
            ),
        ):
            with providers._claude_keychain_credential_server(
                credential,
                bytes.fromhex("01" * 32),
            ):
                self.fail("failed broker unexpectedly started")

        server.server_close.assert_called_once_with()
        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_broker_serve_start_failure_is_inconclusive(self) -> None:
        credential = bytearray(b"fixture-value")
        serve_error = RuntimeError("serve startup failed")
        server = mock.Mock()
        server.wait_until_serving.return_value = False
        server.serve_error.return_value = serve_error
        server.begin_closing.return_value = ()
        server.wait_for_handlers.return_value = True
        server.handler_errors.return_value = ()

        with (
            mock.patch.object(
                providers,
                "_ClaudeKeychainCredentialServer",
                return_value=server,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "did not enter its serve loop",
            ) as raised,
        ):
            with providers._claude_keychain_credential_server(
                credential,
                bytes.fromhex("01" * 32),
            ):
                self.fail("failed broker unexpectedly started")

        self.assert_cleanup_diagnostic_preserves_original_cause(
            raised.exception,
            serve_error,
        )
        server.server_close.assert_called()
        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_broker_propagates_serve_failure_after_ready(self) -> None:
        credential = bytearray(b"fixture-value")
        serve_error = RuntimeError("serve loop failed")
        server = mock.Mock()
        server.server_address = ("127.0.0.1", 43211)
        server.wait_until_serving.return_value = True
        server.serve_forever.side_effect = serve_error
        server.begin_closing.return_value = ()
        server.wait_for_handlers.return_value = True
        server.serve_error.return_value = serve_error
        server.handler_errors.return_value = ()

        with (
            mock.patch.object(
                providers,
                "_ClaudeKeychainCredentialServer",
                return_value=server,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot shut down",
            ),
        ):
            with providers._claude_keychain_credential_server(
                credential,
                bytes.fromhex("01" * 32),
            ):
                pass

        server.scrub_initial_credential.assert_called_once_with()
        self.assertEqual(credential, bytearray(len(credential)))

    @unittest.skipUnless(hasattr(signal, "SIGTERM"), "requires SIGTERM")
    def test_blocked_keychain_handler_preserves_timeout_and_signal(self) -> None:
        context = multiprocessing.get_context("spawn")
        for mode, expected_error, recovery_completed in (
            ("timeout", "ReviewTimeoutError", True),
            ("signal", "ForwardedSignal", True),
            ("recovery", "ReviewTimeoutError", False),
        ):
            with self.subTest(mode=mode):
                parent, child = context.Pipe(duplex=False)
                process = context.Process(
                    target=_blocked_keychain_handler_worker,
                    args=(child, mode),
                )
                process.start()
                child.close()
                messages: list[tuple[object, ...]] = []
                try:
                    self.assertTrue(
                        parent.poll(5.0),
                        "credential-server worker did not become ready",
                    )
                    ready = parent.recv()
                    if (
                        len(ready) >= 2
                        and ready[0] == "result"
                        and ready[1] == "ClaudeLoopbackUnavailable"
                    ):
                        process.join(timeout=2.0)
                        self.skipTest(
                            "loopback bind is unavailable in the current sandbox"
                        )
                    self.assertEqual(ready, ("ready", mode))
                    if mode == "signal":
                        os.kill(process.pid, signal.SIGTERM)
                    self.assertTrue(
                        parent.poll(5.0),
                        "credential-server worker did not propagate control flow",
                    )
                    messages.append(parent.recv())
                    process.join(timeout=2.0)
                    self.assertFalse(
                        process.is_alive(),
                        "credential-server worker remained alive after deadline",
                    )
                finally:
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=2.0)
                    parent.close()

                self.assertEqual(process.exitcode, 0)
                self.assertEqual(
                    messages,
                    [
                        (
                            "result",
                            expected_error,
                            True,
                            True,
                            recovery_completed,
                        )
                    ],
                )

    def test_recv_exact_scrubs_partial_buffer_on_eof_or_error(self) -> None:
        class PartialSocket:
            def __init__(self, *, fail: bool) -> None:
                self.fail = fail
                self.calls = 0
                self.buffer: bytearray | None = None

            def recv_into(self, destination: memoryview, _length: int) -> int:
                if self.calls == 0:
                    self.calls += 1
                    self.buffer = destination.obj
                    destination[:3] = b"abc"
                    return 3
                if self.fail:
                    raise OSError("fixture receive failure")
                return 0

        for fail in (False, True):
            with self.subTest(fail=fail):
                sock = PartialSocket(fail=fail)
                self.assertIsNone(providers._recv_exact(sock, 8))  # type: ignore[arg-type]
                self.assertEqual(sock.buffer, bytearray(8))

    def test_keychain_server_pending_generation_preserves_latest_update(
        self,
    ) -> None:
        try:
            server = providers._ClaudeKeychainCredentialServer(
                None,
                bytes.fromhex("01" * 32),
                None,
            )
        except OSError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        first = bytearray(b"first-rotation")
        second = bytearray(b"latest-rotation")
        pending: bytearray | None = None
        try:
            first_generation = server.stage_pending_update(first)
            second_generation = server.stage_pending_update(second)
            assert first_generation is not None
            assert second_generation is not None
            server.clear_pending_update(first_generation)
            pending = server.abandon_and_detach_pending_update()
            self.assertEqual(pending, second)
            server.clear_pending_update(second_generation)
            self.assertIsNone(server.stage_pending_update(first))
        finally:
            if pending is not None:
                pending[:] = b"\x00" * len(pending)
            server.server_close()
            server.scrub_initial_credential()
            first[:] = b"\x00" * len(first)
            second[:] = b"\x00" * len(second)

    def test_keychain_server_fail_closed_gate_keeps_pending_attached(
        self,
    ) -> None:
        try:
            server = providers._ClaudeKeychainCredentialServer(
                None,
                bytes.fromhex("01" * 32),
                None,
            )
        except OSError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        credential = bytearray(b"fixture-pending-rotation")
        detached: bytearray | None = None
        published = False

        def publish() -> bool:
            nonlocal published
            published = True
            return True

        try:
            generation = server.stage_pending_update(credential)
            assert generation is not None
            server._pending_update_lock.acquire()
            try:
                self.assertFalse(
                    server.close_pending_update_publication(0.0)
                )
            finally:
                server._pending_update_lock.release()
            self.assertFalse(server.commit_pending_update(generation, publish))
            self.assertFalse(published)
            detached = server.abandon_and_detach_pending_update()
            self.assertEqual(detached, credential)
        finally:
            if detached is not None:
                detached[:] = b"\x00" * len(detached)
            server.server_close()
            server.scrub_initial_credential()
            credential[:] = b"\x00" * len(credential)

    def test_shutdown_does_not_detach_when_runtime_abandonment_fails(
        self,
    ) -> None:
        class FixtureThread:
            def join(self, timeout: float | None = None) -> None:
                del timeout

            def is_alive(self) -> bool:
                return True

        class FixtureServer:
            def __init__(self) -> None:
                self.detach_calls = 0
                self.close_publication_calls = 0

            def begin_closing(self) -> tuple[object, ...]:
                return ()

            def shutdown(self) -> None:
                return None

            def server_close(self) -> None:
                return None

            def wait_for_handlers(self, timeout: float) -> bool:
                del timeout
                return False

            def serve_error(self) -> BaseException | None:
                return None

            def handler_errors(self) -> tuple[BaseException, ...]:
                return ()

            def close_pending_update_publication(
                self,
                timeout: float,
            ) -> bool:
                del timeout
                self.close_publication_calls += 1
                return True

            def abandon_and_detach_pending_update(self) -> bytearray:
                self.detach_calls += 1
                return bytearray(b"must-not-detach")

            def try_abandon_and_detach_pending_update(
                self,
                timeout: float | None,
            ) -> tuple[bool, bytearray]:
                del timeout
                self.detach_calls += 1
                return True, bytearray(b"must-not-detach")

        server = FixtureServer()
        abandonment_error = RuntimeError("injected abandonment latch failure")

        def fail_abandonment() -> None:
            raise abandonment_error

        with mock.patch.object(
            providers,
            "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
            0.01,
        ):
            shutdown = providers._bounded_claude_keychain_server_shutdown(
                server,  # type: ignore[arg-type]
                FixtureThread(),  # type: ignore[arg-type]
                abandon_callback=fail_abandonment,
            )

        self.assertFalse(shutdown.quiescent)
        self.assertFalse(shutdown.abandonment_latched)
        self.assertFalse(shutdown.pending_update_detached)
        self.assertIsNone(shutdown.pending_update)
        self.assertIn(abandonment_error, shutdown.errors)
        self.assertEqual(server.detach_calls, 0)
        self.assertEqual(server.close_publication_calls, 1)

    def test_shutdown_abandonment_and_detach_respect_deadline(self) -> None:
        class FixtureThread:
            def join(self, timeout: float | None = None) -> None:
                del timeout

            def is_alive(self) -> bool:
                return True

        for blocked_step in ("credential-lock", "pending-lock", "abandon"):
            with self.subTest(blocked_step=blocked_step):
                credential = bytearray(
                    oauth_credential_fixture(expires_in_seconds=3600)
                )
                pending = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                server = providers._ClaudeKeychainCredentialServer(
                    credential,
                    bytes.fromhex("03" * 32),
                    None,
                )
                generation = server.stage_pending_update(pending)
                self.assertIsNotNone(generation)
                release_abandonment = threading.Event()
                completed = threading.Event()
                results: list[providers._ClaudeKeychainServerShutdown] = []
                errors: list[BaseException] = []
                held_lock = None
                if blocked_step == "credential-lock":
                    held_lock = server.credential_lock
                    held_lock.acquire()
                elif blocked_step == "pending-lock":
                    held_lock = server._pending_update_lock
                    held_lock.acquire()

                def abandon() -> None:
                    if blocked_step == "abandon":
                        self.assertTrue(
                            release_abandonment.wait(timeout=2.0)
                        )

                def run_shutdown() -> None:
                    try:
                        results.append(
                            providers._bounded_claude_keychain_server_shutdown(
                                server,
                                FixtureThread(),  # type: ignore[arg-type]
                                abandon_callback=abandon,
                            )
                        )
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        completed.set()

                owner = threading.Thread(target=run_shutdown, daemon=True)
                try:
                    with (
                        mock.patch.object(
                            providers,
                            "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
                            0.01,
                        ),
                        mock.patch.object(server, "shutdown", return_value=None),
                    ):
                        owner.start()
                        finished_within_bound = completed.wait(timeout=0.2)
                        publication_closed_within_bound = (
                            server._abandoned.is_set()
                        )
                finally:
                    release_abandonment.set()
                    if held_lock is not None:
                        held_lock.release()
                    owner.join(timeout=2.0)

                self.assertTrue(finished_within_bound)
                self.assertTrue(publication_closed_within_bound)
                self.assertFalse(owner.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(len(results), 1)
                self.assertFalse(results[0].quiescent)
                self.assertFalse(results[0].pending_update_detached)
                detached = server.abandon_and_detach_pending_update()
                if detached is not None:
                    detached[:] = b"\x00" * len(detached)
                server.server_close()
                server.scrub_initial_credential()
                credential[:] = b"\x00" * len(credential)
                pending[:] = b"\x00" * len(pending)

    def test_quiescence_recovery_abandonment_respects_deadline(self) -> None:
        release_abandonment = threading.Event()
        abandonment_finished = threading.Event()
        recover_called = False
        pending = bytearray(b"fixture-pending-update")

        def abandon() -> None:
            try:
                self.assertTrue(release_abandonment.wait(timeout=2.0))
            finally:
                abandonment_finished.set()

        def recover(_pending: bytearray | None) -> BaseException | None:
            nonlocal recover_called
            recover_called = True
            return None

        callbacks = providers._ClaudeKeychainQuiescenceCallbacks(
            abandon=abandon,
            recover=recover,
            timeout_error=lambda: RuntimeError("unexpected timeout callback"),
        )
        started = time.monotonic()
        try:
            with mock.patch.object(
                providers,
                "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                0.01,
            ):
                error = providers._bounded_claude_keychain_quiescence_recovery(
                    callbacks,
                    pending,
                )
        finally:
            release_abandonment.set()

        self.assertLess(time.monotonic() - started, 0.2)
        self.assertIsInstance(
            error,
            providers.ClaudeCredentialInspectionInconclusive,
        )
        self.assertFalse(recover_called)
        self.assertEqual(pending, bytearray(len(pending)))
        self.assertTrue(abandonment_finished.wait(timeout=2.0))

    def test_fail_closed_scope_callback_respects_deadline(self) -> None:
        release_callback = threading.Event()
        callback_finished = threading.Event()

        def fail_closed_error() -> BaseException:
            try:
                self.assertTrue(release_callback.wait(timeout=2.0))
                return RuntimeError("fixture fail-closed scope")
            finally:
                callback_finished.set()

        started = time.monotonic()
        try:
            result, error = (
                providers._bounded_claude_keychain_fail_closed_error(
                    fail_closed_error,
                    0.01,
                )
            )
        finally:
            release_callback.set()

        self.assertLess(time.monotonic() - started, 0.2)
        self.assertIsNone(result)
        self.assertIsInstance(
            error,
            providers.ClaudeCredentialInspectionInconclusive,
        )
        self.assertTrue(callback_finished.wait(timeout=2.0))

    def test_recovery_timeout_callback_is_bounded_and_uses_fallback(
        self,
    ) -> None:
        release_recovery = threading.Event()
        recovery_finished = threading.Event()
        release_timeout_callback = threading.Event()
        timeout_callback_finished = threading.Event()
        fallback = providers.ClaudeCredentialInspectionInconclusive(
            "fixture precomputed recovery timeout scope"
        )

        def recover(_pending: bytearray | None) -> BaseException | None:
            try:
                self.assertTrue(release_recovery.wait(timeout=2.0))
                return None
            finally:
                recovery_finished.set()

        def timeout_error() -> BaseException:
            try:
                self.assertTrue(
                    release_timeout_callback.wait(timeout=2.0)
                )
                return RuntimeError("fixture late timeout callback")
            finally:
                timeout_callback_finished.set()

        callbacks = providers._ClaudeKeychainQuiescenceCallbacks(
            abandon=lambda: None,
            recover=recover,
            timeout_error=timeout_error,
            timeout_fallback_error=fallback,
        )
        started = time.monotonic()
        try:
            with mock.patch.object(
                providers,
                "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                0.01,
            ):
                result = (
                    providers._bounded_claude_keychain_quiescence_recovery(
                        callbacks,
                        None,
                    )
                )
        finally:
            release_recovery.set()
            release_timeout_callback.set()

        self.assertLess(time.monotonic() - started, 0.2)
        self.assertIs(result, fallback)
        self.assertTrue(recovery_finished.wait(timeout=2.0))
        self.assertTrue(timeout_callback_finished.wait(timeout=2.0))

    def test_keychain_server_rejects_obsolete_update_generation(self) -> None:
        capability = bytes.fromhex("01" * 32)
        older = b"older-rotation"
        newer = b"newer-rotation"

        for newer_success in (True, False):
            with self.subTest(newer_success=newer_success):
                callback_payloads: list[bytes] = []
                older_staged = threading.Event()
                release_older = threading.Event()
                newer_called = threading.Event()
                responses: dict[bytes, bytes] = {}

                def update_callback(
                    updated: bytearray,
                    commit_pending: Callable[[Callable[[], bool]], bool],
                    _claim_terminal: Callable[[], bool],
                ) -> bool:
                    callback_payloads.append(bytes(updated))
                    newer_called.set()
                    return commit_pending(lambda: newer_success)

                try:
                    server = providers._ClaudeKeychainCredentialServer(
                        None,
                        capability,
                        update_callback,
                    )
                except OSError:
                    self.skipTest(
                        "loopback bind is unavailable in the current sandbox"
                    )
                with server.credential_lock:
                    server.consumed = True
                real_stage = server.stage_pending_update

                def controlled_stage(credential: bytearray) -> int | None:
                    generation = real_stage(credential)
                    if bytes(credential) == older:
                        older_staged.set()
                        if not release_older.wait(timeout=2.0):
                            raise RuntimeError(
                                "fixture older generation was not released"
                            )
                    return generation

                def write_update(payload: bytes) -> None:
                    with socket.create_connection(
                        ("127.0.0.1", int(server.server_address[1])),
                        timeout=2.0,
                    ) as sock:
                        sock.sendall(
                            capability
                            + b"W"
                            + len(payload).to_bytes(4, "big")
                            + payload
                        )
                        responses[payload] = sock.recv(1)

                serve_thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.01},
                    daemon=True,
                )
                older_thread = threading.Thread(
                    target=write_update,
                    args=(older,),
                )
                newer_thread = threading.Thread(
                    target=write_update,
                    args=(newer,),
                )
                with mock.patch.object(
                    server,
                    "stage_pending_update",
                    side_effect=controlled_stage,
                ):
                    serve_thread.start()
                    older_thread.start()
                    try:
                        self.assertTrue(older_staged.wait(timeout=2.0))
                        newer_thread.start()
                        self.assertTrue(newer_called.wait(timeout=2.0))
                    finally:
                        release_older.set()
                        older_thread.join(timeout=2.0)
                        if newer_thread.ident is not None:
                            newer_thread.join(timeout=2.0)
                        server.shutdown()
                        server.server_close()
                        serve_thread.join(timeout=2.0)

                self.assertFalse(older_thread.is_alive())
                self.assertFalse(newer_thread.is_alive())
                self.assertFalse(serve_thread.is_alive())
                self.assertEqual(callback_payloads, [newer])
                self.assertEqual(responses[older], b"\x01")
                self.assertEqual(
                    responses[newer],
                    b"\x00" if newer_success else b"\x01",
                )

    def test_keychain_server_rejects_generation_superseded_during_callback(
        self,
    ) -> None:
        capability = bytes.fromhex("01" * 32)
        older = b"older-rotation"
        newer = b"newer-rotation"
        older_callback_started = threading.Event()
        release_older_callback = threading.Event()
        newer_staged = threading.Event()
        callback_payloads: list[bytes] = []
        responses: dict[bytes, bytes] = {}

        def update_callback(
            updated: bytearray,
            commit_pending: Callable[[Callable[[], bool]], bool],
            _claim_terminal: Callable[[], bool],
        ) -> bool:
            payload = bytes(updated)
            callback_payloads.append(payload)
            if payload == older:
                older_callback_started.set()
                if not release_older_callback.wait(timeout=2.0):
                    raise RuntimeError(
                        "fixture older callback was not released"
                    )
            return commit_pending(lambda: True)

        try:
            server = providers._ClaudeKeychainCredentialServer(
                None,
                capability,
                update_callback,
            )
        except OSError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        with server.credential_lock:
            server.consumed = True
        real_stage = server.stage_pending_update

        def observe_stage(credential: bytearray) -> int | None:
            generation = real_stage(credential)
            if bytes(credential) == newer:
                newer_staged.set()
            return generation

        def write_update(payload: bytes) -> None:
            with socket.create_connection(
                ("127.0.0.1", int(server.server_address[1])),
                timeout=2.0,
            ) as sock:
                sock.sendall(
                    capability
                    + b"W"
                    + len(payload).to_bytes(4, "big")
                    + payload
                )
                responses[payload] = sock.recv(1)

        serve_thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        older_thread = threading.Thread(target=write_update, args=(older,))
        newer_thread = threading.Thread(target=write_update, args=(newer,))
        with mock.patch.object(
            server,
            "stage_pending_update",
            side_effect=observe_stage,
        ):
            serve_thread.start()
            older_thread.start()
            try:
                self.assertTrue(
                    older_callback_started.wait(timeout=2.0),
                    f"handler errors: {server.handler_errors()!r}",
                )
                newer_thread.start()
                self.assertTrue(newer_staged.wait(timeout=2.0))
            finally:
                release_older_callback.set()
                older_thread.join(timeout=2.0)
                if newer_thread.ident is not None:
                    newer_thread.join(timeout=2.0)
                server.shutdown()
                server.server_close()
                serve_thread.join(timeout=2.0)

        self.assertFalse(older_thread.is_alive())
        self.assertFalse(newer_thread.is_alive())
        self.assertFalse(serve_thread.is_alive())
        self.assertEqual(callback_payloads, [older, newer])
        self.assertEqual(responses[older], b"\x01")
        self.assertEqual(responses[newer], b"\x00")

    def test_keychain_server_terminal_update_closes_later_admission(
        self,
    ) -> None:
        capability = bytes.fromhex("01" * 32)
        first = b"terminal-rotation"
        later = b"later-rotation"
        callback_payloads: list[bytes] = []

        def update_callback(
            updated: bytearray,
            _commit_pending: Callable[[Callable[[], bool]], bool],
            claim_terminal: Callable[[], bool],
        ) -> bool:
            callback_payloads.append(bytes(updated))
            self.assertTrue(claim_terminal())
            return False

        try:
            server = providers._ClaudeKeychainCredentialServer(
                None,
                capability,
                update_callback,
            )
        except OSError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        with server.credential_lock:
            server.consumed = True

        def write_update(payload: bytes) -> bytes:
            with socket.create_connection(
                ("127.0.0.1", int(server.server_address[1])),
                timeout=2.0,
            ) as sock:
                sock.sendall(
                    capability
                    + b"W"
                    + len(payload).to_bytes(4, "big")
                    + payload
                )
                return sock.recv(1)

        serve_thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        serve_thread.start()
        try:
            self.assertEqual(write_update(first), b"\x01")
            self.assertEqual(write_update(later), b"\x01")
        finally:
            server.shutdown()
            server.server_close()
            serve_thread.join(timeout=2.0)

        self.assertFalse(serve_thread.is_alive())
        self.assertEqual(callback_payloads, [first])

    def test_keychain_server_only_latest_update_can_claim_terminal_slot(
        self,
    ) -> None:
        capability = bytes.fromhex("01" * 32)
        older = b"older-terminal-candidate"
        newer = b"newer-terminal-candidate"
        older_callback_started = threading.Event()
        release_older_callback = threading.Event()
        newer_staged = threading.Event()
        callback_payloads: list[bytes] = []
        claim_results: list[tuple[bytes, bool]] = []
        responses: dict[bytes, bytes] = {}

        def update_callback(
            updated: bytearray,
            _commit_pending: Callable[[Callable[[], bool]], bool],
            claim_terminal: Callable[[], bool],
        ) -> bool:
            payload = bytes(updated)
            callback_payloads.append(payload)
            if payload == older:
                older_callback_started.set()
                if not release_older_callback.wait(timeout=2.0):
                    raise RuntimeError(
                        "fixture older terminal candidate was not released"
                    )
            claim_results.append((payload, claim_terminal()))
            return False

        try:
            server = providers._ClaudeKeychainCredentialServer(
                None,
                capability,
                update_callback,
            )
        except OSError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        with server.credential_lock:
            server.consumed = True
        real_stage = server.stage_pending_update

        def observe_stage(credential: bytearray) -> int | None:
            generation = real_stage(credential)
            if bytes(credential) == newer:
                newer_staged.set()
            return generation

        def write_update(payload: bytes) -> None:
            with socket.create_connection(
                ("127.0.0.1", int(server.server_address[1])),
                timeout=2.0,
            ) as sock:
                sock.sendall(
                    capability
                    + b"W"
                    + len(payload).to_bytes(4, "big")
                    + payload
                )
                responses[payload] = sock.recv(1)

        serve_thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        older_thread = threading.Thread(target=write_update, args=(older,))
        newer_thread = threading.Thread(target=write_update, args=(newer,))
        with mock.patch.object(
            server,
            "stage_pending_update",
            side_effect=observe_stage,
        ):
            serve_thread.start()
            older_thread.start()
            try:
                self.assertTrue(older_callback_started.wait(timeout=2.0))
                newer_thread.start()
                self.assertTrue(newer_staged.wait(timeout=2.0))
            finally:
                release_older_callback.set()
                older_thread.join(timeout=2.0)
                if newer_thread.ident is not None:
                    newer_thread.join(timeout=2.0)
                server.shutdown()
                server.server_close()
                serve_thread.join(timeout=2.0)

        self.assertFalse(older_thread.is_alive())
        self.assertFalse(newer_thread.is_alive())
        self.assertFalse(serve_thread.is_alive())
        self.assertEqual(callback_payloads, [older, newer])
        self.assertEqual(claim_results, [(older, False), (newer, True)])
        self.assertEqual(responses, {older: b"\x01", newer: b"\x01"})

    def test_keychain_update_script_shape_margin_and_scrubbing(self) -> None:
        with mock.patch.object(
            providers,
            "_claude_keychain_account",
            return_value="fixture-user",
        ):
            credential = bytearray(b"\x00\x7f\xff")
            script = providers._claude_keychain_update_script(credential)
            self.assertIsInstance(script, bytearray)
            self.assertEqual(
                script,
                bytearray(
                    b'add-generic-password -U -a "fixture-user" '
                    b'-s "Claude Code-credentials" -X "007fff"\n'
                ),
            )
            fixed_length = len(providers._claude_keychain_update_script_prefix()) + len(
                providers.CLAUDE_KEYCHAIN_UPDATE_SCRIPT_SUFFIX
            )
            maximum_credential_length = (
                providers.CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES - fixed_length
            ) // 2
            at_limit = bytearray(maximum_credential_length)
            over_limit = bytearray(maximum_credential_length + 1)
            self.assertTrue(
                providers._claude_keychain_credential_has_refresh_margin(at_limit)
            )
            self.assertFalse(
                providers._claude_keychain_credential_has_refresh_margin(over_limit)
            )
            for payload in (credential, script, at_limit, over_limit):
                payload[:] = b"\x00" * len(payload)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "run_bounded_capture")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_keychain_writeback_scrubs_stdin_script(
        self,
        read_credential: mock.Mock,
        run_command: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        expected = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(expected),
            file_digest=None,
            file_snapshot=None,
        )
        read_credential.side_effect = lambda _review: bytearray(expected)
        captured: dict[str, object] = {}
        completed = common.BoundedCapture(
            argv=(str(self.claude_keychain_client), "-i"),
            returncode=0,
            stdout=bytearray(b"fixture-output"),
            stderr=bytearray(b"fixture-error"),
        )

        def capture_script(*_args: object, **kwargs: object) -> common.BoundedCapture:
            script = kwargs["stdin"]
            assert isinstance(script, bytearray)
            captured["script"] = script
            captured["snapshot"] = bytes(script)
            return completed

        run_command.side_effect = capture_script
        with mock.patch.object(
            providers,
            "_claude_credential_update_lock",
            side_effect=lambda _name: contextlib.nullcontext(),
        ):
            self.assertTrue(
                providers._write_claude_keychain_credential(
                    self.review,
                    credential,
                    expected,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
            )

        script = captured["script"]
        assert isinstance(script, bytearray)
        self.assertEqual(script, bytearray(len(script)))
        snapshot = captured["snapshot"]
        assert isinstance(snapshot, bytes)
        self.assertTrue(snapshot.startswith(b"add-generic-password -U "))
        self.assertTrue(snapshot.endswith(b'"\n'))
        self.assertEqual(completed.stdout, bytearray(len(completed.stdout)))
        self.assertEqual(completed.stderr, bytearray(len(completed.stderr)))

        failed_capture: dict[str, bytearray] = {}

        def fail_after_capture(
            *_args: object,
            **kwargs: object,
        ) -> common.BoundedCapture:
            script = kwargs["stdin"]
            assert isinstance(script, bytearray)
            failed_capture["script"] = script
            raise OSError("fixture runner failure")

        run_command.side_effect = fail_after_capture
        with mock.patch.object(
            providers,
            "_claude_credential_update_lock",
            side_effect=lambda _name: contextlib.nullcontext(),
        ):
            self.assertFalse(
                providers._write_claude_keychain_credential(
                    self.review,
                    credential,
                    expected,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
            )
        failed_script = failed_capture["script"]
        self.assertEqual(failed_script, bytearray(len(failed_script)))
        credential[:] = b"\x00" * len(credential)
        expected[:] = b"\x00" * len(expected)

    def test_helper_credential_lock_contention_is_inconclusive(self) -> None:
        import fcntl

        with (
            mock.patch.object(
                providers,
                "CLAUDE_CREDENTIAL_UPDATE_LOCK_TIMEOUT_SECONDS",
                0.0,
            ),
            mock.patch.object(
                fcntl,
                "flock",
                side_effect=BlockingIOError(),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "another isolated review",
            ),
        ):
            with providers._claude_credential_update_lock("keychain"):
                self.fail("contended helper lock unexpectedly acquired")

    def test_helper_credential_lock_open_failure_is_inconclusive(self) -> None:
        with (
            mock.patch.object(
                providers.os,
                "open",
                side_effect=OSError(5, "injected sensitive lock detail"),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot open the Claude credential update lock safely",
            ) as raised,
        ):
            with providers._claude_credential_update_lock("keychain"):
                self.fail("helper lock unexpectedly opened")

        self.assertNotIn("injected sensitive lock detail", str(raised.exception))

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_helper_credential_lock_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = pathlib.Path(temporary) / "credential.lock"
            os.mkfifo(fifo, mode=0o600)
            requested_flags: list[int] = []
            real_open = os.open

            def guarded_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                requested_flags.append(flags)
                return real_open(path, flags | os.O_NONBLOCK, *args, **kwargs)

            with (
                mock.patch.object(providers.pathlib, "Path", return_value=fifo),
                mock.patch.object(
                    providers.os,
                    "open",
                    side_effect=guarded_open,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "update lock is not private",
                ),
            ):
                with providers._claude_credential_update_lock("keychain"):
                    self.fail("FIFO helper lock unexpectedly acquired")

            self.assertEqual(len(requested_flags), 1)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    def test_claude_keychain_broker_serves_one_in_memory_value(self) -> None:
        if (
            sys.platform != "darwin"
            or not providers.CLAUDE_KEYCHAIN_BROKER_COMPILER.is_file()
        ):
            self.skipTest("the native Claude Keychain broker requires macOS clang")
        prepared = self.prepare_claude_keychain_broker(
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "PATH": "/usr/bin",
            },
        )
        broker_dir = pathlib.Path(prepared["PATH"].split(os.pathsep)[0])
        broker = broker_dir / "security"
        credential = bytearray(b"fixture-value")
        capability = bytes.fromhex("01" * 32)
        updates: list[bytes] = []

        def record_update(
            updated: bytearray,
            commit_pending: Callable[[Callable[[], bool]], bool],
            _claim_terminal: Callable[[], bool],
        ) -> bool:
            def publish() -> bool:
                updates.append(bytes(updated))
                return True

            return commit_pending(publish)

        try:
            context = providers._claude_keychain_credential_server(
                credential,
                capability,
                update_callback=record_update,
            )
            with context as port:
                prepared["TMPDIR"] = str(self.review.container_dir / "tmp")
                prepared[providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = str(port)
                prepared[providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV] = (
                    capability.hex()
                )
                profile = providers._claude_review_sandbox_profile(
                    pathlib.Path("/bin/true"),
                    self.review,
                    prepared,
                    proxy_port=43210,
                )
                query = (
                    str(providers.CLAUDE_PROBE_SANDBOX),
                    "-p",
                    profile,
                    str(broker),
                    "find-generic-password",
                    "-a",
                    prepared["USER"],
                    "-w",
                    "-s",
                    providers.CLAUDE_KEYCHAIN_SERVICE,
                )
                with socket.create_connection(("127.0.0.1", port)) as unauthorized:
                    unauthorized.sendall(bytes.fromhex("02" * 32))
                    self.assertEqual(unauthorized.recv(1), b"")
                first = providers.run(query, env=prepared)
                second = providers.run(query, env=prepared)
                refreshed = oauth_credential_fixture()
                update_script = (
                    f'add-generic-password -U -a "{prepared["USER"]}" '
                    f'-s "{providers.CLAUDE_KEYCHAIN_SERVICE}" '
                    f'-X "{refreshed.hex()}"\n'
                ).encode("ascii")
                valid_update = providers.run(
                    (
                        str(providers.CLAUDE_PROBE_SANDBOX),
                        "-p",
                        profile,
                        str(broker),
                        "-i",
                    ),
                    env=prepared,
                    stdin=update_script,
                )
                stdin_update = providers.run(
                    (
                        str(providers.CLAUDE_PROBE_SANDBOX),
                        "-p",
                        profile,
                        str(broker),
                        "-i",
                    ),
                    env=prepared,
                    stdin=b"add-generic-password\n",
                )
                direct_update = providers.run(
                    (
                        str(providers.CLAUDE_PROBE_SANDBOX),
                        "-p",
                        profile,
                        str(broker),
                        "add-generic-password",
                        "-U",
                        "-a",
                        prepared["USER"],
                        "-s",
                        providers.CLAUDE_KEYCHAIN_SERVICE,
                        "-X",
                        "00",
                    ),
                    env=prepared,
                )
        except (PermissionError, providers.ClaudeLoopbackUnavailable):
            self.skipTest("loopback bind is unavailable in the current sandbox")

        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, b"fixture-value\n")
        self.assertEqual(second.returncode, 44)
        self.assertEqual(valid_update.returncode, 0)
        self.assertEqual(updates, [refreshed])
        self.assertEqual(stdin_update.returncode, 64)
        self.assertEqual(direct_update.returncode, 64)
        self.assertEqual(credential, bytearray(len(credential)))
        self.assertTrue(providers._ClaudeKeychainCredentialServer.daemon_threads)
        self.assertFalse(providers._ClaudeKeychainCredentialServer.block_on_close)

    @mock.patch.object(providers, "run_bounded_capture")
    def test_keychain_prefetch_uses_fixed_service_and_account(
        self,
        run_command: mock.Mock,
    ) -> None:
        payload = oauth_credential_fixture()
        completed = common.BoundedCapture(
            argv=(),
            returncode=0,
            stdout=bytearray(payload),
            stderr=bytearray(),
        )
        run_command.return_value = completed

        credential = providers._read_claude_keychain_credential(self.review)

        self.assertEqual(credential, bytearray(payload))
        argv = run_command.call_args.args[0]
        self.assertEqual(argv[0], str(self.claude_keychain_client))
        self.assertEqual(
            argv[1:],
            (
                "find-generic-password",
                "-a",
                providers._claude_keychain_account(),
                "-w",
                "-s",
                "Claude Code-credentials",
            ),
        )
        self.assertEqual(completed.stdout, bytearray(len(payload)))
        self.assertEqual(
            run_command.call_args.kwargs["stdout_limit_bytes"],
            providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
        )
        self.assertEqual(
            run_command.call_args.kwargs["stderr_limit_bytes"],
            providers.CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )

    @mock.patch.object(providers, "run_bounded_capture")
    def test_keychain_exit_44_is_absent_but_other_errors_are_inconclusive(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = common.BoundedCapture(
            argv=(),
            returncode=44,
            stdout=bytearray(),
            stderr=bytearray(b"not found"),
        )
        self.assertIsNone(providers._read_claude_keychain_credential(self.review))

        run_command.return_value = common.BoundedCapture(
            argv=(),
            returncode=36,
            stdout=bytearray(),
            stderr=bytearray(b"interaction denied"),
        )
        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "status 36",
        ):
            providers._read_claude_keychain_credential(self.review)

        payload = oauth_credential_fixture()
        completed = common.BoundedCapture(
            argv=(),
            returncode=0,
            stdout=bytearray(b" \t" + payload + b"\r\n"),
            stderr=bytearray(),
        )
        run_command.return_value = completed
        credential = providers._read_claude_keychain_credential(self.review)
        self.assertEqual(credential, bytearray(payload))
        self.assertEqual(completed.stdout, bytearray(len(completed.stdout)))
        assert credential is not None
        credential[:] = b"\x00" * len(credential)

    @mock.patch.object(
        providers,
        "run_bounded_capture",
        side_effect=OSError("temporary Keychain I/O failure"),
    )
    def test_keychain_io_failure_is_inconclusive(
        self,
        _run_command: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "Keychain query failed",
        ):
            providers._read_claude_keychain_credential(self.review)

    def test_late_keychain_client_loss_is_inconclusive(self) -> None:
        cases = ("missing", "non-executable")
        for condition in cases:
            with self.subTest(condition=condition):
                client = (
                    self.claude_keychain_client.parent / f"security-{condition}"
                )
                if condition == "non-executable":
                    client.write_bytes(b"fixture")
                    client.chmod(0o600)

                with (
                    mock.patch.object(providers, "CLAUDE_KEYCHAIN_CLIENT", client),
                    self.assertRaisesRegex(
                        providers.ClaudeCredentialInspectionInconclusive,
                        "requires /usr/bin/security",
                    ),
                ):
                    providers._read_claude_keychain_credential(self.review)

    def test_pwd_home_credential_reader_ignores_ambient_home_and_config(self) -> None:
        payload = oauth_credential_fixture()
        credential_path = self.write_pwd_home_credential(payload)

        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.review.source_root / "ambient-home"),
                "CLAUDE_CONFIG_DIR": str(self.review.source_root / "ambient-config"),
            },
        ):
            result = providers._read_claude_macos_file_credential()

        self.assertIsNotNone(result)
        assert result is not None
        credential, snapshot = result
        self.assertEqual(credential, bytearray(payload))
        self.assertEqual(snapshot.home, self.claude_pwd_home)
        self.assertEqual(stat.S_IMODE(credential_path.stat().st_mode), 0o600)
        credential[:] = b"\x00" * len(credential)

    def test_absolute_directory_walk_closes_each_owned_descriptor_once(self) -> None:
        close_calls: list[int] = []

        def close_descriptor(descriptor: int) -> None:
            close_calls.append(descriptor)
            if descriptor == 10:
                raise KeyboardInterrupt

        with (
            mock.patch.object(providers.os, "open", side_effect=[10, 11]) as open_fd,
            mock.patch.object(
                providers.os,
                "close",
                side_effect=close_descriptor,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            providers._open_absolute_directory_without_symlinks(
                pathlib.Path("/fixture")
            )

        self.assertEqual(open_fd.call_count, 2)
        self.assertEqual(close_calls, [10, 11])

    def test_absolute_directory_chain_closes_interrupt_before_registration(
        self,
    ) -> None:
        for window, target in (
            ("root", pathlib.Path("/")),
            ("child", self.review.container_dir),
        ):
            with self.subTest(window=window):
                opened: list[int] = []
                real_open = providers.os.open
                real_fstat = providers.os.fstat
                real_close = providers.os.close
                chain_code = (
                    providers._open_absolute_directory_chain_without_symlinks.__wrapped__.__code__
                )
                interrupted = False

                def tracking_open(
                    path: os.PathLike[str] | str,
                    flags: int,
                    *args: object,
                    **kwargs: object,
                ) -> int:
                    descriptor = real_open(path, flags, *args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                def interrupt_before_registration(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal interrupted
                    if (
                        interrupted
                        or event != "line"
                        or getattr(frame, "f_code", None) is not chain_code
                    ):
                        return interrupt_before_registration
                    locals_map = getattr(frame, "f_locals", {})
                    descriptors = locals_map.get("descriptors", ())
                    candidate = locals_map.get(
                        "root_descriptor"
                        if window == "root"
                        else "next_descriptor"
                    )
                    if (
                        isinstance(candidate, int)
                        and candidate in opened
                        and candidate not in descriptors
                    ):
                        interrupted = True
                        raise SystemExit("injected descriptor registration interrupt")
                    return interrupt_before_registration

                leaked: list[int] = []
                try:
                    with (
                        mock.patch.object(
                            providers.os,
                            "open",
                            side_effect=tracking_open,
                        ),
                        self.assertRaisesRegex(
                            SystemExit,
                            "descriptor registration interrupt",
                        ),
                    ):
                        sys.settrace(interrupt_before_registration)
                        with providers._open_absolute_directory_chain_without_symlinks(
                            target
                        ):
                            pass
                finally:
                    sys.settrace(None)
                    for descriptor in opened:
                        try:
                            real_fstat(descriptor)
                        except OSError as error:
                            self.assertEqual(error.errno, errno.EBADF)
                        else:
                            leaked.append(descriptor)
                            real_close(descriptor)

                self.assertTrue(interrupted)
                self.assertEqual(leaked, [])

    def test_config_directory_cleanup_preserves_control_flow_and_closes_all(
        self,
    ) -> None:
        home_metadata = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=os.getuid(),
        )
        close_calls: list[int] = []

        def close_descriptor(descriptor: int) -> None:
            close_calls.append(descriptor)
            if descriptor == 11:
                raise OSError("injected config close failure")

        with (
            mock.patch.object(
                providers,
                "_open_absolute_directory_without_symlinks",
                return_value=10,
            ),
            mock.patch.object(providers.os, "open", return_value=11),
            mock.patch.object(
                providers.os,
                "fstat",
                side_effect=[home_metadata, SystemExit()],
            ),
            mock.patch.object(
                providers.os,
                "close",
                side_effect=close_descriptor,
            ),
            self.assertRaises(SystemExit),
        ):
            providers._open_claude_credential_config_directory(
                pathlib.Path("/fixture")
            )

        self.assertEqual(close_calls, [11, 10])

    def test_missing_config_close_failure_does_not_retry_numeric_descriptor(
        self,
    ) -> None:
        home_metadata = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=os.getuid(),
        )
        with (
            mock.patch.object(
                providers,
                "_open_absolute_directory_without_symlinks",
                return_value=10,
            ),
            mock.patch.object(providers.os, "fstat", return_value=home_metadata),
            mock.patch.object(
                providers.os,
                "open",
                side_effect=FileNotFoundError,
            ),
            mock.patch.object(
                providers.os,
                "close",
                side_effect=OSError("injected home close failure"),
            ) as close_fd,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "credential home",
            ),
        ):
            providers._open_claude_credential_config_directory(
                pathlib.Path("/fixture")
            )

        close_fd.assert_called_once_with(10)

    def test_credential_file_close_does_not_replace_primary_control_flow(
        self,
    ) -> None:
        with (
            mock.patch.object(providers.os, "open", return_value=10),
            mock.patch.object(providers.os, "fstat", side_effect=KeyboardInterrupt),
            mock.patch.object(providers.os, "close", side_effect=SystemExit),
            self.assertRaises(KeyboardInterrupt),
        ):
            providers._read_claude_credential_file_from_directory(5)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_credential_file_reader_rejects_fifo_without_blocking(self) -> None:
        config_dir = self.claude_pwd_home / ".claude"
        config_dir.mkdir(mode=0o700)
        fifo = config_dir / providers.CLAUDE_CREDENTIAL_FILE_NAME
        os.mkfifo(fifo, mode=0o600)
        config_descriptor = os.open(
            config_dir,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        requested_flags: list[int] = []
        real_open = os.open

        def guarded_open(
            path: os.PathLike[str] | str,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            requested_flags.append(flags)
            return real_open(path, flags | os.O_NONBLOCK, *args, **kwargs)

        try:
            with (
                mock.patch.object(providers.os, "open", side_effect=guarded_open),
                self.assertRaisesRegex(
                    providers.ClaudeCredentialUnsafe,
                    "not regular",
                ),
            ):
                providers._read_claude_credential_file_from_directory(
                    config_descriptor
                )
        finally:
            os.close(config_descriptor)

        self.assertEqual(len(requested_flags), 1)
        self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    def test_pwd_home_credential_reader_rejects_unsafe_file_or_directory(self) -> None:
        credential_path = self.write_pwd_home_credential(oauth_credential_fixture())
        credential_path.chmod(0o644)
        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "exactly 0600",
        ):
            providers._read_claude_macos_file_credential()

        credential_path.chmod(0o600)
        credential_path.parent.chmod(0o777)
        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "not group- or world-writable",
        ):
            providers._read_claude_macos_file_credential()

    @mock.patch.object(providers, "_read_claude_macos_file_credential")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_macos_credential_selection_uses_later_expiry_and_keychain_tie(
        self,
        read_keychain: mock.Mock,
        read_file: mock.Mock,
    ) -> None:
        snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1, 2, os.getuid(), 0o700),
            config_identity=(1, 3, os.getuid(), 0o700),
            file_identity=(1, 4, os.getuid(), 0o600, 1, 10, 11, 12),
        )
        keychain = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        file_credential = bytearray(oauth_credential_fixture(expires_in_seconds=120))
        read_keychain.return_value = keychain
        read_file.return_value = (file_credential, snapshot)

        selected = providers._select_claude_macos_credential(self.review)

        self.assertEqual(selected.source, "pwd-home-credential-file")
        assert selected.carrier_snapshot is not None
        self.assertEqual(
            selected.carrier_snapshot.keychain_refresh_digest,
            selected.carrier_snapshot.file_refresh_digest,
        )
        self.assertEqual(keychain, bytearray(len(keychain)))
        selected.payload[:] = b"\x00" * len(selected.payload)

        tied = bytearray(oauth_credential_fixture(expires_in_seconds=300))
        read_keychain.return_value = tied
        read_file.return_value = (bytearray(tied), snapshot)
        selected = providers._select_claude_macos_credential(self.review)
        self.assertEqual(selected.source, "macos-keychain")
        selected.payload[:] = b"\x00" * len(selected.payload)

    @mock.patch.object(providers, "_read_claude_macos_file_credential")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_unselected_distinct_keychain_size_does_not_block_file_login(
        self,
        read_keychain: mock.Mock,
        read_file: mock.Mock,
    ) -> None:
        keychain_value = json.loads(oauth_credential_fixture(expires_in_seconds=60))
        keychain_value["padding"] = "x" * (
            providers.CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES
        )
        keychain = bytearray(json.dumps(keychain_value).encode())
        file_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        file_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-independent-file-refresh-value"
        )
        file_credential = bytearray(json.dumps(file_value).encode())
        snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        read_keychain.return_value = keychain
        read_file.return_value = (file_credential, snapshot)

        selected = providers._select_claude_macos_credential(self.review)

        self.assertEqual(selected.source, "pwd-home-credential-file")
        self.assertEqual(keychain, bytearray(len(keychain)))
        selected.payload[:] = b"\x00" * len(selected.payload)

    @mock.patch.object(providers, "_read_claude_macos_file_credential")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_unselected_oversized_keychain_does_not_block_shared_login_writeback(
        self,
        read_keychain: mock.Mock,
        read_file: mock.Mock,
    ) -> None:
        keychain_value = json.loads(oauth_credential_fixture(expires_in_seconds=60))
        keychain_value["padding"] = "x" * (
            providers.CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES
        )
        keychain = bytearray(json.dumps(keychain_value).encode())
        file_credential = bytearray(
            oauth_credential_fixture(expires_in_seconds=3600)
        )
        snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        read_keychain.return_value = keychain
        read_file.return_value = (file_credential, snapshot)

        selected = providers._select_claude_macos_credential(self.review)

        self.assertEqual(keychain, bytearray(len(keychain)))
        self.assertEqual(selected.source, "pwd-home-credential-file")
        selected.payload[:] = b"\x00" * len(selected.payload)

    @mock.patch.object(providers, "_read_claude_macos_file_credential")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_oversized_selected_file_blocks_shared_keychain_writeback(
        self,
        read_keychain: mock.Mock,
        read_file: mock.Mock,
    ) -> None:
        keychain = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        file_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        file_value["padding"] = "x" * (
            providers.CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES
        )
        file_credential = bytearray(json.dumps(file_value).encode())
        snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        read_keychain.return_value = keychain
        read_file.return_value = (file_credential, snapshot)

        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "too large for safe refresh persistence",
        ):
            providers._select_claude_macos_credential(self.review)

        self.assertEqual(keychain, bytearray(len(keychain)))
        self.assertEqual(file_credential, bytearray(len(file_credential)))

    def test_refresh_lock_protocol_requires_exact_verified_artifact_report(
        self,
    ) -> None:
        version, platform_key, checksum = next(
            iter(claude_refresh_lock.CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS)
        )
        executable = self.review.container_dir / "verified-claude"
        report = {
            "schema": 1,
            "version": version,
            "platform": platform_key,
            "sha256": checksum,
            "verified_executable": str(executable),
            "publisher_provenance": "anthropic-signed-manifest",
        }
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            report,
        )
        self.assertIs(
            providers._certified_claude_refresh_lock_protocol(
                self.review,
                executable,
            ),
            self.claude_refresh_lock_protocol,
        )

        tampered_values = (
            ("version", "2.9.999"),
            ("platform", "linux-unknown"),
            ("sha256", "0" + checksum[1:]),
            ("verified_executable", str(executable) + "-other"),
            ("publisher_provenance", "unverified"),
        )
        for field, value in tampered_values:
            with self.subTest(field=field):
                tampered = dict(report)
                tampered[field] = value
                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    tampered,
                )
                with self.assertRaises(
                    providers.ClaudeExecutableInspectionInconclusive
                ):
                    providers._certified_claude_refresh_lock_protocol(
                        self.review,
                        executable,
                    )

    @mock.patch.object(providers, "_read_claude_macos_file_credential")
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_malformed_secondary_source_blocks_valid_source(
        self,
        read_keychain: mock.Mock,
        read_file: mock.Mock,
    ) -> None:
        keychain = bytearray(oauth_credential_fixture())
        malformed = bytearray(b'{"claudeAiOauth":{}}')
        snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        read_keychain.return_value = keychain
        read_file.return_value = (malformed, snapshot)

        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "pwd-home file credential is malformed",
        ):
            providers._select_claude_macos_credential(self.review)

        self.assertEqual(keychain, bytearray(len(keychain)))
        self.assertEqual(malformed, bytearray(len(malformed)))

    @mock.patch.object(
        providers,
        "_read_claude_macos_file_credential",
        return_value=None,
    )
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_deeply_nested_credential_is_malformed(
        self,
        read_keychain: mock.Mock,
        _read_file: mock.Mock,
    ) -> None:
        depth = 10_000
        credential = bytearray(
            b'{"claudeAiOauth":'
            + b"[" * depth
            + b"0"
            + b"]" * depth
            + b"}"
        )
        read_keychain.return_value = credential

        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "macOS Keychain credential is malformed",
        ):
            providers._select_claude_macos_credential(self.review)

        self.assertEqual(credential, bytearray(len(credential)))
        raw_credential = bytearray(
            b'{"claudeAiOauth":'
            + b"[" * depth
            + b"0"
            + b"]" * depth
            + b"}"
        )
        with self.assertRaisesRegex(
            providers.ClaudeCredentialUnsafe,
            "refresh token is malformed",
        ):
            providers._claude_credential_refresh_digest(raw_credential)

    @mock.patch.object(
        providers,
        "_read_claude_macos_file_credential",
        return_value=None,
    )
    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_expired_access_token_remains_refreshable_in_final_runtime(
        self,
        read_keychain: mock.Mock,
        _read_file: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        read_keychain.return_value = credential

        selected = providers._select_claude_macos_credential(self.review)

        self.assertEqual(selected.source, "macos-keychain")
        self.assertLess(selected.expires_at_ms, time.time() * 1000)
        selected.payload[:] = b"\x00" * len(selected.payload)

    def test_credential_json_rejects_duplicate_keys_and_nonfinite_expiry(self) -> None:
        duplicate = bytearray(
            b'{"claudeAiOauth":{"accessToken":"a","accessToken":"b",'
            b'"refreshToken":"r","expiresAt":1}}'
        )
        nonfinite = bytearray(
            b'{"claudeAiOauth":{"accessToken":"a","refreshToken":"r",'
            b'"expiresAt":NaN}}'
        )
        for payload in (duplicate, nonfinite):
            with self.subTest(payload=payload), self.assertRaises(
                providers.ClaudeCredentialUnsafe
            ):
                providers._validate_claude_local_credential(
                    payload,
                    source="fixture",
                )

    def test_credential_json_normalizes_unicode_failures_as_unsafe(self) -> None:
        with self.assertRaises(providers.ClaudeCredentialUnsafe) as decoded:
            providers._validate_claude_local_credential(
                bytearray(b"\xff"),
                source="fixture",
            )
        self.assertIsInstance(decoded.exception.__cause__, UnicodeDecodeError)

        for field in ("accessToken", "refreshToken"):
            values = {
                "accessToken": "a",
                "refreshToken": "r",
            }
            values[field] = "\\ud800"
            payload = bytearray(
                (
                    '{"claudeAiOauth":{"accessToken":"'
                    + values["accessToken"]
                    + '","refreshToken":"'
                    + values["refreshToken"]
                    + '","expiresAt":1}}'
                ).encode("ascii")
            )
            with self.subTest(field=field):
                with self.assertRaises(
                    providers.ClaudeCredentialUnsafe
                ) as validated:
                    providers._validate_claude_local_credential(
                        payload,
                        source="fixture",
                    )
                self.assertIsInstance(
                    validated.exception.__cause__,
                    UnicodeEncodeError,
                )

        surrogate_refresh = bytearray(
            b'{"claudeAiOauth":{"accessToken":"a",'
            b'"refreshToken":"\\ud800","expiresAt":1}}'
        )
        with self.assertRaises(providers.ClaudeCredentialUnsafe) as encoded:
            providers._claude_credential_refresh_digest(surrogate_refresh)
        self.assertIsInstance(encoded.exception.__cause__, UnicodeEncodeError)

    def test_macos_credential_sync_fails_closed_without_fullfsync(self) -> None:
        with (
            mock.patch.object(providers.os, "fsync") as fsync,
            mock.patch.object(
                providers.sys,
                "platform",
                "darwin",
            ),
            mock.patch.object(
                providers.importlib,
                "import_module",
                return_value=object(),
            ) as import_module,
            self.assertRaisesRegex(OSError, "F_FULLFSYNC"),
        ):
            providers._sync_claude_credential_descriptor(37)

        fsync.assert_called_once_with(37)
        import_module.assert_called_once_with("fcntl")

    def test_non_macos_credential_sync_uses_fsync_only(self) -> None:
        with (
            mock.patch.object(providers.os, "fsync") as fsync,
            mock.patch.object(
                providers.sys,
                "platform",
                "linux",
            ),
            mock.patch.object(
                providers.importlib,
                "import_module",
            ) as import_module,
        ):
            providers._sync_claude_credential_descriptor(41)

        fsync.assert_called_once_with(41)
        import_module.assert_not_called()

    def test_file_refresh_writeback_is_atomic_0600_and_compare_guarded(self) -> None:
        original = oauth_credential_fixture(expires_in_seconds=60)
        credential_path = self.write_pwd_home_credential(original)
        result = providers._read_claude_macos_file_credential()
        assert result is not None
        expected, snapshot = result
        refreshed_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=-60)
        )
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-" + "rotated-refresh-value"
        )
        refreshed = bytearray(json.dumps(refreshed_value).encode())
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=None,
            file_digest=providers._claude_credential_digest(expected),
            file_snapshot=snapshot,
        )

        with mock.patch.object(
            providers,
            "_read_claude_keychain_credential",
            return_value=None,
        ):
            self.assertTrue(providers._write_claude_file_credential(
                self.review,
                refreshed,
                expected,
                snapshot,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            ))
        self.assertEqual(credential_path.read_bytes(), bytes(refreshed))
        self.assertEqual(stat.S_IMODE(credential_path.stat().st_mode), 0o600)

        result = providers._read_claude_macos_file_credential()
        assert result is not None
        stale_expected, stale_snapshot = result
        replacement = oauth_credential_fixture(expires_in_seconds=1800)
        self.write_private_source(credential_path, replacement)
        newer = bytearray(oauth_credential_fixture(expires_in_seconds=10800))
        stale_carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=None,
            file_digest=providers._claude_credential_digest(stale_expected),
            file_snapshot=stale_snapshot,
        )
        with mock.patch.object(
            providers,
            "_read_claude_keychain_credential",
            return_value=None,
        ):
            self.assertFalse(providers._write_claude_file_credential(
                self.review,
                newer,
                stale_expected,
                stale_snapshot,
                stale_carrier_snapshot,
                self.claude_refresh_lock_protocol,
            ))
        self.assertEqual(credential_path.read_bytes(), replacement)
        for payload in (expected, refreshed, stale_expected, newer):
            payload[:] = b"\x00" * len(payload)

    def test_file_refresh_writeback_holds_claude_lock_at_commit(self) -> None:
        original = oauth_credential_fixture(expires_in_seconds=60)
        credential_path = self.write_pwd_home_credential(original)
        result = providers._read_claude_macos_file_credential()
        assert result is not None
        expected, snapshot = result
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=None,
            file_digest=providers._claude_credential_digest(expected),
            file_snapshot=snapshot,
        )
        events: list[str] = []
        lease = mock.Mock(spec=["assert_held"])
        lease.assert_held.side_effect = lambda: events.append("assert-held")
        real_replace = os.replace

        @contextlib.contextmanager
        def coordinated_refresh_lock(
            path: pathlib.Path,
            *,
            protocol: providers.ClaudeRefreshLockProtocol,
        ):
            self.assertEqual(path, credential_path.parent)
            self.assertIs(protocol, self.claude_refresh_lock_protocol)
            events.append("lock-acquired")
            yield lease
            events.append("lock-released")

        def replace_after_assert(*args: object, **kwargs: object) -> None:
            events.append("replace")
            real_replace(*args, **kwargs)

        with (
            mock.patch.object(
                providers,
                "claude_refresh_lock",
                side_effect=coordinated_refresh_lock,
            ),
            mock.patch.object(
                providers.os,
                "replace",
                side_effect=replace_after_assert,
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                return_value=None,
            ),
        ):
            self.assertTrue(
                providers._write_claude_file_credential(
                    self.review,
                    refreshed,
                    expected,
                    snapshot,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
            )

        self.assertLess(events.index("assert-held"), events.index("replace"))
        self.assertEqual(events[0], "lock-acquired")
        self.assertEqual(events[-1], "lock-released")
        expected[:] = b"\x00" * len(expected)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_file_refresh_temporary_close_preserves_control_flow(self) -> None:
        original = oauth_credential_fixture(expires_in_seconds=60)
        credential_path = self.write_pwd_home_credential(original)
        result = providers._read_claude_macos_file_credential()
        assert result is not None
        expected, snapshot = result
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=None,
            file_digest=providers._claude_credential_digest(expected),
            file_snapshot=snapshot,
        )
        real_close = os.close
        temporary_descriptor: list[int] = []

        def interrupt_write(descriptor: int, _payload: bytearray) -> None:
            temporary_descriptor.append(descriptor)
            raise KeyboardInterrupt

        def close_with_temporary_failure(descriptor: int) -> None:
            if temporary_descriptor and descriptor == temporary_descriptor[0]:
                raise OSError("injected temporary close failure")
            real_close(descriptor)

        try:
            with (
                mock.patch.object(
                    providers,
                    "_read_claude_keychain_credential",
                    return_value=None,
                ),
                mock.patch.object(
                    providers,
                    "_write_all_to_descriptor",
                    side_effect=interrupt_write,
                ),
                mock.patch.object(
                    providers.os,
                    "close",
                    side_effect=close_with_temporary_failure,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                providers._write_claude_file_credential(
                    self.review,
                    refreshed,
                    expected,
                    snapshot,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
        finally:
            if temporary_descriptor:
                real_close(temporary_descriptor[0])

        self.assertEqual(credential_path.read_bytes(), original)
        expected[:] = b"\x00" * len(expected)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_file_refresh_writeback_rejects_new_unselected_keychain_value(
        self,
    ) -> None:
        original = oauth_credential_fixture(expires_in_seconds=60)
        credential_path = self.write_pwd_home_credential(original)
        result = providers._read_claude_macos_file_credential()
        assert result is not None
        expected, snapshot = result
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=None,
            file_digest=providers._claude_credential_digest(expected),
            file_snapshot=snapshot,
        )
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        concurrent_keychain = oauth_credential_fixture(expires_in_seconds=10800)

        with mock.patch.object(
            providers,
            "_read_claude_keychain_credential",
            side_effect=lambda _review: bytearray(concurrent_keychain),
        ):
            self.assertFalse(
                providers._write_claude_file_credential(
                    self.review,
                    refreshed,
                    expected,
                    snapshot,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
            )

        self.assertEqual(credential_path.read_bytes(), original)
        expected[:] = b"\x00" * len(expected)
        refreshed[:] = b"\x00" * len(refreshed)

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_final_runtime_persists_refresh_after_broker_quiescence(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
        snapshot_is_current: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(refreshed),
            file_digest=None,
            file_snapshot=None,
        )
        persist_credential.return_value = updated_snapshot
        durable_carriers_seen: list[pathlib.Path] = []

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            recovery_root = providers._claude_macos_recovery_root(
                self.review
            )
            durable_carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(durable_carriers), 1)
            durable_carriers_seen.extend(durable_carriers)
            self.assertEqual(
                (
                    durable_carriers[0]
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                bytes(refreshed),
            )
            yield 43211

        credential_server.side_effect = broker
        write_json = {
            "authentication": {},
            "phase": "pending",
        }
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            write_json,
        )

        with self.claude_keychain_runtime(
            self.review,
            {},
            self.claude_refresh_lock_protocol,
        ) as runtime_env:
            self.assertEqual(
                runtime_env[providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV],
                "43211",
            )
            persist_credential.assert_not_called()

        persist_credential.assert_called_once()
        self.assertEqual(len(durable_carriers_seen), 1)
        self.assertFalse(durable_carriers_seen[0].exists())
        snapshot_is_current.assert_called_once_with(
            self.review,
            updated_snapshot,
            self.claude_refresh_lock_protocol,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["authentication"]["source"], "macos-keychain")
        self.assertEqual(
            report["authentication"]["carrier"],
            "one-shot-security-broker",
        )
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "guarded-writeback-persisted",
        )

    def test_keychain_only_failed_writeback_retains_refreshed_credential(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed_value = json.loads(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-keychain-recovery-refresh-value"
        )
        refreshed_bytes = json.dumps(refreshed_value).encode()
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=None,
            file_snapshot=None,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                original
            ),
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=carrier_snapshot,
        )
        callback_payload: bytearray | None = None

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal callback_payload
            assert update_callback is not None
            callback_payload = bytearray(refreshed_bytes)
            self.assertTrue(update_callback(callback_payload))
            callback_payload[:] = b"\x00" * len(callback_payload)
            yield 43211

        lease = mock.Mock(spec=["assert_held"])
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                side_effect=lambda _review: bytearray(original),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                return_value=None,
            ),
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
                return_value=False,
            ) as write_keychain,
            mock.patch.object(
                providers,
                "_read_claude_macos_carrier_snapshot",
                return_value=carrier_snapshot,
            ),
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
            ) as write_file,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        assert callback_payload is not None
        self.assertEqual(callback_payload, b"\x00" * len(callback_payload))
        carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        self.assertNotIn(
            refreshed_value["claudeAiOauth"]["refreshToken"],
            str(raised.exception),
        )
        self.assertEqual(
            write_keychain.call_count,
            providers.CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS,
        )
        write_file.assert_not_called()
        self.assertIn(str(carrier), str(raised.exception))
        recovery_artifact = (
            carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        )
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            ),
            str(recovery_artifact),
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_artifact"],
            str(recovery_artifact),
        )

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_durable_stage_cleanup_failure_pauses_after_host_commit(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
        _snapshot_is_current: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        selected_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=None,
            file_snapshot=None,
        )
        updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(refreshed),
            file_digest=None,
            file_snapshot=None,
        )
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=selected_snapshot,
        )
        persist_credential.return_value = updated_snapshot

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            yield 43211

        credential_server.side_effect = broker
        retained_carriers: list[pathlib.Path] = []

        def fail_cleanup(
            _review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            _digest: bytes,
        ) -> None:
            retained_carriers.append(carrier)
            failure = providers.ClaudeCredentialInspectionInconclusive(
                "injected durable recovery cleanup failure"
            )
            setattr(
                failure,
                "_codex_claude_retained_credential_carrier",
                str(carrier),
            )
            setattr(
                failure,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            providers._mark_claude_macos_recovery_cleanup_artifact(
                failure,
                carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME,
            )
            raise failure

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
                side_effect=fail_cleanup,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable recovery cleanup failure",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist_credential.assert_called_once()
        self.assertEqual(len(retained_carriers), 1)
        retained = retained_carriers[0]
        self.assertTrue(retained.is_dir())
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(
                retained
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(
                retained
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )

    def test_removed_recovery_carrier_fsync_failure_has_no_cleanup_path(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        digest = providers._claude_credential_digest(credential)
        real_fsync = providers.os.fsync
        directory_fsyncs = 0

        def fail_recovery_root_fsync(descriptor: int) -> None:
            nonlocal directory_fsyncs
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_fsyncs += 1
                if directory_fsyncs == 3:
                    raise OSError("injected recovery root fsync failure")
            real_fsync(descriptor)

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-cleanup"},
        )
        with (
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=fail_recovery_root_fsync,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot remove",
            ) as raised,
        ):
            providers._remove_claude_macos_recovery_carrier(
                self.review,
                carrier,
                digest,
            )

        self.assertEqual(directory_fsyncs, 3)
        self.assertFalse(carrier.exists())
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        providers._record_claude_secondary_persistence_failure(
            self.review,
            raised.exception,
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])
        credential[:] = b"\x00" * len(credential)

    def test_carrier_rmdir_signal_promotes_cleanup_to_recovery_root(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        digest = providers._claude_credential_digest(credential)
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        real_rmdir = providers.os.rmdir

        def signal_after_carrier_rmdir(
            path: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> None:
            real_rmdir(path, *args, **kwargs)
            if path == carrier.name:
                raise forwarded

        with (
            mock.patch.object(
                providers.os,
                "rmdir",
                side_effect=signal_after_carrier_rmdir,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._remove_claude_macos_recovery_carrier(
                self.review,
                carrier,
                digest,
            )

        self.assertIs(raised.exception, forwarded)
        self.assertFalse(carrier.exists())
        self.assertEqual(
            getattr(
                forwarded,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        credential[:] = b"\x00" * len(credential)

    def test_unlink_signal_does_not_publish_vanished_current_credential(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        config_dir = carrier / "config"
        credential_path = config_dir / providers.CLAUDE_CREDENTIAL_FILE_NAME
        digest = providers._claude_credential_digest(credential)
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        real_unlink = providers.os.unlink

        def signal_after_credential_unlink(
            path: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> None:
            real_unlink(path, *args, **kwargs)
            if path == providers.CLAUDE_CREDENTIAL_FILE_NAME:
                raise forwarded

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-cleanup"},
        )
        with (
            mock.patch.object(
                providers.os,
                "unlink",
                side_effect=signal_after_credential_unlink,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._remove_claude_macos_recovery_carrier(
                self.review,
                carrier,
                digest,
            )

        self.assertIs(raised.exception, forwarded)
        self.assertFalse(credential_path.exists())
        self.assertIsNone(
            getattr(
                forwarded,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                forwarded,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertEqual(
            getattr(
                forwarded,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(config_dir),
        )
        providers._record_claude_secondary_persistence_failure(
            self.review,
            forwarded,
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(config_dir),
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])
        credential[:] = b"\x00" * len(credential)

    def test_current_reproof_signal_precedes_ordinary_cleanup_failure(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        credential_path = (
            carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        )
        digest = providers._claude_credential_digest(credential)
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers.os,
                "unlink",
                side_effect=OSError("injected unlink failure"),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_recovery_credential",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._remove_claude_macos_recovery_carrier(
                self.review,
                carrier,
                digest,
            )

        self.assertIs(raised.exception, forwarded)
        self.assertTrue(
            getattr(
                forwarded,
                "_codex_claude_refresh_persistence_failed",
                False,
            )
        )
        self.assertEqual(
            getattr(
                forwarded,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(credential_path),
        )
        self.assertIsNone(
            getattr(
                forwarded,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        credential[:] = b"\x00" * len(credential)

    def test_vanished_credential_artifact_is_not_validated(self) -> None:
        vanished = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-vanished"
            / "config"
            / providers.CLAUDE_CREDENTIAL_FILE_NAME
        )
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        setattr(
            error,
            "_codex_claude_retained_credential_artifact",
            str(vanished),
        )

        self.assertIsNone(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            )
        )

    def test_replaced_current_payload_is_not_validated(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        replacement = oauth_credential_fixture(expires_in_seconds=10800)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=providers._claude_credential_digest(original),
        )
        replacement_path = artifact.with_name("replacement.json")
        replacement_path.write_bytes(replacement)
        replacement_path.chmod(0o600)
        os.replace(replacement_path, artifact)

        self.assertIsNone(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            )
        )
        original[:] = b"\x00" * len(original)

    def test_same_payload_new_inode_is_not_validated(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        replacement_path = artifact.with_name("replacement.json")
        replacement_path.write_bytes(credential)
        replacement_path.chmod(0o600)
        os.replace(replacement_path, artifact)

        self.assertIsNone(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            )
        )
        credential[:] = b"\x00" * len(credential)

    def test_marker_rejects_payload_replaced_after_source_proof(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        replacement = oauth_credential_fixture(expires_in_seconds=10800)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        expected_digest = providers._claude_credential_digest(original)
        replacement_path = artifact.with_name("replacement.json")
        replacement_path.write_bytes(replacement)
        replacement_path.chmod(0o600)
        os.replace(replacement_path, artifact)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )

        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=expected_digest,
        )

        self.assertIsNone(
            getattr(
                error,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                error,
                "_codex_claude_retained_credential_proof",
                None,
            )
        )
        self.assertIsNone(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            )
        )
        self.assertFalse(
            any(
                "current recovery credential" in note
                or "credential update remains" in note
                for note in getattr(error, "__notes__", ())
            )
        )
        original[:] = b"\x00" * len(original)

    def test_marker_accepts_same_payload_pre_capture_replacement(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        original_identity = artifact.stat().st_ino
        replacement_path = artifact.with_name("replacement.json")
        replacement_path.write_bytes(credential)
        replacement_path.chmod(0o600)
        os.replace(replacement_path, artifact)
        self.assertNotEqual(artifact.stat().st_ino, original_identity)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )

        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )

        proof = providers._get_claude_retained_credential_proof(error)
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof.artifact, artifact)
        self.assertEqual(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            ),
            str(artifact),
        )
        credential[:] = b"\x00" * len(credential)

    def test_marker_failure_clears_previous_current_pair(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        replacement = oauth_credential_fixture(expires_in_seconds=10800)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        expected_digest = providers._claude_credential_digest(original)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=expected_digest,
        )
        replacement_path = artifact.with_name("replacement.json")
        replacement_path.write_bytes(replacement)
        replacement_path.chmod(0o600)
        os.replace(replacement_path, artifact)

        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=expected_digest,
        )

        self.assertIsNone(
            providers._get_claude_retained_credential_proof(error)
        )
        self.assertIsNone(
            getattr(
                error,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        original[:] = b"\x00" * len(original)

    def test_current_proof_ignores_legacy_path_mismatch(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        setattr(
            error,
            "_codex_claude_retained_credential_artifact",
            str(artifact.with_name("other.json")),
        )

        self.assertEqual(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                error,
            ),
            str(artifact),
        )
        credential[:] = b"\x00" * len(credential)

    def test_current_proof_replacement_has_no_empty_publication_window(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        source_error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            source_error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        proof = providers._get_claude_retained_credential_proof(source_error)
        self.assertIsNotNone(proof)
        assert proof is not None
        proof_published = threading.Event()
        allow_legacy_publication = threading.Event()
        writer_errors: list[BaseException] = []

        class BlockingProofError(
            providers.ClaudeCredentialInspectionInconclusive
        ):
            publication_armed = False

            def __setattr__(self, name: str, value: object) -> None:
                super().__setattr__(name, value)
                if (
                    self.publication_armed
                    and name == "_codex_claude_retained_credential_proof"
                ):
                    proof_published.set()
                    if not allow_legacy_publication.wait(timeout=2.0):
                        raise RuntimeError(
                            "fixture proof publication was not released"
                        )

        error = BlockingProofError("fixture publication target")
        error.publication_armed = True

        def publish() -> None:
            try:
                providers._set_claude_retained_credential_proof(error, proof)
            except BaseException as publication_error:
                writer_errors.append(publication_error)

        writer = threading.Thread(target=publish)
        writer.start()
        self.assertTrue(proof_published.wait(timeout=2.0))
        try:
            self.assertIsNone(
                getattr(
                    error,
                    "_codex_claude_retained_credential_artifact",
                    None,
                )
            )
            self.assertIs(
                providers._get_claude_retained_credential_proof(error),
                proof,
            )
        finally:
            allow_legacy_publication.set()
            writer.join(timeout=2.0)

        self.assertFalse(writer.is_alive())
        self.assertEqual(writer_errors, [])
        self.assertIs(
            providers._get_claude_retained_credential_proof(error),
            proof,
        )
        credential[:] = b"\x00" * len(credential)

    def test_proof_capture_preserves_directory_open_interrupt(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers,
                "_open_absolute_directory_chain_without_symlinks",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._capture_claude_retained_credential_proof(
                artifact,
                expected_digest=providers._claude_credential_digest(
                    credential
                ),
            )

        self.assertIs(raised.exception, forwarded)
        credential[:] = b"\x00" * len(credential)

    def test_proof_clear_interrupt_cannot_leave_authoritative_proof(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        class InterruptingClearError(
            providers.ClaudeCredentialInspectionInconclusive
        ):
            clear_armed = False

            def __delattr__(self, name: str) -> None:
                super().__delattr__(name)
                if (
                    self.clear_armed
                    and name == "_codex_claude_retained_credential_artifact"
                ):
                    raise forwarded

        error = InterruptingClearError("fixture clear target")
        providers._mark_claude_macos_recovery_update_artifact(
            error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        error.clear_armed = True

        with self.assertRaises(providers.ForwardedSignal) as raised:
            providers._clear_claude_retained_credential_proof(error)

        self.assertIs(raised.exception, forwarded)
        self.assertIsNone(
            providers._get_claude_retained_credential_proof(error)
        )
        credential[:] = b"\x00" * len(credential)

    def test_retained_proof_transfer_interrupt_wipes_credential_payloads(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        marker_error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        providers._mark_claude_macos_recovery_update_artifact(
            marker_error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        proof = providers._get_claude_retained_credential_proof(marker_error)
        self.assertIsNotNone(proof)
        assert proof is not None

        cases = (
            (
                providers._read_claude_macos_recovery_credential,
                lambda: providers._read_claude_macos_recovery_credential(
                    self.review,
                    carrier,
                ),
            ),
            (
                providers._capture_claude_retained_credential_proof,
                lambda: providers._capture_claude_retained_credential_proof(
                    artifact,
                    expected_digest=providers._claude_credential_digest(
                        credential
                    ),
                ),
            ),
            (
                providers._claude_retained_credential_artifact_matches_proof,
                lambda: providers._claude_retained_credential_artifact_matches_proof(
                    artifact,
                    proof,
                ),
            ),
        )
        for function, invoke in cases:
            with self.subTest(function=function.__name__):
                observed = bytearray(credential)
                interrupted = False

                def interrupt_before_transfer(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal interrupted
                    if (
                        interrupted
                        or event != "line"
                        or getattr(frame, "f_code", None) is not function.__code__
                    ):
                        return interrupt_before_transfer
                    locals_map = getattr(frame, "f_locals", {})
                    result = locals_map.get("result")
                    if result is not None and locals_map.get("payload") is None:
                        interrupted = True
                        raise SystemExit("injected payload transfer interrupt")
                    return interrupt_before_transfer

                wiped = False
                try:
                    with (
                        mock.patch.object(
                            providers,
                            "_read_claude_credential_file_from_directory",
                            return_value=(observed, proof.file_identity),
                        ),
                        self.assertRaisesRegex(
                            SystemExit,
                            "payload transfer interrupt",
                        ),
                    ):
                        sys.settrace(interrupt_before_transfer)
                        invoke()
                finally:
                    sys.settrace(None)
                    wiped = observed == bytearray(len(observed))
                    observed[:] = b"\x00" * len(observed)

                self.assertTrue(interrupted)
                self.assertTrue(wiped)
        credential[:] = b"\x00" * len(credential)

    def test_failed_recovery_skips_bare_path_before_valid_proof(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
        )
        artifact = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        persistence_error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        setattr(
            persistence_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        providers._mark_claude_macos_recovery_update_artifact(
            persistence_error,
            artifact,
            expected_digest=providers._claude_credential_digest(credential),
        )
        recovery_error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture recovery failure"
        )
        setattr(
            recovery_error,
            "_codex_claude_retained_credential_artifact",
            str(artifact),
        )

        failed = providers._failed_claude_macos_recovery_error(
            persistence_error,
            recovery_error,
        )

        self.assertEqual(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                failed,
            ),
            str(artifact),
        )
        self.assertEqual(
            getattr(
                failed,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )
        credential[:] = b"\x00" * len(credential)

    def test_vanished_recovery_carrier_is_not_validated(self) -> None:
        vanished = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-vanished"
        )
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture persistence failure"
        )
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(vanished),
        )

        self.assertIsNone(
            providers._validated_claude_retained_credential_carrier(
                self.review,
                error,
            )
        )

    def test_vanished_cleanup_artifact_is_not_validated(self) -> None:
        vanished = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-vanished"
        )
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture cleanup failure"
        )
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            str(vanished),
        )

        self.assertIsNone(
            providers._validated_claude_retained_cleanup_artifact(
                self.review,
                error,
            )
        )

    def test_replaced_cleanup_artifact_is_not_validated(self) -> None:
        artifact = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-replaced"
        )
        artifact.mkdir(parents=True, mode=0o700)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture cleanup failure"
        )
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            str(artifact),
        )
        real_snapshot = providers._claude_nofollow_artifact_snapshot
        replaced = False

        def replace_after_snapshot(
            path: pathlib.Path,
        ) -> providers._ClaudeNoFollowArtifactSnapshot:
            nonlocal replaced
            snapshot = real_snapshot(path)
            if path == artifact and not replaced:
                replaced = True
                artifact.rmdir()
                artifact.write_bytes(b"replacement")
            return snapshot

        with mock.patch.object(
            providers,
            "_claude_nofollow_artifact_snapshot",
            side_effect=replace_after_snapshot,
        ):
            self.assertIsNone(
                providers._validated_claude_retained_cleanup_artifact(
                    self.review,
                    error,
                )
            )

        self.assertTrue(replaced)

    def test_cleanup_root_remains_valid_when_its_contents_change(self) -> None:
        recovery_root = providers._claude_macos_recovery_root(self.review)
        late_residue = recovery_root / "late-residue"
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture cleanup failure"
        )
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            str(recovery_root),
        )
        real_snapshot = providers._claude_nofollow_artifact_snapshot
        mutated = False

        def mutate_after_snapshot(
            path: pathlib.Path,
        ) -> providers._ClaudeNoFollowArtifactSnapshot:
            nonlocal mutated
            snapshot = real_snapshot(path)
            if path == recovery_root and not mutated:
                mutated = True
                late_residue.mkdir(mode=0o700)
            return snapshot

        with mock.patch.object(
            providers,
            "_claude_nofollow_artifact_snapshot",
            side_effect=mutate_after_snapshot,
        ):
            self.assertEqual(
                providers._validated_claude_retained_cleanup_artifact(
                    self.review,
                    error,
                ),
                str(recovery_root),
            )

        self.assertTrue(mutated)

    def test_cleanup_artifact_rejects_ancestor_symlink_swap(self) -> None:
        recovery_root = providers._claude_macos_recovery_root(self.review)
        carrier = recovery_root / "claude-carrier-ancestor-swap"
        carrier.mkdir(mode=0o700)
        artifact = carrier / "residue"
        artifact.write_bytes(b"residue")
        outside = self.review.source_root.parent / "moved-carrier"
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture cleanup failure"
        )
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            str(artifact),
        )
        real_snapshot = providers._claude_nofollow_artifact_snapshot
        swapped = False

        def swap_ancestor_after_snapshot(
            path: pathlib.Path,
        ) -> providers._ClaudeNoFollowArtifactSnapshot:
            nonlocal swapped
            snapshot = real_snapshot(path)
            if path == artifact and not swapped:
                swapped = True
                carrier.rename(outside)
                carrier.symlink_to(outside, target_is_directory=True)
            return snapshot

        with mock.patch.object(
            providers,
            "_claude_nofollow_artifact_snapshot",
            side_effect=swap_ancestor_after_snapshot,
        ):
            self.assertIsNone(
                providers._validated_claude_retained_cleanup_artifact(
                    self.review,
                    error,
                )
            )

        self.assertTrue(swapped)

    def test_cleanup_artifact_rejects_ancestor_swap_during_walk(self) -> None:
        recovery_root = providers._claude_macos_recovery_root(self.review)
        carrier = recovery_root / "claude-carrier-walk-swap"
        carrier.mkdir(mode=0o700)
        artifact = carrier / "residue"
        artifact.write_bytes(b"residue")
        outside = self.review.source_root.parent / "walk-moved-carrier"
        error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture cleanup failure"
        )
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            str(artifact),
        )
        real_stat = providers.os.stat
        swapped = False

        def swap_after_dirent_stat(
            path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal swapped
            result = real_stat(path, *args, **kwargs)
            if path == carrier.name and not swapped:
                swapped = True
                carrier.rename(outside)
                carrier.symlink_to(outside, target_is_directory=True)
            return result

        with mock.patch.object(
            providers.os,
            "stat",
            side_effect=swap_after_dirent_stat,
        ):
            self.assertIsNone(
                providers._validated_claude_retained_cleanup_artifact(
                    self.review,
                    error,
                )
            )

        self.assertTrue(swapped)

    def test_cleanup_artifact_rejects_non_file_leaf_types(self) -> None:
        recovery_root = providers._claude_macos_recovery_root(self.review)
        carrier = recovery_root / "claude-carrier-special-leaf"
        carrier.mkdir(mode=0o700)
        target = carrier / "target"
        target.write_bytes(b"target")
        symlink = carrier / "symlink"
        symlink.symlink_to(target)
        fifo = carrier / "fifo"
        os.mkfifo(fifo, mode=0o600)

        for artifact in (symlink, fifo):
            with self.subTest(artifact=artifact.name):
                error = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture cleanup failure"
                )
                setattr(
                    error,
                    "_codex_claude_retained_cleanup_artifact",
                    str(artifact),
                )
                self.assertIsNone(
                    providers._validated_claude_retained_cleanup_artifact(
                        self.review,
                        error,
                    )
                )

    def test_recovery_carrier_write_failure_is_cleanup_only(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))

        with (
            mock.patch.object(
                providers,
                "_write_all_to_descriptor",
                side_effect=OSError("injected recovery carrier write failure"),
            ),
            self.assertRaisesRegex(
                OSError,
                "recovery carrier write failure",
            ) as raised,
        ):
            providers._retain_claude_macos_refreshed_credential(
                self.review,
                credential,
            )

        cleanup_artifact = self.assert_cleanup_only_macos_recovery_artifact(
            raised.exception
        )
        self.assertTrue(cleanup_artifact.is_dir())
        credential[:] = b"\x00" * len(credential)

    def test_recovery_carrier_fsync_failure_is_cleanup_only(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        real_fsync = providers.os.fsync

        def fail_credential_fsync(descriptor: int) -> None:
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("injected recovery carrier fsync failure")
            real_fsync(descriptor)

        with (
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=fail_credential_fsync,
            ),
            self.assertRaisesRegex(
                OSError,
                "recovery carrier fsync failure",
            ) as raised,
        ):
            providers._retain_claude_macos_refreshed_credential(
                self.review,
                credential,
            )

        cleanup_artifact = self.assert_cleanup_only_macos_recovery_artifact(
            raised.exception
        )
        self.assertTrue(cleanup_artifact.is_dir())
        credential[:] = b"\x00" * len(credential)

    def test_recovery_carrier_requires_exact_payload_readback(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        real_read = providers._read_claude_credential_file_from_directory

        def changed_readback(
            config_descriptor: int,
        ) -> tuple[bytearray, tuple[int, ...]] | None:
            result = real_read(config_descriptor)
            assert result is not None
            payload, identity = result
            payload[-1] = ord(" ")
            return payload, identity

        with (
            mock.patch.object(
                providers,
                "_read_claude_credential_file_from_directory",
                side_effect=changed_readback,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "changed after write",
            ) as raised,
        ):
            providers._retain_claude_macos_refreshed_credential(
                self.review,
                credential,
            )

        cleanup_artifact = self.assert_cleanup_only_macos_recovery_artifact(
            raised.exception
        )
        self.assertTrue(cleanup_artifact.is_dir())
        credential[:] = b"\x00" * len(credential)

    def test_verified_recovery_carrier_close_failure_remains_current(
        self,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        credential_bytes = bytes(credential)
        real_close = providers.os.close
        real_fstat = providers.os.fstat
        regular_close_count = 0
        failed_descriptor: int | None = None

        def fail_verified_credential_close(descriptor: int) -> None:
            nonlocal failed_descriptor, regular_close_count
            metadata = real_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                regular_close_count += 1
                if regular_close_count == 2:
                    failed_descriptor = descriptor
                    raise OSError(
                        "injected verified recovery carrier close failure"
                    )
            real_close(descriptor)

        try:
            with (
                mock.patch.object(
                    providers.os,
                    "close",
                    side_effect=fail_verified_credential_close,
                ),
                self.assertRaisesRegex(
                    providers.ClaudeCredentialInspectionInconclusive,
                    "cannot close the private macOS Claude recovery carrier safely",
                ) as raised,
            ):
                providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    credential,
                )
        finally:
            if failed_descriptor is not None:
                real_close(failed_descriptor)

        carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            credential_bytes,
        )
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            ),
            str(
                carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
        )
        credential[:] = b"\x00" * len(credential)

    def test_durable_stage_pre_rename_read_or_close_failure_is_cleanup_only(
        self,
    ) -> None:
        for failure_kind in ("read", "close"):
            with self.subTest(failure_kind=failure_kind):
                credential = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                recovery_root = providers._claude_macos_recovery_root(
                    self.review
                )
                pending = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
                    + failure_kind
                )
                committed = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
                    + failure_kind
                )
                providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    credential,
                    requested_carrier_root=pending,
                    credential_prevalidated=True,
                    durable_directories=True,
                )
                real_close = providers.os.close
                real_fstat = providers.os.fstat
                failed_descriptor: int | None = None

                def fail_pre_rename_close(descriptor: int) -> None:
                    nonlocal failed_descriptor
                    if stat.S_ISREG(real_fstat(descriptor).st_mode):
                        failed_descriptor = descriptor
                        raise OSError(
                            "injected pre-rename carrier close failure"
                        )
                    real_close(descriptor)

                try:
                    with contextlib.ExitStack() as stack:
                        if failure_kind == "read":
                            stack.enter_context(
                                mock.patch.object(
                                    providers,
                                    "_read_claude_macos_recovery_credential",
                                    side_effect=OSError(
                                        "injected pre-rename carrier read failure"
                                    ),
                                )
                            )
                        else:
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "close",
                                    side_effect=fail_pre_rename_close,
                                )
                            )
                        raised = stack.enter_context(
                            self.assertRaises(
                                (
                                    OSError,
                                    providers.ClaudeCredentialInspectionInconclusive,
                                )
                            )
                        )
                        providers._commit_claude_macos_durable_stage(
                            self.review,
                            pending,
                            committed,
                            credential,
                        )
                finally:
                    if failed_descriptor is not None:
                        real_close(failed_descriptor)

                cleanup_artifact = (
                    self.assert_cleanup_only_macos_recovery_artifact(
                        raised.exception
                    )
                )
                self.assertTrue(cleanup_artifact.is_relative_to(pending))
                self.assertTrue(pending.is_dir())
                self.assertFalse(committed.exists())
                credential[:] = b"\x00" * len(credential)

    def test_durable_stage_post_rename_read_or_close_failure_retains_commit(
        self,
    ) -> None:
        real_read = providers._read_claude_macos_recovery_credential
        for failure_kind in ("read", "close"):
            with self.subTest(failure_kind=failure_kind):
                credential = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                credential_bytes = bytes(credential)
                recovery_root = providers._claude_macos_recovery_root(
                    self.review
                )
                pending = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
                    + "post-"
                    + failure_kind
                )
                committed = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
                    + "post-"
                    + failure_kind
                )
                providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    credential,
                    requested_carrier_root=pending,
                    credential_prevalidated=True,
                    durable_directories=True,
                )
                read_calls = 0
                real_close = providers.os.close
                real_fstat = providers.os.fstat
                regular_close_count = 0
                failed_descriptor: int | None = None

                def fail_post_rename_read(
                    review: providers.ReviewWorkspace,
                    carrier: pathlib.Path,
                ) -> bytearray:
                    nonlocal read_calls
                    read_calls += 1
                    if read_calls == 2 and failure_kind == "read":
                        raise OSError(
                            "injected post-rename carrier read failure"
                        )
                    return real_read(review, carrier)

                def fail_post_rename_close(descriptor: int) -> None:
                    nonlocal failed_descriptor, regular_close_count
                    if stat.S_ISREG(real_fstat(descriptor).st_mode):
                        regular_close_count += 1
                        if regular_close_count == 2:
                            failed_descriptor = descriptor
                            raise OSError(
                                "injected post-rename carrier close failure"
                            )
                    real_close(descriptor)

                try:
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(
                            mock.patch.object(
                                providers,
                                "_read_claude_macos_recovery_credential",
                                side_effect=fail_post_rename_read,
                            )
                        )
                        if failure_kind == "close":
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "close",
                                    side_effect=fail_post_rename_close,
                                )
                            )
                        raised = stack.enter_context(
                            self.assertRaises(
                                (
                                    OSError,
                                    providers.ClaudeCredentialInspectionInconclusive,
                                )
                            )
                        )
                        providers._commit_claude_macos_durable_stage(
                            self.review,
                            pending,
                            committed,
                            credential,
                        )
                finally:
                    if failed_descriptor is not None:
                        real_close(failed_descriptor)

                self.assertEqual(read_calls, 2)
                self.assertFalse(pending.exists())
                self.assertEqual(
                    self.assert_macos_recovery_carrier(
                        raised.exception,
                        credential_bytes,
                    ),
                    committed,
                )
                self.assertIsNone(
                    getattr(
                        raised.exception,
                        "_codex_claude_retained_cleanup_artifact",
                        None,
                    )
                )
                credential[:] = b"\x00" * len(credential)

    def test_durable_stage_post_rename_payload_mismatch_is_cleanup_only(
        self,
    ) -> None:
        credential = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        pending = recovery_root / (
            providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
            + "post-mismatch"
        )
        committed = recovery_root / (
            providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
            + "post-mismatch"
        )
        providers._retain_claude_macos_refreshed_credential(
            self.review,
            credential,
            requested_carrier_root=pending,
            credential_prevalidated=True,
            durable_directories=True,
        )
        real_read = providers._read_claude_macos_recovery_credential
        read_calls = 0

        def mismatch_after_rename(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
        ) -> bytearray:
            nonlocal read_calls
            read_calls += 1
            payload = real_read(review, carrier)
            if read_calls == 2:
                payload[-1] ^= 1
            return payload

        try:
            with (
                mock.patch.object(
                    providers,
                    "_read_claude_macos_recovery_credential",
                    side_effect=mismatch_after_rename,
                ),
                self.assertRaisesRegex(
                    providers.ClaudeCredentialInspectionInconclusive,
                    "changed after commit",
                ) as raised,
            ):
                providers._commit_claude_macos_durable_stage(
                    self.review,
                    pending,
                    committed,
                    credential,
                )

            self.assertEqual(read_calls, 2)
            self.assertFalse(pending.exists())
            self.assertEqual(
                self.assert_cleanup_only_macos_recovery_artifact(
                    raised.exception
                ),
                committed,
            )
        finally:
            credential[:] = b"\x00" * len(credential)

    def test_incomplete_recovery_temp_fsync_failure_removes_temp_even_when_cleanup_fsync_fails(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"

        def fail_recovery_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                raise OSError("injected temporary credential fsync failure")
            raise OSError("injected cleanup directory fsync failure")

        with (
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=fail_recovery_fsync,
            ),
            self.assertRaisesRegex(
                OSError,
                "temporary credential fsync failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        self.assertEqual(
            sorted(path.name for path in config.iterdir()),
            [providers.CLAUDE_CREDENTIAL_FILE_NAME],
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
        )
        notes = getattr(raised.exception, "__notes__", ())
        if notes:
            self.assertIn(
                "Claude credential operation also had a cleanup failure",
                notes,
            )
        else:
            self.assertIsInstance(
                raised.exception.__cause__,
                providers.ClaudeCredentialCleanupDiagnostic,
            )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_incomplete_recovery_temp_metadata_failure_removes_temp(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_fstat = providers.os.fstat

        def fail_temporary_fstat(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                raise OSError("injected temporary credential metadata failure")
            return metadata

        with (
            mock.patch.object(
                providers.os,
                "fstat",
                side_effect=fail_temporary_fstat,
            ),
            self.assertRaisesRegex(
                OSError,
                "temporary credential metadata failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        self.assertEqual(
            sorted(path.name for path in config.iterdir()),
            [providers.CLAUDE_CREDENTIAL_FILE_NAME],
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
        )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_incomplete_recovery_temp_cleanup_stat_failure_reports_cleanup_artifact(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_fsync = providers.os.fsync
        real_stat = providers.os.stat

        def fail_temporary_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                raise OSError("injected temporary credential fsync failure")
            real_fsync(descriptor)

        def fail_temporary_cleanup_stat(
            path: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            if isinstance(path, str) and path.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            ):
                raise OSError("injected incomplete temp cleanup stat failure")
            return real_stat(path, *args, **kwargs)

        with (
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=fail_temporary_fsync,
            ),
            mock.patch.object(
                providers.os,
                "stat",
                side_effect=fail_temporary_cleanup_stat,
            ),
            self.assertRaisesRegex(
                OSError,
                "temporary credential fsync failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        artifact_value = getattr(
            raised.exception,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        self.assertIsInstance(artifact_value, str)
        artifact = pathlib.Path(artifact_value)
        self.assertTrue(artifact.exists())
        self.assertEqual(artifact.parent, config)
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_complete_recovery_temp_close_failure_retains_current_update(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        refreshed_bytes = bytes(refreshed)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_close = providers.os.close
        real_fstat = providers.os.fstat
        failed_descriptor: int | None = None

        def fail_temporary_close(descriptor: int) -> None:
            nonlocal failed_descriptor
            metadata = real_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and failed_descriptor is None:
                failed_descriptor = descriptor
                raise OSError("injected temporary credential close failure")
            real_close(descriptor)

        try:
            with (
                mock.patch.object(
                    providers.os,
                    "close",
                    side_effect=fail_temporary_close,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "temporary credential close failure",
                ) as raised,
            ):
                providers._replace_claude_macos_recovery_credential(
                    self.review,
                    carrier,
                    refreshed,
                )
        finally:
            if failed_descriptor is not None:
                real_close(failed_descriptor)

        artifact_value = getattr(
            raised.exception,
            "_codex_claude_retained_credential_artifact",
            None,
        )
        self.assertIsInstance(artifact_value, str)
        artifact = pathlib.Path(artifact_value)
        self.assertEqual(artifact.parent, config)
        self.assertTrue(
            artifact.name.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            )
        )
        self.assertEqual(artifact.read_bytes(), refreshed_bytes)
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
        )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_tampered_complete_recovery_temp_is_cleanup_only(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        tampered = bytearray(refreshed)
        tampered[-1] = ord("]")
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_replace = providers.os.replace

        def tamper_temporary_then_fail(
            source: str | os.PathLike[str],
            destination: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> None:
            if isinstance(source, str) and source.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            ):
                (config / source).write_bytes(tampered)
                raise OSError("injected recovery rename failure")
            real_replace(source, destination, *args, **kwargs)

        with (
            mock.patch.object(
                providers.os,
                "replace",
                side_effect=tamper_temporary_then_fail,
            ),
            self.assertRaisesRegex(
                OSError,
                "recovery rename failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        cleanup_value = getattr(
            raised.exception,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        self.assertIsInstance(cleanup_value, str)
        cleanup_artifact = pathlib.Path(cleanup_value)
        self.assertEqual(cleanup_artifact.read_bytes(), bytes(tampered))
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        failure = providers._failed_claude_macos_recovery_error(
            providers.ClaudeCredentialInspectionInconclusive(
                "fixture host writeback failure"
            ),
            raised.exception,
        )
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-cleanup"},
        )
        providers._record_claude_secondary_persistence_failure(
            self.review,
            failure,
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_artifact", report["authentication"])
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(cleanup_artifact),
        )
        for payload in (original, refreshed, tampered):
            payload[:] = b"\x00" * len(payload)

    def test_complete_recovery_temp_disappearing_after_readback_is_unreported(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_read = providers._read_claude_credential_file_from_directory
        real_replace = providers.os.replace

        def fail_temporary_replace(
            source: str | os.PathLike[str],
            destination: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> None:
            if isinstance(source, str) and source.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            ):
                raise OSError("injected recovery rename failure")
            real_replace(source, destination, *args, **kwargs)

        def read_then_remove_temporary(
            config_descriptor: int,
            *,
            credential_name: str = providers.CLAUDE_CREDENTIAL_FILE_NAME,
            expected_identity: tuple[int, ...] | None = None,
        ) -> tuple[bytearray, tuple[int, ...]] | None:
            result = real_read(
                config_descriptor,
                credential_name=credential_name,
                expected_identity=expected_identity,
            )
            if credential_name.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            ):
                os.unlink(credential_name, dir_fd=config_descriptor)
            return result

        with (
            mock.patch.object(
                providers.os,
                "replace",
                side_effect=fail_temporary_replace,
            ),
            mock.patch.object(
                providers,
                "_read_claude_credential_file_from_directory",
                side_effect=read_then_remove_temporary,
            ),
            self.assertRaisesRegex(
                OSError,
                "recovery rename failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
        )
        self.assertEqual(
            sorted(path.name for path in config.iterdir()),
            [providers.CLAUDE_CREDENTIAL_FILE_NAME],
        )
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_uninspectable_complete_recovery_temp_is_cleanup_only(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_close = providers.os.close
        real_fstat = providers.os.fstat
        real_stat = providers.os.stat
        failed_descriptor: int | None = None

        def fail_temporary_close(descriptor: int) -> None:
            nonlocal failed_descriptor
            metadata = real_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and failed_descriptor is None:
                failed_descriptor = descriptor
                raise OSError("injected complete temporary close failure")
            real_close(descriptor)

        def fail_temporary_cleanup_stat(
            path: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            if isinstance(path, str) and path.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            ):
                raise OSError("injected complete temporary stat failure")
            return real_stat(path, *args, **kwargs)

        try:
            with (
                mock.patch.object(
                    providers.os,
                    "close",
                    side_effect=fail_temporary_close,
                ),
                mock.patch.object(
                    providers.os,
                    "stat",
                    side_effect=fail_temporary_cleanup_stat,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "complete temporary close failure",
                ) as raised,
            ):
                providers._replace_claude_macos_recovery_credential(
                    self.review,
                    carrier,
                    refreshed,
                )
        finally:
            if failed_descriptor is not None:
                real_close(failed_descriptor)

        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        cleanup_value = getattr(
            raised.exception,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        self.assertIsInstance(cleanup_value, str)
        cleanup_artifact = pathlib.Path(cleanup_value)
        self.assertTrue(cleanup_artifact.exists())
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        failure = providers._failed_claude_macos_recovery_error(
            providers.ClaudeCredentialInspectionInconclusive(
                "fixture host writeback failure"
            ),
            raised.exception,
        )
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-cleanup"},
        )
        providers._record_claude_secondary_persistence_failure(
            self.review,
            failure,
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_artifact", report["authentication"])
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(cleanup_artifact),
        )
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_incomplete_recovery_temp_unlink_failure_reports_cleanup_artifact(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        original_bytes = bytes(original)
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            original,
        )
        config = carrier / "config"
        real_fsync = providers.os.fsync
        real_unlink = providers.os.unlink

        def fail_temporary_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                raise OSError("injected temporary credential fsync failure")
            real_fsync(descriptor)

        def fail_temporary_unlink(
            name: str,
            *args: object,
            **kwargs: object,
        ) -> None:
            if name.startswith(providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX):
                raise OSError("injected incomplete temp unlink failure")
            real_unlink(name, *args, **kwargs)

        with (
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=fail_temporary_fsync,
            ),
            mock.patch.object(
                providers.os,
                "unlink",
                side_effect=fail_temporary_unlink,
            ),
            self.assertRaisesRegex(
                OSError,
                "temporary credential fsync failure",
            ) as raised,
        ):
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                refreshed,
            )

        artifact_value = getattr(
            raised.exception,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        self.assertIsInstance(artifact_value, str)
        artifact = pathlib.Path(artifact_value)
        self.assertTrue(artifact.exists())
        self.assertEqual(artifact.parent, config)
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        self.assertEqual(
            (config / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            original_bytes,
        )
        notes = getattr(raised.exception, "__notes__", ())
        if notes:
            self.assertIn("non-current or incomplete", "\n".join(notes))
        original[:] = b"\x00" * len(original)
        refreshed[:] = b"\x00" * len(refreshed)

    def test_failed_writeback_retains_latest_staged_rotation(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        first_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        first_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-first-recovery-refresh-value"
        )
        first = bytearray(json.dumps(first_value).encode())
        second_value = json.loads(oauth_credential_fixture(expires_in_seconds=7200))
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-latest-recovery-refresh-value"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_bytes = bytes(second)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            recovery_root = providers._claude_macos_recovery_root(
                self.review
            )
            first_carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(first_carriers), 1)
            self.assertEqual(
                (
                    first_carriers[0]
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                bytes(first),
            )
            first[:] = b"\x00" * len(first)
            self.assertTrue(update_callback(second))
            second_carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(second_carriers), 2)
            self.assertEqual(first_carriers[0], second_carriers[0])
            self.assertEqual(
                (
                    second_carriers[-1]
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                bytes(second),
            )
            second[:] = b"\x00" * len(second)
            yield 43211

        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                return_value=None,
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            second_bytes,
        )
        self.assertEqual(
            list(carrier.parent.glob("claude-carrier-*")),
            [carrier],
        )
        self.assertEqual(first, b"\x00" * len(first))
        self.assertEqual(second, b"\x00" * len(second))
        persist.assert_called_once()

    def test_failed_new_durable_generation_retains_exact_new_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-failed-new-durable-generation-refresh-value"
        )
        second = bytearray(json.dumps(second_value).encode())
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        real_commit = providers._commit_claude_macos_durable_stage
        commit_calls = 0
        first_carrier: pathlib.Path | None = None
        failed_carrier: pathlib.Path | None = None

        def fail_second_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            acknowledged: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            nonlocal commit_calls, failed_carrier
            commit_calls += 1
            if commit_calls == 2:
                failed_carrier = pending
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "injected second durable generation failure"
                )
                setattr(
                    failure,
                    "_codex_claude_retained_credential_carrier",
                    str(pending),
                )
                setattr(
                    failure,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                raise failure
            return real_commit(
                review,
                pending,
                acknowledged,
                credential,
            )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal first_carrier
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            recovery_root = providers._claude_macos_recovery_root(
                self.review
            )
            acknowledged = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(acknowledged), 1)
            first_carrier = acknowledged[0]
            self.assertFalse(update_callback(second))
            assert first_carrier is not None
            self.assertEqual(
                (
                    first_carrier
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                bytes(first),
            )
            yield 43211

        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=fail_second_commit,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "second durable generation failure",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        assert first_carrier is not None
        assert failed_carrier is not None
        self.assertFalse(first_carrier.exists())
        self.assertEqual(
            self.assert_macos_recovery_carrier(
                raised.exception,
                bytes(second),
            ),
            failed_carrier,
        )
        self.assertEqual(
            list(failed_carrier.parent.glob("claude-carrier-*")),
            [failed_carrier],
        )
        self.assertEqual(commit_calls, 2)
        persist.assert_not_called()

    def _assert_failed_verified_then_successful_latest_is_canonical(
        self,
        *,
        invalidate_latest: bool,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        failed_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=3600)
        )
        failed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-earlier-verified-failure-refresh"
        )
        failed = bytearray(json.dumps(failed_value).encode())
        latest_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        latest_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-latest-success-after-verified-failure"
        )
        latest = bytearray(json.dumps(latest_value).encode())
        latest_bytes = bytes(latest)
        malformed = bytearray(b'{"claudeAiOauth":')
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        real_commit = providers._commit_claude_macos_durable_stage
        commit_calls = 0
        failed_carrier: pathlib.Path | None = None
        latest_carrier: pathlib.Path | None = None

        def fail_first_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            acknowledged: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            nonlocal commit_calls, failed_carrier
            commit_calls += 1
            if commit_calls == 1:
                failed_carrier = pending
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "injected verified first-generation failure"
                )
                setattr(
                    failure,
                    "_codex_claude_retained_credential_carrier",
                    str(pending),
                )
                setattr(
                    failure,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                raise failure
            return real_commit(
                review,
                pending,
                acknowledged,
                credential,
            )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal latest_carrier
            assert update_callback is not None
            self.assertFalse(update_callback(failed))
            self.assertTrue(update_callback(latest))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            carriers = sorted(recovery_root.glob("claude-carrier-*"))
            self.assertEqual(len(carriers), 2)
            latest_carrier = next(
                carrier
                for carrier in carriers
                if (
                    carrier
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes()
                == latest_bytes
            )
            if invalidate_latest:
                self.assertFalse(update_callback(malformed))
            failed[:] = b"\x00" * len(failed)
            latest[:] = b"\x00" * len(latest)
            malformed[:] = b"\x00" * len(malformed)
            yield 43211

        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=fail_first_commit,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        assert failed_carrier is not None
        assert latest_carrier is not None
        self.assertFalse(failed_carrier.exists())
        self.assertEqual(
            self.assert_macos_recovery_carrier(
                raised.exception,
                latest_bytes,
            ),
            latest_carrier,
        )
        self.assertEqual(
            sorted(latest_carrier.parent.glob("claude-carrier-*")),
            [latest_carrier],
        )
        self.assertEqual(commit_calls, 2)
        persist.assert_not_called()

    def test_failed_verified_then_successful_latest_survives_direct_final(
        self,
    ) -> None:
        self._assert_failed_verified_then_successful_latest_is_canonical(
            invalidate_latest=False,
        )

    def test_failed_verified_then_successful_latest_survives_malformed_update(
        self,
    ) -> None:
        self._assert_failed_verified_then_successful_latest_is_canonical(
            invalidate_latest=True,
        )

    def test_durable_stage_generation_quota_fails_closed_and_scrubs_staged(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        update_values: list[bytearray] = []
        for generation in range(1, 4):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-durable-quota-refresh-{generation}"
            )
            update_values.append(bytearray(json.dumps(value).encode()))
        first, second, third = update_values
        second_bytes = bytes(second)
        third_bytes = bytes(third)
        generation_cap = 3
        byte_cap = (
            len(first)
            + len(second)
            + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        tracked_bytearrays: list[bytearray] = []
        publication_calls = 0
        terminal_claim_calls = 0
        real_bytearray = bytearray

        def tracked_bytearray(
            source: object = b"",
            *args: object,
            **kwargs: object,
        ) -> bytearray:
            result = real_bytearray(source, *args, **kwargs)
            tracked_bytearrays.append(result)
            return result

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal publication_calls, terminal_claim_calls
            assert update_callback is not None

            def commit_pending(publish: Callable[[], bool]) -> bool:
                nonlocal publication_calls
                publication_calls += 1
                return publish()

            def claim_terminal() -> bool:
                nonlocal terminal_claim_calls
                terminal_claim_calls += 1
                return True

            self.assertTrue(
                update_callback(first, commit_pending, claim_terminal)
            )
            self.assertTrue(
                update_callback(second, commit_pending, claim_terminal)
            )
            recovery_root = providers._claude_macos_recovery_root(self.review)
            carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(carriers), 2)
            self.assertEqual(
                (
                    carriers[0]
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                bytes(first),
            )
            self.assertEqual(
                (
                    carriers[1]
                    / "config"
                    / providers.CLAUDE_CREDENTIAL_FILE_NAME
                ).read_bytes(),
                second_bytes,
            )
            staged_copies = [
                candidate
                for candidate in tracked_bytearrays
                if candidate == second_bytes
            ]
            self.assertEqual(len(staged_copies), 1)
            self.assertFalse(
                update_callback(third, commit_pending, claim_terminal)
            )
            self.assertEqual(
                staged_copies[0],
                b"\x00" * len(second_bytes),
            )
            carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(carriers), 3)
            self.assertLessEqual(len(carriers), generation_cap)
            self.assertLessEqual(
                sum(
                    (
                        carrier
                        / "config"
                        / providers.CLAUDE_CREDENTIAL_FILE_NAME
                    ).stat().st_size
                    for carrier in carriers
                ),
                byte_cap,
            )
            self.assertIn(
                third_bytes,
                [
                    (
                        carrier
                        / "config"
                        / providers.CLAUDE_CREDENTIAL_FILE_NAME
                    ).read_bytes()
                    for carrier in carriers
                ],
            )
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                generation_cap,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                byte_cap,
            ),
            mock.patch.object(
                providers,
                "bytearray",
                side_effect=tracked_bytearray,
                create=True,
            ),
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
                wraps=providers._retain_claude_macos_refreshed_credential,
            ) as retain,
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                wraps=providers._commit_claude_macos_durable_stage,
            ) as commit,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable-stage journal is full",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual((retain.call_count, commit.call_count), (3, 3))
        self.assertEqual(publication_calls, 2)
        self.assertEqual(terminal_claim_calls, 1)
        persist.assert_not_called()
        self.assert_macos_recovery_carrier(raised.exception, third_bytes)

    def test_quota_proof_capture_does_not_hold_runtime_state_lock(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=3600)
        )
        first_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-lock-free-proof-first"
        )
        first = bytearray(json.dumps(first_value).encode())
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-lock-free-proof-second"
        )
        second = bytearray(json.dumps(second_value).encode())
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        capture_started = threading.Event()
        release_capture = threading.Event()
        update_results: list[bool] = []
        update_errors: list[BaseException] = []
        update_thread: threading.Thread | None = None
        captured: dict[str, BaseException] = {}
        real_capture = providers._capture_claude_retained_credential_proof

        def blocking_quota_capture(
            artifact: pathlib.Path,
            *,
            expected_digest: bytes,
        ) -> providers._ClaudeRetainedCredentialProof:
            if threading.current_thread() is update_thread:
                capture_started.set()
                if not release_capture.wait(timeout=2.0):
                    raise RuntimeError("fixture proof capture was not released")
            return real_capture(
                artifact,
                expected_digest=expected_digest,
            )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal update_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))
            recovery_root = providers._claude_macos_recovery_root(self.review)

            def reject_second() -> None:
                try:
                    update_results.append(update_callback(second))
                except BaseException as error:
                    update_errors.append(error)

            update_thread = threading.Thread(target=reject_second)
            update_thread.start()
            self.assertTrue(capture_started.wait(timeout=2.0))
            quiescence_callbacks.abandon()
            timeout_error = quiescence_callbacks.timeout_error()
            timeout_proof = providers._get_claude_retained_credential_proof(
                timeout_error
            )
            self.assertIsNone(timeout_proof)
            self.assertIsNone(
                getattr(
                    timeout_error,
                    "_codex_claude_retained_credential_carrier",
                    None,
                )
            )
            self.assertEqual(
                getattr(
                    timeout_error,
                    "_codex_claude_retained_cleanup_artifact",
                    None,
                ),
                str(recovery_root),
            )
            captured["timeout"] = timeout_error
            release_capture.set()
            update_thread.join(timeout=2.0)
            self.assertFalse(update_thread.is_alive())
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers,
                    "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                    2,
                ),
                mock.patch.object(
                    providers,
                    "_capture_claude_retained_credential_proof",
                    side_effect=blocking_quota_capture,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_capture.set()
            if update_thread is not None:
                update_thread.join(timeout=2.0)

        self.assertIs(raised.exception, captured["timeout"])
        self.assertEqual(update_results, [False])
        self.assertEqual(update_errors, [])
        persist.assert_not_called()
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_generation_quota_cleanup_keeps_only_reported_latest_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates: list[bytearray] = []
        for generation in range(1, 5):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-quota-cleanup-refresh-{generation}"
            )
            updates.append(bytearray(json.dumps(value).encode()))
        latest_bytes = bytes(updates[3])
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        complete_carriers: list[pathlib.Path] = []

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            for update in updates[:3]:
                self.assertTrue(update_callback(update))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            complete_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(complete_carriers), 3)
            self.assertFalse(update_callback(updates[3]))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                4,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                sum(len(update) for update in updates[:3])
                + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable-stage journal is full",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        self.assertEqual(len(complete_carriers), 3)
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertNotIn(latest_carrier, complete_carriers)
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(list(recovery_root.iterdir()), [latest_carrier])
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(latest_carrier),
        )
        self.assertEqual(
            report["authentication"]["recovery_artifact"],
            str(
                latest_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        self.assertNotIn(
            "recovery_cleanup_artifact",
            report["authentication"],
        )

    def test_generation_cleanup_preserves_all_when_current_proof_fails(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates: list[bytearray] = []
        for generation in range(1, 5):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-proof-failure-refresh-{generation}"
            )
            updates.append(bytearray(json.dumps(value).encode()))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        complete_carriers: list[pathlib.Path] = []
        fail_capture = False
        real_capture = providers._capture_claude_retained_credential_proof

        def fail_current_proof_capture(
            artifact: pathlib.Path,
            *,
            expected_digest: bytes,
        ) -> providers._ClaudeRetainedCredentialProof:
            if fail_capture and complete_carriers and artifact == (
                complete_carriers[-1]
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ):
                raise OSError("injected current proof capture failure")
            return real_capture(
                artifact,
                expected_digest=expected_digest,
            )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal fail_capture
            assert update_callback is not None
            for update in updates[:3]:
                self.assertTrue(update_callback(update))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            complete_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(complete_carriers), 3)
            self.assertFalse(update_callback(updates[3]))
            all_carriers = sorted(
                recovery_root.glob(
                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                )
            )
            self.assertEqual(len(all_carriers), 4)
            terminal_carrier = next(
                carrier
                for carrier in all_carriers
                if carrier not in complete_carriers
            )
            complete_carriers.append(terminal_carrier)
            latest_artifact = (
                terminal_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            )
            replacement = latest_artifact.with_name("replacement.json")
            replacement.write_bytes(updates[3])
            replacement.chmod(0o600)
            os.replace(replacement, latest_artifact)
            fail_capture = True
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                4,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                sum(len(update) for update in updates[:3])
                + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            ),
            mock.patch.object(
                providers,
                "_capture_claude_retained_credential_proof",
                side_effect=fail_current_proof_capture,
            ),
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
                wraps=providers._remove_claude_macos_recovery_carrier,
            ) as remove,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable-stage journal is full",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        remove.assert_not_called()
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            complete_carriers,
        )
        self.assertIsNone(
            providers._validated_claude_retained_credential_artifact(
                self.review,
                raised.exception,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        for update in updates:
            update[:] = b"\x00" * len(update)

    def test_generation_quota_cleanup_failure_reports_latest_and_stale(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates: list[bytearray] = []
        for generation in range(1, 5):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-quota-cleanup-failure-{generation}"
            )
            updates.append(bytearray(json.dumps(value).encode()))
        latest_bytes = bytes(updates[3])
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        complete_carriers: list[pathlib.Path] = []
        cleanup_attempts: list[pathlib.Path] = []
        real_remove = providers._remove_claude_macos_recovery_carrier

        def fail_oldest_cleanup(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            credential_digest: bytes,
        ) -> None:
            cleanup_attempts.append(carrier)
            if complete_carriers and carrier == complete_carriers[0]:
                raise OSError("injected oldest durable carrier cleanup failure")
            real_remove(review, carrier, credential_digest)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            for update in updates[:3]:
                self.assertTrue(update_callback(update))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            complete_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(complete_carriers), 3)
            self.assertFalse(update_callback(updates[3]))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                4,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                sum(len(update) for update in updates[:3])
                + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            ),
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
                side_effect=fail_oldest_cleanup,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable-stage journal is full",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        self.assertEqual(len(complete_carriers), 3)
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertNotIn(latest_carrier, complete_carriers)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(complete_carriers[0]),
        )
        self.assertEqual(
            cleanup_attempts,
            complete_carriers,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.iterdir()),
            [complete_carriers[0], latest_carrier],
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(latest_carrier),
        )
        self.assertEqual(
            report["authentication"]["recovery_artifact"],
            str(
                latest_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(complete_carriers[0]),
        )

    def test_non_staged_cleanup_control_flow_reports_remaining_scope(
        self,
    ) -> None:
        interruptions = (
            ("forwarded-signal", providers.ForwardedSignal(signal.SIGTERM)),
            ("keyboard-interrupt", KeyboardInterrupt("fixture interrupt")),
            ("system-exit", SystemExit(23)),
        )

        for label, interruption in interruptions:
            with self.subTest(interruption=label):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                updates: list[bytearray] = []
                for generation in range(1, 5):
                    value = json.loads(
                        oauth_credential_fixture(
                            expires_in_seconds=3600 * generation
                        )
                    )
                    value["claudeAiOauth"]["refreshToken"] = (
                        f"fixture-non-staged-control-flow-{label}-{generation}"
                    )
                    updates.append(bytearray(json.dumps(value).encode()))
                latest_bytes = bytes(updates[3])
                selected = providers._ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=original,
                    expires_at_ms=0,
                    carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                        keychain_digest=(
                            providers._claude_credential_digest(original)
                        ),
                        file_digest=None,
                        file_snapshot=None,
                    ),
                )
                staged_carriers: list[pathlib.Path] = []

                @contextlib.contextmanager
                def broker(
                    _credential,
                    _capability,
                    *,
                    update_callback=None,
                    **_kwargs,
                ):
                    assert update_callback is not None
                    recovery_root = providers._claude_macos_recovery_root(
                        self.review
                    )
                    before = set(recovery_root.glob("claude-carrier-*"))
                    for update in updates[:3]:
                        self.assertTrue(update_callback(update))
                    self.assertFalse(update_callback(updates[3]))
                    staged_carriers.extend(
                        sorted(
                            set(recovery_root.glob("claude-carrier-*"))
                            - before
                        )
                    )
                    self.assertEqual(len(staged_carriers), 4)
                    for update in updates:
                        update[:] = b"\x00" * len(update)
                    yield 43211

                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {"authentication": {}, "phase": "runtime-launching"},
                )
                with (
                    mock.patch.object(
                        providers,
                        "_select_claude_macos_credential",
                        return_value=selected,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_keychain_credential_server",
                        side_effect=broker,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                        4,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                        sum(len(update) for update in updates[:3])
                        + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
                    ),
                    mock.patch.object(
                        providers,
                        "_remove_claude_macos_recovery_carrier",
                        side_effect=interruption,
                    ) as remove,
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                    ) as persist,
                    self.assertRaises(type(interruption)) as raised,
                ):
                    with self.claude_keychain_runtime(
                        self.review,
                        {},
                        self.claude_refresh_lock_protocol,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                self.assertEqual(remove.call_count, 1)
                self.assertEqual(remove.call_args.args[1], staged_carriers[0])
                self.assertTrue(staged_carriers[1].is_dir())
                self.assertTrue(staged_carriers[2].is_dir())
                self.assertTrue(staged_carriers[3].is_dir())
                persist.assert_not_called()
                recovery_root = providers._claude_macos_recovery_root(
                    self.review
                )
                self.assertEqual(
                    getattr(
                        raised.exception,
                        "_codex_claude_retained_cleanup_artifact",
                        None,
                    ),
                    str(recovery_root),
                )
                latest_carrier = self.assert_macos_recovery_carrier(
                    raised.exception,
                    latest_bytes,
                )
                self.assertEqual(latest_carrier, staged_carriers[-1])
                report = common.read_json(
                    self.review.container_dir / "claude-runtime.json"
                )
                self.assertEqual(
                    report["authentication"]["recovery_carrier"],
                    str(latest_carrier),
                )
                self.assertEqual(
                    report["authentication"]["recovery_cleanup_artifact"],
                    str(recovery_root),
                )

    def test_failed_durable_stages_consume_generation_reservations(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates = [
            bytearray(oauth_credential_fixture(expires_in_seconds=3600 + index))
            for index in range(3)
        ]
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            for update in updates:
                self.assertFalse(update_callback(update))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                2,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                sum(len(value) for value in updates)
                + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            ),
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
                side_effect=(
                    OSError("injected first durable stage failure"),
                    OSError("injected second durable stage failure"),
                ),
            ) as retain,
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
            ) as commit,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "credential runtime I/O",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(retain.call_count, 2)
        commit.assert_not_called()
        persist.assert_not_called()
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertIn(
            "first durable stage failure",
            str(raised.exception.__cause__),
        )
        for attribute in (
            "_codex_claude_retained_credential_carrier",
            "_codex_claude_retained_credential_artifact",
            "_codex_claude_retained_cleanup_artifact",
        ):
            self.assertIsNone(getattr(raised.exception, attribute, None))
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_artifact", report["authentication"])
        self.assertNotIn("recovery_cleanup_artifact", report["authentication"])

    def test_first_durable_stage_root_setup_failure_has_no_fake_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates = [
            bytearray(oauth_credential_fixture(expires_in_seconds=3600 + index))
            for index in range(2)
        ]
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        setup_error = OSError("injected first durable root setup failure")
        callback_results: list[bool] = []

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            callback_results.extend(
                update_callback(update) for update in updates
            )
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                1,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                sum(len(update) for update in updates),
            ),
            mock.patch.object(
                providers,
                "_claude_macos_recovery_root",
                side_effect=setup_error,
            ) as recovery_root,
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
            ) as retain,
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
            ) as commit,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "fail-closed recovery scope could not be initialized",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(callback_results, [])
        self.assertEqual(recovery_root.call_count, 1)
        retain.assert_not_called()
        commit.assert_not_called()
        persist.assert_not_called()
        self.assert_cleanup_diagnostic_preserves_original_cause(
            raised.exception,
            setup_error,
        )
        for attribute in (
            "_codex_claude_retained_credential_carrier",
            "_codex_claude_retained_credential_artifact",
            "_codex_claude_retained_cleanup_artifact",
        ):
            self.assertIsNone(getattr(raised.exception, attribute, None))
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])

    def test_later_durable_stage_root_setup_failure_reports_prior_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        later = [
            bytearray(oauth_credential_fixture(expires_in_seconds=7200 + index))
            for index in range(2)
        ]
        first_bytes = bytes(first)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        real_recovery_root = providers._claude_macos_recovery_root
        setup_error = OSError("injected later durable root setup failure")
        root_calls = 0
        root_failures = 0
        fail_stage_root = False
        callback_results: list[bool] = []

        def fail_second_root(
            review: providers.ReviewWorkspace,
        ) -> pathlib.Path:
            nonlocal root_calls
            nonlocal root_failures
            nonlocal fail_stage_root
            root_calls += 1
            if fail_stage_root:
                fail_stage_root = False
                root_failures += 1
                raise setup_error
            return real_recovery_root(review)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal fail_stage_root
            assert update_callback is not None
            callback_results.append(update_callback(first))
            fail_stage_root = True
            callback_results.append(update_callback(later[0]))
            roots_after_failure = root_calls
            callback_results.append(update_callback(later[1]))
            self.assertEqual(root_calls, roots_after_failure)
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                2,
            ),
            mock.patch.object(
                providers,
                "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                len(first)
                + sum(len(update) for update in later)
                + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            ),
            mock.patch.object(
                providers,
                "_claude_macos_recovery_root",
                side_effect=fail_second_root,
            ),
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
                wraps=providers._retain_claude_macos_refreshed_credential,
            ) as retain,
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                wraps=providers._commit_claude_macos_durable_stage,
            ) as commit,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "durable recovery stage could not be initialized",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(callback_results, [True, False, False])
        self.assertEqual(root_failures, 1)
        self.assertEqual((retain.call_count, commit.call_count), (1, 1))
        persist.assert_not_called()
        self.assert_cleanup_diagnostic_preserves_original_cause(
            raised.exception,
            setup_error,
        )
        self.assert_macos_recovery_carrier(raised.exception, first_bytes)

    def test_post_commit_registration_failure_retains_current_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        registration_error = RuntimeError(
            "injected post-commit state registration failure"
        )
        callback_results: list[bool] = []
        real_lock_factory = threading.Lock
        real_commit = providers._commit_claude_macos_durable_stage

        class OneShotRegistrationLock:
            def __init__(self) -> None:
                self.lock = real_lock_factory()
                self.fail_next_entry = False

            def __enter__(self) -> OneShotRegistrationLock:
                if self.fail_next_entry:
                    self.fail_next_entry = False
                    raise registration_error
                self.lock.acquire()
                return self

            def __exit__(
                self,
                _exception_type: object,
                _exception: object,
                _traceback: object,
            ) -> None:
                self.lock.release()

        runtime_lock = OneShotRegistrationLock()
        lock_calls = 0

        def lock_factory() -> object:
            nonlocal lock_calls
            lock_calls += 1
            if lock_calls == 1:
                return runtime_lock
            return real_lock_factory()

        def arm_failure_after_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            result = real_commit(review, pending, committed, credential)
            runtime_lock.fail_next_entry = True
            return result

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            callback_results.append(update_callback(refreshed))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers.threading,
                "Lock",
                side_effect=lock_factory,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=arm_failure_after_commit,
            ) as commit,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                RuntimeError,
                "post-commit state registration failure",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, registration_error)
        self.assertEqual(callback_results, [False])
        commit.assert_called_once()
        persist.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )

    def test_durable_stage_fullsyncs_container_ancestors_before_publication(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(refreshed),
            file_digest=None,
            file_snapshot=None,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        required_identities = {
            (
                self.review.source_root.stat().st_dev,
                self.review.source_root.stat().st_ino,
            ),
            (
                self.review.container_dir.parent.stat().st_dev,
                self.review.container_dir.parent.stat().st_ino,
            ),
            (
                self.review.container_dir.stat().st_dev,
                self.review.container_dir.stat().st_ino,
            ),
            (
                (self.review.container_dir / "claude-runtime").stat().st_dev,
                (self.review.container_dir / "claude-runtime").stat().st_ino,
            ),
            (
                recovery_root.stat().st_dev,
                recovery_root.stat().st_ino,
            ),
        }
        synchronized_directories: set[tuple[int, int]] = set()
        full_synced_directories: set[tuple[int, int]] = set()
        full_synced_regular_files = 0
        callback_results: list[bool] = []
        publication_checks = 0
        real_fsync = providers.os.fsync

        def track_fsync(descriptor: int) -> None:
            metadata = providers.os.fstat(descriptor)
            if stat.S_ISDIR(metadata.st_mode):
                synchronized_directories.add(
                    (metadata.st_dev, metadata.st_ino)
                )
            real_fsync(descriptor)

        def track_fullfsync(descriptor: int, command: int) -> int:
            nonlocal full_synced_regular_files
            self.assertEqual(command, 51)
            metadata = providers.os.fstat(descriptor)
            if stat.S_ISDIR(metadata.st_mode):
                full_synced_directories.add(
                    (metadata.st_dev, metadata.st_ino)
                )
            elif stat.S_ISREG(metadata.st_mode):
                full_synced_regular_files += 1
            return 0

        darwin_fcntl = mock.Mock()
        darwin_fcntl.F_FULLFSYNC = 51
        darwin_fcntl.fcntl.side_effect = track_fullfsync

        def commit_pending(publish: Callable[[], bool]) -> bool:
            nonlocal publication_checks
            publication_checks += 1
            self.assertTrue(
                required_identities.issubset(synchronized_directories)
            )
            self.assertTrue(
                required_identities.issubset(full_synced_directories)
            )
            self.assertGreaterEqual(full_synced_regular_files, 1)
            return publish()

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            **_kwargs: object,
        ):
            assert update_callback is not None
            callback_results.append(
                update_callback(refreshed, commit_pending)
            )
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers.os,
                "fsync",
                side_effect=track_fsync,
            ),
            mock.patch.object(
                providers.sys,
                "platform",
                "darwin",
            ),
            mock.patch.object(
                providers.importlib,
                "import_module",
                return_value=darwin_fcntl,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                return_value=updated_snapshot,
            ) as persist,
            mock.patch.object(
                providers,
                "_claude_macos_carrier_snapshot_is_current",
                return_value=True,
            ),
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(callback_results, [True])
        self.assertEqual(publication_checks, 1)
        persist.assert_called_once()
        refreshed[:] = b"\x00" * len(refreshed)

    def test_durable_stage_commit_fullsyncs_after_rename(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        recovery_root = providers._claude_macos_recovery_root(self.review)
        recovery_metadata = recovery_root.stat()
        recovery_identity = (
            recovery_metadata.st_dev,
            recovery_metadata.st_ino,
        )

        for failure_kind in (
            "success",
            "fullsync-failure",
            "post-rename-stat-failure",
        ):
            with self.subTest(failure_kind=failure_kind):
                pending = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
                    + failure_kind
                )
                committed = recovery_root / (
                    providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
                    + failure_kind
                )
                providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    credential,
                    requested_carrier_root=pending,
                    credential_prevalidated=True,
                    durable_directories=True,
                )
                events: list[str] = []
                real_rename = providers.os.rename
                real_stat = providers.os.stat
                post_rename_stat_failed = False

                def track_rename(*args: object, **kwargs: object) -> None:
                    events.append("rename")
                    real_rename(*args, **kwargs)

                def fullsync(descriptor: int, command: int) -> int:
                    self.assertEqual(command, 51)
                    metadata = providers.os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) == recovery_identity:
                        events.append("fullsync")
                        if failure_kind == "fullsync-failure":
                            raise OSError("injected recovery root F_FULLFSYNC failure")
                    return 0

                def fail_once_after_rename(
                    path: object,
                    *args: object,
                    **kwargs: object,
                ) -> os.stat_result:
                    nonlocal post_rename_stat_failed
                    if (
                        failure_kind == "post-rename-stat-failure"
                        and events
                        and events[0] == "rename"
                        and path == committed.name
                        and not post_rename_stat_failed
                    ):
                        post_rename_stat_failed = True
                        raise OSError("injected post-rename stat failure")
                    return real_stat(path, *args, **kwargs)

                darwin_fcntl = mock.Mock()
                darwin_fcntl.F_FULLFSYNC = 51
                darwin_fcntl.fcntl.side_effect = fullsync
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch.object(
                            providers.sys,
                            "platform",
                            "darwin",
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            providers.importlib,
                            "import_module",
                            return_value=darwin_fcntl,
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            providers.os,
                            "rename",
                            side_effect=track_rename,
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            providers.os,
                            "stat",
                            side_effect=fail_once_after_rename,
                        )
                    )
                    raised = None
                    if failure_kind != "success":
                        raised = stack.enter_context(
                            self.assertRaisesRegex(
                                OSError,
                                (
                                    "F_FULLFSYNC failure"
                                    if failure_kind == "fullsync-failure"
                                    else "post-rename stat failure"
                                ),
                            )
                        )
                    result = providers._commit_claude_macos_durable_stage(
                        self.review,
                        pending,
                        committed,
                        credential,
                    )
                self.assertEqual(events[:2], ["rename", "fullsync"])
                if failure_kind == "success":
                    self.assertEqual(result, committed)
                else:
                    assert raised is not None
                    self.assertEqual(
                        self.assert_macos_recovery_carrier(
                            raised.exception,
                            bytes(credential),
                        ),
                        committed,
                    )

        credential[:] = b"\x00" * len(credential)

    def test_durable_stage_fullsync_failure_nacks_before_publication(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        recovery_metadata = recovery_root.stat()
        recovery_identity = (
            recovery_metadata.st_dev,
            recovery_metadata.st_ino,
        )
        recovery_fullsyncs = 0
        callback_results: list[bool] = []
        publication_calls = 0

        def fail_commit_fullsync(descriptor: int, command: int) -> int:
            nonlocal recovery_fullsyncs
            self.assertEqual(command, 51)
            metadata = providers.os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == recovery_identity:
                recovery_fullsyncs += 1
                if recovery_fullsyncs == 2:
                    raise OSError("injected recovery root F_FULLFSYNC failure")
            return 0

        def commit_pending(_publish: Callable[[], bool]) -> bool:
            nonlocal publication_calls
            publication_calls += 1
            return True

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            **_kwargs: object,
        ):
            assert update_callback is not None
            callback_results.append(update_callback(refreshed, commit_pending))
            yield 43211

        darwin_fcntl = mock.Mock()
        darwin_fcntl.F_FULLFSYNC = 51
        darwin_fcntl.fcntl.side_effect = fail_commit_fullsync
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers.sys,
                "platform",
                "darwin",
            ),
            mock.patch.object(
                providers.importlib,
                "import_module",
                return_value=darwin_fcntl,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "runtime I/O was inconclusive",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(callback_results, [False])
        self.assertEqual(publication_calls, 0)
        self.assertGreaterEqual(recovery_fullsyncs, 2)
        persist.assert_not_called()
        retained = self.assert_macos_recovery_carrier(
            raised.exception,
            bytes(refreshed),
        )
        self.assertTrue(
            retained.name.startswith(
                providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
            )
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_durable_stage_rejects_swapped_or_looping_workspace_ancestor(
        self,
    ) -> None:
        for failure_kind in ("swapped", "loop"):
            with self.subTest(failure_kind=failure_kind):
                fixture_root = (
                    self.review.source_root.parent
                    / f"durable-ancestor-{failure_kind}"
                )
                lexical_parent = fixture_root / "workspace-anchor"
                lexical_source = lexical_parent / "source"
                lexical_container = (
                    lexical_source
                    / ".codex-tmp"
                    / "isolated-review-symlink-fixture"
                )
                fixture_root.mkdir(mode=0o700)
                if failure_kind == "swapped":
                    lexical_container.mkdir(mode=0o700, parents=True)
                    original_parent = fixture_root / "workspace-anchor-original"
                    lexical_parent.rename(original_parent)
                    alternate_parent = fixture_root / "alternate-anchor"
                    alternate_container = (
                        alternate_parent
                        / "source"
                        / ".codex-tmp"
                        / "isolated-review-symlink-fixture"
                    )
                    alternate_container.mkdir(mode=0o700, parents=True)
                    lexical_parent.symlink_to(
                        alternate_parent,
                        target_is_directory=True,
                    )
                else:
                    lexical_parent.symlink_to(
                        lexical_parent,
                        target_is_directory=True,
                    )
                    alternate_container = None
                review = ReviewWorkspace(
                    source_root=lexical_source,
                    container_dir=lexical_container,
                    workspace_root=lexical_container / "workspace",
                    base_ref="a" * 40,
                    head_ref="b" * 40,
                    diff_file=lexical_container / "review.diff",
                    prompt_file=lexical_container / "review.prompt",
                )
                credential = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )

                with self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ):
                    providers._retain_claude_macos_refreshed_credential(
                        review,
                        credential,
                        durable_directories=True,
                    )

                if alternate_container is not None:
                    self.assertFalse(
                        (alternate_container / "claude-runtime").exists()
                    )
                credential[:] = b"\x00" * len(credential)

    def test_durable_ancestor_fsync_failure_nacks_before_publication(
        self,
    ) -> None:
        required_paths = (
            self.review.source_root,
            self.review.container_dir.parent,
            self.review.container_dir,
            self.review.container_dir / "claude-runtime",
        )
        for failed_path in required_paths:
            with self.subTest(path=failed_path.name):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                refreshed = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                selected = providers._ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=original,
                    expires_at_ms=0,
                    carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                        keychain_digest=providers._claude_credential_digest(
                            original
                        ),
                        file_digest=None,
                        file_snapshot=None,
                    ),
                )
                failed_metadata = failed_path.stat()
                failed_identity = (
                    failed_metadata.st_dev,
                    failed_metadata.st_ino,
                )
                callback_results: list[bool] = []
                publication_calls = 0
                real_fsync = providers.os.fsync

                def fail_ancestor_fsync(descriptor: int) -> None:
                    metadata = providers.os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) == failed_identity:
                        raise OSError("injected ancestor fsync failure")
                    real_fsync(descriptor)

                def commit_pending(_publish: Callable[[], bool]) -> bool:
                    nonlocal publication_calls
                    publication_calls += 1
                    return True

                @contextlib.contextmanager
                def broker(
                    _credential: bytearray,
                    _capability: bytes,
                    *,
                    update_callback: Callable[..., bool] | None = None,
                    **_kwargs: object,
                ):
                    assert update_callback is not None
                    callback_results.append(
                        update_callback(refreshed, commit_pending)
                    )
                    yield 43211

                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {"authentication": {}, "phase": "runtime-launching"},
                )
                with (
                    mock.patch.object(
                        providers,
                        "_select_claude_macos_credential",
                        return_value=selected,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_keychain_credential_server",
                        side_effect=broker,
                    ),
                    mock.patch.object(
                        providers.os,
                        "fsync",
                        side_effect=fail_ancestor_fsync,
                    ),
                    mock.patch.object(
                        providers,
                        "_commit_claude_macos_durable_stage",
                    ) as commit,
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                    ) as persist,
                    self.assertRaisesRegex(
                        providers.ClaudeCredentialInspectionInconclusive,
                        "durably synchronize",
                    ),
                ):
                    with self.claude_keychain_runtime(
                        self.review,
                        {},
                        self.claude_refresh_lock_protocol,
                    ):
                        pass

                self.assertEqual(callback_results, [False])
                self.assertEqual(publication_calls, 0)
                commit.assert_not_called()
                persist.assert_not_called()
                refreshed[:] = b"\x00" * len(refreshed)

    def test_durable_stage_byte_quota_exact_boundary_and_plus_one(
        self,
    ) -> None:
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        refreshed_bytes = bytes(refreshed)

        for label, byte_limit, accepted in (
            (
                "exact",
                providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
                + len(refreshed_bytes),
                True,
            ),
            (
                "plus-one",
                providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
                + len(refreshed_bytes)
                - 1,
                False,
            ),
        ):
            with self.subTest(label=label):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                selected = providers._ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=original,
                    expires_at_ms=0,
                    carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                        keychain_digest=providers._claude_credential_digest(
                            original
                        ),
                        file_digest=None,
                        file_snapshot=None,
                    ),
                )
                callback_results: list[bool] = []

                @contextlib.contextmanager
                def broker(
                    _credential,
                    _capability,
                    *,
                    update_callback=None,
                    **_kwargs,
                ):
                    assert update_callback is not None
                    callback_results.append(update_callback(refreshed))
                    yield 43211

                updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=providers._claude_credential_digest(
                        refreshed
                    ),
                    file_digest=None,
                    file_snapshot=None,
                )
                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {"authentication": {}, "phase": "runtime-launching"},
                )
                with (
                    mock.patch.object(
                        providers,
                        "_select_claude_macos_credential",
                        return_value=selected,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_keychain_credential_server",
                        side_effect=broker,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                        2,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                        byte_limit,
                    ),
                    mock.patch.object(
                        providers,
                        "_retain_claude_macos_refreshed_credential",
                        wraps=(
                            providers._retain_claude_macos_refreshed_credential
                        ),
                    ) as retain,
                    mock.patch.object(
                        providers,
                        "_commit_claude_macos_durable_stage",
                        wraps=providers._commit_claude_macos_durable_stage,
                    ) as commit,
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                        return_value=updated_snapshot,
                    ) as persist,
                    mock.patch.object(
                        providers,
                        "_claude_macos_carrier_snapshot_is_current",
                        return_value=True,
                    ),
                ):
                    if accepted:
                        with self.claude_keychain_runtime(
                            self.review,
                            {},
                            self.claude_refresh_lock_protocol,
                        ):
                            pass
                    else:
                        with self.assertRaisesRegex(
                            providers.ClaudeCredentialInspectionInconclusive,
                            "durable-stage journal is full",
                        ) as raised:
                            with self.claude_keychain_runtime(
                                self.review,
                                {},
                                self.claude_refresh_lock_protocol,
                            ):
                                pass

                self.assertEqual(callback_results, [accepted])
                if accepted:
                    self.assertEqual((retain.call_count, commit.call_count), (1, 1))
                    persist.assert_called_once()
                else:
                    self.assertEqual((retain.call_count, commit.call_count), (1, 1))
                    persist.assert_not_called()
                    terminal_carrier = self.assert_macos_recovery_carrier(
                        raised.exception,
                        refreshed_bytes,
                    )
                    report = common.read_json(
                        self.review.container_dir / "claude-runtime.json"
                    )
                    self.assertEqual(
                        report["authentication"]["recovery_carrier"],
                        str(terminal_carrier),
                    )
                    self.assertEqual(
                        report["authentication"]["recovery_artifact"],
                        str(
                            terminal_carrier
                            / "config"
                            / providers.CLAUDE_CREDENTIAL_FILE_NAME
                        ),
                    )

    def test_later_rotation_repairs_incomplete_recovery_carrier(self) -> None:
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(oauth_credential_fixture(expires_in_seconds=7200))
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-repaired-recovery-refresh-value"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_bytes = bytes(second)
        real_write = providers._write_all_to_descriptor
        write_calls = 0

        def fail_first_recovery_write(
            descriptor: int,
            payload: bytearray,
        ) -> None:
            nonlocal write_calls
            write_calls += 1
            if write_calls == 1:
                raise OSError("injected initial recovery write failure")
            real_write(descriptor, payload)

        with mock.patch.object(
            providers,
            "_write_all_to_descriptor",
            side_effect=fail_first_recovery_write,
        ):
            with self.assertRaises(OSError) as raised:
                providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    first,
                )
            retained = getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
            self.assertIsInstance(retained, str)
            self.assertIsNone(
                getattr(
                    raised.exception,
                    "_codex_claude_retained_credential_carrier",
                    None,
                )
            )
            carrier = pathlib.Path(retained)
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                second,
            )

        recovery_error = providers._retained_claude_macos_credential_error(
            carrier,
            raised.exception,
            expected_digest=providers._claude_credential_digest(second),
        )
        self.assert_macos_recovery_carrier(recovery_error, second_bytes)
        self.assertEqual(
            list(carrier.parent.glob("claude-carrier-*")),
            [carrier],
        )
        self.assertEqual(write_calls, 2)
        self.assertEqual(
            sorted(path.name for path in (carrier / "config").iterdir()),
            [providers.CLAUDE_CREDENTIAL_FILE_NAME],
        )
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_later_rotation_cleans_retained_recovery_update_artifact(
        self,
    ) -> None:
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        third_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=10800)
        )
        third_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-latest-cleanup-refresh-value"
        )
        third = bytearray(json.dumps(third_value).encode())
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            first,
        )
        real_replace = providers.os.replace
        real_unlink = providers.os.unlink
        replace_calls = 0

        def fail_first_replace(*args: object, **kwargs: object) -> None:
            nonlocal replace_calls
            is_recovery_update = (
                len(args) >= 2
                and isinstance(args[0], str)
                and args[0].startswith(
                    providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
                )
                and args[1] == providers.CLAUDE_CREDENTIAL_FILE_NAME
            )
            if is_recovery_update:
                replace_calls += 1
                if replace_calls == 1:
                    raise OSError("injected recovery replace failure")
            real_replace(*args, **kwargs)

        def fail_stale_cleanup(
            name: str,
            *args: object,
            **kwargs: object,
        ) -> None:
            if name == artifact.name:
                raise OSError("injected stale recovery cleanup failure")
            real_unlink(name, *args, **kwargs)

        with mock.patch.object(
            providers.os,
            "replace",
            side_effect=fail_first_replace,
        ):
            with self.assertRaises(OSError) as raised:
                providers._replace_claude_macos_recovery_credential(
                    self.review,
                    carrier,
                    second,
                )
            artifact_value = getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
            self.assertIsInstance(artifact_value, str)
            artifact = pathlib.Path(artifact_value)
            self.assertEqual(artifact.read_bytes(), bytes(second))
            failure = providers._failed_claude_macos_recovery_error(
                providers.ClaudeCredentialInspectionInconclusive(
                    "fixture host writeback failure"
                ),
                raised.exception,
            )
            common.write_json(
                self.review.container_dir / "claude-runtime.json",
                {"authentication": {}, "phase": "runtime-cleanup"},
            )
            providers._record_claude_secondary_persistence_failure(
                self.review,
                failure,
            )
            report = common.read_json(
                self.review.container_dir / "claude-runtime.json"
            )
            self.assertEqual(
                report["authentication"]["recovery_artifact"],
                str(artifact),
            )
            with mock.patch.object(
                providers.os,
                "unlink",
                side_effect=fail_stale_cleanup,
            ):
                with self.assertRaises(OSError) as cleanup_raised:
                    providers._replace_claude_macos_recovery_credential(
                        self.review,
                        carrier,
                        third,
                    )
            current_recovery_artifact = (
                carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
            )
            self.assertEqual(
                getattr(
                    cleanup_raised.exception,
                    "_codex_claude_retained_credential_artifact",
                    None,
                ),
                str(current_recovery_artifact),
            )
            self.assertEqual(
                getattr(
                    cleanup_raised.exception,
                    "_codex_claude_retained_cleanup_artifact",
                    None,
                ),
                str(artifact),
            )
            self.assertTrue(artifact.exists())
            self.assertEqual(artifact.read_bytes(), bytes(second))
            self.assertEqual(current_recovery_artifact.read_bytes(), bytes(third))
            cleanup_failure = providers._failed_claude_macos_recovery_error(
                providers.ClaudeCredentialInspectionInconclusive(
                    "fixture later host writeback failure"
                ),
                cleanup_raised.exception,
            )
            providers._record_claude_secondary_persistence_failure(
                self.review,
                cleanup_failure,
            )
            cleanup_report = common.read_json(
                self.review.container_dir / "claude-runtime.json"
            )
            self.assertEqual(
                cleanup_report["authentication"]["recovery_artifact"],
                str(current_recovery_artifact),
            )
            self.assertEqual(
                cleanup_report["authentication"]["recovery_cleanup_artifact"],
                str(artifact),
            )
            providers._replace_claude_macos_recovery_credential(
                self.review,
                carrier,
                third,
            )

        self.assertFalse(artifact.exists())
        self.assertEqual(
            sorted(path.name for path in (carrier / "config").iterdir()),
            [providers.CLAUDE_CREDENTIAL_FILE_NAME],
        )
        self.assertEqual(
            (carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME).read_bytes(),
            bytes(third),
        )
        self.assertEqual(replace_calls, 3)
        for payload in (first, second, third):
            payload[:] = b"\x00" * len(payload)

    def test_post_commit_replacement_failures_retain_current_proof(
        self,
    ) -> None:
        for failure_kind in ("stale-fsync", "config-close"):
            with self.subTest(failure_kind=failure_kind):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=3600)
                )
                updated_value = json.loads(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                updated_value["claudeAiOauth"]["refreshToken"] = (
                    f"fixture-post-commit-{failure_kind}-refresh-value"
                )
                updated = bytearray(json.dumps(updated_value).encode())
                carrier = providers._retain_claude_macos_refreshed_credential(
                    self.review,
                    original,
                )
                config_dir = carrier / "config"
                if failure_kind == "stale-fsync":
                    stale = config_dir / (
                        f"{providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX}"
                        "fixture"
                        f"{providers.CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX}"
                    )
                    stale.write_bytes(original)
                    stale.chmod(0o600)

                real_fsync = providers.os.fsync
                real_close = providers.os.close
                real_fstat = providers.os.fstat
                real_open = providers.os.open
                real_replace = providers.os.replace
                directory_fsyncs = 0
                close_failed = False
                failed_descriptor: int | None = None
                config_descriptor: int | None = None
                main_replaced = False

                def fail_final_directory_fsync(descriptor: int) -> None:
                    nonlocal directory_fsyncs
                    if stat.S_ISDIR(real_fstat(descriptor).st_mode):
                        directory_fsyncs += 1
                        if directory_fsyncs == 2:
                            raise OSError(
                                "injected post-commit stale fsync failure"
                            )
                    real_fsync(descriptor)

                def track_config_open(
                    path: os.PathLike[str] | str,
                    flags: int,
                    *args: object,
                    **kwargs: object,
                ) -> int:
                    nonlocal config_descriptor
                    descriptor = real_open(path, flags, *args, **kwargs)
                    if pathlib.Path(path) == config_dir:
                        config_descriptor = descriptor
                    return descriptor

                def track_main_replace(
                    source: os.PathLike[str] | str,
                    destination: os.PathLike[str] | str,
                    *args: object,
                    **kwargs: object,
                ) -> None:
                    nonlocal main_replaced
                    real_replace(source, destination, *args, **kwargs)
                    if destination == providers.CLAUDE_CREDENTIAL_FILE_NAME:
                        main_replaced = True

                def fail_first_config_close(descriptor: int) -> None:
                    nonlocal close_failed, failed_descriptor
                    if (
                        not close_failed
                        and main_replaced
                        and descriptor == config_descriptor
                    ):
                        close_failed = True
                        failed_descriptor = descriptor
                        raise OSError(
                            "injected post-commit config close failure"
                        )
                    real_close(descriptor)

                try:
                    with contextlib.ExitStack() as stack:
                        if failure_kind == "stale-fsync":
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "fsync",
                                    side_effect=fail_final_directory_fsync,
                                )
                            )
                        else:
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "open",
                                    side_effect=track_config_open,
                                )
                            )
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "replace",
                                    side_effect=track_main_replace,
                                )
                            )
                            stack.enter_context(
                                mock.patch.object(
                                    providers.os,
                                    "close",
                                    side_effect=fail_first_config_close,
                                )
                            )
                        raised = stack.enter_context(
                            self.assertRaises(
                                (
                                    OSError,
                                    providers.ClaudeCredentialInspectionInconclusive,
                                )
                            )
                        )
                        providers._replace_claude_macos_recovery_credential(
                            self.review,
                            carrier,
                            updated,
                        )
                finally:
                    if failed_descriptor is not None:
                        real_close(failed_descriptor)

                current = (
                    config_dir / providers.CLAUDE_CREDENTIAL_FILE_NAME
                )
                self.assertEqual(current.read_bytes(), bytes(updated))
                self.assertEqual(
                    providers._validated_claude_retained_credential_artifact(
                        self.review,
                        raised.exception,
                    ),
                    str(current),
                )
                proof = providers._get_claude_retained_credential_proof(
                    raised.exception
                )
                self.assertIsNotNone(proof)
                assert proof is not None
                self.assertEqual(
                    proof.digest,
                    providers._claude_credential_digest(updated),
                )
                original[:] = b"\x00" * len(original)
                updated[:] = b"\x00" * len(updated)

    def test_dual_carrier_file_first_failure_retains_refreshed_credential(
        self,
    ) -> None:
        original_bytes = oauth_credential_fixture(expires_in_seconds=-60)
        self.write_pwd_home_credential(original_bytes)
        file_result = providers._read_claude_macos_file_credential()
        assert file_result is not None
        file_payload, file_snapshot = file_result
        refresh_digest = providers._claude_credential_refresh_digest(file_payload)
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(file_payload),
            file_digest=providers._claude_credential_digest(file_payload),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=refresh_digest,
            file_refresh_digest=refresh_digest,
        )
        selected = providers._ClaudeLocalCredential(
            source="pwd-home-credential-file",
            payload=file_payload,
            expires_at_ms=0,
            file_snapshot=file_snapshot,
            carrier_snapshot=carrier_snapshot,
        )
        refreshed_value = json.loads(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-file-recovery-refresh-value"
        )
        refreshed_bytes = json.dumps(refreshed_value).encode()
        callback_payload: bytearray | None = None

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            nonlocal callback_payload
            assert update_callback is not None
            callback_payload = bytearray(refreshed_bytes)
            self.assertTrue(update_callback(callback_payload))
            callback_payload[:] = b"\x00" * len(callback_payload)
            yield 43211

        lease = mock.Mock(spec=["assert_held"])
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                side_effect=lambda _review: bytearray(original_bytes),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                side_effect=lambda: (bytearray(original_bytes), file_snapshot),
            ),
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
                return_value=False,
            ) as write_file,
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
            ) as write_keychain,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        assert callback_payload is not None
        self.assertEqual(callback_payload, b"\x00" * len(callback_payload))
        self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        write_file.assert_called_once()
        write_keychain.assert_not_called()

    def test_malformed_refresh_does_not_create_recovery_carrier(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertFalse(update_callback(bytearray(b"{}")))
            self.assertFalse(
                update_callback(
                    bytearray(
                        b'{"claudeAiOauth":{"accessToken":"a",'
                        b'"refreshToken":"\\ud800","expiresAt":1}}'
                    )
                )
            )
            yield 43211

        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
            ) as retain,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "malformed refreshed",
            ),
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        retain.assert_not_called()

    def test_refresh_validation_control_flow_retains_recovery_carrier(
        self,
    ) -> None:
        real_validate = providers._validate_claude_local_credential
        interruptions = (
            ("forwarded-signal", providers.ForwardedSignal(signal.SIGTERM)),
            ("keyboard-interrupt", KeyboardInterrupt("fixture interrupt")),
            ("system-exit", SystemExit(19)),
        )

        for label, interruption in interruptions:
            with self.subTest(interruption=label):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                refreshed = bytearray(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                refreshed_bytes = bytes(refreshed)
                selected = providers._ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=original,
                    expires_at_ms=0,
                    carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                        keychain_digest=providers._claude_credential_digest(
                            original
                        ),
                        file_digest=None,
                        file_snapshot=None,
                    ),
                )
                validation_calls = 0
                interrupted_payload: bytearray | None = None

                def interrupt_second_validation(
                    credential: bytearray,
                    *,
                    source: str,
                ) -> None:
                    nonlocal interrupted_payload, validation_calls
                    validation_calls += 1
                    if validation_calls == 2:
                        interrupted_payload = credential
                        raise interruption
                    real_validate(credential, source=source)

                @contextlib.contextmanager
                def broker(
                    _credential,
                    _capability,
                    *,
                    update_callback=None,
                    **_kwargs,
                ):
                    assert update_callback is not None
                    self.assertTrue(update_callback(refreshed))
                    refreshed[:] = b"\x00" * len(refreshed)
                    yield 43211

                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {"authentication": {}, "phase": "runtime-launching"},
                )
                with (
                    mock.patch.object(
                        providers,
                        "_select_claude_macos_credential",
                        return_value=selected,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_keychain_credential_server",
                        side_effect=broker,
                    ),
                    mock.patch.object(
                        providers,
                        "_validate_claude_local_credential",
                        side_effect=interrupt_second_validation,
                    ),
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                    ) as persist,
                    self.assertRaises(type(interruption)) as raised,
                ):
                    with self.claude_keychain_runtime(
                        self.review,
                        {},
                        self.claude_refresh_lock_protocol,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                carrier = self.assert_macos_recovery_carrier(
                    interruption,
                    refreshed_bytes,
                )
                report = common.read_json(
                    self.review.container_dir / "claude-runtime.json"
                )
                self.assertEqual(
                    report["authentication"]["refresh_persistence"],
                    "failed-after-attempt",
                )
                self.assertEqual(
                    report["authentication"]["recovery_carrier"],
                    str(carrier),
                )
                self.assertEqual(validation_calls, 3)
                self.assertIsNotNone(interrupted_payload)
                assert interrupted_payload is not None
                self.assertEqual(
                    interrupted_payload,
                    b"\x00" * len(interrupted_payload),
                )
                self.assertEqual(original, b"\x00" * len(original))
                self.assertEqual(refreshed, b"\x00" * len(refreshed))
                persist.assert_not_called()

    def test_refresh_validation_signal_survives_candidate_generation_failure(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        real_validate = providers._validate_claude_local_credential
        validation_calls = 0
        interrupted_payload: bytearray | None = None

        def interrupt_accept_validation(
            credential: bytearray,
            *,
            source: str,
        ) -> None:
            nonlocal interrupted_payload, validation_calls
            validation_calls += 1
            if validation_calls == 2:
                interrupted_payload = credential
                raise forwarded
            real_validate(credential, source=source)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_validate_claude_local_credential",
                side_effect=interrupt_accept_validation,
            ),
            mock.patch.object(
                providers.secrets,
                "token_hex",
                side_effect=OSError("fixture candidate generation failed"),
            ) as token_hex,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, forwarded)
        self.assertTrue(
            getattr(forwarded, "_codex_claude_refresh_persistence_failed", False)
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertEqual(validation_calls, 2)
        self.assertIsNotNone(interrupted_payload)
        assert interrupted_payload is not None
        self.assertEqual(
            interrupted_payload,
            b"\x00" * len(interrupted_payload),
        )
        self.assertEqual(original, b"\x00" * len(original))
        self.assertEqual(refreshed, b"\x00" * len(refreshed))
        token_hex.assert_called_once_with(16)
        persist.assert_not_called()

    def test_refresh_state_lock_control_flow_retains_recovery_carrier(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        interrupted = KeyboardInterrupt("fixture state-lock interrupt")
        real_lock_factory = threading.Lock
        real_validate = providers._validate_claude_local_credential
        validation_calls = 0
        staged_payload: bytearray | None = None

        class InterruptingLock:
            def __init__(self) -> None:
                self.delegate = real_lock_factory()
                self.entries = 0

            def __enter__(self):
                self.entries += 1
                if self.entries == 7:
                    raise interrupted
                self.delegate.acquire()
                return self

            def __exit__(self, _exc_type, _exc, _traceback) -> None:
                self.delegate.release()

        runtime_lock = InterruptingLock()

        def observe_accept_validation(
            credential: bytearray,
            *,
            source: str,
        ) -> None:
            nonlocal staged_payload, validation_calls
            validation_calls += 1
            if validation_calls == 2:
                staged_payload = credential
            real_validate(credential, source=source)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_validate_claude_local_credential",
                side_effect=observe_accept_validation,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            mock.patch.object(
                providers.threading,
                "Lock",
                return_value=runtime_lock,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, interrupted)
        carrier = self.assert_macos_recovery_carrier(
            interrupted,
            refreshed_bytes,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )
        self.assertEqual(validation_calls, 3)
        self.assertGreaterEqual(runtime_lock.entries, 8)
        self.assertIsNotNone(staged_payload)
        assert staged_payload is not None
        self.assertEqual(staged_payload, b"\x00" * len(staged_payload))
        self.assertEqual(original, b"\x00" * len(original))
        self.assertEqual(refreshed, b"\x00" * len(refreshed))
        persist.assert_not_called()

    def test_refresh_validation_control_flow_replaces_prior_error(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        real_validate = providers._validate_claude_local_credential
        validation_calls = 0
        interrupted_payload: bytearray | None = None

        def interrupt_accept_validation(
            credential: bytearray,
            *,
            source: str,
        ) -> None:
            nonlocal interrupted_payload, validation_calls
            validation_calls += 1
            if validation_calls == 3:
                interrupted_payload = credential
                raise forwarded
            real_validate(credential, source=source)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            malformed = bytearray(b"{}")
            self.assertFalse(update_callback(malformed))
            malformed[:] = b"\x00" * len(malformed)
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_validate_claude_local_credential",
                side_effect=interrupt_accept_validation,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, forwarded)
        carrier = self.assert_macos_recovery_carrier(
            forwarded,
            refreshed_bytes,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )
        self.assertEqual(validation_calls, 4)
        self.assertIsNotNone(interrupted_payload)
        assert interrupted_payload is not None
        self.assertEqual(
            interrupted_payload,
            b"\x00" * len(interrupted_payload),
        )
        self.assertEqual(original, b"\x00" * len(original))
        self.assertEqual(refreshed, b"\x00" * len(refreshed))
        persist.assert_not_called()

    def test_newer_malformed_refresh_invalidates_older_staged_rotation(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        latest_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        latest_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-malformed-successor-latest-refresh"
        )
        latest = bytearray(json.dumps(latest_value).encode())
        latest_bytes = bytes(latest)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        complete_carriers: list[pathlib.Path] = []

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(latest))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            complete_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(complete_carriers), 2)
            self.assertFalse(update_callback(bytearray(b"{}")))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "malformed refreshed",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertEqual(latest_carrier, complete_carriers[-1])
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(list(recovery_root.iterdir()), [latest_carrier])
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(latest_carrier),
        )
        self.assertEqual(
            report["authentication"]["recovery_artifact"],
            str(
                latest_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )

    def test_failed_new_generation_cleans_unreported_complete_carriers(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates: list[bytearray] = []
        for generation in range(1, 4):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-failed-successor-refresh-{generation}"
            )
            updates.append(bytearray(json.dumps(value).encode()))
        latest_bytes = bytes(updates[1])
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        complete_carriers: list[pathlib.Path] = []
        real_commit = providers._commit_claude_macos_durable_stage
        commit_calls = 0

        def fail_third_commit(
            review: ReviewWorkspace,
            pending: pathlib.Path,
            acknowledged: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            nonlocal commit_calls
            commit_calls += 1
            if commit_calls == 3:
                raise OSError("injected third durable generation commit failure")
            return real_commit(
                review,
                pending,
                acknowledged,
                credential,
            )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(updates[0]))
            self.assertTrue(update_callback(updates[1]))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            complete_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(complete_carriers), 2)
            self.assertFalse(update_callback(updates[2]))
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=fail_third_commit,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "credential runtime I/O",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        self.assertEqual(commit_calls, 3)
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertIn(
            "third durable generation commit failure",
            str(raised.exception.__cause__),
        )
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertEqual(latest_carrier, complete_carriers[-1])
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(list(recovery_root.iterdir()), [latest_carrier])
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(latest_carrier),
        )
        self.assertEqual(
            report["authentication"]["recovery_artifact"],
            str(
                latest_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        self.assertNotIn(
            "recovery_cleanup_artifact",
            report["authentication"],
        )

    def test_shared_recovery_candidate_reports_concurrent_owner(self) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        expected = bytes(credential)
        recovery_root = providers._claude_macos_recovery_root(self.review)
        candidate = recovery_root / "claude-carrier-concurrent-owner"
        owner_started_write = threading.Event()
        release_owner = threading.Event()
        owner_results: list[pathlib.Path] = []
        owner_errors: list[BaseException] = []
        real_write = providers._write_all_to_descriptor

        def blocking_write(descriptor: int, payload: bytearray) -> None:
            owner_started_write.set()
            if not release_owner.wait(timeout=2.0):
                raise RuntimeError("fixture recovery owner was not released")
            real_write(descriptor, payload)

        def retain_as_owner() -> None:
            try:
                owner_results.append(
                    providers._retain_claude_macos_refreshed_credential(
                        self.review,
                        credential,
                        requested_carrier_root=candidate,
                    )
                )
            except BaseException as error:
                owner_errors.append(error)

        owner = threading.Thread(target=retain_as_owner)
        with mock.patch.object(
            providers,
            "_write_all_to_descriptor",
            side_effect=blocking_write,
        ):
            owner.start()
            try:
                self.assertTrue(owner_started_write.wait(timeout=2.0))
                with self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised:
                    providers._retain_claude_macos_refreshed_credential(
                        self.review,
                        bytearray(expected),
                        requested_carrier_root=candidate,
                    )
            finally:
                release_owner.set()
                owner.join(timeout=2.0)

        self.assertFalse(owner.is_alive())
        self.assertEqual(owner_errors, [])
        self.assertEqual(owner_results, [candidate])
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(candidate),
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assert_macos_recovery_carrier(
            providers._retained_claude_macos_credential_error(
                candidate,
                raised.exception,
                expected_digest=providers._claude_credential_digest(
                    credential
                ),
            ),
            expected,
        )
        credential[:] = b"\x00" * len(credential)

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_abandon_reuses_durable_recovery_candidate(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[[bytearray], bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(refreshed))
            try:
                yield 43211
            finally:
                quiescence_callbacks.abandon()
                recovery_error = quiescence_callbacks.recover(None)
                if recovery_error is not None:
                    raise recovery_error

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        with (
            mock.patch.object(
                providers.secrets,
                "token_hex",
                side_effect=OSError("injected random source failure"),
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive,
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assert_macos_recovery_carrier(
            raised.exception,
            bytes(refreshed),
        )
        persist_credential.assert_not_called()

    def test_abandoned_primary_oserror_is_runtime_inconclusive(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        primary_error = OSError("injected runtime body I/O failure")

        @contextlib.contextmanager
        def broker(_credential, _capability, **_kwargs):
            try:
                yield 43211
            except OSError as error:
                setattr(
                    error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                setattr(
                    error,
                    (
                        "_codex_claude_keychain_handler_"
                        "quiescence_unproven"
                    ),
                    True,
                )
                raise

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "credential runtime I/O",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                raise primary_error

        self.assertIs(raised.exception.__cause__, primary_error)
        self.assertTrue(
            getattr(
                raised.exception,
                "_codex_claude_refresh_persistence_failed",
                False,
            )
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )

    def test_unquiescent_recovery_reports_prior_durable_journal_scope(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        latest_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        latest_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-unquiescent-prior-journal-latest"
        )
        latest = bytearray(json.dumps(latest_value).encode())
        latest_bytes = bytes(latest)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        staged_carriers: list[pathlib.Path] = []

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(latest))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            staged_carriers.extend(
                sorted(recovery_root.glob("claude-carrier-*"))
            )
            self.assertEqual(len(staged_carriers), 2)
            quiescence_callbacks.abandon()
            recovery_error = quiescence_callbacks.recover(None)
            failure = providers.ClaudeCredentialInspectionInconclusive(
                "fixture handler quiescence failure"
            )
            setattr(
                failure,
                "_codex_claude_keychain_handler_quiescence_unproven",
                True,
            )
            if recovery_error is not None:
                providers._add_claude_persistence_note(
                    failure,
                    recovery_error,
                )
            first[:] = b"\x00" * len(first)
            latest[:] = b"\x00" * len(latest)
            try:
                yield 43211
            finally:
                raise failure

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertEqual(latest_carrier, staged_carriers[-1])
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            staged_carriers,
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(latest_carrier),
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )

    def test_completed_journal_recovery_timeout_reports_current_and_scope(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-completed-journal-timeout-second"
        )
        second = bytearray(json.dumps(second_value).encode())
        replacement_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=10800)
        )
        replacement_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-completed-journal-timeout-replacement"
        )
        replacement = bytearray(json.dumps(replacement_value).encode())
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        staged_carriers: list[pathlib.Path] = []
        immediate_state: dict[str, object] = {}
        replace_started = threading.Event()
        release_replace = threading.Event()
        recovery_threads: list[threading.Thread] = []
        real_replace = providers._replace_claude_macos_recovery_credential
        real_thread = threading.Thread

        def blocking_replace(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            credential: bytearray,
        ) -> None:
            self.assertEqual(carrier, staged_carriers[-1])
            replace_started.set()
            if not release_replace.wait(timeout=2.0):
                raise RuntimeError("fixture journal replacement was not released")
            real_replace(review, carrier, credential)

        def tracking_thread(
            *args: object,
            **kwargs: object,
        ) -> threading.Thread:
            thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
            if kwargs.get("name") == "claude-review-keychain-recovery":
                recovery_threads.append(thread)
            return thread

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(second))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            staged_carriers.extend(
                sorted(recovery_root.glob("claude-carrier-*"))
            )
            self.assertEqual(len(staged_carriers), 2)
            quiescence_callbacks.abandon()
            timeout_error = (
                providers._bounded_claude_keychain_quiescence_recovery(
                    quiescence_callbacks,
                    bytearray(replacement),
                    already_abandoned=True,
                )
            )
            self.assertTrue(replace_started.is_set())
            self.assertIsNotNone(timeout_error)
            assert timeout_error is not None
            immediate_state.update(
                error=timeout_error,
                carrier=getattr(
                    timeout_error,
                    "_codex_claude_retained_credential_carrier",
                    None,
                ),
                artifact=getattr(
                    timeout_error,
                    "_codex_claude_retained_credential_artifact",
                    None,
                ),
                cleanup=getattr(
                    timeout_error,
                    "_codex_claude_retained_cleanup_artifact",
                    None,
                ),
            )
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    providers,
                    "_replace_claude_macos_recovery_credential",
                    side_effect=blocking_replace,
                ),
                mock.patch.object(
                    providers.threading,
                    "Thread",
                    side_effect=tracking_thread,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_replace.set()
            for recovery_thread in recovery_threads:
                recovery_thread.join(timeout=2.0)

        self.assertIs(raised.exception, immediate_state["error"])
        latest_carrier = staged_carriers[-1]
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(immediate_state["carrier"], str(latest_carrier))
        self.assertEqual(
            immediate_state["artifact"],
            str(
                latest_carrier
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            ),
        )
        self.assertEqual(immediate_state["cleanup"], str(recovery_root))
        self.assertEqual(len(recovery_threads), 1)
        self.assertFalse(recovery_threads[0].is_alive())
        persist.assert_not_called()

    def test_recovery_error_exact_proof_refreshes_timeout_expectation(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-recovery-proof-timeout-second"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_digest = providers._claude_credential_digest(second)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        captured: dict[str, BaseException] = {}
        real_replace = providers._replace_claude_macos_recovery_credential

        def replace_then_fail(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            credential: bytearray,
        ) -> None:
            real_replace(review, carrier, credential)
            raise providers._retained_claude_macos_credential_error(
                carrier,
                providers.ClaudeCredentialInspectionInconclusive(
                    "injected post-commit recovery failure"
                ),
                expected_digest=providers._claude_credential_digest(
                    credential
                ),
            )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))
            quiescence_callbacks.abandon()
            recovery_error = quiescence_callbacks.recover(bytearray(second))
            self.assertIsNotNone(recovery_error)
            timeout_error = quiescence_callbacks.timeout_error()
            captured["recovery"] = recovery_error  # type: ignore[assignment]
            captured["timeout"] = timeout_error
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_replace_claude_macos_recovery_credential",
                side_effect=replace_then_fail,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, captured["timeout"])
        timeout_proof = providers._get_claude_retained_credential_proof(
            captured["timeout"]
        )
        self.assertIsNotNone(timeout_proof)
        assert timeout_proof is not None
        self.assertEqual(timeout_proof.digest, second_digest)
        self.assertEqual(
            timeout_proof.artifact.name,
            providers.CLAUDE_CREDENTIAL_FILE_NAME,
        )
        self.assertEqual(timeout_proof.artifact.read_bytes(), bytes(second))
        persist.assert_not_called()
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_recovery_temp_proof_refreshes_timeout_expectation(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-recovery-temp-proof-timeout-second"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_digest = providers._claude_credential_digest(second)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        captured: dict[str, BaseException] = {}
        real_replace = providers.os.replace

        def fail_recovery_temp_replace(
            source: os.PathLike[str] | str,
            destination: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> None:
            if (
                isinstance(source, str)
                and source.startswith(
                    providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
                )
                and destination == providers.CLAUDE_CREDENTIAL_FILE_NAME
            ):
                raise OSError("injected recovery temporary rename failure")
            real_replace(source, destination, *args, **kwargs)

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))
            quiescence_callbacks.abandon()
            timeout_error = quiescence_callbacks.timeout_error()
            recovery_error = quiescence_callbacks.recover(bytearray(second))
            self.assertIsNotNone(recovery_error)
            assert recovery_error is not None
            self.assertIs(recovery_error, timeout_error)
            captured["recovery"] = recovery_error
            captured["timeout"] = timeout_error
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers.os,
                "replace",
                side_effect=fail_recovery_temp_replace,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, captured["timeout"])
        recovery_proof = providers._get_claude_retained_credential_proof(
            captured["recovery"]
        )
        timeout_proof = providers._get_claude_retained_credential_proof(
            captured["timeout"]
        )
        self.assertIsNotNone(recovery_proof)
        self.assertIsNotNone(timeout_proof)
        assert recovery_proof is not None
        assert timeout_proof is not None
        self.assertIs(captured["recovery"], captured["timeout"])
        self.assertEqual(timeout_proof, recovery_proof)
        self.assertEqual(timeout_proof.digest, second_digest)
        self.assertTrue(
            timeout_proof.artifact.name.startswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
            )
        )
        self.assertTrue(
            timeout_proof.artifact.name.endswith(
                providers.CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX
            )
        )
        self.assertEqual(timeout_proof.artifact.read_bytes(), bytes(second))
        persist.assert_not_called()
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_recovery_marker_failure_promotes_root_cleanup_scope(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        captured: dict[str, BaseException] = {}

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
            **_kwargs: object,
        ):
            assert quiescence_callbacks is not None
            quiescence_callbacks.abandon()
            recovery_error = quiescence_callbacks.recover(
                bytearray(refreshed)
            )
            self.assertIsNotNone(recovery_error)
            assert recovery_error is not None
            captured["recovery"] = recovery_error
            raise recovery_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_capture_claude_retained_credential_proof",
                side_effect=OSError("injected recovery marker failure"),
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, captured["recovery"])
        self.assertIsNone(
            providers._get_claude_retained_credential_proof(raised.exception)
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        self.assertEqual(len(list(recovery_root.glob("claude-carrier-*"))), 1)
        persist.assert_not_called()
        refreshed[:] = b"\x00" * len(refreshed)

    def test_timeout_reproof_failure_keeps_root_cleanup_scope(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        replacement = oauth_credential_fixture(expires_in_seconds=10800)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        captured: dict[str, BaseException] = {}

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
            **_kwargs: object,
        ):
            assert quiescence_callbacks is not None
            quiescence_callbacks.abandon()
            recovery_error = quiescence_callbacks.recover(
                bytearray(refreshed)
            )
            self.assertIsNotNone(recovery_error)
            assert recovery_error is not None
            recovery_proof = providers._get_claude_retained_credential_proof(
                recovery_error
            )
            self.assertIsNotNone(recovery_proof)
            assert recovery_proof is not None
            replacement_path = recovery_proof.artifact.with_name(
                "replacement.json"
            )
            replacement_path.write_bytes(replacement)
            replacement_path.chmod(0o600)
            os.replace(replacement_path, recovery_proof.artifact)
            timeout_error = quiescence_callbacks.timeout_error()
            captured["timeout"] = timeout_error
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, captured["timeout"])
        self.assertIsNone(
            providers._get_claude_retained_credential_proof(raised.exception)
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        persist.assert_not_called()
        refreshed[:] = b"\x00" * len(refreshed)

    def test_unquiescent_no_payload_prefers_inflight_exact_proof(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-inflight-exact-proof-second"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_digest = providers._claude_credential_digest(second)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        second_commit_ready = threading.Event()
        release_second_commit = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        captured: dict[str, BaseException] = {}
        callback_thread: threading.Thread | None = None
        recovery_thread: threading.Thread | None = None
        recovery_wait_started = threading.Event()
        recovery_results: list[BaseException | None] = []
        commit_calls = 0
        real_commit = providers._commit_claude_macos_durable_stage
        real_event_wait = providers._ClaudeThreadEvent.wait

        def track_recovery_wait(
            event: providers._ClaudeThreadEvent,
            timeout: float | None = None,
        ) -> bool:
            if (
                threading.current_thread() is recovery_thread
                and not event.is_set()
            ):
                recovery_wait_started.set()
            return real_event_wait(event, timeout)

        def fail_second_after_exact_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            nonlocal commit_calls
            commit_calls += 1
            committed_carrier = real_commit(
                review,
                pending,
                committed,
                credential,
            )
            if commit_calls == 2:
                second_commit_ready.set()
                if not release_second_commit.wait(timeout=2.0):
                    raise RuntimeError(
                        "fixture second durable commit was not released"
                    )
                raise providers._retained_claude_macos_credential_error(
                    committed_carrier,
                    providers.ClaudeCredentialInspectionInconclusive(
                        "injected second post-commit failure"
                    ),
                    expected_digest=providers._claude_credential_digest(
                        credential
                    ),
                )
            return committed_carrier

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread, recovery_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))

            def update_second() -> None:
                try:
                    callback_results.append(update_callback(second))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = threading.Thread(target=update_second)
            callback_thread.start()
            self.assertTrue(second_commit_ready.wait(timeout=2.0))
            quiescence_callbacks.abandon()
            timeout_error = quiescence_callbacks.timeout_error()
            recovery_thread = threading.Thread(
                target=lambda: recovery_results.append(
                    quiescence_callbacks.recover(None)
                )
            )
            recovery_thread.start()
            self.assertTrue(recovery_wait_started.wait(timeout=2.0))
            release_second_commit.set()
            callback_thread.join(timeout=2.0)
            recovery_thread.join(timeout=2.0)
            self.assertFalse(callback_thread.is_alive())
            self.assertFalse(recovery_thread.is_alive())
            self.assertEqual(len(recovery_results), 1)
            recovery_error = recovery_results[0]
            self.assertIsNotNone(recovery_error)
            assert recovery_error is not None
            self.assertIs(recovery_error, timeout_error)
            captured["recovery"] = recovery_error
            raise recovery_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=fail_second_after_exact_commit,
                ),
                mock.patch.object(
                    providers._ClaudeThreadEvent,
                    "wait",
                    new=track_recovery_wait,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_second_commit.set()
            if callback_thread is not None:
                callback_thread.join(timeout=2.0)
            if recovery_thread is not None:
                recovery_thread.join(timeout=2.0)

        self.assertIs(raised.exception, captured["recovery"])
        self.assertEqual(callback_errors, [])
        self.assertEqual(callback_results, [False])
        recovery_proof = providers._get_claude_retained_credential_proof(
            captured["recovery"]
        )
        self.assertIsNotNone(recovery_proof)
        assert recovery_proof is not None
        self.assertEqual(recovery_proof.digest, second_digest)
        self.assertEqual(recovery_proof.artifact.read_bytes(), bytes(second))
        persist.assert_not_called()
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_unquiescent_no_payload_reports_pending_pre_rename_proof(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        refreshed_digest = providers._claude_credential_digest(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        rename_started = threading.Event()
        release_rename = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        callback_thread: threading.Thread | None = None
        captured: dict[str, BaseException] = {}
        real_rename = providers.os.rename

        def fail_stage_rename(
            source: os.PathLike[str] | str,
            destination: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> None:
            if (
                isinstance(source, str)
                and source.startswith(
                    providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
                )
            ):
                rename_started.set()
                if not release_rename.wait(timeout=2.0):
                    raise RuntimeError("fixture stage rename was not released")
                raise OSError("injected durable-stage pre-rename failure")
            real_rename(source, destination, *args, **kwargs)

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None

            def update() -> None:
                try:
                    callback_results.append(update_callback(refreshed))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = threading.Thread(target=update)
            callback_thread.start()
            self.assertTrue(rename_started.wait(timeout=2.0))
            quiescence_callbacks.abandon()
            release_rename.set()
            callback_thread.join(timeout=2.0)
            self.assertFalse(callback_thread.is_alive())
            timeout_error = quiescence_callbacks.timeout_error()
            recovery_error = quiescence_callbacks.recover(None)
            self.assertIs(recovery_error, timeout_error)
            captured["recovery"] = timeout_error
            raise timeout_error
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers.os,
                    "rename",
                    side_effect=fail_stage_rename,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_rename.set()
            if callback_thread is not None:
                callback_thread.join(timeout=2.0)

        self.assertIs(raised.exception, captured["recovery"])
        self.assertEqual(callback_results, [False])
        self.assertEqual(callback_errors, [])
        proof = providers._get_claude_retained_credential_proof(
            captured["recovery"]
        )
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof.digest, refreshed_digest)
        self.assertTrue(
            proof.artifact.parent.parent.name.startswith(
                providers.CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
            )
        )
        self.assertEqual(proof.artifact.read_bytes(), bytes(refreshed))
        persist.assert_not_called()
        refreshed[:] = b"\x00" * len(refreshed)

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_abandon_during_durable_commit_reports_only_retained_generation(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        commit_paths: list[tuple[pathlib.Path, pathlib.Path]] = []
        callback_thread: threading.Thread | None = None
        real_commit = providers._commit_claude_macos_durable_stage

        def blocking_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            acknowledged: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_paths.append((pending, acknowledged))
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            return real_commit(
                review,
                pending,
                acknowledged,
                credential,
            )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None

            def run_callback() -> None:
                try:
                    callback_results.append(update_callback(refreshed))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = threading.Thread(target=run_callback)
            callback_thread.start()
            self.assertTrue(commit_started.wait(timeout=2.0))
            try:
                yield 43211
            finally:
                pending_update = bytearray(refreshed_bytes)
                recovery_error: BaseException | None = None
                try:
                    recovery_error = (
                        providers._bounded_claude_keychain_quiescence_recovery(
                            quiescence_callbacks,
                            pending_update,
                        )
                    )
                finally:
                    release_commit.set()
                    callback_thread.join(timeout=2.0)
                shutdown_error = (
                    providers.ClaudeCredentialInspectionInconclusive(
                        "fixture handler quiescence failure"
                    )
                )
                setattr(
                    shutdown_error,
                    (
                        "_codex_claude_keychain_handler_"
                        "quiescence_unproven"
                    ),
                    True,
                )
                if recovery_error is not None:
                    providers._add_claude_persistence_note(
                        shutdown_error,
                        recovery_error,
                    )
                raise shutdown_error

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        with (
            mock.patch.object(
                providers,
                "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                0.2,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=blocking_commit,
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(callback_errors, [])
        self.assertIsNotNone(callback_thread)
        assert callback_thread is not None
        self.assertFalse(callback_thread.is_alive())
        self.assertEqual(callback_results, [False])
        self.assertEqual(len(commit_paths), 1)
        persist_credential.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(reported),
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_abandon_request_before_snapshot_self_registers_inflight_stage(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        callback_thread: threading.Thread | None = None
        real_commit = providers._commit_claude_macos_durable_stage

        def blocking_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            return real_commit(review, pending, committed, credential)

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None

            def run_callback() -> None:
                try:
                    callback_results.append(update_callback(refreshed))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = threading.Thread(target=run_callback)
            callback_thread.start()
            self.assertTrue(commit_started.wait(timeout=2.0))
            try:
                yield 43211
            finally:
                quiescence_callbacks.abandon()
                release_commit.set()
                callback_thread.join(timeout=2.0)
                recovery_error = quiescence_callbacks.recover(None)
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture handler quiescence failure"
                )
                setattr(
                    failure,
                    "_codex_claude_keychain_handler_quiescence_unproven",
                    True,
                )
                if recovery_error is not None:
                    providers._add_claude_persistence_note(
                        failure,
                        recovery_error,
                    )
                raise failure

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=blocking_commit,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_commit.set()
            if callback_thread is not None:
                callback_thread.join(timeout=2.0)

        self.assertEqual(callback_errors, [])
        self.assertEqual(callback_results, [False])
        persist.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_unquiescent_recovery_reports_failed_inflight_stage_scope(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        callback_thread: threading.Thread | None = None
        real_commit = providers._commit_claude_macos_durable_stage

        def fail_after_exact_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            committed_carrier = real_commit(
                review,
                pending,
                committed,
                credential,
            )
            raise providers._retained_claude_macos_credential_error(
                committed_carrier,
                providers.ClaudeCredentialInspectionInconclusive(
                    "injected post-commit finishing failure"
                ),
                expected_digest=providers._claude_credential_digest(
                    credential
                ),
            )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None

            def run_callback() -> None:
                try:
                    callback_results.append(update_callback(refreshed))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = threading.Thread(target=run_callback)
            callback_thread.start()
            self.assertTrue(commit_started.wait(timeout=2.0))
            try:
                yield 43211
            finally:
                quiescence_callbacks.abandon()
                release_commit.set()
                callback_thread.join(timeout=2.0)
                recovery_error = quiescence_callbacks.recover(
                    bytearray(refreshed_bytes)
                )
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture handler quiescence failure"
                )
                setattr(
                    failure,
                    "_codex_claude_keychain_handler_quiescence_unproven",
                    True,
                )
                if recovery_error is not None:
                    providers._add_claude_persistence_note(
                        failure,
                        recovery_error,
                    )
                raise failure

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_claude_keychain_credential_server",
                    side_effect=broker,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=fail_after_exact_commit,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_commit.set()
            if callback_thread is not None:
                callback_thread.join(timeout=2.0)

        self.assertEqual(callback_errors, [])
        self.assertEqual(callback_results, [False])
        persist.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        carriers = sorted(recovery_root.glob("claude-carrier-*"))
        self.assertEqual(len(carriers), 2)
        self.assertIn(reported, carriers)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_real_server_shutdown_does_not_orphan_commit_before_runtime_abandon(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        commit_finished = threading.Event()
        writer: threading.Thread | None = None
        writer_errors: list[BaseException] = []
        real_commit = providers._commit_claude_macos_durable_stage
        real_abandon = (
            providers._ClaudeKeychainCredentialServer
            .try_abandon_and_detach_pending_update
        )

        def blocking_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            result = real_commit(review, pending, committed, credential)
            commit_finished.set()
            return result

        def abandon_then_finish_handler(
            server: providers._ClaudeKeychainCredentialServer,
            timeout: float | None,
        ) -> tuple[bool, bytearray | None]:
            detached, pending = real_abandon(server, timeout)
            release_commit.set()
            if not commit_finished.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit did not finish")
            if not server.wait_for_handlers(2.0):
                raise RuntimeError(
                    "fixture broker handler did not finish before runtime abandon"
                )
            return detached, pending

        def write_update(port: int, capability: bytes) -> None:
            try:
                with socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=2.0,
                ) as sock:
                    sock.sendall(
                        capability
                        + b"W"
                        + len(refreshed_bytes).to_bytes(4, "big")
                        + refreshed_bytes
                    )
                    with contextlib.suppress(OSError):
                        sock.recv(1)
            except BaseException as error:
                writer_errors.append(error)

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                    1.0,
                ),
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=blocking_commit,
                ),
                mock.patch.object(
                    providers._ClaudeKeychainCredentialServer,
                    "try_abandon_and_detach_pending_update",
                    new=abandon_then_finish_handler,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ) as runtime_env:
                    port = int(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV
                        ]
                    )
                    capability = bytes.fromhex(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV
                        ]
                    )
                    with socket.create_connection(
                        ("127.0.0.1", port),
                        timeout=2.0,
                    ) as sock:
                        sock.sendall(capability + b"R")
                        raw_length = providers._recv_exact(sock, 4)
                        self.assertIsNotNone(raw_length)
                        assert raw_length is not None
                        credential = providers._recv_exact(
                            sock,
                            int.from_bytes(raw_length, "big"),
                        )
                        raw_length[:] = b"\x00" * len(raw_length)
                        self.assertEqual(credential, original)
                        assert credential is not None
                        credential[:] = b"\x00" * len(credential)
                    writer = threading.Thread(
                        target=write_update,
                        args=(port, capability),
                    )
                    writer.start()
                    self.assertTrue(commit_started.wait(timeout=2.0))
        except providers.ClaudeLoopbackUnavailable:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        finally:
            release_commit.set()
            if writer is not None:
                writer.join(timeout=2.0)

        self.assertIsNotNone(writer)
        assert writer is not None
        self.assertFalse(writer.is_alive())
        self.assertEqual(writer_errors, [])
        persist.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_real_server_retries_detach_and_recovers_inflight_without_payload(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        commit_finished = threading.Event()
        writer: threading.Thread | None = None
        writer_responses: list[bytes] = []
        real_commit = providers._commit_claude_macos_durable_stage
        real_detach = (
            providers._ClaudeKeychainCredentialServer
            .try_abandon_and_detach_pending_update
        )
        detach_calls = 0

        def blocking_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            result = real_commit(review, pending, committed, credential)
            commit_finished.set()
            return result

        def detach_then_raise_once(
            server: providers._ClaudeKeychainCredentialServer,
            timeout: float | None,
        ) -> tuple[bool, bytearray | None]:
            nonlocal detach_calls
            detach_calls += 1
            detached, pending = real_detach(server, timeout)
            if detach_calls == 1:
                release_commit.set()
                if not commit_finished.wait(timeout=2.0):
                    raise RuntimeError("fixture durable commit did not finish")
                if not server.wait_for_handlers(2.0):
                    raise RuntimeError("fixture broker handler did not finish")
                if pending is not None:
                    pending[:] = b"\x00" * len(pending)
                raise OSError("injected post-detach failure")
            return detached, pending

        def write_update(port: int, capability: bytes) -> None:
            response = b""
            try:
                with socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=2.0,
                ) as sock:
                    sock.sendall(
                        capability
                        + b"W"
                        + len(refreshed_bytes).to_bytes(4, "big")
                        + refreshed_bytes
                    )
                    with contextlib.suppress(OSError):
                        response = sock.recv(1)
            except OSError:
                pass
            finally:
                writer_responses.append(response)

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                    1.0,
                ),
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=blocking_commit,
                ),
                mock.patch.object(
                    providers._ClaudeKeychainCredentialServer,
                    "try_abandon_and_detach_pending_update",
                    new=detach_then_raise_once,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ) as runtime_env:
                    port = int(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV
                        ]
                    )
                    capability = bytes.fromhex(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV
                        ]
                    )
                    with socket.create_connection(
                        ("127.0.0.1", port),
                        timeout=2.0,
                    ) as sock:
                        sock.sendall(capability + b"R")
                        raw_length = providers._recv_exact(sock, 4)
                        self.assertIsNotNone(raw_length)
                        assert raw_length is not None
                        credential = providers._recv_exact(
                            sock,
                            int.from_bytes(raw_length, "big"),
                        )
                        raw_length[:] = b"\x00" * len(raw_length)
                        self.assertEqual(credential, original)
                        assert credential is not None
                        credential[:] = b"\x00" * len(credential)
                    writer = threading.Thread(
                        target=write_update,
                        args=(port, capability),
                    )
                    writer.start()
                    self.assertTrue(commit_started.wait(timeout=2.0))
        except providers.ClaudeLoopbackUnavailable:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        finally:
            release_commit.set()
            if writer is not None:
                writer.join(timeout=2.0)

        self.assertEqual(detach_calls, 2)
        self.assertIsNotNone(writer)
        assert writer is not None
        self.assertFalse(writer.is_alive())
        self.assertNotIn(b"\x00", writer_responses)
        persist.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )
        refreshed[:] = b"\x00" * len(refreshed)

    def test_real_server_timeout_snapshot_does_not_wait_for_runtime_lock(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        commit_started = threading.Event()
        release_commit = threading.Event()
        commit_finished = threading.Event()
        release_runtime_lock_early = threading.Event()
        runtime_lock_released = threading.Event()
        writer: threading.Thread | None = None
        runtime_lock_release_thread: threading.Thread | None = None
        recovery_threads: list[threading.Thread] = []
        finalization_started: float | None = None
        finalization_elapsed: float | None = None
        writer_responses: list[bytes] = []
        real_commit = providers._commit_claude_macos_durable_stage
        real_lock_factory = threading.Lock
        real_thread = threading.Thread

        class SnapshotContendedRuntimeLock:
            def __init__(self) -> None:
                self.lock = real_lock_factory()

            def acquire(
                self,
                blocking: bool = True,
                timeout: float = -1,
            ) -> bool:
                if timeout == -1:
                    return self.lock.acquire(blocking)
                return self.lock.acquire(blocking, timeout)

            def release(self) -> None:
                self.lock.release()

            def __enter__(self) -> SnapshotContendedRuntimeLock:
                self.acquire()
                return self

            def __exit__(
                self,
                _exception_type: object,
                _exception: object,
                _traceback: object,
            ) -> None:
                self.release()

        runtime_lock = SnapshotContendedRuntimeLock()
        lock_calls = 0

        def lock_factory() -> object:
            nonlocal lock_calls
            lock_calls += 1
            if lock_calls == 1:
                return runtime_lock
            return real_lock_factory()

        def tracking_thread(
            *args: object,
            **kwargs: object,
        ) -> threading.Thread:
            thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
            if kwargs.get("name") == "claude-review-keychain-recovery":
                recovery_threads.append(thread)
            return thread

        def release_runtime_lock_after_bound() -> None:
            release_runtime_lock_early.wait(timeout=1.0)
            runtime_lock.release()
            runtime_lock_released.set()

        def blocking_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            committed: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            commit_started.set()
            if not release_commit.wait(timeout=2.0):
                raise RuntimeError("fixture durable commit was not released")
            result = real_commit(review, pending, committed, credential)
            commit_finished.set()
            return result

        def write_update(port: int, capability: bytes) -> None:
            response = b""
            try:
                with socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=2.0,
                ) as sock:
                    sock.sendall(
                        capability
                        + b"W"
                        + len(refreshed_bytes).to_bytes(4, "big")
                        + refreshed_bytes
                    )
                    with contextlib.suppress(OSError):
                        response = sock.recv(1)
            except OSError:
                pass
            finally:
                writer_responses.append(response)

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        try:
            with (
                mock.patch.object(
                    providers,
                    "_select_claude_macos_credential",
                    return_value=selected,
                ),
                mock.patch.object(
                    providers,
                    "_persist_claude_macos_refreshed_credential",
                ) as persist,
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                    0.2,
                ),
                mock.patch.object(
                    providers,
                    "_commit_claude_macos_durable_stage",
                    side_effect=blocking_commit,
                ),
                mock.patch.object(
                    providers.threading,
                    "Lock",
                    side_effect=lock_factory,
                ),
                mock.patch.object(
                    providers.threading,
                    "Thread",
                    side_effect=tracking_thread,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ) as raised,
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ) as runtime_env:
                    port = int(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV
                        ]
                    )
                    capability = bytes.fromhex(
                        runtime_env[
                            providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV
                        ]
                    )
                    with socket.create_connection(
                        ("127.0.0.1", port),
                        timeout=2.0,
                    ) as sock:
                        sock.sendall(capability + b"R")
                        raw_length = providers._recv_exact(sock, 4)
                        self.assertIsNotNone(raw_length)
                        assert raw_length is not None
                        credential = providers._recv_exact(
                            sock,
                            int.from_bytes(raw_length, "big"),
                        )
                        raw_length[:] = b"\x00" * len(raw_length)
                        self.assertEqual(credential, original)
                        assert credential is not None
                        credential[:] = b"\x00" * len(credential)
                    writer = threading.Thread(
                        target=write_update,
                        args=(port, capability),
                    )
                    writer.start()
                    self.assertTrue(commit_started.wait(timeout=2.0))
                    runtime_lock.acquire()
                    runtime_lock_release_thread = threading.Thread(
                        target=release_runtime_lock_after_bound,
                        daemon=True,
                    )
                    runtime_lock_release_thread.start()
                    finalization_started = time.monotonic()
            assert finalization_started is not None
            finalization_elapsed = time.monotonic() - finalization_started
        except providers.ClaudeLoopbackUnavailable:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        finally:
            release_runtime_lock_early.set()
            if runtime_lock_release_thread is not None:
                runtime_lock_release_thread.join(timeout=2.0)
            release_commit.set()
            commit_finished.wait(timeout=2.0)
            if writer is not None:
                writer.join(timeout=2.0)
            for recovery_thread in recovery_threads:
                recovery_thread.join(timeout=2.0)

        self.assertIsNotNone(finalization_elapsed)
        assert finalization_elapsed is not None
        self.assertLess(finalization_elapsed, 0.75)
        self.assertTrue(runtime_lock_released.is_set())
        self.assertTrue(commit_finished.is_set())
        self.assertTrue(recovery_threads)
        self.assertFalse(any(thread.is_alive() for thread in recovery_threads))
        self.assertIsNotNone(writer)
        assert writer is not None
        self.assertFalse(writer.is_alive())
        self.assertNotIn(b"\x00", writer_responses)
        persist.assert_not_called()
        recovery_root = providers._claude_macos_recovery_root(self.review)
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        self.assertTrue(
            list(recovery_root.glob("claude-carrier-*")),
        )
        refreshed[:] = b"\x00" * len(refreshed)

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_late_quiescence_recovery_leaves_no_unreported_carrier(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        recovery_started = threading.Event()
        release_recovery = threading.Event()
        recovery_threads: list[threading.Thread] = []
        real_retain = providers._retain_claude_macos_refreshed_credential
        real_thread = threading.Thread

        def blocking_retain(*args: object, **kwargs: object) -> pathlib.Path:
            recovery_started.set()
            if not release_recovery.wait(timeout=2.0):
                raise RuntimeError("fixture recovery write was not released")
            return real_retain(*args, **kwargs)  # type: ignore[arg-type]

        def tracking_thread(
            *args: object,
            **kwargs: object,
        ) -> threading.Thread:
            thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
            if kwargs.get("name") == "claude-review-keychain-recovery":
                recovery_threads.append(thread)
            return thread

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
            **_kwargs: object,
        ):
            assert quiescence_callbacks is not None
            try:
                yield 43211
            finally:
                recovery_error = (
                    providers._bounded_claude_keychain_quiescence_recovery(
                        quiescence_callbacks,
                        bytearray(refreshed_bytes),
                    )
                )
                self.assertTrue(recovery_started.is_set())
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture handler quiescence failure"
                )
                setattr(
                    failure,
                    (
                        "_codex_claude_keychain_handler_"
                        "quiescence_unproven"
                    ),
                    True,
                )
                if recovery_error is not None:
                    providers._add_claude_persistence_note(
                        failure,
                        recovery_error,
                    )
                raise failure

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        try:
            with (
                mock.patch.object(
                    providers,
                    "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    providers,
                    "_retain_claude_macos_refreshed_credential",
                    side_effect=blocking_retain,
                ),
                mock.patch.object(
                    providers.threading,
                    "Thread",
                    side_effect=tracking_thread,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ),
            ):
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
        finally:
            release_recovery.set()
            for thread in recovery_threads:
                thread.join(timeout=2.0)

        self.assertEqual(len(recovery_threads), 1)
        self.assertFalse(recovery_threads[0].is_alive())
        persist_credential.assert_not_called()
        recovery_root = providers._claude_macos_recovery_root(self.review)
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        authentication = report["authentication"]
        reported_paths = tuple(
            pathlib.Path(value)
            for key in (
                "recovery_carrier",
                "recovery_artifact",
                "recovery_cleanup_artifact",
            )
            if isinstance((value := authentication.get(key)), str)
        )
        unreported_carriers = [
            carrier
            for carrier in sorted(recovery_root.glob("claude-carrier-*"))
            if not any(
                reported == carrier or reported.is_relative_to(carrier)
                for reported in reported_paths
            )
        ]
        self.assertEqual(unreported_carriers, [])
        refreshed[:] = b"\x00" * len(refreshed)

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_late_replace_existing_cleans_timed_out_inflight_stage(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-late-existing-replacement-refresh"
        )
        second = bytearray(json.dumps(second_value).encode())
        second_bytes = bytes(second)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        second_commit_started = threading.Event()
        release_second_commit = threading.Event()
        replace_started = threading.Event()
        release_replace = threading.Event()
        callback_results: list[bool] = []
        callback_errors: list[BaseException] = []
        callback_thread: threading.Thread | None = None
        recovery_threads: list[threading.Thread] = []
        real_commit = providers._commit_claude_macos_durable_stage
        real_replace = providers._replace_claude_macos_recovery_credential
        real_thread = threading.Thread
        commit_calls = 0

        def blocking_second_commit(
            review: providers.ReviewWorkspace,
            pending: pathlib.Path,
            acknowledged: pathlib.Path,
            credential: bytearray,
        ) -> pathlib.Path:
            nonlocal commit_calls
            commit_calls += 1
            if commit_calls == 2:
                second_commit_started.set()
                if not release_second_commit.wait(timeout=2.0):
                    raise RuntimeError("fixture second commit was not released")
            return real_commit(review, pending, acknowledged, credential)

        def blocking_replace(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            credential: bytearray,
        ) -> None:
            replace_started.set()
            release_second_commit.set()
            if not release_replace.wait(timeout=2.0):
                raise RuntimeError("fixture recovery replacement was not released")
            real_replace(review, carrier, credential)

        def tracking_thread(
            *args: object,
            **kwargs: object,
        ) -> threading.Thread:
            thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
            if kwargs.get("name") == "claude-review-keychain-recovery":
                recovery_threads.append(thread)
            return thread

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[..., bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            assert update_callback is not None
            assert quiescence_callbacks is not None
            self.assertTrue(update_callback(first))

            def run_second_callback() -> None:
                try:
                    callback_results.append(update_callback(second))
                except BaseException as error:
                    callback_errors.append(error)

            callback_thread = real_thread(target=run_second_callback)
            callback_thread.start()
            self.assertTrue(second_commit_started.wait(timeout=2.0))
            try:
                yield 43211
            finally:
                recovery_error = (
                    providers._bounded_claude_keychain_quiescence_recovery(
                        quiescence_callbacks,
                        bytearray(second_bytes),
                    )
                )
                self.assertTrue(replace_started.is_set())
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture handler quiescence failure"
                )
                setattr(
                    failure,
                    (
                        "_codex_claude_keychain_handler_"
                        "quiescence_unproven"
                    ),
                    True,
                )
                if recovery_error is not None:
                    providers._add_claude_persistence_note(
                        failure,
                        recovery_error,
                    )
                raise failure

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        with (
            mock.patch.object(
                providers,
                "CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS",
                0.05,
            ),
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
                side_effect=blocking_second_commit,
            ),
            mock.patch.object(
                providers,
                "_replace_claude_macos_recovery_credential",
                side_effect=blocking_replace,
            ),
            mock.patch.object(
                providers.threading,
                "Thread",
                side_effect=tracking_thread,
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            try:
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
            finally:
                if callback_thread is not None:
                    callback_thread.join(timeout=2.0)
                release_replace.set()
                release_second_commit.set()
                for recovery_thread in recovery_threads:
                    recovery_thread.join(timeout=2.0)

        self.assertEqual(callback_errors, [])
        self.assertEqual(callback_results, [False])
        self.assertEqual(commit_calls, 2)
        self.assertEqual(len(recovery_threads), 1)
        self.assertFalse(recovery_threads[0].is_alive())
        persist_credential.assert_not_called()
        reported = self.assert_macos_recovery_carrier(
            raised.exception,
            second_bytes,
        )
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            sorted(recovery_root.glob("claude-carrier-*")),
            [reported],
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(reported),
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_unquiescent_shutdown_without_write_does_not_report_recovery_artifact(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        shutdown_error = providers.ClaudeCredentialInspectionInconclusive(
            "fixture handler quiescence failure"
        )
        setattr(
            shutdown_error,
            "_codex_claude_keychain_handler_quiescence_unproven",
            True,
        )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
            **_kwargs: object,
        ):
            assert quiescence_callbacks is not None
            try:
                yield 43211
            finally:
                quiescence_callbacks.abandon()
                self.assertIsNone(quiescence_callbacks.recover(None))
                raise shutdown_error

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        with self.assertRaises(
            providers.ClaudeCredentialInspectionInconclusive,
        ) as raised:
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, shutdown_error)
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])
        persist_credential.assert_not_called()

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_durable_stage_creation_failure_does_not_report_uncreated_carrier(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        creation_error = providers.ClaudeCredentialInspectionInconclusive(
            "injected durable stage creation failure"
        )
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[[bytearray], bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
            **_kwargs: object,
        ):
            assert update_callback is not None
            self.assertFalse(update_callback(refreshed))
            yield 43211

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        with (
            mock.patch.object(
                providers,
                "_retain_claude_macos_refreshed_credential",
                side_effect=creation_error,
            ) as retain,
            mock.patch.object(
                providers,
                "_commit_claude_macos_durable_stage",
            ) as commit,
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, creation_error)
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertNotIn("recovery_carrier", report["authentication"])
        self.assertNotIn("recovery_artifact", report["authentication"])
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(list(recovery_root.glob("claude-carrier-*")), [])
        retain.assert_called_once()
        commit.assert_not_called()
        persist_credential.assert_not_called()

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_latest_durable_carrier_is_verified_before_stale_cleanup(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        _snapshot_is_current: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        latest_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        latest_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-latest-carrier-reverify"
        )
        latest = bytearray(json.dumps(latest_value).encode())
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        select_credential.return_value = selected
        staged_carriers: list[pathlib.Path] = []

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[[bytearray], bool] | None = None,
            **_kwargs: object,
        ):
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(latest))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            staged_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(staged_carriers), 2)
            latest_credential = (
                staged_carriers[-1]
                / "config"
                / providers.CLAUDE_CREDENTIAL_FILE_NAME
            )
            latest_credential.write_bytes(first)
            yield 43211

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                return_value=providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=providers._claude_credential_digest(latest),
                    file_digest=None,
                    file_snapshot=None,
                ),
            ) as persist,
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
            ) as remove,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "latest durable recovery carrier",
            ) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        persist.assert_not_called()
        remove.assert_not_called()
        self.assertEqual(len(staged_carriers), 2)
        self.assertTrue(all(carrier.is_dir() for carrier in staged_carriers))
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        self.assertIsNone(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_artifact",
                None,
            )
        )
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )
        self.assertNotIn("recovery_artifact", report["authentication"])
        for payload in (first, latest):
            payload[:] = b"\x00" * len(payload)

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_latest_durable_reverify_precedes_stale_cleanup_and_host_write(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        _snapshot_is_current: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        latest_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=7200)
        )
        latest_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-latest-carrier-ordering"
        )
        latest = bytearray(json.dumps(latest_value).encode())
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        staged_carriers: list[pathlib.Path] = []
        events: list[str] = []
        finalizing = False

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[[bytearray], bool] | None = None,
            **_kwargs: object,
        ):
            nonlocal finalizing
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(latest))
            recovery_root = providers._claude_macos_recovery_root(self.review)
            staged_carriers.extend(
                sorted(
                    recovery_root.glob(
                        f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                    )
                )
            )
            self.assertEqual(len(staged_carriers), 2)
            yield 43211
            finalizing = True

        real_read = providers._read_claude_macos_recovery_credential
        real_remove = providers._remove_claude_macos_recovery_carrier

        def read_with_order(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
        ) -> bytearray:
            if (
                finalizing
                and staged_carriers
                and carrier == staged_carriers[-1]
                and "reverify-latest" not in events
            ):
                events.append("reverify-latest")
            return real_read(review, carrier)

        def remove_with_order(
            review: providers.ReviewWorkspace,
            carrier: pathlib.Path,
            digest: bytes,
        ) -> None:
            if finalizing and staged_carriers:
                events.append(
                    "remove-latest"
                    if carrier == staged_carriers[-1]
                    else "remove-stale"
                )
            real_remove(review, carrier, digest)

        def persist_with_order(
            *_args: object,
            **_kwargs: object,
        ) -> providers._ClaudeMacOSCarrierSnapshot:
            events.append("persist-host")
            return providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(latest),
                file_digest=None,
                file_snapshot=None,
            )

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_read_claude_macos_recovery_credential",
                side_effect=read_with_order,
            ),
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
                side_effect=remove_with_order,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                side_effect=persist_with_order,
            ),
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertEqual(
            events,
            [
                "reverify-latest",
                "remove-stale",
                "persist-host",
                "remove-latest",
            ],
        )
        self.assertTrue(all(not carrier.exists() for carrier in staged_carriers))
        for payload in (first, latest):
            payload[:] = b"\x00" * len(payload)

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_durable_cleanup_control_flow_stops_before_host_write_or_latest_cleanup(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        _snapshot_is_current: mock.Mock,
    ) -> None:
        interruptions = (
            ("forwarded-signal", providers.ForwardedSignal(signal.SIGTERM)),
            ("keyboard-interrupt", KeyboardInterrupt("fixture interrupt")),
            ("system-exit", SystemExit(19)),
        )

        for label, interruption in interruptions:
            with self.subTest(interruption=label):
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                first = bytearray(
                    oauth_credential_fixture(expires_in_seconds=3600)
                )
                second_value = json.loads(
                    oauth_credential_fixture(expires_in_seconds=7200)
                )
                second_value["claudeAiOauth"]["refreshToken"] = (
                    f"fixture-cleanup-control-flow-{label}"
                )
                second = bytearray(json.dumps(second_value).encode())
                select_credential.return_value = (
                    providers._ClaudeLocalCredential(
                        source="macos-keychain",
                        payload=original,
                        expires_at_ms=0,
                        carrier_snapshot=(
                            providers._ClaudeMacOSCarrierSnapshot(
                                keychain_digest=(
                                    providers._claude_credential_digest(
                                        original
                                    )
                                ),
                                file_digest=None,
                                file_snapshot=None,
                            )
                        ),
                    )
                )
                staged_carriers: list[pathlib.Path] = []

                @contextlib.contextmanager
                def broker(
                    _credential: bytearray,
                    _capability: bytes,
                    *,
                    update_callback: Callable[[bytearray], bool] | None = None,
                    **_kwargs: object,
                ):
                    assert update_callback is not None
                    recovery_root = providers._claude_macos_recovery_root(
                        self.review
                    )
                    before = set(
                        recovery_root.glob(
                            f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                        )
                    )
                    self.assertTrue(update_callback(first))
                    self.assertTrue(update_callback(second))
                    staged_carriers.extend(
                        sorted(
                            set(
                                recovery_root.glob(
                                    f"{providers.CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}*"
                                )
                            )
                            - before
                        )
                    )
                    yield 43211

                credential_server.side_effect = broker
                updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=providers._claude_credential_digest(
                        second
                    ),
                    file_digest=None,
                    file_snapshot=None,
                )
                with (
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                        return_value=updated_snapshot,
                    ) as persist,
                    mock.patch.object(
                        providers,
                        "_remove_claude_macos_recovery_carrier",
                        side_effect=interruption,
                    ) as remove,
                    self.assertRaises(type(interruption)) as raised,
                ):
                    with self.claude_keychain_runtime(
                        self.review,
                        {},
                        self.claude_refresh_lock_protocol,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(staged_carriers), 2)
                self.assertEqual(
                    (persist.call_count, remove.call_count),
                    (0, 1),
                )
                self.assertEqual(
                    remove.call_args.args[1],
                    staged_carriers[0],
                )
                self.assertTrue(staged_carriers[-1].is_dir())
                self.assertEqual(
                    getattr(
                        interruption,
                        "_codex_claude_retained_credential_carrier",
                        None,
                    ),
                    str(staged_carriers[-1]),
                )
                self.assertEqual(
                    getattr(
                        interruption,
                        "_codex_claude_retained_cleanup_artifact",
                        None,
                    ),
                    str(staged_carriers[0]),
                )

    def test_staged_cleanup_control_flow_reports_unvisited_carrier_scope(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        updates: list[bytearray] = []
        for generation in range(1, 5):
            value = json.loads(
                oauth_credential_fixture(expires_in_seconds=3600 * generation)
            )
            value["claudeAiOauth"]["refreshToken"] = (
                f"fixture-staged-unvisited-cleanup-{generation}"
            )
            updates.append(bytearray(json.dumps(value).encode()))
        latest_bytes = bytes(updates[-1])
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        staged_carriers: list[pathlib.Path] = []
        interruption = providers.ForwardedSignal(signal.SIGTERM)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            recovery_root = providers._claude_macos_recovery_root(self.review)
            before = set(recovery_root.glob("claude-carrier-*"))
            for update in updates:
                self.assertTrue(update_callback(update))
            staged_carriers.extend(
                sorted(
                    set(recovery_root.glob("claude-carrier-*")) - before
                )
            )
            self.assertEqual(len(staged_carriers), 4)
            for update in updates:
                update[:] = b"\x00" * len(update)
            yield 43211

        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_remove_claude_macos_recovery_carrier",
                side_effect=interruption,
            ) as remove,
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
            ) as persist,
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, interruption)
        self.assertEqual(remove.call_count, 1)
        self.assertEqual(remove.call_args.args[1], staged_carriers[0])
        self.assertTrue(staged_carriers[1].is_dir())
        self.assertTrue(staged_carriers[2].is_dir())
        self.assertTrue(staged_carriers[3].is_dir())
        persist.assert_not_called()
        recovery_root = providers._claude_macos_recovery_root(self.review)
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str(recovery_root),
        )
        latest_carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            latest_bytes,
        )
        self.assertEqual(latest_carrier, staged_carriers[-1])
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertIn(
            "recovery_cleanup_artifact",
            report["authentication"],
            report,
        )
        self.assertEqual(
            report["authentication"]["recovery_cleanup_artifact"],
            str(recovery_root),
        )

    def test_cleanup_control_flow_preserves_identity_when_scope_resolution_fails(
        self,
    ) -> None:
        interruptions = (
            ("forwarded-signal", providers.ForwardedSignal(signal.SIGTERM)),
            ("keyboard-interrupt", KeyboardInterrupt("fixture interrupt")),
            ("system-exit", SystemExit(31)),
        )
        real_recovery_root = providers._claude_macos_recovery_root
        real_attach = providers._attach_claude_credential_cleanup_failure

        for cleanup_mode in ("staged", "non-staged"):
            for label, interruption in interruptions:
                with self.subTest(
                    cleanup_mode=cleanup_mode,
                    interruption=label,
                ):
                    original = bytearray(
                        oauth_credential_fixture(expires_in_seconds=-60)
                    )
                    updates: list[bytearray] = []
                    for generation in range(1, 5):
                        value = json.loads(
                            oauth_credential_fixture(
                                expires_in_seconds=3600 * generation
                            )
                        )
                        value["claudeAiOauth"]["refreshToken"] = (
                            "fixture-scope-resolution-"
                            f"{cleanup_mode}-{label}-{generation}"
                        )
                        updates.append(bytearray(json.dumps(value).encode()))
                    selected = providers._ClaudeLocalCredential(
                        source="macos-keychain",
                        payload=original,
                        expires_at_ms=0,
                        carrier_snapshot=(
                            providers._ClaudeMacOSCarrierSnapshot(
                                keychain_digest=(
                                    providers._claude_credential_digest(
                                        original
                                    )
                                ),
                                file_digest=None,
                                file_snapshot=None,
                            )
                        ),
                    )
                    staged_carriers: list[pathlib.Path] = []
                    cleanup_started = False
                    scope_failure = OSError(
                        "injected recovery scope resolution failure"
                    )

                    def guarded_recovery_root(
                        review: providers.ReviewWorkspace,
                    ) -> pathlib.Path:
                        if cleanup_started:
                            raise scope_failure
                        return real_recovery_root(review)

                    def interrupt_cleanup(
                        _review: providers.ReviewWorkspace,
                        _carrier: pathlib.Path,
                        _digest: bytes,
                    ) -> None:
                        nonlocal cleanup_started
                        cleanup_started = True
                        raise interruption

                    @contextlib.contextmanager
                    def broker(
                        _credential: bytearray,
                        _capability: bytes,
                        *,
                        update_callback: Callable[..., bool] | None = None,
                        **_kwargs: object,
                    ):
                        assert update_callback is not None
                        recovery_root = real_recovery_root(self.review)
                        before = set(
                            recovery_root.glob("claude-carrier-*")
                        )
                        expected_results = (
                            (True, True, True, True)
                            if cleanup_mode == "staged"
                            else (True, True, True, False)
                        )
                        actual_results = tuple(
                            update_callback(update) for update in updates
                        )
                        self.assertEqual(actual_results, expected_results)
                        staged_carriers.extend(
                            sorted(
                                set(
                                    recovery_root.glob("claude-carrier-*")
                                )
                                - before
                            )
                        )
                        self.assertEqual(
                            len(staged_carriers),
                            4,
                        )
                        yield 43211

                    common.write_json(
                        self.review.container_dir / "claude-runtime.json",
                        {"authentication": {}, "phase": "runtime-launching"},
                    )
                    generation_limit = 5 if cleanup_mode == "staged" else 4
                    with (
                        mock.patch.object(
                            providers,
                            "_select_claude_macos_credential",
                            return_value=selected,
                        ),
                        mock.patch.object(
                            providers,
                            "_claude_keychain_credential_server",
                            side_effect=broker,
                        ),
                        mock.patch.object(
                            providers,
                            "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                            generation_limit,
                        ),
                        mock.patch.object(
                            providers,
                            "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                            sum(len(update) for update in updates)
                            + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
                        ),
                        mock.patch.object(
                            providers,
                            "_remove_claude_macos_recovery_carrier",
                            side_effect=interrupt_cleanup,
                        ) as remove,
                        mock.patch.object(
                            providers,
                            "_claude_macos_recovery_root",
                            side_effect=guarded_recovery_root,
                        ),
                        mock.patch.object(
                            providers,
                            "_attach_claude_credential_cleanup_failure",
                            wraps=real_attach,
                        ) as attach,
                        mock.patch.object(
                            providers,
                            "_persist_claude_macos_refreshed_credential",
                        ) as persist,
                        self.assertRaises(type(interruption)) as raised,
                    ):
                        with self.claude_keychain_runtime(
                            self.review,
                            {},
                            self.claude_refresh_lock_protocol,
                        ):
                            pass

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(remove.call_count, 1)
                    persist.assert_not_called()
                    self.assertTrue(
                        any(
                            call.args == (interruption, scope_failure)
                            for call in attach.call_args_list
                        ),
                        attach.call_args_list,
                    )

    def test_multi_path_cleanup_scope_control_flow_becomes_primary(
        self,
    ) -> None:
        scope_interruption_factories: tuple[
            tuple[str, Callable[[], BaseException]], ...
        ] = (
            (
                "forwarded-signal",
                lambda: providers.ForwardedSignal(signal.SIGTERM),
            ),
            (
                "keyboard-interrupt",
                lambda: KeyboardInterrupt("fixture scope interrupt"),
            ),
            ("system-exit", lambda: SystemExit(37)),
        )
        real_recovery_root = providers._claude_macos_recovery_root

        def run_case(
            abandoned_primary: bool,
            label: str,
            scope_interruption: BaseException,
        ) -> None:
            with self.subTest(
                    abandoned_primary=abandoned_primary,
                    interruption=label,
            ):
                marked_primary = (
                    providers.ClaudeCredentialInspectionInconclusive(
                        "fixture abandoned persistence-marked primary"
                    )
                    if abandoned_primary
                    else None
                )
                if marked_primary is not None:
                    setattr(
                        marked_primary,
                        "_codex_claude_refresh_persistence_failed",
                        True,
                    )
                original = bytearray(
                    oauth_credential_fixture(expires_in_seconds=-60)
                )
                updates: list[bytearray] = []
                for generation in range(1, 5):
                    value = json.loads(
                        oauth_credential_fixture(
                            expires_in_seconds=3600 * generation
                        )
                    )
                    value["claudeAiOauth"]["refreshToken"] = (
                        f"fixture-multi-path-scope-{label}-{generation}"
                    )
                    updates.append(bytearray(json.dumps(value).encode()))
                selected = providers._ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=original,
                    expires_at_ms=0,
                    carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                        keychain_digest=(
                            providers._claude_credential_digest(original)
                        ),
                        file_digest=None,
                        file_snapshot=None,
                    ),
                )
                staged_carriers: list[pathlib.Path] = []
                cleanup_errors: list[OSError] = []
                remove_calls = 0
                scope_resolution_should_fail = False
                captured_quiescence_callbacks: (
                    providers._ClaudeKeychainQuiescenceCallbacks | None
                ) = None

                def guarded_recovery_root(
                    review: providers.ReviewWorkspace,
                ) -> pathlib.Path:
                    if scope_resolution_should_fail:
                        if abandoned_primary:
                            assert captured_quiescence_callbacks is not None
                            captured_quiescence_callbacks.abandon()
                        raise scope_interruption
                    return real_recovery_root(review)

                def fail_two_cleanup_paths(
                    _review: providers.ReviewWorkspace,
                    carrier: pathlib.Path,
                    _digest: bytes,
                ) -> None:
                    nonlocal remove_calls
                    nonlocal scope_resolution_should_fail
                    remove_calls += 1
                    if remove_calls > 2:
                        return
                    cleanup_error = OSError(
                        f"injected cleanup failure {remove_calls}"
                    )
                    providers._mark_claude_macos_recovery_cleanup_artifact(
                        cleanup_error,
                        carrier,
                    )
                    cleanup_errors.append(cleanup_error)
                    if remove_calls == 2:
                        scope_resolution_should_fail = True
                    raise cleanup_error

                @contextlib.contextmanager
                def broker(
                    _credential: bytearray,
                    _capability: bytes,
                    *,
                    update_callback: Callable[..., bool] | None = None,
                    quiescence_callbacks: (
                        providers._ClaudeKeychainQuiescenceCallbacks | None
                    ) = None,
                    **_kwargs: object,
                ):
                    nonlocal captured_quiescence_callbacks
                    assert update_callback is not None
                    assert quiescence_callbacks is not None
                    captured_quiescence_callbacks = quiescence_callbacks
                    recovery_root = real_recovery_root(self.review)
                    before = set(recovery_root.glob("claude-carrier-*"))
                    for update in updates:
                        self.assertTrue(update_callback(update))
                    staged_carriers.extend(
                        sorted(
                            set(recovery_root.glob("claude-carrier-*"))
                            - before
                        )
                    )
                    self.assertEqual(len(staged_carriers), 4)
                    try:
                        yield 43211
                    finally:
                        if marked_primary is not None:
                            raise marked_primary

                updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=providers._claude_credential_digest(
                        updates[-1]
                    ),
                    file_digest=None,
                    file_snapshot=None,
                )
                common.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {"authentication": {}, "phase": "runtime-launching"},
                )
                with (
                    mock.patch.object(
                        providers,
                        "_select_claude_macos_credential",
                        return_value=selected,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_keychain_credential_server",
                        side_effect=broker,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS",
                        5,
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES",
                        sum(len(update) for update in updates)
                        + providers.CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
                    ),
                    mock.patch.object(
                        providers,
                        "_remove_claude_macos_recovery_carrier",
                        side_effect=fail_two_cleanup_paths,
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_macos_recovery_root",
                        side_effect=guarded_recovery_root,
                    ),
                    mock.patch.object(
                        providers,
                        "_persist_claude_macos_refreshed_credential",
                        return_value=updated_snapshot,
                    ) as persist,
                    self.assertRaises(type(scope_interruption)) as raised,
                ):
                    with self.claude_keychain_runtime(
                        self.review,
                        {},
                        self.claude_refresh_lock_protocol,
                    ):
                        pass

                self.assertIs(raised.exception, scope_interruption)
                if marked_primary is not None:
                    self.assertIsNot(raised.exception, marked_primary)
                self.assertEqual(len(cleanup_errors), 2)
                self.assertGreaterEqual(remove_calls, 2)
                persist.assert_called_once()
                self.assertTrue(
                    getattr(
                        scope_interruption,
                        "_codex_claude_refresh_persistence_failed",
                        False,
                    )
                )
                self.assert_persistence_diagnostic_visible(scope_interruption)

        for abandoned_primary in (False, True):
            for label, interruption_factory in scope_interruption_factories:
                run_case(
                    abandoned_primary,
                    label,
                    interruption_factory(),
                )

    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_unquiescent_handler_retains_latest_refreshed_credential(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        callback_staged = threading.Event()
        release_handler = threading.Event()
        callback_results: list[bool] = []
        callback_thread: threading.Thread | None = None

        @contextlib.contextmanager
        def broker(
            _credential: bytearray,
            _capability: bytes,
            *,
            update_callback: Callable[[bytearray], bool] | None = None,
            quiescence_callbacks: (
                providers._ClaudeKeychainQuiescenceCallbacks | None
            ) = None,
        ):
            nonlocal callback_thread
            self.assertIsNotNone(update_callback)
            self.assertIsNotNone(quiescence_callbacks)

            def run_handler() -> None:
                assert update_callback is not None
                callback_results.append(update_callback(refreshed))
                callback_staged.set()
                if not release_handler.wait(timeout=5.0):
                    raise RuntimeError("fixture handler was not released")
                refreshed[:] = b"\x00" * len(refreshed)

            try:
                callback_thread = threading.Thread(
                    target=run_handler,
                )
                callback_thread.start()
                self.assertTrue(callback_staged.wait(timeout=2.0))
                yield 43211
            finally:
                assert quiescence_callbacks is not None
                persistence_error = (
                    providers._bounded_claude_keychain_quiescence_recovery(
                        quiescence_callbacks,
                        bytearray(refreshed),
                    )
                )
                self.assertEqual(callback_results, [True])
                failure = providers.ClaudeCredentialInspectionInconclusive(
                    "fixture handler quiescence failure"
                )
                setattr(
                    failure,
                    (
                        "_codex_claude_keychain_handler_"
                        "quiescence_unproven"
                    ),
                    True,
                )
                if persistence_error is not None:
                    providers._add_claude_persistence_note(
                        failure,
                        persistence_error,
                    )
                raise failure

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )

        try:
            with self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised:
                with self.claude_keychain_runtime(
                    self.review,
                    {},
                    self.claude_refresh_lock_protocol,
                ):
                    pass
            persist_credential.assert_not_called()
        finally:
            release_handler.set()
            if callback_thread is not None:
                callback_thread.join(timeout=2.0)

        carrier = self.assert_macos_recovery_carrier(
            raised.exception,
            refreshed_bytes,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )
        self.assertEqual(original, b"\x00" * len(original))
        self.assertEqual(refreshed, b"\x00" * len(refreshed))
        self.assertIsNotNone(callback_thread)
        assert callback_thread is not None
        self.assertFalse(callback_thread.is_alive())
        persist_credential.assert_not_called()

    @mock.patch.object(
        providers,
        "_persist_claude_macos_refreshed_credential",
        return_value=None,
    )
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_refresh_persistence_failure_does_not_override_primary_error(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        credential_server.side_effect = broker
        primary = providers.ReviewTimeoutError("primary review timeout")
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with self.assertRaises(providers.ReviewTimeoutError) as raised:
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                raise primary

        self.assertIs(raised.exception, primary)
        persist_credential.assert_called_once()
        notes = getattr(primary, "__notes__", ())
        if notes:
            self.assertTrue(
                any("persistence also failed" in note for note in notes)
            )
        carrier = self.assert_macos_recovery_carrier(
            primary,
            refreshed_bytes,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_refresh_persistence_signal_overrides_primary_error(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        credential_server.side_effect = broker
        primary = providers.ReviewTimeoutError("primary review timeout")
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                raise primary

        self.assertIs(raised.exception, forwarded)
        carrier = self.assert_macos_recovery_carrier(
            forwarded,
            refreshed_bytes,
        )
        self.assertIn(str(carrier), forwarded.detail or "")
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_refresh_persistence_signal_without_body_error_reports_carrier(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        refreshed_bytes = bytes(refreshed)
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            refreshed[:] = b"\x00" * len(refreshed)
            yield 43211

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "runtime-launching"},
        )
        with (
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                pass

        self.assertIs(raised.exception, forwarded)
        carrier = self.assert_macos_recovery_carrier(
            forwarded,
            refreshed_bytes,
        )
        self.assertIn(str(carrier), forwarded.detail or "")
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    @mock.patch.object(
        providers,
        "_claude_macos_carrier_snapshot_is_current",
        return_value=True,
    )
    @mock.patch.object(providers, "_persist_claude_macos_refreshed_credential")
    @mock.patch.object(providers, "_claude_keychain_credential_server")
    @mock.patch.object(providers, "_select_claude_macos_credential")
    def test_final_runtime_persists_latest_rotation_after_quiescence(
        self,
        select_credential: mock.Mock,
        credential_server: mock.Mock,
        persist_credential: mock.Mock,
        snapshot_is_current: mock.Mock,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        original_bytes = bytes(original)
        first = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        second_value = json.loads(oauth_credential_fixture(expires_in_seconds=7200))
        second_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-second-rotated-refresh-value"
        )
        second = bytearray(json.dumps(second_value).encode())
        initial_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=None,
            file_snapshot=None,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                original
            ),
        )
        second_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(second),
            file_digest=None,
            file_snapshot=None,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(second),
        )
        select_credential.return_value = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=initial_snapshot,
        )
        observed_baselines: list[bytes] = []
        observed_updates: list[bytes] = []

        def persist(*args: object) -> providers._ClaudeMacOSCarrierSnapshot:
            updated = args[2]
            baseline = args[3]
            assert isinstance(updated, bytearray)
            assert isinstance(baseline, bytearray)
            observed_updates.append(bytes(updated))
            observed_baselines.append(bytes(baseline))
            return second_snapshot

        persist_credential.side_effect = persist

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(first))
            self.assertTrue(update_callback(second))
            yield 43211

        credential_server.side_effect = broker
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}, "phase": "pending"},
        )

        with self.claude_keychain_runtime(
            self.review,
            {},
            self.claude_refresh_lock_protocol,
        ):
            pass

        self.assertEqual(observed_updates, [bytes(second)])
        self.assertEqual(observed_baselines, [original_bytes])
        snapshot_is_current.assert_called_once_with(
            self.review,
            second_snapshot,
            self.claude_refresh_lock_protocol,
        )
        first[:] = b"\x00" * len(first)
        second[:] = b"\x00" * len(second)

    def test_same_refresh_token_dual_write_uses_each_carrier_baseline(self) -> None:
        keychain = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        file_credential = bytearray(oauth_credential_fixture(expires_in_seconds=120))
        refreshed_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-dual-rotated-refresh-value"
        )
        refreshed = bytearray(json.dumps(refreshed_value).encode())
        file_snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(keychain),
            file_digest=providers._claude_credential_digest(file_credential),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                keychain
            ),
            file_refresh_digest=providers._claude_credential_refresh_digest(
                file_credential
            ),
        )
        selected = providers._ClaudeLocalCredential(
            source="pwd-home-credential-file",
            payload=bytearray(file_credential),
            expires_at_ms=0,
            file_snapshot=file_snapshot,
            carrier_snapshot=carrier_snapshot,
        )
        lease = mock.Mock(spec=["assert_held"])
        expected_by_source: dict[str, bytes] = {}
        refreshed_digest = providers._claude_credential_digest(refreshed)
        updated_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=refreshed_digest,
            file_digest=refreshed_digest,
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                refreshed
            ),
            file_refresh_digest=providers._claude_credential_refresh_digest(refreshed),
        )

        def write_file(*args: object, **_kwargs: object) -> bool:
            expected = args[2]
            assert isinstance(expected, bytearray)
            expected_by_source["file"] = bytes(expected)
            return True

        def write_keychain(*args: object, **_kwargs: object) -> bool:
            expected = args[2]
            assert isinstance(expected, bytearray)
            expected_by_source["keychain"] = bytes(expected)
            return True

        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                return_value=bytearray(keychain),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                return_value=(bytearray(file_credential), file_snapshot),
            ),
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
                side_effect=write_file,
            ),
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
                side_effect=write_keychain,
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_carrier_snapshot",
                return_value=updated_snapshot,
            ),
        ):
            result = providers._persist_claude_macos_refreshed_credential(
                self.review,
                selected,
                refreshed,
                selected.payload,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            )

        self.assertIs(result, updated_snapshot)
        self.assertEqual(expected_by_source["keychain"], bytes(keychain))
        self.assertEqual(expected_by_source["file"], bytes(file_credential))
        for payload in (keychain, file_credential, refreshed, selected.payload):
            payload[:] = b"\x00" * len(payload)

    def test_keychain_write_forwarded_signal_is_not_reconciled(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        refreshed_value = json.loads(
            oauth_credential_fixture(expires_in_seconds=3600)
        )
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-keychain-forwarded-signal-refresh"
        )
        refreshed = bytearray(json.dumps(refreshed_value).encode())
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=None,
            file_snapshot=None,
            keychain_refresh_digest=(
                providers._claude_credential_refresh_digest(original)
            ),
            file_refresh_digest=None,
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=bytearray(original),
            expires_at_ms=0,
            carrier_snapshot=carrier_snapshot,
        )
        lease = mock.Mock(spec=["assert_held"])
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                return_value=bytearray(original),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                return_value=None,
            ),
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
                side_effect=forwarded,
            ) as write_keychain,
            mock.patch.object(
                providers,
                "_read_claude_macos_carrier_snapshot",
            ) as readback,
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._persist_claude_macos_refreshed_credential(
                self.review,
                selected,
                refreshed,
                selected.payload,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            )

        self.assertIs(raised.exception, forwarded)
        write_keychain.assert_called_once()
        readback.assert_not_called()
        for payload in (original, refreshed, selected.payload):
            payload[:] = b"\x00" * len(payload)

    def test_dual_write_reconciles_keychain_result_before_pausing(self) -> None:
        cases = (
            (
                "ambiguous-success",
                (False,),
                ("complete",),
                1,
                False,
            ),
            (
                "bounded-retry",
                (False, True),
                ("partial", "complete"),
                2,
                False,
            ),
            (
                "unresolved-partial",
                (False, False),
                ("partial", "partial"),
                2,
                True,
            ),
        )
        for (
            label,
            keychain_results,
            readback_states,
            expected_keychain_calls,
            expect_pause,
        ) in cases:
            with self.subTest(label=label):
                keychain = bytearray(oauth_credential_fixture(expires_in_seconds=60))
                file_credential = bytearray(
                    oauth_credential_fixture(expires_in_seconds=120)
                )
                refreshed_value = json.loads(
                    oauth_credential_fixture(expires_in_seconds=3600)
                )
                refreshed_value["claudeAiOauth"]["refreshToken"] = (
                    "fixture-dual-reconciled-refresh-value"
                )
                refreshed = bytearray(json.dumps(refreshed_value).encode())
                original_file_snapshot = providers._ClaudeCredentialFileSnapshot(
                    home=self.claude_pwd_home,
                    home_identity=(1,),
                    config_identity=(2,),
                    file_identity=(3,),
                )
                refreshed_file_snapshot = providers._ClaudeCredentialFileSnapshot(
                    home=self.claude_pwd_home,
                    home_identity=(1,),
                    config_identity=(2,),
                    file_identity=(4,),
                )
                carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=providers._claude_credential_digest(keychain),
                    file_digest=providers._claude_credential_digest(file_credential),
                    file_snapshot=original_file_snapshot,
                    keychain_refresh_digest=(
                        providers._claude_credential_refresh_digest(keychain)
                    ),
                    file_refresh_digest=(
                        providers._claude_credential_refresh_digest(file_credential)
                    ),
                )
                refreshed_digest = providers._claude_credential_digest(refreshed)
                refreshed_refresh_digest = (
                    providers._claude_credential_refresh_digest(refreshed)
                )
                partial_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=carrier_snapshot.keychain_digest,
                    file_digest=refreshed_digest,
                    file_snapshot=refreshed_file_snapshot,
                    keychain_refresh_digest=carrier_snapshot.keychain_refresh_digest,
                    file_refresh_digest=refreshed_refresh_digest,
                )
                complete_snapshot = providers._ClaudeMacOSCarrierSnapshot(
                    keychain_digest=refreshed_digest,
                    file_digest=refreshed_digest,
                    file_snapshot=refreshed_file_snapshot,
                    keychain_refresh_digest=refreshed_refresh_digest,
                    file_refresh_digest=refreshed_refresh_digest,
                )
                readbacks = tuple(
                    complete_snapshot if state == "complete" else partial_snapshot
                    for state in readback_states
                )
                selected = providers._ClaudeLocalCredential(
                    source="pwd-home-credential-file",
                    payload=bytearray(file_credential),
                    expires_at_ms=0,
                    file_snapshot=original_file_snapshot,
                    carrier_snapshot=carrier_snapshot,
                )
                lease = mock.Mock(spec=["assert_held"])
                observed_keychain_baselines: list[bytes] = []
                keychain_result_iterator = iter(keychain_results)

                def write_keychain_side_effect(
                    *args: object,
                    **_kwargs: object,
                ) -> bool:
                    baseline = args[2]
                    assert isinstance(baseline, bytearray)
                    observed_keychain_baselines.append(bytes(baseline))
                    return next(keychain_result_iterator)

                with (
                    mock.patch.object(
                        providers,
                        "_claude_macos_carrier_coordination",
                        return_value=contextlib.nullcontext(lease),
                    ),
                    mock.patch.object(
                        providers,
                        "_read_claude_keychain_credential",
                        return_value=bytearray(keychain),
                    ),
                    mock.patch.object(
                        providers,
                        "_read_claude_macos_file_credential",
                        return_value=(
                            bytearray(file_credential),
                            original_file_snapshot,
                        ),
                    ),
                    mock.patch.object(
                        providers,
                        "_write_claude_file_credential",
                        return_value=True,
                    ) as write_file,
                    mock.patch.object(
                        providers,
                        "_write_claude_keychain_credential",
                        side_effect=write_keychain_side_effect,
                    ) as write_keychain,
                    mock.patch.object(
                        providers,
                        "_read_claude_macos_carrier_snapshot",
                        side_effect=readbacks,
                    ),
                ):
                    if expect_pause:
                        with self.assertRaisesRegex(
                            providers.ClaudeCredentialInspectionInconclusive,
                            "refreshed file carrier was preserved",
                        ):
                            providers._persist_claude_macos_refreshed_credential(
                                self.review,
                                selected,
                                refreshed,
                                selected.payload,
                                carrier_snapshot,
                                self.claude_refresh_lock_protocol,
                            )
                    else:
                        result = providers._persist_claude_macos_refreshed_credential(
                            self.review,
                            selected,
                            refreshed,
                            selected.payload,
                            carrier_snapshot,
                            self.claude_refresh_lock_protocol,
                        )
                        self.assertIs(result, complete_snapshot)

                write_file.assert_called_once()
                self.assertEqual(write_keychain.call_count, expected_keychain_calls)
                self.assertEqual(
                    observed_keychain_baselines,
                    [bytes(keychain)] * expected_keychain_calls,
                )
                for call in write_keychain.call_args_list:
                    self.assertIs(call.kwargs["coordinated_refresh_lock"], lease)
                for payload in (
                    keychain,
                    file_credential,
                    refreshed,
                    selected.payload,
                ):
                    payload[:] = b"\x00" * len(payload)

    def test_keychain_only_ambiguous_write_preserves_unselected_file(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        file_value = json.loads(oauth_credential_fixture(expires_in_seconds=30))
        file_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-unselected-file-refresh-value"
        )
        file_credential = bytearray(json.dumps(file_value).encode())
        file_snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        refreshed_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-keychain-only-rotated-refresh-value"
        )
        refreshed = bytearray(json.dumps(refreshed_value).encode())
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=providers._claude_credential_digest(file_credential),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                original
            ),
            file_refresh_digest=providers._claude_credential_refresh_digest(
                file_credential
            ),
        )
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=bytearray(original),
            expires_at_ms=0,
            carrier_snapshot=carrier_snapshot,
        )
        refreshed_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(refreshed),
            file_digest=carrier_snapshot.file_digest,
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                refreshed
            ),
            file_refresh_digest=carrier_snapshot.file_refresh_digest,
        )
        lease = mock.Mock(spec=["assert_held"])

        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                return_value=bytearray(original),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                return_value=(bytearray(file_credential), file_snapshot),
            ),
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
            ) as write_file,
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
                return_value=False,
            ) as write_keychain,
            mock.patch.object(
                providers,
                "_read_claude_macos_carrier_snapshot",
                return_value=refreshed_snapshot,
            ),
        ):
            result = providers._persist_claude_macos_refreshed_credential(
                self.review,
                selected,
                refreshed,
                selected.payload,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            )

        self.assertIs(result, refreshed_snapshot)
        write_file.assert_not_called()
        write_keychain.assert_called_once()
        for payload in (original, file_credential, refreshed, selected.payload):
            payload[:] = b"\x00" * len(payload)

    def test_dual_write_does_not_overwrite_unexpected_keychain_readback(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        refreshed_value = json.loads(oauth_credential_fixture(expires_in_seconds=3600))
        refreshed_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-dual-unexpected-refresh-value"
        )
        refreshed = bytearray(json.dumps(refreshed_value).encode())
        third_party = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        third_party_value = json.loads(third_party)
        third_party_value["claudeAiOauth"]["refreshToken"] = (
            "fixture-third-party-refresh-value"
        )
        third_party[:] = json.dumps(third_party_value).encode()
        file_snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=providers._claude_credential_digest(original),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                original
            ),
            file_refresh_digest=providers._claude_credential_refresh_digest(original),
        )
        selected = providers._ClaudeLocalCredential(
            source="pwd-home-credential-file",
            payload=bytearray(original),
            expires_at_ms=0,
            file_snapshot=file_snapshot,
            carrier_snapshot=carrier_snapshot,
        )
        refreshed_digest = providers._claude_credential_digest(refreshed)
        unexpected_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(third_party),
            file_digest=refreshed_digest,
            file_snapshot=file_snapshot,
            keychain_refresh_digest=providers._claude_credential_refresh_digest(
                third_party
            ),
            file_refresh_digest=providers._claude_credential_refresh_digest(refreshed),
        )
        lease = mock.Mock(spec=["assert_held"])

        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_read_claude_keychain_credential",
                return_value=bytearray(original),
            ),
            mock.patch.object(
                providers,
                "_read_claude_macos_file_credential",
                return_value=(bytearray(original), file_snapshot),
            ),
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
                return_value=True,
            ),
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
                return_value=False,
            ) as write_keychain,
            mock.patch.object(
                providers,
                "_read_claude_macos_carrier_snapshot",
                return_value=unexpected_snapshot,
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "changed unexpectedly",
            ),
        ):
            providers._persist_claude_macos_refreshed_credential(
                self.review,
                selected,
                refreshed,
                selected.payload,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            )

        write_keychain.assert_called_once()
        for payload in (original, refreshed, third_party, selected.payload):
            payload[:] = b"\x00" * len(payload)

    def test_same_refresh_token_preflights_keychain_size_before_dual_write(
        self,
    ) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        file_snapshot = providers._ClaudeCredentialFileSnapshot(
            home=self.claude_pwd_home,
            home_identity=(1,),
            config_identity=(2,),
            file_identity=(3,),
        )
        refresh_digest = providers._claude_credential_refresh_digest(original)
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=providers._claude_credential_digest(original),
            file_digest=providers._claude_credential_digest(original),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=refresh_digest,
            file_refresh_digest=refresh_digest,
        )
        selected = providers._ClaudeLocalCredential(
            source="pwd-home-credential-file",
            payload=bytearray(original),
            expires_at_ms=0,
            file_snapshot=file_snapshot,
            carrier_snapshot=carrier_snapshot,
        )
        oversized_value = json.loads(oauth_credential_fixture())
        oversized_value["padding"] = "x" * (
            providers.CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES
        )
        oversized = bytearray(json.dumps(oversized_value).encode())

        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
            ) as coordinate,
            mock.patch.object(
                providers,
                "_write_claude_file_credential",
            ) as write_file,
            mock.patch.object(
                providers,
                "_write_claude_keychain_credential",
            ) as write_keychain,
        ):
            self.assertIsNone(
                providers._persist_claude_macos_refreshed_credential(
                    self.review,
                    selected,
                    oversized,
                    selected.payload,
                    carrier_snapshot,
                    self.claude_refresh_lock_protocol,
                )
            )

        coordinate.assert_not_called()
        write_file.assert_not_called()
        write_keychain.assert_not_called()
        for payload in (original, oversized, selected.payload):
            payload[:] = b"\x00" * len(payload)

    def test_runtime_body_error_yields_to_persistence_control_flow(self) -> None:
        original = bytearray(oauth_credential_fixture(expires_in_seconds=-60))
        refreshed = bytearray(oauth_credential_fixture(expires_in_seconds=3600))
        selected = providers._ClaudeLocalCredential(
            source="macos-keychain",
            payload=original,
            expires_at_ms=0,
            carrier_snapshot=providers._ClaudeMacOSCarrierSnapshot(
                keychain_digest=providers._claude_credential_digest(original),
                file_digest=None,
                file_snapshot=None,
            ),
        )

        @contextlib.contextmanager
        def broker(_credential, _capability, *, update_callback=None, **_kwargs):
            assert update_callback is not None
            self.assertTrue(update_callback(refreshed))
            yield 43211

        with (
            mock.patch.object(
                providers,
                "_select_claude_macos_credential",
                return_value=selected,
            ),
            mock.patch.object(
                providers,
                "_claude_keychain_credential_server",
                side_effect=broker,
            ),
            mock.patch.object(
                providers,
                "_persist_claude_macos_refreshed_credential",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            with self.claude_keychain_runtime(
                self.review,
                {},
                self.claude_refresh_lock_protocol,
            ):
                raise ValueError("fixture body failure")

        refreshed[:] = b"\x00" * len(refreshed)

    def test_final_macos_snapshot_unsafe_change_is_inconclusive(self) -> None:
        carrier_snapshot = providers._ClaudeMacOSCarrierSnapshot(
            keychain_digest=b"digest",
            file_digest=None,
            file_snapshot=None,
        )
        lease = mock.Mock(spec=["assert_held"])
        with (
            mock.patch.object(
                providers,
                "_claude_macos_carrier_coordination",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(
                providers,
                "_claude_macos_carriers_match",
                side_effect=providers.ClaudeCredentialUnsafe("fixture unsafe change"),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "became unsafe",
            ),
        ):
            providers._claude_macos_carrier_snapshot_is_current(
                self.review,
                carrier_snapshot,
                self.claude_refresh_lock_protocol,
            )

    @mock.patch.object(
        providers,
        "CLAUDE_KEYCHAIN_CLIENT",
        pathlib.Path("/missing/security"),
    )
    def test_missing_keychain_client_during_prepare_is_unavailable(self) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeKeychainBrokerUnavailable,
            "requires /usr/bin/security",
        ):
            self.prepare_claude_keychain_broker(
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "PATH": "/usr/bin",
                },
            )

    @mock.patch.object(
        providers,
        "CLAUDE_KEYCHAIN_BROKER_COMPILER",
        pathlib.Path("/missing/clang"),
    )
    def test_missing_keychain_broker_compiler_is_unavailable(self) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeKeychainBrokerUnavailable,
            "requires /usr/bin/clang",
        ):
            self.prepare_claude_keychain_broker(
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "PATH": "/usr/bin",
                },
            )

    @mock.patch.object(
        providers,
        "CLAUDE_KEYCHAIN_BROKER_COMPILER",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_keychain_broker_compile_failure_is_inconclusive(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("clang",),
            returncode=1,
            stdout=b"",
            stderr=b"toolchain unavailable",
        )

        with self.assertRaisesRegex(
            providers.ClaudeExecutableInspectionInconclusive,
            "toolchain unavailable",
        ):
            self.prepare_claude_keychain_broker(
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "PATH": "/usr/bin",
                },
            )

    @mock.patch.object(
        providers,
        "CLAUDE_KEYCHAIN_BROKER_COMPILER",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(
        providers,
        "run",
        side_effect=PermissionError("injected compiler start denial"),
    )
    def test_keychain_broker_start_failure_is_inconclusive(
        self,
        _run_command: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeExecutableInspectionInconclusive,
            "compiler start denial",
        ):
            self.prepare_claude_keychain_broker(
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "PATH": "/usr/bin",
                },
            )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_prepare_claude_keychain_broker",
        side_effect=providers.ClaudeExecutableInspectionInconclusive(
            "failed to build the Claude Keychain broker"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_keychain_broker_compile_failure_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _prepare_broker: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "validation was inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "run")
    def test_claude_api_key_skips_keychain_broker(self, run_command: mock.Mock) -> None:
        env = {
            "ANTHROPIC_API_KEY": "test-api-key",
            "HOME": str(self.review.container_dir / "claude-home"),
            "PATH": "/usr/bin",
        }

        self.assertEqual(
            self.prepare_claude_keychain_broker(self.review, env),
            env,
        )
        run_command.assert_not_called()

    def test_model_match_is_normalized_but_not_prefix_based(self) -> None:
        self.assertTrue(providers._model_matches("claude-opus-4-8", "claude-opus-4.8"))
        self.assertFalse(providers._model_matches("gpt-5.5", "gpt-5.5-mini"))
        self.assertFalse(providers._model_matches("gpt-5.5", "gpt-5.5-codex"))

    def test_entitlement_is_fallback_eligible(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Model is not available for your account"),
            "entitlement",
        )
        self.assertEqual(
            providers.classify_failure(
                "",
                "Your account does not have access to this model",
            ),
            "entitlement",
        )

    def test_structured_model_access_code_is_fallback_eligible(self) -> None:
        stdout = json.dumps(
            {
                "type": "error",
                "error": {
                    "code": "model_access_denied",
                    "message": "request rejected",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_ambiguous_model_not_found_without_access_context_does_not_fallback(
        self,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "error",
                "error": {
                    "type": "model_not_found",
                    "message": "requested model identifier does not exist",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "other")
        self.assertEqual(
            providers.classify_failure(
                "",
                "This model is not supported with your ChatGPT account",
            ),
            "entitlement",
        )

    def test_auth_is_not_entitlement(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Authentication failed: invalid token"),
            "auth",
        )

    def test_current_claude_auth_diagnostics_are_classified_as_auth(self) -> None:
        diagnostics = (
            "Login expired",
            "Please run /login",
            "Run claude auth login to continue",
            "OAuth refresh failed",
            "Token refresh failed",
            "HTTP 401 Unauthorized",
            "status 401",
            "OAuth refresh failed after a network timeout",
            "HTTP 401 while the service is temporarily unavailable",
        )
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(
                    providers.classify_failure("", diagnostic),
                    "auth",
                )
        structured = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "message": "request failed for the selected model",
                "errors": ["Login expired · Please run /login"],
                "result": "partial review text mentioning HTTP 503",
            }
        )
        self.assertEqual(providers.classify_failure(structured, ""), "auth")

        for code in providers.STRUCTURED_AUTH_CODES:
            with self.subTest(code=code):
                coded = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "code": code,
                        "message": "model is not available for your account",
                        "result": "the service is temporarily unavailable",
                    }
                )
                self.assertEqual(providers.classify_failure(coded, ""), "auth")

    def test_auth_wins_over_entitlement_wording(self) -> None:
        self.assertEqual(
            providers.classify_failure(
                "",
                "Unauthorized: model is not available for your account",
            ),
            "auth",
        )

    def test_repository_text_in_structured_tool_output_cannot_trigger_fallback(
        self,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "aggregated_output": "not available for your account; timeout",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, "review failed"), "other")

    def test_nested_tool_error_data_cannot_trigger_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "item.completed",
                "data": {
                    "error": {
                        "message": "Model is not available for your account; timeout"
                    }
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, "review failed"), "other")

    def test_partial_result_is_never_failure_classification_evidence(self) -> None:
        repository_controlled_fragments = (
            "Login expired · Please run /login",
            "HTTP 401 Unauthorized",
            "authentication_error",
            "Model is not available for your account",
            "model_access_denied",
            "HTTP 429 rate limit exceeded",
            "the service is temporarily unavailable",
        )
        for fragment in repository_controlled_fragments:
            with self.subTest(fragment=fragment):
                stdout = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "message": "review failed",
                        "result": fragment,
                    }
                )
                self.assertEqual(
                    providers.classify_failure(stdout, ""),
                    "other",
                )

    def test_structured_error_event_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "turn.failed",
                "error": {"message": "Model is not available for your account"},
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_structured_api_error_event_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "api_error",
                "message": "Model is not available for your account",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_errors_field_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_api_error_status_can_trigger_transient_classification(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "api_error_status": 429,
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "transient")

    def test_claude_partial_result_cannot_override_entitlement_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
                "result": "partial review text mentioning timeout",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_partial_result_cannot_override_transient_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "api_error_status": 429,
                "result": "model is not available for your account",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "transient")

    def test_claude_partial_auth_cannot_override_transient_error(self) -> None:
        for status in (429, 503):
            with self.subTest(status=status):
                stdout = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "api_error_status": status,
                        "result": "Login expired · Please run /login",
                    }
                )
                self.assertEqual(
                    providers.classify_failure(stdout, ""),
                    "transient",
                )

    def test_claude_partial_auth_cannot_override_entitlement_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
                "result": "Authentication failed: invalid token",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_structured_error_result_cannot_be_accepted_as_final_text(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "result": "partial findings",
                "modelUsage": {"claude-opus-4-8": {}},
            }
        ).encode()
        final_text, effective_model = providers._parse_claude_output(stdout)
        self.assertIsNone(final_text)
        self.assertEqual(effective_model, "claude-opus-4-8")

    def test_requested_model_wins_over_auxiliary_claude_model_usage(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "modelUsage": {
                    "claude-haiku-4-5-20251001": {},
                    "claude-opus-4-8": {},
                },
            }
        ).encode()
        final_text, effective_model = providers._parse_claude_output(
            stdout, requested_model="claude-opus-4-8"
        )
        self.assertEqual(final_text, "No findings.")
        self.assertEqual(effective_model, "claude-opus-4-8")

    def test_claude_rejects_malformed_model_usage_entry(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "modelUsage": {"claude-opus-4-8": None},
            }
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_success_with_nonempty_errors(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "errors": [{"message": "contradictory failure"}],
                "modelUsage": {"claude-opus-4-8": {}},
            }
        ).encode()

        self.assertEqual(
            providers._parse_claude_output(stdout),
            (None, "claude-opus-4-8"),
        )

    def test_claude_rejects_unknown_or_malformed_error_payloads(self) -> None:
        for field, value in (
            ("errors", [{"exception": "failed"}]),
            ("api_error_status", {"code": 500}),
        ):
            with self.subTest(field=field):
                payload = {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                    field: value,
                }

                self.assertEqual(
                    providers._parse_claude_output(json.dumps(payload).encode()),
                    (None, "claude-opus-4-8"),
                )

    def test_nonterminal_claude_payload_cannot_supply_final_text(self) -> None:
        stdout = json.dumps(
            {
                "type": "progress",
                "data": {
                    "message": "LGTM",
                    "model": "claude-opus-4-8",
                },
            }
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_non_json_prefix_before_success_object(self) -> None:
        stdout = (
            b"warning: degraded output\n"
            + json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                }
            ).encode()
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_unicode_separator_prefix_before_success(self) -> None:
        stdout = (
            "\u2028"
            + json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                }
            )
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_nonstandard_json_constant(self) -> None:
        stdout = (
            b'{"type":"result","subtype":"success","is_error":false,'
            b'"result":"No findings.","modelUsage":{"claude-opus-4-8":{}},'
            b'"metric":NaN}'
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_duplicate_json_object_key(self) -> None:
        stdout = (
            b'{"type":"result","subtype":"success","is_error":true,'
            b'"is_error":false,"result":"No findings.",'
            b'"modelUsage":{"claude-opus-4-8":{}}}'
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_preserves_unicode_separator_at_result_edges(self) -> None:
        result = "\u2028No findings.\u2029"
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": result,
                "modelUsage": {"claude-opus-4-8": {}},
            },
            ensure_ascii=False,
        ).encode()

        self.assertEqual(
            providers._parse_claude_output(stdout),
            (result, "claude-opus-4-8"),
        )

    def test_copilot_requires_terminal_message_for_the_ended_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "tool.execution_complete",
                    "data": {
                        "message": "LGTM",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_non_json_line_before_terminal_events(self) -> None:
        stdout = (
            "warning: degraded output\n"
            + "\n".join(
                json.dumps(item)
                for item in (
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                )
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_error_preserves_mismatched_effective_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, "claude-opus-4.7"),
        )

    def test_copilot_error_without_turn_is_unverifiable(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, None),
        )

    def test_copilot_error_does_not_inherit_previous_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {"type": "session.start", "data": {}},
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, None),
        )

    def test_copilot_error_rejects_malformed_model_evidence(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.message",
                    "data": {"model": 123},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, None),
        )

    def test_copilot_error_after_completed_turn_is_unverifiable(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, None),
        )

    def test_copilot_error_cannot_be_hidden_by_empty_completed_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-2"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, None),
        )

    def test_copilot_error_in_open_turn_after_completed_turn_keeps_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(
                stdout, requested_model="claude-opus-4.8"
            ),
            (None, "claude-opus-4.8"),
        )

    def test_copilot_preserves_unicode_separators_at_content_edges(self) -> None:
        content = "\u2028No findings.\u2029"
        stdout = "\n".join(
            json.dumps(item, ensure_ascii=False)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": content,
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            (content, "claude-opus-4.8"),
        )

    def test_copilot_rejects_nonstandard_json_constant(self) -> None:
        stdout = "\n".join(
            (
                '{"type":"assistant.turn_start","data":{"turnId":"turn-1"}}',
                '{"type":"assistant.message","data":{"content":"No findings.",'
                '"model":"claude-opus-4.8","metric":Infinity}}',
                '{"type":"assistant.turn_end","data":{"turnId":"turn-1"}}',
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_duplicate_json_object_key(self) -> None:
        stdout = "\n".join(
            (
                '{"type":"assistant.turn_start","data":{"turnId":"turn-1"}}',
                '{"type":"assistant.message","data":{"content":"No findings.",'
                '"model":"claude-opus-4.7","model":"claude-opus-4.8"}}',
                '{"type":"assistant.turn_end","data":{"turnId":"turn-1"}}',
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_unicode_separator_only_record(self) -> None:
        stdout = (
            "\u2028\n"
            + "\n".join(
                json.dumps(item)
                for item in (
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                )
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_nested_or_interleaved_turn_boundaries(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-a"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-a"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_unclosed_outer_turn_before_completed_inner(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-a"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-b"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_malformed_later_top_level_message(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "stale findings",
                        "model": "claude-opus-4.8",
                    },
                },
                {"type": "assistant.message", "data": None},
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_malformed_terminal_usage_event(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {"type": "assistant.usage", "data": {"model": None}},
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_accepts_only_tool_free_message_for_ended_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "intermediate LGTM",
                        "toolRequests": [{"name": "view"}],
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                    },
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            ("No findings.", "claude-opus-4.8"),
        )

    def test_copilot_does_not_fall_back_past_terminal_tool_request(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "premature LGTM",
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "checking one more file",
                        "toolRequests": [{"name": "view"}],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_accepts_current_cli_model_extension(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "messageId": "message-1",
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                        "toolRequests": [],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            ("No findings.", "claude-opus-4.8"),
        )

    def test_copilot_success_does_not_inherit_previous_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {"type": "session.start", "data": {}},
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "assistant.message",
                    "data": {"content": "No findings.", "toolRequests": []},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-2"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_streams_complete_jsonl_larger_than_memory_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout_path = pathlib.Path(temporary) / "copilot.stdout.log"
            progress = json.dumps(
                {"type": "progress", "data": {"padding": "x" * 4096}}
            )
            with stdout_path.open("w", encoding="utf-8") as handle:
                while handle.tell() <= 4 * 1024 * 1024:
                    handle.write(progress + "\n")
                for item in (
                    {
                        "type": "session.start",
                        "data": {"selectedModel": "claude-opus-4.8"},
                    },
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                ):
                    handle.write(json.dumps(item) + "\n")

            result = providers._parse_copilot_output_file(stdout_path)

        self.assertEqual(result, ("No findings.", "claude-opus-4.8"))

    def test_copilot_rejects_malformed_terminal_message_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": 123,
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_usage_before_terminal_message(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_earlier_message_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "draft",
                        "model": "claude-opus-4.7",
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_terminal_usage_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_usage_after_turn_end(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_falls_back_from_56_to_55_only_on_entitlement(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.side_effect = (
            self.attempt("codex", "gpt-5.6-sol", "entitlement"),
            self.attempt("codex", "gpt-5.5", "success", final_text="No findings."),
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [item.requested_model for item in outcome.attempts],
            list(providers.CODEX_MODELS),
        )
        self.assertEqual(
            _environment.call_args.kwargs["passthrough_keys"],
            providers.CODEX_ENV_KEYS,
        )

    def test_node_extra_ca_certs_is_claude_only(self) -> None:
        source = "/private/reviewer-ca.pem"
        with mock.patch.dict(
            providers.os.environ,
            {
                "NODE_EXTRA_CA_CERTS": source,
                "NODE_OPTIONS": "--require=/untrusted/bootstrap.js",
                "NODE_TLS_REJECT_UNAUTHORIZED": "0",
            },
            clear=True,
        ):
            claude_env = providers._review_environment(
                review=self.review,
                passthrough_keys=providers.CLAUDE_ENV_KEYS,
            )
            codex_env = providers._review_environment(
                review=self.review,
                passthrough_keys=providers.CODEX_ENV_KEYS,
            )
            copilot_env = providers._review_environment(
                review=self.review,
                passthrough_keys=providers.COPILOT_ENV_KEYS,
            )

        self.assertEqual(claude_env["NODE_EXTRA_CA_CERTS"], source)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", codex_env)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", copilot_env)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", common.BASE_ENV_KEYS)
        for env in (claude_env, codex_env, copilot_env):
            self.assertNotIn("NODE_OPTIONS", env)
            self.assertNotIn("NODE_TLS_REJECT_UNAUTHORIZED", env)

    def test_linux_rejects_prompt_file_mentions_before_authentication(self) -> None:
        self.review.prompt_file.write_text(
            "Review @/config/runtime-state.json\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        with (
            mock.patch.object(
                providers,
                "_is_claude_linux_host",
                return_value=True,
            ),
            mock.patch.object(
                providers,
                "_resolve_validated_claude_executable",
            ) as resolve,
        ):
            outcome = providers.run_review(
                review=self.review,
                reviewer="claude",
                egress_consent="explicit-claude-review",
            )

        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        self.assertIn(
            "ASCII @ file mentions are not allowed",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_linux_prompt_guard_does_not_scan_frozen_diff(self) -> None:
        self.review.diff_file.write_text(
            "diff --git a/example.py b/example.py\n+@decorator\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        with (
            mock.patch.object(providers, "child_environment", return_value={}),
            mock.patch.object(
                providers,
                "_is_claude_linux_host",
                return_value=True,
            ),
            mock.patch.object(
                providers,
                "_resolve_validated_claude_executable",
                return_value=(None, {}),
            ) as resolve,
        ):
            outcome = providers.run_review(
                review=self.review,
                reviewer="claude",
                egress_consent="explicit-claude-review",
            )

        self.assertEqual(outcome.returncode, 2)
        resolve.assert_called_once()
        self.assertNotIn(
            "ASCII @ file mentions are not allowed",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_linux_prompt_projects_host_paths_and_read_only_guidance(self) -> None:
        host_prompt = (
            f"Workspace={self.review.workspace_root}\n"
            f"Diff={self.review.diff_file}\n"
        ).encode()

        projected = providers._claude_review_prompt(
            self.review,
            host_prompt,
            linux=True,
        )

        self.assertNotIn(str(self.review.workspace_root).encode(), projected)
        self.assertIn(b"Workspace=/workspace\n", projected)
        self.assertIn(
            b"Diff=/workspace/.codex-review/review.diff\n",
            projected,
        )
        self.assertIn(b"Only Read is available", projected)
        self.assertIn(b"Every Read `file_path` must be absolute", projected)

    def test_linux_prompt_rejects_ambiguous_host_path_prefixes(self) -> None:
        for ambiguous in (
            f"Workspace={self.review.workspace_root}-backup\n",
            f"Workspace=copy{self.review.workspace_root}\n",
            f"Diff={self.review.diff_file}.sig\n",
            f"Escaping={self.review.workspace_root}/../outside.py\n",
            f"Noncanonical={self.review.workspace_root}//source.py\n",
            f'Path="{self.review.workspace_root}/safe /../../etc/passwd"\n',
            f"Phrase {self.review.workspace_root}/safe /../../etc/passwd\n",
        ):
            with (
                self.subTest(ambiguous=ambiguous),
                self.assertRaisesRegex(ReviewError, "ambiguous host .* path"),
            ):
                providers._claude_review_prompt(
                    self.review,
                    ambiguous.encode(),
                    linux=True,
                )

    def test_linux_prompt_projects_canonical_workspace_descendant(self) -> None:
        cases = (
            (
                f"Nested={self.review.workspace_root}/src/source.py\n",
                b"Nested=/workspace/src/source.py\n",
            ),
            (
                f'Path="{self.review.workspace_root}/src dir/source.py"\n',
                b'Path="/workspace/src dir/source.py"\n',
            ),
        )
        for prompt, expected in cases:
            with self.subTest(prompt=prompt):
                projected = providers._claude_review_prompt(
                    self.review,
                    prompt.encode(),
                    linux=True,
                )
                self.assertIn(expected, projected)

    def test_macos_prompt_projects_default_paths_to_host_absolutes(self) -> None:
        default_prompt = (
            b"- Workspace: .\n"
            b"- Primary diff file: .codex-review/review.diff\n"
        )

        projected = providers._claude_review_prompt(
            self.review,
            default_prompt,
            linux=False,
        )

        self.assertIn(str(self.review.workspace_root).encode(), projected)
        self.assertIn(str(self.review.diff_file).encode(), projected)
        self.assertNotIn(b"Linux/WSL2 runtime tool boundary", projected)

    def test_linux_prompt_projection_rechecks_size_limit(self) -> None:
        with self.assertRaisesRegex(ReviewError, "projected review prompt exceeds"):
            providers._claude_review_prompt(
                self.review,
                b"x" * providers.MAX_REVIEW_PROMPT_BYTES,
                linux=True,
            )

    def test_model_chain_persists_each_completed_attempt(self) -> None:
        first = self.attempt("codex", "gpt-5.6-sol", "entitlement")
        runner = mock.Mock(side_effect=(first, RuntimeError("interrupted fallback")))
        attempts: list[providers.Attempt] = []
        with self.assertRaisesRegex(RuntimeError, "interrupted fallback"):
            providers._run_model_chain(
                review=self.review,
                models=providers.CODEX_MODELS,
                runner=runner,
                runtime="codex",
                requested_effort=providers.CODEX_REASONING_EFFORT,
                env={},
                attempts=attempts,
            )

        persisted = json.loads(
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["requested_model"], "gpt-5.6-sol")
        self.assertEqual(persisted[0]["category"], "entitlement")
        self.assertNotIn("final_text", persisted[0])
        self.assertFalse(persisted[0]["final_available"])

    def test_model_chain_does_not_persist_successful_final_text(self) -> None:
        final_text = "sensitive terminal artifact"
        runner = mock.Mock(
            return_value=self.attempt(
                "codex",
                "gpt-5.6-sol",
                "success",
                final_text=final_text,
            )
        )
        attempts: list[providers.Attempt] = []

        category, returned_text = providers._run_model_chain(
            review=self.review,
            models=("gpt-5.6-sol",),
            runner=runner,
            runtime="codex",
            requested_effort=providers.CODEX_REASONING_EFFORT,
            env={},
            attempts=attempts,
        )

        self.assertEqual(category, "success")
        self.assertEqual(returned_text, final_text)
        persisted = json.loads(
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("final_text", persisted[0])
        self.assertTrue(persisted[0]["final_available"])
        self.assertNotIn(
            final_text,
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8"),
        )

    def test_finish_preserves_unicode_separator_at_result_edges(self) -> None:
        final_text = "\u2028No findings.\u2029"

        outcome = providers._finish(self.review, [], final_text)

        self.assertEqual(outcome.final_text, final_text)
        self.assertEqual(
            (self.review.container_dir / "final.txt").read_text(encoding="utf-8"),
            final_text + "\n",
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_capacity_does_not_downgrade(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.return_value = self.attempt("codex", "gpt-5.6-sol", "transient")
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(codex_attempt.call_count, 1)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_codex_attempt",
        side_effect=providers.ReviewTimeoutError("review timed out"),
    )
    def test_codex_attempt_timeout_is_inconclusive(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(review=self.review, reviewer="codex")

        self.assertEqual(outcome.returncode, 75)
        codex_attempt.assert_called_once()
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.attempts[0].runtime, "codex")
        self.assertEqual(outcome.attempts[0].requested_model, "gpt-5.6-sol")
        self.assertEqual(outcome.attempts[0].category, "inconclusive")
        self.assertTrue(pathlib.Path(outcome.attempts[0].stderr_path).is_file())
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_family_order_is_opus_4_8_then_4_7_on_both_runtimes(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = tuple(
            self.attempt("claude", model, "entitlement")
            for model in providers.CLAUDE_MODELS
        )
        copilot_attempt.side_effect = tuple(
            self.attempt("copilot", model, "entitlement")
            for model in providers.COPILOT_MODELS[:-1]
        ) + (
            self.attempt(
                "copilot",
                providers.COPILOT_MODELS[-1],
                "success",
                final_text="No findings.",
            ),
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [(item.runtime, item.requested_model) for item in outcome.attempts],
            [
                ("claude", "claude-opus-4-8"),
                ("claude", "claude-opus-4-7"),
                ("copilot", "claude-opus-4.8"),
                ("copilot", "claude-opus-4.7"),
            ],
        )
        self.assertEqual(
            [call.kwargs["passthrough_keys"] for call in _environment.call_args_list],
            [providers.CLAUDE_ENV_KEYS, providers.COPILOT_ENV_KEYS],
        )

    def test_claude_model_chain_reuses_preflight_verified_executable(
        self,
    ) -> None:
        source = self.review.source_root / "claude-source"
        source.write_bytes(b"source")
        snapshot = self.review.container_dir / "verified-claude"
        snapshot.write_bytes(b"snapshot")
        seen_executables: list[pathlib.Path | None] = []

        def resolve_once(
            *,
            review: ReviewWorkspace,
            env: dict[str, str],
        ) -> tuple[pathlib.Path, dict[str, str]]:
            self.assertIs(review, self.review)
            self.assertIsInstance(env, dict)
            source.unlink()
            return snapshot, {"ANTHROPIC_API_KEY": "secret"}

        def attempt_with_snapshot(**kwargs) -> providers.Attempt:
            seen_executables.append(kwargs.get("executable"))
            self.assertFalse(source.exists())
            return self.attempt(
                "claude",
                kwargs["model"],
                "entitlement",
            )

        with (
            mock.patch.object(providers, "child_environment", return_value={}),
            mock.patch.object(
                providers,
                "_resolve_validated_claude_executable",
                side_effect=resolve_once,
            ) as resolve_claude,
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ) as prepare_tls,
            mock.patch.object(
                providers,
                "_claude_attempt",
                side_effect=attempt_with_snapshot,
            ) as claude_attempt,
            mock.patch.object(providers, "_copilot_attempt") as copilot_attempt,
        ):
            outcome = providers.run_review(
                review=self.review,
                reviewer="claude",
                egress_consent="explicit-claude-review",
            )

        self.assertEqual(outcome.returncode, 2)
        resolve_claude.assert_called_once()
        self.assertEqual(claude_attempt.call_count, len(providers.CLAUDE_MODELS))
        self.assertEqual(
            seen_executables,
            [snapshot] * len(providers.CLAUDE_MODELS),
        )
        prepare_tls.assert_not_called()
        copilot_attempt.assert_not_called()

    def test_claude_supervision_failures_finalize_runtime_report(self) -> None:
        snapshot = self.review.container_dir / "verified-claude"
        snapshot.write_bytes(b"snapshot")
        cases = (
            (providers.ReviewTimeoutError, "timeout"),
            (providers.ReviewOutputLimitError, "output-limit"),
            (providers.ReviewOutputDrainError, "output-drain"),
            (providers.ReviewProcessLeakError, "process-leak"),
        )

        for error_type, failure_class in cases:
            with self.subTest(failure_class=failure_class):
                diagnostic = f"private diagnostic for {failure_class}"
                providers.write_json(
                    self.review.container_dir / "claude-runtime.json",
                    {
                        "phase": "runtime-launching",
                        "outer_sandbox": {"status": "profile-generated"},
                        "gpg_verifier_trust": "fixed-path-native-host-tool",
                    },
                )
                with (
                    mock.patch.object(
                        providers,
                        "child_environment",
                        return_value={},
                    ),
                    mock.patch.object(
                        providers,
                        "_resolve_validated_claude_executable",
                        return_value=(
                            snapshot,
                            {"ANTHROPIC_API_KEY": "secret"},
                        ),
                    ) as resolve_claude,
                    mock.patch.object(
                        providers,
                        "_with_claude_review_tool_path",
                        side_effect=lambda _review, env: dict(env),
                    ),
                    mock.patch.object(
                        providers,
                        "_prepare_claude_tls_environment",
                        side_effect=lambda _review, env: dict(env),
                    ),
                    mock.patch.object(
                        providers,
                        "_claude_attempt",
                        side_effect=error_type(diagnostic),
                    ),
                    mock.patch.object(providers, "_copilot_attempt") as copilot_attempt,
                ):
                    outcome = providers.run_review(
                        review=self.review,
                        reviewer="claude",
                        egress_consent="double-review",
                    )

                self.assertEqual(outcome.returncode, 75)
                self.assertEqual(len(outcome.attempts), 1)
                self.assertEqual(outcome.attempts[0].category, "inconclusive")
                resolve_claude.assert_called_once()
                copilot_attempt.assert_not_called()
                report_text = (
                    self.review.container_dir / "claude-runtime.json"
                ).read_text(encoding="utf-8")
                report = json.loads(report_text)
                self.assertEqual(report["phase"], "attempt-inconclusive")
                self.assertEqual(report["attempt"]["category"], "inconclusive")
                self.assertEqual(
                    report["attempt"]["failure_class"],
                    failure_class,
                )
                self.assertEqual(
                    report["gpg_verifier_trust"],
                    "fixed-path-native-host-tool",
                )
                self.assertNotIn(diagnostic, report_text)

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"HOME": "/Users/reviewer"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_local_login_is_default_without_api_key(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        claude_attempt.assert_called_once()
        self.assertEqual(
            claude_attempt.call_args.kwargs["env"]["HOME"],
            str(self.review.container_dir / "claude-home"),
        )
        self.assertNotIn(
            "ANTHROPIC_API_KEY",
            claude_attempt.call_args.kwargs["env"],
        )
        copilot_attempt.assert_not_called()

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(None, {}),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(
        providers,
        "_copilot_attempt",
        side_effect=providers.ReviewOutputLimitError("review output exceeded limit"),
    )
    def test_copilot_attempt_output_limit_is_inconclusive(
        self,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_called_once()
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.attempts[0].runtime, "copilot")
        self.assertEqual(
            outcome.attempts[0].requested_model,
            providers.COPILOT_MODELS[0],
        )
        self.assertEqual(outcome.attempts[0].category, "inconclusive")
        self.assertTrue(pathlib.Path(outcome.attempts[0].stderr_path).is_file())
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_capacity_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude", providers.CLAUDE_MODELS[0], "transient"
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_model_mismatch_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            "claude-opus-4-8",
            "model-mismatch",
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=ReviewError("Claude Code --version timed out"),
    )
    def test_claude_cli_validation_failure_refuses_copilot_fallback(
        self,
        _resolve: mock.Mock,
        copilot_attempt: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=providers.ClaudeExecutableInspectionInconclusive(
            "Claude executable disappeared during inspection"
        ),
    )
    def test_claude_inspection_race_refuses_copilot_fallback(
        self,
        _resolve: mock.Mock,
        copilot_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_disappearance_is_inconclusive_not_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = FileNotFoundError("claude disappeared")
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProbeSandboxUnavailable("sandbox unavailable"),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_missing_claude_probe_sandbox_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "secure runtime is unavailable",
            (self.review.container_dir / "claude-skip.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProbeSandboxUnavailable(
            "sandbox unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_missing_probe_sandbox_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "Explicit CODEX_REVIEW_CLAUDE_PATH",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableUnavailable(
            "explicit executable is unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_unavailable_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProvenanceVerifierUnavailable(
            "trusted GPG unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_missing_gpg_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "trusted GPG unavailable",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProvenanceVerifierUnavailable(
            "trusted GPG unavailable"
        ),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_claude_missing_gpg_allows_authorized_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableInspectionInconclusive(
            "GPG snapshot write failed: ENOSPC"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_claude_provenance_io_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "ENOSPC",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableUnavailable("only wrapper found"),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_non_native_claude_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "only wrapper found",
            (self.review.container_dir / "claude-skip.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_attempt_local_auth_unavailable_blocks_without_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        auth_error = providers.ClaudeKeychainCredentialUnavailable(
            "credential refresh persistence failed"
        )
        setattr(
            auth_error,
            "_codex_claude_persistence_attempt",
            self.attempt(
                "claude",
                providers.CLAUDE_MODELS[0],
                "blocked-authentication",
            ),
        )
        claude_attempt.side_effect = auth_error
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "authentication": {"status": "pending"},
            },
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.attempts[0].category, "blocked-authentication")
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("claude auth login", error)
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["phase"], "blocked-authentication")
        self.assertEqual(report["status"], "blocked-authentication")
        self.assertEqual(report["category"], "blocked-authentication")
        self.assertEqual(
            report["authentication"]["status"],
            "blocked-authentication",
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_auth_rejection_preserves_recovery_carrier_diagnostic(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-auth-rejection"
        )
        carrier.mkdir(parents=True, mode=0o700)
        auth_error = providers.ClaudeKeychainCredentialUnavailable(
            "the restricted runtime rejected the rotated credential"
        )
        setattr(
            auth_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        setattr(
            auth_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        setattr(
            auth_error,
            "_codex_claude_persistence_attempt",
            self.attempt(
                "claude",
                providers.CLAUDE_MODELS[0],
                "auth",
            ),
        )
        claude_attempt.side_effect = auth_error
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "runtime-launching",
                "authentication": {"status": "sandbox-auth-staged"},
            },
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        runner_error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("claude auth login", runner_error)
        self.assertIn(providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC, runner_error)
        self.assertIn(str(carrier), runner_error)
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_credential_io_race_is_inconclusive_without_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = (
            providers.ClaudeCredentialInspectionInconclusive(
                "credential source changed while it was read"
            )
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("inconclusive", error)
        self.assertNotIn("claude auth login", error)

    def test_late_keychain_client_loss_pauses_double_and_triple_review(
        self,
    ) -> None:
        snapshot = self.review.container_dir / "verified-claude"
        snapshot.write_bytes(b"snapshot")
        cases = (
            ("double-review", "missing"),
            ("triple-review", "non-executable"),
        )

        for consent, condition in cases:
            with self.subTest(consent=consent, condition=condition):
                client = self.claude_keychain_client.parent / (
                    f"late-security-{condition}"
                )
                client.write_bytes(b"fixture")
                client.chmod(0o700)

                def prepare_broker(
                    _review: ReviewWorkspace,
                    env: dict[str, str],
                ) -> dict[str, str]:
                    self.assertTrue(client.is_file())
                    self.assertTrue(os.access(client, os.X_OK))
                    return dict(env)

                def fail_after_preflight(**_kwargs: object) -> providers.Attempt:
                    self.assertTrue(
                        (self.review.container_dir / "preflight.json").is_file()
                    )
                    if condition == "missing":
                        client.unlink()
                    else:
                        client.chmod(0o600)
                    providers._read_claude_keychain_credential(self.review)
                    raise AssertionError(
                        "late Keychain inspection unexpectedly passed"
                    )

                with (
                    mock.patch.object(
                        providers,
                        "child_environment",
                        return_value={},
                    ),
                    mock.patch.object(
                        providers,
                        "CLAUDE_KEYCHAIN_CLIENT",
                        client,
                    ),
                    mock.patch.object(
                        providers,
                        "_resolve_validated_claude_executable",
                        return_value=(snapshot, {}),
                    ),
                    mock.patch.object(
                        providers,
                        "_prepare_claude_keychain_broker",
                        side_effect=prepare_broker,
                    ) as prepare,
                    mock.patch.object(
                        providers,
                        "_claude_attempt",
                        side_effect=fail_after_preflight,
                    ) as claude_attempt,
                    mock.patch.object(
                        providers,
                        "resolve_reviewer_executable",
                        return_value=pathlib.Path("/bin/copilot"),
                    ),
                    mock.patch.object(
                        providers,
                        "_copilot_attempt",
                        return_value=self.attempt(
                            "copilot",
                            providers.COPILOT_MODELS[0],
                            "success",
                            final_text="No findings.",
                        ),
                    ) as copilot_attempt,
                ):
                    outcome = providers.run_review(
                        review=self.review,
                        reviewer="claude",
                        egress_consent=consent,
                    )

                self.assertEqual(outcome.returncode, 75)
                prepare.assert_called_once()
                claude_attempt.assert_called_once()
                copilot_attempt.assert_not_called()
                self.assertIn(
                    "inconclusive",
                    (self.review.container_dir / "runner-error.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_macos_refresh_recovery_pauses_without_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-run-review"
        )
        config = carrier / "config"
        config.mkdir(parents=True, mode=0o700)
        carrier.chmod(0o700)
        credential = config / providers.CLAUDE_CREDENTIAL_FILE_NAME
        credential_payload = oauth_credential_fixture(expires_in_seconds=7200)
        self.write_private_source(credential, credential_payload)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "guarded host writeback was not proven"
        )
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        claude_attempt.side_effect = error
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "runtime-launching",
                "authentication": {"status": "sandbox-auth-staged"},
            },
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        runner_error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(str(carrier), runner_error)
        self.assertIn(
            providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
            runner_error,
        )
        self.assertNotIn(
            json.loads(credential_payload)["claudeAiOauth"]["refreshToken"],
            runner_error,
        )
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_timeout_reports_secondary_refresh_persistence_failure(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        error = providers.ReviewTimeoutError("primary review timeout")
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        claude_attempt.side_effect = error
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "runtime-launching",
                "authentication": {"status": "sandbox-auth-staged"},
            },
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        runner_error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("primary review timeout", runner_error)
        self.assertIn(providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC, runner_error)
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["phase"], "attempt-inconclusive")
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )
        self.assertEqual(
            report["authentication"]["secondary_diagnostic"],
            providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_generic_review_error_preserves_recovery_carrier_diagnostic(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-generic-error"
        )
        carrier.mkdir(parents=True, mode=0o700)
        error = ReviewError("primary runtime validation failed")
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        claude_attempt.side_effect = error
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "runtime-launching",
                "authentication": {"status": "sandbox-auth-staged"},
            },
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        runner_error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("primary runtime validation failed", runner_error)
        self.assertIn(providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC, runner_error)
        self.assertIn(str(carrier), runner_error)
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_second_model_credential_failure_blocks_authorized_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        error = providers.ClaudeKeychainCredentialUnavailable(
            "second model credential refresh failed"
        )
        first = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            "entitlement",
        )
        claude_attempt.side_effect = (first, error)

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 2)
        self.assertEqual(outcome.attempts, (first,))
        self.assertEqual(claude_attempt.call_count, len(providers.CLAUDE_MODELS))
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "claude auth login",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_second_model_local_auth_unavailable_needs_fallback_consent(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        errors = (
            providers.ClaudeKeychainBrokerUnavailable(
                "second model credential broker is unavailable"
            ),
            providers.ClaudeLoopbackUnavailable(
                "second model authentication loopback is unavailable"
            ),
        )
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                claude_attempt.reset_mock()
                copilot_attempt.reset_mock()
                resolve.reset_mock()
                first = self.attempt(
                    "claude",
                    providers.CLAUDE_MODELS[0],
                    "entitlement",
                )
                claude_attempt.side_effect = (first, error)

                outcome = providers.run_review(
                    review=self.review,
                    reviewer="claude",
                    egress_consent="explicit-claude-review",
                )

                self.assertEqual(outcome.returncode, 2)
                self.assertEqual(outcome.attempts, (first,))
                copilot_attempt.assert_not_called()
                resolve.assert_not_called()
                self.assertIn(
                    "does not authorize GitHub Copilot",
                    (self.review.container_dir / "runner-error.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_with_claude_review_tool_path",
        side_effect=providers.ClaudeReviewToolUnavailable("trusted rg unavailable"),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_missing_trusted_rg_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _tools: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "trusted rg unavailable",
            (self.review.container_dir / "claude-skip.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/explicit/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_with_claude_review_tool_path",
        side_effect=providers.ClaudeReviewToolUnavailable(
            "trusted rg unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_missing_trusted_rg_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _tools: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/explicit/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_with_claude_review_tool_path",
        return_value={},
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "_claude_attempt",
        side_effect=providers.ClaudeReviewToolUnavailable(
            "trusted rg disappeared before the attempt"
        ),
    )
    def test_explicit_claude_attempt_prerequisite_failure_blocks_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _tools: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/explicit/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_with_claude_review_tool_path",
        return_value={},
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "_claude_attempt",
        side_effect=providers.ClaudeExecutableUnavailable(
            "explicit executable disappeared before the attempt"
        ),
    )
    def test_explicit_claude_attempt_unavailable_blocks_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _tools: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(pathlib.Path("/bin/claude"), {}),
    )
    @mock.patch.object(
        providers,
        "_with_claude_review_tool_path",
        return_value={},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "_claude_attempt",
        side_effect=providers.ClaudeLoopbackUnavailable("loopback bind failed"),
    )
    def test_loopback_unavailable_allows_authorized_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _tools: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "loopback bind failed",
            (self.review.container_dir / "claude-skip.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_partial_result_cannot_authorize_model_or_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "message": "review failed",
                "result": (
                    "Repository text: authentication_error; model is not "
                    "available for your account"
                ),
            }
        )
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            providers.classify_failure(stdout, ""),
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 1)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(outcome.attempts[0].category, "other")

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_auth_result_blocks_authorized_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        diagnostics = tuple(
            ("", diagnostic)
            for diagnostic in (
                "Login expired",
                "Please run /login",
                "Run claude auth login to continue",
                "OAuth refresh failed",
                "Token refresh failed",
                "HTTP 401 Unauthorized",
                "OAuth refresh failed after a network timeout",
                "HTTP 401 while the service is temporarily unavailable",
            )
        ) + (
            (
                json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "message": "request failed for the selected model",
                        "errors": ["Login expired · Please run /login"],
                        "result": "partial review text mentioning HTTP 503",
                    }
                ),
                "",
            ),
            (
                json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "code": "authentication_error",
                        "message": "model is not available for your account",
                        "result": "the service is temporarily unavailable",
                    }
                ),
                "",
            ),
        )
        for stdout, stderr in diagnostics:
            with self.subTest(stdout=stdout, stderr=stderr):
                claude_attempt.reset_mock()
                copilot_attempt.reset_mock()
                resolve.reset_mock()
                claude_attempt.return_value = self.attempt(
                    "claude",
                    providers.CLAUDE_MODELS[0],
                    providers.classify_failure(stdout, stderr),
                )
                outcome = providers.run_review(
                    review=self.review,
                    reviewer="claude",
                    egress_consent="double-review",
                )

                self.assertEqual(outcome.returncode, 2)
                claude_attempt.assert_called_once()
                copilot_attempt.assert_not_called()
                self.assertEqual(resolve.call_count, 1)
                self.assertEqual(
                    outcome.attempts[0].category,
                    "blocked-authentication",
                )
                self.assertIn(
                    "claude auth login",
                    (self.review.container_dir / "runner-error.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "fixture-api-key"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_api_key_auth_failure_blocks_with_api_key_action(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            providers.classify_failure("", "HTTP 401 invalid API key"),
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("Unset or replace `ANTHROPIC_API_KEY`", error)
        self.assertNotIn("claude auth login", error)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_invalid_explicit_claude_override_blocks_without_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        def reject_override(_name: str, **kwargs):
            self.assertTrue(callable(kwargs["candidate_validator"]))
            raise ReviewError("invalid explicit override")

        resolve.side_effect = reject_override

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_timeout_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewTimeoutError("probe timed out")

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_output_limit_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewOutputLimitError(
            "probe output exceeded limit"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_drain_failure_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewOutputDrainError(
            "probe output drain failed"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_process_leak_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewProcessLeakError(
            "probe left descendant process"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/true"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_attempt_validation_failure_still_blocks_copilot(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = ReviewError("unsafe executable identity")

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=None,
    )
    def test_explicit_claude_consent_does_not_authorize_copilot_fallback(
        self,
        resolve: mock.Mock,
        copilot_attempt: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="explicit-claude-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_called_once()
        self.assertEqual(resolve.call_args.args, ("claude",))
        self.assertTrue(callable(resolve.call_args.kwargs["candidate_validator"]))
        copilot_attempt.assert_not_called()
        self.assertIn(
            "does not authorize GitHub Copilot",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_effective_model_substitution_does_not_infer_entitlement(self) -> None:
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=json.dumps(
                {"result": "No findings.", "modelUsage": {"claude-opus-4-7": {}}}
            ).encode(),
            stderr=b"",
        )

        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="claude",
            model="claude-opus-4-8",
            completed=completed,
            final_text="No findings.",
            effective_model="claude-opus-4-7",
            requested_effort="max",
            effective_effort=None,
        )
        self.assertEqual(attempt.category, "model-mismatch")
        self.assertIsNone(attempt.final_text)

    def test_failed_attempt_metadata_mismatch_blocks_fallback(self) -> None:
        completed = Completed(
            argv=("codex",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                }
            ).encode(),
            stderr=b"",
        )
        cases = (
            (1, "gpt-5.5", "xhigh", "model-mismatch"),
            (2, "gpt-5.6-sol", "high", "effort-mismatch"),
        )
        for index, effective_model, effective_effort, expected_category in cases:
            with self.subTest(expected_category=expected_category):
                attempt = providers._record_attempt(
                    review=self.review,
                    index=index,
                    runtime="codex",
                    model="gpt-5.6-sol",
                    completed=completed,
                    final_text=None,
                    effective_model=effective_model,
                    requested_effort="xhigh",
                    effective_effort=effective_effort,
                )
                self.assertEqual(attempt.category, expected_category)
                self.assertIsNone(attempt.final_text)

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/codex"),
    )
    @mock.patch.object(providers, "_codex_session_metadata")
    @mock.patch.object(providers, "run")
    def test_failed_codex_permission_mismatch_blocks_fallback(
        self,
        run_command: mock.Mock,
        session_metadata: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("codex",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {
                        "message": "Model is not available for your account"
                    },
                }
            ).encode(),
            stderr=b"",
        )
        session_metadata.return_value = ("gpt-5.6-sol", "xhigh", False)

        attempt = providers._codex_attempt(
            review=self.review,
            model="gpt-5.6-sol",
            index=1,
            env={},
        )

        self.assertEqual(attempt.category, "permission-mismatch")
        self.assertIsNone(attempt.final_text)

    def test_success_without_verified_runtime_metadata_is_not_accepted(self) -> None:
        completed = Completed(
            argv=("codex",),
            returncode=0,
            stdout=b'{"type":"thread.started","thread_id":"missing"}\n',
            stderr=b"",
        )
        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="codex",
            model="gpt-5.6-sol",
            completed=completed,
            final_text="No findings.",
            effective_model=None,
            requested_effort="xhigh",
            effective_effort=None,
            require_verified_model=True,
            require_verified_effort=True,
        )
        self.assertEqual(attempt.category, "runtime-unverified")
        self.assertIsNone(attempt.final_text)

    def test_entitlement_without_verified_model_cannot_authorize_fallback(
        self,
    ) -> None:
        completed = Completed(
            argv=("copilot",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                }
            ).encode(),
            stderr=b"",
        )
        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="copilot",
            model="claude-opus-4.8",
            completed=completed,
            final_text=None,
            effective_model=None,
            requested_effort="max",
            effective_effort=None,
            require_verified_model=True,
        )

        self.assertEqual(attempt.category, "runtime-unverified")
        self.assertIsNone(attempt.final_text)

    @mock.patch.object(providers, "child_environment", return_value={})
    def test_claude_lane_requires_explicit_egress_consent(
        self,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
        )
        self.assertEqual(outcome.returncode, 2)
        self.assertIn(
            "explicit egress-consent",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_sensitive_content_blocks_external_reviewer_before_launch(
        self,
        resolve: mock.Mock,
    ) -> None:
        secret = "AKIA" + "A" * 16
        (self.review.workspace_root / "secret.txt").write_text(
            secret + "\n",
            encoding="utf-8",
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        self.assertFalse((self.review.container_dir / "egress.json").exists())
        self.assertFalse((self.review.container_dir / "preflight.json").exists())
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("sensitive content preflight", error)
        self.assertNotIn(secret, error)

    @mock.patch.object(providers, "_codex_attempt")
    def test_sensitive_content_blocks_codex_before_launch(
        self,
        codex_attempt: mock.Mock,
    ) -> None:
        secret = "AKIA" + "B" * 16
        self.review.diff_file.write_text(
            "diff --git a/config b/config\n-AWS_KEY=" + secret + "\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 2)
        codex_attempt.assert_not_called()
        self.assertFalse((self.review.container_dir / "preflight.json").exists())
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("sensitive content preflight", error)
        self.assertNotIn(secret, error)

    @mock.patch.object(providers, "_review_environment", return_value={})
    @mock.patch.object(providers, "_run_model_chain")
    def test_codex_preflight_evidence_precedes_model_launch(
        self,
        run_model_chain: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        def inspect_preflight(**_kwargs):
            evidence = json.loads(
                (self.review.container_dir / "preflight.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                evidence["review_range"],
                f"{self.review.base_ref}..{self.review.head_ref}",
            )
            diff_bytes = self.review.diff_file.read_bytes()
            self.assertEqual(
                evidence["primary_diff"],
                {
                    "path": ".codex-review/review.diff",
                    "sha256": hashlib.sha256(diff_bytes).hexdigest(),
                    "size": len(diff_bytes),
                },
            )
            return "success", "No findings."

        run_model_chain.side_effect = inspect_preflight

        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )

        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.final_text, "No findings.")

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_deleted_generic_token_in_diff_blocks_external_reviewer(
        self,
        resolve: mock.Mock,
    ) -> None:
        token = "z9Y8x7W6v5U4t3S2r1Q0p9O8n7M6"
        self.review.diff_file.write_text(
            "diff --git a/config b/config\n-AUTH_TOKEN=" + token + "\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("review.diff (generic-secret-assignment)", error)
        self.assertNotIn(token, error)

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_deleted_sensitive_path_blocks_external_reviewer(
        self,
        resolve: mock.Mock,
    ) -> None:
        (self.review.workspace_root / ".codex-review/changed-paths.z").write_bytes(
            b"config/.env.production\0"
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(".env.production (environment-file; changed-path)", error)

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_nested_credential_basename_blocks_external_reviewer(
        self,
        resolve: mock.Mock,
    ) -> None:
        credential = self.review.workspace_root / "fixtures/home/.netrc"
        credential.parent.mkdir(parents=True)
        credential.write_text("machine example.invalid\n", encoding="utf-8")
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("fixtures/home/.netrc (credential-path)", error)

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/codex"),
    )
    @mock.patch.object(providers, "run")
    def test_codex_command_pins_model_and_reasoning(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        thread_id = "019f18a6-ed56-7ff3-af51-08703a6d225a"
        codex_home = pathlib.Path(self.temporary.name) / "codex-home"
        rollout = (
            codex_home
            / "sessions/2026/06/30"
            / f"rollout-2026-06-30T21-10-20-{thread_id}.jsonl"
        )
        rollout.parent.mkdir(parents=True)
        rollout.write_text(
            json.dumps(
                {
                    "type": "turn_context",
                    "payload": {
                        "model": "gpt-5.6-sol",
                        "effort": "xhigh",
                        "approval_policy": "never",
                        "sandbox_policy": {"type": "read-only"},
                        "permission_profile": {
                            "type": "managed",
                            "network": "restricted",
                            "file_system": {
                                "type": "restricted",
                                "glob_scan_max_depth": 8,
                                "entries": [
                                    {
                                        "path": {
                                            "type": "special",
                                            "value": {"kind": "minimal"},
                                        },
                                        "access": "read",
                                    },
                                    {
                                        "path": {
                                            "type": "path",
                                            "path": str(self.review.workspace_root.resolve()),
                                        },
                                        "access": "read",
                                    },
                                    *[
                                        {
                                            "path": {
                                                "type": "path",
                                                "path": str(
                                                    (self.review.workspace_root / name).resolve()
                                                ),
                                            },
                                            "access": "deny",
                                        }
                                        for name in (".git", ".codex", ".agents")
                                    ],
                                    *[
                                        {
                                            "path": {
                                                "type": "glob_pattern",
                                                "pattern": str(
                                                    self.review.workspace_root.resolve()
                                                    / pattern
                                                ),
                                            },
                                            "access": "deny",
                                        }
                                        for pattern in ("*.env", "**/*.env")
                                    ],
                                ],
                            },
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        def complete(argv, **_kwargs):
            argv = tuple(argv)
            final_path = pathlib.Path(argv[argv.index("-o") + 1])
            final_path.parent.mkdir(parents=True, exist_ok=True)
            final_path.write_text("No findings.\n", encoding="utf-8")
            stdout = json.dumps(
                {"type": "thread.started", "thread_id": thread_id}
            ).encode()
            return Completed(argv=argv, returncode=0, stdout=stdout, stderr=b"")

        run_command.side_effect = complete
        attempt = providers._codex_attempt(
            review=self.review,
            model="gpt-5.6-sol",
            index=1,
            env={
                "CODEX_HOME": str(codex_home),
                "OPENAI_API_KEY": "parent-only-secret",
            },
        )
        argv = run_command.call_args.args[0]
        self.assertIn("gpt-5.6-sol", argv)
        self.assertIn('model_reasoning_effort="xhigh"', argv)
        configs = [argv[index + 1] for index, value in enumerate(argv) if value == "-c"]
        self.assertIn('approval_policy="never"', configs)
        self.assertIn('default_permissions="isolated_review"', configs)
        permission_configs = [
            value for value in configs if value.startswith("permissions.isolated_review=")
        ]
        self.assertEqual(len(permission_configs), 1)
        permission_config = permission_configs[0]
        parsed_permissions = tomllib.loads(
            f"profile = {permission_config.partition('=')[2]}"
        )["profile"]
        self.assertEqual(
            set(parsed_permissions["filesystem"]),
            {"glob_scan_max_depth", ":minimal", ":workspace_roots"},
        )
        self.assertIn('"glob_scan_max_depth"=8', permission_config)
        self.assertIn('":minimal"="read"', permission_config)
        self.assertIn('":workspace_roots"={"."="read"', permission_config)
        self.assertIn('".git"="deny"', permission_config)
        self.assertTrue(
            any("shell_environment_policy.inherit" in value for value in configs)
        )
        self.assertTrue(
            any("shell_environment_policy.set" in value for value in configs)
        )
        self.assertIn("project_doc_max_bytes=0", configs)
        self.assertNotIn("parent-only-secret", "\n".join(configs))
        self.assertIn("--skip-git-repo-check", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("--strict-config", argv)
        self.assertNotIn("-s", argv)
        final_path = pathlib.Path(argv[argv.index("-o") + 1])
        self.assertTrue(final_path.parent.is_dir())
        self.assertEqual(attempt.effective_model, "gpt-5.6-sol")
        self.assertEqual(attempt.effective_effort, "xhigh")
        self.assertEqual(attempt.category, "success")
        self.assertEqual(
            run_command.call_args.kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args.kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        )

    def test_codex_rejects_legacy_sandbox_override(self) -> None:
        payload = {
            "approval_policy": "never",
            "sandbox_policy": {"type": "workspace-write"},
            "permission_profile": {
                "type": "managed",
                "network": "restricted",
                "file_system": {"type": "restricted", "entries": []},
            },
        }
        self.assertFalse(
            providers._codex_permissions_match(
                payload,
                review_root=self.review.workspace_root,
            )
        )

    def test_codex_rejects_extra_permission_profile_read_path(self) -> None:
        root = self.review.workspace_root.resolve()
        payload = {
            "approval_policy": "never",
            "sandbox_policy": {"type": "read-only"},
            "permission_profile": {
                "type": "managed",
                "network": "restricted",
                "file_system": {
                    "type": "restricted",
                    "glob_scan_max_depth": 8,
                    "entries": [
                        {
                            "path": {
                                "type": "special",
                                "value": {"kind": "minimal"},
                            },
                            "access": "read",
                        },
                        {"path": {"type": "path", "path": str(root)}, "access": "read"},
                        *[
                            {
                                "path": {
                                    "type": "path",
                                    "path": str((root / name).resolve()),
                                },
                                "access": "deny",
                            }
                            for name in (".git", ".codex", ".agents")
                        ],
                        *[
                            {
                                "path": {
                                    "type": "glob_pattern",
                                    "pattern": str(root / pattern),
                                },
                                "access": "deny",
                            }
                            for pattern in ("*.env", "**/*.env")
                        ],
                        {
                            "path": {"type": "path", "path": str(root.parent)},
                            "access": "read",
                        },
                    ],
                },
            },
        }
        self.assertFalse(
            providers._codex_permissions_match(
                payload,
                review_root=self.review.workspace_root,
            )
        )

    def test_codex_allows_only_one_direct_arg_transport_file(self) -> None:
        root = self.review.workspace_root.resolve()
        codex_home = pathlib.Path(self.temporary.name) / "codex-home"
        arg_root = codex_home.resolve() / "tmp/arg0"

        def payload(extra_entries):
            return {
                "approval_policy": "never",
                "sandbox_policy": {"type": "read-only"},
                "permission_profile": {
                    "type": "managed",
                    "network": "restricted",
                    "file_system": {
                        "type": "restricted",
                        "glob_scan_max_depth": 8,
                        "entries": [
                            {
                                "path": {
                                    "type": "special",
                                    "value": {"kind": "minimal"},
                                },
                                "access": "read",
                            },
                            {"path": {"type": "path", "path": str(root)}, "access": "read"},
                            *[
                                {
                                    "path": {
                                        "type": "path",
                                        "path": str((root / name).resolve()),
                                    },
                                    "access": "deny",
                                }
                                for name in (".git", ".codex", ".agents")
                            ],
                            *[
                                {
                                    "path": {
                                        "type": "glob_pattern",
                                        "pattern": str(root / pattern),
                                    },
                                    "access": "deny",
                                }
                                for pattern in ("*.env", "**/*.env")
                            ],
                            *extra_entries,
                        ],
                    },
                },
            }

        def read_entry(path: pathlib.Path):
            return {
                "path": {"type": "path", "path": str(path)},
                "access": "read",
            }

        direct = read_entry(arg_root / "codex-arg0AbE73u")
        nested = read_entry(arg_root / "private/codex-arg0AbE73u")
        second = read_entry(arg_root / "codex-arg0Second")
        self.assertTrue(
            providers._codex_permissions_match(
                payload([direct]),
                review_root=root,
                codex_home=codex_home,
            )
        )
        for extras in ([nested], [direct, second]):
            with self.subTest(extras=extras):
                self.assertFalse(
                    providers._codex_permissions_match(
                        payload(extras),
                        review_root=root,
                        codex_home=codex_home,
                    )
                )

    @mock.patch.object(
        providers,
        "_native_macho_dependencies",
        return_value=(
            pathlib.Path("/review-install/claude"),
            pathlib.Path("/review-real/claude"),
        ),
    )
    def test_claude_probe_profile_only_reads_runtime_and_probe_roots(
        self,
        _dependencies: mock.Mock,
    ) -> None:
        profile = providers._claude_probe_sandbox_profile(
            pathlib.Path("/review-install/claude"),
            pathlib.Path("/isolated/probe-home"),
        )

        self.assertIn("(deny default)", profile)
        self.assertNotIn("(allow default)", profile)
        self.assertIn('(literal "/review-install/claude")', profile)
        self.assertIn('(literal "/review-real/claude")', profile)
        self.assertIn('(subpath "/isolated/probe-home")', profile)
        self.assertIn('(subpath "/review-install")', profile)
        self.assertIn('(subpath "/review-real")', profile)
        self.assertNotIn("(allow file-read-metadata)", profile)
        self.assertIn(
            '(allow file-read-metadata (literal "/")',
            profile,
        )
        self.assertNotIn("/Users/joey", profile)

    def test_claude_probe_profile_rejects_overly_broad_dependency_roots(
        self,
    ) -> None:
        for dependency in (
            pathlib.Path("/Users/joey/claude"),
            pathlib.Path("/claude"),
        ):
            with (
                self.subTest(dependency=dependency),
                mock.patch.object(
                    providers,
                    "_native_macho_dependencies",
                    return_value=(dependency,),
                ),
                mock.patch.dict(providers.os.environ, {"HOME": "/Users/joey"}),
            ):
                with self.assertRaisesRegex(
                    providers.InvalidReviewerExecutable, "overly broad"
                ):
                    providers._claude_probe_sandbox_profile(
                        dependency,
                        pathlib.Path("/isolated/probe-home"),
                    )

    def test_claude_preflight_probe_environment_ignores_ambient_secrets(
        self,
    ) -> None:
        with mock.patch.dict(
            providers.os.environ,
            {
                "ALL_PROXY": "http://user:secret@proxy.invalid:8080",
                "ANTHROPIC_API_KEY": "secret-api-key",
                "CURL_CA_BUNDLE": "/secret/curl-ca.pem",
                "HTTPS_PROXY": "http://user:secret@proxy.invalid:8080",
                "HTTP_PROXY": "http://user:secret@proxy.invalid:8080",
                "REQUESTS_CA_BUNDLE": "/secret/requests-ca.pem",
                "SECRET_SENTINEL": "must-not-cross-preflight-boundary",
                "NODE_EXTRA_CA_CERTS": "/secret/node-extra-ca.pem",
                "SSL_CERT_DIR": "/secret/certs",
                "SSL_CERT_FILE": "/secret/ssl-ca.pem",
                "all_proxy": "http://lower:secret@proxy.invalid:8080",
                "http_proxy": "http://lower:secret@proxy.invalid:8080",
                "https_proxy": "http://lower:secret@proxy.invalid:8080",
            },
            clear=True,
        ):
            environment = providers._claude_preflight_probe_environment(
                home=pathlib.Path("/isolated/probe-home"),
                tmp=pathlib.Path("/isolated/tmp"),
            )

        self.assertEqual(
            environment,
            {
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_SAFE_MODE": "1",
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
                "HOME": "/isolated/probe-home",
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin",
                "TEMP": "/isolated/tmp",
                "TMP": "/isolated/tmp",
                "TMPDIR": "/isolated/tmp",
            },
        )

    @mock.patch.object(providers, "_run_claude_probe")
    def test_claude_identity_accepts_floating_supported_version(
        self,
        run_probe: mock.Mock,
    ) -> None:
        run_probe.return_value = Completed(
            argv=("claude", "--version"),
            returncode=0,
            stdout=b"2.1.211 (Claude Code)\n",
            stderr=b"",
        )

        version = providers._require_claude_identity(
            pathlib.Path("/bin/claude"),
            {"HOME": "/isolated/probe-home"},
        )

        self.assertEqual(version.text, "2.1.211")

    @mock.patch.object(providers, "_run_claude_probe")
    def test_claude_identity_rejects_old_or_next_major_version(
        self,
        run_probe: mock.Mock,
    ) -> None:
        for output in (
            b"2.1.210 (Claude Code)\n",
            b"3.0.0 (Claude Code)\n",
        ):
            with self.subTest(output=output):
                run_probe.return_value = Completed(
                    argv=("claude", "--version"),
                    returncode=0,
                    stdout=output,
                    stderr=b"",
                )
                with self.assertRaisesRegex(
                    providers.InvalidReviewerExecutable,
                    "supported >=2.1.211,<3 range",
                ):
                    providers._require_claude_identity(
                        pathlib.Path("/bin/claude"),
                        {"HOME": "/isolated/probe-home"},
                    )

    def test_real_resolver_types_rejected_automatic_claude_candidate(
        self,
    ) -> None:
        wrapper = self.review.source_root / "claude"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)

        def reject_candidate(_candidate: pathlib.Path) -> None:
            raise providers.InvalidReviewerExecutable("not native")

        with (
            mock.patch.object(
                common,
                "_user_executable_candidates",
                return_value=(wrapper,),
            ),
            mock.patch.object(common.shutil, "which", return_value=None),
            mock.patch.object(
                common.pathlib.Path,
                "is_file",
                autospec=True,
                side_effect=lambda path: path == wrapper,
            ),
            mock.patch.object(
                common.os,
                "access",
                side_effect=lambda path, _mode: pathlib.Path(path) == wrapper,
            ),
            mock.patch.dict(common.os.environ, {}, clear=True),
            self.assertRaises(common.RejectedReviewerCandidates),
        ):
            common.resolve_reviewer_executable(
                "claude",
                candidate_validator=reject_candidate,
            )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=common.RejectedReviewerCandidates("only wrapper found"),
    )
    def test_claude_resolver_maps_automatic_rejection_to_unavailable(
        self,
        _resolve: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeExecutableUnavailable,
            "only wrapper found",
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={"HOME": str(self.review.container_dir / "home")},
            )

    def test_claude_linux_probe_uses_synthetic_root_backend(self) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/opt/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock()
        library_roots = (pathlib.Path("/lib"), pathlib.Path("/usr/lib"))
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                return_value=info,
            ),
            mock.patch.object(
                providers,
                "discover_claude_linux_toolchain",
                return_value=toolchain,
            ),
            mock.patch.object(
                providers,
                "_claude_linux_bootstrap_library_roots",
                return_value=library_roots,
            ),
            mock.patch.object(
                providers,
                "build_claude_linux_probe_command",
                return_value=("/usr/bin/bwrap", "--probe"),
            ) as build_probe,
        ):
            command = providers._claude_probe_command(
                executable,
                self.review.container_dir,
                "--version",
            )

        self.assertEqual(command, ("/usr/bin/bwrap", "--probe"))
        build_probe.assert_called_once_with(
            host,
            toolchain,
            executable,
            self.review.container_dir,
            (),
            ("--version",),
            library_roots=library_roots,
        )

    def test_claude_linux_runtime_dependency_error_mapping(self) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/verified/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock(
            socat=pathlib.Path("/usr/bin/socat"),
            rg=pathlib.Path("/usr/bin/rg"),
        )
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        cases = (
            (
                providers.LinuxHostDependencyUnavailable("missing trusted ldd"),
                providers.ClaudeProbeSandboxUnavailable,
            ),
            (
                providers.LinuxRuntimeInspectionInconclusive("ldd output raced"),
                providers.ClaudeExecutableInspectionInconclusive,
            ),
            (
                providers.LinuxRuntimeUnsafe("writable library parent"),
                providers.LinuxRuntimeUnsafe,
            ),
        )

        for failure, expected in cases:
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(
                    providers, "_claude_linux_host", return_value=host
                ),
                mock.patch.object(
                    providers,
                    "validate_claude_linux_executable",
                    return_value=info,
                ),
                mock.patch.object(
                    providers,
                    "discover_claude_linux_toolchain",
                    return_value=toolchain,
                ),
                mock.patch.object(
                    providers,
                    "_claude_linux_runtime_root",
                    return_value=runtime_root,
                ),
                mock.patch.object(
                    providers,
                    "_claude_linux_private_directory",
                    return_value=runtime_root / "private",
                ),
                mock.patch.object(
                    providers,
                    "compile_claude_linux_launcher",
                    return_value=runtime_root / "launcher",
                ),
                mock.patch.object(
                    providers,
                    "collect_claude_linux_runtime_libraries",
                    side_effect=failure,
                ),
                self.assertRaises(expected),
            ):
                with providers._claude_linux_review_runtime(
                    self.review,
                    executable,
                    {},
                    ("--print", "review"),
                ):
                    pass

    def test_claude_linux_prelaunch_credential_failure_keeps_probe_pending(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")

        @contextlib.contextmanager
        def failing_runtime():
            raise providers.LinuxCredentialUnavailable("credential unavailable")
            yield  # pragma: no cover

        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "outer_sandbox": {"status": "pending-runtime-launch"},
                "authentication": {"status": "pending"},
            },
        )
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                return_value=failing_runtime(),
            ),
            mock.patch.object(providers, "run") as run_command,
            self.assertRaisesRegex(
                providers.ClaudeKeychainCredentialUnavailable,
                "credential unavailable",
            ),
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        run_command.assert_not_called()
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["phase"], "blocked-authentication")
        self.assertEqual(
            report["outer_sandbox"]["status"],
            "pending-isolation-probe",
        )
        self.assertIsNone(report["attempt"])

    def test_claude_linux_refresh_writeback_failure_blocks_authentication(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")
        completed = Completed(
            argv=("sandbox",),
            returncode=0,
            stdout=b"{}",
            stderr=b"",
        )

        def run_after_spawn(*_args: object, **kwargs: object) -> Completed:
            on_process_started = kwargs.get("on_process_started")
            assert callable(on_process_started)
            on_process_started()
            return completed

        @contextlib.contextmanager
        def failing_runtime():
            yield mock.Mock(argv=("sandbox",), env={})
            raise providers.LinuxCredentialUnsafe(
                "host credential changed before refresh writeback"
            )

        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "authentication": {"status": "pending"},
            },
        )
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                return_value=failing_runtime(),
            ),
            mock.patch.object(
                providers,
                "run",
                side_effect=run_after_spawn,
            ) as run_command,
            self.assertRaisesRegex(
                providers.ClaudeCredentialUnsafe,
                "changed before refresh writeback",
            ) as raised,
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        run_command.assert_called_once()
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["phase"], "blocked-authentication")
        self.assertEqual(report["status"], "blocked-authentication")
        self.assertEqual(report["category"], "blocked-authentication")
        self.assertEqual(
            report["authentication"]["status"],
            "blocked-authentication",
        )
        self.assertEqual(
            report["authentication"]["failure_class"],
            "refresh-persistence",
        )
        self.assertEqual(report["attempt"]["returncode"], 0)
        attempt = getattr(
            raised.exception,
            "_codex_claude_persistence_attempt",
        )
        self.assertIsInstance(attempt, providers.Attempt)
        self.assertEqual(attempt.category, "blocked-authentication")
        self.assertEqual(attempt.returncode, 0)

    def test_claude_linux_auth_rejection_precedes_inspection_failure(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")
        completed = Completed(
            argv=("sandbox",),
            returncode=1,
            stdout=b"",
            stderr=b"HTTP 401 Unauthorized; please run /login",
        )

        def run_after_spawn(*_args: object, **kwargs: object) -> Completed:
            on_process_started = kwargs.get("on_process_started")
            assert callable(on_process_started)
            on_process_started()
            return completed

        @contextlib.contextmanager
        def failing_runtime():
            yield mock.Mock(argv=("sandbox",), env={})
            raise providers.LinuxCredentialInspectionInconclusive(
                "final credential snapshot unavailable"
            )

        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "authentication": {"status": "pending"},
            },
        )
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                return_value=failing_runtime(),
            ),
            mock.patch.object(
                providers,
                "run",
                side_effect=run_after_spawn,
            ),
            self.assertRaisesRegex(
                providers.ClaudeKeychainCredentialUnavailable,
                "rejected the configured credential",
            ) as raised,
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        attempt = getattr(
            raised.exception,
            "_codex_claude_persistence_attempt",
        )
        self.assertIsInstance(attempt, providers.Attempt)
        self.assertEqual(attempt.category, "auth")
        self.assertEqual(attempt.returncode, 1)

    def test_claude_persistence_attempt_log_failures_are_best_effort(
        self,
    ) -> None:
        completed = Completed(
            argv=("sandbox",),
            returncode=1,
            stdout=b"",
            stderr=b"",
        )
        failure_patches = (
            (
                "attempt-directory",
                mock.patch.object(
                    pathlib.Path,
                    "mkdir",
                    side_effect=OSError("attempt directory unavailable"),
                ),
            ),
            (
                "empty-log",
                mock.patch.object(
                    pathlib.Path,
                    "touch",
                    side_effect=OSError("attempt log unavailable"),
                ),
            ),
            (
                "append",
                mock.patch.object(
                    providers,
                    "_append_attempt_diagnostic",
                    side_effect=OSError("attempt diagnostic unavailable"),
                ),
            ),
        )

        for index, (label, failure_patch) in enumerate(
            failure_patches,
            start=1,
        ):
            with self.subTest(label=label), failure_patch:
                attempt = providers._claude_persistence_failed_attempt(
                    review=self.review,
                    index=index,
                    model=providers.CLAUDE_MODELS[0],
                    completed=completed,
                    category="inconclusive",
                )

                self.assertEqual(attempt.category, "inconclusive")
                self.assertEqual(attempt.returncode, 1)

    def test_auth_rejection_preserves_recovery_when_attempt_log_fails(
        self,
    ) -> None:
        completed = Completed(
            argv=("sandbox",),
            returncode=1,
            stdout=b"",
            stderr=b"HTTP 401 Unauthorized; please run /login",
        )
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-attempt-log-failure"
        )
        carrier.mkdir(parents=True, mode=0o700)
        inspection_error = providers.LinuxCredentialInspectionInconclusive(
            "final credential snapshot unavailable"
        )
        setattr(
            inspection_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        setattr(
            inspection_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )

        with mock.patch.object(
            providers,
            "_append_attempt_diagnostic",
            side_effect=OSError("attempt diagnostic unavailable"),
        ):
            failure = (
                providers._claude_auth_rejection_after_credential_inspection(
                    review=self.review,
                    index=1,
                    model=providers.CLAUDE_MODELS[0],
                    completed=completed,
                    inspection_error=inspection_error,
                )
            )

        self.assertIsInstance(
            failure,
            providers.ClaudeKeychainCredentialUnavailable,
        )
        assert failure is not None
        self.assertEqual(
            getattr(
                failure,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )
        self.assertIs(
            getattr(
                failure,
                "_codex_claude_refresh_persistence_failed",
                False,
            ),
            True,
        )
        attempt = getattr(
            failure,
            "_codex_claude_persistence_attempt",
        )
        self.assertIsInstance(attempt, providers.Attempt)
        self.assertEqual(attempt.category, "auth")

    def test_claude_linux_report_error_preserves_recovery_carrier(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")
        completed = Completed(
            argv=("sandbox",),
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-report-error"
        )
        carrier.mkdir(parents=True, mode=0o700)
        inspection_error = providers.LinuxCredentialInspectionInconclusive(
            "final credential snapshot unavailable"
        )
        setattr(
            inspection_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        setattr(
            inspection_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        report_error = OSError("runtime report write failed")
        original_update = providers._update_claude_runtime_report

        def run_after_spawn(*_args: object, **kwargs: object) -> Completed:
            on_process_started = kwargs.get("on_process_started")
            assert callable(on_process_started)
            on_process_started()
            return completed

        @contextlib.contextmanager
        def failing_runtime():
            yield mock.Mock(argv=("sandbox",), env={})
            raise inspection_error

        def fail_inconclusive_report(
            review: ReviewWorkspace,
            report: dict[str, object],
        ) -> None:
            if report.get("phase") == "authentication-inspection-inconclusive":
                raise report_error
            original_update(review, report)

        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "authentication": {"status": "pending"},
            },
        )
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                return_value=failing_runtime(),
            ),
            mock.patch.object(
                providers,
                "_update_claude_runtime_report",
                side_effect=fail_inconclusive_report,
            ),
            mock.patch.object(
                providers,
                "run",
                side_effect=run_after_spawn,
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        self.assertIs(raised.exception.__cause__, report_error)
        self.assertIn(str(carrier), str(raised.exception))
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )

    def test_claude_linux_supervision_failure_does_not_claim_writer_quiescence(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")
        lifecycle_states: list[tuple[bool, bool]] = []

        @contextlib.contextmanager
        def observing_runtime(
            *_args: object,
            writer_started=None,
            writer_quiescent=None,
            **_kwargs: object,
        ):
            assert callable(writer_started)
            assert callable(writer_quiescent)
            self.assertFalse(writer_started())
            self.assertFalse(writer_quiescent())
            try:
                yield mock.Mock(argv=("sandbox",), env={})
            finally:
                lifecycle_states.append(
                    (writer_started(), writer_quiescent())
                )

        def timeout_after_spawn(*_args: object, **kwargs: object) -> None:
            on_process_started = kwargs.get("on_process_started")
            assert callable(on_process_started)
            on_process_started()
            raise providers.ReviewTimeoutError("review timed out")

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                side_effect=observing_runtime,
            ),
            mock.patch.object(
                providers,
                "run",
                side_effect=timeout_after_spawn,
            ),
            self.assertRaises(providers.ReviewTimeoutError),
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        self.assertEqual(lifecycle_states, [(True, False)])

    def test_claude_linux_pre_spawn_failure_keeps_writer_unstarted(
        self,
    ) -> None:
        executable = pathlib.Path("/verified/claude")
        lifecycle_states: list[tuple[bool, bool]] = []

        @contextlib.contextmanager
        def observing_runtime(
            *_args: object,
            writer_started=None,
            writer_quiescent=None,
            **_kwargs: object,
        ):
            assert callable(writer_started)
            assert callable(writer_quiescent)
            try:
                yield mock.Mock(argv=("sandbox",), env={})
            finally:
                lifecycle_states.append(
                    (writer_started(), writer_quiescent())
                )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_linux_review_runtime",
                side_effect=observing_runtime,
            ),
            mock.patch.object(
                providers,
                "run",
                side_effect=OSError("fixture pre-spawn failure"),
            ),
            self.assertRaisesRegex(OSError, "pre-spawn failure"),
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        self.assertEqual(lifecycle_states, [(False, False)])

    def test_claude_persistence_diagnostic_reports_retained_private_carrier(
        self,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-fixture"
        )
        carrier.mkdir(parents=True, mode=0o700)
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}},
        )
        error = providers.ReviewTimeoutError("review timed out")
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )

        diagnostic = providers._record_claude_secondary_persistence_failure(
            self.review,
            error,
        )

        assert diagnostic is not None
        self.assertIn(str(carrier), diagnostic)
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    def test_persistence_report_signal_overrides_original_error(self) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-report-signal"
        )
        carrier.mkdir(parents=True, mode=0o700)
        original = providers.ReviewTimeoutError("review timed out")
        setattr(original, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            original,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers,
                "_update_claude_runtime_report",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._record_claude_secondary_persistence_failure(
                self.review,
                original,
            )

        self.assertIs(raised.exception, forwarded)
        self.assertIsNotNone(forwarded.detail)
        self.assertIn(str(carrier), forwarded.detail or "")
        self.assertEqual(
            getattr(
                forwarded,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )

    def test_recovery_path_resolution_preserves_forwarded_signal(self) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-signal"
        )
        carrier.mkdir(parents=True, mode=0o700)
        error = providers.ClaudeCredentialInspectionInconclusive(
            "guarded host writeback failed"
        )
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers,
                "_claude_nofollow_artifact_snapshot",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._validated_claude_retained_credential_carrier(
                self.review,
                error,
            )

        self.assertIs(raised.exception, forwarded)

    def test_macos_inconclusive_report_signal_preserves_recovery_path(
        self,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-inconclusive-report-signal"
        )
        carrier.mkdir(parents=True, mode=0o700)
        persistence_error = providers.ClaudeCredentialInspectionInconclusive(
            "guarded host writeback failed"
        )
        setattr(
            persistence_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        setattr(
            persistence_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        forwarded = providers.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                providers,
                "_update_claude_runtime_report",
                side_effect=forwarded,
            ),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            providers._update_claude_runtime_report_preserving_persistence(
                self.review,
                {"phase": "authentication-inspection-inconclusive"},
                persistence_error,
            )

        self.assertIs(raised.exception, forwarded)
        self.assertIn(str(carrier), forwarded.detail or "")
        self.assertEqual(
            getattr(
                forwarded,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )

    def test_macos_inconclusive_report_error_preserves_recovery_path(
        self,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "macos"
            / "claude-carrier-inconclusive-report-error"
        )
        carrier.mkdir(parents=True, mode=0o700)
        persistence_error = providers.ClaudeCredentialInspectionInconclusive(
            "guarded host writeback failed"
        )
        setattr(
            persistence_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        setattr(
            persistence_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        report_error = OSError("runtime report write failed")

        with (
            mock.patch.object(
                providers,
                "_update_claude_runtime_report",
                side_effect=report_error,
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            providers._update_claude_runtime_report_preserving_persistence(
                self.review,
                {"phase": "authentication-inspection-inconclusive"},
                persistence_error,
            )

        self.assertIs(raised.exception.__cause__, report_error)
        self.assertIn(str(carrier), str(raised.exception))
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            ),
            str(carrier),
        )

    def test_claude_persistence_diagnostic_populates_forwarded_signal_detail(
        self,
    ) -> None:
        carrier = (
            self.review.container_dir
            / "claude-runtime"
            / "linux"
            / "claude-carrier-signal"
        )
        carrier.mkdir(parents=True, mode=0o700)
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}},
        )
        error = providers.ForwardedSignal(
            signal.SIGTERM,
            detail="review process group stopped",
        )
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )

        diagnostic = providers._record_claude_secondary_persistence_failure(
            self.review,
            error,
        )

        assert diagnostic is not None
        assert error.detail is not None
        self.assertIn("review process group stopped", error.detail)
        self.assertIn(str(carrier), error.detail)
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["recovery_carrier"],
            str(carrier),
        )

    def test_claude_persistence_diagnostic_ignores_malformed_carrier_path(
        self,
    ) -> None:
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"authentication": {}},
        )
        error = providers.ForwardedSignal(signal.SIGTERM)
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            "/malformed\0carrier",
        )

        diagnostic = providers._record_claude_secondary_persistence_failure(
            self.review,
            error,
        )

        self.assertEqual(
            diagnostic,
            providers.CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
        )
        self.assertEqual(error.detail, diagnostic)
        report = common.read_json(
            self.review.container_dir / "claude-runtime.json"
        )
        self.assertEqual(
            report["authentication"]["refresh_persistence"],
            "failed-after-attempt",
        )
        self.assertNotIn("recovery_carrier", report["authentication"])

    def test_macos_coordination_surfaces_inconclusive_lock_cleanup_paths(
        self,
    ) -> None:
        lock_path = pathlib.Path("/fixture/.claude/.oauth_refresh.lock")
        cleanup_error = (
            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
                "helper-owned lock paths may remain at "
                f"{lock_path}; confirm that no writer is active before cleanup"
            )
        )

        @contextlib.contextmanager
        def failing_refresh_lock(*_args: object, **_kwargs: object):
            raise cleanup_error
            yield  # pragma: no cover

        with (
            mock.patch.object(
                providers,
                "_claude_credential_update_lock",
                side_effect=lambda _label: contextlib.nullcontext(),
            ),
            mock.patch.object(
                providers,
                "claude_refresh_lock",
                side_effect=failing_refresh_lock,
            ),
            self.assertRaises(
                providers.ClaudeCredentialInspectionInconclusive
            ) as raised,
        ):
            with providers._claude_macos_carrier_coordination(
                self.claude_refresh_lock_protocol
            ):
                self.fail("inconclusive cleanup unexpectedly yielded")

        self.assertIn(str(lock_path), str(raised.exception))
        self.assertIn("no writer is active", str(raised.exception))

    def test_claude_linux_stages_single_attempt_credential_each_time(
        self,
    ) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/verified/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock(
            socat=pathlib.Path("/usr/bin/socat"),
            rg=pathlib.Path("/usr/bin/rg"),
        )
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        runtime_root.mkdir(parents=True, exist_ok=True)
        source = self.review.source_root / ".claude" / ".credentials.json"
        staged = mock.Mock(config_dir=runtime_root / "staged-config")
        attempts = (
            self.attempt("claude", providers.CLAUDE_MODELS[0], "entitlement"),
            self.attempt(
                "claude",
                providers.CLAUDE_MODELS[1],
                "success",
                final_text="No findings.",
            ),
        )
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=b"{}",
            stderr=b"",
        )

        def run_after_spawn(*_args: object, **kwargs: object) -> Completed:
            on_process_started = kwargs.get("on_process_started")
            assert callable(on_process_started)
            on_process_started()
            return completed

        started_callbacks: list[Callable[[], bool]] = []
        quiescence_callbacks: list[Callable[[], bool]] = []
        lifecycle_exit_states: list[tuple[bool, bool]] = []

        @contextlib.contextmanager
        def staged_context(
            writer_started: Callable[[], bool],
            writer_quiescent: Callable[[], bool],
        ):
            try:
                yield staged
            finally:
                lifecycle_exit_states.append(
                    (writer_started(), writer_quiescent())
                )

        def stage_once(*_args: object, **kwargs: object):
            writer_started = kwargs.get("writer_started")
            writer_quiescent = kwargs.get("writer_quiescent")
            assert callable(writer_started)
            assert callable(writer_quiescent)
            self.assertFalse(writer_started())
            self.assertFalse(writer_quiescent())
            started_callbacks.append(writer_started)
            quiescence_callbacks.append(writer_quiescent)
            return staged_context(writer_started, writer_quiescent)

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_is_claude_linux_host",
                    return_value=True,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_linux_host",
                    return_value=host,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "validate_claude_linux_executable",
                    return_value=info,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "discover_claude_linux_toolchain",
                    return_value=toolchain,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_linux_runtime_root",
                    return_value=runtime_root,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_linux_private_directory",
                    side_effect=lambda _review, name: runtime_root / name,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "compile_claude_linux_launcher",
                    return_value=runtime_root / "bin/launcher",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "collect_claude_linux_runtime_libraries",
                    return_value=(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_linux_ca_bundle",
                    return_value=runtime_root / "ca/bundle.pem",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_linux_credential_source",
                    return_value=source,
                )
            )
            stage_credentials = stack.enter_context(
                mock.patch.object(
                    providers,
                    "stage_claude_credentials",
                    side_effect=stage_once,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_claude_unix_connect_proxy",
                    return_value=contextlib.nullcontext(runtime_root / "proxy.sock"),
                )
            )
            isolation_probe = stack.enter_context(
                mock.patch.object(providers, "run_claude_linux_isolation_probe")
            )
            stack.enter_context(
                mock.patch.object(providers, "_update_claude_runtime_report")
            )
            build_sandbox = stack.enter_context(
                mock.patch.object(
                    providers,
                    "build_claude_linux_sandbox_command",
                    return_value=mock.Mock(argv=("sandbox",), env={}),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_with_claude_review_tool_path",
                    side_effect=lambda _review, env: dict(env),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_prepare_claude_tls_environment",
                    side_effect=lambda _review, env: dict(env),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "run",
                    side_effect=run_after_spawn,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_parse_claude_output",
                    return_value=(None, None),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    providers,
                    "_record_attempt",
                    side_effect=attempts,
                )
            )
            recorded_attempts: list[providers.Attempt] = []

            def runner(**kwargs) -> providers.Attempt:
                return providers._claude_attempt(
                    executable=executable,
                    refresh_lock_protocol=self.claude_refresh_lock_protocol,
                    **kwargs,
                )

            category, final_text = providers._run_model_chain(
                review=self.review,
                models=providers.CLAUDE_MODELS,
                runner=runner,
                runtime="claude",
                requested_effort=providers.CLAUDE_REASONING_EFFORT,
                env={},
                attempts=recorded_attempts,
            )

            self.assertEqual(category, "success")
            self.assertEqual(final_text, "No findings.")
            self.assertEqual(recorded_attempts, list(attempts))
            self.assertEqual(
                stage_credentials.call_count,
                len(providers.CLAUDE_MODELS),
            )
            for call in stage_credentials.call_args_list:
                self.assertEqual(call.args, (source, runtime_root))
            self.assertTrue(all(callback() for callback in started_callbacks))
            self.assertTrue(all(callback() for callback in quiescence_callbacks))
            self.assertEqual(
                lifecycle_exit_states,
                [(True, True)] * len(providers.CLAUDE_MODELS),
            )
            for call in build_sandbox.call_args_list:
                self.assertFalse(
                    call.args[0].node_extra_ca_certs_configured
                )

            with providers._claude_linux_review_runtime(
                self.review,
                executable,
                {
                    "ANTHROPIC_API_KEY": "test-only",
                    "NODE_EXTRA_CA_CERTS": "/caller/node-extra-ca.pem",
                },
                providers._claude_review_arguments(
                    model=providers.CLAUDE_MODELS[0],
                    settings=providers._claude_review_settings(linux=True),
                    linux=True,
                ),
            ):
                pass

            self.assertEqual(
                stage_credentials.call_count,
                len(providers.CLAUDE_MODELS),
            )
            for captured in (
                isolation_probe.call_args.args[0],
                build_sandbox.call_args.args[0],
            ):
                self.assertTrue(captured.node_extra_ca_certs_configured)
                self.assertEqual(
                    captured.ca_bundle,
                    runtime_root / "ca/bundle.pem",
                )
            self.assertEqual(
                build_sandbox.call_args.kwargs["auth_env"],
                {"ANTHROPIC_API_KEY": "test-only"},
            )

    def test_claude_linux_final_workspace_inspection_is_inconclusive(self) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/verified/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock(
            socat=pathlib.Path("/usr/bin/socat"),
            rg=pathlib.Path("/usr/bin/rg"),
        )
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        runtime_root.mkdir(parents=True, exist_ok=True)
        failure = providers.LinuxRuntimeInspectionInconclusive(
            "workspace symlink changed during inspection"
        )

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                return_value=info,
            ),
            mock.patch.object(
                providers,
                "discover_claude_linux_toolchain",
                return_value=toolchain,
            ),
            mock.patch.object(
                providers,
                "_claude_linux_runtime_root",
                return_value=runtime_root,
            ),
            mock.patch.object(
                providers,
                "_claude_linux_private_directory",
                side_effect=lambda _review, name: runtime_root / name,
            ),
            mock.patch.object(
                providers,
                "compile_claude_linux_launcher",
                return_value=runtime_root / "bin/launcher",
            ),
            mock.patch.object(
                providers,
                "collect_claude_linux_runtime_libraries",
                return_value=(),
            ),
            mock.patch.object(providers, "_claude_linux_ca_bundle", return_value=None),
            mock.patch.object(
                providers,
                "_claude_unix_connect_proxy",
                return_value=contextlib.nullcontext(runtime_root / "proxy.sock"),
            ),
            mock.patch.object(providers, "run_claude_linux_isolation_probe"),
            mock.patch.object(providers, "_update_claude_runtime_report"),
            mock.patch.object(
                providers,
                "build_claude_linux_sandbox_command",
                side_effect=failure,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "workspace symlink",
            ),
        ):
            with providers._claude_linux_review_runtime(
                self.review,
                executable,
                {"ANTHROPIC_API_KEY": "test-only"},
                ("--print", "review"),
            ):
                pass

    def test_claude_linux_launcher_error_mapping(self) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/verified/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock()
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        cases = (
            (
                providers.LinuxIsolationUnavailable("compiler rejected launcher"),
                providers.ClaudeProbeSandboxUnavailable,
            ),
            (
                providers.LinuxRuntimeInspectionInconclusive("compiler path raced"),
                providers.ClaudeExecutableInspectionInconclusive,
            ),
            (
                providers.LinuxRuntimeUnsafe("unsafe compiler path"),
                providers.LinuxRuntimeUnsafe,
            ),
        )

        for failure, expected in cases:
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(
                    providers, "_claude_linux_host", return_value=host
                ),
                mock.patch.object(
                    providers,
                    "validate_claude_linux_executable",
                    return_value=info,
                ),
                mock.patch.object(
                    providers,
                    "discover_claude_linux_toolchain",
                    return_value=toolchain,
                ),
                mock.patch.object(
                    providers,
                    "_claude_linux_runtime_root",
                    return_value=runtime_root,
                ),
                mock.patch.object(
                    providers,
                    "_claude_linux_private_directory",
                    return_value=runtime_root / "private",
                ),
                mock.patch.object(
                    providers,
                    "compile_claude_linux_launcher",
                    side_effect=failure,
                ),
                self.assertRaises(expected),
            ):
                with providers._claude_linux_review_runtime(
                    self.review,
                    executable,
                    {},
                    ("--print", "review"),
                ):
                    pass

    def test_claude_linux_runtime_root_rejects_symlink_without_chmod(self) -> None:
        victim = self.review.source_root / "runtime-victim"
        victim.mkdir(mode=0o755)
        victim.chmod(0o755)
        victim_mode = stat.S_IMODE(victim.stat().st_mode)
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        runtime_root.symlink_to(victim, target_is_directory=True)

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(providers, "reject_claude_wsl_windows_path"),
            self.assertRaisesRegex(ReviewError, "real directory"),
        ):
            providers._claude_linux_runtime_root(self.review)

        self.assertTrue(runtime_root.is_symlink())
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), victim_mode)

    def test_claude_linux_private_directory_rejects_symlink_without_chmod(
        self,
    ) -> None:
        victim = self.review.source_root / "private-victim"
        victim.mkdir(mode=0o755)
        victim.chmod(0o755)
        victim_mode = stat.S_IMODE(victim.stat().st_mode)

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(providers, "reject_claude_wsl_windows_path"),
        ):
            runtime_root = providers._claude_linux_runtime_root(self.review)
            private_path = runtime_root / "home"
            private_path.symlink_to(victim, target_is_directory=True)
            with self.assertRaisesRegex(ReviewError, "real directory"):
                providers._claude_linux_private_directory(self.review, "home")

        self.assertTrue(private_path.is_symlink())
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), victim_mode)

    def test_claude_linux_runtime_root_rejects_unsafe_mode_without_chmod(
        self,
    ) -> None:
        runtime_root = self.review.container_dir / "claude-runtime" / "linux"
        runtime_root.mkdir(mode=0o755)
        runtime_root.chmod(0o755)

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(providers, "reject_claude_wsl_windows_path"),
            self.assertRaisesRegex(ReviewError, "must be 0700"),
        ):
            providers._claude_linux_runtime_root(self.review)

        self.assertEqual(stat.S_IMODE(runtime_root.stat().st_mode), 0o755)

    def test_claude_linux_runtime_root_preserves_mountinfo_inconclusive(
        self,
    ) -> None:
        failure = providers.LinuxRuntimeInspectionInconclusive(
            "cannot read WSL2 mountinfo"
        )

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(
                providers,
                "reject_claude_wsl_windows_path",
                side_effect=failure,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._claude_linux_runtime_root(self.review)

    def test_claude_linux_runtime_root_blocks_windows_filesystem(self) -> None:
        failure = providers.LinuxRuntimeUnsafe("runtime root is on DrvFS")

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(
                providers,
                "reject_claude_wsl_windows_path",
                side_effect=failure,
            ),
            self.assertRaisesRegex(providers.LinuxRuntimeUnsafe, "DrvFS"),
        ):
            providers._claude_linux_runtime_root(self.review)

    def test_claude_linux_credential_source_preserves_mountinfo_inconclusive(
        self,
    ) -> None:
        failure = providers.LinuxRuntimeInspectionInconclusive(
            "cannot parse WSL2 mountinfo"
        )

        with (
            mock.patch.object(providers, "_claude_linux_host", return_value=mock.Mock()),
            mock.patch.object(
                providers,
                "reject_claude_wsl_windows_path",
                side_effect=failure,
            ),
            mock.patch.dict(
                providers.os.environ,
                {"HOME": str(self.review.container_dir)},
                clear=True,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._claude_linux_credential_source()

    def test_claude_wsl2_rejects_review_state_on_windows_drive(self) -> None:
        root = pathlib.Path("/mnt/c/review-source")
        review = ReviewWorkspace(
            source_root=root,
            container_dir=root / ".codex-tmp" / "review",
            workspace_root=root / ".codex-tmp" / "review" / "workspace",
            base_ref="a" * 40,
            head_ref="b" * 40,
            diff_file=root / "review.diff",
            prompt_file=root / "review.prompt",
        )
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            self.assertRaisesRegex(
                providers.LinuxRuntimeUnsafe,
                "Windows drive",
            ),
        ):
            providers._resolve_validated_claude_executable(
                review=review,
                env={},
            )

    def test_claude_wsl2_review_state_mountinfo_failure_is_inconclusive(
        self,
    ) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        failure = providers.LinuxRuntimeInspectionInconclusive(
            "cannot read WSL2 mountinfo"
        )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "reject_claude_wsl_windows_path",
                side_effect=failure,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        self.assertFalse((self.review.container_dir / "claude-home").exists())

    def test_claude_gpg_temp_root_does_not_repair_existing_mode(self) -> None:
        temp_root = self.review.container_dir / "claude-runtime" / "gpg-tmp"
        temp_root.mkdir(mode=0o700)
        temp_root.chmod(0o755)

        with self.assertRaisesRegex(ReviewError, "must be 0700"):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        self.assertEqual(stat.S_IMODE(temp_root.stat().st_mode), 0o755)

    def test_claude_wsl2_rejects_drvfs_gpg_temp_root_as_invalid(self) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        validator = providers._claude_gpg_temp_root_validator(host)
        mountinfo = (
            "24 1 0:22 / / rw,relatime - 9p drvfs rw,aname=drvfs"
        )

        with (
            mock.patch.object(
                claude_linux,
                "_read_mountinfo",
                return_value=mountinfo,
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceInvalid,
                "Linux-native filesystem",
            ),
        ):
            validator((self.review.container_dir,))

    def test_claude_wsl2_gpg_temp_mountinfo_failure_is_inconclusive(self) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        validator = providers._claude_gpg_temp_root_validator(host)

        with (
            mock.patch.object(
                claude_linux,
                "_read_mountinfo",
                side_effect=claude_linux.LinuxRuntimeError(
                    "cannot read WSL2 mountinfo"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceInconclusive,
                "cannot prove",
            ),
        ):
            validator((self.review.container_dir,))

    def test_claude_wsl2_gpg_verifier_fails_before_creating_private_home(
        self,
    ) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        temp_root = self.review.container_dir / "claude-runtime" / "gpg-tmp"
        temp_root.mkdir(parents=True)
        temp_root.chmod(0o700)
        temp_root = temp_root.resolve(strict=True)
        bundle = claude_provenance.SignedClaudeManifest(
            version="2.1.202",
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            manifest=b"{}",
            signature=b"signature",
        )
        cases = (
            (
                "24 1 0:22 / / rw,relatime - 9p drvfs rw,aname=drvfs",
                providers.ClaudeProvenanceInvalid,
                "Linux-native filesystem",
            ),
            (
                "",
                providers.ClaudeProvenanceInconclusive,
                "cannot prove",
            ),
        )

        for mountinfo, error_type, message in cases:
            with (
                self.subTest(message=message),
                mock.patch.object(
                    claude_linux,
                    "_read_mountinfo",
                    return_value=mountinfo,
                ),
                mock.patch.object(
                    claude_provenance,
                    "_run_gpg",
                ) as run_gpg,
                mock.patch.object(
                    claude_provenance.tempfile,
                    "TemporaryDirectory",
                ) as temporary_home,
                self.assertRaisesRegex(error_type, message),
            ):
                claude_provenance.verify_manifest_signature(
                    bundle,
                    temp_root=temp_root,
                    temp_root_validator=(
                        providers._claude_gpg_temp_root_validator(host)
                    ),
                    gpg_candidates=(),
                )

            run_gpg.assert_not_called()
            temporary_home.assert_not_called()

    def test_claude_resolver_uses_linux_manifest_platform(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()
        info = mock.Mock(path=candidate, manifest_platform_key="linux-x64")
        snapshot = self.review.container_dir / "verified-claude"
        self.trusted_release.return_value = providers.VerifiedClaudeExecutable(
            executable=snapshot,
            artifact=claude_provenance.ClaudeReleaseArtifact(
                version="2.1.202",
                platform_key="linux-x64",
                binary="claude",
                checksum="a" * 64,
                size=123,
            ),
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            gpg_path=pathlib.Path("/usr/bin/gpg"),
        )

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                return_value=info,
            ),
            mock.patch.object(
                providers,
                "_require_claude_identity",
                return_value=providers.ClaudeVersion("2.1.202", (2, 1, 202)),
            ),
            mock.patch.object(providers, "_require_claude_safe_mode"),
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
        ):
            executable, _env = providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        self.assertEqual(executable, snapshot)
        self.trusted_release.assert_called_once_with(
            candidate,
            version="2.1.202",
            platform_key="linux-x64",
            gpg_temp_root=(
                self.review.container_dir / "claude-runtime" / "gpg-tmp"
            ),
            gpg_temp_root_validator=mock.ANY,
            cache_dir=(
                self.review.container_dir
                / "claude-runtime"
                / "provenance-cache"
            ),
            snapshot_dir=(
                self.review.container_dir
                / "claude-runtime"
                / "verified-executables"
            ),
        )
        report = json.loads(
            (self.review.container_dir / "claude-runtime.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["source_executable"], str(candidate.absolute()))
        self.assertEqual(report["verified_executable"], str(snapshot))
        self.assertEqual(
            report["gpg_verifier_trust"],
            "fixed-path-native-host-tool",
        )
        self.assertEqual(
            report["phase"],
            "publisher-and-capabilities-verified",
        )

    def test_claude_linux_candidate_mountinfo_failure_is_inconclusive(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(providers, "reject_claude_wsl_windows_path"),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                side_effect=providers.LinuxRuntimeInspectionInconclusive(
                    "mountinfo changed during inspection"
                ),
            ),
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

    def test_claude_linux_candidate_windows_filesystem_is_blocked(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(providers, "reject_claude_wsl_windows_path"),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                side_effect=providers.LinuxRuntimeUnsafe(
                    "Claude executable is on DrvFS"
                ),
            ),
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
            self.assertRaisesRegex(providers.LinuxRuntimeUnsafe, "DrvFS"),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

    def test_claude_review_path_pins_broker_and_trusted_ripgrep(self) -> None:
        trusted_dir = self.review.source_root / "trusted-tools"
        trusted_dir.mkdir()
        trusted_rg = trusted_dir / "rg"
        trusted_rg.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        trusted_rg.chmod(0o700)

        with mock.patch.object(
            providers,
            "CLAUDE_REVIEW_TOOL_EXECUTABLE_CANDIDATES",
            (trusted_rg,),
        ):
            prepared = providers._with_claude_review_tool_path(
                self.review,
                {
                    "PATH": "/untrusted/claude:/usr/bin",
                },
            )

        self.assertEqual(
            prepared["PATH"].split(os.pathsep),
            [str(self.claude_broker.parent.resolve()), str(trusted_dir.absolute())],
        )

    def test_trusted_ripgrep_skips_invalid_native_candidate(self) -> None:
        first_dir = self.review.source_root / "first-tools"
        second_dir = self.review.source_root / "second-tools"
        first_dir.mkdir()
        second_dir.mkdir()
        first = first_dir / "rg"
        second = second_dir / "rg"
        for candidate in (first, second):
            candidate.write_bytes(b"fixture")
            candidate.chmod(0o700)

        def dependencies(path: pathlib.Path, *, label: str) -> tuple[pathlib.Path, ...]:
            self.assertEqual(label, "ripgrep")
            if path == first:
                raise providers.InvalidReviewerExecutable("not native")
            return (path,)

        with (
            mock.patch.object(
                providers,
                "CLAUDE_REVIEW_TOOL_EXECUTABLE_CANDIDATES",
                (first, second),
            ),
            mock.patch.object(
                providers,
                "_native_macho_dependencies",
                side_effect=dependencies,
            ),
        ):
            selected = providers._trusted_claude_ripgrep()

        self.assertEqual(selected, second)

    def test_claude_review_path_classifies_non_native_ripgrep_unavailable(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "_trusted_claude_ripgrep",
                return_value=pathlib.Path("/usr/bin/rg"),
            ),
            mock.patch.object(
                providers,
                "_native_macho_dependencies",
                side_effect=providers.InvalidReviewerExecutable(
                    "ripgrep must be native"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeReviewToolUnavailable,
                "ripgrep must be native",
            ),
        ):
            providers._with_claude_review_tool_path(self.review, {})

    @mock.patch.object(providers, "_trusted_claude_ripgrep", return_value=None)
    def test_claude_sandbox_classifies_missing_ripgrep_unavailable(
        self,
        _rg: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeReviewToolUnavailable,
            "requires ripgrep",
        ):
            providers._claude_review_sandbox_profile(
                pathlib.Path("/bin/true"),
                self.review,
                {
                    "ANTHROPIC_API_KEY": "test-api-key",
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "TMPDIR": str(self.review.container_dir / "tmp"),
                },
                proxy_port=43210,
            )

    def test_claude_linux_arguments_confine_file_tools_to_workspace(self) -> None:
        settings = providers._claude_review_settings(linux=True)
        arguments = providers._claude_review_arguments(
            model="claude-opus-4-8",
            settings=settings,
            linux=True,
        )

        self.assertEqual(
            arguments[arguments.index("--permission-mode") + 1], "dontAsk"
        )
        self.assertEqual(arguments[arguments.index("--tools") + 1], "Read")
        self.assertEqual(
            arguments[arguments.index("--allowedTools") + 1], "Read(./**)"
        )
        cli_denies = set(
            arguments[arguments.index("--disallowedTools") + 1].split(",")
        )
        self.assertTrue(
            set(providers.CLAUDE_LINUX_FILE_TOOL_DENY_RULES).issubset(cli_denies)
        )
        self.assertTrue({"Grep", "Glob"}.issubset(cli_denies))
        settings_denies = set(json.loads(settings)["permissions"]["deny"])
        self.assertTrue(
            set(providers.CLAUDE_LINUX_FILE_TOOL_DENY_RULES).issubset(
                settings_denies
            )
        )
        self.assertIn("Read(//auth/**)", settings_denies)
        self.assertIn("Read(//proc/**)", settings_denies)
        self.assertNotIn("Read(/config/**)", settings_denies)

    def test_claude_macos_arguments_preserve_search_tools_and_default_mode(
        self,
    ) -> None:
        settings = providers._claude_review_settings(linux=False)
        arguments = providers._claude_review_arguments(
            model="claude-opus-4-8",
            settings=settings,
            linux=False,
        )

        self.assertEqual(
            arguments[arguments.index("--permission-mode") + 1], "default"
        )
        self.assertEqual(
            arguments[arguments.index("--tools") + 1], "Read,Grep,Glob"
        )
        self.assertNotIn(
            "Read(//config/**)", json.loads(settings)["permissions"]["deny"]
        )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(
        providers,
        "_claude_connect_proxy",
        return_value=contextlib.nullcontext(43210),
    )
    @mock.patch.object(providers, "run")
    def test_claude_command_pins_model_and_max_with_local_login_safe_mode(
        self,
        run_command: mock.Mock,
        _proxy: mock.Mock,
        _rg: mock.Mock,
        resolve: mock.Mock,
    ) -> None:
        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            candidate = pathlib.Path("/bin/claude")
            kwargs["candidate_validator"](candidate)
            return candidate

        resolve.side_effect = resolve_and_validate
        node_ca_file = self.review.source_root / "node-extra-ca.pem"
        self.write_private_source(node_ca_file, self.sample_ca_certificate())
        self.assertIn("(deny default)", providers.CLAUDE_PROBE_SANDBOX_PROFILE)
        self.assertNotIn("(allow default)", providers.CLAUDE_PROBE_SANDBOX_PROFILE)
        payload = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": "No findings.",
            "modelUsage": {"claude-opus-4-8": {}},
        }
        run_command.side_effect = (
            Completed(
                argv=("claude", "--version"),
                returncode=0,
                stdout=b"2.1.211 (Claude Code)\n",
                stderr=b"",
            ),
            Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=claude_help_fixture(),
                stderr=b"",
            ),
            Completed(
                argv=("claude",),
                returncode=0,
                stdout=json.dumps(payload).encode(),
                stderr=b"",
            ),
        )
        providers._claude_attempt(
            review=self.review,
            model="claude-opus-4-8",
            index=1,
            env={
                "ALL_PROXY": "http://all-user:all-secret@proxy.invalid:8080",
                "HOME": "/Users/reviewer",
                "HTTPS_PROXY": "http://https-user:https-secret@proxy.invalid:8080",
                "HTTP_PROXY": "http://http-user:http-secret@proxy.invalid:8080",
                "NO_PROXY": "credential-bearing-no-proxy.invalid",
                "NODE_EXTRA_CA_CERTS": str(node_ca_file),
                "XDG_CONFIG_HOME": "/Users/reviewer/.config",
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                "CODEX_ISOLATED_REVIEW_RANGE": "base..head",
                "all_proxy": "http://lower-all:secret@proxy.invalid:8080",
                "http_proxy": "http://lower-http:secret@proxy.invalid:8080",
                "https_proxy": "http://lower-https:secret@proxy.invalid:8080",
                "no_proxy": "lower-no-proxy.invalid",
            },
            refresh_lock_protocol=self.claude_refresh_lock_protocol,
        )
        argv = run_command.call_args_list[2].args[0]
        self.assertIn("claude-opus-4-8", argv)
        self.assertEqual(argv[argv.index("--effort") + 1], "max")
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "default")
        self.assertNotIn("--prompt-suggestions", argv)
        self.assertEqual(argv[argv.index("--tools") + 1], "Read,Grep,Glob")
        self.assertEqual(argv[argv.index("--allowedTools") + 1], "Read(./**)")
        self.assertNotIn("Read,Grep,Glob", argv[argv.index("--allowedTools") + 1 :])
        settings = json.loads(argv[argv.index("--settings") + 1])
        self.assertIn("Read(~/.ssh/**)", settings["permissions"]["deny"])
        self.assertTrue(settings["disableAllHooks"])
        self.assertEqual(argv[:2], ("/usr/bin/true", "-p"))
        self.assertEqual(argv[3], "/bin/claude")
        review_profile = argv[2]
        self.assertNotIn(str(node_ca_file), " ".join(argv))
        self.assertIn("(deny default)", review_profile)
        self.assertIn(str(self.review.workspace_root), review_profile)
        self.assertNotIn("com.apple.securityd.xpc", review_profile)
        self.assertIn('(remote ip "localhost:43210")', review_profile)
        self.assertIn('(remote ip "localhost:43211")', review_profile)
        self.assertIn("(allow process-fork)", review_profile)
        self.assertIn(f'(literal "{self.claude_broker.resolve()}")', review_profile)
        self.assertNotIn('(literal "/usr/bin/security")', review_profile)
        self.assertNotIn(f'(subpath "{self.claude_broker.parent}")', review_profile)
        self.assertIn('(literal "/bin/echo")', review_profile)
        self.assertNotIn('(literal "/bin/sh")', review_profile)
        self.assertNotIn("mdsDirectory.db", review_profile)
        self.assertNotIn("mdsObject.db", review_profile)
        self.assertNotIn('(subpath "/private/etc/ssl")', review_profile)
        self.assertIn('(literal "/private/etc/ssl/cert.pem")', review_profile)
        self.assertNotIn("/Users/reviewer", review_profile)
        self.assertIn("--safe-mode", argv)
        self.assertNotIn("--bare", argv)
        self.assertIn("--strict-mcp-config", argv)
        self.assertEqual(
            argv[argv.index("--mcp-config") + 1],
            '{"mcpServers":{}}',
        )
        version_argv = run_command.call_args_list[0].args[0]
        self.assertEqual(version_argv[:2], ("/usr/bin/true", "-p"))
        self.assertEqual(
            version_argv[3:],
            ("/bin/claude", "--safe-mode", "--version"),
        )
        self.assertIn("(deny default)", version_argv[2])
        self.assertIn('(literal "/bin/claude")', version_argv[2])
        self.assertNotIn("(allow default)", version_argv[2])
        probe_env = run_command.call_args_list[0].kwargs["env"]
        self.assertNotIn("ANTHROPIC_API_KEY", probe_env)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", probe_env)
        self.assertNotIn("CODEX_ISOLATED_REVIEW_RANGE", probe_env)
        self.assertEqual(
            probe_env,
            {
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_SAFE_MODE": "1",
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
                "HOME": str(self.review.container_dir / "claude-probe-home"),
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin",
                "TEMP": str(self.review.container_dir / "tmp"),
                "TMP": str(self.review.container_dir / "tmp"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
            },
        )
        self.assertEqual(
            run_command.call_args_list[1].args[0][-3:],
            ("/bin/claude", "--safe-mode", "--help"),
        )
        self.assertEqual(run_command.call_args_list[1].kwargs["env"], probe_env)
        for probe_call in run_command.call_args_list[:2]:
            self.assertEqual(
                probe_call.kwargs["timeout_seconds"],
                providers.CLAUDE_PROBE_TIMEOUT_SECONDS,
            )
            self.assertEqual(
                probe_call.kwargs["capture_limit_bytes"],
                providers.CLAUDE_PROBE_OUTPUT_LIMIT_BYTES,
            )
            self.assertEqual(
                probe_call.kwargs["output_file_limit_bytes"],
                providers.CLAUDE_PROBE_OUTPUT_LIMIT_BYTES,
            )
            self.assertEqual(
                probe_call.kwargs["stdout_path"].parent.parent,
                self.review.container_dir / "claude-probe-home",
            )
            self.assertFalse(probe_call.kwargs["stdout_path"].parent.exists())
        review_env = run_command.call_args_list[2].kwargs["env"]
        self.assertNotIn("ANTHROPIC_API_KEY", review_env)
        prepared_node_ca = pathlib.Path(review_env["NODE_EXTRA_CA_CERTS"])
        prepared_node_metadata = prepared_node_ca.stat()
        self.assertTrue(
            providers.is_relative_to(prepared_node_ca, self.review.container_dir)
        )
        self.assertTrue(stat.S_ISREG(prepared_node_metadata.st_mode))
        self.assertEqual(stat.S_IMODE(prepared_node_metadata.st_mode), 0o600)
        self.assertIn(f'(literal "{prepared_node_ca}")', review_profile)
        self.assertNotIn(f'(subpath "{prepared_node_ca.parent}")', review_profile)
        self.assertNotIn(str(node_ca_file), review_profile)
        self.assertEqual(
            review_env["HOME"],
            str(self.review.container_dir / "claude-home"),
        )
        self.assertEqual(
            review_env["CLAUDE_CODE_TMPDIR"],
            str(self.review.container_dir / "tmp"),
        )
        self.assertNotIn("XDG_CONFIG_HOME", review_env)
        self.assertEqual(
            review_env["PATH"].split(os.pathsep),
            [str(self.claude_broker.parent.resolve()), "/bin"],
        )
        self.assertEqual(review_env["HTTPS_PROXY"], "http://127.0.0.1:43210")
        self.assertEqual(review_env["HTTP_PROXY"], review_env["HTTPS_PROXY"])
        self.assertEqual(review_env["ALL_PROXY"], review_env["HTTPS_PROXY"])
        _proxy.assert_called_once()
        upstream_proxy_env = _proxy.call_args.args[0]
        self.assertEqual(
            upstream_proxy_env["HTTPS_PROXY"],
            "http://https-user:https-secret@proxy.invalid:8080",
        )
        self.assertEqual(
            upstream_proxy_env["https_proxy"],
            "http://lower-https:secret@proxy.invalid:8080",
        )
        self.assertEqual(review_env["NO_PROXY"], "")
        self.assertEqual(
            run_command.call_args_list[2].kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[2].kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        )

    def test_claude_profile_failure_does_not_claim_runtime_launch(self) -> None:
        executable = self.review.container_dir / "verified-claude"
        executable.write_bytes(b"snapshot")
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "outer_sandbox": {"status": "pending-runtime-launch"},
                "gpg_verifier_trust": "fixed-path-native-host-tool",
            },
        )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=False),
            mock.patch.object(
                providers,
                "_resolve_validated_claude_executable",
            ) as resolve_claude,
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_connect_proxy",
                return_value=contextlib.nullcontext(43210),
            ),
            mock.patch.object(
                providers,
                "_claude_review_sandbox_profile",
                side_effect=ReviewError("profile construction failed"),
            ),
            mock.patch.object(providers, "run") as run_command,
            self.assertRaisesRegex(ReviewError, "profile construction failed"),
        ):
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={"ANTHROPIC_API_KEY": "secret"},
                executable=executable,
            )

        report = json.loads(
            (self.review.container_dir / "claude-runtime.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["phase"], "authentication-source-pending")
        self.assertEqual(
            report["outer_sandbox"]["status"],
            "pending-runtime-launch",
        )
        self.assertEqual(
            report["gpg_verifier_trust"],
            "fixed-path-native-host-tool",
        )
        resolve_claude.assert_not_called()
        run_command.assert_not_called()

    def test_claude_post_run_refresh_failure_reports_completed_attempt(self) -> None:
        executable = self.review.container_dir / "verified-claude"
        executable.write_bytes(b"snapshot")
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "outer_sandbox": {"status": "pending-runtime-launch"},
                "authentication": {"status": "pending"},
            },
        )
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=b"{}",
            stderr=b"",
        )

        @contextlib.contextmanager
        def runtime(_review, env, _refresh_lock_protocol):
            yield dict(env)
            raise providers.ClaudeKeychainCredentialUnavailable(
                "refresh persistence failed"
            )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=False),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(providers, "_claude_keychain_runtime", side_effect=runtime),
            mock.patch.object(
                providers,
                "_claude_connect_proxy",
                return_value=contextlib.nullcontext(43210),
            ),
            mock.patch.object(
                providers,
                "_claude_review_sandbox_profile",
                return_value="(version 1)",
            ),
            mock.patch.object(providers, "run", return_value=completed),
            self.assertRaisesRegex(
                providers.ClaudeKeychainCredentialUnavailable,
                "refresh persistence failed",
            ) as raised,
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(report["phase"], "blocked-authentication")
        self.assertEqual(report["outer_sandbox"]["status"], "enforced-at-launch")
        self.assertEqual(
            report["authentication"]["failure_class"],
            "refresh-persistence",
        )
        self.assertEqual(report["attempt"]["category"], "blocked-authentication")
        self.assertEqual(report["attempt"]["returncode"], 0)
        attempt = getattr(
            raised.exception,
            "_codex_claude_persistence_attempt",
        )
        self.assertIsInstance(attempt, providers.Attempt)
        self.assertEqual(attempt.category, "blocked-authentication")
        self.assertEqual(attempt.returncode, 0)

    def test_claude_post_run_auth_rejection_precedes_inspection_failure(
        self,
    ) -> None:
        executable = self.review.container_dir / "verified-claude"
        executable.write_bytes(b"snapshot")
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "publisher-and-capabilities-verified",
                "outer_sandbox": {"status": "pending-runtime-launch"},
                "authentication": {"status": "pending"},
            },
        )
        completed = Completed(
            argv=("claude",),
            returncode=1,
            stdout=b"",
            stderr=b"Login expired; please run /login",
        )

        @contextlib.contextmanager
        def runtime(_review, env, _refresh_lock_protocol):
            yield dict(env)
            raise providers.ClaudeCredentialInspectionInconclusive(
                "final credential snapshot unavailable"
            )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=False),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(providers, "_claude_keychain_runtime", side_effect=runtime),
            mock.patch.object(
                providers,
                "_claude_connect_proxy",
                return_value=contextlib.nullcontext(43210),
            ),
            mock.patch.object(
                providers,
                "_claude_review_sandbox_profile",
                return_value="(version 1)",
            ),
            mock.patch.object(providers, "run", return_value=completed),
            self.assertRaisesRegex(
                providers.ClaudeKeychainCredentialUnavailable,
                "rejected the configured credential",
            ) as raised,
        ):
            providers._claude_attempt(
                review=self.review,
                model=providers.CLAUDE_MODELS[0],
                index=1,
                env={},
                executable=executable,
                refresh_lock_protocol=self.claude_refresh_lock_protocol,
            )

        attempt = getattr(
            raised.exception,
            "_codex_claude_persistence_attempt",
        )
        self.assertIsInstance(attempt, providers.Attempt)
        self.assertEqual(attempt.category, "auth")
        self.assertEqual(attempt.returncode, 1)

    def test_claude_malformed_result_finalizes_runtime_report(self) -> None:
        executable = self.review.container_dir / "verified-claude"
        executable.write_bytes(b"snapshot")
        providers.write_json(
            self.review.container_dir / "claude-runtime.json",
            {
                "phase": "runtime-launching",
                "outer_sandbox": {"status": "profile-generated"},
                "gpg_verifier_trust": "fixed-path-native-host-tool",
            },
        )
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=(
                b'{"type":"result","subtype":"success","is_error":false,'
                b'"result":"No findings."}'
            ),
            stderr=b"",
        )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=False),
            mock.patch.object(
                providers,
                "_with_claude_review_tool_path",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_prepare_claude_tls_environment",
                side_effect=lambda _review, env: dict(env),
            ),
            mock.patch.object(
                providers,
                "_claude_connect_proxy",
                return_value=contextlib.nullcontext(43210),
            ),
            mock.patch.object(
                providers,
                "_claude_review_sandbox_profile",
                return_value="(version 1)",
            ),
            mock.patch.object(providers, "run", return_value=completed),
        ):
            attempt = providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={"ANTHROPIC_API_KEY": "secret"},
                executable=executable,
            )

        self.assertEqual(attempt.category, "other")
        self.assertIsNone(attempt.final_text)
        report = json.loads(
            (self.review.container_dir / "claude-runtime.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["phase"], "attempt-complete")
        self.assertEqual(report["attempt"]["category"], "other")
        self.assertEqual(report["attempt"]["returncode"], 0)
        self.assertIsNone(report["attempt"]["effective_model"])
        self.assertEqual(
            report["gpg_verifier_trust"],
            "fixed-path-native-host-tool",
        )

    def test_claude_review_sandbox_rejects_host_home(self) -> None:
        with self.assertRaisesRegex(ReviewError, "helper-owned HOME and TMPDIR"):
            providers._claude_review_sandbox_profile(
                pathlib.Path("/bin/true"),
                self.review,
                {
                    "HOME": "/Users/reviewer",
                    "TMPDIR": str(self.review.container_dir / "tmp"),
                },
                proxy_port=43210,
            )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=None,
    )
    def test_claude_review_sandbox_requires_trusted_ripgrep(
        self,
        _rg: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "requires ripgrep"):
            providers._claude_review_sandbox_profile(
                pathlib.Path("/bin/true"),
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "TMPDIR": str(self.review.container_dir / "tmp"),
                    "PATH": str(self.claude_broker.parent),
                    providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV: "43211",
                    providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV: "00" * 32,
                },
                proxy_port=43210,
            )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_reads_only_exact_executable(
        self,
        _rg: mock.Mock,
    ) -> None:
        install_dir = self.review.source_root / "private-install"
        install_dir.mkdir()
        executable = install_dir / "claude"
        executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        executable.chmod(0o700)

        profile = providers._claude_review_sandbox_profile(
            executable,
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV: "43211",
                providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV: "00" * 32,
            },
            proxy_port=43210,
        )

        self.assertIn(f'(literal "{executable.resolve()}")', profile)
        self.assertNotIn(f'(subpath "{install_dir.resolve()}")', profile)

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_cannot_read_macos_recovery_carrier(
        self,
        _rg: mock.Mock,
    ) -> None:
        payload = bytearray(oauth_credential_fixture(expires_in_seconds=7200))
        carrier = providers._retain_claude_macos_refreshed_credential(
            self.review,
            payload,
        )
        payload[:] = b"\x00" * len(payload)

        profile = providers._claude_review_sandbox_profile(
            pathlib.Path("/bin/true"),
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV: "43211",
                providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV: "00" * 32,
            },
            proxy_port=43210,
        )

        credential = carrier / "config" / providers.CLAUDE_CREDENTIAL_FILE_NAME
        for private_path in (carrier.parent, carrier, credential.parent, credential):
            self.assertNotIn(f'(literal "{private_path}")', profile)
            self.assertNotIn(f'(subpath "{private_path}")', profile)
        for allowed_subpath in re.findall(r'\(subpath "([^"]+)"\)', profile):
            self.assertFalse(
                providers.is_relative_to(
                    credential.resolve(),
                    pathlib.Path(allowed_subpath).resolve(),
                ),
                f"recovery credential is readable through {allowed_subpath}",
            )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_allows_exact_custom_ca_paths(
        self,
        _rg: mock.Mock,
    ) -> None:
        certificate = self.sample_ca_certificate()
        ca_file = self.review.source_root / "corporate-ca.pem"
        self.write_private_source(ca_file, certificate)
        node_ca_file = self.review.source_root / "node-extra-ca.pem"
        self.write_private_source(node_ca_file, certificate)
        ca_dir = self.review.source_root / "certs"
        ca_dir.mkdir(mode=0o700)
        self.write_private_source(ca_dir / "12345678.0", certificate)

        prepared_env = providers._prepare_claude_tls_environment(
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV: "43211",
                providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV: "00" * 32,
                "NODE_EXTRA_CA_CERTS": str(node_ca_file),
                "SSL_CERT_FILE": str(ca_file),
                "SSL_CERT_DIR": str(ca_dir),
            },
        )

        profile = providers._claude_review_sandbox_profile(
            pathlib.Path("/bin/true"),
            self.review,
            prepared_env,
            proxy_port=43210,
        )

        prepared_file = pathlib.Path(prepared_env["SSL_CERT_FILE"])
        prepared_node_file = pathlib.Path(prepared_env["NODE_EXTRA_CA_CERTS"])
        prepared_dir = pathlib.Path(prepared_env["SSL_CERT_DIR"])
        self.assertTrue(providers.is_relative_to(prepared_file, self.review.container_dir))
        self.assertTrue(
            providers.is_relative_to(prepared_node_file, self.review.container_dir)
        )
        self.assertTrue(providers.is_relative_to(prepared_dir, self.review.container_dir))
        node_metadata = prepared_node_file.stat()
        self.assertTrue(stat.S_ISREG(node_metadata.st_mode))
        self.assertEqual(stat.S_IMODE(node_metadata.st_mode), 0o600)
        self.assertIn(f'(literal "{prepared_file}")', profile)
        self.assertIn(f'(literal "{prepared_node_file}")', profile)
        self.assertIn(f'(subpath "{prepared_dir}")', profile)
        self.assertNotIn(f'(subpath "{prepared_node_file.parent}")', profile)
        self.assertNotIn(str(ca_file), profile)
        self.assertNotIn(str(node_ca_file), profile)
        self.assertNotIn(str(ca_dir), profile)

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_rejects_host_node_extra_ca_file(
        self,
        _rg: mock.Mock,
    ) -> None:
        source = self.review.source_root / "node-extra-ca.pem"
        self.write_private_source(source, self.sample_ca_certificate())

        with self.assertRaisesRegex(
            ReviewError,
            "helper-owned NODE_EXTRA_CA_CERTS",
        ):
            providers._claude_review_sandbox_profile(
                pathlib.Path("/bin/true"),
                self.review,
                {
                    "ANTHROPIC_API_KEY": "test-api-key",
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "TMPDIR": str(self.review.container_dir / "tmp"),
                    "PATH": "/usr/bin",
                    "NODE_EXTRA_CA_CERTS": str(source),
                },
                proxy_port=43210,
            )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_omits_keychain_broker_for_api_key(
        self,
        _rg: mock.Mock,
    ) -> None:
        profile = providers._claude_review_sandbox_profile(
            pathlib.Path("/bin/true"),
            self.review,
            {
                "ANTHROPIC_API_KEY": "test-api-key",
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": "/usr/bin",
            },
            proxy_port=43210,
        )

        self.assertNotIn("/usr/bin/security", profile)
        self.assertNotIn("com.apple.securityd.xpc", profile)

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_rejects_relative_ca_file(
        self,
        _rg: mock.Mock,
    ) -> None:
        for key in ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ReviewError, f"valid absolute {key}"),
            ):
                providers._prepare_claude_tls_environment(
                    self.review,
                    {key: "corporate-ca.pem"},
                )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_rejects_host_ca_directory(
        self,
        _rg: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "helper-owned SSL_CERT_DIR"):
            providers._claude_review_sandbox_profile(
                pathlib.Path("/bin/true"),
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "TMPDIR": str(self.review.container_dir / "tmp"),
                    "SSL_CERT_DIR": "/",
                },
                proxy_port=43210,
            )

    def test_claude_tls_preparation_rejects_non_certificate_file(self) -> None:
        source = self.review.source_root / ".netrc"
        self.write_private_source(
            source,
            b"machine example.test login user password secret\n",
        )

        for key in ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ReviewError, "contains no PEM certificate"),
            ):
                providers._prepare_claude_tls_environment(
                    self.review,
                    {key: str(source)},
                )

    def test_claude_tls_preparation_rejects_private_key_material(self) -> None:
        source = self.review.source_root / "combined.pem"
        self.write_private_source(
            source,
            self.sample_ca_certificate()
            + b"-----BEGIN "
            + b"PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        )

        for key in ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ReviewError, "contains a private key"),
            ):
                providers._prepare_claude_tls_environment(
                    self.review,
                    {key: str(source)},
                )

    def test_claude_tls_source_rejects_symlink_and_fifo(self) -> None:
        certificate = self.sample_ca_certificate()
        target = self.review.source_root / "target-ca.pem"
        self.write_private_source(target, certificate)
        symlink = self.review.source_root / "symlink-ca.pem"
        symlink.symlink_to(target)
        fifo = self.review.source_root / "fifo-ca.pem"
        os.mkfifo(fifo)

        for source in (symlink, fifo):
            with (
                self.subTest(source=source.name),
                self.assertRaisesRegex(ReviewError, "not a regular file"),
            ):
                providers._read_ca_source(source, source="SSL_CERT_FILE")

    def test_claude_tls_source_requires_safe_file_mode(self) -> None:
        source = self.review.source_root / "writable-ca.pem"
        source.write_bytes(self.sample_ca_certificate())
        source.chmod(0o666)

        with self.assertRaisesRegex(ReviewError, "group- or world-writable"):
            providers._read_ca_source(source, source="SSL_CERT_FILE")

    def test_claude_tls_source_uses_only_bounded_descriptor_reads(self) -> None:
        source = self.review.source_root / "corporate-ca.pem"
        certificate = self.sample_ca_certificate()
        self.write_private_source(source, certificate)
        original_read = os.read
        requested_sizes: list[int] = []

        def record_read(descriptor: int, size: int) -> bytes:
            requested_sizes.append(size)
            return original_read(descriptor, size)

        with (
            mock.patch.object(providers.os, "read", side_effect=record_read),
            mock.patch.object(
                pathlib.Path,
                "read_bytes",
                side_effect=AssertionError("path read must not be used"),
            ),
        ):
            material = providers._read_ca_source(source, source="SSL_CERT_FILE")

        self.assertEqual(material, certificate)
        self.assertTrue(requested_sizes)
        self.assertLessEqual(
            max(requested_sizes),
            providers.CLAUDE_CA_FILE_LIMIT_BYTES + 1,
        )

    def test_claude_tls_source_rejects_path_replacement_as_inconclusive(
        self,
    ) -> None:
        certificate = self.sample_ca_certificate()
        source = self.review.source_root / "corporate-ca.pem"
        self.write_private_source(source, certificate)
        replacement = self.review.source_root / "replacement-ca.pem"
        self.write_private_source(replacement, certificate)
        original_read = os.read
        replaced = False

        def replace_before_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            if not replaced:
                replaced = True
                os.replace(replacement, source)
            return original_read(descriptor, size)

        with (
            mock.patch.object(providers.os, "read", side_effect=replace_before_read),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "changed while being read",
            ),
        ):
            providers._read_ca_source(source, source="SSL_CERT_FILE")

    def test_claude_tls_source_rejects_in_place_mutation_as_inconclusive(
        self,
    ) -> None:
        certificate = self.sample_ca_certificate()
        source = self.review.source_root / "corporate-ca.pem"
        self.write_private_source(source, certificate)
        initial = source.stat()
        original_read = os.read
        mutated = False

        def mutate_before_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            if not mutated:
                mutated = True
                with source.open("r+b") as handle:
                    handle.seek(0)
                    handle.write(b"X")
                    handle.flush()
                    os.fsync(handle.fileno())
                # Some Linux filesystems can retain the same timestamp for two
                # writes in one clock tick. Force a distinct metadata identity
                # so this test deterministically exercises the race detector.
                os.utime(
                    source,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                )
            return original_read(descriptor, size)

        with (
            mock.patch.object(providers.os, "read", side_effect=mutate_before_read),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "changed while being read",
            ),
        ):
            providers._read_ca_source(source, source="SSL_CERT_FILE")

    def test_claude_tls_preparation_preserves_same_named_ca_entries(self) -> None:
        certificate = self.sample_ca_certificate()
        source_dirs = []
        for name in ("first", "second"):
            source_dir = self.review.source_root / name
            source_dir.mkdir(mode=0o700)
            self.write_private_source(source_dir / "deadbeef.0", certificate)
            source_dirs.append(source_dir)

        prepared = providers._prepare_claude_tls_environment(
            self.review,
            {"SSL_CERT_DIR": os.pathsep.join(str(path) for path in source_dirs)},
        )

        prepared_dirs = [
            pathlib.Path(raw) for raw in prepared["SSL_CERT_DIR"].split(os.pathsep)
        ]
        self.assertEqual(len(prepared_dirs), 2)
        self.assertNotEqual(prepared_dirs[0], prepared_dirs[1])
        for prepared_dir in prepared_dirs:
            self.assertEqual((prepared_dir / "deadbeef.0").read_bytes(), certificate)

    def test_claude_tls_preparation_materializes_hash_symlink_name(self) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "hashed-ca-dir"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        self.write_private_source(target, certificate)
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to(target.name)

        prepared = providers._prepare_claude_tls_environment(
            self.review,
            {"SSL_CERT_DIR": str(source_dir)},
        )

        prepared_dir = pathlib.Path(prepared["SSL_CERT_DIR"])
        materialized_hash = prepared_dir / hash_entry.name
        self.assertFalse(materialized_hash.is_symlink())
        self.assertTrue(stat.S_ISREG(materialized_hash.lstat().st_mode))
        self.assertEqual(stat.S_IMODE(materialized_hash.stat().st_mode), 0o600)
        self.assertEqual(materialized_hash.read_bytes(), certificate)

    def test_claude_tls_preparation_accepts_symlinked_ca_directory(self) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "real-ca-dir"
        source_dir.mkdir(mode=0o700)
        self.write_private_source(source_dir / "certificate.pem", certificate)
        directory_link = self.review.source_root / "configured-ca-dir"
        directory_link.symlink_to(source_dir.name)

        prepared = providers._prepare_claude_tls_environment(
            self.review,
            {"SSL_CERT_DIR": str(directory_link)},
        )

        prepared_dir = pathlib.Path(prepared["SSL_CERT_DIR"])
        self.assertEqual(
            (prepared_dir / "certificate.pem").read_bytes(),
            certificate,
        )

    def test_claude_tls_preparation_accepts_linux_system_hashed_directory(
        self,
    ) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux system CA directory test")
        source_dir = pathlib.Path("/etc/ssl/certs")
        if not source_dir.is_dir():
            self.skipTest("Linux system CA directory is unavailable")

        try:
            prepared = providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_DIR": str(source_dir)},
            )
        except ReviewError as error:
            if not self.host_ca_safety_rejection(error, source="SSL_CERT_DIR:"):
                raise
            self.skipTest(f"host system CA directory is not immutable: {error}")

        prepared_dir = pathlib.Path(prepared["SSL_CERT_DIR"])
        hash_entries = list(prepared_dir.glob("????????.[0-9]*"))
        self.assertTrue(hash_entries)
        self.assertTrue(all(not path.is_symlink() for path in hash_entries))

    def test_claude_tls_directory_symlink_supports_ubuntu_two_hop_chain(
        self,
    ) -> None:
        system_ca, expected = self.stable_system_ca_file()
        source_dir = self.review.source_root / "ubuntu-ca-dir"
        source_dir.mkdir(mode=0o700)
        hash_entry = source_dir / "002c0b4f.0"
        named_entry = source_dir / "GlobalSign_Root_R46.pem"
        hash_entry.symlink_to(named_entry.name)
        named_entry.symlink_to(system_ca)

        material, _source_size = providers._read_ca_path_from_parent_with_size(
            hash_entry,
            source=f"SSL_CERT_DIR:{hash_entry.name}",
        )

        self.assertEqual(material, expected)

    def test_claude_tls_directory_symlink_supports_safe_parent_traversal(
        self,
    ) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "etc" / "ssl" / "certs"
        source_dir.mkdir(mode=0o700, parents=True)
        target_dir = self.review.source_root / "usr" / "share" / "ca-certificates"
        target_dir.mkdir(mode=0o700, parents=True)
        for directory in (
            self.review.source_root / "etc",
            self.review.source_root / "etc" / "ssl",
            source_dir,
            self.review.source_root / "usr",
            self.review.source_root / "usr" / "share",
            target_dir,
        ):
            directory.chmod(0o700)
        target = target_dir / "certificate.crt"
        self.write_private_source(target, certificate)
        hash_entry = source_dir / "deadbeef.0"
        named_entry = source_dir / "certificate.pem"
        hash_entry.symlink_to(named_entry.name)
        named_entry.symlink_to("../../../usr/share/ca-certificates/certificate.crt")

        material, _source_size = providers._read_ca_path_from_parent_with_size(
            hash_entry,
            source=f"SSL_CERT_DIR:{hash_entry.name}",
        )

        self.assertEqual(material, certificate)

    def test_claude_tls_directory_symlink_rejects_unsafe_parent(self) -> None:
        source_dir = self.review.source_root / "unsafe-parent-source"
        source_dir.mkdir(mode=0o700)
        unsafe_parent = self.review.source_root / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o700)
        unsafe_parent.chmod(0o777)
        target = unsafe_parent / "certificate.pem"
        self.write_private_source(target, self.sample_ca_certificate())
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to("../unsafe-parent/certificate.pem")

        with self.assertRaisesRegex(ReviewError, "group- or world-writable"):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_directory_symlink_rejects_link_chain_and_loop(
        self,
    ) -> None:
        source_dir = self.review.source_root / "loop-ca-dir"
        source_dir.mkdir(mode=0o700)
        self_link = source_dir / "cafebabe.0"
        self_link.symlink_to(self_link.name)
        with self.assertRaisesRegex(ReviewError, "contains a loop"):
            providers._read_ca_path_from_parent_with_size(
                self_link,
                source=f"SSL_CERT_DIR:{self_link.name}",
            )

        hash_entry = source_dir / "deadbeef.0"
        intermediate = source_dir / "certificate.pem"
        hash_entry.symlink_to(intermediate.name)
        intermediate.symlink_to(hash_entry.name)

        with self.assertRaisesRegex(ReviewError, "contains a loop"):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_directory_symlink_enforces_depth_limit(self) -> None:
        source_dir = self.review.source_root / "deep-link-ca-dir"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        self.write_private_source(target, self.sample_ca_certificate())
        links = [
            source_dir / f"link-{index:02d}"
            for index in range(providers.CLAUDE_CA_SYMLINK_LIMIT)
        ]
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to(links[0].name)
        for current, following in zip(links, links[1:]):
            current.symlink_to(following.name)
        links[-1].symlink_to(target.name)

        with self.assertRaisesRegex(ReviewError, "exceeds the depth limit"):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_directory_open_wraps_post_open_disappearance(
        self,
    ) -> None:
        source_dir = self.review.source_root / "directory-race-ca-dir"
        source_dir.mkdir(mode=0o700)
        original_lstat = pathlib.Path.lstat
        inspected = 0

        def disappear_after_open(path: pathlib.Path) -> os.stat_result:
            nonlocal inspected
            if path == source_dir:
                inspected += 1
                if inspected == 2:
                    raise FileNotFoundError(path)
            return original_lstat(path)

        with (
            mock.patch.object(pathlib.Path, "lstat", new=disappear_after_open),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "cannot validate a stable Claude review CA directory",
            ),
        ):
            providers._open_stable_ca_directory(
                source_dir,
                source="SSL_CERT_DIR",
            )

    def test_claude_tls_directory_symlink_preserves_target_mode_checks(
        self,
    ) -> None:
        source_dir = self.review.source_root / "unsafe-target-ca-dir"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        target.write_bytes(self.sample_ca_certificate())
        target.chmod(0o666)
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to(target.name)

        with self.assertRaisesRegex(ReviewError, "group- or world-writable"):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_directory_symlink_rejects_link_replacement(
        self,
    ) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "link-race-ca-dir"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        replacement_target = source_dir / "replacement.pem"
        self.write_private_source(target, certificate)
        self.write_private_source(replacement_target, certificate)
        hash_entry = source_dir / "deadbeef.0"
        intermediate = source_dir / "named-certificate.pem"
        hash_entry.symlink_to(intermediate.name)
        intermediate.symlink_to(target.name)
        original_read = os.read
        replaced = False

        def replace_link_before_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            if not replaced:
                replaced = True
                intermediate.unlink()
                intermediate.symlink_to(replacement_target.name)
            return original_read(descriptor, size)

        with (
            mock.patch.object(providers.os, "read", side_effect=replace_link_before_read),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "symlink changed while being read",
            ),
        ):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_directory_symlink_rejects_target_replacement(
        self,
    ) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "target-race-ca-dir"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        replacement = source_dir / "replacement.pem"
        self.write_private_source(target, certificate)
        self.write_private_source(replacement, certificate)
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to(target.name)
        original_read = os.read
        replaced = False

        def replace_target_before_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            if not replaced:
                replaced = True
                os.replace(replacement, target)
            return original_read(descriptor, size)

        with (
            mock.patch.object(
                providers.os,
                "read",
                side_effect=replace_target_before_read,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "source changed while being read",
            ),
        ):
            providers._read_ca_path_from_parent_with_size(
                hash_entry,
                source=f"SSL_CERT_DIR:{hash_entry.name}",
            )

    def test_claude_tls_preparation_bounds_directory_enumeration_before_sort(
        self,
    ) -> None:
        source_dir = self.review.source_root / "large-ca-dir"
        source_dir.mkdir(mode=0o700)
        source_dir.chmod(0o700)
        consumed = 0

        def entries():
            nonlocal consumed
            for index in range(providers.CLAUDE_CA_DIR_ENTRY_LIMIT + 10):
                consumed += 1
                yield source_dir / f"entry-{index:05d}"

        with (
            mock.patch.object(
                providers.os,
                "scandir",
                return_value=contextlib.nullcontext(entries()),
            ),
            self.assertRaisesRegex(ReviewError, "too many entries"),
        ):
            providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_DIR": str(source_dir)},
            )

        self.assertEqual(consumed, providers.CLAUDE_CA_DIR_ENTRY_LIMIT + 1)

    def test_claude_tls_preparation_counts_non_certificate_directory_input(
        self,
    ) -> None:
        source_dir = self.review.source_root / "non-certificate-ca-dir"
        source_dir.mkdir(mode=0o700)
        for name in ("first", "second"):
            self.write_private_source(source_dir / name, b"x")

        with (
            mock.patch.object(providers, "CLAUDE_CA_DIR_LIMIT_BYTES", 1),
            mock.patch.object(
                providers,
                "_read_ca_directory_entry_at_with_size",
                return_value=(b"x", 1),
            ) as read_entry,
            self.assertRaisesRegex(ReviewError, "directory exceeds the size limit"),
        ):
            providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_DIR": str(source_dir)},
            )

        self.assertEqual(read_entry.call_count, 2)

    def test_claude_absolute_ca_reader_preserves_relative_symlink_base(
        self,
    ) -> None:
        candidates: list[pathlib.Path] = []
        system_dir = pathlib.Path("/etc/ssl/certs")
        if system_dir.is_dir():
            candidates.extend(itertools.islice(system_dir.iterdir(), 256))
        defaults = ssl.get_default_verify_paths()
        if defaults.cafile:
            candidates.append(pathlib.Path(defaults.cafile))
        for candidate in candidates:
            try:
                if not candidate.is_symlink():
                    continue
                raw_target = os.readlink(candidate)
                if pathlib.Path(raw_target).is_absolute():
                    continue
                expected = providers._read_ca_source(
                    candidate.resolve(strict=True),
                    source="test resolved CA",
                )
                material, _source_size = providers._read_absolute_ca_path_with_size(
                    candidate,
                    source="test absolute CA",
                )
            except (OSError, ReviewError):
                continue
            self.assertEqual(material, expected)
            return
        self.skipTest("no safe system CA with a relative symlink is available")

    def test_claude_linux_ca_bundle_bounds_streamed_input(self) -> None:
        certificate = self.sample_ca_certificate()
        oversized_half = providers.CLAUDE_CA_DIR_LIMIT_BYTES // 2 + 1
        env = {
            "CURL_CA_BUNDLE": "/first.pem",
            "SSL_CERT_FILE": "/second.pem",
        }

        with (
            mock.patch.object(
                providers,
                "_read_ca_path_from_parent_with_size",
                return_value=(certificate, oversized_half),
            ) as read_source,
            self.assertRaisesRegex(ReviewError, "input exceeds the size limit"),
        ):
            providers._claude_linux_ca_bundle(self.review, env)

        self.assertEqual(read_source.call_count, 2)

    def test_claude_linux_ca_bundle_shares_entry_limit_across_directories(
        self,
    ) -> None:
        source_dirs: list[pathlib.Path] = []
        for name in ("first-linux-ca", "second-linux-ca"):
            source_dir = self.review.source_root / name
            source_dir.mkdir(mode=0o700)
            self.write_private_source(
                source_dir / "ignored.txt",
                b"not a certificate\n",
            )
            source_dirs.append(source_dir)

        with (
            mock.patch.object(providers, "CLAUDE_CA_DIR_ENTRY_LIMIT", 1),
            self.assertRaisesRegex(ReviewError, "directories have too many entries"),
        ):
            providers._claude_linux_ca_bundle(
                self.review,
                {
                    "SSL_CERT_DIR": os.pathsep.join(
                        str(path) for path in source_dirs
                    )
                },
            )

    def test_claude_linux_node_extra_ca_retains_default_trust(self) -> None:
        default_certificate, node_certificate = self.sample_ca_certificates(2)
        default_file = self.review.source_root / "default-ca.pem"
        node_file = self.review.source_root / "node-extra-ca.pem"
        self.write_private_source(default_file, default_certificate)
        self.write_private_source(node_file, node_certificate)
        destination_dir = self.review.container_dir / "node-default-ca-bundle"
        destination_dir.mkdir(mode=0o700)

        def read_default(
            path: pathlib.Path,
            *,
            source: str,
            extract_certificates: bool = True,
        ) -> tuple[bytes, int]:
            del source, extract_certificates
            if path == default_file:
                return default_certificate, len(default_certificate)
            try:
                raise FileNotFoundError(path)
            except FileNotFoundError as error:
                raise providers.ClaudeExecutableInspectionInconclusive(
                    f"missing default CA file: {path}"
                ) from error

        with (
            mock.patch.object(
                providers.ssl,
                "get_default_verify_paths",
                return_value=mock.Mock(cafile=str(default_file), capath=None),
            ),
            mock.patch.object(
                providers,
                "_read_absolute_ca_path_with_size",
                side_effect=read_default,
            ),
            mock.patch.object(
                providers,
                "_claude_linux_private_directory",
                return_value=destination_dir,
            ),
        ):
            bundle = providers._claude_linux_ca_bundle(
                self.review,
                {"NODE_EXTRA_CA_CERTS": str(node_file)},
            )

        self.assertEqual(bundle.read_bytes(), default_certificate + node_certificate)

    def test_claude_linux_node_extra_ca_appends_to_replacement_and_deduplicates(
        self,
    ) -> None:
        replacement_certificate, node_certificate = self.sample_ca_certificates(2)
        replacement_file = self.review.source_root / "replacement-ca.pem"
        node_file = self.review.source_root / "node-extra-ca.pem"
        self.write_private_source(replacement_file, replacement_certificate)
        self.write_private_source(
            node_file,
            replacement_certificate + node_certificate,
        )
        destination_dir = self.review.container_dir / "replacement-node-ca-bundle"
        destination_dir.mkdir(mode=0o700)

        with (
            mock.patch.object(providers.ssl, "get_default_verify_paths") as defaults,
            mock.patch.object(
                providers,
                "_claude_linux_private_directory",
                return_value=destination_dir,
            ),
        ):
            bundle = providers._claude_linux_ca_bundle(
                self.review,
                {
                    "SSL_CERT_FILE": str(replacement_file),
                    "NODE_EXTRA_CA_CERTS": str(node_file),
                },
            )

        defaults.assert_not_called()
        self.assertEqual(
            bundle.read_bytes(),
            replacement_certificate + node_certificate,
        )

    def test_claude_linux_ca_bundle_uses_capath_without_cafile(self) -> None:
        certificate = self.sample_ca_certificate()
        source_dir = self.review.source_root / "default-capath"
        source_dir.mkdir(mode=0o700)
        target = source_dir / "certificate.pem"
        self.write_private_source(target, certificate)
        hash_entry = source_dir / "deadbeef.0"
        hash_entry.symlink_to(target.name)
        destination_dir = self.review.container_dir / "capath-bundle"
        destination_dir.mkdir(mode=0o700)

        def missing_default_file(*_args: object, **_kwargs: object) -> None:
            try:
                raise FileNotFoundError("missing default CA file")
            except FileNotFoundError as error:
                raise providers.ClaudeExecutableInspectionInconclusive(
                    "missing default CA file"
                ) from error

        with (
            mock.patch.object(
                providers.ssl,
                "get_default_verify_paths",
                return_value=mock.Mock(cafile=None, capath=str(source_dir)),
            ),
            mock.patch.object(
                providers,
                "_read_absolute_ca_path_with_size",
                side_effect=missing_default_file,
            ),
            mock.patch.object(
                providers,
                "_read_ca_directory_entry_at_with_size",
                wraps=providers._read_ca_directory_entry_at_with_size,
            ) as read_entry,
            mock.patch.object(
                providers,
                "_claude_linux_private_directory",
                return_value=destination_dir,
            ),
        ):
            bundle = providers._claude_linux_ca_bundle(self.review, {})

        self.assertEqual(bundle.read_bytes(), certificate)
        self.assertEqual(
            {call.args[1] for call in read_entry.call_args_list},
            {target.name, hash_entry.name},
        )

    def test_claude_linux_ca_bundle_reads_default_symlink_stably(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux default CA bundle test")
        destination_dir = self.review.container_dir / "linux-ca-bundle"
        destination_dir.mkdir(mode=0o700)

        try:
            with mock.patch.object(
                providers,
                "_claude_linux_private_directory",
                return_value=destination_dir,
            ):
                bundle = providers._claude_linux_ca_bundle(self.review, {})
        except ReviewError as error:
            if not self.host_ca_safety_rejection(
                error,
                source="Linux default CA directory:",
            ):
                raise
            self.skipTest(f"host system CA directory is not immutable: {error}")

        self.assertEqual(bundle, destination_dir / "bundle.pem")
        self.assertTrue(providers.CLAUDE_CERTIFICATE_BLOCK.search(bundle.read_bytes()))

    @mock.patch.object(providers.ssl, "create_default_context")
    def test_proxy_ssl_context_honors_git_ca_bundle(
        self,
        create_context: mock.Mock,
    ) -> None:
        context = create_context.return_value

        result = providers._proxy_ssl_context(
            {"GIT_SSL_CAINFO": "/isolated/git-ca.pem"}
        )

        self.assertIs(result, context)
        create_context.assert_called_once_with(cafile="/isolated/git-ca.pem")

    @mock.patch.object(providers.ssl, "create_default_context")
    def test_proxy_ssl_context_ignores_node_extra_ca_certs(
        self,
        create_context: mock.Mock,
    ) -> None:
        context = create_context.return_value

        result = providers._proxy_ssl_context(
            {"NODE_EXTRA_CA_CERTS": "/isolated/node-extra-ca.pem"}
        )

        self.assertIs(result, context)
        create_context.assert_called_once_with(cafile=None)

    @mock.patch.object(providers.ssl, "create_default_context")
    def test_proxy_ssl_context_loads_each_ca_directory(
        self,
        create_context: mock.Mock,
    ) -> None:
        context = create_context.return_value

        result = providers._proxy_ssl_context(
            {"SSL_CERT_DIR": os.pathsep.join(("/first", "/second"))}
        )

        self.assertIs(result, context)
        create_context.assert_called_once_with(cafile=None)
        self.assertEqual(
            context.load_verify_locations.call_args_list,
            [mock.call(capath="/first"), mock.call(capath="/second")],
        )

    def test_claude_connect_proxy_allows_only_configured_target(self) -> None:
        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request.recv(1024)
                self.request.sendall(data)

        try:
            target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        except PermissionError:
            self.skipTest("loopback bind is unavailable in the current sandbox")
        target.daemon_threads = True
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        target_port = int(target.server_address[1])
        try:
            with providers._claude_connect_proxy(
                {},
                allowed_targets=frozenset({("127.0.0.1", target_port)}),
            ) as proxy_port:
                with socket.create_connection(("127.0.0.1", proxy_port)) as client:
                    client.sendall(
                        (
                            f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                        ).encode("ascii")
                    )
                    response = client.recv(4096)
                    self.assertIn(b"200 Connection Established", response)
                    client.sendall(b"ping")
                    self.assertEqual(client.recv(4), b"ping")

                with socket.create_connection(("127.0.0.1", proxy_port)) as client:
                    client.sendall(
                        b"CONNECT example.com:443 HTTP/1.1\r\n"
                        b"Host: example.com:443\r\n\r\n"
                    )
                    self.assertIn(b"403 Forbidden", client.recv(4096))
        finally:
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=5.0)

    def test_claude_unix_connect_proxy_is_private_and_enforces_targets(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("Unix sockets are unavailable")
        try:
            context = providers._claude_unix_connect_proxy(
                self.review,
                {},
                allowed_targets=frozenset({("api.anthropic.com", 443)}),
            )
            with context as socket_path:
                self.assertEqual(stat.S_IMODE(socket_path.stat().st_mode), 0o600)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(socket_path))
                    client.sendall(
                        b"CONNECT example.com:443 HTTP/1.1\r\n"
                        b"Host: example.com:443\r\n\r\n"
                    )
                    self.assertIn(b"403 Forbidden", client.recv(4096))
        except providers.ClaudeLoopbackUnavailable as error:
            if "Operation not permitted" in str(error):
                self.skipTest("Unix socket bind is blocked by the current sandbox")
            raise
        self.assertFalse(socket_path.exists())

    def test_claude_unix_proxy_bind_uncertainty_is_inconclusive(self) -> None:
        for bind_error in (
            OSError("unknown bind failure"),
            OSError(errno.EMFILE, "descriptor capacity exhausted"),
            OSError(errno.EADDRINUSE, "address temporarily occupied"),
        ):
            with (
                self.subTest(errno=bind_error.errno),
                mock.patch.object(
                    providers,
                    "_ClaudeUnixProxyServer",
                    side_effect=bind_error,
                ),
                self.assertRaisesRegex(
                    providers.ClaudeCredentialInspectionInconclusive,
                    "private Unix socket",
                ),
            ):
                with providers._claude_unix_connect_proxy(self.review, {}):
                    self.fail("failed proxy unexpectedly started")

    @mock.patch.object(
        providers,
        "_ClaudeUnixProxyServer",
        side_effect=PermissionError(errno.EACCES, "bind denied by policy"),
    )
    def test_claude_unix_proxy_policy_bind_denial_is_runtime_unavailable(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "bind denied by policy",
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("unavailable proxy unexpectedly started")

    def test_claude_unix_proxy_chmod_failure_is_inconclusive(self) -> None:
        server = mock.Mock()
        real_chmod = pathlib.Path.chmod

        def fail_socket_chmod(path: pathlib.Path, mode: int) -> None:
            if path.name == "p.sock":
                raise OSError(errno.EIO, "injected chmod failure")
            real_chmod(path, mode)

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                return_value=server,
            ),
            mock.patch.object(pathlib.Path, "chmod", new=fail_socket_chmod),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "make its Unix socket private",
            ),
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("failed proxy unexpectedly started")

        server.server_close.assert_called_once_with()

    def test_claude_unix_proxy_directory_chmod_failure_is_inconclusive(
        self,
    ) -> None:
        real_chmod = pathlib.Path.chmod

        def fail_directory_chmod(path: pathlib.Path, mode: int) -> None:
            if path.name.startswith("codex-claude-proxy-"):
                raise OSError(errno.EIO, "injected directory chmod failure")
            real_chmod(path, mode)

        with (
            mock.patch.object(pathlib.Path, "chmod", new=fail_directory_chmod),
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
            ) as server_constructor,
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "private Unix proxy directory",
            ),
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("failed proxy unexpectedly started")

        server_constructor.assert_not_called()

    def test_claude_unix_proxy_thread_failure_closes_server(self) -> None:
        server = mock.Mock()
        thread = mock.Mock()
        thread.start.side_effect = RuntimeError("thread unavailable")

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "Unix CONNECT proxy cannot start",
            ),
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("failed proxy unexpectedly started")

        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_not_called()

    def test_claude_unix_proxy_start_signal_is_preserved_and_cleaned(
        self,
    ) -> None:
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        server = mock.Mock()
        server.is_serving.return_value = False
        server.serve_error.return_value = None
        thread = mock.Mock()
        thread.ident = 123
        thread.is_alive.return_value = False
        thread.start.side_effect = forwarded

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("interrupted proxy unexpectedly started")

        self.assertIs(raised.exception, forwarded)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_unix_proxy_thread_construction_failure_closes_server(
        self,
    ) -> None:
        server = mock.Mock()

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(
                providers.threading,
                "Thread",
                side_effect=RuntimeError("thread construction failed"),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot construct",
            ),
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("failed proxy unexpectedly started")

        server.server_close.assert_called_once_with()

    def test_claude_unix_proxy_serve_start_failure_is_inconclusive(self) -> None:
        serve_error = RuntimeError("serve startup failed")
        server = mock.Mock()
        server.wait_until_serving.return_value = False
        server.serve_error.return_value = serve_error
        server.is_serving.return_value = False
        thread = mock.Mock()
        thread.is_alive.return_value = False

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "did not enter its serve loop",
            ) as raised,
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                self.fail("failed proxy unexpectedly started")

        self.assertIs(raised.exception.__cause__, serve_error)
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_unix_proxy_post_start_serve_failure_is_inconclusive(
        self,
    ) -> None:
        serve_error = RuntimeError("injected post-start serve failure")
        server = mock.Mock()
        server.wait_until_serving.return_value = True
        server.is_serving.return_value = False
        server.serve_error.return_value = serve_error
        thread = mock.Mock()
        thread.is_alive.return_value = False

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "serve loop failed after startup",
            ) as raised,
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                pass

        self.assertIs(raised.exception.__cause__, serve_error)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_unix_proxy_cleanup_preserves_control_flow_and_continues(
        self,
    ) -> None:
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        server = mock.Mock()
        server.wait_until_serving.return_value = True
        server.is_serving.return_value = True
        server.serve_error.return_value = None
        server.shutdown.side_effect = OSError("injected shutdown failure")
        thread = mock.Mock()
        thread.is_alive.return_value = False

        def create_server(
            socket_path: pathlib.Path,
            **_kwargs: object,
        ) -> mock.Mock:
            socket_path.touch(mode=0o600)
            return server

        with (
            mock.patch.object(
                providers,
                "_ClaudeUnixProxyServer",
                side_effect=create_server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with providers._claude_unix_connect_proxy(self.review, {}):
                raise forwarded

        self.assertIs(raised.exception, forwarded)
        server.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_https_proxy_tunnel_drains_decrypted_pending_data(self) -> None:
        class PlainSocket:
            def __init__(self) -> None:
                self.sent: list[bytes] = []

            def settimeout(self, _value) -> None:
                return

            def sendall(self, data: bytes) -> None:
                self.sent.append(data)

        class FakeTLSSocket:
            def __init__(self) -> None:
                self.pending_values = iter((1, 1, 0))
                self.received = iter((b"a" * (64 * 1024), b"b" * (64 * 1024), b""))

            def settimeout(self, _value) -> None:
                return

            def pending(self) -> int:
                return next(self.pending_values)

            def recv(self, _size: int) -> bytes:
                return next(self.received)

        client = PlainSocket()
        upstream = FakeTLSSocket()
        with (
            mock.patch.object(providers.ssl, "SSLSocket", FakeTLSSocket),
            mock.patch.object(
                providers.select,
                "select",
                return_value=([upstream], (), ()),
            ) as select_call,
        ):
            providers._tunnel_proxy_sockets(client, upstream)

        self.assertEqual(client.sent, [b"a" * (64 * 1024), b"b" * (64 * 1024)])
        select_call.assert_called_once()

    def test_claude_proxy_environment_blocks_bypass_variables(self) -> None:
        env = providers._with_claude_proxy_environment(
            {
                "HTTPS_PROXY": "http://corporate-proxy:8080",
                "NO_PROXY": "example.com",
            },
            43210,
        )

        for key in (
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "http_proxy",
            "https_proxy",
        ):
            self.assertEqual(env[key], "http://127.0.0.1:43210")
        self.assertEqual(env["NO_PROXY"], "")
        self.assertEqual(env["no_proxy"], "")

    def test_claude_upstream_proxy_accepts_lowercase_environment(self) -> None:
        self.assertEqual(
            providers._upstream_proxy_url(
                {"https_proxy": "http://corporate-proxy:8080"},
                host="api.anthropic.com",
                port=443,
            ),
            "http://corporate-proxy:8080",
        )

    def test_claude_upstream_proxy_prefers_lowercase_override(self) -> None:
        self.assertEqual(
            providers._upstream_proxy_url(
                {
                    "HTTPS_PROXY": "http://system-proxy:8080",
                    "https_proxy": "http://task-proxy:8080",
                },
                host="api.anthropic.com",
                port=443,
            ),
            "http://task-proxy:8080",
        )

    def test_empty_lowercase_proxy_disables_uppercase_pair(self) -> None:
        for lowercase, uppercase in (
            ("https_proxy", "HTTPS_PROXY"),
            ("http_proxy", "HTTP_PROXY"),
            ("all_proxy", "ALL_PROXY"),
        ):
            with self.subTest(lowercase=lowercase):
                self.assertIsNone(
                    providers._upstream_proxy_url(
                        {
                            lowercase: "",
                            uppercase: "http://system-proxy:8080",
                        },
                        host="api.anthropic.com",
                        port=443,
                    )
                )

    def test_claude_proxy_rejects_invalid_upstream_ports_before_bind(self) -> None:
        for value in (
            "http://corporate-proxy:0",
            "http://corporate-proxy:99999",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                ReviewError,
                "upstream proxy .* invalid",
            ):
                with providers._claude_connect_proxy({"https_proxy": value}):
                    self.fail("invalid upstream proxy unexpectedly started")

    @mock.patch.object(
        providers,
        "_ClaudeProxyServer",
        side_effect=OSError("bind failed"),
    )
    def test_claude_proxy_bind_failure_is_inconclusive(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "CONNECT proxy cannot bind loopback",
        ):
            with providers._claude_connect_proxy({}):
                self.fail("failed proxy unexpectedly started")

    def test_claude_proxy_resource_bind_failures_are_inconclusive(self) -> None:
        for bind_error in (
            OSError(errno.EMFILE, "descriptor capacity exhausted"),
            OSError(errno.EADDRINUSE, "address temporarily occupied"),
        ):
            with (
                self.subTest(errno=bind_error.errno),
                mock.patch.object(
                    providers,
                    "_ClaudeProxyServer",
                    side_effect=bind_error,
                ),
                self.assertRaises(
                    providers.ClaudeCredentialInspectionInconclusive
                ),
            ):
                with providers._claude_connect_proxy({}):
                    self.fail("failed proxy unexpectedly started")

    @mock.patch.object(
        providers,
        "_ClaudeProxyServer",
        side_effect=PermissionError(errno.EACCES, "bind denied by policy"),
    )
    def test_claude_proxy_policy_bind_denial_is_runtime_unavailable(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "bind denied by policy",
        ):
            with providers._claude_connect_proxy({}):
                self.fail("unavailable proxy unexpectedly started")

    def test_claude_proxy_thread_failure_closes_server(self) -> None:
        server = mock.Mock()
        thread = mock.Mock()
        thread.start.side_effect = RuntimeError("thread unavailable")

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "CONNECT proxy cannot start",
            ),
        ):
            with providers._claude_connect_proxy({}):
                self.fail("unavailable proxy unexpectedly started")

        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_not_called()

    def test_claude_proxy_start_signal_is_preserved_and_cleaned(self) -> None:
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        server = mock.Mock()
        server.is_serving.return_value = False
        server.serve_error.return_value = None
        thread = mock.Mock()
        thread.ident = 123
        thread.is_alive.return_value = False
        thread.start.side_effect = forwarded

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with providers._claude_connect_proxy({}):
                self.fail("interrupted proxy unexpectedly started")

        self.assertIs(raised.exception, forwarded)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_proxy_thread_construction_failure_closes_server(self) -> None:
        server = mock.Mock()

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(
                providers.threading,
                "Thread",
                side_effect=RuntimeError("thread construction failed"),
            ),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "cannot construct",
            ),
        ):
            with providers._claude_connect_proxy({}):
                self.fail("failed proxy unexpectedly started")

        server.server_close.assert_called_once_with()

    def test_claude_proxy_serve_start_failure_is_inconclusive(self) -> None:
        serve_error = RuntimeError("serve startup failed")
        server = mock.Mock()
        server.wait_until_serving.return_value = False
        server.serve_error.return_value = serve_error
        server.is_serving.return_value = False
        thread = mock.Mock()
        thread.is_alive.return_value = False

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "did not enter its serve loop",
            ) as raised,
        ):
            with providers._claude_connect_proxy({}):
                self.fail("failed proxy unexpectedly started")

        self.assertIs(raised.exception.__cause__, serve_error)
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_proxy_post_start_serve_failure_is_inconclusive(self) -> None:
        serve_error = RuntimeError("injected post-start serve failure")
        server = mock.Mock()
        server.server_address = ("127.0.0.1", 43210)
        server.wait_until_serving.return_value = True
        server.is_serving.return_value = False
        server.serve_error.return_value = serve_error
        thread = mock.Mock()
        thread.is_alive.return_value = False

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaisesRegex(
                providers.ClaudeCredentialInspectionInconclusive,
                "serve loop failed after startup",
            ) as raised,
        ):
            with providers._claude_connect_proxy({}):
                pass

        self.assertIs(raised.exception.__cause__, serve_error)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_proxy_shutdown_prioritizes_post_start_serve_failure(
        self,
    ) -> None:
        serve_error = RuntimeError("injected post-start serve failure")
        server_close_error = OSError("injected server-close failure")
        server = mock.Mock()
        server.is_serving.return_value = False
        server.server_close.side_effect = server_close_error
        server.serve_error.return_value = serve_error
        thread = mock.Mock()
        thread.is_alive.return_value = False

        with self.assertRaisesRegex(
            providers.ClaudeCredentialInspectionInconclusive,
            "serve loop failed after startup",
        ) as raised:
            providers._shutdown_claude_proxy_server(
                server,
                thread,
                thread_started=True,
                primary_error=None,
            )

        chain: list[BaseException] = []
        current: BaseException | None = raised.exception
        while current is not None and len(chain) < 8:
            chain.append(current)
            current = current.__cause__
        self.assertIn(serve_error, chain)
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_proxy_shutdown_promotes_post_start_control_flow(
        self,
    ) -> None:
        for serve_error in (
            providers.ForwardedSignal(signal.SIGTERM),
            KeyboardInterrupt("injected post-start interrupt"),
            SystemExit("injected post-start exit"),
        ):
            with self.subTest(serve_error=type(serve_error).__name__):
                server = mock.Mock()
                server.is_serving.return_value = False
                server.serve_error.return_value = serve_error
                thread = mock.Mock()
                thread.is_alive.return_value = False
                body_error = RuntimeError("injected ordinary body failure")

                with self.assertRaises(type(serve_error)) as raised:
                    providers._shutdown_claude_proxy_server(
                        server,
                        thread,
                        thread_started=True,
                        primary_error=body_error,
                    )

                self.assertIs(raised.exception, serve_error)
                server.server_close.assert_called_once_with()
                thread.join.assert_called_once()

    def test_claude_proxy_cleanup_preserves_control_flow_and_continues(
        self,
    ) -> None:
        forwarded = providers.ForwardedSignal(signal.SIGTERM)
        server = mock.Mock()
        server.server_address = ("127.0.0.1", 43210)
        server.wait_until_serving.return_value = True
        server.is_serving.return_value = True
        server.serve_error.return_value = RuntimeError(
            "injected post-start serve failure"
        )
        server.shutdown.side_effect = OSError("injected shutdown failure")
        thread = mock.Mock()
        thread.is_alive.return_value = False

        with (
            mock.patch.object(
                providers,
                "_ClaudeProxyServer",
                return_value=server,
            ),
            mock.patch.object(providers.threading, "Thread", return_value=thread),
            self.assertRaises(providers.ForwardedSignal) as raised,
        ):
            with providers._claude_connect_proxy({}):
                raise forwarded

        self.assertIs(raised.exception, forwarded)
        server.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once()

    def test_claude_upstream_proxy_respects_bypass_environment(self) -> None:
        for key in ("NO_PROXY", "no_proxy"):
            with self.subTest(key=key):
                self.assertIsNone(
                    providers._upstream_proxy_url(
                        {
                            "HTTPS_PROXY": "http://corporate-proxy:8080",
                            key: ".anthropic.com",
                        },
                        host="api.anthropic.com",
                        port=443,
                    )
                )

    def test_claude_proxy_allows_api_and_oauth_refresh_targets(self) -> None:
        self.assertEqual(
            providers.CLAUDE_PROXY_TARGETS,
            frozenset(
                {
                    ("api.anthropic.com", 443),
                    ("platform.claude.com", 443),
                }
            ),
        )
        self.assertIn(
            providers._parse_connect_target("platform.claude.com:443"),
            providers.CLAUDE_PROXY_TARGETS,
        )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_refuses_unverified_safe_mode_semantics(
        self,
        run_command: mock.Mock,
        resolve: mock.Mock,
    ) -> None:
        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            candidate = pathlib.Path("/bin/claude")
            kwargs["candidate_validator"](candidate)
            return candidate

        resolve.side_effect = resolve_and_validate
        run_command.side_effect = (
            Completed(
                argv=("claude", "--version"),
                returncode=0,
                stdout=b"2.1.211 (Claude Code)\n",
                stderr=b"",
            ),
            Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=b"generic help",
                stderr=b"",
            ),
        )

        with self.assertRaisesRegex(ReviewError, "required review option"):
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={"HOME": "/Users/reviewer"},
            )

        self.assertEqual(run_command.call_count, 2)

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_accepts_semantic_safe_mode_option_block(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("claude", "--help"),
            returncode=0,
            stdout=claude_help_fixture(),
            stderr=b"",
        )

        providers._require_claude_safe_mode(
            pathlib.Path("/bin/claude"),
            {"HOME": str(self.review.container_dir)},
        )

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_rejects_safe_mode_option_mutations(
        self,
        run_command: mock.Mock,
    ) -> None:
        form = CLAUDE_SAFE_MODE_DESCRIPTION
        for mutated_form in (
            form.replace("plugins, hooks", "plugins", 1),
            form.replace("Auth, model selection", "Model selection", 1),
            form.replace("CLAUDE_CODE_SAFE_MODE=1", "CLAUDE_CODE_SAFE_MODE=0", 1),
            form.replace("all customizations", "some customizations", 1),
        ):
            with self.subTest(mutated_form=mutated_form):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=claude_help_fixture(safe_mode=mutated_form),
                    stderr=b"",
                )

                with self.assertRaisesRegex(ReviewError, "safe-mode semantics"):
                    providers._require_claude_safe_mode(
                        pathlib.Path("/bin/claude"),
                        {"HOME": str(self.review.container_dir)},
                    )

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_rejects_duplicate_or_conflicting_safe_mode_descriptions(
        self,
        run_command: mock.Mock,
    ) -> None:
        for help_text in (
            claude_help_fixture()
            + b"  --safe-mode hooks still load\n",
            claude_help_fixture(
                safe_mode=CLAUDE_SAFE_MODE_DESCRIPTION.replace(
                    "plugins, hooks, MCP",
                    "plugins, hooks still load, MCP",
                )
            ),
        ):
            with self.subTest(help_text=help_text):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=help_text,
                    stderr=b"",
                )

                with self.assertRaises(ReviewError):
                    providers._require_claude_safe_mode(
                        pathlib.Path("/bin/claude"),
                        {"HOME": str(self.review.container_dir)},
                    )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "run")
    def test_copilot_command_pins_opus_and_max(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        payload = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "messageId": "message-1",
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                        "toolRequests": [],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        )
        permission_help = " ".join(providers.COPILOT_PERMISSION_HELP_FRAGMENTS)
        run_command.side_effect = (
            Completed(
                argv=("copilot", "help", "permissions"),
                returncode=0,
                stdout=permission_help.encode(),
                stderr=b"",
            ),
            Completed(
                argv=("copilot",),
                returncode=0,
                stdout=payload.encode(),
                stderr=b"",
            ),
        )
        providers._copilot_attempt(
            review=self.review,
            model="claude-opus-4.8",
            index=1,
            env={"GH_TOKEN": "secret"},
        )
        argv = run_command.call_args_list[1].args[0]
        self.assertEqual(argv[argv.index("-C") + 1], str(self.review.workspace_root))
        self.assertEqual(
            argv[argv.index("--prompt") + 1],
            "Review this diff.\n",
        )
        self.assertIn("claude-opus-4.8", argv)
        self.assertEqual(argv[argv.index("--reasoning-effort") + 1], "max")
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertIn("--available-tools=view,glob,grep", argv)
        self.assertIn("--disable-builtin-mcps", argv)
        self.assertIn("--no-custom-instructions", argv)
        self.assertIn("--deny-tool=write", argv)
        self.assertIn("--deny-tool=shell", argv)
        self.assertIn("--deny-tool=url", argv)
        self.assertIn("--disallow-temp-dir", argv)
        self.assertNotIn("--allow-all-paths", argv)
        self.assertNotIn("--add-dir", argv)
        self.assertIn("--no-auto-update", argv)
        self.assertIn("--secret-env-vars=GH_TOKEN", argv)
        self.assertEqual(
            run_command.call_args_list[1].kwargs["env"]["COPILOT_HOME"],
            str(self.review.container_dir / "copilot-home"),
        )
        self.assertTrue((self.review.container_dir / "copilot-home").is_dir())
        self.assertEqual(
            run_command.call_args_list[0].kwargs["timeout_seconds"],
            providers.COPILOT_PROBE_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[0].kwargs["capture_limit_bytes"],
            providers.COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
        )
        self.assertEqual(
            run_command.call_args_list[0].kwargs["output_file_limit_bytes"],
            providers.COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
        )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "run")
    def test_copilot_refuses_unverified_path_permission_semantics(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("copilot", "help", "permissions"),
            returncode=0,
            stdout=b"generic help",
            stderr=b"",
        )
        with self.assertRaisesRegex(ReviewError, "cwd-only path verifier"):
            providers._copilot_attempt(
                review=self.review,
                model="claude-opus-4.8",
                index=1,
                env={"GH_TOKEN": "secret"},
            )
        self.assertEqual(run_command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
