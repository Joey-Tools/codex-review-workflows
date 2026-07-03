from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common, providers  # noqa: E402
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


class ProviderPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        source_root = root / "source"
        container = source_root / ".codex-tmp" / "isolated-review-test"
        workspace = container / "workspace"
        control = workspace / ".codex-review"
        control.mkdir(parents=True)
        diff_file = control / "review.diff"
        diff_file.write_text("diff --git a/a b/a\n", encoding="utf-8")
        (control / "changed-paths.z").write_bytes(b"")
        (control / "changed-blob-findings.z").write_bytes(b"")
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
        self.claude_broker = (
            container / "claude-runtime" / "keychain-broker" / "security"
        )
        self.claude_broker.parent.mkdir(parents=True)
        self.claude_broker.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        self.claude_broker.chmod(0o700)
        self.claude_keychain_client = root / "host-tools" / "security"
        self.claude_ripgrep = root / "host-tools" / "rg"
        for fixture in (
            self.claude_keychain_client,
            self.claude_ripgrep,
        ):
            fixture.parent.mkdir(parents=True, exist_ok=True)
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
        self.native_macho_dependencies = providers._native_macho_dependencies
        self.native_dependency_patcher = mock.patch.object(
            providers,
            "_native_macho_dependencies",
            side_effect=lambda path, *, label: tuple(
                dict.fromkeys((path.absolute(), path.resolve()))
            ),
        )
        self.native_dependency_patcher.start()
        self.require_trusted_claude_digest = providers._require_trusted_claude_digest
        self.trusted_digest_patcher = mock.patch.object(
            providers,
            "_require_trusted_claude_digest",
        )
        self.trusted_digest = self.trusted_digest_patcher.start()
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
        self.keychain_runtime_patcher = mock.patch.object(
            providers,
            "_claude_keychain_runtime",
            side_effect=self.fake_claude_keychain_runtime,
        )
        self.keychain_runtime_patcher.start()
        self.require_fresh_claude_keychain_credential = (
            providers._require_fresh_claude_keychain_credential
        )
        self.warm_claude_local_login = providers._warm_claude_local_login
        self.warmup_patcher = mock.patch.object(
            providers,
            "_warm_claude_local_login",
        )
        self.warmup = self.warmup_patcher.start()

    def tearDown(self) -> None:
        self.warmup_patcher.stop()
        self.keychain_runtime_patcher.stop()
        self.keychain_broker_patcher.stop()
        self.trusted_digest_patcher.stop()
        self.native_dependency_patcher.stop()
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
    ):
        result = dict(env)
        if not result.get("ANTHROPIC_API_KEY"):
            result[providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = "43211"
            result[providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV] = "00" * 32
        yield result

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

    def sample_ca_certificate(self) -> bytes:
        defaults = ssl.get_default_verify_paths()
        for raw in (defaults.cafile, "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
            if not raw:
                continue
            path = pathlib.Path(raw)
            if not path.is_file():
                continue
            blocks = providers.CLAUDE_CERTIFICATE_BLOCK.findall(path.read_bytes())
            if blocks:
                return blocks[0] + b"\n"
        self.skipTest("no system PEM CA certificate is available")

    def test_capacity_wins_over_unavailable_wording(self) -> None:
        category = providers.classify_failure(
            "",
            "Selected model is temporarily unavailable because it is at capacity",
        )
        self.assertEqual(category, "transient")

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

    def test_claude_digest_accepts_pinned_release_across_helper_architectures(
        self,
    ) -> None:
        executable = self.review.source_root / "claude"
        payload = b"trusted Claude release fixture"
        executable.write_bytes(payload)
        expected = hashlib.sha256(payload).hexdigest()

        with mock.patch.object(
            providers,
            "CLAUDE_TRUSTED_SHA256_BY_MACHINE",
            {"arm64": "00" * 32, "x86_64": expected},
        ):
            self.require_trusted_claude_digest(executable)

    def test_claude_digest_rejects_unpinned_native_binary(self) -> None:
        executable = self.review.source_root / "claude"
        executable.write_bytes(b"untrusted native fixture")

        with mock.patch.object(
            providers,
            "CLAUDE_TRUSTED_SHA256_BY_MACHINE",
            {"arm64": "00" * 32, "x86_64": "11" * 32},
        ), self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "trusted macOS release digests",
        ):
            self.require_trusted_claude_digest(executable)

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
    def test_keychain_broker_bind_failure_is_runtime_unavailable(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "Keychain broker cannot bind loopback",
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
        side_effect=providers.ClaudeLoopbackUnavailable("bind denied"),
    )
    def test_keychain_runtime_zeroes_credential_when_broker_bind_fails(
        self,
        _server: mock.Mock,
        read_credential: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture())
        read_credential.return_value = credential

        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "bind denied",
        ):
            with self.claude_keychain_runtime(self.review, {}):
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
                providers.ClaudeLoopbackUnavailable,
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

        try:
            context = providers._claude_keychain_credential_server(
                credential,
                capability,
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
        self.assertEqual(stdin_update.returncode, 64)
        self.assertEqual(direct_update.returncode, 64)
        self.assertEqual(credential, bytearray(len(credential)))
        self.assertFalse(providers._ClaudeKeychainCredentialServer.daemon_threads)

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

    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_keychain_preflight_rejects_stale_access_token(
        self,
        read_credential: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture(expires_in_seconds=60))
        read_credential.return_value = credential

        with self.assertRaisesRegex(
            providers.ClaudeKeychainCredentialUnavailable,
            "cannot cover the isolated review window",
        ):
            self.require_fresh_claude_keychain_credential(self.review)

        self.assertEqual(credential, bytearray(len(credential)))

    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_keychain_preflight_accepts_fresh_access_token(
        self,
        read_credential: mock.Mock,
    ) -> None:
        credential = bytearray(oauth_credential_fixture())
        read_credential.return_value = credential

        self.require_fresh_claude_keychain_credential(self.review)

        self.assertEqual(credential, bytearray(len(credential)))

    @mock.patch.object(providers, "_read_claude_keychain_credential")
    def test_keychain_preflight_requires_whole_model_chain_lifetime(
        self,
        read_credential: mock.Mock,
    ) -> None:
        single_attempt_lifetime = (
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS
            + providers.CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS
            + 30
        )
        credential = bytearray(
            oauth_credential_fixture(expires_in_seconds=single_attempt_lifetime)
        )
        read_credential.return_value = credential

        with self.assertRaisesRegex(
            providers.ClaudeKeychainCredentialUnavailable,
            "cannot cover the isolated review window",
        ):
            self.require_fresh_claude_keychain_credential(self.review)

        self.assertEqual(credential, bytearray(len(credential)))

    def test_keychain_preflight_rejects_unbounded_integer_expiry(self) -> None:
        credential = bytearray(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "access" + "Token": "fixture-" + "access-value",
                        "refresh" + "Token": "fixture-" + "refresh-value",
                        "expiresAt": 10**1000,
                    }
                }
            ).encode()
        )

        with self.assertRaisesRegex(
            providers.ClaudeKeychainCredentialUnavailable,
            "cannot cover the isolated review window",
        ):
            providers._validate_fresh_claude_keychain_credential(credential)

    @mock.patch.object(providers, "_require_fresh_claude_keychain_credential")
    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    @mock.patch.object(
        providers,
        "_claude_review_sandbox_profile",
        return_value="(version 1)(deny default)",
    )
    @mock.patch.object(
        providers,
        "_claude_connect_proxy",
        return_value=contextlib.nullcontext(43210),
    )
    @mock.patch.object(providers, "run")
    def test_stale_local_login_uses_fixed_safe_mode_warmup(
        self,
        run_command: mock.Mock,
        proxy: mock.Mock,
        sandbox_profile: mock.Mock,
        _rg: mock.Mock,
        require_fresh: mock.Mock,
    ) -> None:
        require_fresh.side_effect = (
            providers.ClaudeKeychainCredentialUnavailable("stale"),
            None,
        )
        run_command.return_value = Completed(
            argv=("claude",),
            returncode=0,
            stdout=b'OK',
            stderr=b"",
        )
        home = self.review.container_dir / "claude-home"
        temporary = self.review.container_dir / "tmp"
        home.mkdir(exist_ok=True)
        temporary.mkdir(exist_ok=True)

        self.warm_claude_local_login(
            self.review,
            pathlib.Path("/bin/claude"),
            {
                "HOME": str(home),
                "TMPDIR": str(temporary),
                "PATH": "/untrusted",
            },
        )

        argv = run_command.call_args.args[0]
        self.assertIn("--safe-mode", argv)
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "default")
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertEqual(
            argv[argv.index("--allowedTools") + 1],
            "Read(./__claude_auth_warmup_no_files__)",
        )
        self.assertEqual(run_command.call_args.kwargs["stdin"], b"Reply with exactly OK.")
        self.assertEqual(
            run_command.call_args.kwargs["timeout_seconds"],
            providers.CLAUDE_AUTH_WARMUP_TIMEOUT_SECONDS,
        )
        self.assertEqual(require_fresh.call_count, 2)
        self.assertEqual(
            proxy.call_args.kwargs["allowed_targets"],
            providers.CLAUDE_AUTH_PROXY_TARGETS,
        )
        self.assertTrue(
            sandbox_profile.call_args.kwargs["allow_direct_keychain"]
        )
        self.assertFalse(
            sandbox_profile.call_args.kwargs["allow_workspace_read"]
        )

    @mock.patch.object(providers, "_require_fresh_claude_keychain_credential")
    @mock.patch.object(providers, "_run_claude_auth_warmup")
    def test_transient_login_warmup_failure_is_inconclusive(
        self,
        warmup: mock.Mock,
        require_fresh: mock.Mock,
    ) -> None:
        require_fresh.side_effect = (
            providers.ClaudeKeychainCredentialUnavailable("stale"),
            providers.ClaudeKeychainCredentialUnavailable("still stale"),
        )
        warmup.return_value = Completed(
            argv=("claude",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "result",
                    "subtype": "error_during_execution",
                    "is_error": True,
                    "api_error_status": 429,
                }
            ).encode(),
            stderr=b"",
        )

        with self.assertRaisesRegex(
            providers.ClaudeAuthWarmupInconclusive,
            "transient",
        ):
            self.warm_claude_local_login(
                self.review,
                pathlib.Path("/bin/claude"),
                {},
            )

    @mock.patch.object(providers, "_require_fresh_claude_keychain_credential")
    @mock.patch.object(providers, "_run_claude_auth_warmup")
    def test_auth_login_warmup_failure_remains_unavailable(
        self,
        warmup: mock.Mock,
        require_fresh: mock.Mock,
    ) -> None:
        require_fresh.side_effect = (
            providers.ClaudeKeychainCredentialUnavailable("stale"),
            providers.ClaudeKeychainCredentialUnavailable("still stale"),
        )
        warmup.return_value = Completed(
            argv=("claude",),
            returncode=1,
            stdout=b"",
            stderr=b"authentication failed",
        )

        with self.assertRaisesRegex(
            providers.ClaudeKeychainCredentialUnavailable,
            "still stale",
        ):
            self.warm_claude_local_login(
                self.review,
                pathlib.Path("/bin/claude"),
                {},
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
    def test_keychain_broker_compile_failure_is_unavailable(
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
            providers.ClaudeKeychainBrokerUnavailable,
            "toolchain unavailable",
        ):
            self.prepare_claude_keychain_broker(
                self.review,
                {
                    "HOME": str(self.review.container_dir / "claude-home"),
                    "PATH": "/usr/bin",
                },
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
        side_effect=(pathlib.Path("/bin/claude"), pathlib.Path("/bin/copilot")),
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
    def test_stale_claude_credential_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        self.warmup.side_effect = (
            providers.ClaudeKeychainCredentialUnavailable("credential remains stale")
        )
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
            "credential remains stale",
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
    def test_transient_claude_warmup_failure_refuses_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        self.warmup.side_effect = providers.ClaudeAuthWarmupInconclusive(
            "transient refresh failure"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "transient refresh failure",
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
        side_effect=(pathlib.Path("/bin/claude"), pathlib.Path("/bin/copilot")),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_without_usable_auth_uses_authorized_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            "auth",
        )
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
        self.assertEqual(resolve.call_count, 2)

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
                    "error": {"message": "Model is not available for your account"},
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
                    "error": {
                        "message": "Model is not available for your account"
                    },
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

    @mock.patch.object(providers, "_run_claude_probe")
    def test_claude_identity_requires_exact_supported_version(
        self,
        run_probe: mock.Mock,
    ) -> None:
        run_probe.return_value = Completed(
            argv=("claude", "--version"),
            returncode=0,
            stdout=b"2.1.188 (Claude Code)\n",
            stderr=b"",
        )

        with self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "supported Claude Code 2.1.187",
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
                stdout=b"2.1.187 (Claude Code)\n",
                stderr=b"",
            ),
            Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=(
                    "Options:\n  "
                    + providers.CLAUDE_SAFE_MODE_HELP_FORM
                    + "\n  --betas <betas...> Beta headers\n"
                ).encode(),
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
                "HOME": "/Users/reviewer",
                "XDG_CONFIG_HOME": "/Users/reviewer/.config",
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                "CODEX_ISOLATED_REVIEW_RANGE": "base..head",
            },
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
        self.assertNotIn("CODEX_ISOLATED_REVIEW_RANGE", probe_env)
        self.assertEqual(
            probe_env["HOME"],
            str(self.review.container_dir / "claude-probe-home"),
        )
        self.assertNotIn("XDG_CONFIG_HOME", probe_env)
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
        self.assertEqual(review_env["NO_PROXY"], "")
        self.assertEqual(
            run_command.call_args_list[2].kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[2].kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
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
    def test_claude_review_sandbox_allows_exact_custom_ca_paths(
        self,
        _rg: mock.Mock,
    ) -> None:
        certificate = self.sample_ca_certificate()
        ca_file = self.review.source_root / "corporate-ca.pem"
        ca_file.write_bytes(certificate)
        ca_dir = self.review.source_root / "certs"
        ca_dir.mkdir()
        (ca_dir / "12345678.0").write_bytes(certificate)

        prepared_env = providers._prepare_claude_tls_environment(
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": str(self.claude_broker.parent),
                providers.CLAUDE_KEYCHAIN_BROKER_PORT_ENV: "43211",
                providers.CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV: "00" * 32,
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
        prepared_dir = pathlib.Path(prepared_env["SSL_CERT_DIR"])
        self.assertTrue(providers.is_relative_to(prepared_file, self.review.container_dir))
        self.assertTrue(providers.is_relative_to(prepared_dir, self.review.container_dir))
        self.assertIn(f'(literal "{prepared_file}")', profile)
        self.assertIn(f'(subpath "{prepared_dir}")', profile)
        self.assertNotIn(str(ca_file), profile)
        self.assertNotIn(str(ca_dir), profile)

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
    def test_claude_auth_warmup_allows_only_direct_keychain_client(
        self,
        _rg: mock.Mock,
    ) -> None:
        profile = providers._claude_review_sandbox_profile(
            pathlib.Path("/bin/true"),
            self.review,
            {
                "HOME": str(self.review.container_dir / "claude-home"),
                "TMPDIR": str(self.review.container_dir / "tmp"),
                "PATH": "/usr/bin:/bin",
            },
            proxy_port=43210,
            allow_direct_keychain=True,
            allow_workspace_read=False,
        )

        self.assertIn(
            f'(literal "{self.claude_keychain_client.resolve()}")',
            profile,
        )
        self.assertIn("com.apple.securityd.xpc", profile)
        self.assertNotIn(str(self.claude_broker.resolve()), profile)
        self.assertNotIn(
            f'(subpath "{self.review.workspace_root.resolve()}")',
            profile,
        )

    @mock.patch.object(
        providers,
        "_trusted_claude_ripgrep",
        return_value=pathlib.Path("/bin/echo"),
    )
    def test_claude_review_sandbox_rejects_relative_ca_file(
        self,
        _rg: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "valid absolute SSL_CERT_FILE"):
            providers._prepare_claude_tls_environment(
                self.review,
                {
                    "SSL_CERT_FILE": "corporate-ca.pem",
                },
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
        source.write_text(
            "machine example.test login user password secret\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ReviewError, "contains no PEM certificate"):
            providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_FILE": str(source)},
            )

    def test_claude_tls_preparation_rejects_private_key_material(self) -> None:
        source = self.review.source_root / "combined.pem"
        source.write_bytes(
            self.sample_ca_certificate()
            + b"-----BEGIN "
            + b"PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
        )

        with self.assertRaisesRegex(ReviewError, "contains a private key"):
            providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_FILE": str(source)},
            )

    def test_claude_tls_preparation_preserves_same_named_ca_entries(self) -> None:
        certificate = self.sample_ca_certificate()
        source_dirs = []
        for name in ("first", "second"):
            source_dir = self.review.source_root / name
            source_dir.mkdir()
            (source_dir / "deadbeef.0").write_bytes(certificate)
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

    def test_claude_tls_preparation_bounds_directory_enumeration_before_sort(
        self,
    ) -> None:
        source_dir = self.review.source_root / "large-ca-dir"
        source_dir.mkdir()
        consumed = 0

        def entries():
            nonlocal consumed
            for index in range(providers.CLAUDE_CA_DIR_ENTRY_LIMIT + 10):
                consumed += 1
                yield source_dir / f"entry-{index:05d}"

        with (
            mock.patch.object(pathlib.Path, "iterdir", return_value=entries()),
            self.assertRaisesRegex(ReviewError, "too many entries"),
        ):
            providers._prepare_claude_tls_environment(
                self.review,
                {"SSL_CERT_DIR": str(source_dir)},
            )

        self.assertEqual(consumed, providers.CLAUDE_CA_DIR_ENTRY_LIMIT + 1)

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
    def test_claude_proxy_bind_failure_is_runtime_unavailable(
        self,
        _server: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeLoopbackUnavailable,
            "CONNECT proxy cannot bind loopback",
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
                providers.ClaudeLoopbackUnavailable,
                "CONNECT proxy cannot start",
            ),
        ):
            with providers._claude_connect_proxy({}):
                self.fail("unavailable proxy unexpectedly started")

        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        thread.join.assert_not_called()

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
            frozenset({("api.anthropic.com", 443)}),
        )
        self.assertEqual(
            providers.CLAUDE_AUTH_PROXY_TARGETS,
            frozenset(
                {
                    ("api.anthropic.com", 443),
                    ("platform.claude.com", 443),
                }
            ),
        )
        self.assertIn(
            providers._parse_connect_target("platform.claude.com:443"),
            providers.CLAUDE_AUTH_PROXY_TARGETS,
        )
        self.assertNotIn(
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
                stdout=b"2.1.187 (Claude Code)\n",
                stderr=b"",
            ),
            Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=b"generic help",
                stderr=b"",
            ),
        )

        with self.assertRaisesRegex(ReviewError, "uniquely verifiable --safe-mode"):
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
    def test_claude_accepts_exact_safe_mode_option_block(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("claude", "--help"),
            returncode=0,
            stdout=(
                "Usage: claude [options]\nOptions:\n  "
                + providers.CLAUDE_SAFE_MODE_HELP_FORM
                + "\n  --betas <betas...> Beta headers\n"
            ).encode(),
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
        form = providers.CLAUDE_SAFE_MODE_HELP_FORM
        for mutated_form in (
            form.replace("plugins, hooks", "plugins with hooks", 1),
            form.replace("auth, model selection", "model selection", 1),
            form.replace("claude_code_safe_mode=1", "claude_code_safe_mode=0", 1),
            form.replace("all customizations", "some customizations", 1),
        ):
            with self.subTest(mutated_form=mutated_form):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=(
                        "Options:\n  "
                        + mutated_form
                        + "\n  --betas <betas...> Beta headers\n"
                    ).encode(),
                    stderr=b"",
                )

                with self.assertRaisesRegex(ReviewError, "uniquely verifiable --safe-mode"):
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
        form = providers.CLAUDE_SAFE_MODE_HELP_FORM
        for help_text in (
            "Options:\n  " + form + "\n  --safe-mode hooks still load\n",
            "Options:\n  "
            + form
            + "\n  hooks still load\n  --betas <betas...> Beta headers\n",
            "Options:\n  "
            + form
            + "\n  --betas <betas...> Unlike --safe-mode, hooks still load\n",
        ):
            with self.subTest(help_text=help_text):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=help_text.encode(),
                    stderr=b"",
                )

                with self.assertRaisesRegex(ReviewError, "uniquely verifiable --safe-mode"):
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
