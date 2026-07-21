from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_provenance  # noqa: E402


def artifact_for(payload: bytes) -> claude_provenance.ClaudeReleaseArtifact:
    return claude_provenance.ClaudeReleaseArtifact(
        version="2.1.211",
        platform_key="darwin-arm64",
        binary="claude",
        checksum=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def verified_for(
    executable: pathlib.Path,
    payload: bytes,
) -> claude_provenance.VerifiedClaudeExecutable:
    return claude_provenance.VerifiedClaudeExecutable(
        executable=executable.resolve(),
        artifact=artifact_for(payload),
        manifest_url="https://downloads.claude.ai/manifest.json",
        signature_url="https://downloads.claude.ai/manifest.json.sig",
        gpg_path=pathlib.Path("/trusted/gpg"),
    )


def manifest_for(
    payload: bytes,
    *,
    version: str = "2.1.211",
    platform_key: str = "darwin-arm64",
    binary: str = "claude",
    checksum: str | None = None,
    size: int | bool | None = None,
) -> bytes:
    value = {
        "version": version,
        "platforms": {
            platform_key: {
                "binary": binary,
                "checksum": checksum or hashlib.sha256(payload).hexdigest(),
                "size": len(payload) if size is None else size,
            }
        },
    }
    return json.dumps(value).encode()


def completed(
    argv: list[str],
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class ReleaseVersionTest(unittest.TestCase):
    def test_accepts_supported_floating_release_versions(self) -> None:
        self.assertEqual(
            claude_provenance.require_supported_release_version("2.1.211"),
            (2, 1, 211),
        )
        self.assertEqual(
            claude_provenance.require_supported_release_version("2.1.216"),
            (2, 1, 216),
        )
        self.assertEqual(
            claude_provenance.require_supported_release_version("2.99.1000"),
            (2, 99, 1000),
        )

    def test_rejects_versions_outside_supported_major_range(self) -> None:
        for version in ("2.1.210", "1.99.999", "3.0.0", "4.1.0"):
            with self.subTest(version=version):
                with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                    claude_provenance.require_supported_release_version(version)

    def test_rejects_non_release_or_noncanonical_semver(self) -> None:
        for version in (
            "2.1.211-beta.1",
            "2.1.211+build",
            "v2.1.211",
            "02.1.211",
            "2.01.211",
            "2.1",
            "2.1.211\n",
        ):
            with self.subTest(version=version):
                with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                    claude_provenance.require_supported_release_version(version)

    def test_builds_exact_version_urls(self) -> None:
        self.assertEqual(
            claude_provenance.release_artifact_urls("2.1.211"),
            (
                "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json",
                "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json.sig",
            ),
        )


class SignedManifestFetchTest(unittest.TestCase):
    def test_deadline_cleanup_legacy_fallback_respects_context_visibility(
        self,
    ) -> None:
        class LegacyError(RuntimeError):
            add_note = None

        sensitive_path = "/fixture/private/suppressed-provenance-context/auth.json"
        for suppress_context in (False, True):
            with self.subTest(suppress_context=suppress_context):
                marker = (
                    sensitive_path if suppress_context else "visible-provenance-context"
                )
                original_context = RuntimeError(marker)
                primary = LegacyError("primary deadline failure")
                primary.__context__ = original_context
                primary.__suppress_context__ = suppress_context

                claude_provenance._add_deadline_cleanup_note(
                    primary,
                    OSError("deadline cleanup failed"),
                )

                diagnostic = primary.__cause__
                self.assertIsInstance(
                    diagnostic,
                    claude_provenance._FetchDeadlineCleanupDiagnostic,
                )
                assert diagnostic is not None
                if suppress_context:
                    self.assertIsNone(diagnostic.__context__)
                else:
                    self.assertIs(diagnostic.__context__, original_context)
                formatted = "".join(
                    traceback.format_exception(
                        type(primary),
                        primary,
                        primary.__traceback__,
                    )
                )
                if suppress_context:
                    self.assertNotIn(marker, formatted)
                else:
                    self.assertIn(marker, formatted)

    def test_deadline_rejects_blocked_sigalrm_before_installing_handler(self) -> None:
        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                return_value=(0.0, 0.0),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value={claude_provenance.signal.SIGALRM},
            ),
            mock.patch.object(claude_provenance.signal, "signal") as install,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "SIGALRM is blocked",
            ),
        ):
            with claude_provenance._enforce_fetch_deadline(1):
                self.fail("blocked SIGALRM must prevent egress")

        install.assert_not_called()

    def test_deadline_restores_handler_after_install_interruption(self) -> None:
        handlers: list[object] = []

        def interrupt_after_install(_signum: int, handler: object) -> None:
            handlers.append(handler)
            if len(handlers) == 1:
                raise KeyboardInterrupt

        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                return_value=(0.0, 0.0),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "signal",
                side_effect=interrupt_after_install,
            ),
            mock.patch.object(claude_provenance.signal, "setitimer") as set_timer,
            self.assertRaises(KeyboardInterrupt),
        ):
            with claude_provenance._enforce_fetch_deadline(1):
                self.fail("interrupted handler installation must not enter body")

        self.assertEqual(handlers[-1], claude_provenance.signal.SIG_DFL)
        set_timer.assert_not_called()

    def test_deadline_disarms_timer_after_install_interruption(self) -> None:
        timer_calls: list[tuple[object, ...]] = []

        def interrupt_after_arming(*args: object) -> None:
            timer_calls.append(args)
            if len(timer_calls) == 1:
                raise KeyboardInterrupt

        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                return_value=(0.0, 0.0),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(claude_provenance.signal, "signal") as install,
            mock.patch.object(
                claude_provenance.signal,
                "setitimer",
                side_effect=interrupt_after_arming,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            with claude_provenance._enforce_fetch_deadline(1):
                self.fail("interrupted timer installation must not enter body")

        self.assertEqual(
            timer_calls[-1],
            (claude_provenance.signal.ITIMER_REAL, 0),
        )
        self.assertEqual(install.call_count, 2)

    def test_deadline_keeps_guard_handler_when_timer_cannot_be_disarmed(self) -> None:
        timer_calls = 0

        def fail_disarm(*_args: object) -> None:
            nonlocal timer_calls
            timer_calls += 1
            if timer_calls == 2:
                raise OSError("injected disarm failure")

        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                side_effect=((0.0, 0.0), (1.0, 0.0)),
            ),
            mock.patch.object(claude_provenance.signal, "signal") as install,
            mock.patch.object(
                claude_provenance.signal,
                "setitimer",
                side_effect=fail_disarm,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "safely clear",
            ),
        ):
            with claude_provenance._enforce_fetch_deadline(1):
                pass

        self.assertEqual(install.call_count, 1)

    def test_deadline_preserves_timer_state_inspection_interruption(self) -> None:
        interruption = KeyboardInterrupt()
        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                side_effect=((0.0, 0.0), interruption),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(claude_provenance.signal, "signal") as install,
            mock.patch.object(
                claude_provenance.signal,
                "setitimer",
                side_effect=(None, OSError("injected disarm failure")),
            ),
        ):
            try:
                with claude_provenance._enforce_fetch_deadline(1):
                    pass
            except KeyboardInterrupt as error:
                self.assertIs(error, interruption)
            else:
                self.fail("timer-state interruption must remain control flow")

        self.assertEqual(install.call_count, 1)

    def test_deadline_preserves_body_interruption_when_disarm_fails(self) -> None:
        interruption = KeyboardInterrupt()
        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                side_effect=((0.0, 0.0), (1.0, 0.0)),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(claude_provenance.signal, "signal") as install,
            mock.patch.object(
                claude_provenance.signal,
                "setitimer",
                side_effect=(None, OSError("injected disarm failure")),
            ),
        ):
            try:
                with claude_provenance._enforce_fetch_deadline(1):
                    raise interruption
            except KeyboardInterrupt as error:
                self.assertIs(error, interruption)
            else:
                self.fail("body interruption must remain control flow")

        self.assertEqual(install.call_count, 1)

    def test_deadline_preserves_handler_restore_interruption(self) -> None:
        interruption = KeyboardInterrupt()
        with (
            mock.patch.object(
                claude_provenance.signal,
                "getsignal",
                return_value=claude_provenance.signal.SIG_DFL,
            ),
            mock.patch.object(
                claude_provenance.signal,
                "getitimer",
                side_effect=((0.0, 0.0), (0.0, 0.0)),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "pthread_sigmask",
                return_value=set(),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "signal",
                side_effect=(None, interruption),
            ),
            mock.patch.object(
                claude_provenance.signal,
                "setitimer",
                side_effect=(None, OSError("injected disarm failure")),
            ),
        ):
            try:
                with claude_provenance._enforce_fetch_deadline(1):
                    pass
            except KeyboardInterrupt as error:
                self.assertIs(error, interruption)
            else:
                self.fail("handler-restore interruption must remain control flow")

    def test_fetches_exact_urls_with_independent_byte_limits(self) -> None:
        calls: list[tuple[str, int, float]] = []

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            calls.append((url, max_bytes, timeout_seconds))
            return b"manifest" if url.endswith("manifest.json") else b"signature"

        bundle = claude_provenance.fetch_signed_manifest(
            "2.1.211",
            fetcher=fetcher,
            timeout_seconds=3.5,
        )

        self.assertEqual(bundle.manifest, b"manifest")
        self.assertEqual(bundle.signature, b"signature")
        self.assertEqual(
            calls,
            [
                (
                    "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json",
                    claude_provenance.CLAUDE_MANIFEST_MAX_BYTES,
                    3.5,
                ),
                (
                    "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json.sig",
                    claude_provenance.CLAUDE_SIGNATURE_MAX_BYTES,
                    3.5,
                ),
            ],
        )

    def test_rejects_oversized_injected_fetcher_result(self) -> None:
        def fetcher(
            _url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del timeout_seconds
            return b"x" * (max_bytes + 1)

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "byte limit",
        ):
            claude_provenance.fetch_signed_manifest("2.1.211", fetcher=fetcher)

    def test_classifies_fetcher_failure_as_inconclusive(self) -> None:
        def fetcher(
            _url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            raise OSError("network unavailable")

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInconclusive,
            "network unavailable",
        ):
            claude_provenance.fetch_signed_manifest("2.1.211", fetcher=fetcher)

    def test_rejects_non_bytes_or_empty_fetcher_result(self) -> None:
        for payload in ("manifest", b""):
            with self.subTest(payload=payload):
                with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                    claude_provenance.fetch_signed_manifest(
                        "2.1.211",
                        fetcher=lambda *_args, **_kwargs: payload,
                    )

    def test_default_fetcher_rejects_redirects_from_exact_release_url(self) -> None:
        url = "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json"
        redirect = claude_provenance.urllib.error.HTTPError(
            url,
            302,
            "Found",
            {},
            None,
        )
        opener = mock.Mock()
        opener.open.side_effect = redirect
        with mock.patch.object(
            claude_provenance.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "redirected",
            ):
                claude_provenance._default_fetcher(
                    url,
                    max_bytes=1024,
                    timeout_seconds=1,
                )

    def test_default_fetcher_deadline_includes_url_open_and_headers(self) -> None:
        url = "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json"
        opener = mock.Mock()

        def stall_before_headers(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            time.sleep(5)
            raise AssertionError("deadline did not interrupt URL open")

        opener.open.side_effect = stall_before_headers
        started = time.monotonic()
        with mock.patch.object(
            claude_provenance.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "total timeout",
            ):
                claude_provenance._default_fetcher(
                    url,
                    max_bytes=1024,
                    timeout_seconds=0.05,
                )

        self.assertLess(time.monotonic() - started, 1.0)

    def test_default_fetcher_reads_response_body_in_bounded_chunks(self) -> None:
        url = "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json"
        body = b"x" * (claude_provenance.CLAUDE_FETCH_CHUNK_BYTES + 3)

        class ChunkedResponse:
            status = 200
            headers: dict[str, str] = {}

            def __init__(self) -> None:
                self.offset = 0
                self.read_sizes: list[int] = []
                self.fp = mock.Mock()

            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *_args):  # type: ignore[no-untyped-def]
                return False

            def geturl(self) -> str:
                return url

            def read1(self, size: int) -> bytes:
                self.read_sizes.append(size)
                chunk = body[self.offset : self.offset + size]
                self.offset += len(chunk)
                return chunk

        response = ChunkedResponse()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
            claude_provenance.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            payload = claude_provenance._default_fetcher(
                url,
                max_bytes=len(body),
                timeout_seconds=1,
            )

        self.assertEqual(payload, body)
        self.assertGreaterEqual(len(response.read_sizes), 3)
        self.assertLessEqual(
            max(response.read_sizes),
            claude_provenance.CLAUDE_FETCH_CHUNK_BYTES,
        )
        self.assertEqual(
            response.fp.raw._sock.settimeout.call_count,
            len(response.read_sizes),
        )

    def test_default_fetcher_stops_slow_drip_at_total_deadline(self) -> None:
        url = (
            "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json.sig"
        )
        clock = [10.0]

        class SlowDripResponse:
            status = 200
            headers: dict[str, str] = {}

            def __init__(self) -> None:
                self.read_sizes: list[int] = []
                self.fp = mock.Mock()

            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *_args):  # type: ignore[no-untyped-def]
                return False

            def geturl(self) -> str:
                return url

            def read1(self, size: int) -> bytes:
                self.read_sizes.append(size)
                clock[0] += 0.4
                return b"x"

        response = SlowDripResponse()
        opener = mock.Mock()
        opener.open.return_value = response
        with (
            mock.patch.object(
                claude_provenance.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            mock.patch.object(
                claude_provenance.time,
                "monotonic",
                side_effect=lambda: clock[0],
            ),
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "total timeout",
            ):
                claude_provenance._default_fetcher(
                    url,
                    max_bytes=1024,
                    timeout_seconds=1,
                )

        self.assertEqual(len(response.read_sizes), 3)
        self.assertTrue(
            all(
                size <= claude_provenance.CLAUDE_FETCH_CHUNK_BYTES
                for size in response.read_sizes
            )
        )
        applied_timeouts = [
            call.args[0] for call in response.fp.raw._sock.settimeout.call_args_list
        ]
        self.assertEqual(len(applied_timeouts), 3)
        for actual, expected in zip(applied_timeouts, (1.0, 0.6, 0.2)):
            self.assertAlmostEqual(actual, expected)


class ManifestParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = b"\x7fELF trusted Claude fixture"

    def test_parses_supported_platform_artifact(self) -> None:
        artifact = claude_provenance.parse_signed_manifest_artifact(
            manifest_for(self.payload, platform_key="linux-x64"),
            version="2.1.211",
            platform_key="linux-x64",
        )

        self.assertEqual(artifact.version, "2.1.211")
        self.assertEqual(artifact.platform_key, "linux-x64")
        self.assertEqual(artifact.binary, "claude")
        self.assertEqual(artifact.size, len(self.payload))

    def test_rejects_duplicate_json_keys_at_any_depth(self) -> None:
        manifest = (
            b'{"version":"2.1.211","platforms":{"darwin-arm64":'
            b'{"binary":"claude","binary":"wrapper","checksum":"'
            + hashlib.sha256(self.payload).hexdigest().encode()
            + b'","size":24}}}'
        )

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "duplicate key",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest,
                version="2.1.211",
                platform_key="darwin-arm64",
            )

    def test_rejects_non_standard_json_constants(self) -> None:
        manifest = manifest_for(self.payload).replace(
            str(len(self.payload)).encode(),
            b"NaN",
        )

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "non-standard JSON constant",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest,
                version="2.1.211",
                platform_key="darwin-arm64",
            )

    def test_rejects_manifest_version_mismatch(self) -> None:
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "version does not match",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest_for(self.payload, version="2.1.203"),
                version="2.1.211",
                platform_key="darwin-arm64",
            )

    def test_rejects_unsupported_native_windows_platform(self) -> None:
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "unsupported.*platform",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest_for(
                    self.payload,
                    platform_key="win32-x64",
                    binary="claude.exe",
                ),
                version="2.1.211",
                platform_key="win32-x64",
            )

    def test_rejects_wrong_binary_name(self) -> None:
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "binary name",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest_for(self.payload, binary="claude-wrapper"),
                version="2.1.211",
                platform_key="darwin-arm64",
            )

    def test_rejects_invalid_checksum(self) -> None:
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "SHA-256",
        ):
            claude_provenance.parse_signed_manifest_artifact(
                manifest_for(self.payload, checksum="A" * 64),
                version="2.1.211",
                platform_key="darwin-arm64",
            )

    def test_rejects_boolean_zero_and_oversized_artifact_sizes(self) -> None:
        for size in (True, 0, claude_provenance.CLAUDE_BINARY_MAX_BYTES + 1):
            with self.subTest(size=size):
                with self.assertRaisesRegex(
                    claude_provenance.ClaudeProvenanceInvalid,
                    "invalid size",
                ):
                    claude_provenance.parse_signed_manifest_artifact(
                        manifest_for(self.payload, size=size),
                        version="2.1.211",
                        platform_key="darwin-arm64",
                    )


class GpgVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gpg_runtime_patcher = mock.patch.object(
            claude_provenance,
            "_prepare_trusted_gpg_runtime",
            return_value=claude_provenance._TrustedGpgRuntime(),
        )
        self.gpg_runtime_patcher.start()
        self.temporary = tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        )
        self.root = pathlib.Path(self.temporary.name)
        self.bundle = claude_provenance.SignedClaudeManifest(
            version="2.1.211",
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            manifest=b"{}",
            signature=b"signature",
        )
        self.gpg_payload = b"\x7fELF" + b"trusted native GPG fixture"
        self.gpg_path = self.root / "gpg"
        self.gpg_path.write_bytes(self.gpg_payload)
        self.gpg_path.chmod(0o700)

    def tearDown(self) -> None:
        self.gpg_runtime_patcher.stop()
        self.temporary.cleanup()

    def fake_gpg(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        timeout_seconds: float,
        signer: str | None = None,
        primary: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del timeout_seconds
        home = pathlib.Path(env["GNUPGHOME"])
        self.assertTrue(home.is_dir())
        self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
        self.assertEqual(env["HOME"], str(home))
        if "--dearmor" in argv:
            output = pathlib.Path(argv[argv.index("--output") + 1])
            output.write_bytes(b"keyring")
            return completed(argv)
        if "--with-colons" in argv:
            fingerprint = claude_provenance.CLAUDE_RELEASE_KEY_FINGERPRINT
            return completed(argv, stdout=f"fpr:::::::::{fingerprint}:\n".encode())
        if "--verify" in argv:
            signature_fingerprint = signer or (
                claude_provenance.CLAUDE_RELEASE_KEY_FINGERPRINT
            )
            fields = [
                signature_fingerprint,
                "2026-07-01",
                "0",
                "4",
                "0",
                "1",
                "10",
                "00",
                "0",
                primary or signature_fingerprint,
            ]
            status_line = "[GNUPG:] VALIDSIG " + " ".join(fields) + "\n"
            return completed(argv, stdout=status_line.encode())
        raise AssertionError(f"unexpected GPG command: {argv}")

    def test_verifies_expected_primary_fingerprint_in_isolated_home(self) -> None:
        homes: list[pathlib.Path] = []
        execution_paths: list[pathlib.Path] = []

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            home = pathlib.Path(env["GNUPGHOME"])
            homes.append(home)
            execution_path = pathlib.Path(argv[0])
            execution_paths.append(execution_path)
            metadata = execution_path.stat(follow_symlinks=False)
            self.assertEqual(execution_path.parent, home)
            self.assertNotEqual(execution_path, self.gpg_path.resolve())
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o500)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(execution_path.read_bytes(), self.gpg_payload)
            return self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
            )

        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            side_effect=runner,
        ):
            selected = claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        self.assertEqual(selected, self.gpg_path.resolve())
        self.assertTrue(homes)
        self.assertEqual(len(execution_paths), 3)
        self.assertEqual(len(set(execution_paths)), 1)
        self.assertTrue(all(not home.exists() for home in homes))

    def test_revalidates_dynamic_dependencies_before_every_gpg_call(self) -> None:
        with (
            mock.patch.object(
                claude_provenance,
                "_revalidate_trusted_gpg_runtime",
            ) as revalidate,
            mock.patch.object(
                claude_provenance,
                "_run_gpg",
                side_effect=self.fake_gpg,
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        self.assertEqual(revalidate.call_count, 3)

    def test_changed_dynamic_dependency_blocks_gpg_before_execution(self) -> None:
        dependency = self.root / "libgcrypt.dylib"
        dependency.write_bytes(b"trusted")
        dependency.chmod(0o400)
        runtime = claude_provenance._TrustedGpgRuntime(
            darwin_dependencies=(
                claude_provenance._TrustedGpgDependency(
                    dependency,
                    (
                        (
                            dependency,
                            claude_provenance._stat_identity(dependency.lstat()),
                        ),
                    ),
                ),
            )
        )

        def prepare(_executable):  # type: ignore[no-untyped-def]
            replacement = self.root / "replacement.dylib"
            replacement.write_bytes(b"evil-lib")
            replacement.chmod(0o400)
            os.replace(replacement, dependency)
            return runtime

        with (
            mock.patch.object(
                claude_provenance,
                "_prepare_trusted_gpg_runtime",
                side_effect=prepare,
            ),
            mock.patch.object(claude_provenance, "_run_gpg") as runner,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "dynamic dependency changed",
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        runner.assert_not_called()

    def test_darwin_dependency_inspection_rejects_mutable_external_path(
        self,
    ) -> None:
        executable = pathlib.Path("/private/tmp/gpg-verifier")

        def otool(path, option):  # type: ignore[no-untyped-def]
            if option == "-l":
                return (
                    f"{path}:\n"
                    "Load command 0\n"
                    "          cmd LC_LOAD_DYLINKER\n"
                    "      cmdsize 32\n"
                    "         name /usr/lib/dyld (offset 12)\n"
                )
            return (
                f"{path}:\n"
                "\t/tmp/libgcrypt.20.dylib "
                "(compatibility version 1.0.0, current version 1.0.0)\n"
            )

        with (
            mock.patch.object(
                claude_provenance,
                "_run_otool",
                side_effect=otool,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "outside sealed or Homebrew roots",
            ),
        ):
            claude_provenance._collect_darwin_gpg_dependencies(executable)

    def test_darwin_load_commands_require_one_standard_main_dyld(self) -> None:
        executable = pathlib.Path("/private/tmp/gpg-verifier")
        for label, load_commands in (
            (
                "missing",
                f"{executable}:\n"
                "Load command 0\n"
                "      cmd LC_SEGMENT_64\n"
                "  cmdsize 72\n",
            ),
            (
                "custom",
                f"{executable}:\n"
                "Load command 0\n"
                "          cmd LC_LOAD_DYLINKER\n"
                "      cmdsize 40\n"
                "         name /opt/homebrew/lib/dyld (offset 12)\n",
            ),
            (
                "duplicate",
                f"{executable}:\n"
                "Load command 0\n"
                "          cmd LC_LOAD_DYLINKER\n"
                "      cmdsize 32\n"
                "         name /usr/lib/dyld (offset 12)\n"
                "Load command 1\n"
                "          cmd LC_LOAD_DYLINKER\n"
                "      cmdsize 32\n"
                "         name /usr/lib/dyld (offset 12)\n",
            ),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    claude_provenance.ClaudeProvenanceInvalid,
                    "exactly one sealed /usr/lib/dyld",
                ),
            ):
                claude_provenance._validate_darwin_gpg_load_commands(
                    executable,
                    load_commands,
                    main_executable=True,
                )

    def test_darwin_dependency_cannot_declare_a_dynamic_linker(self) -> None:
        dependency = pathlib.Path("/opt/homebrew/opt/libgcrypt/lib/libgcrypt.20.dylib")
        load_commands = (
            f"{dependency}:\n"
            "Load command 0\n"
            "          cmd LC_LOAD_DYLINKER\n"
            "      cmdsize 32\n"
            "         name /usr/lib/dyld (offset 12)\n"
        )

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "dependency unexpectedly declares LC_LOAD_DYLINKER",
        ):
            claude_provenance._validate_darwin_gpg_load_commands(
                dependency,
                load_commands,
                main_executable=False,
            )

    def test_darwin_dependency_inspection_rejects_rpath(self) -> None:
        executable = pathlib.Path("/private/tmp/gpg-verifier")

        def otool(path, option):  # type: ignore[no-untyped-def]
            if option == "-l":
                return f"{path}:\nLoad command 1\n      cmd LC_RPATH\n"
            self.fail("-L must not run after an unsafe LC_RPATH")

        with (
            mock.patch.object(
                claude_provenance,
                "_run_otool",
                side_effect=otool,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "mutable dyld search path",
            ),
        ):
            claude_provenance._collect_darwin_gpg_dependencies(executable)

    def test_darwin_dependency_symlink_loop_is_inconclusive(self) -> None:
        dependency = pathlib.Path("/opt/homebrew/opt/libgcrypt/lib/libgcrypt.20.dylib")

        with (
            mock.patch.object(
                pathlib.Path,
                "resolve",
                autospec=True,
                side_effect=RuntimeError("symlink loop fixture"),
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "cannot resolve GPG dynamic dependency",
            ),
        ):
            claude_provenance._capture_gpg_dependency_chain(dependency)

    def test_otool_start_io_failure_is_inconclusive(self) -> None:
        trusted_otool = mock.Mock()
        trusted_otool.stat.return_value = mock.Mock(
            st_mode=stat.S_IFREG | 0o755,
            st_uid=0,
        )

        with (
            mock.patch.object(
                claude_provenance,
                "TRUSTED_OTOOL",
                trusted_otool,
            ),
            mock.patch.object(
                claude_provenance.os,
                "access",
                return_value=True,
            ),
            mock.patch.object(
                claude_provenance,
                "run_bounded_capture",
                side_effect=OSError("exec fixture"),
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "cannot start bounded macOS",
            ),
        ):
            claude_provenance._run_otool(
                pathlib.Path("/private/tmp/gpg-verifier"),
                "-L",
            )

    def test_otool_unsafe_metadata_is_invalid_not_unavailable(self) -> None:
        trusted_otool = mock.Mock()
        trusted_otool.stat.return_value = mock.Mock(
            st_mode=stat.S_IFREG | 0o775,
            st_uid=0,
        )

        with (
            mock.patch.object(
                claude_provenance,
                "TRUSTED_OTOOL",
                trusted_otool,
            ),
            mock.patch.object(
                claude_provenance.os,
                "access",
                return_value=True,
            ),
            self.assertRaises(claude_provenance.ClaudeProvenanceInvalid) as caught,
        ):
            claude_provenance._run_otool(
                pathlib.Path("/private/tmp/gpg-verifier"),
                "-L",
            )

        self.assertNotIsInstance(
            caught.exception,
            claude_provenance.ClaudeProvenanceUnavailable,
        )

    def test_otool_inspection_failure_is_inconclusive(self) -> None:
        trusted_otool = mock.Mock()
        trusted_otool.stat.return_value = mock.Mock(
            st_mode=stat.S_IFREG | 0o755,
            st_uid=0,
        )

        with (
            mock.patch.object(
                claude_provenance,
                "TRUSTED_OTOOL",
                trusted_otool,
            ),
            mock.patch.object(
                claude_provenance.os,
                "access",
                return_value=True,
            ),
            mock.patch.object(
                claude_provenance,
                "run_bounded_capture",
                return_value=completed(
                    ["/usr/bin/otool", "-L"],
                    returncode=1,
                    stderr=b"inspection fixture",
                ),
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "could not inspect",
            ),
        ):
            claude_provenance._run_otool(
                pathlib.Path("/private/tmp/gpg-verifier"),
                "-L",
            )

    def test_darwin_dependency_rejects_group_writable_library_file(self) -> None:
        dependency = self.root / "libgcrypt.dylib"
        dependency.write_bytes(b"fixture")
        dependency.chmod(0o460)
        gid = dependency.stat().st_gid

        with (
            mock.patch.object(
                claude_provenance,
                "_darwin_homebrew_dependency_path",
                return_value=True,
            ),
            mock.patch.object(
                claude_provenance,
                "_darwin_homebrew_path",
                return_value=True,
            ),
            mock.patch.object(
                claude_provenance,
                "_darwin_admin_gid",
                return_value=gid,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "untrusted writable path",
            ),
        ):
            claude_provenance._capture_gpg_dependency_chain(dependency)

    def test_ambient_tmpdir_cannot_redirect_gpg_snapshot_execution(self) -> None:
        ambient = self.root / "ambient-tmp"
        ambient.mkdir(mode=0o700)
        ambient.chmod(0o777)
        homes: list[pathlib.Path] = []

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            homes.append(pathlib.Path(env["GNUPGHOME"]))
            return self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
            )

        with (
            mock.patch.dict(os.environ, {"TMPDIR": str(ambient)}),
            mock.patch.object(tempfile, "tempdir", str(ambient)),
            mock.patch.object(
                claude_provenance,
                "_run_gpg",
                side_effect=runner,
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        trusted_root = self.root.resolve(strict=True)
        self.assertEqual(len(homes), 3)
        self.assertTrue(all(home.parent == trusted_root for home in homes))
        self.assertTrue(all(ambient not in home.parents for home in homes))

    def test_rejects_private_temp_root_beneath_unsafe_parent(self) -> None:
        unsafe_parent = self.root / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o700)
        unsafe_parent.chmod(0o770)
        candidate = unsafe_parent / "private-temp"
        candidate.mkdir(mode=0o700)

        with (
            mock.patch.object(claude_provenance, "_run_gpg") as runner,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "unsafe parent chain",
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=candidate,
                gpg_candidates=(self.gpg_path,),
            )

        runner.assert_not_called()

    def test_rejects_private_temp_root_beneath_symlinked_parent(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        candidate = real_parent / "private-temp"
        candidate.mkdir(mode=0o700)
        alias = self.root / "parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)

        with (
            mock.patch.object(claude_provenance, "_run_gpg") as runner,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "real directory",
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=alias / "private-temp",
                gpg_candidates=(self.gpg_path,),
            )

        runner.assert_not_called()

    def test_validates_every_temp_root_anchor_before_gpg_execution(self) -> None:
        validated: list[pathlib.Path] = []

        def validator(paths: tuple[pathlib.Path, ...]) -> None:
            validated.extend(paths)

        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            side_effect=self.fake_gpg,
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                temp_root_validator=validator,
                gpg_candidates=(self.gpg_path,),
            )

        self.assertIn(self.root.resolve(strict=True), validated)
        self.assertIn(self.root.parent.resolve(strict=True), validated)
        self.assertIn(pathlib.Path("/"), validated)

    def test_revalidates_temp_root_filesystem_before_each_gpg_call(self) -> None:
        unsafe = False
        gpg_calls = 0

        def validator(_paths: tuple[pathlib.Path, ...]) -> None:
            if unsafe:
                raise claude_provenance.ClaudeProvenanceInvalid(
                    "temporary filesystem changed"
                )

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            nonlocal gpg_calls, unsafe
            result = self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
            )
            gpg_calls += 1
            unsafe = True
            return result

        with (
            mock.patch.object(
                claude_provenance,
                "_run_gpg",
                side_effect=runner,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "filesystem changed",
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                temp_root_validator=validator,
                gpg_candidates=(self.gpg_path,),
            )

        self.assertEqual(gpg_calls, 1)

    def test_rejects_temp_root_identity_change_before_next_gpg_call(self) -> None:
        gpg_calls = 0

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            nonlocal gpg_calls
            result = self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
            )
            gpg_calls += 1
            self.root.chmod(0o750)
            return result

        try:
            with (
                mock.patch.object(
                    claude_provenance,
                    "_run_gpg",
                    side_effect=runner,
                ),
                self.assertRaisesRegex(
                    claude_provenance.ClaudeProvenanceInconclusive,
                    "root or parent changed",
                ),
            ):
                claude_provenance.verify_manifest_signature(
                    self.bundle,
                    temp_root=self.root,
                    gpg_candidates=(self.gpg_path,),
                )
        finally:
            self.root.chmod(0o700)

        self.assertEqual(gpg_calls, 1)

    def test_source_path_replacement_after_resolve_cannot_change_execution(
        self,
    ) -> None:
        original_resolver = claude_provenance._resolve_trusted_gpg_source
        replacement_payload = b"\x7fELF" + b"replacement GPG payload"
        executed_payloads: list[bytes] = []
        execution_paths: list[pathlib.Path] = []

        def resolve_then_replace(candidates):  # type: ignore[no-untyped-def]
            source = original_resolver(candidates)
            displaced = self.root / "gpg-before-replacement"
            os.replace(self.gpg_path, displaced)
            self.gpg_path.write_bytes(replacement_payload)
            self.gpg_path.chmod(0o700)
            return source

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            execution_path = pathlib.Path(argv[0])
            execution_paths.append(execution_path)
            executed_payloads.append(execution_path.read_bytes())
            return self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
            )

        with (
            mock.patch.object(
                claude_provenance,
                "_resolve_trusted_gpg_source",
                side_effect=resolve_then_replace,
            ),
            mock.patch.object(
                claude_provenance,
                "_run_gpg",
                side_effect=runner,
            ),
        ):
            selected = claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        self.assertEqual(selected, self.gpg_path.resolve())
        self.assertEqual(len(execution_paths), 3)
        self.assertEqual(len(set(execution_paths)), 1)
        self.assertTrue(all(path != selected for path in execution_paths))
        self.assertEqual(executed_payloads, [self.gpg_payload] * 3)
        self.assertEqual(self.gpg_path.read_bytes(), replacement_payload)

    def test_in_place_source_mutation_after_resolve_fails_closed(self) -> None:
        original_resolver = claude_provenance._resolve_trusted_gpg_source

        def resolve_then_mutate(candidates):  # type: ignore[no-untyped-def]
            source = original_resolver(candidates)
            self.gpg_path.write_bytes(b"\x7fELF" + b"mutated native fixture")
            self.gpg_path.chmod(0o700)
            return source

        with (
            mock.patch.object(
                claude_provenance,
                "_resolve_trusted_gpg_source",
                side_effect=resolve_then_mutate,
            ),
            mock.patch.object(claude_provenance, "_run_gpg") as runner,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed before snapshotting",
            ),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        runner.assert_not_called()

    def test_signature_verification_rejects_unsafe_source_before_execution(
        self,
    ) -> None:
        self.gpg_path.chmod(0o720)
        with (
            mock.patch.object(claude_provenance, "_run_gpg") as runner,
            self.assertRaises(claude_provenance.ClaudeProvenanceInvalid),
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

        runner.assert_not_called()

    def test_accepts_signing_subkey_when_validsig_names_pinned_primary(self) -> None:
        subkey = "A" * 40

        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            return self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
                signer=subkey,
                primary=claude_provenance.CLAUDE_RELEASE_KEY_FINGERPRINT,
            )

        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            side_effect=runner,
        ):
            claude_provenance.verify_manifest_signature(
                self.bundle,
                temp_root=self.root,
                gpg_candidates=(self.gpg_path,),
            )

    def test_rejects_valid_signature_from_wrong_fingerprint(self) -> None:
        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            return self.fake_gpg(
                argv,
                env=env,
                timeout_seconds=timeout_seconds,
                signer="B" * 40,
                primary="B" * 40,
            )

        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            side_effect=runner,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "pinned key",
            ):
                claude_provenance.verify_manifest_signature(
                    self.bundle,
                    temp_root=self.root,
                    gpg_candidates=(self.gpg_path,),
                )

    def test_rejects_vendored_key_with_wrong_fingerprint(self) -> None:
        def runner(argv, *, env, timeout_seconds):  # type: ignore[no-untyped-def]
            if "--dearmor" in argv:
                output = pathlib.Path(argv[argv.index("--output") + 1])
                output.write_bytes(b"keyring")
                return completed(argv)
            if "--with-colons" in argv:
                return completed(argv, stdout=b"fpr:::::::::AAAAAAAA:\n")
            raise AssertionError(f"unexpected GPG command: {argv}")

        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            side_effect=runner,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "fingerprint does not match",
            ):
                claude_provenance.verify_manifest_signature(
                    self.bundle,
                    temp_root=self.root,
                    gpg_candidates=(self.gpg_path,),
                )

    def test_classifies_key_decode_failure_as_invalid(self) -> None:
        with mock.patch.object(
            claude_provenance,
            "_run_gpg",
            return_value=completed([], returncode=2),
        ):
            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                claude_provenance.verify_manifest_signature(
                    self.bundle,
                    temp_root=self.root,
                    gpg_candidates=(self.gpg_path,),
                )

    def test_run_gpg_classifies_timeout_as_inconclusive(self) -> None:
        with mock.patch.object(
            claude_provenance,
            "run_bounded_capture",
            side_effect=claude_provenance.ReviewTimeoutError("timeout"),
        ):
            with self.assertRaises(claude_provenance.ClaudeProvenanceInconclusive):
                claude_provenance._run_gpg(
                    ["gpg"],
                    env={},
                    timeout_seconds=1,
                )

    def test_run_gpg_classifies_output_overflow_as_inconclusive(self) -> None:
        with mock.patch.object(
            claude_provenance,
            "run_bounded_capture",
            side_effect=claude_provenance.ReviewOutputLimitError("overflow"),
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "bounded",
            ):
                claude_provenance._run_gpg(
                    ["/trusted/gpg", "--version"],
                    env={"LANG": "C"},
                    timeout_seconds=1,
                )

    def test_run_gpg_start_io_is_not_dependency_unavailable(self) -> None:
        with (
            mock.patch.object(
                claude_provenance,
                "run_bounded_capture",
                side_effect=OSError(errno.EIO, "injected GPG launch failure"),
            ),
            self.assertRaises(claude_provenance.ClaudeProvenanceUnavailable) as caught,
        ):
            claude_provenance._run_gpg(
                ["/trusted/gpg", "--version"],
                env={"LANG": "C"},
                timeout_seconds=1,
            )

        self.assertNotIsInstance(
            caught.exception,
            claude_provenance.ClaudeProvenanceDependencyUnavailable,
        )

    def test_gpg_snapshot_write_io_is_not_dependency_unavailable(self) -> None:
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
            source.write(b"\x7fELF" + b"trusted GPG fixture")
            source.flush()
            with (
                mock.patch.object(
                    claude_provenance.os,
                    "write",
                    side_effect=OSError(
                        errno.ENOSPC,
                        "injected GPG snapshot write failure",
                    ),
                ),
                self.assertRaises(
                    claude_provenance.ClaudeProvenanceUnavailable
                ) as caught,
            ):
                claude_provenance._copy_gpg_snapshot(
                    source.fileno(),
                    target.fileno(),
                    max_bytes=1024,
                )

        self.assertNotIsInstance(
            caught.exception,
            claude_provenance.ClaudeProvenanceDependencyUnavailable,
        )

    def test_run_gpg_applies_independent_stream_limits(self) -> None:
        capture = mock.Mock(returncode=0, stdout=bytearray(b"out"), stderr=bytearray())
        with mock.patch.object(
            claude_provenance,
            "run_bounded_capture",
            return_value=capture,
        ) as runner:
            result = claude_provenance._run_gpg(
                ["/trusted/gpg", "--version"],
                env={"LANG": "C"},
                timeout_seconds=2,
            )

        self.assertEqual(result.stdout, b"out")
        runner.assert_called_once_with(
            ("/trusted/gpg", "--version"),
            env={"LANG": "C"},
            timeout_seconds=2,
            stdout_limit_bytes=claude_provenance.CLAUDE_GPG_OUTPUT_MAX_BYTES,
            stderr_limit_bytes=claude_provenance.CLAUDE_GPG_OUTPUT_MAX_BYTES,
        )

    def test_resolve_trusted_gpg_requires_native_absolute_candidate(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            root = pathlib.Path(raw)
            wrapper = root / "gpg-wrapper"
            wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            wrapper.chmod(0o700)
            native = root / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)

            self.assertEqual(
                claude_provenance.resolve_trusted_gpg(
                    (pathlib.Path("relative-gpg"), wrapper, native)
                ),
                native.resolve(),
            )

    def test_missing_trusted_gpg_candidate_is_dependency_unavailable(self) -> None:
        with self.assertRaises(claude_provenance.ClaudeProvenanceDependencyUnavailable):
            claude_provenance.resolve_trusted_gpg(
                (pathlib.Path("/definitely/missing/codex-review-gpg"),)
            )

    def test_wrapper_only_gpg_candidate_is_invalid_not_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            wrapper = pathlib.Path(raw) / "gpg-wrapper"
            wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            wrapper.chmod(0o700)

            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid) as caught:
                claude_provenance.resolve_trusted_gpg((wrapper,))

        self.assertNotIsInstance(
            caught.exception,
            claude_provenance.ClaudeProvenanceUnavailable,
        )

    def test_trusted_gpg_candidate_stat_io_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            native = pathlib.Path(raw) / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            resolved = native.resolve()
            original_stat = pathlib.Path.stat

            def fail_candidate_stat(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if path == resolved:
                    raise OSError(errno.EIO, "injected candidate stat failure")
                return original_stat(path, *args, **kwargs)  # type: ignore[arg-type]

            with (
                mock.patch.object(
                    pathlib.Path,
                    "stat",
                    autospec=True,
                    side_effect=fail_candidate_stat,
                ),
                self.assertRaisesRegex(
                    claude_provenance.ClaudeProvenanceInconclusive,
                    "candidate stat failure",
                ),
            ):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_trusted_gpg_candidate_open_race_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            native = pathlib.Path(raw) / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)

            with (
                mock.patch.object(
                    claude_provenance.os,
                    "open",
                    side_effect=FileNotFoundError(
                        errno.ENOENT,
                        "injected candidate open race",
                    ),
                ),
                self.assertRaisesRegex(
                    claude_provenance.ClaudeProvenanceInconclusive,
                    "candidate open race",
                ),
            ):
                claude_provenance.resolve_trusted_gpg((native,))

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_trusted_gpg_fifo_replacement_after_stat_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            native = pathlib.Path(raw) / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            resolved = native.resolve(strict=True)
            replacement = native.with_name("gpg.fifo")
            os.mkfifo(replacement, mode=0o700)
            real_open = os.open
            requested_flags: list[int] = []
            failures: list[BaseException] = []
            values: list[pathlib.Path] = []
            swapped = False

            def swap_before_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal swapped
                if pathlib.Path(path) == resolved and not swapped:
                    swapped = True
                    requested_flags.append(flags)
                    os.replace(replacement, native)
                return real_open(path, flags, *args, **kwargs)

            def resolve() -> None:
                try:
                    values.append(claude_provenance.resolve_trusted_gpg((native,)))
                except BaseException as error:
                    failures.append(error)

            worker = threading.Thread(target=resolve, daemon=True)
            with (
                mock.patch.object(
                    claude_provenance.os,
                    "open",
                    side_effect=swap_before_open,
                ),
                mock.patch.object(
                    claude_provenance.os,
                    "read",
                    side_effect=AssertionError(
                        "replaced GPG descriptor must be rejected before read"
                    ),
                ) as reader,
            ):
                worker.start()
                worker.join(timeout=1.0)
                if worker.is_alive():
                    rescue = real_open(native, os.O_RDWR | os.O_NONBLOCK)
                    os.close(rescue)
                    worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive(), "trusted GPG FIFO open blocked")
            self.assertTrue(swapped)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)
            self.assertFalse(values)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(
                failures[0],
                claude_provenance.ClaudeProvenanceInconclusive,
            )
            reader.assert_not_called()

    def test_default_linux_gpg_candidates_are_root_owned_usr_bin_only(self) -> None:
        with (
            mock.patch.object(claude_provenance.sys, "platform", "linux"),
            mock.patch.object(
                claude_provenance,
                "_resolve_trusted_gpg_source",
                side_effect=claude_provenance.ClaudeProvenanceUnavailable("fixture"),
            ) as resolver,
            self.assertRaises(claude_provenance.ClaudeProvenanceUnavailable),
        ):
            claude_provenance.resolve_trusted_gpg()

        resolver.assert_called_once_with(
            (
                pathlib.Path("/usr/bin/gpg"),
                pathlib.Path("/usr/bin/gpg2"),
            ),
            require_root_owner=True,
        )

    def test_resolve_trusted_gpg_rejects_writable_verifier_file(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            native = pathlib.Path(raw) / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o720)

            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_resolve_trusted_gpg_rejects_world_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            root = pathlib.Path(raw)
            native = root / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            root.chmod(0o707)

            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_resolve_trusted_gpg_rejects_generic_group_writable_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            root = pathlib.Path(raw)
            native = root / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            root.chmod(0o770)

            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_resolve_trusted_gpg_allows_only_homebrew_admin_group_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            root = pathlib.Path(raw)
            native = root / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            root.chmod(0o770)
            gid = root.stat().st_gid

            with (
                mock.patch.object(
                    claude_provenance,
                    "_darwin_homebrew_path",
                    return_value=True,
                ),
                mock.patch.object(
                    claude_provenance,
                    "_darwin_admin_gid",
                    return_value=gid,
                ),
            ):
                self.assertEqual(
                    claude_provenance.resolve_trusted_gpg((native,)),
                    native.resolve(),
                )

            with (
                mock.patch.object(
                    claude_provenance,
                    "_darwin_homebrew_path",
                    return_value=True,
                ),
                mock.patch.object(
                    claude_provenance,
                    "_darwin_admin_gid",
                    return_value=gid + 1,
                ),
                self.assertRaises(claude_provenance.ClaudeProvenanceInvalid),
            ):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_resolve_trusted_gpg_rejects_foreign_non_root_owner(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parent
        ) as raw:
            native = pathlib.Path(raw) / "gpg"
            native.write_bytes(b"\x7fELF" + b"\x00" * 16)
            native.chmod(0o700)
            resolved = native.resolve()
            original_stat = pathlib.Path.stat

            def stat_with_foreign_owner(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                metadata = original_stat(path, *args, **kwargs)  # type: ignore[arg-type]
                if path != resolved:
                    return metadata
                fields = list(metadata)
                fields[4] = 4242
                return os.stat_result(fields)

            with (
                mock.patch.object(
                    claude_provenance.os,
                    "geteuid",
                    return_value=4243,
                ),
                mock.patch.object(
                    pathlib.Path,
                    "stat",
                    autospec=True,
                    side_effect=stat_with_foreign_owner,
                ),
                self.assertRaises(claude_provenance.ClaudeProvenanceInvalid),
            ):
                claude_provenance.resolve_trusted_gpg((native,))

    def test_vendored_release_key_bytes_are_stable(self) -> None:
        self.assertEqual(
            hashlib.sha256(
                claude_provenance.CLAUDE_RELEASE_KEY_PATH.read_bytes()
            ).hexdigest(),
            "bd70a5e4a268002704024ceba7f8446024114e94f3f0bdd11c23a9e592be81c6",
        )


class ExecutableVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.payload = b"\x7fELF" + b"trusted Claude executable fixture"
        self.executable = self.root / "claude-real"
        self.executable.write_bytes(self.payload)
        self.executable.chmod(0o700)
        self.artifact = artifact_for(self.payload)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _verify_full_release(
        self,
    ) -> claude_provenance.VerifiedClaudeExecutable:
        manifest = manifest_for(self.payload)

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            return manifest if url.endswith("manifest.json") else b"signature"

        with mock.patch.object(
            claude_provenance,
            "verify_manifest_signature",
            return_value=pathlib.Path("/trusted/gpg"),
        ):
            return claude_provenance.verify_claude_release(
                self.executable,
                version="2.1.211",
                platform_key="darwin-arm64",
                gpg_temp_root=self.root,
                fetcher=fetcher,
            )

    def test_accepts_stable_digest_and_returns_resolved_executable(self) -> None:
        link = self.root / "claude"
        link.symlink_to(self.executable)

        verified = claude_provenance.verify_release_executable(
            link,
            self.artifact,
        )

        self.assertEqual(verified, self.executable.resolve())

    def test_missing_executable_is_inconclusive(self) -> None:
        missing = self.root / "missing-claude"

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInconclusive,
            "cannot resolve",
        ):
            claude_provenance.verify_release_executable(missing, self.artifact)

    def test_executable_symlink_loop_is_inconclusive(self) -> None:
        with (
            mock.patch.object(
                pathlib.Path,
                "resolve",
                autospec=True,
                side_effect=RuntimeError("fixture symlink loop"),
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "cannot resolve",
            ),
        ):
            claude_provenance.verify_release_executable(
                self.executable,
                self.artifact,
            )

    def test_executable_stat_io_failure_is_inconclusive(self) -> None:
        original_stat = pathlib.Path.stat
        resolved_target = self.executable.resolve()

        def fail_target_stat(
            path: pathlib.Path,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            if path == resolved_target and kwargs.get("follow_symlinks") is False:
                raise OSError("fixture stat I/O failure")
            return original_stat(path, *args, **kwargs)  # type: ignore[arg-type]

        with (
            mock.patch.object(
                pathlib.Path,
                "stat",
                autospec=True,
                side_effect=fail_target_stat,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "cannot stat",
            ),
        ):
            claude_provenance.verify_release_executable(
                self.executable,
                self.artifact,
            )

    def test_rejects_stable_size_mismatch_without_hashing(self) -> None:
        wrong = claude_provenance.ClaudeReleaseArtifact(
            **{**self.artifact.__dict__, "size": self.artifact.size + 1}
        )
        with (
            mock.patch.object(
                claude_provenance,
                "_sha256_file_descriptor",
                side_effect=AssertionError("stable size mismatch must not be hashed"),
            ) as hasher,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "size does not match",
            ),
        ):
            claude_provenance.verify_release_executable(self.executable, wrong)
        hasher.assert_not_called()

    def test_size_mismatch_race_is_inconclusive(self) -> None:
        wrong = claude_provenance.ClaudeReleaseArtifact(
            **{**self.artifact.__dict__, "size": self.artifact.size + 1}
        )
        original_open = os.open
        resolved_target = self.executable.resolve(strict=True)
        raced = False

        def grow_before_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal raced
            if pathlib.Path(path) == resolved_target and not raced:
                raced = True
                with self.executable.open("ab") as handle:
                    handle.write(b"X")
            return original_open(path, flags, *args, **kwargs)

        with (
            mock.patch.object(
                claude_provenance.os,
                "open",
                side_effect=grow_before_open,
            ),
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed while",
            ),
        ):
            claude_provenance.verify_release_executable(self.executable, wrong)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_fifo_replacement_after_stat_is_inconclusive_without_blocking(
        self,
    ) -> None:
        real_open = os.open
        resolved_target = self.executable.resolve(strict=True)
        replacement = self.executable.with_name("claude-real.fifo")
        os.mkfifo(replacement, mode=0o700)
        requested_flags: list[int] = []
        failures: list[BaseException] = []
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal swapped
            if pathlib.Path(path) == resolved_target and not swapped:
                swapped = True
                requested_flags.append(flags)
                os.replace(replacement, self.executable)
            return real_open(path, flags, *args, **kwargs)

        def verify() -> None:
            try:
                claude_provenance.verify_release_executable(
                    self.executable,
                    self.artifact,
                )
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=verify, daemon=True)
        with mock.patch.object(
            claude_provenance.os,
            "open",
            side_effect=swap_before_open,
        ):
            worker.start()
            worker.join(timeout=1.0)
            if worker.is_alive():
                rescue = real_open(self.executable, os.O_RDWR | os.O_NONBLOCK)
                os.close(rescue)
                worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive(), "executable FIFO open blocked verification")
        self.assertTrue(swapped)
        self.assertTrue(requested_flags[0] & os.O_NONBLOCK)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0],
            claude_provenance.ClaudeProvenanceInconclusive,
        )

    def test_rejects_digest_mismatch(self) -> None:
        wrong = claude_provenance.ClaudeReleaseArtifact(
            **{**self.artifact.__dict__, "checksum": "0" * 64}
        )
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "SHA-256",
        ):
            claude_provenance.verify_release_executable(self.executable, wrong)

    def test_rejects_non_executable_file(self) -> None:
        self.executable.chmod(0o600)
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "not executable",
        ):
            claude_provenance.verify_release_executable(
                self.executable,
                self.artifact,
            )

    def test_classifies_stat_change_during_hash_as_inconclusive(self) -> None:
        original_hash = claude_provenance._sha256_file_descriptor

        def hash_then_mutate(handle):  # type: ignore[no-untyped-def]
            result = original_hash(handle)
            self.executable.chmod(0o750)
            return result

        with mock.patch.object(
            claude_provenance,
            "_sha256_file_descriptor",
            side_effect=hash_then_mutate,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed while",
            ):
                claude_provenance.verify_release_executable(
                    self.executable,
                    self.artifact,
                )

    def test_full_verifier_returns_authenticated_release_metadata(self) -> None:
        descriptor_identity: tuple[int, ...] | None = None
        original_hash = claude_provenance._sha256_file_descriptor

        def capture_descriptor_identity(handle):  # type: ignore[no-untyped-def]
            nonlocal descriptor_identity
            descriptor_identity = claude_provenance._stat_identity(
                os.fstat(handle.fileno())
            )
            return original_hash(handle)

        with mock.patch.object(
            claude_provenance,
            "_sha256_file_descriptor",
            side_effect=capture_descriptor_identity,
        ):
            result = self._verify_full_release()

        self.assertEqual(result.executable, self.executable.resolve())
        self.assertEqual(result.artifact.checksum, self.artifact.checksum)
        self.assertEqual(result.gpg_path, pathlib.Path("/trusted/gpg"))
        self.assertEqual(result.source_identity, descriptor_identity)
        self.assertIsNotNone(result.source_identity)
        assert result.source_identity is not None
        self.assertEqual(
            result.source_identity[-1],
            self.executable.stat(follow_symlinks=False).st_ctime_ns,
        )
        self.assertEqual(
            result.manifest_url,
            "https://downloads.claude.ai/claude-code-releases/2.1.211/manifest.json",
        )

    def test_materialization_rejects_replaced_verified_source_before_reuse(
        self,
    ) -> None:
        verified = self._verify_full_release()
        snapshot_root = self.root / "snapshots"
        claude_provenance.materialize_verified_executable(
            verified,
            snapshot_root,
        )
        replacement = self.root / "replacement"
        replacement.write_bytes(self.payload)
        replacement.chmod(0o700)
        os.replace(replacement, self.executable)

        with (
            mock.patch.object(
                claude_provenance,
                "_verify_snapshot_entry",
                side_effect=AssertionError(
                    "changed verified source must be rejected before snapshot reuse"
                ),
            ) as snapshot_verifier,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed after provenance verification",
            ),
        ):
            claude_provenance.materialize_verified_executable(
                verified,
                snapshot_root,
            )

        snapshot_verifier.assert_not_called()

    def test_materialization_rejects_ctime_only_source_mutation_before_copy(
        self,
    ) -> None:
        verified = self._verify_full_release()
        self.assertIsNotNone(verified.source_identity)
        assert verified.source_identity is not None
        original_mode = stat.S_IMODE(
            self.executable.stat(follow_symlinks=False).st_mode
        )
        alternate_mode = original_mode ^ stat.S_IXUSR
        deadline = time.monotonic() + 2.0
        while True:
            self.executable.chmod(alternate_mode)
            self.executable.chmod(original_mode)
            mutated_identity = claude_provenance._stat_identity(
                self.executable.stat(follow_symlinks=False)
            )
            if mutated_identity[-1] != verified.source_identity[-1]:
                break
            if time.monotonic() >= deadline:
                self.fail("filesystem ctime did not advance after bounded mode changes")
            time.sleep(0.01)
        self.assertEqual(mutated_identity[:-1], verified.source_identity[:-1])

        with (
            mock.patch.object(
                claude_provenance,
                "_copy_and_hash_snapshot",
                side_effect=AssertionError(
                    "changed verified source must be rejected before copying"
                ),
            ) as copier,
            self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed after provenance verification",
            ),
        ):
            claude_provenance.materialize_verified_executable(
                verified,
                self.root / "snapshots",
            )

        copier.assert_not_called()

    def test_verified_manifest_cache_avoids_repeat_network_fetch(self) -> None:
        manifest = manifest_for(self.payload)
        cache_dir = self.root / "provenance-cache"
        fetch_calls: list[str] = []

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            fetch_calls.append(url)
            return manifest if url.endswith("manifest.json") else b"signature"

        with mock.patch.object(
            claude_provenance,
            "verify_manifest_signature",
            return_value=pathlib.Path("/trusted/gpg"),
        ) as signature_verifier:
            claude_provenance.verify_claude_release(
                self.executable,
                version="2.1.211",
                platform_key="darwin-arm64",
                gpg_temp_root=self.root,
                fetcher=fetcher,
                cache_dir=cache_dir,
            )
            claude_provenance.verify_claude_release(
                self.executable,
                version="2.1.211",
                platform_key="darwin-arm64",
                gpg_temp_root=self.root,
                fetcher=lambda *_args, **_kwargs: self.fail(
                    "cache hit must not use the network fetcher"
                ),
                cache_dir=cache_dir,
            )

        self.assertEqual(len(fetch_calls), 2)
        self.assertEqual(signature_verifier.call_count, 2)
        self.assertEqual(stat.S_IMODE(cache_dir.stat().st_mode), 0o700)
        version_dir = cache_dir / "2.1.211"
        self.assertEqual(stat.S_IMODE(version_dir.stat().st_mode), 0o700)
        for name in ("manifest.json", "manifest.json.sig", "ready.json"):
            self.assertEqual(
                stat.S_IMODE((version_dir / name).stat().st_mode),
                0o600,
            )

    def test_cache_is_written_only_after_signature_verification(self) -> None:
        manifest = manifest_for(self.payload)
        cache_dir = self.root / "provenance-cache"

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            return manifest if url.endswith("manifest.json") else b"bad-signature"

        with mock.patch.object(
            claude_provenance,
            "verify_manifest_signature",
            side_effect=claude_provenance.ClaudeProvenanceInvalid("bad signature"),
        ):
            with self.assertRaises(claude_provenance.ClaudeProvenanceInvalid):
                claude_provenance.verify_claude_release(
                    self.executable,
                    version="2.1.211",
                    platform_key="darwin-arm64",
                    gpg_temp_root=self.root,
                    fetcher=fetcher,
                    cache_dir=cache_dir,
                )

        self.assertFalse((cache_dir / "2.1.211" / "ready.json").exists())

    def test_cache_is_written_only_after_strict_manifest_parsing(self) -> None:
        cache_dir = self.root / "provenance-cache"
        malformed_manifest = b'{"version":"2.1.211","platforms":NaN}'

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            return malformed_manifest if url.endswith("manifest.json") else b"signature"

        with mock.patch.object(
            claude_provenance,
            "verify_manifest_signature",
            return_value=pathlib.Path("/trusted/gpg"),
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInvalid,
                "non-standard JSON constant",
            ):
                claude_provenance.verify_claude_release(
                    self.executable,
                    version="2.1.211",
                    platform_key="darwin-arm64",
                    gpg_temp_root=self.root,
                    fetcher=fetcher,
                    cache_dir=cache_dir,
                )

        self.assertFalse((cache_dir / "2.1.211" / "ready.json").exists())

    def test_rejects_corrupted_complete_cache_without_network_fallback(self) -> None:
        manifest = manifest_for(self.payload)
        cache_dir = self.root / "provenance-cache"

        def fetcher(
            url: str,
            *,
            max_bytes: int,
            timeout_seconds: float,
        ) -> bytes:
            del max_bytes, timeout_seconds
            return manifest if url.endswith("manifest.json") else b"signature"

        with mock.patch.object(
            claude_provenance,
            "verify_manifest_signature",
            return_value=pathlib.Path("/trusted/gpg"),
        ):
            claude_provenance.verify_claude_release(
                self.executable,
                version="2.1.211",
                platform_key="darwin-arm64",
                gpg_temp_root=self.root,
                fetcher=fetcher,
                cache_dir=cache_dir,
            )

        cached_manifest = cache_dir / "2.1.211" / "manifest.json"
        cached_manifest.write_bytes(b"tampered")
        cached_manifest.chmod(0o600)
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "does not match its metadata",
        ):
            claude_provenance.verify_claude_release(
                self.executable,
                version="2.1.211",
                platform_key="darwin-arm64",
                gpg_temp_root=self.root,
                fetcher=lambda *_args, **_kwargs: self.fail(
                    "corrupt complete cache must fail closed"
                ),
                cache_dir=cache_dir,
            )


class ExecutableSnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.payload = b"\x7fELF" + b"trusted Claude executable snapshot fixture"
        self.executable = self.root / "claude-real"
        self.executable.write_bytes(self.payload)
        self.executable.chmod(0o700)
        self.verified = verified_for(self.executable, self.payload)
        self.snapshot_root = self.root / "snapshots"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_materializes_private_digest_keyed_executable_snapshot(self) -> None:
        result = claude_provenance.materialize_verified_executable(
            self.verified,
            self.snapshot_root,
        )

        expected_name = (
            f"claude-2.1.211-darwin-arm64-{hashlib.sha256(self.payload).hexdigest()}"
        )
        self.assertEqual(
            result.executable, self.snapshot_root.resolve() / expected_name
        )
        self.assertEqual(result.executable.read_bytes(), self.payload)
        self.assertEqual(stat.S_IMODE(self.snapshot_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(result.executable.stat().st_mode), 0o500)
        self.assertEqual(result.executable.stat().st_nlink, 1)
        self.assertEqual(result.artifact, self.verified.artifact)
        self.assertEqual(result.gpg_path, self.verified.gpg_path)
        self.assertEqual(self.verified.executable, self.executable.resolve())
        self.assertFalse(any(self.snapshot_root.glob(".*.tmp")))

    def test_reuses_and_reverifies_existing_snapshot(self) -> None:
        first = claude_provenance.materialize_verified_executable(
            self.verified,
            self.snapshot_root,
        )
        first_identity = (
            first.executable.stat().st_dev,
            first.executable.stat().st_ino,
        )

        with mock.patch.object(
            claude_provenance,
            "_copy_and_hash_snapshot",
            side_effect=AssertionError("reusable snapshot must not be recopied"),
        ) as copier:
            second = claude_provenance.materialize_verified_executable(
                self.verified,
                self.snapshot_root,
            )

        self.assertFalse(copier.called)
        self.assertEqual(
            (second.executable.stat().st_dev, second.executable.stat().st_ino),
            first_identity,
        )

    def test_reuse_fails_closed_when_snapshot_content_is_tampered(self) -> None:
        snapshot = claude_provenance.materialize_verified_executable(
            self.verified,
            self.snapshot_root,
        ).executable
        snapshot.chmod(0o700)
        snapshot.write_bytes(b"X" * len(self.payload))
        snapshot.chmod(0o500)

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "does not match the signed release",
        ):
            claude_provenance.materialize_verified_executable(
                self.verified,
                self.snapshot_root,
            )

    def test_rejects_non_private_or_symlink_snapshot_root(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "0700 real directory",
        ):
            claude_provenance.materialize_verified_executable(
                self.verified,
                unsafe,
            )

        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "snapshot-link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInvalid,
            "0700 real directory",
        ):
            claude_provenance.materialize_verified_executable(
                self.verified,
                link,
            )

    def test_source_metadata_change_during_copy_is_inconclusive(self) -> None:
        original_copy = claude_provenance._copy_and_hash_snapshot

        def copy_then_change(
            source_descriptor: int,
            destination_descriptor: int,
            *,
            max_bytes: int,
        ) -> tuple[str, int]:
            result = original_copy(
                source_descriptor,
                destination_descriptor,
                max_bytes=max_bytes,
            )
            self.executable.chmod(0o750)
            return result

        with mock.patch.object(
            claude_provenance,
            "_copy_and_hash_snapshot",
            side_effect=copy_then_change,
        ):
            with self.assertRaisesRegex(
                claude_provenance.ClaudeProvenanceInconclusive,
                "changed while copying",
            ):
                claude_provenance.materialize_verified_executable(
                    self.verified,
                    self.snapshot_root,
                )
        self.assertFalse(any(self.snapshot_root.iterdir()))

    def test_source_replacement_after_verification_is_inconclusive(self) -> None:
        replacement = self.root / "replacement"
        replacement.write_bytes(b"Y" * len(self.payload))
        replacement.chmod(0o700)
        os.replace(replacement, self.executable)

        with self.assertRaisesRegex(
            claude_provenance.ClaudeProvenanceInconclusive,
            "changed after provenance verification",
        ):
            claude_provenance.materialize_verified_executable(
                self.verified,
                self.snapshot_root,
            )
        self.assertFalse(any(self.snapshot_root.iterdir()))


if __name__ == "__main__":
    unittest.main()
