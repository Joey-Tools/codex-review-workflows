from __future__ import annotations

import os
import pathlib
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_refresh_lock  # noqa: E402


EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS = {
    (
        "2.1.211",
        "darwin-arm64",
        "5a728a76198b6eca7f3c7cdbff43bab44b77b48c2108f7a3107d889773382629",
    ),
    (
        "2.1.211",
        "darwin-x64",
        "33049eb14cf4702b992b7eda41ec077fc6e76539f7fd046e6d32538757235da4",
    ),
    (
        "2.1.211",
        "linux-arm64",
        "1fff7e8f947c07b19d10b1fbf714b7e547e9536253b9b58230d8adbc4624f867",
    ),
    (
        "2.1.211",
        "linux-x64",
        "8272c8a474ac9ea1bc35f19b9f7c7e7dc4dc4eb6d5ad3e484b19335ac72446b2",
    ),
    (
        "2.1.211",
        "linux-arm64-musl",
        "ca094a85ea464b2ebec2ecfcc9e2c056573d4ca95ebe12ffae2c7dccb722e17b",
    ),
    (
        "2.1.211",
        "linux-x64-musl",
        "c99bd7934ac841d5be6ee7d3644cb63bccef2cd495c6c1bb982a1b1deac1b466",
    ),
}


class ClaudeRefreshLockTest(unittest.TestCase):
    PROTOCOL = claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211

    def _config_dir(self, root: pathlib.Path) -> pathlib.Path:
        config = root / ".claude"
        config.mkdir(mode=0o700)
        return config

    def _lease_descriptors(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> tuple[int, ...]:
        return tuple(
            dict.fromkeys(
                (
                    *(lock.descriptor for lock in lease._locks),
                    lease._legacy_parent_anchor.descriptor,
                    lease._config_anchor.descriptor,
                )
            )
        )

    def _operator_cleanup_inconclusive_lease(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        thread = lease._heartbeat_thread
        assert thread is not None
        thread.join(timeout=1.0)
        self.assertFalse(thread.is_alive())
        for path in reversed(lease.paths):
            if path.exists():
                path.rmdir()
        for descriptor in self._lease_descriptors(lease):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_acquires_exact_primary_and_realpath_legacy_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary))
            canonical = config.resolve()
            primary = canonical / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(canonical) + ".lock")

            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            self.assertEqual(lease.paths, (primary, legacy))
            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())
            self.assertEqual(
                tuple(identity.path for identity in lease.identities),
                lease.paths,
            )
            for identity in lease.identities:
                self.assertEqual(identity.uid, os.getuid())
                self.assertEqual(identity.mode, 0o700)
                self.assertGreater(identity.device, 0)
                self.assertGreater(identity.inode, 0)
            lease.assert_held()

            lease.release()
            lease.release()
            self.assertTrue(lease.released)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    def test_signed_artifact_catalog_is_exact_and_cross_platform(self) -> None:
        catalog = claude_refresh_lock.CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS
        self.assertEqual(set(catalog), EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS)
        for (version, platform, checksum), protocol in catalog.items():
            self.assertIs(
                claude_refresh_lock.certified_claude_refresh_lock_protocol(
                    version=version,
                    platform_key=platform,
                    checksum=checksum,
                ),
                protocol,
            )
        sample_version, sample_platform, sample_checksum = next(iter(catalog))
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version="2.9.999",
                platform_key=sample_platform,
                checksum=sample_checksum,
            )
        )
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version=sample_version,
                platform_key="linux-unknown",
                checksum=sample_checksum,
            )
        )
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version=sample_version,
                platform_key=sample_platform,
                checksum="0" + sample_checksum[1:],
            )
        )

    def test_background_heartbeat_renews_slow_critical_section_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            real_renew = claude_refresh_lock._renew_lock
            real_wait = claude_refresh_lock.threading.Event.wait

            def fast_wait(
                event: object,
                timeout: float | None = None,
            ) -> bool:
                bounded = 0.01 if timeout is None else min(timeout, 0.01)
                return real_wait(event, bounded)

            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_renew_lock",
                    wraps=real_renew,
                ) as renew,
            ):
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                old_mtime_ns = 1_000_000_000
                for path in lease.paths:
                    os.utime(path, ns=(old_mtime_ns, old_mtime_ns))

                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if renew.call_count >= 4 and all(
                        path.stat().st_mtime_ns > old_mtime_ns
                        for path in lease.paths
                    ):
                        break
                    time.sleep(0.01)
                else:
                    self.fail("Claude refresh-lock heartbeat did not renew both locks")

                calls_before_additional_wait = renew.call_count
                time.sleep(0.05)
                self.assertGreater(renew.call_count, calls_before_additional_wait)

                lease.release()
                calls_after_release = renew.call_count
                time.sleep(0.04)
                self.assertEqual(renew.call_count, calls_after_release)

    def test_release_retries_cleanup_after_transient_heartbeat_join_timeout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", side_effect=(True, False)),
                self.assertRaisesRegex(
                    claude_refresh_lock.ClaudeRefreshLockError,
                    "heartbeat did not stop",
                ),
            ):
                lease.release()

            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in lease.paths))
            lease.release()

    def test_release_becomes_terminal_after_both_bounded_join_attempts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                lease.release()

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            for path in lease.paths:
                self.assertIn(str(path), str(raised.exception))
            with self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockCompromised,
                "release already started",
            ):
                lease.assert_held()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, raised.exception)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

            self._operator_cleanup_inconclusive_lease(lease)

    def test_context_owner_retries_transient_heartbeat_join_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", side_effect=(True, False)),
                self.assertRaisesRegex(
                    claude_refresh_lock.ClaudeRefreshLockError,
                    "heartbeat did not stop",
                ),
            ):
                manager.__exit__(None, None, None)

            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in lease.paths))

    def test_context_owner_reports_locks_after_both_join_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                manager.__exit__(None, None, None)

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            for path in lease.paths:
                self.assertIn(str(path), str(raised.exception))

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, raised.exception)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

            self._operator_cleanup_inconclusive_lease(lease)

    def test_context_body_error_displays_inconclusive_cleanup_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None
            body_error = claude_refresh_lock.ReviewError(
                "injected credential operation failure"
            )

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
            ):
                suppressed = manager.__exit__(
                    type(body_error),
                    body_error,
                    None,
                )

            self.assertFalse(suppressed)
            for path in lease.paths:
                self.assertIn(str(path), str(body_error))
            self.assertEqual(
                getattr(
                    body_error,
                    "_codex_claude_refresh_lock_paths",
                ),
                tuple(str(path) for path in lease.paths),
            )
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self._operator_cleanup_inconclusive_lease(lease)

    def test_release_never_retries_after_descriptor_cleanup_started(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            calls = 0

            def interrupt_after_cleanup_started() -> None:
                nonlocal calls
                calls += 1
                with lease._state_lock:
                    lease._cleanup_started = True
                    lease._heartbeat_stop.set()
                raise interruption

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=interrupt_after_cleanup_started,
                ),
                self.assertRaises(
                    claude_refresh_lock.ForwardedSignal
                ) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, interruption)
            self.assertEqual(calls, 1)
            assert interruption.detail is not None
            for path in lease.paths:
                self.assertIn(str(path), interruption.detail)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertEqual(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_paths",
                ),
                tuple(str(path) for path in lease.paths),
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_retry_cleanup_gap_publishes_terminal_signal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_timeout = claude_refresh_lock.ClaudeRefreshLockError(
                "Claude refresh-lock heartbeat did not stop"
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            calls = 0

            def timeout_then_interrupt_cleanup() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise first_timeout
                lease._heartbeat_stop.set()
                lease._mark_cleanup_inconclusive(
                    "injected second-attempt cleanup gap"
                )
                with lease._state_lock:
                    lease._cleanup_started = True
                raise forwarded

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=timeout_then_interrupt_cleanup,
                ),
                self.assertRaises(
                    claude_refresh_lock.ForwardedSignal
                ) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, forwarded)
            self.assertEqual(calls, 2)
            assert forwarded.detail is not None
            for path in lease.paths:
                self.assertIn(str(path), forwarded.detail)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertEqual(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_paths",
                ),
                tuple(str(path) for path in lease.paths),
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_cleanup_loop_signal_keeps_partial_release_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            real_remove = claude_refresh_lock._remove_owned_lock
            calls = 0

            def interrupt_first_removal(
                lock: claude_refresh_lock._HeldLock,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise forwarded
                real_remove(lock)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=interrupt_first_removal,
                ),
                self.assertRaises(
                    claude_refresh_lock.ForwardedSignal
                ) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, forwarded)
            self.assertFalse(lease.released)
            assert forwarded.detail is not None
            for path in lease.paths:
                self.assertIn(str(path), forwarded.detail)
            self.assertFalse(lease.paths[0].exists())
            self.assertTrue(lease.paths[1].is_dir())
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertEqual(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_paths",
                ),
                tuple(str(path) for path in lease.paths),
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_heartbeat_start_failure_does_not_swallow_cleanup_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            start_error = claude_refresh_lock.ClaudeRefreshLockError(
                "injected heartbeat start failure"
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            real_release = claude_refresh_lock.ClaudeRefreshLockLease.release

            def release_then_signal(
                lease: claude_refresh_lock.ClaudeRefreshLockLease,
            ) -> None:
                real_release(lease)
                raise forwarded

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_start_heartbeat",
                    side_effect=start_error,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "release",
                    autospec=True,
                    side_effect=release_then_signal,
                ),
                self.assertRaises(
                    claude_refresh_lock.ForwardedSignal
                ) as raised,
            ):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertIs(raised.exception, forwarded)
            self.assertFalse((config / ".oauth_refresh.lock").exists())
            self.assertFalse(pathlib.Path(str(config) + ".lock").exists())

    def test_synchronous_renewal_detects_post_utime_identity_compromise(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = self._config_dir(root).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary = config / ".oauth_refresh.lock"
            primary_descriptor = lease._locks[0].descriptor
            real_utime = os.utime
            replaced = False

            def renew_then_replace(
                path: int | os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> None:
                nonlocal replaced
                real_utime(path, *args, **kwargs)
                if path == primary_descriptor and not replaced:
                    replaced = True
                    primary.rmdir()
                    primary.mkdir(mode=0o700)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "utime",
                    side_effect=renew_then_replace,
                ),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ),
            ):
                lease.assert_held()

            self.assertTrue(replaced)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCompromised
            ):
                lease.release()
            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_primary_contention_times_out_without_touching_either_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockTimeout):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertTrue(primary.is_dir())
            self.assertFalse(legacy.exists())

    def test_stale_crash_residue_pauses_without_unsafe_reclaim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            stale_time = time.time() - self.PROTOCOL.stale_seconds - 5.0
            os.utime(primary, (stale_time, stale_time))

            with self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockStale,
                "controlled cleanup",
            ):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertTrue(primary.is_dir())
            self.assertFalse(legacy.exists())

    def test_recovery_removes_only_exact_empty_helper_owned_staged_locks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            recovered = (
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )
            )

            self.assertEqual(recovered, (primary, legacy))
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())
            self.assertTrue(config.is_dir())
            self.assertTrue(carrier.is_dir())

    def test_staged_recovery_requires_quiescence_and_preflights_all_locks(
        self,
    ) -> None:
        for case in ("unproven", "nonempty-legacy"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                carrier = root / "claude-carrier-fixture"
                carrier.mkdir(mode=0o700)
                config = carrier / "config"
                config.mkdir(mode=0o700)
                primary = config / ".oauth_refresh.lock"
                legacy = pathlib.Path(str(config) + ".lock")
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)
                if case == "nonempty-legacy":
                    (legacy / "unexpected").write_text("occupied", encoding="utf-8")

                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockUnsafe
                ):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=case != "unproven",
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_host_shaped_config_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary) / "account-home"
            carrier.mkdir(mode=0o700)
            config = carrier / ".claude"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_wrong_carrier_name_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary) / "not-a-claude-carrier"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_symlink_lock_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            target = root / "external-lock"
            target.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            primary.symlink_to(target, target_is_directory=True)
            legacy = pathlib.Path(str(config) + ".lock")
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_symlink())
            self.assertTrue(target.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_unsafe_lock_mode_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary) / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            primary.chmod(0o755)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertEqual(stat.S_IMODE(primary.stat().st_mode), 0o755)
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_requires_exact_private_carrier_modes(self) -> None:
        for unsafe_directory in ("carrier", "config"):
            with (
                self.subTest(unsafe_directory=unsafe_directory),
                tempfile.TemporaryDirectory() as temporary,
            ):
                carrier = pathlib.Path(temporary) / "claude-carrier-fixture"
                carrier.mkdir(mode=0o700)
                config = carrier / "config"
                config.mkdir(mode=0o700)
                primary = config / ".oauth_refresh.lock"
                legacy = pathlib.Path(str(config) + ".lock")
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)
                unsafe = carrier if unsafe_directory == "carrier" else config
                unsafe.chmod(0o755)

                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockUnsafe
                ):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_carrier_and_config_symlinks(self) -> None:
        for symlinked_directory in ("carrier", "config"):
            with (
                self.subTest(symlinked_directory=symlinked_directory),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                if symlinked_directory == "carrier":
                    real_carrier = root / "real-carrier"
                    real_carrier.mkdir(mode=0o700)
                    real_config = real_carrier / "config"
                    real_config.mkdir(mode=0o700)
                    carrier = root / "claude-carrier-link"
                    carrier.symlink_to(real_carrier, target_is_directory=True)
                    config = carrier / "config"
                    primary = real_config / ".oauth_refresh.lock"
                    legacy = real_carrier / "config.lock"
                else:
                    carrier = root / "claude-carrier-fixture"
                    carrier.mkdir(mode=0o700)
                    real_config = root / "real-config"
                    real_config.mkdir(mode=0o700)
                    config = carrier / "config"
                    config.symlink_to(real_config, target_is_directory=True)
                    primary = real_config / ".oauth_refresh.lock"
                    legacy = carrier / "config.lock"
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)

                with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_legacy_contention_releases_the_new_primary_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockTimeout):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertFalse(primary.exists())
            self.assertTrue(legacy.is_dir())

    def test_assert_held_detects_deleted_replaced_and_symlinked_lock(self) -> None:
        cases = ("deleted", "replaced", "symlinked")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                config = self._config_dir(root).resolve()
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                primary = config / ".oauth_refresh.lock"
                primary.rmdir()
                if case == "replaced":
                    primary.mkdir(mode=0o700)
                elif case == "symlinked":
                    target = root / "replacement"
                    target.mkdir(mode=0o700)
                    primary.symlink_to(target, target_is_directory=True)

                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ):
                    lease.assert_held()
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ):
                    lease.release()
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as repeated:
                    lease.release()
                for path in lease.paths:
                    self.assertIn(str(path), str(repeated.exception))

                if case == "replaced":
                    self.assertTrue(primary.is_dir())
                    primary.rmdir()
                elif case == "symlinked":
                    self.assertTrue(primary.is_symlink())
                    primary.unlink()

    def test_rejects_unsafe_config_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            readable = self._config_dir(root)
            readable.chmod(0o755)
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                readable,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease.release()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            permissive = self._config_dir(root)
            permissive.chmod(0o777)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    permissive,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = self._config_dir(root)
            alias = root / "config-link"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    alias,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

    def test_release_never_removes_a_replacement_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary = config / ".oauth_refresh.lock"
            primary.rmdir()
            primary.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.release()

            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_body_error_remains_primary_when_release_detects_compromise(self) -> None:
        marker = ValueError("body marker")
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"

            with self.assertRaises(ValueError) as raised:
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                ):
                    primary.rmdir()
                    primary.mkdir(mode=0o700)
                    raise marker

            self.assertIs(raised.exception, marker)
            notes = getattr(marker, "__notes__", ())
            if notes:
                self.assertTrue(any("cleanup" in note.lower() for note in notes))
            else:
                self.assertIsInstance(
                    marker.__cause__,
                    claude_refresh_lock.ClaudeRefreshLockCleanupDiagnostic,
                )
            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_release_interruption_overrides_ordinary_body_error(self) -> None:
        body_error = ValueError("body marker")
        release_error = KeyboardInterrupt("release marker")
        lease = mock.Mock(spec=["release"])
        lease.release.side_effect = release_error

        with (
            mock.patch.object(
                claude_refresh_lock,
                "acquire_claude_refresh_lock",
                return_value=lease,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            with claude_refresh_lock.claude_refresh_lock(
                "/fixture/.claude",
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ):
                raise body_error

        self.assertIs(raised.exception, release_error)
        lease.release.assert_called_once_with()
        notes = getattr(release_error, "__notes__", ())
        if notes:
            self.assertTrue(any("cleanup" in note.lower() for note in notes))

    def test_legacy_acquire_cleanup_interruption_overrides_acquire_error(
        self,
    ) -> None:
        acquire_error = ValueError("legacy acquire marker")
        cleanup_error = KeyboardInterrupt("legacy cleanup marker")
        anchors = (
            mock.Mock(descriptor=101),
            mock.Mock(descriptor=102),
        )

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=anchors,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_acquire_one",
                    side_effect=(mock.Mock(), acquire_error),
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "release",
                    side_effect=cleanup_error,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        self.assertIs(raised.exception, cleanup_error)

    def test_outer_anchor_close_interruption_overrides_acquire_error(self) -> None:
        acquire_error = ValueError("primary acquire marker")
        cleanup_error = KeyboardInterrupt("anchor close marker")
        anchors = (
            mock.Mock(descriptor=201),
            mock.Mock(descriptor=202),
        )

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=anchors,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_acquire_one",
                    side_effect=acquire_error,
                ),
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=(cleanup_error, None),
                ) as close,
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        self.assertIs(raised.exception, cleanup_error)
        self.assertEqual(close.call_count, 2)

    def test_missing_lock_churn_still_obeys_acquisition_deadline(self) -> None:
        parent = mock.Mock(descriptor=301)
        with (
            mock.patch.object(claude_refresh_lock, "_assert_anchor"),
            mock.patch.object(
                claude_refresh_lock.os,
                "mkdir",
                side_effect=FileExistsError,
            ) as mkdir,
            mock.patch.object(
                claude_refresh_lock,
                "_inspect_existing_lock",
                return_value="missing",
            ) as inspect,
            mock.patch.object(
                claude_refresh_lock.time,
                "monotonic",
                side_effect=(99.5, 100.0),
            ),
            self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockTimeout,
                "timed out",
            ),
        ):
            claude_refresh_lock._acquire_one(
                label="primary",
                path=pathlib.Path("/fixture/.oauth_refresh.lock"),
                name=".oauth_refresh.lock",
                parent=parent,
                protocol=self.PROTOCOL,
                deadline=100.0,
                retry_interval_seconds=0.01,
            )

        self.assertEqual(mkdir.call_count, 2)
        self.assertEqual(inspect.call_count, 2)

    def test_filesystem_failure_does_not_copy_arbitrary_error_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "mkdir",
                    side_effect=OSError(5, "sensitive injected detail"),
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertNotIn("sensitive injected detail", str(raised.exception))
            self.assertIn("errno 5", str(raised.exception))

    def test_close_oserror_is_normalized_as_refresh_lock_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_descriptor = self._lease_descriptors(lease)[0]
            real_close = os.close
            failed = False

            def fail_first_close(descriptor: int) -> None:
                nonlocal failed
                if not failed:
                    failed = True
                    raise OSError(5, "sensitive injected close detail")
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=fail_first_close,
                ),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockError
                ) as raised,
            ):
                lease.release()

            real_close(first_descriptor)
            self.assertNotIsInstance(raised.exception, OSError)
            self.assertNotIn("sensitive injected close detail", str(raised.exception))
            self.assertIn("errno 5", str(raised.exception))

    def test_close_control_flow_exception_remains_primary(self) -> None:
        marker = KeyboardInterrupt("close marker")
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_descriptor = self._lease_descriptors(lease)[0]
            real_close = os.close
            failed = False

            def interrupt_first_close(descriptor: int) -> None:
                nonlocal failed
                if not failed:
                    failed = True
                    raise marker
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=interrupt_first_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                lease.release()

            real_close(first_descriptor)
            self.assertIs(raised.exception, marker)

    def test_identity_mode_is_permission_bits_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ) as lease:
                for identity in lease.identities:
                    self.assertEqual(identity.mode, stat.S_IMODE(identity.mode))


if __name__ == "__main__":
    unittest.main()
