from __future__ import annotations

import os
import pathlib
import signal
import stat
import sys
import tempfile
import threading
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

    def _join_started_workers(
        self,
        *workers: threading.Thread,
    ) -> list[str]:
        alive: list[str] = []
        for worker in workers:
            if worker.ident is None:
                continue
            worker.join(timeout=2.0)
            if worker.is_alive():
                alive.append(worker.name)
        return alive

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
            completed_renewals = 0
            completed_renewals_lock = threading.Lock()

            def fast_wait(
                event: object,
                timeout: float | None = None,
            ) -> bool:
                if timeout is None:
                    return real_wait(event, None)
                bounded = min(timeout, 0.01)
                return real_wait(event, bounded)

            def tracked_renew(
                lock: object,
                protocol: claude_refresh_lock.ClaudeRefreshLockProtocol,
            ) -> None:
                nonlocal completed_renewals
                real_renew(lock, protocol)
                with completed_renewals_lock:
                    completed_renewals += 1

            def renewal_count() -> int:
                with completed_renewals_lock:
                    return completed_renewals

            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_renew_lock",
                    side_effect=tracked_renew,
                ),
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
                    if renewal_count() >= 4 and all(
                        path.stat().st_mtime_ns > old_mtime_ns
                        for path in lease.paths
                    ):
                        break
                    time.sleep(0.01)
                else:
                    self.fail("Claude refresh-lock heartbeat did not renew both locks")

                calls_before_additional_wait = renewal_count()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if renewal_count() > calls_before_additional_wait:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("Claude refresh-lock heartbeat stopped renewing")

                lease.release()
                heartbeat_thread = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat_thread)
                assert heartbeat_thread is not None
                self.assertFalse(heartbeat_thread.is_alive())

    def test_blocked_heartbeat_cannot_prevent_bounded_release(self) -> None:
        heartbeat_entered = threading.Event()
        allow_heartbeat_exit = threading.Event()
        release_finished = threading.Event()
        release_errors: list[BaseException] = []
        real_wait = claude_refresh_lock.threading.Event.wait

        def fast_wait(
            event: threading.Event,
            timeout: float | None = None,
        ) -> bool:
            bounded = 0.01 if timeout is None else min(timeout, 0.01)
            return real_wait(event, bounded)

        def block_heartbeat_renewal(
            _lease: claude_refresh_lock.ClaudeRefreshLockLease,
        ) -> None:
            heartbeat_entered.set()
            real_wait(allow_heartbeat_exit, 10.0)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_renew_and_assert",
                    autospec=True,
                    side_effect=block_heartbeat_renewal,
                ),
            ):
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                release_thread: threading.Thread | None = None
                try:
                    self.assertTrue(real_wait(heartbeat_entered, 2.0))
                    thread = lease._heartbeat_thread
                    assert thread is not None

                    def release_lease() -> None:
                        try:
                            lease.release()
                        except BaseException as error:
                            release_errors.append(error)
                        finally:
                            release_finished.set()

                    release_thread = threading.Thread(
                        target=release_lease,
                        name="test-refresh-lock-release",
                        daemon=True,
                    )
                    with (
                        mock.patch.object(thread, "join", return_value=None),
                        mock.patch.object(thread, "is_alive", return_value=True),
                    ):
                        release_thread.start()
                        finished_without_rescue = real_wait(release_finished, 1.0)
                        if not finished_without_rescue:
                            allow_heartbeat_exit.set()
                            self.assertTrue(real_wait(release_finished, 2.0))
                    release_thread.join(timeout=2.0)
                    self.assertFalse(release_thread.is_alive())
                    self.assertTrue(
                        finished_without_rescue,
                        "release blocked on heartbeat-held state lock before bounded join",
                    )
                    self.assertEqual(len(release_errors), 1)
                    self.assertIsInstance(
                        release_errors[0],
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                    )
                    for path in lease.paths:
                        self.assertIn(str(path), str(release_errors[0]))
                finally:
                    allow_heartbeat_exit.set()
                    alive_workers = self._join_started_workers(
                        *(
                            (release_thread,)
                            if release_thread is not None
                            else ()
                        )
                    )
                    if not alive_workers:
                        self._operator_cleanup_inconclusive_lease(lease)
                    self.assertEqual(alive_workers, [])

    def test_blocked_assert_retains_locks_after_bounded_release(self) -> None:
        assert_entered = threading.Event()
        allow_assert_exit = threading.Event()
        assert_finished = threading.Event()
        release_finished = threading.Event()
        assert_errors: list[BaseException] = []
        release_errors: list[BaseException] = []

        def block_assert_renewal() -> None:
            assert_entered.set()
            allow_assert_exit.wait(timeout=10.0)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())

            def assert_lease() -> None:
                try:
                    lease.assert_held()
                except BaseException as error:
                    assert_errors.append(error)
                finally:
                    assert_finished.set()

            def release_lease() -> None:
                try:
                    lease.release()
                except BaseException as error:
                    release_errors.append(error)
                finally:
                    release_finished.set()

            assert_thread = threading.Thread(
                target=assert_lease,
                name="test-refresh-lock-assert",
                daemon=True,
            )
            release_thread = threading.Thread(
                target=release_lease,
                name="test-refresh-lock-release",
                daemon=True,
            )
            try:
                with (
                    mock.patch.object(
                        lease,
                        "_renew_and_assert",
                        side_effect=block_assert_renewal,
                    ),
                    mock.patch.object(
                        lease,
                        "_shutdown_timeout_seconds",
                        return_value=0.05,
                    ),
                ):
                    assert_thread.start()
                    self.assertTrue(assert_entered.wait(timeout=2.0))
                    release_thread.start()
                    finished_without_rescue = release_finished.wait(timeout=1.0)
                    if not finished_without_rescue:
                        allow_assert_exit.set()
                        self.assertTrue(release_finished.wait(timeout=2.0))

                release_thread.join(timeout=2.0)
                self.assertFalse(release_thread.is_alive())
                self.assertTrue(
                    finished_without_rescue,
                    "release blocked instead of bounding an active assertion",
                )
                self.assertEqual(len(release_errors), 1)
                self.assertIsInstance(
                    release_errors[0],
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                )
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                for descriptor in self._lease_descriptors(lease):
                    os.fstat(descriptor)

                allow_assert_exit.set()
                self.assertTrue(assert_finished.wait(timeout=2.0))
                assert_thread.join(timeout=2.0)
                self.assertFalse(assert_thread.is_alive())
                self.assertEqual(len(assert_errors), 1)
                self.assertIsInstance(
                    assert_errors[0],
                    claude_refresh_lock.ClaudeRefreshLockCompromised,
                )
                self.assertIn("release already started", str(assert_errors[0]))
            finally:
                allow_assert_exit.set()
                alive_workers = self._join_started_workers(
                    assert_thread,
                    release_thread,
                )
                if not alive_workers:
                    self._operator_cleanup_inconclusive_lease(lease)
                self.assertEqual(alive_workers, [])

    def test_release_observes_late_heartbeat_failure(self) -> None:
        heartbeat_entered = threading.Event()
        allow_heartbeat_failure = threading.Event()
        release_finished = threading.Event()
        release_errors: list[BaseException] = []
        real_wait = claude_refresh_lock.threading.Event.wait
        compromise = claude_refresh_lock.ClaudeRefreshLockCompromised(
            "injected late heartbeat compromise"
        )

        def fast_wait(
            event: threading.Event,
            timeout: float | None = None,
        ) -> bool:
            bounded = 0.01 if timeout is None else min(timeout, 0.01)
            return real_wait(event, bounded)

        def fail_heartbeat_after_release(
            _lease: claude_refresh_lock.ClaudeRefreshLockLease,
        ) -> None:
            heartbeat_entered.set()
            real_wait(allow_heartbeat_failure, 10.0)
            raise compromise

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_renew_and_assert",
                    autospec=True,
                    side_effect=fail_heartbeat_after_release,
                ),
            ):
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

                def release_lease() -> None:
                    try:
                        lease.release()
                    except BaseException as error:
                        release_errors.append(error)
                    finally:
                        release_finished.set()

                release_thread = threading.Thread(
                    target=release_lease,
                    name="test-refresh-lock-late-failure-release",
                    daemon=True,
                )
                try:
                    self.assertTrue(real_wait(heartbeat_entered, 2.0))
                    release_thread.start()
                    release_started = real_wait(lease._heartbeat_stop, 1.0)
                    if not release_started:
                        allow_heartbeat_failure.set()
                        self.assertTrue(real_wait(lease._heartbeat_stop, 2.0))
                    allow_heartbeat_failure.set()
                    self.assertTrue(real_wait(release_finished, 2.0))
                    release_thread.join(timeout=2.0)
                    self.assertFalse(release_thread.is_alive())
                    self.assertTrue(
                        release_started,
                        "release could not publish stop while heartbeat I/O was active",
                    )
                    self.assertEqual(release_errors, [compromise])
                    self.assertTrue(lease.released)
                    self.assertTrue(all(not path.exists() for path in lease.paths))
                finally:
                    allow_heartbeat_failure.set()
                    alive_workers = self._join_started_workers(release_thread)
                    if not alive_workers and not lease.released:
                        self._operator_cleanup_inconclusive_lease(lease)
                    self.assertEqual(alive_workers, [])

    def test_release_observes_late_assert_failure(self) -> None:
        assert_entered = threading.Event()
        allow_assert_failure = threading.Event()
        release_waiting_for_operation = threading.Event()
        assert_finished = threading.Event()
        release_finished = threading.Event()
        assert_errors: list[BaseException] = []
        release_errors: list[BaseException] = []
        compromise = claude_refresh_lock.ClaudeRefreshLockCompromised(
            "injected late assertion compromise"
        )

        class ObservedOperationLock:
            def __init__(self) -> None:
                self._lock = threading.Lock()

            def __enter__(self) -> ObservedOperationLock:
                self._lock.acquire()
                return self

            def __exit__(
                self,
                _error_type: type[BaseException] | None,
                _error: BaseException | None,
                _traceback: object,
            ) -> None:
                self._lock.release()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                release_waiting_for_operation.set()
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self._lock.release()

        def fail_assert_after_release() -> None:
            assert_entered.set()
            allow_assert_failure.wait(timeout=10.0)
            raise compromise

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = claude_refresh_lock.acquire_claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            lease._operation_lock = ObservedOperationLock()

            def assert_lease() -> None:
                try:
                    lease.assert_held()
                except BaseException as error:
                    assert_errors.append(error)
                finally:
                    assert_finished.set()

            def release_lease() -> None:
                try:
                    lease.release()
                except BaseException as error:
                    release_errors.append(error)
                finally:
                    release_finished.set()

            assert_thread = threading.Thread(
                target=assert_lease,
                name="test-refresh-lock-late-assert-failure",
                daemon=True,
            )
            release_thread = threading.Thread(
                target=release_lease,
                name="test-refresh-lock-late-assert-release",
                daemon=True,
            )
            try:
                with mock.patch.object(
                    lease,
                    "_renew_and_assert",
                    side_effect=fail_assert_after_release,
                ):
                    assert_thread.start()
                    self.assertTrue(assert_entered.wait(timeout=2.0))
                    release_thread.start()
                    self.assertTrue(
                        release_waiting_for_operation.wait(timeout=2.0)
                    )
                    allow_assert_failure.set()
                    self.assertTrue(assert_finished.wait(timeout=2.0))
                    self.assertTrue(release_finished.wait(timeout=2.0))

                self.assertEqual(assert_errors, [compromise])
                self.assertEqual(release_errors, [compromise])
                self.assertTrue(lease.released)
                self.assertTrue(all(not path.exists() for path in lease.paths))
            finally:
                allow_assert_failure.set()
                alive_workers = self._join_started_workers(
                    assert_thread,
                    release_thread,
                )
                if not alive_workers and not lease.released:
                    self._operator_cleanup_inconclusive_lease(lease)
                self.assertEqual(alive_workers, [])

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

    def test_borrowed_directory_anchors_acquire_and_release_exact_locks(
        self,
    ) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary).resolve())
            config_fd = os.open(config, flags)
            parent_fd = os.open(config.parent, flags)
            try:
                with mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=AssertionError("path reopen is forbidden"),
                ):
                    lease = claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                        config_dir_fd=config_fd,
                        legacy_parent_dir_fd=parent_fd,
                    )
                self.assertEqual(
                    lease.paths,
                    (
                        config / ".oauth_refresh.lock",
                        pathlib.Path(str(config) + ".lock"),
                    ),
                )
                lease.assert_held()
                lease.release()
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_borrowed_directory_anchors_use_retained_tree_after_path_retarget(
        self,
    ) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            replacement_home = root / "replacement-home"
            replacement_home.mkdir(mode=0o700)
            replacement_config = self._config_dir(replacement_home)
            retained_home = root / "retained-home"
            config_fd = os.open(config, flags)
            parent_fd = os.open(home, flags)
            try:
                home.rename(retained_home)
                home.symlink_to(replacement_home, target_is_directory=True)
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    config_dir_fd=config_fd,
                    legacy_parent_dir_fd=parent_fd,
                )
                retained_config = retained_home / ".claude"
                self.assertTrue(
                    (retained_config / ".oauth_refresh.lock").is_dir()
                )
                self.assertTrue(
                    pathlib.Path(str(retained_config) + ".lock").is_dir()
                )
                self.assertFalse(
                    (replacement_config / ".oauth_refresh.lock").exists()
                )
                self.assertFalse(
                    pathlib.Path(str(replacement_config) + ".lock").exists()
                )
                lease.assert_held()
                lease.release()
                self.assertFalse(
                    (retained_config / ".oauth_refresh.lock").exists()
                )
                self.assertFalse(
                    pathlib.Path(str(retained_config) + ".lock").exists()
                )
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_borrowed_anchor_cleanup_failure_omits_retargeted_path(self) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            replacement_home = root / "replacement-home"
            replacement_home.mkdir(mode=0o700)
            replacement_config = self._config_dir(replacement_home)
            retained_home = root / "retained-home"
            config_fd = os.open(config, flags)
            parent_fd = os.open(home, flags)
            try:
                home.rename(retained_home)
                home.symlink_to(replacement_home, target_is_directory=True)
                lease = claude_refresh_lock.acquire_claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    config_dir_fd=config_fd,
                    legacy_parent_dir_fd=parent_fd,
                )
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_remove_owned_lock",
                        side_effect=claude_refresh_lock.ClaudeRefreshLockError(
                            "injected descriptor-bound cleanup failure"
                        ),
                    ),
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockError
                    ) as raised,
                ):
                    lease.release()

                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(
                        raised.exception
                    )
                )
                messages: list[str] = []
                pending: list[BaseException] = [raised.exception]
                seen: set[int] = set()
                while pending:
                    current = pending.pop()
                    if id(current) in seen:
                        continue
                    seen.add(id(current))
                    messages.append(str(current))
                    messages.extend(getattr(current, "__notes__", ()))
                    for chained in (current.__cause__, current.__context__):
                        if isinstance(chained, BaseException):
                            pending.append(chained)
                self.assertTrue(
                    any(
                        "no authoritative pathname is available" in message
                        for message in messages
                    )
                )
                self.assertFalse(
                    (replacement_config / ".oauth_refresh.lock").exists()
                )
                self.assertFalse(
                    pathlib.Path(str(replacement_config) + ".lock").exists()
                )
                retained_config = retained_home / ".claude"
                retained_primary = retained_config / ".oauth_refresh.lock"
                retained_legacy = pathlib.Path(str(retained_config) + ".lock")
                self.assertTrue(retained_primary.is_dir())
                self.assertTrue(retained_legacy.is_dir())
                retained_legacy.rmdir()
                retained_primary.rmdir()
            finally:
                os.close(parent_fd)
                os.close(config_fd)

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
