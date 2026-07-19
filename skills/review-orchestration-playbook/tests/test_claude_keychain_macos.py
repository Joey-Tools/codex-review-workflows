from __future__ import annotations

import ctypes
import errno
import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_keychain_macos  # noqa: E402
from review_runtime.common import ForwardedSignal  # noqa: E402


ACCOUNT = "test-user"
SERVICE = "Claude Code-credentials"


def worker_identity() -> claude_keychain_macos.KeychainIdentity:
    return claude_keychain_macos.KeychainIdentity(
        path="/Users/test/Library/Keychains/login.keychain-db",
        components=(
            claude_keychain_macos.KeychainPathComponentIdentity(
                name="login.keychain-db",
                device=101,
                inode=202,
                file_type=stat.S_IFREG,
                owner=501,
                group=20,
                mode=0o600,
                flags=0,
                generation=7,
                link_count=1,
                descriptor_policy=(
                    claude_keychain_macos.KeychainDescriptorPolicyIdentity(
                        filesystem_id=(303, 404),
                        filesystem_type="apfs",
                        filesystem_flags=claude_keychain_macos._MNT_LOCAL,
                        deny_acl_entries=0,
                    )
                ),
            ),
        ),
    )


class FakeDescriptorLibC:
    def __init__(
        self,
        *,
        acl_tags: tuple[int, ...] = (),
        acl_get_errno: int | None = None,
        enumerate_errno: int | None = None,
        tag_error: bool = False,
        free_error: bool = False,
        filesystem_type: bytes = b"apfs",
        filesystem_flags: int = claude_keychain_macos._MNT_LOCAL,
        fstatfs_error: int | None = None,
    ) -> None:
        self.acl_tags = acl_tags
        self.acl_get_errno = acl_get_errno
        self.enumerate_errno = enumerate_errno
        self.tag_error = tag_error
        self.free_error = free_error
        self.filesystem_type = filesystem_type
        self.filesystem_flags = filesystem_flags
        self.fstatfs_error = fstatfs_error
        self.entry_index = 0
        self.free_calls = 0

    def fstatfs(self, descriptor: int, output: object) -> int:
        del descriptor
        if self.fstatfs_error is not None:
            ctypes.set_errno(self.fstatfs_error)
            return -1
        filesystem = ctypes.cast(
            output,
            ctypes.POINTER(claude_keychain_macos._DarwinStatFS),
        ).contents
        filesystem.f_fsid.values[0] = 101
        filesystem.f_fsid.values[1] = 202
        filesystem.f_flags = self.filesystem_flags
        filesystem.f_fstypename = self.filesystem_type
        return 0

    def acl_get_fd_np(self, descriptor: int, acl_type: int) -> ctypes.c_void_p | None:
        del descriptor
        if acl_type != claude_keychain_macos._ACL_TYPE_EXTENDED:
            raise AssertionError("wrong ACL type")
        if self.acl_get_errno is not None:
            ctypes.set_errno(self.acl_get_errno)
            return None
        self.entry_index = 0
        return ctypes.c_void_p(0xA11)

    def acl_get_entry(self, acl: object, entry_id: int, output: object) -> int:
        del acl
        expected_entry_id = (
            claude_keychain_macos._ACL_FIRST_ENTRY
            if self.entry_index == 0
            else claude_keychain_macos._ACL_NEXT_ENTRY
        )
        if entry_id != expected_entry_id:
            raise AssertionError("wrong ACL entry selector")
        if self.enumerate_errno is not None:
            ctypes.set_errno(self.enumerate_errno)
            return -1
        if self.entry_index >= len(self.acl_tags):
            ctypes.set_errno(errno.EINVAL)
            return -1
        entry = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
        entry.contents.value = 0xE00 + self.entry_index
        self.entry_index += 1
        return 0

    def acl_get_tag_type(self, entry: object, output: object) -> int:
        if self.tag_error:
            return -1
        entry_value = ctypes.cast(entry, ctypes.c_void_p).value
        if entry_value is None:
            raise AssertionError("missing ACL entry")
        index = entry_value - 0xE00
        tag = ctypes.cast(output, ctypes.POINTER(ctypes.c_int))
        tag.contents.value = self.acl_tags[index]
        return 0

    def acl_free(self, acl: object) -> int:
        del acl
        self.free_calls += 1
        return -1 if self.free_error else 0


def descriptor_policy_with_libc(
    libc: FakeDescriptorLibC,
) -> claude_keychain_macos._DarwinDescriptorPolicy:
    policy = object.__new__(claude_keychain_macos._DarwinDescriptorPolicy)
    policy._libc = libc
    return policy


def fake_descriptor_policy(
    descriptor: int,
) -> claude_keychain_macos.KeychainDescriptorPolicyIdentity:
    metadata = os.fstat(descriptor)
    return claude_keychain_macos.KeychainDescriptorPolicyIdentity(
        filesystem_id=(metadata.st_dev, metadata.st_dev),
        filesystem_type="apfs",
        filesystem_flags=0x00001000,
        deny_acl_entries=0,
    )


class FakeWatcher:
    def __init__(self, descriptors: tuple[int, ...], leaf_descriptor: int) -> None:
        self.descriptors = descriptors
        self.leaf_descriptor = leaf_descriptor
        self.hard_event = False
        self.expected_update_event = False
        self.closed = False
        self.close_error: BaseException | None = None
        self.quiet_checks = 0
        self.update_event_checks = 0

    def signal_hard_event(self) -> None:
        self.hard_event = True

    def signal_expected_update_event(self) -> None:
        self.expected_update_event = True

    def assert_quiet(self) -> None:
        self.quiet_checks += 1
        if self.hard_event or self.expected_update_event:
            raise claude_keychain_macos.MacOSKeychainInspectionInconclusive(
                "fake vnode event"
            )

    def consume_expected_update_events(self) -> None:
        self.update_event_checks += 1
        if self.hard_event:
            raise claude_keychain_macos.MacOSKeychainInspectionInconclusive(
                "fake unsafe vnode event"
            )
        self.expected_update_event = False

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class FakeWatcherFactory:
    def __init__(self) -> None:
        self.watchers: list[FakeWatcher] = []
        self.close_error: BaseException | None = None

    @property
    def current(self) -> FakeWatcher:
        return self.watchers[-1]

    def __call__(
        self,
        descriptors: tuple[int, ...],
        leaf_descriptor: int,
    ) -> FakeWatcher:
        watcher = FakeWatcher(descriptors, leaf_descriptor)
        watcher.close_error = self.close_error
        self.watchers.append(watcher)
        return watcher


class FakeSecurityBackend:
    def __init__(
        self,
        payload: bytes,
        watcher_factory: FakeWatcherFactory,
    ) -> None:
        self.value = bytearray(payload)
        self.watcher_factory = watcher_factory
        self.keychain = object()
        self.item = object()
        self.missing = False
        self.open_calls = 0
        self.modify_calls = 0
        self.copy_calls = 0
        self.opened_path: pathlib.Path | None = None
        self.find_hook: Callable[[bytearray], None] | None = None
        self.release_item_error: BaseException | None = None
        self.find_payloads: list[bytearray] = []
        self.modify_payloads: list[bytearray] = []
        self.copy_payloads: list[bytearray] = []
        self.modified_items: list[object] = []
        self.copied_items: list[object] = []
        self.released_items: list[object] = []
        self.released_keychains: list[object] = []

    def open_keychain(self, path: pathlib.Path) -> object:
        self.open_calls += 1
        self.opened_path = path
        return self.keychain

    def find_generic_password(
        self,
        keychain: object,
        account: str,
        service: str,
    ) -> claude_keychain_macos._FoundCredential | None:
        if keychain is not self.keychain:
            raise AssertionError("wrong keychain reference")
        if account != ACCOUNT or service != SERVICE:
            raise AssertionError("wrong generic-password selector")
        if self.missing:
            return None
        payload = bytearray(self.value)
        self.find_payloads.append(payload)
        if self.find_hook is not None:
            self.find_hook(payload)
        return claude_keychain_macos._FoundCredential(payload, self.item)

    def modify_item(self, item: object, payload: bytearray) -> None:
        self.modify_calls += 1
        self.modified_items.append(item)
        self.modify_payloads.append(payload)
        self.value[:] = payload
        self.watcher_factory.current.signal_expected_update_event()

    def copy_item_content(self, item: object) -> bytearray:
        self.copy_calls += 1
        self.copied_items.append(item)
        payload = bytearray(self.value)
        self.copy_payloads.append(payload)
        return payload

    def release_item(self, item: object) -> None:
        self.released_items.append(item)
        if self.release_item_error is not None:
            raise self.release_item_error

    def release_keychain(self, keychain: object) -> None:
        self.released_keychains.append(keychain)


class KeychainFixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.anchor = root
        self.home = root / "home"
        self.library = self.home / "Library"
        self.keychains = self.library / "Keychains"
        self.target = self.keychains / "login.keychain-db"
        self.watcher_factory = FakeWatcherFactory()
        self.backend = FakeSecurityBackend(b"credential-a", self.watcher_factory)

    def create(self) -> None:
        for directory in (self.home, self.library, self.keychains):
            directory.mkdir(mode=0o700)
        self.target.write_bytes(b"database-a")
        self.target.chmod(0o600)

    def runtime(self) -> claude_keychain_macos._Runtime:
        return claude_keychain_macos._Runtime(
            path=self.target,
            anchor=self.anchor,
            user_owned_from=0,
            uid=os.getuid(),
            backend=self.backend,
            watcher_factory=self.watcher_factory,
            descriptor_policy=fake_descriptor_policy,
        )


class ClaudeKeychainMacOSTest(unittest.TestCase):
    def _fixture(self, temporary: str) -> KeychainFixture:
        fixture = KeychainFixture(pathlib.Path(temporary))
        fixture.create()
        return fixture

    def _assert_descriptors_closed(self, watcher: FakeWatcher) -> None:
        for descriptor in watcher.descriptors:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def _read(
        self,
        fixture: KeychainFixture,
    ) -> tuple[bytearray, claude_keychain_macos.KeychainIdentity] | None:
        return claude_keychain_macos._read_with_runtime(
            ACCOUNT,
            SERVICE,
            fixture.runtime(),
        )

    def _replace(
        self,
        fixture: KeychainFixture,
        expected: bytearray,
        replacement: bytearray,
        identity: claude_keychain_macos.KeychainIdentity,
    ) -> claude_keychain_macos.KeychainIdentity:
        return claude_keychain_macos._replace_with_runtime(
            ACCOUNT,
            SERVICE,
            expected,
            replacement,
            identity,
            fixture.runtime(),
        )

    def _runtime_with_real_watcher(
        self,
        fixture: KeychainFixture,
    ) -> claude_keychain_macos._Runtime:
        runtime = fixture.runtime()
        return claude_keychain_macos._Runtime(
            path=runtime.path,
            anchor=runtime.anchor,
            user_owned_from=runtime.user_owned_from,
            uid=runtime.uid,
            backend=runtime.backend,
            watcher_factory=claude_keychain_macos._default_watcher_factory,
            descriptor_policy=runtime.descriptor_policy,
        )

    def test_darwin_statfs_layout_matches_xcode_26_6_abi(self) -> None:
        self.assertEqual(
            ctypes.sizeof(claude_keychain_macos._DarwinStatFS),
            2168,
        )
        self.assertEqual(
            claude_keychain_macos._DarwinStatFS.f_fstypename.offset,
            72,
        )

    def test_descriptor_policy_accepts_empty_acl_reported_as_enoent(self) -> None:
        libc = FakeDescriptorLibC(acl_get_errno=errno.ENOENT)

        identity = descriptor_policy_with_libc(libc)(42)

        self.assertEqual(
            identity,
            claude_keychain_macos.KeychainDescriptorPolicyIdentity(
                filesystem_id=(101, 202),
                filesystem_type="apfs",
                filesystem_flags=claude_keychain_macos._MNT_LOCAL,
                deny_acl_entries=0,
            ),
        )
        self.assertEqual(libc.free_calls, 0)

    def test_descriptor_policy_accepts_allocated_empty_acl_and_frees_it(self) -> None:
        libc = FakeDescriptorLibC()

        identity = descriptor_policy_with_libc(libc)(42)

        self.assertEqual(identity.deny_acl_entries, 0)
        self.assertEqual(libc.free_calls, 1)

    def test_descriptor_policy_accepts_only_deny_acl_and_count_is_stable(self) -> None:
        libc = FakeDescriptorLibC(
            acl_tags=(
                claude_keychain_macos._ACL_EXTENDED_DENY,
                claude_keychain_macos._ACL_EXTENDED_DENY,
            )
        )
        policy = descriptor_policy_with_libc(libc)

        first = policy(42)
        second = policy(42)

        self.assertEqual(first.deny_acl_entries, 2)
        self.assertEqual(second, first)
        self.assertEqual(libc.free_calls, 2)

    def test_descriptor_policy_rejects_allow_and_unknown_acl_entries(self) -> None:
        for tag in (
            claude_keychain_macos._ACL_EXTENDED_ALLOW,
            99,
        ):
            with self.subTest(tag=tag):
                libc = FakeDescriptorLibC(acl_tags=(tag,))

                with self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe):
                    descriptor_policy_with_libc(libc)(42)

                self.assertEqual(libc.free_calls, 1)

    def test_descriptor_policy_acl_failures_fail_closed_and_free_when_owned(
        self,
    ) -> None:
        cases = (
            ("get", FakeDescriptorLibC(acl_get_errno=errno.EIO), 0),
            ("enumerate", FakeDescriptorLibC(enumerate_errno=errno.EIO), 1),
            (
                "tag",
                FakeDescriptorLibC(
                    acl_tags=(claude_keychain_macos._ACL_EXTENDED_DENY,),
                    tag_error=True,
                ),
                1,
            ),
            (
                "free",
                FakeDescriptorLibC(
                    acl_tags=(claude_keychain_macos._ACL_EXTENDED_DENY,),
                    free_error=True,
                ),
                1,
            ),
        )
        for label, libc, free_calls in cases:
            with self.subTest(label=label):
                with self.assertRaises(
                    claude_keychain_macos.MacOSKeychainInspectionInconclusive
                ):
                    descriptor_policy_with_libc(libc)(42)

                self.assertEqual(libc.free_calls, free_calls)

    def test_descriptor_policy_rejects_nonlocal_non_apfs_and_failed_statfs(
        self,
    ) -> None:
        cases = (
            (
                "nonlocal",
                FakeDescriptorLibC(filesystem_flags=0),
                claude_keychain_macos.MacOSKeychainUnsafe,
            ),
            (
                "non-apfs",
                FakeDescriptorLibC(filesystem_type=b"nfs"),
                claude_keychain_macos.MacOSKeychainUnsafe,
            ),
            (
                "fstatfs",
                FakeDescriptorLibC(fstatfs_error=errno.EIO),
                claude_keychain_macos.MacOSKeychainInspectionInconclusive,
            ),
        )
        for label, libc, expected_error in cases:
            with self.subTest(label=label):
                with self.assertRaises(expected_error):
                    descriptor_policy_with_libc(libc)(42)

                self.assertEqual(libc.free_calls, 0)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS descriptor APIs")
    def test_real_descriptor_policy_accepts_empty_acl_on_event_only_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "empty-acl"
            target.touch(mode=0o600)
            descriptor = os.open(
                target,
                getattr(os, "O_EVTONLY", os.O_RDONLY)
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                identity = claude_keychain_macos._DarwinDescriptorPolicy()(descriptor)
            finally:
                os.close(descriptor)

        self.assertEqual(identity.filesystem_type, "apfs")
        self.assertTrue(identity.filesystem_flags & claude_keychain_macos._MNT_LOCAL)
        self.assertEqual(identity.deny_acl_entries, 0)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS ACL APIs")
    def test_real_descriptor_policy_accepts_stable_deny_only_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "deny-only-acl"
            target.touch(mode=0o600)
            subprocess.run(
                ("/bin/chmod", "+a", "everyone deny delete", os.fspath(target)),
                check=True,
                capture_output=True,
            )
            descriptor = os.open(
                target,
                getattr(os, "O_EVTONLY", os.O_RDONLY)
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                policy = claude_keychain_macos._DarwinDescriptorPolicy()
                first = policy(descriptor)
                second = policy(descriptor)
            finally:
                os.close(descriptor)
                subprocess.run(
                    ("/bin/chmod", "-N", os.fspath(target)),
                    check=True,
                    capture_output=True,
                )

        self.assertEqual(first.deny_acl_entries, 1)
        self.assertEqual(second, first)

    def test_native_oversized_content_is_scrubbed_before_free(self) -> None:
        class FakeSecurity:
            def __init__(self, allocation: object) -> None:
                self.allocation = allocation
                self.free_calls = 0
                self.zeroed_at_free = False

            def SecKeychainItemFreeContent(
                self,
                attributes: object,
                data: ctypes.c_void_p,
            ) -> int:
                del attributes, data
                self.free_calls += 1
                content = bytes(self.allocation)
                self.zeroed_at_free = not any(content)
                return 0

        length = claude_keychain_macos.MAXIMUM_CREDENTIAL_BYTES + 1
        allocation = (ctypes.c_ubyte * length)()
        ctypes.memset(ctypes.addressof(allocation), 0x5A, length)
        security = FakeSecurity(allocation)
        backend = object.__new__(claude_keychain_macos._CtypesSecurityBackend)
        backend._security = security

        with self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe):
            backend._copy_and_free_content(
                ctypes.c_void_p(ctypes.addressof(allocation)),
                length,
            )

        self.assertEqual(security.free_calls, 1)
        self.assertTrue(security.zeroed_at_free)

    def test_native_scrub_failure_still_releases_content(self) -> None:
        class FakeSecurity:
            def __init__(self) -> None:
                self.free_calls = 0

            def SecKeychainItemFreeContent(
                self,
                attributes: object,
                data: ctypes.c_void_p,
            ) -> int:
                del attributes, data
                self.free_calls += 1
                return 0

        length = claude_keychain_macos.MAXIMUM_CREDENTIAL_BYTES + 1
        allocation = (ctypes.c_ubyte * length)()
        security = FakeSecurity()
        backend = object.__new__(claude_keychain_macos._CtypesSecurityBackend)
        backend._security = security

        with (
            mock.patch.object(
                claude_keychain_macos.ctypes,
                "memset",
                side_effect=OSError("synthetic scrub failure"),
            ),
            self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe),
        ):
            backend._copy_and_free_content(
                ctypes.c_void_p(ctypes.addressof(allocation)),
                length,
            )

        self.assertEqual(security.free_calls, 1)

    def test_open_failure_preserves_primary_when_unexpected_ref_release_fails(
        self,
    ) -> None:
        class FakeSecurity:
            @staticmethod
            def SecKeychainOpen(path: object, output: object) -> int:
                del path
                reference = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
                reference.contents.value = 0xCAFE
                return -50

        class FakeCoreFoundation:
            def __init__(self) -> None:
                self.release_calls = 0

            def CFRelease(self, reference: object) -> None:
                del reference
                self.release_calls += 1
                raise OSError("synthetic release failure")

        core_foundation = FakeCoreFoundation()
        backend = object.__new__(claude_keychain_macos._CtypesSecurityBackend)
        backend._security = FakeSecurity()
        backend._core_foundation = core_foundation

        with self.assertRaisesRegex(
            claude_keychain_macos.MacOSKeychainInspectionInconclusive,
            "SecKeychainOpen failed with OSStatus -50",
        ):
            backend.open_keychain(pathlib.Path("/synthetic/login.keychain-db"))

        self.assertEqual(core_foundation.release_calls, 1)

    def test_find_copy_failure_preserves_primary_when_item_release_fails(
        self,
    ) -> None:
        class FakeSecurity:
            @staticmethod
            def SecKeychainFindGenericPassword(
                keychain: object,
                service_length: object,
                service: object,
                account_length: object,
                account: object,
                length_output: object,
                data_output: object,
                item_output: object,
            ) -> int:
                del (
                    keychain,
                    service_length,
                    service,
                    account_length,
                    account,
                )
                length = ctypes.cast(length_output, ctypes.POINTER(ctypes.c_uint32))
                length.contents.value = 0
                data = ctypes.cast(data_output, ctypes.POINTER(ctypes.c_void_p))
                data.contents.value = None
                item = ctypes.cast(item_output, ctypes.POINTER(ctypes.c_void_p))
                item.contents.value = 0x1A11
                return 0

        class FakeCoreFoundation:
            def __init__(self) -> None:
                self.release_calls = 0

            def CFRelease(self, reference: object) -> None:
                del reference
                self.release_calls += 1
                raise OSError("synthetic release failure")

        primary = claude_keychain_macos.MacOSKeychainUnsafe("synthetic copy failure")
        core_foundation = FakeCoreFoundation()
        backend = object.__new__(claude_keychain_macos._CtypesSecurityBackend)
        backend._security = FakeSecurity()
        backend._core_foundation = core_foundation

        with (
            mock.patch.object(
                backend,
                "_copy_and_free_content",
                side_effect=primary,
            ),
            self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe) as raised,
        ):
            backend.find_generic_password(object(), ACCOUNT, SERVICE)

        self.assertIs(raised.exception, primary)
        self.assertEqual(core_foundation.release_calls, 1)

    def test_stable_query_returns_exact_payload_identity_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            fixture.backend.value[:] = b"  exact\x00payload\n"

            result = self._read(fixture)

            self.assertIsNotNone(result)
            assert result is not None
            payload, identity = result
            self.assertEqual(payload, b"  exact\x00payload\n")
            self.assertEqual(identity.path, os.fspath(fixture.target))
            self.assertEqual(
                [component.name for component in identity.components],
                [
                    os.fspath(fixture.anchor),
                    "home",
                    "Library",
                    "Keychains",
                    "login.keychain-db",
                ],
            )
            watcher = fixture.watcher_factory.current
            self.assertTrue(watcher.closed)
            self.assertGreaterEqual(watcher.quiet_checks, 6)
            self._assert_descriptors_closed(watcher)
            self.assertEqual(fixture.backend.released_items, [fixture.backend.item])
            self.assertEqual(
                fixture.backend.released_keychains,
                [fixture.backend.keychain],
            )
            payload[:] = b"\x00" * len(payload)

    def test_stable_update_uses_same_item_ref_and_zeroes_working_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            replacement = bytearray(b"credential-c")

            updated_identity = self._replace(
                fixture,
                expected,
                replacement,
                identity,
            )

            self.assertEqual(updated_identity, identity)
            self.assertEqual(fixture.backend.value, replacement)
            self.assertEqual(fixture.backend.modify_calls, 1)
            self.assertEqual(fixture.backend.copy_calls, 1)
            self.assertIs(fixture.backend.modified_items[-1], fixture.backend.item)
            self.assertIs(fixture.backend.copied_items[-1], fixture.backend.item)
            self.assertEqual(
                fixture.backend.modify_payloads[-1],
                b"\x00" * len(replacement),
            )
            self.assertEqual(
                fixture.backend.find_payloads[-1],
                b"\x00" * len(expected),
            )
            self.assertEqual(
                fixture.backend.copy_payloads[-1],
                b"\x00" * len(replacement),
            )
            self.assertEqual(expected, b"credential-a")
            self.assertEqual(replacement, b"credential-c")
            update_watcher = fixture.watcher_factory.current
            self.assertEqual(update_watcher.update_event_checks, 1)
            self.assertTrue(update_watcher.closed)
            self._assert_descriptors_closed(update_watcher)
            expected[:] = b"\x00" * len(expected)
            replacement[:] = b"\x00" * len(replacement)

    def test_leaf_aba_query_never_returns_b_and_zeroes_captured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            original = fixture.target.with_name("login.keychain-db.original")

            def leaf_aba(payload: bytearray) -> None:
                fixture.target.rename(original)
                try:
                    fixture.target.write_bytes(b"database-b")
                    fixture.target.chmod(0o600)
                    payload[:] = b"credential-b"
                finally:
                    fixture.target.unlink(missing_ok=True)
                    original.rename(fixture.target)
                fixture.watcher_factory.current.signal_hard_event()

            fixture.backend.find_hook = leaf_aba

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                self._read(fixture)

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(
                fixture.backend.find_payloads[-1],
                b"\x00" * len(b"credential-b"),
            )
            watcher = fixture.watcher_factory.current
            self.assertTrue(watcher.closed)
            self._assert_descriptors_closed(watcher)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS kqueue")
    def test_real_kqueue_rejects_leaf_rename_restore_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            original = fixture.target.with_name("login.keychain-db.original")

            def leaf_aba(payload: bytearray) -> None:
                fixture.target.rename(original)
                try:
                    fixture.target.write_bytes(b"database-b")
                    fixture.target.chmod(0o600)
                    payload[:] = b"credential-b"
                finally:
                    fixture.target.unlink(missing_ok=True)
                    original.rename(fixture.target)
                time.sleep(0.05)

            fixture.backend.find_hook = leaf_aba

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                claude_keychain_macos._read_with_runtime(
                    ACCOUNT,
                    SERVICE,
                    self._runtime_with_real_watcher(fixture),
                )

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(
                fixture.backend.find_payloads[-1],
                b"\x00" * len(b"credential-b"),
            )

    def test_ancestor_aba_query_never_returns_b(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            original_home = fixture.anchor / "home.original"

            def ancestor_aba(payload: bytearray) -> None:
                fixture.home.rename(original_home)
                try:
                    replacement_keychains = fixture.home / "Library" / "Keychains"
                    replacement_keychains.mkdir(parents=True, mode=0o700)
                    replacement_target = replacement_keychains / "login.keychain-db"
                    replacement_target.write_bytes(b"database-b")
                    replacement_target.chmod(0o600)
                    payload[:] = b"credential-b"
                finally:
                    if fixture.home.exists():
                        shutil.rmtree(fixture.home)
                    original_home.rename(fixture.home)
                fixture.watcher_factory.current.signal_hard_event()

            fixture.backend.find_hook = ancestor_aba

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                self._read(fixture)

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(
                fixture.backend.find_payloads[-1],
                b"\x00" * len(b"credential-b"),
            )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS kqueue")
    def test_real_kqueue_rejects_ancestor_rename_restore_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            original_home = fixture.anchor / "home.original"

            def ancestor_aba(payload: bytearray) -> None:
                fixture.home.rename(original_home)
                try:
                    replacement_keychains = fixture.home / "Library" / "Keychains"
                    replacement_keychains.mkdir(parents=True, mode=0o700)
                    replacement_target = replacement_keychains / "login.keychain-db"
                    replacement_target.write_bytes(b"database-b")
                    replacement_target.chmod(0o600)
                    payload[:] = b"credential-b"
                finally:
                    if fixture.home.exists():
                        shutil.rmtree(fixture.home)
                    original_home.rename(fixture.home)
                time.sleep(0.05)

            fixture.backend.find_hook = ancestor_aba

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                claude_keychain_macos._read_with_runtime(
                    ACCOUNT,
                    SERVICE,
                    self._runtime_with_real_watcher(fixture),
                )

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(
                fixture.backend.find_payloads[-1],
                b"\x00" * len(b"credential-b"),
            )

    def test_update_event_before_modify_leaves_a_and_b_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            alternate = fixture.target.with_name("login.keychain-db.b")
            alternate.write_bytes(b"database-b")
            alternate.chmod(0o600)
            original = fixture.target.with_name("login.keychain-db.a")

            def aba_before_modify(_payload: bytearray) -> None:
                fixture.target.rename(original)
                alternate.rename(fixture.target)
                fixture.target.rename(alternate)
                original.rename(fixture.target)
                fixture.watcher_factory.current.signal_hard_event()

            fixture.backend.find_hook = aba_before_modify
            replacement = bytearray(b"credential-c")

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                self._replace(fixture, expected, replacement, identity)

            self.assertEqual(fixture.backend.modify_calls, 0)
            self.assertEqual(fixture.backend.value, b"credential-a")
            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(alternate.read_bytes(), b"database-b")
            self.assertEqual(expected, b"credential-a")
            self.assertEqual(replacement, b"credential-c")
            expected[:] = b"\x00" * len(expected)
            replacement[:] = b"\x00" * len(replacement)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS kqueue")
    def test_real_kqueue_rejects_leaf_aba_inside_modify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            replacement = bytearray(b"credential-c")
            original = fixture.target.with_name("login.keychain-db.original")

            class LeafABABackend(FakeSecurityBackend):
                def modify_item(self, item: object, payload: bytearray) -> None:
                    self.modify_calls += 1
                    self.modified_items.append(item)
                    self.modify_payloads.append(payload)
                    fixture.target.rename(original)
                    try:
                        fixture.target.write_bytes(b"database-b")
                        fixture.target.chmod(0o600)
                    finally:
                        fixture.target.unlink(missing_ok=True)
                        original.rename(fixture.target)
                    self.value[:] = payload
                    time.sleep(0.05)

            backend = LeafABABackend(b"credential-a", fixture.watcher_factory)
            fixture.backend = backend

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                claude_keychain_macos._replace_with_runtime(
                    ACCOUNT,
                    SERVICE,
                    expected,
                    replacement,
                    identity,
                    self._runtime_with_real_watcher(fixture),
                )

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(backend.copy_calls, 0)
            self.assertEqual(
                backend.find_payloads[-1],
                b"\x00" * len(b"credential-a"),
            )
            self.assertEqual(
                backend.modify_payloads[-1],
                b"\x00" * len(b"credential-c"),
            )
            expected[:] = b"\x00" * len(expected)
            replacement[:] = b"\x00" * len(replacement)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS kqueue")
    def test_real_kqueue_rejects_ancestor_aba_inside_modify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            replacement = bytearray(b"credential-c")
            original_home = fixture.anchor / "home.original"

            class AncestorABABackend(FakeSecurityBackend):
                def modify_item(self, item: object, payload: bytearray) -> None:
                    self.modify_calls += 1
                    self.modified_items.append(item)
                    self.modify_payloads.append(payload)
                    fixture.home.rename(original_home)
                    try:
                        replacement_keychains = fixture.home / "Library" / "Keychains"
                        replacement_keychains.mkdir(parents=True, mode=0o700)
                        replacement_target = replacement_keychains / "login.keychain-db"
                        replacement_target.write_bytes(b"database-b")
                        replacement_target.chmod(0o600)
                    finally:
                        if fixture.home.exists():
                            shutil.rmtree(fixture.home)
                        original_home.rename(fixture.home)
                    self.value[:] = payload
                    time.sleep(0.05)

            backend = AncestorABABackend(b"credential-a", fixture.watcher_factory)
            fixture.backend = backend

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                claude_keychain_macos._replace_with_runtime(
                    ACCOUNT,
                    SERVICE,
                    expected,
                    replacement,
                    identity,
                    self._runtime_with_real_watcher(fixture),
                )

            self.assertEqual(fixture.target.read_bytes(), b"database-a")
            self.assertEqual(backend.copy_calls, 0)
            self.assertEqual(
                backend.find_payloads[-1],
                b"\x00" * len(b"credential-a"),
            )
            self.assertEqual(
                backend.modify_payloads[-1],
                b"\x00" * len(b"credential-c"),
            )
            expected[:] = b"\x00" * len(expected)
            replacement[:] = b"\x00" * len(replacement)

    def test_identity_mismatch_stops_before_security_or_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            original = fixture.target.with_name("login.keychain-db.a")
            fixture.target.rename(original)
            fixture.target.write_bytes(b"database-b")
            fixture.target.chmod(0o600)
            fixture.backend.open_calls = 0
            replacement = bytearray(b"credential-c")

            with self.assertRaises(claude_keychain_macos.MacOSKeychainIdentityMismatch):
                self._replace(fixture, expected, replacement, identity)

            self.assertEqual(fixture.backend.open_calls, 0)
            self.assertEqual(fixture.backend.modify_calls, 0)
            self.assertEqual(fixture.backend.value, b"credential-a")
            self.assertEqual(original.read_bytes(), b"database-a")
            self.assertEqual(fixture.target.read_bytes(), b"database-b")
            expected[:] = b"\x00" * len(expected)
            replacement[:] = b"\x00" * len(replacement)

    def test_cleanup_failure_zeroes_payload_and_closes_every_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            fixture.backend.release_item_error = OSError("release failed")

            with self.assertRaises(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive
            ):
                self._read(fixture)

            captured = fixture.backend.find_payloads[-1]
            self.assertEqual(captured, b"\x00" * len(captured))
            self.assertEqual(
                fixture.backend.released_keychains,
                [fixture.backend.keychain],
            )
            watcher = fixture.watcher_factory.current
            self.assertTrue(watcher.closed)
            self._assert_descriptors_closed(watcher)

    def test_zero_failures_are_independent_and_resources_still_close(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            result = self._read(fixture)
            assert result is not None
            expected, identity = result
            replacement = bytearray(b"credential-c")
            original_zero = claude_keychain_macos._zero
            zero_calls: list[bytearray | None] = []

            def fail_first_zero(payload: bytearray | None) -> None:
                zero_calls.append(payload)
                if len(zero_calls) == 1:
                    raise OSError("synthetic zero failure")
                original_zero(payload)

            with (
                mock.patch.object(
                    claude_keychain_macos,
                    "_zero",
                    side_effect=fail_first_zero,
                ),
                self.assertRaises(
                    claude_keychain_macos.MacOSKeychainInspectionInconclusive
                ),
            ):
                self._replace(fixture, expected, replacement, identity)

            self.assertEqual(len(zero_calls), 4)
            self.assertEqual(
                fixture.backend.copy_payloads[-1],
                b"\x00" * len(b"credential-c"),
            )
            self.assertEqual(
                fixture.backend.modify_payloads[-1],
                b"\x00" * len(b"credential-c"),
            )
            self.assertEqual(
                fixture.backend.released_items[-1],
                fixture.backend.item,
            )
            self.assertEqual(
                fixture.backend.released_keychains[-1],
                fixture.backend.keychain,
            )
            watcher = fixture.watcher_factory.current
            self.assertTrue(watcher.closed)
            self._assert_descriptors_closed(watcher)
            original_zero(fixture.backend.find_payloads[-1])
            original_zero(expected)
            original_zero(replacement)

    def test_hardlinked_leaf_is_rejected_before_security_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            os.link(
                fixture.target,
                fixture.target.with_name("login.keychain-db.link"),
            )

            with self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe):
                self._read(fixture)

            self.assertEqual(fixture.backend.open_calls, 0)
            self.assertEqual(fixture.watcher_factory.watchers, [])

    def test_group_writable_ancestor_is_rejected_before_security_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(temporary)
            fixture.library.chmod(0o770)

            with self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe):
                self._read(fixture)

            self.assertEqual(fixture.backend.open_calls, 0)
            self.assertEqual(fixture.watcher_factory.watchers, [])

    def test_worker_identity_metadata_round_trips_full_descriptor_chain(self) -> None:
        identity = worker_identity()

        metadata = claude_keychain_macos._identity_to_worker_metadata(identity)

        self.assertEqual(
            claude_keychain_macos._identity_from_worker_metadata(metadata),
            identity,
        )
        self.assertEqual(
            metadata["components"][0]["descriptor_policy"]["filesystem_id"],
            [303, 404],
        )
        invalid = claude_keychain_macos._identity_to_worker_metadata(identity)
        invalid["components"][0]["unexpected"] = True
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._identity_from_worker_metadata(invalid)

    def test_worker_metadata_and_frames_fail_closed_and_scrub_partial_reads(
        self,
    ) -> None:
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._decode_worker_metadata(bytearray(b"[]"))
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._decode_worker_metadata(bytearray(b"{"))
        for malformed in (
            b'{"status":"ok","status":"error"}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
        ):
            with (
                self.subTest(malformed=malformed),
                self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError),
            ):
                claude_keychain_macos._decode_worker_metadata(bytearray(malformed))
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._decode_worker_metadata(
                bytearray(claude_keychain_macos._KEYCHAIN_WORKER_METADATA_BYTES + 1)
            )

        class PartialSocket:
            def __init__(self) -> None:
                self.calls = 0
                self.target: bytearray | None = None

            def settimeout(self, timeout: float) -> None:
                self.asserted_timeout = timeout

            def recv_into(self, target: memoryview, length: int) -> int:
                del length
                self.target = target.obj
                self.calls += 1
                if self.calls == 1:
                    target[:4] = b"leak"
                    return 4
                return 0

        partial = PartialSocket()
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._receive_worker_exact(
                partial,
                8,
                deadline=time.monotonic() + 1.0,
            )
        self.assertIsNotNone(partial.target)
        assert partial.target is not None
        self.assertEqual(partial.target, b"\x00" * 8)

        parent, child = socket.socketpair()
        try:
            child.sendall(
                claude_keychain_macos._FRAME_LENGTH.pack(
                    claude_keychain_macos._KEYCHAIN_WORKER_METADATA_BYTES + 1
                )
            )
            with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
                claude_keychain_macos._receive_worker_frame(
                    parent,
                    maximum_bytes=(
                        claude_keychain_macos._KEYCHAIN_WORKER_METADATA_BYTES
                    ),
                    deadline=time.monotonic() + 1.0,
                )
        finally:
            parent.close()
            child.close()

        for trailing_data in (b"", b"x"):
            parent, child = socket.socketpair()
            try:
                if trailing_data:
                    child.sendall(trailing_data)
                child.shutdown(socket.SHUT_WR)
                if trailing_data:
                    with self.assertRaises(
                        claude_keychain_macos._KeychainWorkerProtocolError
                    ):
                        claude_keychain_macos._require_worker_protocol_eof(
                            parent,
                            deadline=time.monotonic() + 1.0,
                        )
                else:
                    claude_keychain_macos._require_worker_protocol_eof(
                        parent,
                        deadline=time.monotonic() + 1.0,
                    )
            finally:
                parent.close()
                child.close()

    def test_worker_response_rejects_unknown_error_and_mismatched_success(
        self,
    ) -> None:
        zero_payload = bytearray(b"\x00\x00")
        with mock.patch.object(
            claude_keychain_macos,
            "_send_worker_frame",
        ) as send_frame:
            claude_keychain_macos._send_worker_response(
                mock.Mock(),
                {"status": "synthetic"},
                zero_payload,
                deadline=time.monotonic() + 1.0,
            )
        self.assertIs(send_frame.call_args_list[1].args[1], zero_payload)

        unknown_error = {
            "protocol": claude_keychain_macos._KEYCHAIN_WORKER_PROTOCOL,
            "status": "error",
            "kind": "error",
            "identity": None,
            "error_type": "UnknownKeychainError",
            "message": "synthetic failure",
        }
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._decode_worker_response(
                unknown_error,
                bytearray(),
                operation="read",
            )

        mismatched_success = {
            "protocol": claude_keychain_macos._KEYCHAIN_WORKER_PROTOCOL,
            "status": "ok",
            "kind": "replace",
            "identity": claude_keychain_macos._identity_to_worker_metadata(
                worker_identity()
            ),
            "error_type": None,
            "message": None,
        }
        with self.assertRaises(claude_keychain_macos._KeychainWorkerProtocolError):
            claude_keychain_macos._decode_worker_response(
                mismatched_success,
                bytearray(),
                operation="read",
            )

    def test_worker_command_uses_isolated_absolute_runtime(self) -> None:
        command = claude_keychain_macos._worker_command(7)

        self.assertTrue(pathlib.Path(command[0]).is_absolute())
        self.assertEqual(command[1:3], ("-I", "-S"))
        self.assertTrue(pathlib.Path(command[3]).is_absolute())
        self.assertEqual(
            command[4:],
            (claude_keychain_macos._KEYCHAIN_WORKER_FLAG, "7"),
        )

    def test_supervisor_rejects_invalid_timeouts_before_spawning(self) -> None:
        invalid_timeouts = (
            True,
            0.0,
            -1.0,
            float("nan"),
            float("inf"),
            claude_keychain_macos._KEYCHAIN_WORKER_SELF_DESTRUCT_SECONDS + 1,
        )
        with mock.patch.object(
            claude_keychain_macos.socket,
            "socketpair",
        ) as socketpair:
            for timeout in invalid_timeouts:
                with (
                    self.subTest(timeout=timeout),
                    self.assertRaises(claude_keychain_macos.MacOSKeychainUnsafe),
                ):
                    claude_keychain_macos._run_supervised_keychain_operation(
                        operation="read",
                        account=ACCOUNT,
                        service=SERVICE,
                        timeout_seconds=timeout,
                    )
        socketpair.assert_not_called()

    def test_supervisor_defers_control_flow_only_after_replace_dispatch(
        self,
    ) -> None:
        cases = (
            ("before-dispatch", 2, None, ForwardedSignal(signal.SIGTERM)),
            ("after-dispatch", 3, None, ForwardedSignal(signal.SIGTERM)),
            ("after-dispatch-keyboard", 3, None, KeyboardInterrupt()),
            (
                "after-dispatch-reap-inconclusive",
                3,
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive(
                    "synthetic reap failure"
                ),
                KeyboardInterrupt(),
            ),
        )
        for label, interrupted_call, termination_failure, interruption in cases:
            with self.subTest(label=label):
                parent_connection = mock.Mock()
                child_connection = mock.Mock()
                child_connection.fileno.return_value = 7
                process = mock.Mock(pid=43212)
                process.poll.return_value = None
                send_calls = 0

                def send_frame(*_args: object, **_kwargs: object) -> None:
                    nonlocal send_calls
                    send_calls += 1
                    if send_calls == interrupted_call:
                        raise interruption

                with (
                    mock.patch.object(
                        claude_keychain_macos.socket,
                        "socketpair",
                        return_value=(parent_connection, child_connection),
                    ),
                    mock.patch.object(
                        claude_keychain_macos,
                        "_worker_command",
                        return_value=("/usr/bin/true",),
                    ),
                    mock.patch.object(
                        claude_keychain_macos.subprocess,
                        "Popen",
                        return_value=process,
                    ),
                    mock.patch.object(
                        claude_keychain_macos,
                        "_send_worker_frame",
                        side_effect=send_frame,
                    ),
                    mock.patch.object(
                        claude_keychain_macos,
                        "_kill_and_reap_worker",
                        side_effect=termination_failure,
                    ) as kill_worker,
                ):
                    if interrupted_call == 2:
                        with self.assertRaises(type(interruption)) as raised:
                            claude_keychain_macos._run_supervised_keychain_operation(
                                operation="replace",
                                account=ACCOUNT,
                                service=SERVICE,
                                expected=b"before",
                                replacement=b"after",
                                expected_identity=worker_identity(),
                            )
                        self.assertIs(raised.exception, interruption)
                    elif termination_failure is not None:
                        with self.assertRaises(
                            claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
                        ) as raised:
                            claude_keychain_macos._run_supervised_keychain_operation(
                                operation="replace",
                                account=ACCOUNT,
                                service=SERVICE,
                                expected=b"before",
                                replacement=b"after",
                                expected_identity=worker_identity(),
                            )
                        self.assertIs(raised.exception, termination_failure)
                        self.assertIs(raised.exception.__cause__, interruption)
                    else:
                        with self.assertRaises(
                            claude_keychain_macos.MacOSKeychainWriteOutcomeUnknown
                        ) as raised:
                            claude_keychain_macos._run_supervised_keychain_operation(
                                operation="replace",
                                account=ACCOUNT,
                                service=SERVICE,
                                expected=b"before",
                                replacement=b"after",
                                expected_identity=worker_identity(),
                            )
                        self.assertIs(raised.exception.__cause__, interruption)

                kill_worker.assert_called_once_with(process)

    def test_cleanup_poll_interruption_is_termination_inconclusive(self) -> None:
        process = mock.Mock(pid=43213)
        poll_interruption = KeyboardInterrupt()
        process.poll.side_effect = poll_interruption
        primary = ForwardedSignal(signal.SIGTERM)
        dispatch_state = claude_keychain_macos._WorkerDispatchState()

        with self.assertRaises(
            claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
        ) as raised:
            claude_keychain_macos._cleanup_supervised_keychain_worker(
                process=process,
                connections=(),
                payloads=(),
                primary=primary,
                dispatch_state=dispatch_state,
            )

        process.poll.assert_called_once_with()
        self.assertTrue(dispatch_state.worker_spawned)
        self.assertFalse(dispatch_state.worker_termination_proven)
        self.assertIs(dispatch_state.worker_termination_failure, raised.exception)
        self.assertIs(raised.exception.__cause__, primary)
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(any("KeyboardInterrupt" in note for note in notes))

    def test_cleanup_termination_failure_overrides_keyboard_interrupt(
        self,
    ) -> None:
        process = mock.Mock(pid=43214)
        process.poll.return_value = None
        primary = KeyboardInterrupt()
        termination_failure = (
            claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive(
                "synthetic reap failure"
            )
        )
        dispatch_state = claude_keychain_macos._WorkerDispatchState()

        with (
            mock.patch.object(
                claude_keychain_macos,
                "_kill_and_reap_worker",
                side_effect=termination_failure,
            ),
            self.assertRaises(
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
            ) as raised,
        ):
            claude_keychain_macos._cleanup_supervised_keychain_worker(
                process=process,
                connections=(),
                payloads=(),
                primary=primary,
                dispatch_state=dispatch_state,
            )

        self.assertIs(raised.exception, termination_failure)
        self.assertIs(raised.exception.__cause__, primary)
        self.assertIs(dispatch_state.worker_termination_failure, termination_failure)

    def test_cleanup_preserves_control_flow_from_termination_cause(self) -> None:
        process = mock.Mock(pid=43216)
        process.poll.return_value = None
        primary = RuntimeError("synthetic primary failure")
        interruption = KeyboardInterrupt()
        termination_failure = (
            claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive(
                "synthetic reap failure"
            )
        )
        termination_failure.__cause__ = interruption
        dispatch_state = claude_keychain_macos._WorkerDispatchState()

        with (
            mock.patch.object(
                claude_keychain_macos,
                "_kill_and_reap_worker",
                side_effect=termination_failure,
            ),
            self.assertRaises(
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
            ) as raised,
        ):
            claude_keychain_macos._cleanup_supervised_keychain_worker(
                process=process,
                connections=(),
                payloads=(),
                primary=primary,
                dispatch_state=dispatch_state,
            )

        self.assertIs(raised.exception, termination_failure)
        self.assertIs(raised.exception.__cause__, interruption)

    def test_supervisor_promotes_cleanup_gap_when_worker_is_unproven(self) -> None:
        interruption = ForwardedSignal(signal.SIGTERM)
        termination_failure = (
            claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive(
                "synthetic reap failure"
            )
        )

        def interrupt_after_cleanup_state(**kwargs: object) -> None:
            dispatch_state = kwargs["dispatch_state"]
            assert isinstance(
                dispatch_state,
                claude_keychain_macos._WorkerDispatchState,
            )
            dispatch_state.replacement_dispatched = True
            dispatch_state.worker_spawned = True
            dispatch_state.worker_termination_failure = termination_failure
            raise interruption

        with (
            mock.patch.object(
                claude_keychain_macos,
                "_run_supervised_keychain_operation_once",
                side_effect=interrupt_after_cleanup_state,
            ),
            self.assertRaises(
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
            ) as raised,
        ):
            claude_keychain_macos._run_supervised_keychain_operation(
                operation="replace",
                account=ACCOUNT,
                service=SERVICE,
                expected=b"before",
                replacement=b"after",
                expected_identity=worker_identity(),
            )

        self.assertIs(raised.exception, termination_failure)
        self.assertIs(raised.exception.__cause__, interruption)

    def test_cleanup_consumes_pending_signal_before_restoring_mask(self) -> None:
        process = mock.Mock(pid=43215)
        process.poll.return_value = 0
        pending = ForwardedSignal(signal.SIGTERM)
        dispatch_state = claude_keychain_macos._WorkerDispatchState()

        with (
            mock.patch.object(
                claude_keychain_macos.signal,
                "pthread_sigmask",
                side_effect=(set(), set()),
            ) as pthread_sigmask,
            mock.patch.object(
                claude_keychain_macos,
                "_consume_pending_supervisor_signal",
                return_value=signal.SIGTERM,
            ) as consume_pending,
            mock.patch.object(
                claude_keychain_macos,
                "_forwarded_signal_error",
                return_value=pending,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            claude_keychain_macos._cleanup_supervised_keychain_worker(
                process=process,
                connections=(),
                payloads=(),
                primary=None,
                dispatch_state=dispatch_state,
            )

        self.assertIs(raised.exception, pending)
        self.assertTrue(dispatch_state.worker_termination_proven)
        consume_pending.assert_called_once_with()
        self.assertEqual(pthread_sigmask.call_count, 2)
        self.assertEqual(pthread_sigmask.call_args_list[0].args[0], signal.SIG_BLOCK)
        self.assertEqual(
            pthread_sigmask.call_args_list[1],
            mock.call(signal.SIG_SETMASK, set()),
        )

    def test_worker_reap_failure_is_terminal_and_keeps_background_reaper(
        self,
    ) -> None:
        process = mock.Mock(pid=43210)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired(
            cmd=("synthetic-worker",),
            timeout=claude_keychain_macos._KEYCHAIN_WORKER_KILL_GRACE_SECONDS,
        )
        reaper = mock.Mock()
        with (
            mock.patch.object(claude_keychain_macos.os, "killpg") as kill_group,
            mock.patch.object(
                claude_keychain_macos.threading,
                "Thread",
                return_value=reaper,
            ) as thread,
            self.assertRaises(
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive
            ),
        ):
            claude_keychain_macos._kill_and_reap_worker(process)

        kill_group.assert_called_once_with(process.pid, signal.SIGKILL)
        thread.assert_called_once_with(
            target=claude_keychain_macos._background_reap_worker,
            args=(process,),
            daemon=True,
        )
        reaper.start.assert_called_once_with()

        process = mock.Mock(pid=43211)
        process.poll.return_value = None
        process.kill.side_effect = PermissionError("synthetic kill denial")
        with (
            mock.patch.object(
                claude_keychain_macos.os,
                "killpg",
                side_effect=PermissionError("synthetic group kill denial"),
            ),
            self.assertRaisesRegex(
                claude_keychain_macos.MacOSKeychainWorkerTerminationInconclusive,
                "cannot terminate",
            ),
        ):
            claude_keychain_macos._kill_and_reap_worker(process)
        process.wait.assert_not_called()

    def test_native_backend_disables_ui_before_access_and_restores_after_cleanup(
        self,
    ) -> None:
        events: list[tuple[str, int | None]] = []
        security = mock.Mock()
        for name in (
            "SecKeychainFindGenericPassword",
            "SecKeychainItemModifyAttributesAndData",
            "SecKeychainItemCopyContent",
            "SecKeychainItemFreeContent",
        ):
            setattr(security, name, mock.Mock(return_value=0))

        def get_interaction(output: object) -> int:
            events.append(("get-ui", None))
            state = ctypes.cast(output, ctypes.POINTER(ctypes.c_ubyte))
            state.contents.value = 1
            return 0

        def set_interaction(state: ctypes.c_ubyte) -> int:
            events.append(("set-ui", int(state.value)))
            return 0

        def open_keychain(path: object, output: object) -> int:
            del path
            events.append(("open", None))
            reference = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
            reference.contents.value = 0xCAFE
            return 0

        security.SecKeychainGetUserInteractionAllowed = mock.Mock(
            side_effect=get_interaction
        )
        security.SecKeychainSetUserInteractionAllowed = mock.Mock(
            side_effect=set_interaction
        )
        security.SecKeychainOpen = mock.Mock(side_effect=open_keychain)
        core_foundation = mock.Mock()
        core_foundation.CFRelease = mock.Mock(
            side_effect=lambda reference: events.append(("release", None))
        )

        with (
            mock.patch.object(claude_keychain_macos.sys, "platform", "darwin"),
            mock.patch.object(
                claude_keychain_macos.ctypes,
                "CDLL",
                side_effect=(security, core_foundation),
            ),
        ):
            backend = claude_keychain_macos._CtypesSecurityBackend()
            keychain = backend.open_keychain(
                pathlib.Path("/synthetic/login.keychain-db")
            )
            backend.release_keychain(keychain)
            backend.restore_user_interaction()
            backend.restore_user_interaction()

        self.assertEqual(
            events,
            [
                ("get-ui", None),
                ("set-ui", 0),
                ("open", None),
                ("release", None),
                ("set-ui", 1),
            ],
        )
        self.assertEqual(
            security.SecKeychainSetUserInteractionAllowed.argtypes,
            [ctypes.c_ubyte],
        )
        self.assertEqual(
            security.SecKeychainGetUserInteractionAllowed.argtypes,
            [ctypes.POINTER(ctypes.c_ubyte)],
        )

    def test_native_backend_fails_closed_on_ui_policy_errors(self) -> None:
        def frameworks(
            *,
            get_status: int = 0,
            set_statuses: tuple[int, ...] = (0,),
        ) -> tuple[object, object]:
            security = mock.Mock()
            for name in (
                "SecKeychainOpen",
                "SecKeychainFindGenericPassword",
                "SecKeychainItemModifyAttributesAndData",
                "SecKeychainItemCopyContent",
                "SecKeychainItemFreeContent",
            ):
                setattr(security, name, mock.Mock(return_value=0))

            def get_interaction(output: object) -> int:
                if get_status == 0:
                    state = ctypes.cast(output, ctypes.POINTER(ctypes.c_ubyte))
                    state.contents.value = 1
                return get_status

            statuses = iter(set_statuses)
            security.SecKeychainGetUserInteractionAllowed = mock.Mock(
                side_effect=get_interaction
            )
            security.SecKeychainSetUserInteractionAllowed = mock.Mock(
                side_effect=lambda state: next(statuses)
            )
            core_foundation = mock.Mock()
            core_foundation.CFRelease = mock.Mock()
            return security, core_foundation

        for get_status, set_statuses, expected_message in (
            (-50, (0,), "inspect native Keychain user interaction"),
            (0, (-51,), "disable native Keychain user interaction"),
        ):
            security, core_foundation = frameworks(
                get_status=get_status,
                set_statuses=set_statuses,
            )
            with (
                self.subTest(expected_message=expected_message),
                mock.patch.object(claude_keychain_macos.sys, "platform", "darwin"),
                mock.patch.object(
                    claude_keychain_macos.ctypes,
                    "CDLL",
                    side_effect=(security, core_foundation),
                ),
                self.assertRaisesRegex(
                    claude_keychain_macos.MacOSKeychainInspectionInconclusive,
                    expected_message,
                ),
            ):
                claude_keychain_macos._CtypesSecurityBackend()

        security, core_foundation = frameworks(set_statuses=(0, -52))
        with (
            mock.patch.object(claude_keychain_macos.sys, "platform", "darwin"),
            mock.patch.object(
                claude_keychain_macos.ctypes,
                "CDLL",
                side_effect=(security, core_foundation),
            ),
        ):
            backend = claude_keychain_macos._CtypesSecurityBackend()
            with self.assertRaisesRegex(
                claude_keychain_macos.MacOSKeychainInspectionInconclusive,
                "restore native Keychain user interaction",
            ):
                backend.restore_user_interaction()

    def test_worker_scrubs_request_and_result_buffers_before_restoring_ui(self) -> None:
        identity = worker_identity()
        result_payload = bytearray(b"credential-result")
        request = claude_keychain_macos._WorkerRequest(
            operation="read",
            account=ACCOUNT,
            service=SERVICE,
            expected=bytearray(),
            replacement=bytearray(),
            expected_identity=None,
        )
        events: list[str] = []
        backend = mock.Mock()
        backend.restore_user_interaction.side_effect = lambda: events.append(
            "restore-ui"
        )
        runtime = mock.Mock(backend=backend)

        def send_response(
            connection: object,
            metadata: dict[str, object],
            payload: bytearray | None,
            *,
            deadline: float,
        ) -> None:
            del connection, metadata, deadline
            self.assertEqual(payload, b"credential-result")
            events.append("send")

        with (
            mock.patch.object(
                claude_keychain_macos,
                "_receive_worker_request",
                return_value=request,
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_login_keychain_runtime",
                return_value=runtime,
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_read_with_runtime",
                return_value=(result_payload, identity),
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_send_worker_response",
                side_effect=send_response,
            ),
        ):
            self.assertEqual(
                claude_keychain_macos._serve_keychain_worker(mock.Mock()),
                0,
            )

        self.assertEqual(result_payload, b"\x00" * len(result_payload))
        self.assertEqual(events, ["send", "restore-ui"])

        expected = bytearray(b"credential-before")
        replacement = bytearray(b"credential-after")
        request = claude_keychain_macos._WorkerRequest(
            operation="replace",
            account=ACCOUNT,
            service=SERVICE,
            expected=expected,
            replacement=replacement,
            expected_identity=identity,
        )
        backend.reset_mock()
        with (
            mock.patch.object(
                claude_keychain_macos,
                "_receive_worker_request",
                return_value=request,
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_login_keychain_runtime",
                return_value=runtime,
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_replace_with_runtime",
                return_value=identity,
            ),
            mock.patch.object(
                claude_keychain_macos,
                "_send_worker_response",
            ),
        ):
            self.assertEqual(
                claude_keychain_macos._serve_keychain_worker(mock.Mock()),
                0,
            )
        self.assertEqual(expected, b"\x00" * len(expected))
        self.assertEqual(replacement, b"\x00" * len(replacement))
        backend.restore_user_interaction.assert_called_once_with()

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_supervisor_hard_timeout_kills_reaps_and_hides_credentials(
        self,
    ) -> None:
        helper_source = """\
import os
import signal
import socket
import sys

if os.getcwd() != "/" or len(sys.argv) != 2:
    raise SystemExit(91)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
connection = socket.socket(fileno=int(sys.argv[1]))
while connection.recv(4096):
    pass
signal.pause()
"""
        identity = worker_identity()
        expected = b"credential-surface-before"
        replacement = bytearray(b"credential-surface-sentinel")
        real_popen = subprocess.Popen
        real_send_frame = claude_keychain_macos._send_worker_frame

        with tempfile.TemporaryDirectory() as temporary:
            helper = pathlib.Path(temporary) / "blocking_worker.py"
            helper.write_text(helper_source, encoding="utf-8")
            for operation in ("read", "replace"):
                processes: list[subprocess.Popen[bytes]] = []
                popen_surfaces: list[tuple[object, dict[str, object]]] = []
                secret_copies: list[bytearray] = []

                def command(descriptor: int) -> tuple[str, ...]:
                    return (
                        os.fspath(pathlib.Path(sys.executable).resolve()),
                        "-I",
                        "-S",
                        os.fspath(helper),
                        str(descriptor),
                    )

                def spawn(
                    worker_command: object,
                    **kwargs: object,
                ) -> subprocess.Popen[bytes]:
                    popen_surfaces.append((worker_command, dict(kwargs)))
                    process = real_popen(worker_command, **kwargs)
                    processes.append(process)
                    return process

                def send_frame(
                    connection: socket.socket,
                    payload: bytes | bytearray | memoryview,
                    *,
                    maximum_bytes: int,
                    deadline: float,
                ) -> None:
                    if isinstance(payload, bytearray) and bytes(payload) in {
                        expected,
                        bytes(replacement),
                    }:
                        secret_copies.append(payload)
                    real_send_frame(
                        connection,
                        payload,
                        maximum_bytes=maximum_bytes,
                        deadline=deadline,
                    )

                started = time.monotonic()
                with (
                    self.subTest(operation=operation),
                    mock.patch.object(
                        claude_keychain_macos,
                        "_worker_command",
                        side_effect=command,
                    ),
                    mock.patch.object(
                        claude_keychain_macos.subprocess,
                        "Popen",
                        side_effect=spawn,
                    ),
                    mock.patch.object(
                        claude_keychain_macos,
                        "_send_worker_frame",
                        side_effect=send_frame,
                    ),
                    self.assertRaises(
                        claude_keychain_macos.MacOSKeychainInspectionInconclusive
                    ) as raised,
                ):
                    claude_keychain_macos._run_supervised_keychain_operation(
                        operation=operation,
                        account=ACCOUNT,
                        service=SERVICE,
                        expected=expected if operation == "replace" else b"",
                        replacement=(replacement if operation == "replace" else b""),
                        expected_identity=(
                            identity if operation == "replace" else None
                        ),
                        timeout_seconds=0.5,
                    )
                elapsed = time.monotonic() - started

                self.assertLess(elapsed, 4.0)
                self.assertEqual(len(processes), 1)
                self.assertEqual(processes[0].poll(), -signal.SIGKILL)
                self.assertEqual(len(popen_surfaces), 1)
                worker_command, kwargs = popen_surfaces[0]
                visible = repr((worker_command, kwargs)).encode()
                self.assertNotIn(expected, visible)
                self.assertNotIn(bytes(replacement), visible)
                self.assertEqual(kwargs["cwd"], "/")
                self.assertEqual(kwargs["env"], {})
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertTrue(kwargs["close_fds"])
                self.assertTrue(kwargs["start_new_session"])
                if operation == "replace":
                    self.assertIsInstance(
                        raised.exception,
                        claude_keychain_macos.MacOSKeychainWriteOutcomeUnknown,
                    )
                    self.assertEqual(len(secret_copies), 2)
                    for secret_copy in secret_copies:
                        self.assertEqual(secret_copy, b"\x00" * len(secret_copy))
                else:
                    self.assertNotIsInstance(
                        raised.exception,
                        claude_keychain_macos.MacOSKeychainWriteOutcomeUnknown,
                    )

        replacement[:] = b"\x00" * len(replacement)

    def test_non_darwin_public_api_fails_closed_before_path_access(self) -> None:
        with (
            mock.patch.object(claude_keychain_macos.sys, "platform", "linux"),
            mock.patch.object(
                claude_keychain_macos,
                "_run_supervised_keychain_operation",
            ) as supervisor,
        ):
            with self.assertRaises(claude_keychain_macos.MacOSKeychainUnavailable):
                claude_keychain_macos.read_login_keychain_credential(
                    ACCOUNT,
                    SERVICE,
                )
            with self.assertRaises(claude_keychain_macos.MacOSKeychainUnavailable):
                claude_keychain_macos.replace_login_keychain_credential(
                    ACCOUNT,
                    SERVICE,
                    b"credential-before",
                    b"credential-after",
                    worker_identity(),
                )
        supervisor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
