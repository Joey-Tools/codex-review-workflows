from __future__ import annotations

import dis
import ctypes
import errno
import os
import pathlib
import shutil
import signal
import stat
import sys
import time
import unittest
from dataclasses import replace
from unittest import mock

import review_supervisor.gitraw as gitraw
import review_supervisor.recovery_cleanup as recovery_cleanup
import review_supervisor.runtime as runtime
import review_supervisor.secureio as secureio
from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.gitraw import (
    add_detached_worktree,
    create_sanitized_view,
    enumerate_registration,
    initialize_index,
    inspect_repository,
    remove_both_present_worktree,
)
from review_supervisor.ledger import (
    acquire_retention_lease,
    open_attempt_lease,
    read_attempt_state,
)
from review_supervisor.models import Identity
from review_supervisor.recovery_cleanup import (
    _KIND_DIRECTORY,
    CustodiedDeletionResultOwner,
    CustodiedManifestResultOwner,
    CustodyLostError,
    QuarantinedRootRecoveryEvidence,
    RootSpec,
    _index_manifest_records,
    build_custodied_manifest,
    delete_custodied_roots,
    quarantine_and_remove_empty_root,
    quarantined_root_recovery_evidence,
)
from review_supervisor.runtime import _cleanup_worktree, _registration_json
from review_supervisor.secureio import (
    MAX_LEAF_XATTR_TOTAL_BYTES,
    MAX_LEAF_XATTR_VALUE_BYTES,
    MacOSDirectoryMetadataBinding,
    canonical_json,
    directory_identities_match,
    identity_from_stat,
    macos_leaf_metadata_digest,
)
from review_supervisor.signal_relay import (
    DeferredSignalInterrupt,
    activate_deferred_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)

from tests.support import (
    SUPERVISOR_INTERNAL_CHILD_FIXTURE,
    _remove_exact_test_entry,
    _test_entry_object_identity,
    bind_attempt_state,
    owned_temporary_directory,
)
from tests.test_git_checkout import GIT, _build_repository

ENTRYPOINT = SUPERVISOR_INTERNAL_CHILD_FIXTURE


class _DeferredLeafSignal(BaseException):
    pass


class _StatOverride:
    def __init__(self, original: os.stat_result, **overrides: int) -> None:
        self._original = original
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._original, name)


def _set_macos_fd_xattr(fd: int, name: str, value: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fsetxattr = libc.fsetxattr
    fsetxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    fsetxattr.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(value)
    ctypes.set_errno(0)
    if fsetxattr(fd, name.encode("utf-8"), buffer, len(value), 0, 0) != 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "cannot set test xattr")


def _call_followup_offset(
    function: object,
    *,
    called_name: str,
    following_opname: str,
    following_argval: str | None = None,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        if not any(candidate.argval == called_name for candidate in prior):
            continue
        following = instructions[index + 1]
        if following.opname != following_opname:
            continue
        if following_argval is None or following.argval == following_argval:
            return following.offset
    raise AssertionError(
        f"cannot find {called_name} CALL-to-{following_opname} boundary"
    )


def _instruction_after_offset(function: object, offset: int) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions[:-1]):
        if instruction.offset == offset:
            return instructions[index + 1].offset
    raise AssertionError(f"cannot find instruction after offset {offset}")


def _instruction_before_offset(function: object, offset: int) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions[1:], start=1):
        if instruction.offset == offset:
            return instructions[index - 1].offset
    raise AssertionError(f"cannot find instruction before offset {offset}")


def _call_opcode_offsets(
    function: object,
    *,
    called_name: str,
    following_opname: str,
    following_argval: str | None = None,
) -> tuple[int, ...]:
    instructions = tuple(dis.get_instructions(function))
    matches: list[int] = []
    for index, instruction in enumerate(instructions[:-1]):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        following = instructions[index + 1]
        if not any(candidate.argval == called_name for candidate in prior):
            continue
        if following.opname != following_opname:
            continue
        if following_argval is not None and following.argval != following_argval:
            continue
        matches.append(instruction.offset)
    if not matches:
        raise AssertionError(
            f"cannot find {called_name} CALL before {following_opname}"
        )
    return tuple(matches)


def _direct_call_opcode_offsets(
    function: object,
    *,
    called_name: str,
) -> tuple[int, ...]:
    """Locate CALLs whose current operand-loading segment names the callee."""

    instructions = tuple(dis.get_instructions(function))
    matches: list[int] = []
    previous_call_index = -1
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        operands = instructions[previous_call_index + 1 : index]
        if any(candidate.argval == called_name for candidate in operands):
            matches.append(instruction.offset)
        previous_call_index = index
    if not matches:
        raise AssertionError(f"cannot find direct CALL for {called_name}")
    return tuple(matches)


class _CountingRecord:
    def __init__(
        self,
        *,
        path: bytes,
        identity: Identity,
        counters: dict[str, int],
    ) -> None:
        self.root_index = 0
        self.kind = _KIND_DIRECTORY
        self.identity = identity
        self._path = path
        self._counters = counters

    @property
    def path(self) -> bytes:
        self._counters["path_reads"] += 1
        return self._path


class _CountingRecords:
    def __init__(self, records: list[_CountingRecord], counters: dict[str, int]):
        self._records = records
        self._counters = counters

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        self._counters["iterations"] += 1
        return iter(self._records)


class ManifestTraversalTests(unittest.TestCase):
    def _build_empty_manifest(
        self,
        root: pathlib.Path,
        *names: str,
    ) -> tuple[recovery_cleanup.CustodiedManifest, int]:
        parent = root / "parent"
        parent.mkdir(mode=0o700)
        control = root / "control"
        control.mkdir(mode=0o700)
        parent_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        roots: list[RootSpec] = []
        for name in names:
            target = parent / name
            target.mkdir(mode=0o700)
            roots.append(
                RootSpec(
                    label=f"close-{name}",
                    parent_fd=parent_fd,
                    parent_identity=identity_from_stat(os.fstat(parent_fd)),
                    name=os.fsencode(name),
                    expected_identity=identity_from_stat(os.stat(target)),
                )
            )
        manifest = build_custodied_manifest(
            roots=tuple(roots),
            manifest_path=control / "manifest.bin",
            entry_cap=10,
            payload_cap=4096,
            deadline=time.monotonic() + 5.0,
        )
        return manifest, parent_fd

    def _build_target_manifest(
        self,
        root: pathlib.Path,
        target: pathlib.Path,
        *,
        label: str,
    ) -> tuple[recovery_cleanup.CustodiedManifest, int]:
        control = root / "control"
        control.mkdir(mode=0o700, exist_ok=True)
        parent_fd = os.open(
            target.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label=label,
                        parent_fd=parent_fd,
                        parent_identity=identity_from_stat(os.fstat(parent_fd)),
                        name=os.fsencode(target.name),
                        expected_identity=identity_from_stat(os.stat(target)),
                    ),
                ),
                manifest_path=control / f"{label}.manifest.bin",
                entry_cap=20,
                payload_cap=8192,
                deadline=time.monotonic() + 5.0,
            )
        except BaseException:
            os.close(parent_fd)
            raise
        return manifest, parent_fd

    def _assert_descriptor_is_closed(self, descriptor: int) -> None:
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_manifest_root_open_call_to_store_retains_exact_owner(self) -> None:
        with owned_temporary_directory("manifest-root-open-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_offset = _call_followup_offset(
                build_custodied_manifest,
                called_name="_open_custodied_directory_descriptor",
                following_opname="STORE_FAST",
                following_argval="root_fd",
            )
            interruption = KeyboardInterrupt("manifest root open result interrupt")
            captured_fd: int | None = None
            injected = False
            real_open = os.open

            def tracking_open(*args: object, **kwargs: object) -> int:
                nonlocal captured_fd
                descriptor = real_open(*args, **kwargs)
                if args and args[0] == b"target" and kwargs.get("dir_fd") == parent_fd:
                    captured_fd = descriptor
                return descriptor

            def interrupt_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is build_custodied_manifest.__code__:
                    frame.f_trace_opcodes = True
                    if (
                        not injected
                        and event == "opcode"
                        and frame.f_lasti == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_store

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    recovery_cleanup.os,
                    "open",
                    side_effect=tracking_open,
                ):
                    sys.settrace(interrupt_store)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        build_custodied_manifest(
                            roots=(
                                RootSpec(
                                    label="root-open-owner",
                                    parent_fd=parent_fd,
                                    parent_identity=identity_from_stat(
                                        os.fstat(parent_fd)
                                    ),
                                    name=b"target",
                                    expected_identity=identity_from_stat(
                                        os.stat(target)
                                    ),
                                ),
                            ),
                            manifest_path=control / "manifest.bin",
                            entry_cap=10,
                            payload_cap=4096,
                            deadline=time.monotonic() + 5.0,
                        )
            finally:
                sys.settrace(previous_trace)
                os.close(parent_fd)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertIsNotNone(captured_fd)
            assert captured_fd is not None
            self._assert_descriptor_is_closed(captured_fd)
            owners = recovery_cleanup.directory_descriptor_custody_owners(
                caught.exception
            )
            root_owner = next(
                owner
                for owner in owners
                if owner.purpose == "manifest-root:root-open-owner"
            )
            self.assertEqual(root_owner.state, "closed")
            self.assertIsNone(root_owner.descriptor)

    def test_manifest_child_open_call_to_store_retains_exact_owner(self) -> None:
        with owned_temporary_directory("manifest-child-open-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir(mode=0o700)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_offset = _call_followup_offset(
                recovery_cleanup._enumerate_directory,
                called_name="_open_custodied_directory_descriptor",
                following_opname="STORE_FAST",
                following_argval="child_fd",
            )
            interruption = KeyboardInterrupt("manifest child open result interrupt")
            captured_fd: int | None = None
            injected = False
            real_open = os.open

            def tracking_open(*args: object, **kwargs: object) -> int:
                nonlocal captured_fd
                descriptor = real_open(*args, **kwargs)
                if args and args[0] == b"nested":
                    captured_fd = descriptor
                return descriptor

            def interrupt_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._enumerate_directory.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not injected
                        and event == "opcode"
                        and frame.f_lasti == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_store

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    recovery_cleanup.os,
                    "open",
                    side_effect=tracking_open,
                ):
                    sys.settrace(interrupt_store)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        build_custodied_manifest(
                            roots=(
                                RootSpec(
                                    label="child-open-owner",
                                    parent_fd=parent_fd,
                                    parent_identity=identity_from_stat(
                                        os.fstat(parent_fd)
                                    ),
                                    name=b"target",
                                    expected_identity=identity_from_stat(
                                        os.stat(target)
                                    ),
                                ),
                            ),
                            manifest_path=control / "manifest.bin",
                            entry_cap=10,
                            payload_cap=4096,
                            deadline=time.monotonic() + 5.0,
                        )
            finally:
                sys.settrace(previous_trace)
                os.close(parent_fd)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertIsNotNone(captured_fd)
            assert captured_fd is not None
            self._assert_descriptor_is_closed(captured_fd)
            owners = recovery_cleanup.directory_descriptor_custody_owners(
                caught.exception
            )
            child_owner = next(
                owner
                for owner in owners
                if owner.purpose.startswith("manifest-enumeration:")
            )
            self.assertEqual(child_owner.state, "closed")
            self.assertIsNone(child_owner.descriptor)

    def test_recursive_child_open_call_to_store_retains_exact_owner(self) -> None:
        with owned_temporary_directory("delete-child-open-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir(mode=0o700)
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="recursive-child-open-owner",
            )
            target_offset = _call_followup_offset(
                recovery_cleanup._delete_directory_contents,
                called_name="_open_custodied_directory_descriptor",
                following_opname="STORE_FAST",
                following_argval="child_fd",
            )
            interruption = KeyboardInterrupt("recursive child open result interrupt")
            captured_fd: int | None = None
            injected = False
            real_open = os.open

            def tracking_open(*args: object, **kwargs: object) -> int:
                nonlocal captured_fd
                descriptor = real_open(*args, **kwargs)
                if args and args[0] == b"nested":
                    captured_fd = descriptor
                return descriptor

            def interrupt_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_directory_contents.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not injected
                        and event == "opcode"
                        and frame.f_lasti == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_store

            result_owner = CustodiedDeletionResultOwner()
            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    recovery_cleanup.os,
                    "open",
                    side_effect=tracking_open,
                ):
                    sys.settrace(interrupt_store)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        delete_custodied_roots(
                            manifest,
                            result_owner=result_owner,
                        )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertIsNotNone(captured_fd)
                assert captured_fd is not None
                self._assert_descriptor_is_closed(captured_fd)
                owners = recovery_cleanup.directory_descriptor_custody_owners(
                    caught.exception
                )
                child_owner = next(
                    owner
                    for owner in owners
                    if owner.purpose.startswith("recursive-delete:")
                )
                self.assertEqual(child_owner.state, "closed")
                self.assertIsNone(child_owner.descriptor)
                self.assertIn(child_owner, result_owner.directory_cleanup_owners)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_directory_close_pre_and_post_call_ambiguity_is_terminal(self) -> None:
        close_method = recovery_cleanup._CustodiedManifestDescriptorSlot.close_one_shot
        instructions = tuple(dis.get_instructions(close_method))
        close_call_indexes = tuple(
            index
            for index, instruction in enumerate(instructions[:-1])
            if instruction.opname.startswith("CALL")
            and instructions[index + 1].opname == "POP_TOP"
            and any(
                candidate.argval == "close"
                for candidate in instructions[max(0, index - 4) : index]
            )
        )
        self.assertEqual(len(close_call_indexes), 1)
        close_call_index = close_call_indexes[0]
        close_call_offset = instructions[close_call_index].offset
        close_discard_offset = instructions[close_call_index + 1].offset
        cases = (
            (
                "pre-call",
                close_call_offset,
                True,
            ),
            (
                "post-call",
                _instruction_after_offset(close_method, close_discard_offset),
                False,
            ),
        )
        with owned_temporary_directory("directory-close-ambiguity-") as root:
            expected_identity = identity_from_stat(os.stat(root))
            for name, target_offset, remains_open in cases:
                with self.subTest(name=name):
                    descriptor = os.open(
                        root,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                    owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                        purpose=f"close-{name}",
                        expected_identity=expected_identity,
                    )
                    owner.publish(descriptor)
                    interruption = KeyboardInterrupt(f"directory close {name}")
                    injected = False

                    def interrupt_close(
                        frame: object,
                        event: str,
                        _argument: object,
                        target_offset: int = target_offset,
                    ) -> object:
                        nonlocal injected
                        if getattr(frame, "f_code", None) is close_method.__code__:
                            frame.f_trace_opcodes = True
                            if (
                                not injected
                                and event == "opcode"
                                and frame.f_lasti == target_offset
                            ):
                                injected = True
                                raise interruption
                        return interrupt_close

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_close)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            owner.close_one_shot()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertTrue(injected)
                    self.assertIs(caught.exception, interruption)
                    self.assertEqual(owner.state, "close-outcome-unproven")
                    self.assertIs(owner.close_error, interruption)
                    self.assertIn(
                        owner,
                        recovery_cleanup.directory_descriptor_custody_owners(
                            caught.exception
                        ),
                    )
                    self.assertIs(
                        recovery_cleanup._settle_directory_descriptor_owner(owner),
                        None,
                    )
                    self.assertEqual(owner.state, "close-outcome-unproven")
                    if remains_open:
                        os.fstat(descriptor)
                        os.close(descriptor)
                    else:
                        self._assert_descriptor_is_closed(descriptor)

    def test_directory_close_rejects_reused_descriptor_without_closing_it(
        self,
    ) -> None:
        with owned_temporary_directory("directory-close-reuse-") as root:
            descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                purpose="reused-directory-descriptor",
                expected_identity=identity_from_stat(os.fstat(descriptor)),
            )
            owner.publish(descriptor)
            os.close(descriptor)
            replacement = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            if replacement != descriptor:
                os.dup2(replacement, descriptor)
                os.close(replacement)
            try:
                with self.assertRaisesRegex(
                    CustodyLostError,
                    "identity changed before close",
                ) as caught:
                    owner.close_one_shot()
                self.assertEqual(owner.state, "identity-mismatch-before-close")
                self.assertEqual(owner.descriptor, descriptor)
                self.assertIs(owner.close_error, caught.exception)
                os.fstat(descriptor)
            finally:
                os.close(descriptor)

    def test_manifest_child_settlement_call_boundary_uses_build_owner(self) -> None:
        with owned_temporary_directory("manifest-child-settle-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir(mode=0o700)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            settle_offset = _call_opcode_offsets(
                recovery_cleanup._enumerate_directory,
                called_name="_settle_directory_descriptor_owner",
                following_opname="STORE_FAST",
                following_argval="selected",
            )[0]
            interruption = KeyboardInterrupt("manifest child settlement boundary")
            injected = False

            def interrupt_settlement(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._enumerate_directory.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not injected
                        and event == "opcode"
                        and frame.f_lasti == settle_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_settlement

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_settlement)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    build_custodied_manifest(
                        roots=(
                            RootSpec(
                                label="child-settle-owner",
                                parent_fd=parent_fd,
                                parent_identity=identity_from_stat(os.fstat(parent_fd)),
                                name=b"target",
                                expected_identity=identity_from_stat(os.stat(target)),
                            ),
                        ),
                        manifest_path=control / "manifest.bin",
                        entry_cap=10,
                        payload_cap=4096,
                        deadline=time.monotonic() + 5.0,
                    )
            finally:
                sys.settrace(previous_trace)
                os.close(parent_fd)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            owners = recovery_cleanup.directory_descriptor_custody_owners(
                caught.exception
            )
            child_owner = next(
                owner
                for owner in owners
                if owner.purpose.startswith("manifest-enumeration:")
            )
            self.assertEqual(child_owner.state, "closed")
            self.assertIsNone(child_owner.descriptor)

    def test_recursive_child_settlement_call_boundary_uses_deletion_owner(
        self,
    ) -> None:
        with owned_temporary_directory("delete-child-settle-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir(mode=0o700)
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="recursive-child-settle-owner",
            )
            settle_offset = _call_opcode_offsets(
                recovery_cleanup._delete_directory_contents,
                called_name="_settle_directory_descriptor_owner",
                following_opname="STORE_FAST",
                following_argval="selected",
            )[0]
            interruption = KeyboardInterrupt("recursive child settlement boundary")
            injected = False

            def interrupt_settlement(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_directory_contents.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not injected
                        and event == "opcode"
                        and frame.f_lasti == settle_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_settlement

            result_owner = CustodiedDeletionResultOwner()
            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_settlement)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                owner = next(
                    candidate
                    for candidate in result_owner.directory_cleanup_owners
                    if candidate.purpose.startswith("recursive-delete:")
                )
                self.assertEqual(owner.state, "closed")
                self.assertIsNone(owner.descriptor)
                self.assertIn(
                    owner,
                    recovery_cleanup.directory_descriptor_custody_owners(
                        caught.exception
                    ),
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_bulk_directory_settlement_aggregates_after_control_flow_replacement(
        self,
    ) -> None:
        with owned_temporary_directory("directory-bulk-owner-aggregate-") as root:
            identity = identity_from_stat(os.stat(root))
            control_owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                purpose="bulk-control-owner",
                expected_identity=identity,
            )
            successful_owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                purpose="bulk-successful-owner",
                expected_identity=identity,
            )
            owners = (control_owner, successful_owner)
            descriptors: list[int] = []
            for owner in owners:
                descriptor = os.open(
                    root,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                descriptors.append(descriptor)
                owner.publish(descriptor)

            trigger = RuntimeError("bulk settlement trigger")
            control_error = KeyboardInterrupt("control-flow close failure")
            real_close_one_shot = (
                recovery_cleanup._CustodiedManifestDescriptorSlot.close_one_shot
            )

            def fail_close(
                owner: recovery_cleanup._CustodiedManifestDescriptorSlot,
            ) -> None:
                if owner is successful_owner:
                    real_close_one_shot(owner)
                    return
                self.assertIs(owner, control_owner)
                owner.state = "close-outcome-unproven"
                owner.close_error = control_error
                raise control_error

            try:
                with mock.patch.object(
                    recovery_cleanup._CustodiedManifestDescriptorSlot,
                    "close_one_shot",
                    autospec=True,
                    side_effect=fail_close,
                ):
                    selected = recovery_cleanup._settle_directory_descriptor_owners(
                        owners,
                        trigger,
                    )
                self.assertIs(selected, control_error)
                self.assertEqual(
                    getattr(selected, "_directory_descriptor_custody_owners"),
                    owners,
                )
                self.assertEqual(
                    recovery_cleanup.directory_descriptor_custody_owners(selected),
                    owners,
                )
                self.assertEqual(successful_owner.state, "closed")
                self.assertIsNone(successful_owner.descriptor)
                self._assert_descriptor_is_closed(descriptors[1])
            finally:
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

    def test_deletion_directory_reconciliation_aggregates_after_replacement(
        self,
    ) -> None:
        with owned_temporary_directory("deletion-owner-replacement-") as root:
            identity = identity_from_stat(os.stat(root))
            control_error = KeyboardInterrupt("deletion control-flow close failure")
            control_owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                purpose="deletion-control-owner",
                expected_identity=identity,
                state="close-outcome-unproven",
                close_error=control_error,
            )
            successful_owner = recovery_cleanup._CustodiedManifestDescriptorSlot(
                purpose="deletion-successful-owner",
                expected_identity=identity,
            )
            descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            successful_owner.publish(descriptor)
            deletion_owner = CustodiedDeletionResultOwner()
            deletion_owner.register_directory_cleanup(control_owner)
            deletion_owner.register_directory_cleanup(successful_owner)

            selected = recovery_cleanup._reconcile_registered_directory_cleanup(
                deletion_owner,
                RuntimeError("deletion boundary trigger"),
            )

            self.assertIs(selected, control_error)
            owners = (control_owner, successful_owner)
            self.assertEqual(
                getattr(selected, "_directory_descriptor_custody_owners"),
                owners,
            )
            self.assertEqual(
                recovery_cleanup.directory_descriptor_custody_owners(selected),
                owners,
            )
            self.assertEqual(successful_owner.state, "closed")
            self.assertIsNone(successful_owner.descriptor)
            self._assert_descriptor_is_closed(descriptor)

    def test_manifest_rejects_hardlinks_before_publication(self) -> None:
        with owned_temporary_directory("manifest-hardlink-admission-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            original = target / "original.txt"
            original.write_bytes(b"same object\n")
            alias = target / "alias.txt"
            os.link(original, alias)
            control = root / "control"
            control.mkdir(mode=0o700)
            manifest_path = control / "manifest.bin"
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            alias_object = _test_entry_object_identity(
                os.stat(
                    b"alias.txt",
                    dir_fd=target_fd,
                    follow_symlinks=False,
                )
            )
            try:
                with self.assertRaisesRegex(ValueError, "non-unique leaf"):
                    build_custodied_manifest(
                        roots=(
                            RootSpec(
                                label="hardlink-admission",
                                parent_fd=parent_fd,
                                parent_identity=identity_from_stat(os.fstat(parent_fd)),
                                name=b"target",
                                expected_identity=identity_from_stat(os.stat(target)),
                            ),
                        ),
                        manifest_path=manifest_path,
                        entry_cap=10,
                        payload_cap=4096,
                        deadline=time.monotonic() + 5.0,
                    )
                self.assertTrue(original.exists())
                self.assertTrue(alias.exists())
                self.assertFalse(manifest_path.exists())
                self.assertFalse(
                    any(
                        item.name.startswith(".targeted-cleanup-quarantine-")
                        for item in parent.iterdir()
                    )
                )
            finally:
                try:
                    _remove_exact_test_entry(
                        target_fd,
                        b"alias.txt",
                        alias_object,
                    )
                finally:
                    os.close(target_fd)
                    os.close(parent_fd)

    def test_leaf_descriptor_cleanup_supports_regular_fifo_and_symlink(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-leaf-types-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "regular.txt").write_bytes(b"regular\n")
            os.mkfifo(target / "transport.fifo", 0o600)
            os.symlink("regular.txt", target / "regular.link")
            real_preadv = os.preadv
            read_file_types: list[int] = []

            def tracked_preadv(
                descriptor: int,
                buffers: object,
                offset: int,
            ) -> int:
                file_type = stat.S_IFMT(os.fstat(descriptor).st_mode)
                read_file_types.append(file_type)
                self.assertTrue(stat.S_ISREG(file_type))
                return real_preadv(descriptor, buffers, offset)

            with mock.patch.object(
                secureio.os,
                "preadv",
                side_effect=tracked_preadv,
            ):
                manifest, parent_fd = self._build_target_manifest(
                    root,
                    target,
                    label="leaf-types",
                )
                policies = {
                    record.path: record.leaf_policy
                    for record in manifest.records
                    if record.leaf_policy is not None
                }
                self.assertEqual(
                    policies[b"regular.txt"].content_state,
                    secureio.LEAF_CONTENT_STATE_REGULAR,
                )
                self.assertEqual(
                    policies[b"transport.fifo"].content_state,
                    secureio.LEAF_CONTENT_STATE_FIFO,
                )
                self.assertEqual(
                    policies[b"regular.link"].content_state,
                    secureio.LEAF_CONTENT_STATE_SYMLINK,
                )
                records = {record.path: record for record in manifest.records}
                for path, wrong_state in (
                    (b"regular.txt", secureio.LEAF_CONTENT_STATE_FIFO),
                    (b"transport.fifo", secureio.LEAF_CONTENT_STATE_REGULAR),
                ):
                    record = records[path]
                    assert record.leaf_policy is not None
                    with self.assertRaisesRegex(
                        ValueError,
                        "content state is inconsistent",
                    ):
                        recovery_cleanup._validate_manifest_leaf_policy(
                            replace(
                                record,
                                leaf_policy=replace(
                                    record.leaf_policy,
                                    content_state=wrong_state,
                                ),
                            )
                        )
                try:
                    with manifest:
                        proof = delete_custodied_roots(manifest)
                    self.assertEqual(proof["removed_entries"], 4)
                    self.assertEqual(
                        proof["removed_entries"],
                        proof["manifest_record_count"],
                    )
                    self.assertTrue(proof["exact_names_absent"])
                    self.assertFalse(target.exists())
                    self.assertTrue(read_file_types)
                finally:
                    os.close(parent_fd)

    def test_manifest_leaf_metadata_digest_is_persisted_without_raw_values(
        self,
    ) -> None:
        metadata = MacOSDirectoryMetadataBinding(
            acl_entry_count=0,
            acl_entries=(),
            xattrs=("com.example.synthetic-leaf-policy",),
            quarantine_present=False,
        )
        metadata_binding = macos_leaf_metadata_digest(
            metadata,
            xattr_values=((metadata.xattrs[0], b"synthetic-value"),),
        )
        changed_value_binding = macos_leaf_metadata_digest(
            metadata,
            xattr_values=((metadata.xattrs[0], b"changed-value"),),
        )
        self.assertNotEqual(metadata_binding, changed_value_binding)
        with owned_temporary_directory("manifest-leaf-policy-payload-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"policy payload\n")
            with mock.patch.object(
                recovery_cleanup,
                "inspect_macos_leaf_metadata_digest",
                return_value=metadata_binding,
            ):
                manifest, parent_fd = self._build_target_manifest(
                    root,
                    target,
                    label="leaf-policy-payload",
                )
            try:
                record = next(record for record in manifest.records if record.path)
                self.assertIsNotNone(record.leaf_policy)
                assert record.leaf_policy is not None
                payload = pathlib.Path(manifest.seal["path"]).read_bytes()
                self.assertEqual(manifest.seal["version"], 3)
                self.assertIn(record.leaf_policy.metadata_sha256, payload)
                self.assertIn(record.leaf_policy.content_sha256, payload)
                self.assertNotIn(
                    b"com.example.synthetic-leaf-policy",
                    payload,
                )
                self.assertNotIn(b"synthetic-value", payload)
                self.assertNotIn(b"policy payload\n", payload)
                self.assertFalse(hasattr(record.leaf_policy, "macos_metadata"))
                self.assertFalse(hasattr(record.leaf_policy, "content_bytes"))
                none_binding = macos_leaf_metadata_digest(None)
                empty_binding = macos_leaf_metadata_digest(
                    MacOSDirectoryMetadataBinding(
                        acl_entry_count=0,
                        acl_entries=(),
                        xattrs=(),
                        quarantine_present=False,
                    )
                )
                self.assertNotEqual(none_binding, empty_binding)
                self.assertLessEqual(
                    recovery_cleanup._RECORD.size
                    + recovery_cleanup._LEAF_POLICY_RECORD.size,
                    recovery_cleanup.TARGETED_MANIFEST_RECORD_BYTES,
                )
                with self.assertRaisesRegex(ValueError, "value exceeds"):
                    macos_leaf_metadata_digest(
                        metadata,
                        xattr_values=(
                            (
                                metadata.xattrs[0],
                                b"x" * (MAX_LEAF_XATTR_VALUE_BYTES + 1),
                            ),
                        ),
                    )
                aggregate_names = tuple(
                    f"com.example.aggregate-{index:02d}" for index in range(17)
                )
                aggregate_metadata = MacOSDirectoryMetadataBinding(
                    acl_entry_count=0,
                    acl_entries=(),
                    xattrs=aggregate_names,
                    quarantine_present=False,
                )
                aggregate_value_size = MAX_LEAF_XATTR_TOTAL_BYTES // 16
                with self.assertRaisesRegex(ValueError, "aggregate byte bound"):
                    macos_leaf_metadata_digest(
                        aggregate_metadata,
                        xattr_values=tuple(
                            (name, b"x" * aggregate_value_size)
                            for name in aggregate_names
                        ),
                    )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_equal_size_rewrite_through_existing_fd_is_retained(self) -> None:
        original = b"A" * 32
        changed = b"B" * len(original)
        with owned_temporary_directory("manifest-leaf-content-rewrite-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(original)
            writer_fd = os.open(payload, os.O_RDWR | os.O_CLOEXEC)
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-content-rewrite",
            )
            result_owner = CustodiedDeletionResultOwner()
            try:
                self.assertEqual(os.pwrite(writer_fd, changed, 0), len(changed))
                os.fsync(writer_fd)
                self.assertEqual(os.fstat(writer_fd).st_size, len(original))
                with self.assertRaisesRegex(
                    CustodyLostError,
                    "leaf content stability changed",
                ) as caught:
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertEqual(
                    (retained_root / "payload.txt").read_bytes(),
                    changed,
                )
            finally:
                os.close(writer_fd)
                manifest.close()
                os.close(parent_fd)

    def test_leaf_content_cap_fails_before_first_read(self) -> None:
        with owned_temporary_directory("manifest-leaf-content-cap-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"cap-bound")
            with (
                mock.patch.object(secureio, "MAX_LEAF_CONTENT_BYTES", 8),
                mock.patch.object(secureio.os, "preadv") as preadv,
                self.assertRaisesRegex(
                    CustodyLostError,
                    "policy revalidation is unreadable",
                ),
            ):
                self._build_target_manifest(
                    root,
                    target,
                    label="leaf-content-cap",
                )
            preadv.assert_not_called()
            self.assertEqual(payload.read_bytes(), b"cap-bound")

    def test_leaf_content_read_failure_retains_no_raw_runtime_buffer(self) -> None:
        raw_chunk = b"raw!"
        with owned_temporary_directory("manifest-leaf-content-read-error-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"abcdefgh")
            reads = 0

            def uncertain_preadv(
                _descriptor: int,
                buffers: list[memoryview],
                offset: int,
            ) -> int:
                nonlocal reads
                reads += 1
                if offset:
                    raise OSError(errno.EIO, "synthetic content read failure")
                buffers[0][: len(raw_chunk)] = raw_chunk
                return len(raw_chunk)

            with (
                mock.patch.object(
                    secureio.os,
                    "preadv",
                    side_effect=uncertain_preadv,
                ),
                self.assertRaisesRegex(
                    CustodyLostError,
                    "policy revalidation is unreadable",
                ) as caught,
            ):
                self._build_target_manifest(
                    root,
                    target,
                    label="leaf-content-read-error",
                )
            self.assertEqual(reads, 2)
            self.assertEqual(payload.read_bytes(), b"abcdefgh")
            pending: list[BaseException] = [caught.exception]
            seen: set[int] = set()
            while pending:
                error = pending.pop()
                if id(error) in seen:
                    continue
                seen.add(id(error))
                traceback_item = error.__traceback__
                while traceback_item is not None:
                    frame = traceback_item.tb_frame
                    if frame.f_globals.get("__name__") == secureio.__name__:
                        for name in (
                            "buffer",
                            "view",
                            "read_view",
                            "digest_view",
                        ):
                            self.assertIsNone(frame.f_locals.get(name))
                        self.assertNotIn(raw_chunk, frame.f_locals.values())
                    traceback_item = traceback_item.tb_next
                if error.__context__ is not None:
                    pending.append(error.__context__)
                if error.__cause__ is not None:
                    pending.append(error.__cause__)

    def test_leaf_content_deadline_stops_before_next_chunk(self) -> None:
        with owned_temporary_directory("manifest-leaf-content-deadline-") as root:
            payload = root / "payload.txt"
            payload.write_bytes(b"abcdefgh")
            descriptor = os.open(
                payload,
                os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            reads = 0

            def short_preadv(
                _descriptor: int,
                buffers: list[memoryview],
                _offset: int,
            ) -> int:
                nonlocal reads
                reads += 1
                buffers[0][:4] = b"abcd"
                return 4

            try:
                with (
                    mock.patch.object(
                        secureio.os,
                        "preadv",
                        side_effect=short_preadv,
                    ),
                    mock.patch.object(
                        secureio.time,
                        "monotonic",
                        side_effect=(0.0, 0.0, 1.0),
                    ),
                    self.assertRaisesRegex(
                        TimeoutError,
                        "monotonic deadline expired",
                    ),
                ):
                    secureio.inspect_leaf_content_digest(
                        descriptor,
                        deadline=1.0,
                    )
                self.assertEqual(reads, 1)
            finally:
                os.close(descriptor)

    def test_leaf_content_timeout_propagates_unchanged(self) -> None:
        with owned_temporary_directory("manifest-leaf-content-timeout-") as root:
            payload = root / "payload.txt"
            payload.write_bytes(b"timeout")
            descriptor = os.open(
                payload,
                os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            timeout = secureio.LeafContentDeadlineExpired("synthetic content deadline")
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "inspect_macos_leaf_metadata_digest",
                        return_value=macos_leaf_metadata_digest(None),
                    ),
                    mock.patch.object(
                        recovery_cleanup,
                        "inspect_leaf_content_digest",
                        side_effect=timeout,
                    ),
                    self.assertRaises(TimeoutError) as caught,
                ):
                    recovery_cleanup._observe_leaf_policy_fd(
                        descriptor,
                        stage="during timeout propagation test",
                        deadline=time.monotonic() + 1.0,
                    )
                self.assertIs(caught.exception, timeout)

                for error in (
                    TimeoutError(errno.ETIMEDOUT, "synthetic filesystem timeout"),
                    OSError(errno.EBADF, "synthetic unreadable content descriptor"),
                ):
                    with (
                        mock.patch.object(
                            recovery_cleanup,
                            "inspect_macos_leaf_metadata_digest",
                            return_value=macos_leaf_metadata_digest(None),
                        ),
                        mock.patch.object(
                            recovery_cleanup,
                            "inspect_leaf_content_digest",
                            side_effect=error,
                        ),
                        self.assertRaisesRegex(
                            CustodyLostError,
                            "policy revalidation is unreadable",
                        ) as classified,
                    ):
                        recovery_cleanup._observe_leaf_policy_fd(
                            descriptor,
                            stage="during content I/O classification test",
                            deadline=time.monotonic() + 1.0,
                        )
                    self.assertIs(classified.exception.__cause__, error)
            finally:
                os.close(descriptor)

    def test_leaf_xattr_producer_stops_before_aggregate_overflow_read(
        self,
    ) -> None:
        names = tuple(f"com.example.aggregate-{index:02d}" for index in range(17))
        sizes = {
            name: MAX_LEAF_XATTR_VALUE_BYTES if index < 16 else 1
            for index, name in enumerate(names)
        }

        class FakeFGetXattr:
            argtypes: object = None
            restype: object = None

            def __init__(self) -> None:
                self.size_queries: list[str] = []
                self.data_reads: list[str] = []
                self.buffers: list[object] = []

            def __call__(
                self,
                _fd: int,
                raw_name: bytes,
                value: object | None,
                size: int,
                _position: int,
                _options: int,
            ) -> int:
                name = raw_name.decode("utf-8")
                expected_size = sizes[name]
                if value is None:
                    self.size_queries.append(name)
                    return expected_size
                self.data_reads.append(name)
                self.buffers.append(value)
                self.assert_size(size, expected_size)
                ctypes.memset(value, 0xA5, size)
                return size

            @staticmethod
            def assert_size(observed: int, expected: int) -> None:
                if observed != expected:
                    raise AssertionError(
                        f"unexpected fake fgetxattr size: {observed} != {expected}"
                    )

        fake_fgetxattr = FakeFGetXattr()
        fake_libc = type("FakeLibC", (), {"fgetxattr": fake_fgetxattr})()
        metadata = MacOSDirectoryMetadataBinding(
            acl_entry_count=0,
            acl_entries=(),
            xattrs=names,
            quarantine_present=False,
        )
        with (
            mock.patch.object(secureio.ctypes, "CDLL", return_value=fake_libc),
            self.assertRaisesRegex(ValueError, "aggregate byte bound") as caught,
        ):
            secureio._macos_leaf_metadata_digest_from_fd(41, metadata)

        self.assertEqual(fake_fgetxattr.data_reads, list(names[:16]))
        self.assertEqual(fake_fgetxattr.size_queries[-1], names[-1])
        self.assertEqual(fake_fgetxattr.size_queries.count(names[-1]), 1)
        for buffer in fake_fgetxattr.buffers:
            self.assertEqual(bytes(buffer), bytes(len(buffer)))
        traceback_item = caught.exception.__traceback__
        while traceback_item is not None:
            frame = traceback_item.tb_frame
            if frame.f_globals.get("__name__") == secureio.__name__:
                self.assertIsNone(frame.f_locals.get("buffer"))
                self.assertFalse(
                    any(
                        isinstance(value, bytes)
                        and len(value) >= MAX_LEAF_XATTR_VALUE_BYTES
                        for value in frame.f_locals.values()
                    )
                )
            traceback_item = traceback_item.tb_next

    def _assert_leaf_stat_policy_drift_is_retained(self, field: str) -> None:
        with owned_temporary_directory(f"manifest-leaf-{field}-drift-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"retained policy object\n")
            leaf_inode = os.stat(payload).st_ino
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label=f"leaf-{field}-drift",
            )
            real_fstat = os.fstat

            def drift_leaf_policy(descriptor: int) -> object:
                metadata = real_fstat(descriptor)
                if metadata.st_ino != leaf_inode or stat.S_ISDIR(metadata.st_mode):
                    return metadata
                original = getattr(metadata, field, 0)
                return _StatOverride(metadata, **{field: original + 1})

            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "fstat",
                        side_effect=drift_leaf_policy,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "leaf access policy drift",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertEqual(
                    (retained_root / "payload.txt").read_bytes(),
                    b"retained policy object\n",
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_gid_policy_only_drift_is_retained(self) -> None:
        self._assert_leaf_stat_policy_drift_is_retained("st_gid")

    def test_leaf_flags_policy_only_drift_is_retained(self) -> None:
        self._assert_leaf_stat_policy_drift_is_retained("st_flags")

    def _assert_leaf_extended_metadata_drift_is_detected(
        self,
        changed: MacOSDirectoryMetadataBinding,
        *,
        label: str,
        mutation_inspection: int = 2,
    ) -> None:
        initial = MacOSDirectoryMetadataBinding(
            acl_entry_count=0,
            acl_entries=(),
            xattrs=(),
            quarantine_present=False,
        )
        initial_binding = macos_leaf_metadata_digest(initial)
        changed_binding = macos_leaf_metadata_digest(
            changed,
            xattr_values=tuple((name, b"changed") for name in changed.xattrs),
        )
        with owned_temporary_directory(f"manifest-leaf-{label}-drift-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"retained metadata object\n")
            with mock.patch.object(
                recovery_cleanup,
                "inspect_macos_leaf_metadata_digest",
                return_value=initial_binding,
            ):
                manifest, parent_fd = self._build_target_manifest(
                    root,
                    target,
                    label=f"leaf-{label}-drift",
                )
            inspections = 0

            def drift_after_rename(
                _descriptor: int,
            ) -> tuple[int, bytes]:
                nonlocal inspections
                inspections += 1
                return (
                    initial_binding
                    if inspections < mutation_inspection
                    else changed_binding
                )

            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "inspect_macos_leaf_metadata_digest",
                        side_effect=drift_after_rename,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "leaf access policy drift",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                self.assertEqual(inspections, mutation_inspection)
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                leaf_quarantines = tuple(
                    child
                    for child in retained_root.iterdir()
                    if os.fsencode(child.name).startswith(
                        recovery_cleanup._LEAF_QUARANTINE_PREFIX
                    )
                )
                if mutation_inspection == 2:
                    self.assertEqual(len(leaf_quarantines), 1)
                    self.assertEqual(
                        leaf_quarantines[0].read_bytes(),
                        b"retained metadata object\n",
                    )
                else:
                    self.assertEqual(leaf_quarantines, ())
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_acl_policy_only_drift_after_rename_is_retained(self) -> None:
        self._assert_leaf_extended_metadata_drift_is_detected(
            MacOSDirectoryMetadataBinding(
                acl_entry_count=1,
                acl_entries=("synthetic-user:allow:read",),
                xattrs=(),
                quarantine_present=False,
            ),
            label="acl",
        )

    def test_leaf_xattr_policy_only_drift_after_unlink_is_detected(self) -> None:
        self._assert_leaf_extended_metadata_drift_is_detected(
            MacOSDirectoryMetadataBinding(
                acl_entry_count=0,
                acl_entries=(),
                xattrs=("com.example.synthetic-policy",),
                quarantine_present=False,
            ),
            label="xattr",
            mutation_inspection=3,
        )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS xattrs")
    def test_leaf_same_name_xattr_value_drift_is_retained(self) -> None:
        with owned_temporary_directory("manifest-leaf-xattr-value-drift-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"retained xattr value object\n")
            xattr_name = "com.example.codex-leaf-policy"
            payload_fd = os.open(
                payload,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                _set_macos_fd_xattr(payload_fd, xattr_name, b"value-before")
            finally:
                os.close(payload_fd)
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-xattr-value-drift",
            )
            payload_fd = os.open(
                payload,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                _set_macos_fd_xattr(payload_fd, xattr_name, b"value-after")
            finally:
                os.close(payload_fd)
            result_owner = CustodiedDeletionResultOwner()
            try:
                with self.assertRaisesRegex(
                    CustodyLostError,
                    "leaf access policy drift",
                ) as caught:
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                retained_leaf = retained_root / "payload.txt"
                self.assertEqual(
                    retained_leaf.read_bytes(),
                    b"retained xattr value object\n",
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_deadline_rechecked_after_content_before_unlink(self) -> None:
        with owned_temporary_directory("manifest-leaf-unlink-deadline-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"retained at deadline\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-unlink-deadline",
            )
            real_inspect = recovery_cleanup.inspect_leaf_content_digest
            real_monotonic = time.monotonic
            inspections = 0
            expired = False

            def expire_after_pre_unlink_inspection(
                descriptor: int,
                *,
                deadline: float,
            ) -> tuple[int, bytes]:
                nonlocal expired, inspections
                result = real_inspect(descriptor, deadline=deadline)
                inspections += 1
                if inspections == 2:
                    expired = True
                return result

            def controlled_monotonic() -> float:
                return manifest.deadline if expired else real_monotonic()

            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "inspect_leaf_content_digest",
                        side_effect=expire_after_pre_unlink_inspection,
                    ),
                    mock.patch.object(
                        recovery_cleanup.time,
                        "monotonic",
                        side_effect=controlled_monotonic,
                    ),
                    mock.patch.object(recovery_cleanup.os, "unlink") as unlink,
                    self.assertRaisesRegex(
                        TimeoutError,
                        "deadline expired before leaf unlink",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                unlink.assert_not_called()
                self.assertEqual(inspections, 2)
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                leaf_quarantines = tuple(
                    child
                    for child in retained_root.iterdir()
                    if os.fsencode(child.name).startswith(
                        recovery_cleanup._LEAF_QUARANTINE_PREFIX
                    )
                )
                self.assertEqual(len(leaf_quarantines), 1)
                self.assertEqual(
                    leaf_quarantines[0].read_bytes(),
                    b"retained at deadline\n",
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_oversized_xattr_observation_is_unreadable_and_retained(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-leaf-xattr-oversized-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"retained oversized xattr\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-xattr-oversized",
            )
            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "inspect_macos_leaf_metadata_digest",
                        side_effect=ValueError(
                            "leaf xattr value exceeds its byte bound"
                        ),
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "policy revalidation is unreadable",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertEqual(
                    (retained_root / "payload.txt").read_bytes(),
                    b"retained oversized xattr\n",
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_descriptor_open_store_boundary_is_quiescent(self) -> None:
        with owned_temporary_directory("leaf-open-store-") as root:
            target = root / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"open boundary\n")
            directory_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            store_offset = _call_followup_offset(
                recovery_cleanup._open_leaf_descriptor,
                called_name="open",
                following_opname="STORE_FAST",
                following_argval="descriptor",
            )
            attempts = 0

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal attempts
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._open_leaf_descriptor.__code__
                ):
                    frame.f_trace_opcodes = True
                    if event == "opcode" and frame.f_lasti == store_offset:
                        attempts += 1
                        raise AssertionError(
                            "trace hook reached the open result STORE boundary"
                        )
                return trace_hook

            previous_trace = sys.gettrace()
            descriptor_owner = recovery_cleanup._LeafDescriptorCustodyOwner()
            error_owner = recovery_cleanup._LeafCleanupErrorOwner()
            settlement = recovery_cleanup._LeafDescriptorCloseSettlement(
                descriptor_owner,
                error_owner,
            )
            delivery_owner = recovery_cleanup._LeafCleanupDeliveryOwner(
                descriptor_owner,
                error_owner,
                settlement,
            )
            try:
                sys.settrace(trace_hook)
                recovery_cleanup._delete_manifest_leaf(
                    directory_fd=directory_fd,
                    name=b"payload.txt",
                    expected=identity_from_stat(os.stat(payload)),
                    deadline=time.monotonic() + 5.0,
                    delivery_owner=delivery_owner,
                )
                recovery_cleanup._drive_leaf_cleanup_delivery(delivery_owner)
            finally:
                sys.settrace(previous_trace)
                os.close(directory_fd)

            self.assertEqual(attempts, 0)
            self.assertFalse(payload.exists())

    def test_leaf_descriptor_caller_store_boundary_is_quiescent(
        self,
    ) -> None:
        with owned_temporary_directory("leaf-caller-store-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"caller boundary\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-caller-store",
            )
            store_offset = _call_followup_offset(
                recovery_cleanup._delete_manifest_leaf,
                called_name="_open_leaf_descriptor",
                following_opname="STORE_FAST",
                following_argval="descriptor",
            )
            attempts = 0

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal attempts
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_manifest_leaf.__code__
                ):
                    frame.f_trace_opcodes = True
                    if event == "opcode" and frame.f_lasti == store_offset:
                        attempts += 1
                        raise AssertionError(
                            "trace hook reached the caller open-result STORE boundary"
                        )
                return trace_hook

            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace_hook)
                with manifest:
                    delete_custodied_roots(manifest)
            finally:
                sys.settrace(previous_trace)
                os.close(parent_fd)

            self.assertEqual(attempts, 0)
            self.assertFalse(target.exists())

    def test_leaf_quarantine_failure_attach_hook_cannot_skip_settlement(self) -> None:
        for hook_kind in ("trace", "profile"):
            with self.subTest(  # noqa: SIM117 - keeps hook scope clear
                hook=hook_kind
            ):
                with owned_temporary_directory(
                    f"leaf-quarantine-{hook_kind}-attach-"
                ) as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"attach boundary\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"leaf-quarantine-{hook_kind}-attach",
                    )
                    body_error = RuntimeError(
                        f"synthetic {hook_kind} quarantine failure"
                    )
                    hook_error = RuntimeError(f"synthetic {hook_kind} attach delivery")
                    attach_calls = 0

                    def hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        hook_error: RuntimeError = hook_error,
                    ) -> object:
                        nonlocal attach_calls
                        if (
                            event == "call"
                            and getattr(frame, "f_code", None)
                            is recovery_cleanup._attach_leaf_descriptor_custody.__code__
                        ):
                            attach_calls += 1
                            if attach_calls == 1:
                                raise hook_error
                        return hook

                    previous_trace = sys.gettrace()
                    previous_profile = sys.getprofile()
                    try:
                        if hook_kind == "trace":
                            sys.settrace(hook)
                        else:
                            sys.setprofile(hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_quarantine_leaf",
                                side_effect=body_error,
                            ),
                            self.assertRaises(RuntimeError) as caught,
                        ):
                            delete_custodied_roots(manifest)
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertGreaterEqual(attach_calls, 1)
                        self.assertIs(caught.exception, body_error)
                        owners = recovery_cleanup.leaf_descriptor_custody_owners(
                            caught.exception
                        )
                        self.assertEqual(len(owners), 1)
                        self.assertIn(
                            owners[0].state,
                            {"closed", "close-outcome-unproven"},
                        )
                        if owners[0].state == "closed":
                            self.assertIsNone(owners[0].descriptor)
                        self.assertEqual(
                            recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                            owners,
                        )
                        evidence = quarantined_root_recovery_evidence(caught.exception)
                        self.assertEqual(len(evidence), 1)
                        self.assertEqual(
                            evidence[0].leaf_descriptor_custody_owners,
                            owners,
                        )
                        retained_root = parent / os.fsdecode(
                            evidence[0].quarantine_name
                        )
                        self.assertEqual(
                            (retained_root / "payload.txt").read_bytes(),
                            b"attach boundary\n",
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_leaf_authoritative_getter_hook_cannot_replace_control_flow(
        self,
    ) -> None:
        getter = recovery_cleanup._LeafCleanupErrorOwner.authoritative_error.fget
        assert getter is not None
        for hook_kind in ("trace", "profile"):
            with self.subTest(  # noqa: SIM117 - keeps hook scope clear
                hook=hook_kind
            ):
                with owned_temporary_directory(
                    f"leaf-authoritative-{hook_kind}-getter-"
                ) as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"getter boundary\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"leaf-authoritative-{hook_kind}-getter",
                    )
                    body_error = KeyboardInterrupt(
                        f"synthetic {hook_kind} authoritative body"
                    )
                    hook_error = RuntimeError(
                        f"synthetic {hook_kind} authoritative getter"
                    )
                    getter_calls = 0

                    def hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        hook_error: RuntimeError = hook_error,
                    ) -> object:
                        nonlocal getter_calls
                        if (
                            event == "call"
                            and getattr(frame, "f_code", None) is getter.__code__
                        ):
                            getter_calls += 1
                            if getter_calls == 1:
                                raise hook_error
                        return hook

                    previous_trace = sys.gettrace()
                    previous_profile = sys.getprofile()
                    try:
                        if hook_kind == "trace":
                            sys.settrace(hook)
                        else:
                            sys.setprofile(hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_unlink_quarantined_leaf_critical",
                                side_effect=body_error,
                            ),
                            self.assertRaises(KeyboardInterrupt) as caught,
                        ):
                            delete_custodied_roots(manifest)
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertGreaterEqual(getter_calls, 1)
                        self.assertIs(caught.exception, body_error)
                        owners = recovery_cleanup.leaf_descriptor_custody_owners(
                            caught.exception
                        )
                        self.assertEqual(len(owners), 1)
                        self.assertEqual(owners[0].state, "closed")
                        self.assertIsNone(owners[0].descriptor)
                        self.assertEqual(
                            recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                            owners,
                        )
                        self.assertTrue(
                            any(
                                "leaf cleanup owner-bound delivery boundary" in note
                                and str(hook_error) in note
                                for note in getattr(body_error, "__notes__", ())
                            )
                        )
                        evidence = quarantined_root_recovery_evidence(caught.exception)
                        self.assertEqual(len(evidence), 1)
                        self.assertEqual(
                            evidence[0].leaf_descriptor_custody_owners,
                            owners,
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_leaf_delivery_loop_head_store_cannot_skip_owned_settlement(self) -> None:
        store_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(
                recovery_cleanup._LeafCleanupDeliveryOwner.step
            )
            if instruction.opname == "STORE_FAST"
            and instruction.argval == "authoritative"
        )
        with owned_temporary_directory("leaf-delivery-loop-head-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"loop-head boundary\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-delivery-loop-head",
            )
            body_error = RuntimeError("synthetic quarantine body failure")
            hook_error = RuntimeError("synthetic delivery loop-head STORE")
            fired = False

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal fired
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._LeafCleanupDeliveryOwner.step.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not fired
                        and event == "opcode"
                        and frame.f_lasti == store_offset
                    ):
                        fired = True
                        raise hook_error
                return trace_hook

            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace_hook)
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "_quarantine_leaf",
                        side_effect=body_error,
                    ),
                    self.assertRaises(RuntimeError) as caught,
                ):
                    delete_custodied_roots(manifest)
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                owners = recovery_cleanup.leaf_descriptor_custody_owners(
                    caught.exception
                )
                self.assertEqual(len(owners), 1)
                self.assertIn(
                    owners[0].state,
                    {"closed", "close-outcome-unproven"},
                )
                if owners[0].state == "closed":
                    self.assertIsNone(owners[0].descriptor)
                self.assertEqual(
                    recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                    owners,
                )
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(
                    evidence[0].leaf_descriptor_custody_owners,
                    owners,
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_outer_nop_uses_root_owner_after_settlement(self) -> None:
        instructions = tuple(
            dis.get_instructions(recovery_cleanup._delete_directory_contents)
        )
        leaf_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "_delete_manifest_leaf"
                for candidate in instructions[max(0, index - 64) : index]
            )
        )
        outer_nop_offset = next(
            instruction.offset
            for instruction in instructions[leaf_call_index + 1 :]
            if instruction.opname == "NOP"
        )
        with owned_temporary_directory("leaf-outer-nop-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"outer NOP boundary\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-outer-nop",
            )
            body_error = RuntimeError("synthetic quarantine failure")
            hook_error = RuntimeError("synthetic outer NOP delivery")
            result_owner = CustodiedDeletionResultOwner()
            fired = False

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal fired
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_directory_contents.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not fired
                        and event == "opcode"
                        and frame.f_lasti == outer_nop_offset
                    ):
                        fired = True
                        raise hook_error
                return trace_hook

            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace_hook)
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "_quarantine_leaf",
                        side_effect=body_error,
                    ),
                    self.assertRaises(RuntimeError) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertIs(
                    caught.exception.custodied_deletion_result_owner,
                    result_owner,
                )
                self.assertEqual(len(result_owner.leaf_cleanup_owners), 1)
                delivery_owner = result_owner.leaf_cleanup_owners[0]
                self.assertIn(
                    delivery_owner.descriptor_owner.state,
                    {"closed", "close-outcome-unproven"},
                )
                owners = recovery_cleanup.leaf_descriptor_custody_owners(
                    caught.exception
                )
                self.assertEqual(owners, (delivery_owner.descriptor_owner,))
                self.assertEqual(
                    recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                    owners,
                )
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].leaf_descriptor_custody_owners, owners)
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_authoritative_getter_success_return_is_caller_owned(self) -> None:
        getter = recovery_cleanup._LeafCleanupErrorOwner.authoritative_error.fget
        assert getter is not None
        return_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(getter)
            if instruction.opname == "RETURN_VALUE"
        )
        for hook_kind in ("trace", "profile"):
            with self.subTest(  # noqa: SIM117 - keeps hook scope clear
                hook=hook_kind
            ):
                with owned_temporary_directory(
                    f"leaf-getter-{hook_kind}-return-"
                ) as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"getter return\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"leaf-getter-{hook_kind}-return",
                    )
                    body_error = KeyboardInterrupt(
                        f"synthetic {hook_kind} getter-return body"
                    )
                    hook_error = RuntimeError(f"synthetic {hook_kind} getter RETURN")
                    fired = False

                    def hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        hook_error: RuntimeError = hook_error,
                        hook_kind: str = hook_kind,
                    ) -> object:
                        nonlocal fired
                        if getattr(frame, "f_code", None) is getter.__code__:
                            if hook_kind == "trace":
                                frame.f_trace_opcodes = True
                                matches = (
                                    event == "opcode" and frame.f_lasti == return_offset
                                )
                            else:
                                matches = event == "return"
                            if not fired and matches:
                                fired = True
                                raise hook_error
                        return hook

                    previous_trace = sys.gettrace()
                    previous_profile = sys.getprofile()
                    try:
                        if hook_kind == "trace":
                            sys.settrace(hook)
                        else:
                            sys.setprofile(hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_unlink_quarantined_leaf_critical",
                                side_effect=body_error,
                            ),
                            self.assertRaises(KeyboardInterrupt) as caught,
                        ):
                            delete_custodied_roots(manifest)
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertIs(caught.exception, body_error)
                        owners = recovery_cleanup.leaf_descriptor_custody_owners(
                            caught.exception
                        )
                        self.assertEqual(len(owners), 1)
                        self.assertEqual(owners[0].state, "closed")
                        self.assertEqual(
                            recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                            owners,
                        )
                        evidence = quarantined_root_recovery_evidence(caught.exception)
                        self.assertEqual(len(evidence), 1)
                        self.assertEqual(
                            evidence[0].leaf_descriptor_custody_owners,
                            owners,
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_leaf_successful_return_is_root_owned_with_control_flow_priority(
        self,
    ) -> None:
        with owned_temporary_directory("leaf-profile-successful-return-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"successful return\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-profile-successful-return",
            )
            body_error = KeyboardInterrupt("synthetic profile return body")
            hook_error = RuntimeError("synthetic profile leaf RETURN delivery")
            result_owner = CustodiedDeletionResultOwner()
            fired = False

            def profile_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal fired
                if (
                    not fired
                    and event == "return"
                    and getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_manifest_leaf.__code__
                ):
                    fired = True
                    raise hook_error
                return profile_hook

            previous_profile = sys.getprofile()
            try:
                sys.setprofile(profile_hook)
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "_unlink_quarantined_leaf_critical",
                        side_effect=body_error,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
            finally:
                sys.setprofile(previous_profile)

            try:
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertIs(
                    caught.exception.custodied_deletion_result_owner,
                    result_owner,
                )
                self.assertEqual(len(result_owner.leaf_cleanup_owners), 1)
                delivery_owner = result_owner.leaf_cleanup_owners[0]
                owners = recovery_cleanup.leaf_descriptor_custody_owners(
                    caught.exception
                )
                self.assertEqual(owners, (delivery_owner.descriptor_owner,))
                self.assertEqual(owners[0].state, "closed")
                self.assertEqual(
                    recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                    owners,
                )
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].leaf_descriptor_custody_owners, owners)
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_final_armed_raise_is_root_owned(self) -> None:
        instructions = tuple(
            dis.get_instructions(recovery_cleanup._delete_directory_contents)
        )
        raise_offset = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname == "RAISE_VARARGS"
            and instruction.arg == 0
            and any(
                candidate.argval == "_armed_error"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        with owned_temporary_directory("leaf-armed-driver-raise-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"armed raise\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-armed-driver-raise",
            )
            body_error = KeyboardInterrupt("synthetic armed delivery body")
            hook_error = RuntimeError("synthetic armed bare-raise delivery")
            result_owner = CustodiedDeletionResultOwner()
            fired = False

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal fired
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_directory_contents.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not fired
                        and event == "opcode"
                        and frame.f_lasti == raise_offset
                    ):
                        fired = True
                        raise hook_error
                return trace_hook

            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace_hook)
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "_unlink_quarantined_leaf_critical",
                        side_effect=body_error,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertIs(
                    caught.exception.custodied_deletion_result_owner,
                    result_owner,
                )
                self.assertEqual(len(result_owner.leaf_cleanup_owners), 1)
                delivery_owner = result_owner.leaf_cleanup_owners[0]
                owners = recovery_cleanup.leaf_descriptor_custody_owners(
                    caught.exception
                )
                self.assertEqual(owners, (delivery_owner.descriptor_owner,))
                self.assertEqual(owners[0].state, "closed")
                self.assertEqual(
                    recovery_cleanup.leaf_descriptor_custody_owners(hook_error),
                    owners,
                )
                self.assertTrue(
                    any(
                        "leaf root-owner delivery boundary" in note
                        and str(hook_error) in note
                        for note in getattr(body_error, "__notes__", ())
                    )
                )
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(
                    evidence[0].leaf_descriptor_custody_owners,
                    owners,
                )
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_descriptor_close_boundaries_are_never_retried(self) -> None:
        instructions = tuple(
            dis.get_instructions(recovery_cleanup._LeafDescriptorCustodyOwner.close)
        )
        close_call_offset = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "close"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        cases = (
            ("pre-close", close_call_offset, 0, True),
            (
                "post-close",
                _instruction_after_offset(
                    recovery_cleanup._LeafDescriptorCustodyOwner.close,
                    close_call_offset,
                ),
                1,
                False,
            ),
        )
        real_close = os.close
        for name, target_offset, expected_calls, descriptor_remains_open in cases:
            with self.subTest(name=name):  # noqa: SIM117 - keeps case scope clear
                with owned_temporary_directory(f"leaf-{name}-") as root:
                    path = root / "payload.txt"
                    path.write_bytes(b"close boundary\n")
                    descriptor = os.open(
                        path,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                    owner = recovery_cleanup._LeafDescriptorCustodyOwner()
                    owner.publish(descriptor)
                    error_owner = recovery_cleanup._LeafCleanupErrorOwner()
                    settlement = recovery_cleanup._LeafDescriptorCloseSettlement(
                        owner,
                        error_owner,
                    )
                    injected = RuntimeError(f"synthetic {name} interrupt")
                    close_calls = 0
                    fired = False

                    def counted_close(candidate: int) -> None:
                        nonlocal close_calls
                        close_calls += 1
                        real_close(candidate)

                    def trace_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        target_offset: int = target_offset,
                        injected: RuntimeError = injected,
                    ) -> object:
                        nonlocal fired
                        if (
                            getattr(frame, "f_code", None)
                            is recovery_cleanup._LeafDescriptorCustodyOwner.close.__code__
                        ):
                            frame.f_trace_opcodes = True
                            if (
                                not fired
                                and event == "opcode"
                                and frame.f_lasti == target_offset
                            ):
                                fired = True
                                raise injected
                        return trace_hook

                    previous_trace = sys.gettrace()
                    try:
                        with mock.patch.object(
                            recovery_cleanup.os,
                            "close",
                            side_effect=counted_close,
                        ):
                            sys.settrace(trace_hook)
                            settlement.settle()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertTrue(fired)
                    self.assertEqual(close_calls, expected_calls)
                    self.assertEqual(owner.state, "close-outcome-unproven")
                    self.assertEqual(owner.descriptor, descriptor)
                    self.assertIs(error_owner.authoritative_error, injected)
                    self.assertEqual(
                        recovery_cleanup.leaf_descriptor_custody_owners(injected),
                        (owner,),
                    )
                    settlement.settle()
                    self.assertEqual(close_calls, expected_calls)
                    if descriptor_remains_open:
                        self.assertEqual(
                            os.fstat(descriptor).st_ino, os.stat(path).st_ino
                        )
                        real_close(descriptor)
                    else:
                        with self.assertRaises(OSError) as caught:
                            os.fstat(descriptor)
                        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_leaf_delivery_hooks_cannot_replace_body_control_flow(self) -> None:
        for hook_kind in ("trace", "profile"):
            with self.subTest(  # noqa: SIM117 - keeps hook scope clear
                hook=hook_kind
            ):
                with owned_temporary_directory(f"leaf-{hook_kind}-delivery-") as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"delivery boundary\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"leaf-{hook_kind}-delivery",
                    )
                    body_error = KeyboardInterrupt(f"synthetic {hook_kind} body")
                    hook_error = RuntimeError(f"synthetic {hook_kind} delivery")
                    fired = False
                    selector_calls = 0

                    def hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        hook_error: RuntimeError = hook_error,
                    ) -> object:
                        nonlocal fired, selector_calls
                        if (
                            event == "call"
                            and getattr(frame, "f_code", None)
                            is recovery_cleanup._select_leaf_cleanup_error.__code__
                        ):
                            selector_calls += 1
                            raise hook_error
                        if (
                            not fired
                            and event == "call"
                            and getattr(frame, "f_code", None)
                            is recovery_cleanup._LeafCleanupErrorOwner.raise_authoritative.__code__
                        ):
                            fired = True
                            raise hook_error
                        return hook

                    previous_trace = sys.gettrace()
                    previous_profile = sys.getprofile()
                    try:
                        if hook_kind == "trace":
                            sys.settrace(hook)
                        else:
                            sys.setprofile(hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_unlink_quarantined_leaf_critical",
                                side_effect=body_error,
                            ),
                            self.assertRaises(KeyboardInterrupt) as caught,
                        ):
                            delete_custodied_roots(manifest)
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertEqual(selector_calls, 0)
                        self.assertIs(caught.exception, body_error)
                        self.assertTrue(
                            any(
                                "leaf cleanup owner-bound delivery boundary" in note
                                and str(hook_error) in note
                                for note in getattr(body_error, "__notes__", ())
                            )
                        )
                        owners = recovery_cleanup.leaf_descriptor_custody_owners(
                            caught.exception
                        )
                        self.assertEqual(len(owners), 1)
                        self.assertEqual(owners[0].state, "closed")
                        evidence = quarantined_root_recovery_evidence(caught.exception)
                        self.assertEqual(
                            evidence[0].leaf_descriptor_custody_owners,
                            owners,
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_leaf_quarantine_revalidation_never_unlinks_replacement(self) -> None:
        with owned_temporary_directory("manifest-leaf-replacement-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"manifest object\n")
            original_identity = identity_from_stat(os.stat(payload))
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-replacement",
            )
            real_rename_noreplace = recovery_cleanup.rename_noreplace
            quarantine_name: bytes | None = None
            swapped = False

            def replace_at_quarantine_entry(
                source_dir_fd: int,
                source: bytes,
                destination_dir_fd: int,
                destination: bytes,
            ) -> None:
                nonlocal quarantine_name, swapped
                if not swapped and source == b"payload.txt":
                    swapped = True
                    os.rename(
                        source,
                        b"displaced-original",
                        src_dir_fd=source_dir_fd,
                        dst_dir_fd=source_dir_fd,
                    )
                    replacement_fd = os.open(
                        source,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=source_dir_fd,
                    )
                    try:
                        os.write(replacement_fd, b"replacement object\n")
                    finally:
                        os.close(replacement_fd)
                    quarantine_name = destination
                real_rename_noreplace(
                    source_dir_fd,
                    source,
                    destination_dir_fd,
                    destination,
                )

            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "rename_noreplace",
                        side_effect=replace_at_quarantine_entry,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "quarantined leaf identity changed",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )

                self.assertTrue(swapped)
                self.assertIsNotNone(quarantine_name)
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                assert quarantine_name is not None
                self.assertEqual(
                    (retained_root / os.fsdecode(quarantine_name)).read_bytes(),
                    b"replacement object\n",
                )
                displaced = retained_root / "displaced-original"
                self.assertEqual(
                    identity_from_stat(os.stat(displaced)),
                    original_identity,
                )
                self.assertEqual(displaced.read_bytes(), b"manifest object\n")
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_unlink_quiesces_current_trace_and_profile_hooks(self) -> None:
        with owned_temporary_directory("manifest-leaf-hooks-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"delete exactly\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-hooks",
            )
            instructions = tuple(
                dis.get_instructions(recovery_cleanup._unlink_quarantined_leaf_critical)
            )
            unlink_offset = next(
                instruction.offset
                for index, instruction in enumerate(instructions)
                if instruction.opname.startswith("CALL")
                and any(
                    candidate.argval == "unlink"
                    for candidate in instructions[max(0, index - 64) : index]
                )
            )
            trace_attempts = 0
            profile_attempts = 0

            def trace_hook(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal trace_attempts
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._unlink_quarantined_leaf_critical.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        event == "opcode"
                        and getattr(frame, "f_lasti", None) == unlink_offset
                    ):
                        trace_attempts += 1
                        raise AssertionError(
                            "trace hook entered the leaf unlink critical section"
                        )
                return trace_hook

            def profile_hook(
                frame: object,
                event: str,
                argument: object,
            ) -> None:
                nonlocal profile_attempts
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._unlink_quarantined_leaf_critical.__code__
                    and event == "c_call"
                    and argument is recovery_cleanup.os.unlink
                ):
                    profile_attempts += 1
                    raise AssertionError(
                        "profile hook entered the leaf unlink critical section"
                    )

            previous_trace = sys.gettrace()
            previous_profile = sys.getprofile()
            try:
                sys.settrace(trace_hook)
                sys.setprofile(profile_hook)
                with manifest:
                    proof = delete_custodied_roots(manifest)
                self.assertIs(sys.gettrace(), trace_hook)
                self.assertIs(sys.getprofile(), profile_hook)
            finally:
                sys.setprofile(previous_profile)
                sys.settrace(previous_trace)
                os.close(parent_fd)

            self.assertEqual(trace_attempts, 0)
            self.assertEqual(profile_attempts, 0)
            self.assertTrue(proof["exact_names_absent"])
            self.assertFalse(target.exists())

    def test_leaf_unlink_hardlink_race_never_publishes_success(self) -> None:
        with owned_temporary_directory("manifest-leaf-hardlink-race-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"retained alias\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-hardlink-race",
            )
            real_unlink = recovery_cleanup.os.unlink
            linked = False

            def link_before_unlink(name: bytes, *, dir_fd: int) -> None:
                nonlocal linked
                if not linked and name.startswith(
                    recovery_cleanup._LEAF_QUARANTINE_PREFIX
                ):
                    linked = True
                    os.link(
                        name,
                        b"late-alias",
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                        follow_symlinks=False,
                    )
                real_unlink(name, dir_fd=dir_fd)

            result_owner = CustodiedDeletionResultOwner()
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "unlink",
                        side_effect=link_before_unlink,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "exact leaf deletion is unproven",
                    ) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )

                self.assertTrue(linked)
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                alias = retained_root / "late-alias"
                self.assertEqual(alias.read_bytes(), b"retained alias\n")
                self.assertEqual(os.stat(alias).st_nlink, 1)
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_leaf_critical_compound_failures_preserve_error_priority(self) -> None:
        real_pthread_sigmask = signal.pthread_sigmask
        cases = (
            (
                "body-control-flow",
                KeyboardInterrupt("synthetic body interrupt"),
                RuntimeError("synthetic mask restoration failure"),
                "body",
                "leaf signal-mask restoration",
            ),
            (
                "restoration-control-flow",
                RuntimeError("synthetic body failure"),
                KeyboardInterrupt("synthetic restoration interrupt"),
                "restoration",
                "leaf deletion critical body",
            ),
            (
                "ordinary-first-error",
                RuntimeError("synthetic first failure"),
                ValueError("synthetic later failure"),
                "body",
                "leaf signal-mask restoration",
            ),
        )
        for name, body_error, restoration_error, winner, secondary_label in cases:
            with self.subTest(name=name):

                def fail_after_mask_restoration(
                    how: int,
                    values: object,
                    restoration_error: BaseException = restoration_error,
                ) -> set[signal.Signals]:
                    result = real_pthread_sigmask(how, values)
                    if how == signal.SIG_SETMASK:
                        raise restoration_error
                    return result

                expected = body_error if winner == "body" else restoration_error
                error_owner = recovery_cleanup._LeafCleanupErrorOwner()
                with (
                    mock.patch.object(
                        recovery_cleanup.signal,
                        "pthread_sigmask",
                        side_effect=fail_after_mask_restoration,
                    ),
                    self.assertRaises(type(expected)) as caught,
                    recovery_cleanup._SupportedLeafDeletionCriticalSection(error_owner),
                ):
                    raise body_error

                self.assertIs(caught.exception, expected)
                self.assertTrue(
                    any(
                        secondary_label in note
                        for note in getattr(expected, "__notes__", ())
                    )
                )

    def test_leaf_unlink_defers_owned_signal_until_recovery_handoff(self) -> None:
        with owned_temporary_directory("manifest-leaf-signal-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            (target / "payload.txt").write_bytes(b"signal boundary\n")
            manifest, parent_fd = self._build_target_manifest(
                root,
                target,
                label="leaf-signal",
            )
            interrupt = DeferredSignalInterrupt(
                lambda number: _DeferredLeafSignal(f"injected owned signal {number}")
            )
            binding = activate_deferred_signal_interrupt(interrupt)
            previous_handler = signal.getsignal(signal.SIGINT)
            signal.signal(
                signal.SIGINT,
                lambda number, _frame: interrupt.request(number),
            )
            real_unlink = recovery_cleanup.os.unlink
            requested = False
            observed_mask: set[signal.Signals] | None = None

            def request_before_unlink(name: bytes, *, dir_fd: int) -> None:
                nonlocal observed_mask, requested
                if not requested and name.startswith(
                    recovery_cleanup._LEAF_QUARANTINE_PREFIX
                ):
                    requested = True
                    observed_mask = set(signal.pthread_sigmask(signal.SIG_BLOCK, ()))
                    os.kill(os.getpid(), signal.SIGINT)
                real_unlink(name, dir_fd=dir_fd)

            result_owner = CustodiedDeletionResultOwner()
            try:
                try:
                    with (
                        mock.patch.object(
                            recovery_cleanup.os,
                            "unlink",
                            side_effect=request_before_unlink,
                        ),
                        self.assertRaises(_DeferredLeafSignal) as caught,
                    ):
                        delete_custodied_roots(
                            manifest,
                            result_owner=result_owner,
                        )
                finally:
                    deactivate_deferred_signal_interrupt(binding)
                    signal.signal(signal.SIGINT, previous_handler)

                self.assertTrue(requested)
                self.assertIsNotNone(observed_mask)
                assert observed_mask is not None
                self.assertTrue(
                    set(recovery_cleanup._LEAF_DELETION_SIGNALS).issubset(observed_mask)
                )
                self.assertIsNone(result_owner.proof)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].stage, "recursive-delete")
                retained_root = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertEqual(tuple(retained_root.iterdir()), ())
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_manifest_close_first_ambiguity_still_settles_later_roots(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-close-partial-") as root:
            manifest, parent_fd = self._build_empty_manifest(
                root,
                "first",
                "second",
            )
            original_fds = tuple(manifest.root_fds)
            close_discard_offset = _call_followup_offset(
                recovery_cleanup.CustodiedManifest.close,
                called_name="close",
                following_opname="POP_TOP",
            )
            target_offset = _instruction_after_offset(
                recovery_cleanup.CustodiedManifest.close,
                close_discard_offset,
            )
            interruption = KeyboardInterrupt(
                "injected partial manifest close interrupt"
            )
            injected = False

            def interrupt_first_close(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup.CustodiedManifest.close.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                        and getattr(frame, "f_locals", {}).get("index") == 0
                    ):
                        injected = True
                        raise interruption
                return interrupt_first_close

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_first_close)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    manifest.close()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertTrue(manifest._closed)
                self.assertEqual(manifest.root_fds, [])
                with self.assertRaises(OSError) as first_closed:
                    os.fstat(original_fds[0])
                self.assertEqual(first_closed.exception.errno, errno.EBADF)
                with self.assertRaises(OSError) as second_closed:
                    os.fstat(original_fds[1])
                self.assertEqual(second_closed.exception.errno, errno.EBADF)
                self.assertEqual(
                    manifest.close_evidence[-1].state,
                    "ownership-ambiguous-closed-or-missing",
                )
                self.assertEqual(
                    manifest.close_evidence[-1].protected_property,
                    "open-file-description-close-ownership",
                )
                manifest.close()
                self.assertTrue(manifest._closed)
                self.assertEqual(manifest.root_fds, [])
            finally:
                if manifest.root_fds:
                    manifest.close()
                os.close(parent_fd)

    def test_manifest_close_aggregates_all_failed_root_owners_and_evidence(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-close-plural-") as root:
            manifest, parent_fd = self._build_empty_manifest(
                root,
                "missing",
                "mismatch",
            )
            first_fd, second_fd = manifest.root_fds
            slots = tuple(manifest._root_fd_slots)
            replacement_fd: int | None = os.open(
                "/dev/null",
                os.O_RDONLY | os.O_CLOEXEC,
            )
            try:
                os.close(first_fd)
                os.dup2(replacement_fd, second_fd)
                os.close(replacement_fd)
                replacement_fd = None

                with self.assertRaisesRegex(
                    CustodyLostError,
                    "missing-before-close",
                ) as caught:
                    manifest.close()

                error = caught.exception
                direct_owners = getattr(
                    error,
                    "_directory_descriptor_custody_owners",
                )
                self.assertEqual(len(direct_owners), 2)
                for actual, expected in zip(direct_owners, slots, strict=True):
                    self.assertIs(actual, expected)
                collected_owners = recovery_cleanup.directory_descriptor_custody_owners(
                    error
                )
                self.assertEqual(len(collected_owners), 2)
                for actual, expected in zip(collected_owners, slots, strict=True):
                    self.assertIs(actual, expected)

                expected_evidence = manifest.close_evidence
                self.assertEqual(
                    tuple(item.state for item in expected_evidence),
                    ("missing-before-close", "identity-mismatch"),
                )
                direct_evidence = getattr(
                    error,
                    "custodied_manifest_close_evidence_items",
                )
                self.assertEqual(len(direct_evidence), 2)
                for actual, expected in zip(
                    direct_evidence,
                    expected_evidence,
                    strict=True,
                ):
                    self.assertIs(actual, expected)
                collected_evidence = (
                    recovery_cleanup.custodied_manifest_close_evidence_items(error)
                )
                self.assertEqual(len(collected_evidence), 2)
                for actual, expected in zip(
                    collected_evidence,
                    expected_evidence,
                    strict=True,
                ):
                    self.assertIs(actual, expected)
                self.assertIs(
                    getattr(error, "custodied_manifest_close_evidence"),
                    expected_evidence[0],
                )

                self._assert_descriptor_is_closed(first_fd)
                os.fstat(second_fd)
            finally:
                if replacement_fd is not None:
                    os.close(replacement_fd)
                os.close(second_fd)
                os.close(parent_fd)

    def test_manifest_close_reconciles_terminal_publication_interrupts(
        self,
    ) -> None:
        close_instructions = tuple(
            dis.get_instructions(recovery_cleanup.CustodiedManifest.close)
        )
        set_add_offsets = tuple(
            instruction.offset
            for instruction in close_instructions
            if instruction.opname == "SET_ADD"
        )
        self.assertEqual(len(set_add_offsets), 1)
        evidence_generator_code = next(
            constant
            for constant in recovery_cleanup.CustodiedManifest.close.__code__.co_consts
            if getattr(constant, "co_name", None) == "<genexpr>"
            and "root_index" in getattr(constant, "co_names", ())
        )
        owner_attach_offset = _direct_call_opcode_offsets(
            recovery_cleanup.CustodiedManifest.close,
            called_name="_attach_directory_descriptor_custody_owners",
        )[-1]
        evidence_attach_offset = _direct_call_opcode_offsets(
            recovery_cleanup.CustodiedManifest.close,
            called_name="_attach_custodied_manifest_close_evidence_items",
        )[-1]
        cases = (
            (
                "freeze-set-comprehension-opcode",
                "trace",
                set_add_offsets[0],
                None,
            ),
            (
                "freeze-evidence-generator-profile",
                "profile",
                None,
                evidence_generator_code,
            ),
            (
                "selector-call-profile",
                "profile",
                None,
                recovery_cleanup._select_leaf_cleanup_error.__code__,
            ),
            (
                "final-owner-attach-opcode",
                "trace",
                owner_attach_offset,
                None,
            ),
            (
                "final-evidence-attach-opcode",
                "trace",
                evidence_attach_offset,
                None,
            ),
        )
        for name, hook_kind, target_offset, profile_code in cases:
            with self.subTest(name=name):
                with owned_temporary_directory(
                    f"manifest-close-publication-{name}-"
                ) as root:
                    manifest, parent_fd = self._build_empty_manifest(
                        root,
                        "missing",
                        "mismatch",
                    )
                    first_fd, second_fd = manifest.root_fds
                    slots = tuple(manifest._root_fd_slots)
                    replacement_fd: int | None = os.open(
                        "/dev/null",
                        os.O_RDONLY | os.O_CLOEXEC,
                    )
                    os.close(first_fd)
                    os.dup2(replacement_fd, second_fd)
                    os.close(replacement_fd)
                    replacement_fd = None
                    hook_error = KeyboardInterrupt(f"manifest close publication {name}")
                    fired = False

                    def profile_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                    ) -> None:
                        nonlocal fired
                        if (
                            not fired
                            and event == "call"
                            and getattr(frame, "f_code", None) is profile_code
                        ):
                            fired = True
                            raise hook_error

                    def trace_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                    ) -> object:
                        nonlocal fired
                        if (
                            getattr(frame, "f_code", None)
                            is recovery_cleanup.CustodiedManifest.close.__code__
                        ):
                            frame.f_trace_opcodes = True
                            if (
                                not fired
                                and event == "opcode"
                                and frame.f_lasti == target_offset
                            ):
                                fired = True
                                raise hook_error
                        return trace_hook

                    previous_profile = sys.getprofile()
                    previous_trace = sys.gettrace()
                    try:
                        if hook_kind == "profile":
                            sys.setprofile(profile_hook)
                        else:
                            sys.settrace(trace_hook)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            manifest.close()
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertIs(caught.exception, hook_error)
                        direct_owners = getattr(
                            caught.exception,
                            "_directory_descriptor_custody_owners",
                        )
                        self.assertEqual(len(direct_owners), 2)
                        for actual, expected in zip(
                            direct_owners,
                            slots,
                            strict=True,
                        ):
                            self.assertIs(actual, expected)
                        self.assertEqual(
                            tuple(slot.state for slot in slots),
                            ("missing-before-close", "identity-mismatch"),
                        )
                        direct_evidence = getattr(
                            caught.exception,
                            "custodied_manifest_close_evidence_items",
                        )
                        self.assertEqual(len(direct_evidence), 2)
                        for actual, expected in zip(
                            direct_evidence,
                            manifest.close_evidence,
                            strict=True,
                        ):
                            self.assertIs(actual, expected)
                        self.assertIs(
                            getattr(
                                caught.exception,
                                "custodied_manifest_close_evidence",
                            ),
                            manifest.close_evidence[0],
                        )
                        self._assert_descriptor_is_closed(first_fd)
                        os.fstat(second_fd)
                    finally:
                        if replacement_fd is not None:
                            os.close(replacement_fd)
                        os.close(second_fd)
                        os.close(parent_fd)

    def test_bulk_prepublication_interrupts_are_reconciled_before_settlement(
        self,
    ) -> None:
        attach_offsets = _direct_call_opcode_offsets(
            recovery_cleanup._settle_directory_descriptor_owners,
            called_name="_attach_directory_descriptor_custody_owners",
        )
        self.assertEqual(len(attach_offsets), 3)
        first_attach_offset = attach_offsets[0]
        cases = (
            ("relevant-call-profile", "profile"),
            ("first-attach-opcode", "trace"),
        )
        for name, hook_kind in cases:
            with self.subTest(name=name):
                with owned_temporary_directory(f"bulk-prepublication-{name}-") as root:
                    identity = identity_from_stat(os.stat(root))
                    owners = tuple(
                        recovery_cleanup._CustodiedManifestDescriptorSlot(
                            purpose=f"bulk-prepublication-{name}-{index}",
                            expected_identity=identity,
                        )
                        for index in range(2)
                    )
                    descriptors: list[int] = []
                    for owner in owners:
                        descriptor = os.open(
                            root,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        )
                        descriptors.append(descriptor)
                        owner.publish(descriptor)
                    trigger = RuntimeError(f"bulk prepublication trigger {name}")
                    hook_error = KeyboardInterrupt(f"bulk prepublication hook {name}")
                    fired = False

                    def profile_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                    ) -> None:
                        nonlocal fired
                        if (
                            not fired
                            and event == "call"
                            and getattr(frame, "f_code", None)
                            is recovery_cleanup._relevant_directory_descriptor_custody_owners.__code__
                        ):
                            fired = True
                            raise hook_error

                    def trace_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                    ) -> object:
                        nonlocal fired
                        if (
                            getattr(frame, "f_code", None)
                            is recovery_cleanup._settle_directory_descriptor_owners.__code__
                        ):
                            frame.f_trace_opcodes = True
                            if (
                                not fired
                                and event == "opcode"
                                and frame.f_lasti == first_attach_offset
                            ):
                                fired = True
                                raise hook_error
                        return trace_hook

                    previous_profile = sys.getprofile()
                    previous_trace = sys.gettrace()
                    try:
                        if hook_kind == "profile":
                            sys.setprofile(profile_hook)
                        else:
                            sys.settrace(trace_hook)
                        selected = recovery_cleanup._settle_directory_descriptor_owners(
                            owners,
                            trigger,
                        )
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertIs(selected, hook_error)
                        for error in (trigger, selected):
                            direct_owners = getattr(
                                error,
                                "_directory_descriptor_custody_owners",
                            )
                            self.assertEqual(len(direct_owners), 2)
                            for actual, expected in zip(
                                direct_owners,
                                owners,
                                strict=True,
                            ):
                                self.assertIs(actual, expected)
                                self.assertEqual(actual.state, "closed")
                                self.assertIsNone(actual.descriptor)
                        for descriptor in descriptors:
                            self._assert_descriptor_is_closed(descriptor)
                    finally:
                        for descriptor in descriptors:
                            try:
                                os.close(descriptor)
                            except OSError as error:
                                if error.errno != errno.EBADF:
                                    raise

    def test_bulk_settlement_prepublication_survives_final_attach_interrupt(
        self,
    ) -> None:
        attach_offsets = _direct_call_opcode_offsets(
            recovery_cleanup._settle_directory_descriptor_owners,
            called_name="_attach_directory_descriptor_custody_owners",
        )
        self.assertEqual(len(attach_offsets), 3)
        final_attach_offset = attach_offsets[-1]
        with owned_temporary_directory("bulk-final-attach-publication-") as root:
            identity = identity_from_stat(os.stat(root))
            owners = tuple(
                recovery_cleanup._CustodiedManifestDescriptorSlot(
                    purpose=f"bulk-publication-{index}",
                    expected_identity=identity,
                )
                for index in range(2)
            )
            descriptors: list[int] = []
            for owner in owners:
                descriptor = os.open(
                    root,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                descriptors.append(descriptor)
                owner.publish(descriptor)
            trigger = RuntimeError("bulk caller-owned trigger")
            hook_error = KeyboardInterrupt("bulk final attach boundary")
            fired = False

            def interrupt_final_attach(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal fired
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._settle_directory_descriptor_owners.__code__
                ):
                    frame.f_trace_opcodes = True
                    if (
                        not fired
                        and event == "opcode"
                        and frame.f_lasti == final_attach_offset
                    ):
                        fired = True
                        raise hook_error
                return interrupt_final_attach

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_final_attach)
                selected = recovery_cleanup._settle_directory_descriptor_owners(
                    owners,
                    trigger,
                )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(fired)
            self.assertIs(selected, hook_error)
            direct_owners = getattr(
                trigger,
                "_directory_descriptor_custody_owners",
            )
            self.assertEqual(len(direct_owners), 2)
            for actual, expected in zip(direct_owners, owners, strict=True):
                self.assertIs(actual, expected)
                self.assertEqual(actual.state, "closed")
                self.assertIsNone(actual.descriptor)
            self.assertEqual(
                recovery_cleanup.directory_descriptor_custody_owners(selected),
                owners,
            )
            for descriptor in descriptors:
                self._assert_descriptor_is_closed(descriptor)

    def test_manifest_close_result_interrupt_never_closes_reused_descriptor(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-close-reused-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            original_fd = manifest.root_fds[0]
            close_discard_offset = _call_followup_offset(
                recovery_cleanup.CustodiedManifest.close,
                called_name="close",
                following_opname="POP_TOP",
            )
            target_offset = _instruction_after_offset(
                recovery_cleanup.CustodiedManifest.close,
                close_discard_offset,
            )
            interruption = KeyboardInterrupt(
                "injected manifest close result interrupt with FD reuse"
            )
            injected = False
            reused_fd: int | None = None

            def interrupt_and_reuse(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected, reused_fd
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup.CustodiedManifest.close.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        reused_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                        raise interruption
                return interrupt_and_reuse

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_and_reuse)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    manifest.close()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(reused_fd, original_fd)
                self.assertEqual(manifest.root_fds, [])
                self.assertFalse(manifest._closed)
                self.assertEqual(
                    manifest.close_evidence[-1].state,
                    "ownership-ambiguous-identity-mismatch",
                )
                with self.assertRaisesRegex(
                    CustodyLostError,
                    "ownership-ambiguous-identity-mismatch",
                ):
                    manifest.close()
                assert reused_fd is not None
                os.fstat(reused_fd)
            finally:
                if reused_fd is not None:
                    os.close(reused_fd)
                os.close(parent_fd)

    def test_manifest_close_result_interrupt_never_closes_same_root_reuse(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-close-same-root-reuse-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            original_fd = manifest.root_fds[0]
            target = root / "parent" / "target"
            close_discard_offset = _call_followup_offset(
                recovery_cleanup.CustodiedManifest.close,
                called_name="close",
                following_opname="POP_TOP",
            )
            target_offset = _instruction_after_offset(
                recovery_cleanup.CustodiedManifest.close,
                close_discard_offset,
            )
            interruption = KeyboardInterrupt(
                "injected manifest close result interrupt with same-root FD reuse"
            )
            injected = False
            reused_fd: int | None = None

            def interrupt_and_reopen_same_root(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected, reused_fd
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup.CustodiedManifest.close.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        reused_fd = os.open(
                            target,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        )
                        raise interruption
                return interrupt_and_reopen_same_root

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_and_reopen_same_root)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    manifest.close()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(reused_fd, original_fd)
                self.assertEqual(manifest.root_fds, [])
                self.assertFalse(manifest._closed)
                evidence = manifest.close_evidence[-1]
                self.assertEqual(
                    evidence.state,
                    "ownership-ambiguous-live-same-object",
                )
                assert evidence.observed_identity is not None
                self.assertTrue(
                    directory_identities_match(
                        evidence.observed_identity,
                        evidence.expected_identity,
                    )
                )
                assert reused_fd is not None
                for _ in range(2):
                    with self.assertRaisesRegex(
                        CustodyLostError,
                        "ownership-ambiguous-live-same-object",
                    ):
                        manifest.close()
                    os.fstat(reused_fd)
            finally:
                if reused_fd is not None:
                    os.close(reused_fd)
                os.close(parent_fd)

    def test_manifest_close_result_interrupt_records_unreadable_ambiguity(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-close-result-unreadable-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            descriptor = manifest.root_fds[0]
            interruption = KeyboardInterrupt(
                "injected manifest close call interrupt before close"
            )
            real_close = os.close
            real_fstat = os.fstat
            descriptor_fstat_calls = 0

            def interrupt_close(candidate: int) -> None:
                if candidate == descriptor:
                    raise interruption
                real_close(candidate)

            def unreadable_after_close(candidate: int):
                nonlocal descriptor_fstat_calls
                if candidate == descriptor:
                    descriptor_fstat_calls += 1
                    if descriptor_fstat_calls > 1:
                        raise OSError(
                            errno.EIO,
                            "injected post-close unreadable descriptor",
                        )
                return real_fstat(candidate)

            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "close",
                        side_effect=interrupt_close,
                    ),
                    mock.patch.object(
                        recovery_cleanup.os,
                        "fstat",
                        side_effect=unreadable_after_close,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    manifest.close()
                self.assertIs(caught.exception, interruption)
                self.assertEqual(manifest.root_fds, [])
                self.assertEqual(
                    manifest.close_evidence[-1].state,
                    "ownership-ambiguous-unreadable",
                )
                with self.assertRaisesRegex(
                    CustodyLostError,
                    "ownership-ambiguous-unreadable",
                ):
                    manifest.close()
                os.fstat(descriptor)
            finally:
                os.close(descriptor)
                os.close(parent_fd)

    def test_manifest_close_distinguishes_missing_and_unreadable_custody(
        self,
    ) -> None:
        with self.subTest(state="missing"):
            with owned_temporary_directory("manifest-close-missing-") as root:
                manifest, parent_fd = self._build_empty_manifest(root, "target")
                descriptor = manifest.root_fds[0]
                os.close(descriptor)
                try:
                    with self.assertRaisesRegex(
                        CustodyLostError,
                        "missing-before-close",
                    ):
                        manifest.close()
                    self.assertEqual(manifest.root_fds, [])
                    self.assertFalse(manifest._closed)
                    self.assertEqual(
                        manifest.close_evidence[-1].state,
                        "missing-before-close",
                    )
                finally:
                    os.close(parent_fd)

        with self.subTest(state="unreadable"):
            with owned_temporary_directory("manifest-close-unreadable-") as root:
                manifest, parent_fd = self._build_empty_manifest(root, "target")
                descriptor = manifest.root_fds[0]
                real_fstat = os.fstat

                def unreadable(candidate: int):
                    if candidate == descriptor:
                        raise OSError(errno.EIO, "injected unreadable descriptor")
                    return real_fstat(candidate)

                try:
                    with (
                        mock.patch.object(
                            recovery_cleanup.os,
                            "fstat",
                            side_effect=unreadable,
                        ),
                        self.assertRaisesRegex(
                            CustodyLostError,
                            "unreadable",
                        ),
                    ):
                        manifest.close()
                    self.assertEqual(manifest.root_fds, [])
                    self.assertFalse(manifest._closed)
                    self.assertEqual(
                        manifest.close_evidence[-1].state,
                        "unreadable",
                    )
                    with self.assertRaisesRegex(CustodyLostError, "unreadable"):
                        manifest.close()
                    os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                    os.close(parent_fd)

    def test_delete_result_owner_recovers_call_to_store_interrupt(self) -> None:
        with owned_temporary_directory("manifest-delete-result-owner-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            result_owner = CustodiedDeletionResultOwner()

            def caller() -> dict[str, object]:
                proof = delete_custodied_roots(
                    manifest,
                    result_owner=result_owner,
                )
                result_owner.transfer(proof)
                return result_owner.finish()

            target_offset = _call_followup_offset(
                caller,
                called_name="delete_custodied_roots",
                following_opname="STORE_FAST",
                following_argval="proof",
            )
            interruption = KeyboardInterrupt(
                "injected deletion result CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is caller.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    caller()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertIsNotNone(result_owner.proof)
                self.assertFalse(result_owner.transferred)
                self.assertFalse(result_owner.finished)
                proof = result_owner.finish()
                self.assertIs(proof, result_owner.proof)
                self.assertIs(result_owner.finish(), proof)
                self.assertIs(result_owner.transfer(proof), proof)
                self.assertIs(result_owner.transfer(proof), proof)
                self.assertTrue(result_owner.transferred)
                self.assertTrue(result_owner.finished)
                self.assertEqual(proof["manifest_sha256"], manifest.seal["sha256"])
                self.assertEqual(
                    proof["manifest_record_count"],
                    manifest.seal["record_count"],
                )
                self.assertEqual(proof["removed_entries"], 1)
                self.assertTrue(proof["parent_fsync_complete"])
                self.assertTrue(proof["exact_names_absent"])
                self.assertFalse((root / "parent" / "target").exists())
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_deletion_delivery_state_publication_is_atomic(self) -> None:
        owner = CustodiedDeletionResultOwner()
        body_error = KeyboardInterrupt("synthetic atomic delivery body")
        hook_error = RuntimeError("synthetic atomic delivery hook")
        capture = CustodiedDeletionResultOwner.capture_delivery_error
        instructions = tuple(dis.get_instructions(capture))
        state_store_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "STORE_ATTR"
            and instruction.argval == "_delivery_state"
        )
        target_offset = instructions[state_store_index + 1].offset
        fired = False

        def trace_hook(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal fired
            if getattr(frame, "f_code", None) is capture.__code__:
                frame.f_trace_opcodes = True
                if not fired and event == "opcode" and frame.f_lasti == target_offset:
                    fired = True
                    raise hook_error
            return trace_hook

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace_hook)
            with self.assertRaises(RuntimeError) as caught:
                owner.capture_delivery_error("atomic body", body_error)
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(fired)
        self.assertIs(caught.exception, hook_error)
        self.assertIs(owner.authoritative_delivery_error, body_error)
        self.assertEqual(owner.delivery_errors, (("atomic body", body_error),))
        selected = owner.settle_delivery_boundary(hook_error)
        self.assertIs(selected, body_error)
        self.assertIs(owner.authoritative_delivery_error, body_error)
        self.assertTrue(any(error is hook_error for _, error in owner.delivery_errors))

    def test_delete_operation_handler_boundaries_cross_public_handoff(self) -> None:
        operation = recovery_cleanup._delete_custodied_roots_operation
        operation_instructions = tuple(dis.get_instructions(operation))
        settle_store_offset = _call_followup_offset(
            operation,
            called_name="_settle_custodied_deletion_boundary",
            following_opname="STORE_FAST",
            following_argval="selected",
        )
        final_bare_index = max(
            index
            for index, instruction in enumerate(operation_instructions)
            if instruction.opname == "RAISE_VARARGS" and instruction.arg == 0
        )
        final_jump = operation_instructions[final_bare_index - 1]
        self.assertEqual(final_jump.opname, "POP_JUMP_IF_FALSE")
        settlement = recovery_cleanup._settle_custodied_deletion_boundary
        settlement_attr_pop_offset = _call_followup_offset(
            settlement,
            called_name="setattr",
            following_opname="POP_TOP",
        )
        cases = (
            ("reconcile-call-store", operation, settle_store_offset),
            ("owner-attach-call-pop", settlement, settlement_attr_pop_offset),
            ("final-conditional-jump", operation, final_jump.offset),
            (
                "final-bare-raise",
                operation,
                operation_instructions[final_bare_index].offset,
            ),
        )
        for name, function, target_offset in cases:
            with self.subTest(name=name):  # noqa: SIM117 - keeps hook scope clear
                with owned_temporary_directory(f"delete-api-{name}-") as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"API handler boundary\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"delete-api-{name}",
                    )
                    body_error = KeyboardInterrupt(f"synthetic {name} body")
                    hook_error = RuntimeError(f"synthetic {name} hook")
                    result_owner = CustodiedDeletionResultOwner()
                    fired = False

                    def trace_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        function: object = function,
                        hook_error: RuntimeError = hook_error,
                        target_offset: int = target_offset,
                    ) -> object:
                        nonlocal fired
                        if getattr(frame, "f_code", None) is function.__code__:
                            frame.f_trace_opcodes = True
                            if (
                                not fired
                                and event == "opcode"
                                and frame.f_lasti == target_offset
                            ):
                                fired = True
                                raise hook_error
                        return trace_hook

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(trace_hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_unlink_quarantined_leaf_critical",
                                side_effect=body_error,
                            ),
                            self.assertRaises(KeyboardInterrupt) as caught,
                        ):
                            delete_custodied_roots(
                                manifest,
                                result_owner=result_owner,
                            )
                    finally:
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertIs(caught.exception, body_error)
                        self.assertIsNot(caught.exception, hook_error)
                        self.assertIs(manifest.deletion_result_owner, result_owner)
                        self.assertIs(
                            result_owner.authoritative_delivery_error,
                            body_error,
                        )
                        self.assertTrue(
                            any(
                                error is hook_error
                                for _, error in result_owner.delivery_errors
                            )
                        )
                        self.assertIs(
                            hook_error.custodied_deletion_result_owner,
                            result_owner,
                        )
                        owners = recovery_cleanup.leaf_descriptor_custody_owners(
                            caught.exception
                        )
                        self.assertEqual(len(owners), 1)
                        self.assertEqual(owners[0].state, "closed")
                        evidence = quarantined_root_recovery_evidence(caught.exception)
                        self.assertEqual(len(evidence), 1)
                        self.assertEqual(
                            evidence[0].leaf_descriptor_custody_owners,
                            owners,
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_delete_api_handler_boundaries_cross_caller_handoff(self) -> None:
        instructions = tuple(dis.get_instructions(delete_custodied_roots))
        settle_store_offset = _call_followup_offset(
            delete_custodied_roots,
            called_name="_settle_custodied_deletion_boundary",
            following_opname="STORE_FAST",
            following_argval="selected",
        )
        final_bare_index = max(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "RAISE_VARARGS" and instruction.arg == 0
        )
        final_jump = instructions[final_bare_index - 1]
        self.assertEqual(final_jump.opname, "POP_JUMP_IF_FALSE")
        settlement = recovery_cleanup._settle_custodied_deletion_boundary
        settlement_attr_pop_offset = _call_followup_offset(
            settlement,
            called_name="setattr",
            following_opname="POP_TOP",
        )
        cases = (
            (
                "reconcile-call-store",
                delete_custodied_roots,
                settle_store_offset,
                None,
            ),
            (
                "owner-attach-call-pop",
                settlement,
                settlement_attr_pop_offset,
                delete_custodied_roots.__code__,
            ),
            (
                "final-conditional-jump",
                delete_custodied_roots,
                final_jump.offset,
                None,
            ),
            (
                "final-bare-raise",
                delete_custodied_roots,
                instructions[final_bare_index].offset,
                None,
            ),
        )
        for name, function, target_offset, required_parent_code in cases:
            with self.subTest(name=name):  # noqa: SIM117 - keeps hook scope clear
                with owned_temporary_directory(f"delete-api-{name}-") as root:
                    parent = root / "parent"
                    parent.mkdir(mode=0o700)
                    target = parent / "target"
                    target.mkdir(mode=0o700)
                    (target / "payload.txt").write_bytes(b"public API boundary\n")
                    manifest, parent_fd = self._build_target_manifest(
                        root,
                        target,
                        label=f"delete-api-{name}",
                    )
                    body_error = KeyboardInterrupt(f"synthetic public {name} body")
                    hook_error = RuntimeError(f"synthetic public {name} hook")
                    fired = False

                    def caller(
                        bound_manifest: recovery_cleanup.CustodiedManifest = manifest,
                    ) -> None:
                        try:
                            delete_custodied_roots(bound_manifest)
                        except BaseException as boundary_error:
                            result_owner = bound_manifest.deletion_result_owner
                            assert result_owner is not None
                            selected = result_owner.settle_delivery_boundary(
                                boundary_error
                            )
                            if selected is boundary_error:
                                raise
                            raise selected

                    def trace_hook(
                        frame: object,
                        event: str,
                        _argument: object,
                        function: object = function,
                        hook_error: RuntimeError = hook_error,
                        required_parent_code: object = required_parent_code,
                        target_offset: int = target_offset,
                    ) -> object:
                        nonlocal fired
                        if getattr(frame, "f_code", None) is function.__code__:
                            parent_frame = getattr(frame, "f_back", None)
                            if (
                                required_parent_code is not None
                                and getattr(
                                    parent_frame,
                                    "f_code",
                                    None,
                                )
                                is not required_parent_code
                            ):
                                return trace_hook
                            frame.f_trace_opcodes = True
                            if (
                                not fired
                                and event == "opcode"
                                and frame.f_lasti == target_offset
                            ):
                                fired = True
                                raise hook_error
                        return trace_hook

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(trace_hook)
                        with (
                            mock.patch.object(
                                recovery_cleanup,
                                "_unlink_quarantined_leaf_critical",
                                side_effect=body_error,
                            ),
                            self.assertRaises(KeyboardInterrupt) as caught,
                        ):
                            caller()
                    finally:
                        sys.settrace(previous_trace)

                    try:
                        self.assertTrue(fired)
                        self.assertIs(caught.exception, body_error)
                        self.assertIsNot(caught.exception, hook_error)
                        result_owner = manifest.deletion_result_owner
                        self.assertIsNotNone(result_owner)
                        assert result_owner is not None
                        self.assertIs(
                            result_owner.authoritative_delivery_error,
                            body_error,
                        )
                        self.assertIs(
                            hook_error.custodied_deletion_result_owner,
                            result_owner,
                        )
                    finally:
                        manifest.close()
                        os.close(parent_fd)

    def test_delete_api_successful_return_retains_default_owner_and_proof(
        self,
    ) -> None:
        with owned_temporary_directory("delete-api-success-return-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            hook_error = RuntimeError("synthetic delete API RETURN hook")
            returned_proof: object | None = None
            fired = False

            def profile_hook(
                frame: object,
                event: str,
                argument: object,
            ) -> None:
                nonlocal fired, returned_proof
                if (
                    not fired
                    and event == "return"
                    and getattr(frame, "f_code", None)
                    is delete_custodied_roots.__code__
                ):
                    fired = True
                    returned_proof = argument
                    raise hook_error

            previous_profile = sys.getprofile()
            try:
                sys.setprofile(profile_hook)
                with self.assertRaises(RuntimeError) as caught:
                    delete_custodied_roots(manifest)
            finally:
                sys.setprofile(previous_profile)

            try:
                self.assertTrue(fired)
                self.assertIs(caught.exception, hook_error)
                result_owner = manifest.deletion_result_owner
                self.assertIsNotNone(result_owner)
                assert result_owner is not None
                self.assertIs(result_owner.proof, returned_proof)
                self.assertIs(result_owner.finish(), returned_proof)
                self.assertTrue(result_owner.proof["exact_names_absent"])
                self.assertFalse((root / "parent" / "target").exists())
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_root_deletion_proof_precedes_aggregate_publication(self) -> None:
        with owned_temporary_directory("manifest-root-proof-owner-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            result_owner = CustodiedDeletionResultOwner()
            target_offset = _call_followup_offset(
                recovery_cleanup._delete_custodied_roots_operation,
                called_name="_remove_quarantined_empty_root",
                following_opname="POP_TOP",
            )
            interruption = KeyboardInterrupt(
                "injected root deletion result interruption"
            )
            injected = False

            def interrupt_after_root_proof(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_custodied_roots_operation.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_after_root_proof

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_after_root_proof)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertFalse((root / "parent" / "target").exists())
                self.assertIsNone(result_owner.proof)
                self.assertEqual(len(result_owner.root_outcomes), 1)
                outcome = result_owner.root_outcomes[0]
                self.assertEqual(outcome.state, "complete")
                self.assertIsNotNone(outcome.proof)
                assert outcome.proof is not None
                self.assertTrue(outcome.proof["exact_name_absent"])
                self.assertTrue(outcome.proof["quarantine_name_absent"])
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_second_root_early_failure_preserves_first_root_proof_owner(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-two-root-owner-") as root:
            manifest, parent_fd = self._build_empty_manifest(
                root,
                "first",
                "second",
            )
            result_owner = CustodiedDeletionResultOwner()
            original_require = manifest.require_root_custody
            second_root_checks = 0
            injected = CustodyLostError("synthetic second-root early failure")

            def fail_second_loop_check(index: int) -> None:
                nonlocal second_root_checks
                original_require(index)
                if index == 1:
                    second_root_checks += 1
                    if second_root_checks == 2:
                        raise injected

            try:
                with (
                    mock.patch.object(
                        manifest,
                        "require_root_custody",
                        side_effect=fail_second_loop_check,
                    ),
                    self.assertRaises(CustodyLostError) as caught,
                ):
                    delete_custodied_roots(
                        manifest,
                        result_owner=result_owner,
                    )

                self.assertIs(caught.exception, injected)
                self.assertIs(
                    caught.exception.custodied_deletion_result_owner,
                    result_owner,
                )
                self.assertEqual(len(result_owner.root_outcomes), 1)
                outcome = result_owner.root_outcomes[0]
                self.assertEqual(outcome.root_index, 0)
                self.assertEqual(outcome.state, "complete")
                self.assertIsNotNone(outcome.proof)
                self.assertFalse((root / "parent" / "first").exists())
                self.assertTrue((root / "parent" / "second").is_dir())
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_manifest_retention_call_to_store_keeps_error_owner(self) -> None:
        with owned_temporary_directory("manifest-retention-owner-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            result_owner = CustodiedManifestResultOwner()
            result_owner.publish(manifest)
            retention_error = RuntimeError("synthetic retention")
            retention_error.retained_resources = []

            def caller() -> recovery_cleanup.CustodiedManifest:
                retained_manifest = result_owner.retain(retention_error)
                return retained_manifest

            target_offset = _call_followup_offset(
                caller,
                called_name="retain",
                following_opname="STORE_FAST",
                following_argval="retained_manifest",
            )
            interruption = KeyboardInterrupt(
                "injected manifest retention result interruption"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is caller.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    caller()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertTrue(result_owner.preserves(manifest))
                self.assertIn(manifest, retention_error.retained_resources)
                os.fstat(manifest.root_fds[0])
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_large_manifest_index_is_linear(self) -> None:
        child_count = 10_000
        counters = {"iterations": 0, "path_reads": 0}
        identity = Identity(
            device=1,
            inode=1,
            mode=stat.S_IFDIR | 0o700,
            link_count=1,
            uid=os.getuid(),
            size=0,
        )
        records = [
            _CountingRecord(path=b"", identity=identity, counters=counters),
            *(
                _CountingRecord(
                    path=f"directory-{index:05d}".encode("ascii"),
                    identity=identity,
                    counters=counters,
                )
                for index in range(child_count)
            ),
        ]

        index = _index_manifest_records(
            _CountingRecords(records, counters),  # type: ignore[arg-type]
            root_count=1,
            entry_cap=len(records),
            deadline=time.monotonic() + 5.0,
        )

        self.assertEqual(counters["iterations"], 2)
        self.assertLessEqual(counters["path_reads"], len(records) * 8)
        self.assertEqual(len(index[(0, b"")]), child_count)
        self.assertEqual(sum(len(children) for children in index.values()), child_count)

    def test_delete_deadline_after_quarantine_retains_tree_without_recursion(
        self,
    ) -> None:
        with owned_temporary_directory("manifest-deadline-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload.txt"
            payload.write_bytes(b"retained\n")
            payload.chmod(0o600)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                manifest = build_custodied_manifest(
                    roots=(
                        RootSpec(
                            label="checkout",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=identity_from_stat(os.stat(target)),
                        ),
                    ),
                    manifest_path=control / "manifest.bin",
                    entry_cap=10,
                    payload_cap=4096,
                    deadline=time.monotonic() + 5.0,
                )
                with manifest:
                    clock_reads = 0

                    def monotonic() -> float:
                        nonlocal clock_reads
                        clock_reads += 1
                        return 0.0 if clock_reads < 6 else 2.0

                    manifest.deadline = 1.0
                    with mock.patch(
                        "review_supervisor.recovery_cleanup.time.monotonic",
                        side_effect=monotonic,
                    ):
                        with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                            delete_custodied_roots(manifest)
                self.assertFalse(target.exists())
                quarantines = tuple(
                    path
                    for path in parent.iterdir()
                    if path.name.startswith(".targeted-cleanup-quarantine-")
                )
                self.assertEqual(len(quarantines), 1)
                self.assertEqual(
                    (quarantines[0] / payload.name).read_bytes(),
                    b"retained\n",
                )
            finally:
                os.close(parent_fd)

    def test_delete_quarantines_root_before_recursive_deletion(self) -> None:
        with owned_temporary_directory("manifest-quarantine-order-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            nested = target / "nested"
            nested.mkdir(mode=0o700)
            payload = nested / "payload.txt"
            payload.write_bytes(b"delete after quarantine\n")
            payload.chmod(0o600)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.stat(target))
            try:
                manifest = build_custodied_manifest(
                    roots=(
                        RootSpec(
                            label="checkout",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                    ),
                    manifest_path=control / "manifest.bin",
                    entry_cap=10,
                    payload_cap=4096,
                    deadline=time.monotonic() + 5.0,
                )
                real_delete = recovery_cleanup._delete_directory_contents
                root_recursions = 0

                def observe_quarantine_before_delete(**kwargs):
                    nonlocal root_recursions
                    if kwargs["prefix"] == b"":
                        root_recursions += 1
                        self.assertFalse(target.exists())
                        quarantines = tuple(
                            path
                            for path in parent.iterdir()
                            if path.name.startswith(".targeted-cleanup-quarantine-")
                        )
                        self.assertEqual(len(quarantines), 1)
                        self.assertTrue(
                            directory_identities_match(
                                identity_from_stat(os.stat(quarantines[0])),
                                target_identity,
                            )
                        )
                        self.assertEqual(
                            (quarantines[0] / nested.name / payload.name).read_bytes(),
                            b"delete after quarantine\n",
                        )
                    return real_delete(**kwargs)

                with (
                    manifest,
                    mock.patch.object(
                        recovery_cleanup,
                        "_delete_directory_contents",
                        side_effect=observe_quarantine_before_delete,
                    ),
                ):
                    proof = delete_custodied_roots(manifest)

                self.assertEqual(root_recursions, 1)
                self.assertEqual(
                    proof["removed_entries"],
                    proof["manifest_record_count"],
                )
                self.assertFalse(target.exists())
                self.assertFalse(
                    any(
                        path.name.startswith(".targeted-cleanup-quarantine-")
                        for path in parent.iterdir()
                    )
                )
            finally:
                os.close(parent_fd)

    def test_quarantine_rename_result_interrupt_exposes_live_recovery_fds(
        self,
    ) -> None:
        with owned_temporary_directory("cleanup-quarantine-rename-result-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.fstat(target_fd))
            target_offset = _call_followup_offset(
                recovery_cleanup._quarantine_custodied_root,
                called_name="rename",
                following_opname="POP_TOP",
            )
            interruption = KeyboardInterrupt(
                "injected quarantine rename syscall-result interrupt"
            )
            injected = False

            def interrupt_rename_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._quarantine_custodied_root.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_rename_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_rename_result)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    recovery_cleanup._quarantine_custodied_root(
                        RootSpec(
                            label="rename-result-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].stage, "rename-result-unproven")
                self.assertEqual(
                    evidence[0].protected_property,
                    "object-identity-and-access-policy",
                )
                os.fstat(evidence[0].parent_fd)
                os.fstat(evidence[0].root_fd)
                self.assertFalse(target.exists())
                self.assertTrue(
                    (parent / os.fsdecode(evidence[0].quarantine_name)).is_dir()
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)

    def test_quarantine_return_store_interrupt_preserves_prepublished_owner(
        self,
    ) -> None:
        with owned_temporary_directory("cleanup-quarantine-return-store-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.fstat(target_fd))
            target_offset = _call_followup_offset(
                quarantine_and_remove_empty_root,
                called_name="_quarantine_custodied_root",
                following_opname="STORE_FAST",
                following_argval="quarantine_name",
            )
            interruption = KeyboardInterrupt(
                "injected quarantine return CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is quarantine_and_remove_empty_root.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    quarantine_and_remove_empty_root(
                        RootSpec(
                            label="return-store-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(
                    evidence[0].stage,
                    "quarantine-result-publication",
                )
                os.fstat(evidence[0].parent_fd)
                os.fstat(evidence[0].root_fd)
                self.assertFalse(target.exists())
                self.assertTrue(
                    (parent / os.fsdecode(evidence[0].quarantine_name)).is_dir()
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)

    def test_post_rename_fsync_failure_exposes_quarantine_recovery(self) -> None:
        with owned_temporary_directory("cleanup-quarantine-fsync-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.fstat(target_fd))
            cause = RuntimeError("synthetic fsync cause")
            injected = OSError("synthetic parent fsync failure")
            injected.__cause__ = cause
            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "fsync",
                        side_effect=injected,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    recovery_cleanup._quarantine_custodied_root(
                        RootSpec(
                            label="fsync-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )

                self.assertIs(caught.exception, injected)
                self.assertIs(caught.exception.__cause__, cause)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertIsInstance(
                    evidence[0],
                    QuarantinedRootRecoveryEvidence,
                )
                self.assertEqual(evidence[0].stage, "post-rename-parent-fsync")
                self.assertEqual(evidence[0].parent_fd, parent_fd)
                self.assertEqual(evidence[0].root_fd, target_fd)
                self.assertEqual(evidence[0].original_name, b"target")
                self.assertEqual(
                    evidence[0].parent_identity,
                    identity_from_stat(os.fstat(parent_fd)),
                )
                self.assertEqual(evidence[0].expected_identity, target_identity)
                self.assertTrue(
                    directory_identities_match(
                        identity_from_stat(os.fstat(evidence[0].root_fd)),
                        target_identity,
                    )
                )
                quarantine = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertFalse(target.exists())
                self.assertTrue(
                    directory_identities_match(
                        identity_from_stat(os.stat(quarantine)),
                        target_identity,
                    )
                )
                wrapper = RuntimeError("synthetic retention wrapper")
                wrapper.__cause__ = caught.exception
                self.assertEqual(
                    quarantined_root_recovery_evidence(wrapper),
                    evidence,
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)

    def test_post_rename_revalidation_failure_exposes_quarantine_recovery(
        self,
    ) -> None:
        with owned_temporary_directory("cleanup-quarantine-revalidation-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.fstat(target_fd))
            injected = CustodyLostError("synthetic quarantine revalidation failure")
            real_descriptor_identity = recovery_cleanup._root_descriptor_identity
            descriptor_checks = 0

            def fail_post_rename_revalidation(*args, **kwargs):
                nonlocal descriptor_checks
                descriptor_checks += 1
                if descriptor_checks == 2:
                    raise injected
                return real_descriptor_identity(*args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        recovery_cleanup,
                        "_root_descriptor_identity",
                        side_effect=fail_post_rename_revalidation,
                    ),
                    self.assertRaises(CustodyLostError) as caught,
                ):
                    recovery_cleanup._quarantine_custodied_root(
                        RootSpec(
                            label="revalidation-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )

                self.assertIs(caught.exception, injected)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(
                    evidence[0].stage,
                    "post-rename-quarantine-revalidation",
                )
                self.assertEqual(evidence[0].parent_fd, parent_fd)
                self.assertEqual(evidence[0].root_fd, target_fd)
                self.assertEqual(evidence[0].original_name, b"target")
                self.assertEqual(evidence[0].expected_identity, target_identity)
                quarantine = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertFalse(target.exists())
                self.assertTrue(
                    directory_identities_match(
                        identity_from_stat(os.stat(quarantine)),
                        target_identity,
                    )
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)

    def test_recursive_delete_failure_exposes_quarantine_recovery(self) -> None:
        with owned_temporary_directory("cleanup-quarantine-recursive-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            for name in ("first.txt", "second.txt"):
                payload = target / name
                payload.write_text(name, encoding="ascii")
                payload.chmod(0o600)
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.stat(target))
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label="recursive-regression",
                        parent_fd=parent_fd,
                        parent_identity=identity_from_stat(os.fstat(parent_fd)),
                        name=b"target",
                        expected_identity=target_identity,
                    ),
                ),
                manifest_path=control / "manifest.bin",
                entry_cap=10,
                payload_cap=4096,
                deadline=time.monotonic() + 5.0,
            )
            real_unlink = recovery_cleanup.os.unlink
            unlink_calls = 0
            cause = RuntimeError("synthetic recursive cause")
            injected = OSError("synthetic recursive deletion failure")
            injected.__cause__ = cause

            def fail_second_unlink(name: bytes, *, dir_fd: int) -> None:
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_calls == 2:
                    raise injected
                real_unlink(name, dir_fd=dir_fd)

            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "unlink",
                        side_effect=fail_second_unlink,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    delete_custodied_roots(manifest)

                self.assertIs(caught.exception, injected)
                self.assertIs(caught.exception.__cause__, cause)
                evidence = quarantined_root_recovery_evidence(caught.exception)
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].stage, "recursive-delete")
                self.assertEqual(evidence[0].parent_fd, parent_fd)
                self.assertEqual(evidence[0].root_fd, manifest.root_fds[0])
                self.assertEqual(evidence[0].original_name, b"target")
                self.assertEqual(evidence[0].expected_identity, target_identity)
                os.fstat(evidence[0].root_fd)
                quarantine = parent / os.fsdecode(evidence[0].quarantine_name)
                self.assertFalse(target.exists())
                self.assertEqual(len(tuple(quarantine.iterdir())), 1)
            finally:
                manifest.close()
                os.close(parent_fd)

    def test_quarantine_revalidation_retains_swapped_original_and_replacement(
        self,
    ) -> None:
        with owned_temporary_directory("cleanup-quarantine-swap-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            displaced = parent / "original-evidence"
            replacement = parent / "replacement-stage"
            replacement.mkdir(mode=0o700)
            marker = replacement / "replacement.txt"
            marker.write_text("replacement evidence", encoding="ascii")
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            original_identity = identity_from_stat(os.fstat(target_fd))
            real_rename = os.rename
            swapped = False

            def swap_before_quarantine(
                source: bytes,
                destination: bytes,
                *,
                src_dir_fd: int,
                dst_dir_fd: int,
            ) -> None:
                nonlocal swapped
                if not swapped and source == b"target":
                    swapped = True
                    real_rename(target, displaced)
                    real_rename(replacement, target)
                real_rename(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "rename",
                        side_effect=swap_before_quarantine,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "quarantined root changed",
                    ),
                ):
                    quarantine_and_remove_empty_root(
                        RootSpec(
                            label="swap-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=original_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )

                self.assertTrue(swapped)
                self.assertEqual(
                    identity_from_stat(os.stat(displaced)).inode,
                    original_identity.inode,
                )
                quarantines = tuple(
                    path
                    for path in parent.iterdir()
                    if path.name.startswith(".targeted-cleanup-quarantine-")
                )
                self.assertEqual(len(quarantines), 1)
                self.assertEqual(
                    (quarantines[0] / marker.name).read_text(encoding="ascii"),
                    "replacement evidence",
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)

    def test_quarantine_rmdir_aba_never_deletes_public_replacement(self) -> None:
        with owned_temporary_directory("cleanup-quarantine-aba-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            parent_fd = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_fd = os.open(
                target,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            target_identity = identity_from_stat(os.fstat(target_fd))
            real_rmdir = os.rmdir
            injected = False

            def replace_public_name(
                name: bytes,
                *,
                dir_fd: int,
            ) -> None:
                nonlocal injected
                if not injected and name.startswith(b".targeted-cleanup-quarantine-"):
                    injected = True
                    os.mkdir(b"target", 0o700, dir_fd=dir_fd)
                    replacement_fd = os.open(
                        b"target",
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=dir_fd,
                    )
                    try:
                        marker_fd = os.open(
                            b"replacement.txt",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            0o600,
                            dir_fd=replacement_fd,
                        )
                        os.write(marker_fd, b"replacement evidence")
                        os.close(marker_fd)
                    finally:
                        os.close(replacement_fd)
                real_rmdir(name, dir_fd=dir_fd)

            try:
                with (
                    mock.patch.object(
                        recovery_cleanup.os,
                        "rmdir",
                        side_effect=replace_public_name,
                    ),
                    self.assertRaisesRegex(
                        CustodyLostError,
                        "replaced during quarantine removal",
                    ),
                ):
                    quarantine_and_remove_empty_root(
                        RootSpec(
                            label="aba-regression",
                            parent_fd=parent_fd,
                            parent_identity=identity_from_stat(os.fstat(parent_fd)),
                            name=b"target",
                            expected_identity=target_identity,
                        ),
                        target_fd,
                        deadline=time.monotonic() + 5.0,
                    )

                self.assertTrue(injected)
                self.assertEqual(
                    (target / "replacement.txt").read_text(encoding="ascii"),
                    "replacement evidence",
                )
            finally:
                os.close(target_fd)
                os.close(parent_fd)


@unittest.skipUnless(GIT.is_file(), "/usr/bin/git is required")
class TargetedRecoveryTests(unittest.TestCase):
    def _prepare(
        self,
        root: pathlib.Path,
        *,
        cleanup_status: str = "clean",
        lock_reason: str = "independent-codex-pr-review",
    ):
        repo, base_sha, head_sha = _build_repository(root)
        info = inspect_repository(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            git_executable=str(GIT),
        )
        checkout_parent = root / "checkouts"
        checkout_parent.mkdir(mode=0o700)
        retention = root / "retention"
        retention.mkdir(mode=0o700)
        attempt_id = f"1-{'b' * 32}"
        attempt = retention / f"attempt-{attempt_id}"
        attempt.mkdir(mode=0o700)
        control = create_sanitized_view(info, attempt / "git-control")
        worktree = checkout_parent / "review-fixture"
        registration = add_detached_worktree(
            info,
            worktree,
            lock_reason=lock_reason,
            control=control,
        )
        initialize_index(info, registration)
        count, path_bytes = enumerate_registration(registration.registration)
        registration_value = _registration_json(registration)
        registration_value["descendant_count"] = count
        registration_value["descendant_path_bytes"] = path_bytes
        namespace = checkout_parent / ".review-control-fixture"
        namespace.mkdir(mode=0o700)
        state = {
            "schema_version": SCHEMA_VERSION,
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "attempt_id": attempt_id,
            "record_generation": 1,
            "previous_record_sha256": None,
            "phase": "reviewed",
            "repo": str(repo),
            "base_sha": base_sha,
            "head_sha": head_sha,
            "git_executable": str(GIT),
            "worktree_path": str(worktree),
            "control_namespace": str(namespace),
            "targeted_manifest_published": str(namespace / "manifest.bin"),
            "registration": registration_value,
            "git_control_binding": registration_value["control"],
            "worktree_status": "active",
            "checkout_settlement": "outstanding",
            "checkout_physical_remaining_by_fs": {"fixture": 1},
            "reservation_status": "outstanding",
            "cleanup_status": cleanup_status,
            "checkout_parent_binding": {
                "path": str(checkout_parent),
                "identity": identity_from_stat(os.stat(checkout_parent)).to_json(),
            },
            "common_git_dir_binding": {
                "path": str(info.common_git_dir),
                "identity": identity_from_stat(os.stat(info.common_git_dir)).to_json(),
            },
            "admission": {
                "targeted_manifest_entry_bound": 10_000,
                "targeted_manifest_payload_bound": 8 * 1024 * 1024,
            },
            "unsupported_clauses": [
                {"clause": "automatic-targeted-mixed-worktree-removal"},
                {"clause": "optional-fixture-clause"},
            ],
        }
        bind_attempt_state(
            state,
            retention_root=retention,
            attempt_dir=attempt,
        )
        state_path = attempt / "state.json"
        state_path.write_bytes(canonical_json(state))
        state_path.chmod(0o600)
        disk, _, digest = read_attempt_state(attempt)
        return retention, attempt, worktree, registration, namespace, disk, digest

    def _cleanup(self, retention, attempt, state, digest):
        with acquire_retention_lease(
            retention,
            deadline=time.monotonic() + 5.0,
        ) as lease:
            with open_attempt_lease(lease, attempt) as bound_attempt:
                return _cleanup_worktree(
                    entrypoint=ENTRYPOINT,
                    attempt=bound_attempt,
                    state=state,
                    state_digest=digest,
                )

    def test_checkout_only_is_removed_from_external_manifest(self) -> None:
        with owned_temporary_directory("checkout-only-") as root:
            (
                retention,
                attempt,
                worktree,
                registration,
                namespace,
                state,
                digest,
            ) = self._prepare(root, cleanup_status="logs-truncated")
            diagnostic = attempt / "codex.stderr.0.gz"
            diagnostic.write_bytes(b"retained diagnostics\n")
            diagnostic.chmod(0o600)
            shutil.rmtree(registration.registration)
            scanned_git_dirs: list[pathlib.Path] = []
            original_scan = runtime.enumerate_registration_conflicts

            def capture_registration_scan(
                *,
                common_git_dir: pathlib.Path,
                worktree: pathlib.Path,
            ):
                scanned_git_dirs.append(common_git_dir)
                return original_scan(
                    common_git_dir=common_git_dir,
                    worktree=worktree,
                )

            with mock.patch(
                "review_supervisor.runtime.enumerate_registration_conflicts",
                side_effect=capture_registration_scan,
            ):
                state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(
                state["checkout_settlement"],
                "exact",
                state.get("cleanup_error"),
            )
            self.assertEqual(
                state["checkout_cleanup_evidence"]["branch"], "checkout-only"
            )
            self.assertEqual(state["cleanup_status"], "logs-truncated")
            self.assertFalse(state["cleanup_warning"]["outstanding"])
            self.assertTrue(state["cleanup_warning"]["non_ttl"])
            self.assertEqual(state["targeted_cleanup"]["stage"], "complete")
            self.assertFalse(worktree.exists())
            self.assertFalse(namespace.exists())
            self.assertTrue(diagnostic.is_file())
            self.assertTrue(scanned_git_dirs)
            self.assertEqual(
                set(scanned_git_dirs),
                {registration.control.path},
            )
            clauses = {item["clause"] for item in state["unsupported_clauses"]}
            self.assertEqual(clauses, {"optional-fixture-clause"})

    def test_registration_only_is_removed_from_external_manifest(self) -> None:
        with owned_temporary_directory("registration-only-") as root:
            (
                retention,
                attempt,
                worktree,
                registration,
                namespace,
                state,
                digest,
            ) = self._prepare(root)
            shutil.rmtree(worktree)

            state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(state["checkout_settlement"], "exact")
            self.assertEqual(
                state["checkout_cleanup_evidence"]["branch"],
                "registration-only",
            )
            self.assertEqual(state["cleanup_status"], "cleanup-warning")
            self.assertFalse(registration.registration.exists())
            self.assertFalse(namespace.exists())
            proof = state["checkout_cleanup_evidence"]["deletion_proof"]
            self.assertTrue(proof["parent_fsync_complete"])
            self.assertTrue(proof["exact_names_absent"])

    def test_production_deletion_call_to_store_persists_aggregate_owner(
        self,
    ) -> None:
        with owned_temporary_directory("registration-result-owner-") as root:
            (
                retention,
                attempt,
                worktree,
                registration,
                _,
                state,
                digest,
            ) = self._prepare(root)
            shutil.rmtree(worktree)
            target_offset = _call_followup_offset(
                runtime._cleanup_worktree,
                called_name="delete_custodied_roots",
                following_opname="STORE_FAST",
                following_argval="deletion_result",
            )
            interruption = KeyboardInterrupt(
                "injected production deletion CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is runtime._cleanup_worktree.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                state, _ = self._cleanup(retention, attempt, state, digest)
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertEqual(state["worktree_status"], "manual-recovery-required")
            self.assertEqual(state["checkout_settlement"], "outstanding")
            self.assertFalse(registration.registration.exists())
            self.assertEqual(
                state["worktree_cleanup_intent"]["stage"],
                "deletion-proven",
            )
            progress = state["checkout_cleanup_progress"]
            self.assertEqual(progress["branch"], "registration-only")
            self.assertTrue(progress["parent_fsync_complete"])
            self.assertTrue(progress["exact_names_absent"])
            ownership = state["cleanup_recovery_evidence"]["deletion_result_ownership"]
            self.assertEqual(ownership["aggregate_result_state"], "published")
            self.assertEqual(ownership["expected_root_count"], 1)
            self.assertEqual(ownership["completed_root_count"], 1)
            self.assertTrue(ownership["result_transferred"])
            self.assertTrue(ownership["result_finished"])
            self.assertEqual(
                ownership,
                state["targeted_cleanup"]["deletion_result_ownership"],
            )

    def test_production_partial_deletion_persists_per_root_owner(self) -> None:
        with owned_temporary_directory("registration-root-owner-") as root:
            (
                retention,
                attempt,
                worktree,
                registration,
                _,
                state,
                digest,
            ) = self._prepare(root)
            shutil.rmtree(worktree)
            target_offset = _call_followup_offset(
                recovery_cleanup._delete_custodied_roots_operation,
                called_name="_remove_quarantined_empty_root",
                following_opname="POP_TOP",
            )
            interruption = SystemExit("injected production per-root proof interruption")
            injected = False

            def interrupt_root_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is recovery_cleanup._delete_custodied_roots_operation.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_root_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_root_result)
                state, _ = self._cleanup(retention, attempt, state, digest)
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertEqual(state["worktree_status"], "manual-recovery-required")
            self.assertFalse(registration.registration.exists())
            self.assertEqual(
                state["worktree_cleanup_intent"]["stage"],
                "deletion-result-partial",
            )
            progress = state["checkout_cleanup_progress"]
            self.assertEqual(progress["result"], "partial-or-unproven")
            ownership = progress["deletion_result_ownership"]
            self.assertEqual(ownership["aggregate_result_state"], "not-published")
            self.assertEqual(ownership["expected_root_count"], 1)
            self.assertEqual(ownership["completed_root_count"], 1)
            self.assertFalse(ownership["result_finished"])
            self.assertEqual(len(ownership["roots"]), 1)
            root_proof = ownership["roots"][0]
            self.assertEqual(root_proof["state"], "complete")
            self.assertTrue(root_proof["proof"]["exact_name_absent"])
            self.assertTrue(root_proof["proof"]["quarantine_name_absent"])
            self.assertEqual(
                ownership,
                state["cleanup_recovery_evidence"]["deletion_result_ownership"],
            )

    def test_absent_registration_record_rejects_alias_before_settlement(self) -> None:
        with owned_temporary_directory("registration-alias-") as root:
            retention, attempt, worktree, registration, _, state, digest = (
                self._prepare(root)
            )
            state["registration"] = None
            state["record_generation"] += 1
            state["previous_record_sha256"] = digest
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            state, _, digest = read_attempt_state(attempt)

            state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(state["checkout_settlement"], "outstanding")
            self.assertEqual(state["worktree_status"], "manual-recovery-required")
            evidence = state["cleanup_recovery_evidence"]["registration_scan"]
            self.assertIn(registration.registration.name, evidence["alias_matches"])
            self.assertTrue(worktree.exists())
            self.assertTrue(registration.registration.exists())

    def test_create_in_progress_recovers_authenticated_locked_registration(
        self,
    ) -> None:
        with owned_temporary_directory("registration-create-intent-") as root:
            lock_reason = f"independent-codex-pr-review:{'c' * 64}"
            retention, attempt, worktree, registration, _, state, digest = (
                self._prepare(root, lock_reason=lock_reason)
            )
            state["registration"] = None
            state["phase"] = "worktree-adding"
            state["worktree_status"] = "adding"
            state["worktree_create_intent"] = {
                "version": 2,
                "worktree": str(worktree),
                "control_git_dir": str(registration.control.path),
                "registration_parent": str(registration.registration.parent),
                "lock_reason": lock_reason,
            }
            state["record_generation"] += 1
            state["previous_record_sha256"] = digest
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            state, _, digest = read_attempt_state(attempt)

            config = pathlib.Path(state["repo"]) / ".git" / "config"
            original_config = config.read_bytes()
            original_run = gitraw.run_bounded
            injected_calls = 0

            def run_with_source_config_aba(
                *args: object,
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                nonlocal injected_calls
                injected_calls += 1
                config.write_bytes(b"[include]\n\tpath = /untrusted/recovery.config\n")
                try:
                    return original_run(*args, **kwargs)
                finally:
                    config.write_bytes(original_config)

            with mock.patch(
                "review_supervisor.gitraw.run_bounded",
                side_effect=run_with_source_config_aba,
            ):
                state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(
                state["checkout_settlement"],
                "exact",
                state.get("cleanup_error"),
            )
            self.assertGreaterEqual(injected_calls, 5)
            self.assertEqual(state["worktree_status"], "removed")
            self.assertEqual(
                state["checkout_cleanup_evidence"]["branch"],
                "both-present",
            )
            self.assertFalse(worktree.exists())
            self.assertFalse(registration.registration.exists())

    def test_bound_control_without_created_worktree_cleans_exactly(self) -> None:
        with owned_temporary_directory("control-before-worktree-") as root:
            retention, attempt, worktree, registration, _, state, digest = (
                self._prepare(root)
            )
            remove_both_present_worktree(
                inspect_repository(
                    repo=pathlib.Path(state["repo"]),
                    base_sha=state["base_sha"],
                    head_sha=state["head_sha"],
                    git_executable=state["git_executable"],
                ),
                registration,
            )
            state["registration"] = None
            state["phase"] = "worktree-adding"
            state["worktree_status"] = "adding"
            state["worktree_create_intent"] = {
                "version": 2,
                "worktree": str(worktree),
                "control_git_dir": str(registration.control.path),
                "registration_parent": str(registration.registration.parent),
                "lock_reason": f"independent-codex-pr-review:{'d' * 64}",
            }
            state["record_generation"] += 1
            state["previous_record_sha256"] = digest
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            state, _, digest = read_attempt_state(attempt)

            state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(state["checkout_settlement"], "exact")
            self.assertEqual(state["worktree_status"], "absent")
            self.assertFalse(registration.control.path.exists())

    def test_persisted_intent_without_live_descriptors_requires_manual_recovery(
        self,
    ) -> None:
        with owned_temporary_directory("custody-lost-") as root:
            retention, attempt, worktree, _, _, state, digest = self._prepare(root)
            state["worktree_cleanup_intent"] = {
                "version": 1,
                "stage": "intent-persisted",
                "outstanding": True,
            }
            state["record_generation"] += 1
            state["previous_record_sha256"] = digest
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            state, _, digest = read_attempt_state(attempt)

            state, _ = self._cleanup(retention, attempt, state, digest)

            self.assertEqual(state["worktree_status"], "manual-recovery-required")
            self.assertEqual(state["checkout_settlement"], "outstanding")
            self.assertTrue(state["cleanup_warning"]["outstanding"])
            self.assertTrue(worktree.exists())


if __name__ == "__main__":
    unittest.main()
