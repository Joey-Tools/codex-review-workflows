from __future__ import annotations

import dis
import errno
import os
import pathlib
import shutil
import stat
import sys
import time
import unittest
from unittest import mock

import review_supervisor.gitraw as gitraw
import review_supervisor.recovery_cleanup as recovery_cleanup
import review_supervisor.runtime as runtime

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
    CustodiedDeletionResultOwner,
    CustodiedManifestResultOwner,
    CustodyLostError,
    QuarantinedRootRecoveryEvidence,
    RootSpec,
    _KIND_DIRECTORY,
    _index_manifest_records,
    build_custodied_manifest,
    delete_custodied_roots,
    quarantine_and_remove_empty_root,
    quarantined_root_recovery_evidence,
)
from review_supervisor.runtime import _cleanup_worktree, _registration_json
from review_supervisor.secureio import (
    canonical_json,
    directory_identities_match,
    identity_from_stat,
)

from tests.support import bind_attempt_state, owned_temporary_directory
from tests.test_git_checkout import GIT, _build_repository


ENTRYPOINT = (
    pathlib.Path(__file__).resolve().parent.parent / "independent-codex-pr-review"
)


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

    def test_manifest_close_partial_interrupt_retains_only_live_descriptors(
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
                self.assertFalse(manifest._closed)
                self.assertEqual(manifest.root_fds, [original_fds[1]])
                with self.assertRaises(OSError) as first_closed:
                    os.fstat(original_fds[0])
                self.assertEqual(first_closed.exception.errno, errno.EBADF)
                os.fstat(original_fds[1])
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
                with self.assertRaises(OSError) as second_closed:
                    os.fstat(original_fds[1])
                self.assertEqual(second_closed.exception.errno, errno.EBADF)
            finally:
                if manifest.root_fds:
                    manifest.close()
                os.close(parent_fd)

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

    def test_root_deletion_proof_precedes_aggregate_publication(self) -> None:
        with owned_temporary_directory("manifest-root-proof-owner-") as root:
            manifest, parent_fd = self._build_empty_manifest(root, "target")
            result_owner = CustodiedDeletionResultOwner()
            target_offset = _call_followup_offset(
                delete_custodied_roots,
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
                if getattr(frame, "f_code", None) is delete_custodied_roots.__code__:
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
                delete_custodied_roots,
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
                if getattr(frame, "f_code", None) is delete_custodied_roots.__code__:
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
