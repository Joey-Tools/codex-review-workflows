from __future__ import annotations

import pathlib
import time
import unittest
from unittest import mock

from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    PROCESS_ENVELOPE_BYTES,
    SCHEMA_VERSION,
)
from review_supervisor.errors import SupervisorError
from review_supervisor.ledger import (
    EntryCountMismatch,
    INITIAL_CRASH_RECLAIM_AGE_SECONDS,
    LedgerSnapshot,
    RetentionLease,
    aggregate_unique_parents,
    calculate_admission,
    commit_state,
    create_reserved_attempt,
    read_attempt_state,
    reconcile_ledger,
)
from review_supervisor.models import (
    Admission,
    FilesystemMeasure,
    HelperCustody,
    Identity,
    TreeManifest,
)
from review_supervisor.secureio import canonical_json

from tests.support import owned_temporary_directory


class _NeverIterate:
    def __iter__(self):
        raise AssertionError("path stream was touched before baseline admission")


class _PoisonRecord:
    def __getattribute__(self, name: str):
        raise AssertionError(f"extra record content was touched through {name}")


class _SyntheticEntry:
    __slots__ = ("_counters", "_index")

    def __init__(self, counters: dict[str, int], index: int) -> None:
        self._counters = counters
        self._index = index

    @property
    def size(self) -> int:
        self._counters["size_reads"] += 1
        return 1

    @property
    def path(self) -> bytes:
        self._counters["path_reads"] += 1
        return f"{self._index:05d}/f".encode("ascii")


class _SyntheticEntries:
    def __init__(self, count: int, counters: dict[str, int]) -> None:
        self._count = count
        self._counters = counters

    def __len__(self) -> int:
        return self._count

    def __iter__(self):
        self._counters["iterations"] += 1
        return (_SyntheticEntry(self._counters, index) for index in range(self._count))


class ParentAggregationTests(unittest.TestCase):
    def test_baseline_projector_runs_before_iterable_is_touched(self) -> None:
        calls: list[tuple[int, int, int]] = []

        def reject(count: int, path_bytes: int, consumed: int) -> None:
            calls.append((count, path_bytes, consumed))
            raise OverflowError("baseline projection rejected")

        with self.assertRaisesRegex(OverflowError, "baseline"):
            aggregate_unique_parents(
                _NeverIterate(),
                expected_count=1,
                projector=reject,
            )
        self.assertEqual(calls, [(0, 0, 0)])

    def test_extra_record_is_not_inspected(self) -> None:
        with self.assertRaisesRegex(EntryCountMismatch, "extra record"):
            aggregate_unique_parents(
                iter((b"one", _PoisonRecord())),
                expected_count=1,
                projector=lambda *_: None,
            )

    def test_parent_projection_is_monotone_and_exact(self) -> None:
        projections: list[tuple[int, int, int]] = []
        result = aggregate_unique_parents(
            (b"a/b/c", b"a/b/d", b"x/y"),
            expected_count=3,
            projector=lambda *values: projections.append(values),
        )
        self.assertEqual(result.unique_parent_directory_count, 3)
        self.assertEqual(result.unique_parent_path_bytes, 5)
        self.assertEqual(result.consumed_paths, 3)
        self.assertEqual(
            projections,
            [(0, 0, 0), (1, 1, 1), (2, 4, 1), (3, 5, 3)],
        )

    def test_trailing_slash_fails_before_parent_accounting(self) -> None:
        projections: list[tuple[int, int, int]] = []
        with self.assertRaisesRegex(ValueError, "trailing slash"):
            aggregate_unique_parents(
                (b"unsafe/",),
                expected_count=1,
                projector=lambda *values: projections.append(values),
            )
        self.assertEqual(projections, [(0, 0, 0)])


class AdmissionProjectionTests(unittest.TestCase):
    def test_near_limit_projection_scans_manifest_only_twice(self) -> None:
        entry_count = 99_999
        counters = {"iterations": 0, "size_reads": 0, "path_reads": 0}
        entries = _SyntheticEntries(entry_count, counters)
        manifest = TreeManifest(
            commit="a" * 40,
            entries=entries,  # type: ignore[arg-type]
            metadata_bytes=entry_count,
            aggregate_regular_bytes=entry_count,
            gitlink_count=0,
        )
        snapshot = LedgerSnapshot(
            process_logical_bytes=0,
            checkout_logical_bytes=0,
            process_physical_remaining_by_fs={},
            checkout_physical_remaining_by_fs={},
            retained_worktree_attempt=None,
            attempt_count=0,
        )

        def filesystem(path: pathlib.Path) -> FilesystemMeasure:
            return FilesystemMeasure(
                identity=f"fs:{path.name}",
                device=1,
                allocation_unit=1,
                free_bytes=10**15,
            )

        with mock.patch(
            "review_supervisor.ledger.measure_filesystem", side_effect=filesystem
        ):
            admission = calculate_admission(
                snapshot=snapshot,
                retention_root=pathlib.Path("/retention"),
                checkout_parent=pathlib.Path("/checkout"),
                common_git_dir=pathlib.Path("/git"),
                manifest=manifest,
                diff_length=1,
            )

        self.assertEqual(admission.unique_parent_directory_count, entry_count)
        self.assertEqual(counters["iterations"], 2)
        self.assertEqual(counters["size_reads"], entry_count)
        self.assertEqual(counters["path_reads"], entry_count)


class InitialAttemptCrashRecoveryTests(unittest.TestCase):
    def _attempt(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, int]:
        retention = root / "retention"
        retention.mkdir(mode=0o700)
        created_at = int(time.time())
        attempt = retention / f"attempt-{created_at}-{'a' * 32}"
        attempt.mkdir(mode=0o700)
        return retention, attempt, created_at

    def _initial_state(self, attempt: pathlib.Path, created_at: int) -> bytes:
        return canonical_json(
            {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": attempt.name.removeprefix("attempt-"),
                "record_generation": 1,
                "previous_record_sha256": None,
                "created_at": created_at + 0.25,
                "phase": "reserved",
                "launch_status": "not-attempted",
                "reservation_status": "outstanding",
                "closure": "unproven",
                "process_settlement": "outstanding",
                "checkout_settlement": "outstanding",
                "retention_state": "active/unsafe",
                "leader": None,
            }
        )

    def test_pre_rename_atomic_temp_is_reclaimed_after_stale_writer_check(
        self,
    ) -> None:
        with owned_temporary_directory("ledger-initial-crash-") as root:
            retention, attempt, created_at = self._attempt(root)
            temporary = attempt / ".state.json.tmp-999999-0123456789abcdef"
            temporary.write_bytes(self._initial_state(attempt, created_at))
            temporary.chmod(0o600)

            with (
                mock.patch(
                    "review_supervisor.ledger.time.time",
                    return_value=created_at + INITIAL_CRASH_RECLAIM_AGE_SECONDS + 5,
                ),
                mock.patch(
                    "review_supervisor.ledger._pid_exists",
                    return_value=False,
                ) as pid_exists,
            ):
                snapshot = reconcile_ledger(retention)

            self.assertEqual(snapshot.attempt_count, 0)
            self.assertFalse(attempt.exists())
            pid_exists.assert_called_once_with(999999)

    def test_state_less_attempt_with_unknown_content_is_rejected(self) -> None:
        with owned_temporary_directory("ledger-unknown-crash-") as root:
            retention, attempt, created_at = self._attempt(root)
            unknown = attempt / "unexpected.txt"
            unknown.write_bytes(b"not an atomic state temporary\n")
            unknown.chmod(0o600)

            with mock.patch(
                "review_supervisor.ledger.time.time",
                return_value=created_at + INITIAL_CRASH_RECLAIM_AGE_SECONDS + 5,
            ):
                with self.assertRaisesRegex(ValueError, "unknown entry"):
                    reconcile_ledger(retention)
            self.assertTrue(attempt.is_dir())
            self.assertTrue(unknown.is_file())

    def test_live_atomic_temp_writer_blocks_reclaim(self) -> None:
        with owned_temporary_directory("ledger-live-writer-") as root:
            retention, attempt, created_at = self._attempt(root)
            temporary = attempt / ".state.json.tmp-1234-fedcba9876543210"
            temporary.write_bytes(self._initial_state(attempt, created_at))
            temporary.chmod(0o600)

            with (
                mock.patch(
                    "review_supervisor.ledger.time.time",
                    return_value=created_at + INITIAL_CRASH_RECLAIM_AGE_SECONDS + 5,
                ),
                mock.patch(
                    "review_supervisor.ledger._pid_exists",
                    return_value=True,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "writer may still be alive"):
                    reconcile_ledger(retention)
            self.assertTrue(temporary.is_file())

    def test_atomic_temp_with_unknown_state_content_is_rejected(self) -> None:
        with owned_temporary_directory("ledger-unknown-state-") as root:
            retention, attempt, created_at = self._attempt(root)
            temporary = attempt / ".state.json.tmp-999999-aaaaaaaaaaaaaaaa"
            temporary.write_bytes(canonical_json({"not": "an initial state"}))
            temporary.chmod(0o600)

            with (
                mock.patch(
                    "review_supervisor.ledger.time.time",
                    return_value=created_at + INITIAL_CRASH_RECLAIM_AGE_SECONDS + 5,
                ),
                mock.patch(
                    "review_supervisor.ledger._pid_exists",
                    return_value=False,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "content is not authentic"):
                    reconcile_ledger(retention)
            self.assertTrue(temporary.is_file())

    def test_attempt_state_requires_exact_low_level_review_contract(self) -> None:
        valid = {
            "schema_version": SCHEMA_VERSION,
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        }
        mutations = {
            "missing-contract": {"review_contract"},
            "missing-eligibility": {"named_lane_eligible"},
            "wrong-contract": {"review_contract": "clean-git-worktree"},
            "eligible": {"named_lane_eligible": True},
            "integer-zero": {"named_lane_eligible": 0},
        }
        for name, mutation in mutations.items():
            with (
                self.subTest(name=name),
                owned_temporary_directory(f"ledger-review-contract-{name}-") as root,
            ):
                attempt = root / "attempt"
                attempt.mkdir(mode=0o700)
                state = dict(valid)
                if isinstance(mutation, set):
                    for key in mutation:
                        state.pop(key)
                else:
                    state.update(mutation)
                state_path = attempt / "state.json"
                state_path.write_bytes(canonical_json(state))
                state_path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "review contract is invalid"):
                    read_attempt_state(attempt)

    def test_reserved_attempt_persists_low_level_review_contract(self) -> None:
        with owned_temporary_directory("ledger-reserved-review-contract-") as root:
            retention = root / "retention"
            checkout = root / "checkout"
            git_dir = root / "git"
            for directory in (retention, checkout, git_dir):
                directory.mkdir(mode=0o700)
            identity = Identity(
                device=1,
                inode=1,
                mode=0o100600,
                link_count=1,
                uid=0,
                size=1,
            )
            custody = HelperCustody(
                state_dir="/fixture/state",
                state_identity=identity,
                workspace_root="/fixture/workspace",
                source_path="/fixture/source",
                source_identity=identity,
                cleanup_lock_path="/fixture/cleanup.lock",
                cleanup_lock_identity=identity,
                review_range=f"{'1' * 40}..{'2' * 40}",
                base_sha="1" * 40,
                head_sha="2" * 40,
                diff_length=1,
                diff_sha256="3" * 64,
                preflight_sha256="4" * 64,
                control_state_sha256="5" * 64,
            )
            filesystem = FilesystemMeasure(
                identity="fixture-fs",
                device=1,
                allocation_unit=4096,
                free_bytes=10**12,
            )
            admission = Admission(
                retention_fs=filesystem,
                checkout_fs=filesystem,
                git_fs=filesystem,
                entry_count=0,
                tree_metadata_bytes=0,
                unique_parent_directory_count=0,
                unique_parent_path_bytes=0,
                gitlink_count=0,
                checkout_base_bound_without_parents=0,
                checkout_root_bound=0,
                git_admin_bound=0,
                checkout_accounting_bound=0,
                review_diff_bound=1,
                targeted_manifest_entry_bound=0,
                targeted_manifest_payload_bound=0,
                targeted_manifest_file_bound=0,
                targeted_manifest_bound=0,
                process_charge=PROCESS_ENVELOPE_BYTES,
            )
            attempt, state, digest = create_reserved_attempt(
                lease=RetentionLease(root=retention, fd=-1),
                checkout_parent=checkout,
                prompt=b"review\n",
                prompt_sha256="6" * 64,
                custody=custody,
                admission=admission,
                base_manifest_sha256="7" * 64,
                head_manifest_sha256="8" * 64,
                repo=root,
                common_git_dir=git_dir,
                pr_url="https://github.example/owner/repo/pull/1",
                git_executable="/usr/bin/git",
                codex_executable="/usr/bin/true",
                exec_budget={},
            )
            self.assertEqual(state["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT)
            self.assertIs(state["named_lane_eligible"], NAMED_LANE_ELIGIBLE)
            persisted, _, _ = read_attempt_state(attempt)
            self.assertEqual(persisted["review_contract"], state["review_contract"])
            self.assertIs(persisted["named_lane_eligible"], False)
            before = (attempt / "state.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "review contract is invalid"):
                commit_state(
                    attempt,
                    state,
                    digest,
                    named_lane_eligible=True,
                )
            self.assertEqual((attempt / "state.json").read_bytes(), before)

    def test_launched_exact_settlement_requires_authenticated_profile(self) -> None:
        with owned_temporary_directory("ledger-profile-") as root:
            retention, attempt, _ = self._attempt(root)
            attempt_id = attempt.name.removeprefix("attempt-")
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": attempt_id,
                "record_generation": 1,
                "previous_record_sha256": None,
                "launch_status": "launched",
                "leader_started": True,
                "leader": {
                    "pid": 1234,
                    "pgid": 1234,
                    "start_identity": "fixture-start",
                },
                "closure": "proven-by-owner",
                "process_settlement": "exact",
                "checkout_settlement": "exact",
                "retained_process_bytes": 0,
                "process_physical_remaining_by_fs": {},
                "checkout_physical_remaining_by_fs": {},
                "retention_state": "held",
            }
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)

            with self.assertRaisesRegex(
                SupervisorError,
                "lacks authenticated no-child-process profile evidence",
            ):
                reconcile_ledger(retention)

            leader = state["leader"]
            state["no_child_process_profile"] = {
                "version": 1,
                "authenticated": True,
                "kernel_enforced": True,
                "child_process_limit": 0,
                "leader": leader,
            }
            state_path.write_bytes(canonical_json(state))
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.attempt_count, 1)


if __name__ == "__main__":
    unittest.main()
