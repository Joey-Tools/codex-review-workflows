from __future__ import annotations

import os
import pathlib
import shutil
import stat
import time
import unittest
from unittest import mock

import review_supervisor.gitraw as gitraw
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
    RootSpec,
    _KIND_DIRECTORY,
    _index_manifest_records,
    build_custodied_manifest,
    delete_custodied_roots,
)
from review_supervisor.runtime import _cleanup_worktree, _registration_json
from review_supervisor.secureio import canonical_json, identity_from_stat

from tests.support import bind_attempt_state, owned_temporary_directory
from tests.test_git_checkout import GIT, _build_repository


ENTRYPOINT = (
    pathlib.Path(__file__).resolve().parent.parent / "independent-codex-pr-review"
)


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

    def test_delete_deadline_after_identity_check_changes_nothing(self) -> None:
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
                self.assertTrue(target.is_dir())
                self.assertEqual(payload.read_bytes(), b"retained\n")
            finally:
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
