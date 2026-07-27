from __future__ import annotations

import os
import time
import unittest
from unittest import mock

from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    PROCESS_ENVELOPE_BYTES,
    SCHEMA_VERSION,
)
from review_supervisor.ledger import (
    acquire_retention_lease,
    open_attempt_lease,
    read_bound_attempt_state,
    read_attempt_state,
    reconcile_ledger,
)
from review_supervisor.secureio import allocated_bytes, canonical_json
from review_supervisor.settlement_state import publish_exact_process_settlement

from tests.support import bind_attempt_state, owned_temporary_directory


class ProcessSettlementTests(unittest.TestCase):
    def _build_attempt(self, root):
        retention = root / "retention"
        retention.mkdir(mode=0o700)
        attempt_id = f"1-{'a' * 32}"
        attempt = retention / f"attempt-{attempt_id}"
        attempt.mkdir(mode=0o700)
        state = {
            "schema_version": SCHEMA_VERSION,
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "attempt_id": attempt_id,
            "record_generation": 1,
            "previous_record_sha256": None,
            "process_settlement": "outstanding",
            "checkout_settlement": "exact",
            "retained_process_bytes": None,
            "process_physical_remaining_by_fs": {"fixture-fs": PROCESS_ENVELOPE_BYTES},
            "checkout_physical_remaining_by_fs": {},
            "admission": {"retention_fs": {"identity": "fixture-fs"}},
            "retention_state": "active/unsafe",
            "reservation_status": "outstanding",
        }
        bind_attempt_state(
            state,
            retention_root=retention,
            attempt_dir=attempt,
        )
        state_path = attempt / "state.json"
        state_path.write_bytes(canonical_json(state))
        state_path.chmod(0o600)
        diagnostic = attempt / "codex.stderr.0.gz"
        diagnostic.write_bytes(b"diagnostic evidence\n")
        diagnostic.chmod(0o600)
        current, _, digest = read_attempt_state(attempt)
        return retention, attempt, current, digest

    def test_exact_is_published_only_after_candidate_proof(self) -> None:
        with owned_temporary_directory("settlement-success-") as root:
            retention, attempt, current, digest = self._build_attempt(root)
            with acquire_retention_lease(
                retention, deadline=time.monotonic() + 5.0
            ) as lease, open_attempt_lease(lease, attempt) as attempt_lease:
                settled, settled_digest = publish_exact_process_settlement(
                    attempt_lease,
                    current,
                    digest,
                    deadline=time.monotonic() + 5.0,
                )
                disk, _, disk_digest = read_bound_attempt_state(attempt_lease)
            self.assertEqual(disk, settled)
            self.assertEqual(disk_digest, settled_digest)
            self.assertEqual(settled["process_settlement"], "exact")
            self.assertEqual(
                settled["retained_process_bytes"],
                allocated_bytes(attempt, entry_cap=1_000),
            )
            proof = settled["process_settlement_proof"]
            self.assertEqual(proof["predecessor_sha256"], digest)
            self.assertEqual(proof["readback"], "exact-before-publication")
            self.assertTrue((attempt / proof["predecessor_retained_name"]).is_file())

    def test_attempt_replacement_before_settlement_is_rejected(self) -> None:
        with owned_temporary_directory("settlement-attempt-replacement-") as root:
            retention, attempt, current, digest = self._build_attempt(root)
            original = retention / "original-attempt"
            state_raw = (attempt / "state.json").read_bytes()
            with acquire_retention_lease(
                retention, deadline=time.monotonic() + 5.0
            ) as lease, open_attempt_lease(lease, attempt) as attempt_lease:
                attempt.rename(original)
                attempt.mkdir(mode=0o700)
                replacement_state = attempt / "state.json"
                replacement_state.write_bytes(state_raw)
                replacement_state.chmod(0o600)

                with self.assertRaisesRegex(OSError, "binding changed"):
                    publish_exact_process_settlement(
                        attempt_lease,
                        current,
                        digest,
                        deadline=time.monotonic() + 5.0,
                    )

            self.assertEqual(replacement_state.read_bytes(), state_raw)
            self.assertTrue((original / "state.json").is_file())

    def test_exchange_failure_leaves_outstanding_charge(self) -> None:
        with owned_temporary_directory("settlement-failure-") as root:
            retention, attempt, current, digest = self._build_attempt(root)
            with acquire_retention_lease(
                retention, deadline=time.monotonic() + 5.0
            ) as lease, open_attempt_lease(lease, attempt) as attempt_lease:
                with mock.patch(
                    "review_supervisor.settlement_state.rename_exchange",
                    side_effect=OSError("injected exchange failure"),
                ):
                    with self.assertRaisesRegex(OSError, "injected exchange failure"):
                        publish_exact_process_settlement(
                            attempt_lease,
                            current,
                            digest,
                            deadline=time.monotonic() + 5.0,
                        )

                disk, _, disk_digest = read_bound_attempt_state(attempt_lease)
            self.assertEqual(disk_digest, digest)
            self.assertEqual(disk["process_settlement"], "outstanding")
            temporary_names = [
                name
                for name in os.listdir(attempt)
                if name.startswith(".state.json.tmp-")
            ]
            self.assertEqual(len(temporary_names), 1)
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.process_logical_bytes, PROCESS_ENVELOPE_BYTES)


if __name__ == "__main__":
    unittest.main()
