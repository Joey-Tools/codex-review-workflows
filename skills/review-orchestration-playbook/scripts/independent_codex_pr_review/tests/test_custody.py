from __future__ import annotations

import fcntl
import json
import os
import time
import unittest
from types import SimpleNamespace

from review_supervisor.custody import acquire_source_custody, authenticate_helper_state
from review_supervisor.errors import SupervisorError
from review_supervisor.supervisor import _acquire_source_custody_via_helper

from tests.support import (
    SUPERVISOR_INTERNAL_CHILD_FIXTURE,
    build_helper_fixture,
    owned_temporary_directory,
)


class HelperCustodyTests(unittest.TestCase):
    def test_bounded_helper_transfers_same_open_descriptions(self) -> None:
        with owned_temporary_directory("custody-helper-") as root:
            fixture = build_helper_fixture(root)
            evidence = authenticate_helper_state(
                state_dir=fixture["state_dir"],
                repo=fixture["repo"],
                base_sha=fixture["base"],
                head_sha=fixture["head"],
            )
            attempt = root / "attempt"
            attempt.mkdir(mode=0o700)
            prepared = SimpleNamespace(
                helper=evidence,
                repository=SimpleNamespace(repo=fixture["repo"]),
                attempt_dir=attempt,
            )
            entrypoint = SUPERVISOR_INTERNAL_CHILD_FIXTURE
            transient = fixture["state_dir"] / "benign-transient-child"
            transient.mkdir(mode=0o700)
            handles = None
            competing = None
            try:
                handles = _acquire_source_custody_via_helper(
                    entrypoint=entrypoint,
                    prepared=prepared,
                    deadline=time.monotonic() + 10,
                )
                competing = os.open(
                    fixture["state_dir"] / "cleanup.lock",
                    os.O_RDONLY,
                )
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(
                    os.read(handles.source_fd, len(fixture["diff"])), fixture["diff"]
                )
            finally:
                if handles is not None:
                    handles.close()
                transient.rmdir()
            assert competing is not None
            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(competing)

    def test_authenticates_and_holds_cleanup_lock_with_source_fd(self) -> None:
        with owned_temporary_directory("custody-") as root:
            fixture = build_helper_fixture(root)
            evidence = authenticate_helper_state(
                state_dir=fixture["state_dir"],
                repo=fixture["repo"],
                base_sha=fixture["base"],
                head_sha=fixture["head"],
            )
            self.assertEqual(evidence.diff_length, len(fixture["diff"]))
            custody = acquire_source_custody(
                expected=evidence,
                repo=fixture["repo"],
                deadline=time.monotonic() + 2,
            )
            competing = os.open(fixture["state_dir"] / "cleanup.lock", os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(
                    os.read(custody.source_fd, len(fixture["diff"])), fixture["diff"]
                )
            finally:
                custody.close()
            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(competing)

    def test_directory_child_churn_does_not_invalidate_custody(self) -> None:
        with owned_temporary_directory("custody-directory-churn-") as root:
            fixture = build_helper_fixture(root)
            evidence = authenticate_helper_state(
                state_dir=fixture["state_dir"],
                repo=fixture["repo"],
                base_sha=fixture["base"],
                head_sha=fixture["head"],
            )
            for directory in (
                fixture["state_dir"],
                fixture["state_dir"] / "workspace",
                fixture["state_dir"] / "workspace" / ".codex-review",
            ):
                transient = directory / "benign-transient-child"
                transient.mkdir(mode=0o700)
                transient.rmdir()

            custody = acquire_source_custody(
                expected=evidence,
                repo=fixture["repo"],
                deadline=time.monotonic() + 2,
            )
            try:
                self.assertEqual(
                    os.read(custody.source_fd, len(fixture["diff"])),
                    fixture["diff"],
                )
            finally:
                custody.close()

    def test_rejects_preflight_control_digest_disagreement(self) -> None:
        with owned_temporary_directory("custody-tamper-") as root:
            fixture = build_helper_fixture(root)
            path = fixture["state_dir"] / "preflight.json"
            payload = json.loads(path.read_text())
            payload["primary_diff"]["sha256"] = "f" * 64
            path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            )
            os.chmod(path, 0o600)
            with self.assertRaises(SupervisorError) as raised:
                authenticate_helper_state(
                    state_dir=fixture["state_dir"],
                    repo=fixture["repo"],
                    base_sha=fixture["base"],
                    head_sha=fixture["head"],
                )
            self.assertEqual(raised.exception.failure.code, "helper-custody-invalid")


if __name__ == "__main__":
    unittest.main()
