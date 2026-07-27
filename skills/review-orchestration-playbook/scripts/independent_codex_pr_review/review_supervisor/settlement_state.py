from __future__ import annotations

import os
import stat
import time
from typing import Any

from .ledger import AttemptLease, MAX_ATTEMPT_STATE_BYTES, read_bound_attempt_state
from .secureio import (
    allocated_bytes_fd,
    canonical_json,
    open_regular_at,
    read_fd_exact,
    rename_exchange,
    sha256_bytes,
    validate_private_regular_fd,
    write_all,
)


def _candidate_state(
    current: dict[str, Any],
    current_digest: str,
    *,
    retained_bytes: int,
    retention_fs_identity: str,
    predecessor_name: str,
    candidate_device: int,
    candidate_inode: int,
) -> dict[str, Any]:
    value = dict(current)
    value.update(
        {
            "process_settlement": "exact",
            "retained_process_bytes": retained_bytes,
            "process_physical_remaining_by_fs": {
                retention_fs_identity: retained_bytes,
            },
            "retention_state": "held",
            "reservation_status": (
                "settled"
                if current.get("checkout_settlement") == "exact"
                else "checkout-outstanding"
            ),
            "process_settlement_proof": {
                "version": 1,
                "predecessor_sha256": current_digest,
                "predecessor_retained_name": predecessor_name,
                "candidate_anchor": {
                    "device": candidate_device,
                    "inode": candidate_inode,
                },
                "post_write_allocated_bytes": retained_bytes,
                "readback": "exact-before-publication",
                "publication": "atomic-exchange",
            },
        }
    )
    value["record_generation"] = current["record_generation"] + 1
    value["previous_record_sha256"] = current_digest
    return value


def publish_exact_process_settlement(
    attempt: AttemptLease,
    current: dict[str, Any],
    current_digest: str,
    *,
    deadline: float,
) -> tuple[dict[str, Any], str]:
    attempt.revalidate(current)
    disk, predecessor_raw, disk_digest = read_bound_attempt_state(attempt)
    if disk != current or disk_digest != current_digest:
        raise ValueError("process settlement predecessor changed")
    admission = current.get("admission")
    retention_fs = (
        admission.get("retention_fs") if isinstance(admission, dict) else None
    )
    retention_fs_identity = (
        retention_fs.get("identity") if isinstance(retention_fs, dict) else None
    )
    if not isinstance(retention_fs_identity, str) or not retention_fs_identity:
        raise ValueError("process settlement has no retention filesystem identity")

    directory_fd = os.dup(attempt.fd)
    candidate_name = f".state.json.tmp-{os.getpid()}-{os.urandom(8).hex()}"
    candidate_raw_name = os.fsencode(candidate_name)
    candidate_fd: int | None = None
    exchanged = False
    try:
        candidate_fd = os.open(
            candidate_raw_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        validate_private_regular_fd(
            candidate_fd,
            attempt.path / candidate_name,
        )
        anchor = os.fstat(candidate_fd)

        retained_bytes = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
        candidate: dict[str, Any] | None = None
        candidate_data: bytes | None = None
        for _ in range(8):
            if time.monotonic() >= deadline:
                raise TimeoutError("process settlement proof deadline expired")
            candidate = _candidate_state(
                current,
                current_digest,
                retained_bytes=retained_bytes,
                retention_fs_identity=retention_fs_identity,
                predecessor_name=candidate_name,
                candidate_device=anchor.st_dev,
                candidate_inode=anchor.st_ino,
            )
            candidate_data = canonical_json(candidate)
            if len(candidate_data) > MAX_ATTEMPT_STATE_BYTES:
                raise ValueError("process settlement state exceeds its byte limit")
            os.ftruncate(candidate_fd, 0)
            os.lseek(candidate_fd, 0, os.SEEK_SET)
            write_all(candidate_fd, candidate_data)
            os.fsync(candidate_fd)
            identity = validate_private_regular_fd(
                candidate_fd,
                attempt.path / candidate_name,
            )
            if (
                not stat.S_ISREG(identity.mode)
                or identity.uid != os.getuid()
                or identity.link_count != 1
                or stat.S_IMODE(identity.mode) != 0o600
                or identity.device != anchor.st_dev
                or identity.inode != anchor.st_ino
            ):
                raise ValueError("process settlement candidate custody changed")
            readback = read_fd_exact(
                candidate_fd,
                max_bytes=MAX_ATTEMPT_STATE_BYTES,
                expected_size=len(candidate_data),
            )
            if readback != candidate_data:
                raise ValueError("process settlement candidate readback differs")
            actual = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
            if actual == retained_bytes:
                break
            retained_bytes = actual
        else:
            raise ValueError("process settlement allocation proof did not converge")

        assert candidate is not None and candidate_data is not None
        disk, exact_predecessor_raw, disk_digest = read_bound_attempt_state(attempt)
        if (
            disk != current
            or disk_digest != current_digest
            or exact_predecessor_raw != predecessor_raw
        ):
            raise ValueError(
                "process settlement predecessor changed before publication"
            )
        if allocated_bytes_fd(attempt.fd, entry_cap=1_000) != retained_bytes:
            raise ValueError("process settlement allocation changed before publication")
        final_candidate_readback = read_fd_exact(
            candidate_fd,
            max_bytes=MAX_ATTEMPT_STATE_BYTES,
            expected_size=len(candidate_data),
        )
        if final_candidate_readback != candidate_data:
            raise ValueError("process settlement final candidate readback differs")

        rename_exchange(
            directory_fd,
            candidate_raw_name,
            directory_fd,
            b"state.json",
        )
        exchanged = True
        os.fsync(directory_fd)
        attempt.revalidate(candidate)

        state_fd, published_identity = open_regular_at(
            directory_fd,
            b"state.json",
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            if (
                published_identity.device != anchor.st_dev
                or published_identity.inode != anchor.st_ino
            ):
                raise ValueError("published process settlement inode changed")
            published = read_fd_exact(
                state_fd,
                max_bytes=MAX_ATTEMPT_STATE_BYTES,
                expected_size=len(candidate_data),
            )
        finally:
            os.close(state_fd)
        if published != candidate_data:
            raise ValueError("published process settlement readback differs")

        predecessor_fd, _ = open_regular_at(
            directory_fd,
            candidate_raw_name,
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            retained_predecessor = read_fd_exact(
                predecessor_fd,
                max_bytes=MAX_ATTEMPT_STATE_BYTES,
                expected_size=len(predecessor_raw),
            )
        finally:
            os.close(predecessor_fd)
        if (
            retained_predecessor != predecessor_raw
            or sha256_bytes(retained_predecessor) != current_digest
        ):
            raise ValueError("retained process settlement predecessor differs")
        if allocated_bytes_fd(attempt.fd, entry_cap=1_000) != retained_bytes:
            raise ValueError("published process settlement allocation differs")
        attempt.revalidate(candidate)
        return candidate, sha256_bytes(candidate_data)
    finally:
        if candidate_fd is not None:
            os.close(candidate_fd)
        if not exchanged:
            os.fsync(directory_fd)
        os.close(directory_fd)
