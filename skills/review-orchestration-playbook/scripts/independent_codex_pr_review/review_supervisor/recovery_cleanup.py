from __future__ import annotations

import errno
import hashlib
import math
import os
import pathlib
import secrets
import stat
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .models import Identity
from .secureio import (
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_regular_at,
    publish_bytes,
    read_fd_exact,
    sha256_bytes,
    validate_private_directory_fd,
)


_MANIFEST_MAGIC = b"targeted-cleanup-manifest-v1\0"
_RECORD = struct.Struct(">BBIIQQQQQ")
_KIND_DIRECTORY = 1
_KIND_ENTRY = 2
_DEFAULT_TARGETED_CLEANUP_SECONDS = 30.0
_MAX_DIRECTORY_DEPTH = 512
_QUARANTINE_PREFIX = b".targeted-cleanup-quarantine-"
_QUARANTINE_NAME_ATTEMPTS = 64
_QUARANTINED_ROOT_RECOVERY_ATTR = "_quarantined_root_recovery_evidence"


class CustodyLostError(RuntimeError):
    pass


@dataclass(frozen=True)
class RootSpec:
    label: str
    parent_fd: int
    parent_identity: Identity
    name: bytes
    expected_identity: Identity
    private_metadata: bool = False


@dataclass(frozen=True, slots=True)
class QuarantinedRootRecoveryEvidence:
    label: str
    stage: str
    parent_fd: int
    root_fd: int
    original_name: bytes
    quarantine_name: bytes
    parent_identity: Identity
    expected_identity: Identity
    protected_property: str = "object-identity-and-access-policy"


@dataclass(slots=True)
class _QuarantinedRootRecoveryOwner:
    spec: RootSpec
    root_fd: int
    quarantine_name: bytes | None = None
    rename_armed: bool = False
    rename_returned: bool = False
    result_transferred: bool = False

    def prepare(self, quarantine_name: bytes) -> None:
        if self.quarantine_name is not None or self.rename_armed:
            raise ValueError("quarantine recovery owner was already prepared")
        self.quarantine_name = quarantine_name

    def arm_rename(self) -> None:
        if self.quarantine_name is None or self.rename_armed:
            raise ValueError("quarantine recovery owner cannot arm rename")
        self.rename_armed = True

    def mark_rename_returned(self) -> None:
        if not self.rename_armed:
            raise ValueError("quarantine rename returned before ownership was armed")
        self.rename_returned = True

    def transfer_result(self, quarantine_name: bytes) -> None:
        if (
            self.quarantine_name != quarantine_name
            or not self.rename_returned
            or self.result_transferred
        ):
            raise ValueError("quarantine result transfer is inconsistent")
        self.result_transferred = True

    def attach_if_untransferred(
        self,
        error: BaseException,
        *,
        stage: str,
    ) -> None:
        if (
            not self.rename_armed
            or self.result_transferred
            or self.quarantine_name is None
        ):
            return
        existing = quarantined_root_recovery_evidence(error)
        if any(
            evidence.parent_fd == self.spec.parent_fd
            and evidence.root_fd == self.root_fd
            and evidence.original_name == self.spec.name
            and evidence.quarantine_name == self.quarantine_name
            for evidence in existing
        ):
            return
        _attach_quarantined_root_recovery(
            error,
            _quarantined_root_evidence(
                self.spec,
                self.root_fd,
                self.quarantine_name,
                stage=stage,
            ),
        )


def quarantined_root_recovery_evidence(
    error: BaseException,
) -> tuple[QuarantinedRootRecoveryEvidence, ...]:
    collected: list[QuarantinedRootRecoveryEvidence] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        attached = getattr(current, _QUARANTINED_ROOT_RECOVERY_ATTR, ())
        if isinstance(attached, tuple):
            for evidence in attached:
                if (
                    isinstance(evidence, QuarantinedRootRecoveryEvidence)
                    and evidence not in collected
                ):
                    collected.append(evidence)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return tuple(collected)


def _attach_quarantined_root_recovery(
    error: BaseException,
    evidence: QuarantinedRootRecoveryEvidence,
) -> None:
    attached = getattr(error, _QUARANTINED_ROOT_RECOVERY_ATTR, ())
    if not isinstance(attached, tuple) or not all(
        isinstance(item, QuarantinedRootRecoveryEvidence) for item in attached
    ):
        attached = ()
    if evidence in attached:
        return
    setattr(error, _QUARANTINED_ROOT_RECOVERY_ATTR, (*attached, evidence))
    try:
        error.add_note(
            "descriptor-bound quarantine recovery: "
            f"stage={evidence.stage}, "
            f"parent_fd={evidence.parent_fd}, "
            f"root_fd={evidence.root_fd}, "
            f"original_name_hex={evidence.original_name.hex()}, "
            f"quarantine_name_hex={evidence.quarantine_name.hex()}"
        )
    except BaseException:
        pass


@dataclass(frozen=True)
class ManifestRecord:
    root_index: int
    path: bytes
    kind: int
    identity: Identity


@dataclass
class _TraversalBudget:
    deadline: float
    remaining: int

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")

    def consume(self) -> None:
        self.check()
        if self.remaining <= 0:
            raise ValueError("targeted cleanup traversal exceeds its entry cap")
        self.remaining -= 1


def _operation_deadline(deadline: float | None) -> float:
    now = time.monotonic()
    value = now + _DEFAULT_TARGETED_CLEANUP_SECONDS if deadline is None else deadline
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError("targeted cleanup deadline is invalid")
    if value <= now:
        raise TimeoutError("targeted cleanup monotonic deadline expired")
    return float(value)


def _validate_manifest_path(path: bytes, *, root: bool) -> None:
    if not isinstance(path, bytes):
        raise ValueError("targeted cleanup manifest path is not bytes")
    if root:
        if path:
            raise ValueError("targeted cleanup root manifest path is invalid")
        return
    if (
        not path
        or path.startswith(b"/")
        or path.endswith(b"/")
        or b"\0" in path
        or any(component in {b"", b".", b".."} for component in path.split(b"/"))
    ):
        raise ValueError("targeted cleanup manifest path is invalid")


def _bounded_directory_names(
    directory_fd: int,
    *,
    entry_cap: int,
    deadline: float,
    error: str,
    sort_names: bool,
) -> tuple[bytes, ...]:
    names: list[bytes] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise TimeoutError("targeted cleanup monotonic deadline expired")
            if len(names) >= entry_cap:
                raise ValueError(error)
            names.append(os.fsencode(entry.name))
    if sort_names:
        names.sort()
    return tuple(names)


def _index_manifest_records(
    records: Sequence[ManifestRecord],
    *,
    root_count: int,
    entry_cap: int,
    deadline: float,
) -> dict[tuple[int, bytes], dict[bytes, ManifestRecord]]:
    if len(records) > entry_cap:
        raise ValueError("targeted cleanup manifest exceeds its entry cap")
    budget = _TraversalBudget(deadline=deadline, remaining=entry_cap * 2)
    directory_paths: set[tuple[int, bytes]] = set()
    seen_paths: set[tuple[int, bytes]] = set()
    root_records: set[int] = set()
    for record in records:
        budget.consume()
        if (
            type(record.root_index) is not int
            or not 0 <= record.root_index < root_count
        ):
            raise ValueError("targeted cleanup manifest root index is invalid")
        if type(record.kind) is not int or record.kind not in {
            _KIND_DIRECTORY,
            _KIND_ENTRY,
        }:
            raise ValueError("targeted cleanup manifest entry kind is invalid")
        _validate_manifest_path(record.path, root=not record.path)
        key = (record.root_index, record.path)
        if key in seen_paths:
            raise ValueError("targeted cleanup manifest contains a duplicate path")
        seen_paths.add(key)
        if not record.path:
            if record.kind != _KIND_DIRECTORY:
                raise ValueError("targeted cleanup manifest root is not a directory")
            root_records.add(record.root_index)
        if record.kind == _KIND_DIRECTORY:
            directory_paths.add(key)
    if root_records != set(range(root_count)):
        raise ValueError("targeted cleanup manifest root records are incomplete")

    children: dict[tuple[int, bytes], dict[bytes, ManifestRecord]] = {
        key: {} for key in directory_paths
    }
    for record in records:
        budget.consume()
        if not record.path:
            continue
        parent, separator, name = record.path.rpartition(b"/")
        if not separator:
            parent = b""
            name = record.path
        parent_key = (record.root_index, parent)
        expected = children.get(parent_key)
        if expected is None:
            raise ValueError("targeted cleanup manifest entry has no directory parent")
        if name in expected:
            raise ValueError("targeted cleanup manifest contains duplicate siblings")
        expected[name] = record
    return children


@dataclass(frozen=True, slots=True)
class CustodiedManifestCloseEvidence:
    root_index: int
    descriptor: int
    state: str
    expected_identity: Identity
    observed_identity: Identity | None
    reason: str
    protected_property: str = "open-file-description-close-ownership"


@dataclass(slots=True)
class _CustodiedManifestDescriptorSlot:
    descriptor: int
    state: str = "owned"
    close_error: BaseException | None = None


class CustodiedManifest:
    def __init__(
        self,
        *,
        roots: tuple[RootSpec, ...],
        root_fds: tuple[int, ...],
        records: tuple[ManifestRecord, ...],
        seal: dict[str, Any],
        children_by_parent: dict[tuple[int, bytes], dict[bytes, ManifestRecord]],
        deadline: float,
    ) -> None:
        self.roots = roots
        self._root_fd_slots = [
            _CustodiedManifestDescriptorSlot(descriptor) for descriptor in root_fds
        ]
        self.records = records
        self.seal = seal
        self.children_by_parent = children_by_parent
        self.deadline = deadline
        self._closed = False
        self._close_blocked = False
        self._close_evidence: list[CustodiedManifestCloseEvidence] = []

    @property
    def root_fds(self) -> list[int]:
        return [
            slot.descriptor for slot in self._root_fd_slots if slot.state == "owned"
        ]

    @property
    def close_evidence(self) -> tuple[CustodiedManifestCloseEvidence, ...]:
        return tuple(self._close_evidence)

    def _observe_close_descriptor(
        self,
        index: int,
        descriptor: int,
        *,
        missing_state: str,
        live_state: str,
        mismatch_state: str = "identity-mismatch",
        unreadable_state: str = "unreadable",
    ) -> CustodiedManifestCloseEvidence:
        expected = self.roots[index].expected_identity
        try:
            observed = identity_from_stat(os.fstat(descriptor))
        except OSError as error:
            state = missing_state if error.errno == errno.EBADF else unreadable_state
            return CustodiedManifestCloseEvidence(
                root_index=index,
                descriptor=descriptor,
                state=state,
                expected_identity=expected,
                observed_identity=None,
                reason=f"{type(error).__name__}: {error}",
            )
        if not directory_identities_match(observed, expected):
            return CustodiedManifestCloseEvidence(
                root_index=index,
                descriptor=descriptor,
                state=mismatch_state,
                expected_identity=expected,
                observed_identity=observed,
                reason=(
                    "descriptor names a different filesystem object; its open "
                    "file description is not owned by the manifest"
                ),
            )
        return CustodiedManifestCloseEvidence(
            root_index=index,
            descriptor=descriptor,
            state=live_state,
            expected_identity=expected,
            observed_identity=observed,
            reason=(
                "descriptor names the expected root object, but object identity "
                "cannot prove ownership of its open file description"
                if live_state == "ownership-ambiguous-live-same-object"
                else "descriptor still names the expected root object"
            ),
        )

    def _record_close_evidence(
        self,
        evidence: CustodiedManifestCloseEvidence,
        error: BaseException | None = None,
    ) -> None:
        self._close_evidence.append(evidence)
        if error is not None:
            setattr(error, "custodied_manifest_close_evidence", evidence)

    def close(self) -> None:
        if self._closed:
            return
        if self._close_blocked:
            blocked_state = next(
                (
                    slot.state
                    for slot in self._root_fd_slots
                    if slot.state
                    not in {
                        "owned",
                        "closed",
                        "ownership-ambiguous-closed-or-missing",
                    }
                ),
                "close-outcome-unproven",
            )
            raise CustodyLostError(
                f"targeted cleanup descriptor close remains blocked: {blocked_state}"
            )
        for index, slot in enumerate(self._root_fd_slots):
            if slot.state in {
                "closed",
                "ownership-ambiguous-closed-or-missing",
            }:
                continue
            if slot.state != "owned":
                self._close_blocked = True
                raise CustodyLostError(
                    f"targeted cleanup descriptor close remains blocked: {slot.state}"
                )
            descriptor = slot.descriptor
            before = self._observe_close_descriptor(
                index,
                descriptor,
                missing_state="missing-before-close",
                live_state="live-before-close",
            )
            if before.state != "live-before-close":
                slot.state = before.state
                self._close_blocked = True
                self._record_close_evidence(before)
                raise CustodyLostError(
                    "targeted cleanup descriptor cannot be closed safely: "
                    f"{before.state}"
                )
            try:
                slot.state = "close-outcome-unproven"
                self._close_blocked = True
                os.close(descriptor)
                slot.state = "closed"
                slot.close_error = None
                self._close_blocked = False
            except BaseException as error:
                # A returned close can be interrupted before Python records the
                # result. The integer may already name a newly opened file
                # description, so the slot retains evidence but never retries.
                after = self._observe_close_descriptor(
                    index,
                    descriptor,
                    missing_state="ownership-ambiguous-closed-or-missing",
                    live_state="ownership-ambiguous-live-same-object",
                    mismatch_state="ownership-ambiguous-identity-mismatch",
                    unreadable_state="ownership-ambiguous-unreadable",
                )
                slot.state = after.state
                slot.close_error = error
                self._close_blocked = (
                    after.state != "ownership-ambiguous-closed-or-missing"
                )
                if after.state == "ownership-ambiguous-closed-or-missing":
                    slot.close_error = None
                self._record_close_evidence(after, error)
                raise
        self._closed = True

    def __enter__(self) -> CustodiedManifest:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def require_live_custody(self) -> None:
        if self._closed or len(self.root_fds) != len(self.roots):
            raise CustodyLostError("targeted cleanup root custody was lost")
        for index in range(len(self.roots)):
            self.require_root_custody(index)

    def require_root_custody(self, index: int) -> None:
        if self._closed or len(self.root_fds) != len(self.roots):
            raise CustodyLostError("targeted cleanup root custody was lost")
        spec = self.roots[index]
        slot = self._root_fd_slots[index]
        if slot.state != "owned":
            raise CustodyLostError("targeted cleanup root custody was lost")
        root_fd = slot.descriptor
        _require_parent_custody(spec)
        try:
            descriptor = (
                validate_private_directory_fd(
                    root_fd,
                    pathlib.Path(os.fsdecode(spec.name)),
                )
                if spec.private_metadata
                else identity_from_stat(os.fstat(root_fd))
            )
        except (OSError, ValueError) as error:
            raise CustodyLostError(
                f"targeted cleanup access policy changed for {spec.label}"
            ) from error
        path_identity = identity_from_stat(
            os.stat(spec.name, dir_fd=spec.parent_fd, follow_symlinks=False)
        )
        if not directory_identities_match(
            descriptor, spec.expected_identity
        ) or not directory_identities_match(path_identity, descriptor):
            raise CustodyLostError(f"targeted cleanup custody changed for {spec.label}")


@dataclass(slots=True)
class CustodiedManifestResultOwner:
    manifest: CustodiedManifest | None = None
    transferred: bool = False
    retained: bool = False
    retention_error: BaseException | None = None

    def publish(self, manifest: CustodiedManifest) -> None:
        if self.manifest is not None:
            raise ValueError("custodied manifest result was published more than once")
        self.manifest = manifest

    def transfer(self, manifest: CustodiedManifest) -> None:
        if self.manifest is not manifest or self.transferred:
            raise ValueError("custodied manifest result transfer is inconsistent")
        self.transferred = True

    def retain(
        self,
        retention_error: BaseException | None = None,
    ) -> CustodiedManifest:
        if self.manifest is None:
            raise ValueError("custodied manifest result is unavailable for retention")
        if retention_error is not None:
            if (
                self.retention_error is not None
                and self.retention_error is not retention_error
            ):
                raise ValueError(
                    "custodied manifest retention owner cannot be replaced"
                )
            self.retention_error = retention_error
            self.finish_retention()
        else:
            self.retained = True
        return self.manifest

    def finish_retention(self) -> CustodiedManifest:
        if self.manifest is None:
            raise ValueError("custodied manifest retention was not published")
        if self.retention_error is not None:
            resources = getattr(self.retention_error, "retained_resources", None)
            if not isinstance(resources, list):
                raise ValueError("custodied manifest retention error is malformed")
            if not any(resource is self.manifest for resource in resources):
                resources.append(self.manifest)
        elif not self.retained:
            raise ValueError("custodied manifest retention was not requested")
        self.retained = True
        return self.manifest

    def preserves(self, manifest: CustodiedManifest) -> bool:
        if not self.retained or self.manifest is not manifest:
            return False
        if self.retention_error is None:
            return True
        resources = getattr(self.retention_error, "retained_resources", None)
        return isinstance(resources, list) and any(
            resource is manifest for resource in resources
        )


@dataclass(slots=True)
class CustodiedRootDeletionOutcome:
    root_index: int
    label: str
    parent_fd: int
    root_fd: int
    original_name: bytes
    quarantine_name: bytes
    state: str = "armed"
    proof: dict[str, Any] | None = None
    protected_property: str = "root-removal-and-durable-name-absence"


@dataclass(slots=True)
class CustodiedDeletionResultOwner:
    proof: dict[str, Any] | None = None
    transferred: bool = False
    finished: bool = False
    root_outcomes: list[CustodiedRootDeletionOutcome] = field(default_factory=list)

    def arm_root(
        self,
        *,
        root_index: int,
        spec: RootSpec,
        root_fd: int,
        quarantine_name: bytes,
    ) -> CustodiedRootDeletionOutcome:
        for outcome in self.root_outcomes:
            if outcome.root_index == root_index:
                if (
                    outcome.label != spec.label
                    or outcome.parent_fd != spec.parent_fd
                    or outcome.root_fd != root_fd
                    or outcome.original_name != spec.name
                    or outcome.quarantine_name != quarantine_name
                ):
                    raise ValueError("custodied root deletion owner was rebound")
                return outcome
        outcome = CustodiedRootDeletionOutcome(
            root_index=root_index,
            label=spec.label,
            parent_fd=spec.parent_fd,
            root_fd=root_fd,
            original_name=spec.name,
            quarantine_name=quarantine_name,
        )
        self.root_outcomes.append(outcome)
        return outcome

    def arm_remove(self, outcome: CustodiedRootDeletionOutcome) -> None:
        if (
            not any(candidate is outcome for candidate in self.root_outcomes)
            or outcome.state != "armed"
        ):
            raise ValueError("custodied root deletion outcome cannot arm removal")
        outcome.state = "remove-outcome-unproven"

    def complete_root(
        self,
        outcome: CustodiedRootDeletionOutcome,
        proof: dict[str, Any],
    ) -> None:
        if not any(candidate is outcome for candidate in self.root_outcomes):
            raise ValueError("custodied root deletion outcome is not owned")
        if outcome.proof is not None and outcome.proof is not proof:
            raise ValueError("custodied root deletion proof was rebound")
        outcome.proof = proof
        outcome.state = "complete"

    def completed_root_proofs(self, expected_count: int) -> list[dict[str, Any]]:
        ordered = sorted(self.root_outcomes, key=lambda outcome: outcome.root_index)
        if len(ordered) != expected_count or any(
            outcome.root_index != index
            or outcome.state != "complete"
            or outcome.proof is None
            for index, outcome in enumerate(ordered)
        ):
            raise ValueError("custodied root deletion proofs are incomplete")
        return [outcome.proof for outcome in ordered if outcome.proof is not None]

    def publish(self, proof: dict[str, Any]) -> None:
        if self.proof is None:
            self.proof = proof
            return
        if self.proof is not proof:
            raise ValueError("custodied deletion result owner was rebound")

    def transfer(self, proof: dict[str, Any]) -> dict[str, Any]:
        if self.proof is not proof:
            raise ValueError("custodied deletion result transfer is inconsistent")
        self.transferred = True
        return proof

    def finish(self) -> dict[str, Any]:
        if self.proof is None:
            raise ValueError("custodied deletion result is unavailable")
        self.transferred = True
        self.finished = True
        return self.proof

    def recovery_evidence(self, *, expected_root_count: int) -> dict[str, Any]:
        """Return durable proof ownership without persisting live descriptors."""

        if type(expected_root_count) is not int or expected_root_count < 0:
            raise ValueError("expected custodied root count is invalid")
        ordered = sorted(self.root_outcomes, key=lambda outcome: outcome.root_index)
        if len(ordered) > expected_root_count or any(
            outcome.root_index != index for index, outcome in enumerate(ordered)
        ):
            raise ValueError("custodied root deletion outcome sequence is invalid")
        valid_states = {"armed", "remove-outcome-unproven", "complete"}
        if any(outcome.state not in valid_states for outcome in ordered):
            raise ValueError("custodied root deletion outcome state is invalid")
        completed_count = sum(
            outcome.state == "complete" and outcome.proof is not None
            for outcome in ordered
        )
        if self.proof is not None and (
            len(ordered) != expected_root_count
            or completed_count != expected_root_count
        ):
            raise ValueError("aggregate deletion proof has incomplete root ownership")
        return {
            "protected_property": ("destructive-deletion-proof-and-result-ownership"),
            "expected_root_count": expected_root_count,
            "published_root_count": len(ordered),
            "completed_root_count": completed_count,
            "aggregate_result_state": (
                "published" if self.proof is not None else "not-published"
            ),
            "aggregate_proof": self.proof,
            "result_transferred": self.transferred,
            "result_finished": self.finished,
            "roots": [
                {
                    "root_index": outcome.root_index,
                    "label": outcome.label,
                    "original_name_hex": outcome.original_name.hex(),
                    "quarantine_name_hex": outcome.quarantine_name.hex(),
                    "state": outcome.state,
                    "proof": outcome.proof,
                    "protected_property": outcome.protected_property,
                }
                for outcome in ordered
            ],
        }


def _require_parent_custody(spec: RootSpec) -> None:
    actual = identity_from_stat(os.fstat(spec.parent_fd))
    if not directory_identities_match(actual, spec.parent_identity):
        raise CustodyLostError(f"targeted cleanup parent changed for {spec.label}")


def _entry_kind(mode: int) -> int:
    if stat.S_ISDIR(mode):
        return _KIND_DIRECTORY
    if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        return _KIND_ENTRY
    raise ValueError("targeted cleanup tree contains an unsupported entry type")


def _enumerate_directory(
    *,
    root_index: int,
    directory_fd: int,
    prefix: bytes,
    records: list[ManifestRecord],
    budget: _TraversalBudget,
    depth: int,
) -> None:
    budget.check()
    if depth > _MAX_DIRECTORY_DEPTH:
        raise ValueError("targeted cleanup tree exceeds its depth cap")
    names = _bounded_directory_names(
        directory_fd,
        entry_cap=budget.remaining,
        deadline=budget.deadline,
        error="targeted cleanup manifest exceeds its entry cap",
        sort_names=True,
    )
    for name in names:
        budget.consume()
        if not name or name in {b".", b".."} or b"/" in name or b"\0" in name:
            raise ValueError("targeted cleanup tree returned an invalid raw name")
        relative = name if not prefix else prefix + b"/" + name
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = identity_from_stat(metadata)
        kind = _entry_kind(metadata.st_mode)
        records.append(
            ManifestRecord(
                root_index=root_index,
                path=relative,
                kind=kind,
                identity=identity,
            )
        )
        if kind != _KIND_DIRECTORY:
            continue
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            if not directory_identities_match(
                identity_from_stat(os.fstat(child_fd)), identity
            ):
                raise CustodyLostError(
                    "targeted cleanup directory changed during enumeration"
                )
            _enumerate_directory(
                root_index=root_index,
                directory_fd=child_fd,
                prefix=relative,
                records=records,
                budget=budget,
                depth=depth + 1,
            )
        finally:
            os.close(child_fd)


def _encode_manifest(
    records: Iterable[ManifestRecord],
    *,
    payload_cap: int,
    deadline: float,
) -> bytes:
    value = bytearray(_MANIFEST_MAGIC)
    for record in records:
        if time.monotonic() >= deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")
        path = record.path
        identity = record.identity
        value.extend(
            _RECORD.pack(
                record.root_index,
                record.kind,
                len(path),
                identity.mode,
                identity.device,
                identity.inode,
                identity.link_count,
                identity.uid,
                identity.size,
            )
        )
        value.extend(path)
        if len(value) > payload_cap:
            raise ValueError("targeted cleanup manifest exceeds its payload cap")
    return bytes(value)


def build_custodied_manifest(
    *,
    roots: tuple[RootSpec, ...],
    manifest_path: pathlib.Path,
    entry_cap: int,
    payload_cap: int,
    deadline: float | None = None,
    result_owner: CustodiedManifestResultOwner | None = None,
) -> CustodiedManifest:
    if not roots or len(roots) > 2:
        raise ValueError("targeted cleanup requires one or two roots")
    if entry_cap <= 0 or payload_cap < len(_MANIFEST_MAGIC):
        raise ValueError("targeted cleanup manifest bounds are invalid")
    operation_deadline = _operation_deadline(deadline)
    budget = _TraversalBudget(deadline=operation_deadline, remaining=entry_cap)
    root_fds: list[int] = []
    records: list[ManifestRecord] = []
    manifest: CustodiedManifest | None = None
    try:
        for index, spec in enumerate(roots):
            budget.consume()
            if index > 255:
                raise ValueError("targeted cleanup has too many roots")
            _require_parent_custody(spec)
            path_metadata = os.stat(
                spec.name,
                dir_fd=spec.parent_fd,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(path_metadata.st_mode):
                raise ValueError("targeted cleanup root is not a directory")
            root_fd = os.open(
                spec.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=spec.parent_fd,
            )
            root_fds.append(root_fd)
            descriptor = (
                validate_private_directory_fd(
                    root_fd,
                    pathlib.Path(os.fsdecode(spec.name)),
                )
                if spec.private_metadata
                else identity_from_stat(os.fstat(root_fd))
            )
            path_identity = identity_from_stat(path_metadata)
            if (
                not directory_identities_match(descriptor, spec.expected_identity)
                or not directory_identities_match(path_identity, descriptor)
                or descriptor.uid != os.getuid()
            ):
                raise CustodyLostError(
                    f"targeted cleanup root changed for {spec.label}"
                )
            records.append(
                ManifestRecord(
                    root_index=index,
                    path=b"",
                    kind=_KIND_DIRECTORY,
                    identity=descriptor,
                )
            )
            _enumerate_directory(
                root_index=index,
                directory_fd=root_fd,
                prefix=b"",
                records=records,
                budget=budget,
                depth=1,
            )

        records_tuple = tuple(records)
        children_by_parent = _index_manifest_records(
            records_tuple,
            root_count=len(roots),
            entry_cap=entry_cap,
            deadline=operation_deadline,
        )
        payload = _encode_manifest(
            records_tuple,
            payload_cap=payload_cap,
            deadline=operation_deadline,
        )
        if time.monotonic() >= operation_deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")
        manifest_identity = publish_bytes(manifest_path, payload, mode=0o600)
        seal = {
            "version": 1,
            "path": str(manifest_path),
            "identity": manifest_identity.to_json(),
            "length": len(payload),
            "sha256": sha256_bytes(payload),
            "record_count": len(records),
            "entry_cap": entry_cap,
            "payload_cap": payload_cap,
            "roots": [
                {
                    "label": spec.label,
                    "name_hex": spec.name.hex(),
                    "parent_identity": spec.parent_identity.to_json(),
                    "root_identity": spec.expected_identity.to_json(),
                    "private_metadata": spec.private_metadata,
                }
                for spec in roots
            ],
        }
        manifest = CustodiedManifest(
            roots=roots,
            root_fds=tuple(root_fds),
            records=records_tuple,
            seal=seal,
            children_by_parent=children_by_parent,
            deadline=operation_deadline,
        )
        if result_owner is not None:
            result_owner.publish(manifest)
        return manifest
    except BaseException:
        if (
            manifest is not None
            and result_owner is not None
            and result_owner.manifest is manifest
        ):
            raise
        if manifest is not None:
            manifest.close()
        else:
            for fd in root_fds:
                os.close(fd)
        raise


def _same_entry(left: Identity, right: Identity, *, directory: bool) -> bool:
    if directory:
        return directory_identities_match(left, right)
    return left == right


def _children_for(
    manifest: CustodiedManifest,
    *,
    root_index: int,
    prefix: bytes,
) -> dict[bytes, ManifestRecord]:
    try:
        return manifest.children_by_parent[(root_index, prefix)]
    except KeyError as error:
        raise CustodyLostError(
            "targeted cleanup manifest directory index is incomplete"
        ) from error


def _delete_directory_contents(
    *,
    manifest: CustodiedManifest,
    root_index: int,
    directory_fd: int,
    prefix: bytes,
    budget: _TraversalBudget,
    depth: int,
) -> int:
    budget.check()
    if depth > _MAX_DIRECTORY_DEPTH:
        raise ValueError("targeted cleanup tree exceeds its depth cap")
    expected = _children_for(
        manifest,
        root_index=root_index,
        prefix=prefix,
    )
    try:
        actual_names = _bounded_directory_names(
            directory_fd,
            entry_cap=len(expected),
            deadline=budget.deadline,
            error="targeted cleanup tree changed after manifest publication",
            sort_names=False,
        )
    except ValueError as error:
        raise CustodyLostError(str(error)) from error
    if len(actual_names) != len(expected) or set(actual_names) != set(expected):
        raise CustodyLostError(
            "targeted cleanup tree changed after manifest publication"
        )
    removed = 0
    try:
        for name in actual_names:
            budget.consume()
            record = expected[name]
            metadata = identity_from_stat(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            directory = record.kind == _KIND_DIRECTORY
            if not _same_entry(metadata, record.identity, directory=directory):
                raise CustodyLostError("targeted cleanup entry identity changed")
            relative = name if not prefix else prefix + b"/" + name
            if directory:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    if not directory_identities_match(
                        identity_from_stat(os.fstat(child_fd)), record.identity
                    ):
                        raise CustodyLostError(
                            "targeted cleanup directory descriptor changed"
                        )
                    removed += _delete_directory_contents(
                        manifest=manifest,
                        root_index=root_index,
                        directory_fd=child_fd,
                        prefix=relative,
                        budget=budget,
                        depth=depth + 1,
                    )
                finally:
                    os.close(child_fd)
                refreshed = identity_from_stat(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if not directory_identities_match(refreshed, record.identity):
                    raise CustodyLostError(
                        "targeted cleanup directory changed before removal"
                    )
                budget.check()
                os.rmdir(name, dir_fd=directory_fd)
            else:
                budget.check()
                os.unlink(name, dir_fd=directory_fd)
            removed += 1
    finally:
        if removed:
            os.fsync(directory_fd)
    budget.check()
    return removed


def _root_descriptor_identity(
    spec: RootSpec,
    root_fd: int,
    *,
    path_name: bytes,
) -> Identity:
    try:
        if spec.private_metadata:
            return validate_private_directory_fd(
                root_fd,
                pathlib.Path(os.fsdecode(path_name)),
            )
        return identity_from_stat(os.fstat(root_fd))
    except (OSError, ValueError) as error:
        raise CustodyLostError(
            f"targeted cleanup access policy changed for {spec.label}"
        ) from error


def _require_name_absent(
    *,
    parent_fd: int,
    name: bytes,
    error: str,
) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise CustodyLostError(error)


def _quarantined_root_evidence(
    spec: RootSpec,
    root_fd: int,
    quarantine_name: bytes,
    *,
    stage: str,
) -> QuarantinedRootRecoveryEvidence:
    return QuarantinedRootRecoveryEvidence(
        label=spec.label,
        stage=stage,
        parent_fd=spec.parent_fd,
        root_fd=root_fd,
        original_name=spec.name,
        quarantine_name=quarantine_name,
        parent_identity=spec.parent_identity,
        expected_identity=spec.expected_identity,
    )


def _quarantine_custodied_root(
    spec: RootSpec,
    root_fd: int,
    *,
    deadline: float,
    recovery_owner: _QuarantinedRootRecoveryOwner | None = None,
) -> bytes:
    owner = (
        _QuarantinedRootRecoveryOwner(spec=spec, root_fd=root_fd)
        if recovery_owner is None
        else recovery_owner
    )
    if owner.spec is not spec or owner.root_fd != root_fd:
        raise ValueError("quarantine recovery owner is not root-bound")
    _require_parent_custody(spec)
    descriptor = _root_descriptor_identity(
        spec,
        root_fd,
        path_name=spec.name,
    )
    current = identity_from_stat(
        os.stat(spec.name, dir_fd=spec.parent_fd, follow_symlinks=False)
    )
    if not directory_identities_match(
        descriptor, spec.expected_identity
    ) or not directory_identities_match(current, descriptor):
        raise CustodyLostError("targeted cleanup root changed before quarantine")

    quarantine_name: bytes | None = None
    for _ in range(_QUARANTINE_NAME_ATTEMPTS):
        candidate = _QUARANTINE_PREFIX + secrets.token_hex(16).encode("ascii")
        try:
            os.stat(candidate, dir_fd=spec.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            quarantine_name = candidate
            break
    if quarantine_name is None:
        raise FileExistsError("cannot allocate a fresh cleanup quarantine name")

    if time.monotonic() >= deadline:
        raise TimeoutError("targeted cleanup monotonic deadline expired")
    stage = "rename-result-unproven"
    owner.prepare(quarantine_name)
    owner.arm_rename()
    try:
        os.rename(
            spec.name,
            quarantine_name,
            src_dir_fd=spec.parent_fd,
            dst_dir_fd=spec.parent_fd,
        )
        owner.mark_rename_returned()
        stage = "post-rename-parent-fsync"
        os.fsync(spec.parent_fd)
        stage = "post-rename-parent-custody"
        _require_parent_custody(spec)
        stage = "post-rename-quarantine-revalidation"
        quarantined = identity_from_stat(
            os.stat(quarantine_name, dir_fd=spec.parent_fd, follow_symlinks=False)
        )
        descriptor = _root_descriptor_identity(
            spec,
            root_fd,
            path_name=quarantine_name,
        )
        if not directory_identities_match(
            descriptor, spec.expected_identity
        ) or not directory_identities_match(quarantined, descriptor):
            raise CustodyLostError(
                "targeted cleanup quarantined root changed; quarantine retained"
            )
        stage = "post-rename-public-name-check"
        _require_name_absent(
            parent_fd=spec.parent_fd,
            name=spec.name,
            error=(
                "targeted cleanup public root name was replaced; original "
                "quarantine and replacement retained"
            ),
        )
    except BaseException as error:
        owner.attach_if_untransferred(error, stage=stage)
        raise
    return quarantine_name


def _remove_quarantined_empty_root_impl(
    spec: RootSpec,
    root_fd: int,
    *,
    quarantine_name: bytes,
    deadline: float,
    deletion_owner: CustodiedDeletionResultOwner | None = None,
    deletion_outcome: CustodiedRootDeletionOutcome | None = None,
) -> dict[str, Any]:
    _require_parent_custody(spec)
    quarantined = identity_from_stat(
        os.stat(quarantine_name, dir_fd=spec.parent_fd, follow_symlinks=False)
    )
    descriptor = _root_descriptor_identity(
        spec,
        root_fd,
        path_name=quarantine_name,
    )
    if not directory_identities_match(
        descriptor, spec.expected_identity
    ) or not directory_identities_match(quarantined, descriptor):
        raise CustodyLostError(
            "targeted cleanup quarantined root changed before removal"
        )
    _require_name_absent(
        parent_fd=spec.parent_fd,
        name=spec.name,
        error=(
            "targeted cleanup public root name was replaced before quarantine "
            "removal; original quarantine and replacement retained"
        ),
    )
    if _bounded_directory_names(
        root_fd,
        entry_cap=1,
        deadline=deadline,
        error="targeted cleanup quarantined root changed before removal",
        sort_names=False,
    ):
        raise CustodyLostError(
            "targeted cleanup quarantined root is not empty before removal"
        )

    if time.monotonic() >= deadline:
        raise TimeoutError(
            "targeted cleanup deadline expired; original quarantine retained"
        )
    if deletion_owner is not None:
        if deletion_outcome is None:
            raise ValueError("custodied root deletion outcome is unavailable")
        deletion_owner.arm_remove(deletion_outcome)
    os.rmdir(quarantine_name, dir_fd=spec.parent_fd)
    os.fsync(spec.parent_fd)
    _require_parent_custody(spec)
    try:
        os.stat(quarantine_name, dir_fd=spec.parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise CustodyLostError("targeted cleanup quarantine name remains present")
    _require_name_absent(
        parent_fd=spec.parent_fd,
        name=spec.name,
        error=(
            "targeted cleanup public root name was replaced during quarantine "
            "removal; replacement retained"
        ),
    )
    proof = {
        "label": spec.label,
        "name_hex": spec.name.hex(),
        "quarantine_name_hex": quarantine_name.hex(),
        "parent_identity": identity_from_stat(os.fstat(spec.parent_fd)).to_json(),
        "exact_name_absent": True,
        "quarantine_name_absent": True,
    }
    if deletion_owner is not None:
        assert deletion_outcome is not None
        deletion_owner.complete_root(deletion_outcome, proof)
    return proof


def _remove_quarantined_empty_root(
    spec: RootSpec,
    root_fd: int,
    *,
    quarantine_name: bytes,
    deadline: float,
    deletion_owner: CustodiedDeletionResultOwner | None = None,
    deletion_outcome: CustodiedRootDeletionOutcome | None = None,
) -> dict[str, Any]:
    try:
        return _remove_quarantined_empty_root_impl(
            spec,
            root_fd,
            quarantine_name=quarantine_name,
            deadline=deadline,
            deletion_owner=deletion_owner,
            deletion_outcome=deletion_outcome,
        )
    except BaseException as error:
        if deletion_owner is not None:
            setattr(error, "custodied_deletion_result_owner", deletion_owner)
        _attach_quarantined_root_recovery(
            error,
            _quarantined_root_evidence(
                spec,
                root_fd,
                quarantine_name,
                stage="quarantine-removal",
            ),
        )
        raise


def quarantine_and_remove_empty_root(
    spec: RootSpec,
    root_fd: int,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Quarantine a custodied root before proving it empty and removing it."""

    operation_deadline = _operation_deadline(deadline)
    owner = _QuarantinedRootRecoveryOwner(spec=spec, root_fd=root_fd)
    try:
        quarantine_name = _quarantine_custodied_root(
            spec,
            root_fd,
            deadline=operation_deadline,
            recovery_owner=owner,
        )
        owner.transfer_result(quarantine_name)
    except BaseException as error:
        owner.attach_if_untransferred(
            error,
            stage="quarantine-result-publication",
        )
        raise
    return _remove_quarantined_empty_root(
        spec,
        root_fd,
        quarantine_name=quarantine_name,
        deadline=operation_deadline,
    )


def delete_custodied_roots(
    manifest: CustodiedManifest,
    *,
    deadline: float | None = None,
    result_owner: CustodiedDeletionResultOwner | None = None,
) -> dict[str, Any]:
    deletion_owner = result_owner or CustodiedDeletionResultOwner()
    try:
        operation_deadline = (
            manifest.deadline
            if deadline is None
            else min(manifest.deadline, _operation_deadline(deadline))
        )
        budget = _TraversalBudget(
            deadline=operation_deadline,
            remaining=manifest.seal["record_count"],
        )
        budget.check()
        manifest.require_live_custody()
        removed_entries = 0
        for index, (spec, root_fd) in enumerate(
            zip(manifest.roots, manifest.root_fds, strict=True)
        ):
            budget.consume()
            manifest.require_root_custody(index)
            owner = _QuarantinedRootRecoveryOwner(spec=spec, root_fd=root_fd)
            try:
                quarantine_name = _quarantine_custodied_root(
                    spec,
                    root_fd,
                    deadline=budget.deadline,
                    recovery_owner=owner,
                )
                owner.transfer_result(quarantine_name)
            except BaseException as error:
                owner.attach_if_untransferred(
                    error,
                    stage="quarantine-result-publication",
                )
                raise
            stage = "recursive-delete"
            try:
                removed_entries += _delete_directory_contents(
                    manifest=manifest,
                    root_index=index,
                    directory_fd=root_fd,
                    prefix=b"",
                    budget=budget,
                    depth=1,
                )
                stage = "post-recursion-deadline"
                budget.check()
            except BaseException as error:
                _attach_quarantined_root_recovery(
                    error,
                    _quarantined_root_evidence(
                        spec,
                        root_fd,
                        quarantine_name,
                        stage=stage,
                    ),
                )
                raise
            root_outcome = deletion_owner.arm_root(
                root_index=index,
                spec=spec,
                root_fd=root_fd,
                quarantine_name=quarantine_name,
            )
            _remove_quarantined_empty_root(
                spec,
                root_fd,
                quarantine_name=quarantine_name,
                deadline=budget.deadline,
                deletion_owner=deletion_owner,
                deletion_outcome=root_outcome,
            )
            removed_entries += 1
        proofs = deletion_owner.completed_root_proofs(len(manifest.roots))
        proof = {
            "manifest_sha256": manifest.seal["sha256"],
            "manifest_record_count": manifest.seal["record_count"],
            "removed_entries": removed_entries,
            "roots": proofs,
            "parent_fsync_complete": True,
            "exact_names_absent": True,
        }
        deletion_owner.publish(proof)
        return proof
    except BaseException as error:
        # Earlier roots may already have durable removal proofs even when a later
        # root fails before it reaches the remove wrapper. Preserve that owner on
        # every exit so callers can distinguish completed and unresolved roots.
        setattr(error, "custodied_deletion_result_owner", deletion_owner)
        raise


def remove_published_manifest(seal: dict[str, Any]) -> None:
    path = pathlib.Path(seal["path"])
    expected_identity = Identity(**seal["identity"])
    directory_fd, _ = open_absolute_directory_chain(path.parent, private_leaf=True)
    try:
        fd, identity = open_regular_at(
            directory_fd,
            os.fsencode(path.name),
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            if identity != expected_identity or identity.size != seal["length"]:
                raise CustodyLostError("targeted cleanup manifest identity changed")
            content = read_fd_exact(
                fd,
                max_bytes=seal["payload_cap"],
                expected_size=seal["length"],
            )
        finally:
            os.close(fd)
        if sha256_bytes(content) != seal["sha256"]:
            raise CustodyLostError("targeted cleanup manifest digest changed")
        os.unlink(os.fsencode(path.name), dir_fd=directory_fd)
        os.fsync(directory_fd)
        try:
            os.stat(
                os.fsencode(path.name),
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise CustodyLostError("targeted cleanup manifest remains present")
    finally:
        os.close(directory_fd)


def enumerate_registration_conflicts(
    *,
    common_git_dir: pathlib.Path,
    worktree: pathlib.Path,
    entry_cap: int = 100_000,
    deadline: float | None = None,
) -> dict[str, Any]:
    if type(entry_cap) is not int or entry_cap < 0:
        raise ValueError("Git worktree registration entry cap is invalid")
    operation_deadline = _operation_deadline(deadline)
    namespace = common_git_dir / "worktrees"
    try:
        parent_fd, _ = open_absolute_directory_chain(namespace)
    except FileNotFoundError:
        return {
            "namespace_present": False,
            "registration_count": 0,
            "namespace_sha256": sha256_bytes(b""),
            "exact_matches": [],
            "alias_matches": [],
        }
    try:
        names = _bounded_directory_names(
            parent_fd,
            entry_cap=entry_cap,
            deadline=operation_deadline,
            error="Git worktree registration namespace exceeds its cap",
            sort_names=True,
        )
        exact_name = os.fsencode(worktree.name)
        expected_marker = os.fsencode(worktree / ".git")
        digest = hashlib.sha256()
        exact_matches: list[str] = []
        alias_matches: list[str] = []
        for name in names:
            if time.monotonic() >= operation_deadline:
                raise TimeoutError("targeted cleanup monotonic deadline expired")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Git worktree registration entry is not a directory")
            if name == exact_name:
                exact_matches.append(os.fsdecode(name))
            registration_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                try:
                    gitdir_fd, gitdir_identity = open_regular_at(
                        registration_fd,
                        b"gitdir",
                        expected_uid=os.getuid(),
                    )
                except FileNotFoundError:
                    continue
                try:
                    if gitdir_identity.size > 4096:
                        raise ValueError("Git worktree gitdir record is oversized")
                    target = read_fd_exact(
                        gitdir_fd,
                        max_bytes=4096,
                        expected_size=gitdir_identity.size,
                    ).strip()
                finally:
                    os.close(gitdir_fd)
                digest.update(sha256_bytes(target).encode("ascii"))
                if os.path.normpath(target) == os.path.normpath(expected_marker):
                    alias_matches.append(os.fsdecode(name))
            finally:
                os.close(registration_fd)
        if len(exact_matches) > 16 or len(alias_matches) > 16:
            raise ValueError("too many conflicting Git worktree registrations")
        return {
            "namespace_present": True,
            "registration_count": len(names),
            "namespace_sha256": digest.hexdigest(),
            "exact_matches": exact_matches,
            "alias_matches": alias_matches,
        }
    finally:
        os.close(parent_fd)


def require_no_registration_conflicts(evidence: dict[str, Any]) -> None:
    if evidence["exact_matches"] or evidence["alias_matches"]:
        raise ValueError("exact or alias Git worktree registration remains present")
