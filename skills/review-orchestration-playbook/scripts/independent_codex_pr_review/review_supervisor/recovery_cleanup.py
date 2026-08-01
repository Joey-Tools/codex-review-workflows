from __future__ import annotations

import errno
import hashlib
import math
import os
import pathlib
import secrets
import signal
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .constants import TARGETED_MANIFEST_RECORD_BYTES
from .models import Identity
from .secureio import (
    LEAF_CONTENT_STATES,
    MAX_LEAF_CONTENT_BYTES,
    LeafContentDeadlineExpired,
    directory_identities_match,
    identity_from_stat,
    inspect_leaf_content_digest,
    inspect_macos_leaf_metadata_digest,
    leaf_content_state_for_file_type,
    open_absolute_directory_chain,
    open_regular_at,
    publish_bytes,
    read_fd_exact,
    rename_noreplace,
    sha256_bytes,
    validate_private_directory_fd,
)
from .signal_relay import (
    DeferredSignalScope,
    begin_bound_signal_deferral,
    checkpoint_bound_signal_interrupt,
)

_MANIFEST_MAGIC = b"targeted-cleanup-manifest-v3\0"
_RECORD = struct.Struct(">BBIIQQQQQ")
_LEAF_POLICY_RECORD = struct.Struct(">QQQB32sB32s")
if _RECORD.size + _LEAF_POLICY_RECORD.size > TARGETED_MANIFEST_RECORD_BYTES:
    raise RuntimeError("targeted cleanup leaf record exceeds its admission bound")
_KIND_DIRECTORY = 1
_KIND_ENTRY = 2
_DEFAULT_TARGETED_CLEANUP_SECONDS = 30.0
_MAX_DIRECTORY_DEPTH = 512
_QUARANTINE_PREFIX = b".targeted-cleanup-quarantine-"
_QUARANTINE_NAME_ATTEMPTS = 64
_LEAF_QUARANTINE_PREFIX = b".targeted-cleanup-leaf-"
_LEAF_DELETION_SIGNALS = (
    signal.SIGHUP,
    signal.SIGINT,
    signal.SIGQUIT,
    signal.SIGTERM,
)
_QUARANTINED_ROOT_RECOVERY_ATTR = "_quarantined_root_recovery_evidence"
_LEAF_DESCRIPTOR_CUSTODY_ATTR = "_leaf_descriptor_custody_owners"
_DIRECTORY_DESCRIPTOR_CUSTODY_ATTR = "_directory_descriptor_custody_owners"
_CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ATTR = "custodied_manifest_close_evidence"
_CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ITEMS_ATTR = (
    "custodied_manifest_close_evidence_items"
)
_DELETION_RESULT_OWNER_ATTR = "custodied_deletion_result_owner"


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
    leaf_descriptor_custody_owners: tuple[_LeafDescriptorCustodyOwner, ...] = ()


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
    leaf_owners = leaf_descriptor_custody_owners(error)
    if leaf_owners and not evidence.leaf_descriptor_custody_owners:
        evidence = replace(
            evidence,
            leaf_descriptor_custody_owners=leaf_owners,
        )
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
    leaf_policy: LeafAccessPolicyBinding | None = None


@dataclass(frozen=True, slots=True)
class LeafAccessPolicyBinding:
    """Manifest-bound leaf identity, content shape, and access policy."""

    device: int
    inode: int
    file_type: int
    generation: int
    uid: int
    gid: int
    mode: int
    flags: int
    size: int
    metadata_state: int
    metadata_sha256: bytes
    content_state: int
    content_sha256: bytes

    @property
    def object_key(self) -> tuple[int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.file_type,
            self.generation,
        )

    @property
    def content_key(self) -> tuple[int, int, bytes]:
        return self.size, self.content_state, self.content_sha256

    @property
    def access_policy_key(
        self,
    ) -> tuple[int, int, int, int, int, bytes]:
        return (
            self.uid,
            self.gid,
            self.mode,
            self.flags,
            self.metadata_state,
            self.metadata_sha256,
        )


@dataclass(frozen=True, slots=True)
class LeafSnapshot:
    policy: LeafAccessPolicyBinding
    link_count: int


def _leaf_snapshot_from_stat(
    metadata: os.stat_result,
    *,
    metadata_state: int,
    metadata_sha256: bytes,
    content_state: int,
    content_sha256: bytes,
) -> LeafSnapshot:
    return LeafSnapshot(
        policy=LeafAccessPolicyBinding(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            file_type=stat.S_IFMT(metadata.st_mode),
            generation=getattr(metadata, "st_gen", 0),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=stat.S_IMODE(metadata.st_mode),
            flags=getattr(metadata, "st_flags", 0),
            size=metadata.st_size,
            metadata_state=metadata_state,
            metadata_sha256=metadata_sha256,
            content_state=content_state,
            content_sha256=content_sha256,
        ),
        link_count=metadata.st_nlink,
    )


def _validate_manifest_leaf_policy(record: ManifestRecord) -> None:
    policy = record.leaf_policy
    if record.kind == _KIND_DIRECTORY:
        if policy is not None:
            raise ValueError(
                "targeted cleanup directory record has a leaf policy binding"
            )
        return
    if not isinstance(policy, LeafAccessPolicyBinding):
        raise ValueError("targeted cleanup leaf policy binding is missing")
    if not _leaf_policy_matches_identity(policy, record.identity):
        raise ValueError("targeted cleanup leaf policy binding is inconsistent")
    for value in (
        policy.device,
        policy.inode,
        policy.file_type,
        policy.generation,
        policy.uid,
        policy.gid,
        policy.mode,
        policy.flags,
        policy.size,
    ):
        if type(value) is not int or not 0 <= value < 2**64:
            raise ValueError("targeted cleanup leaf policy binding is invalid")
    if (
        type(policy.metadata_state) is not int
        or policy.metadata_state not in {0, 1}
        or not isinstance(policy.metadata_sha256, bytes)
        or len(policy.metadata_sha256) != hashlib.sha256().digest_size
    ):
        raise ValueError("targeted cleanup leaf metadata binding is invalid")
    if (
        type(policy.content_state) is not int
        or policy.content_state not in LEAF_CONTENT_STATES
        or not isinstance(policy.content_sha256, bytes)
        or len(policy.content_sha256) != hashlib.sha256().digest_size
    ):
        raise ValueError("targeted cleanup leaf content binding is invalid")
    if policy.content_state != leaf_content_state_for_file_type(policy.file_type):
        raise ValueError("targeted cleanup leaf content state is inconsistent")
    if stat.S_ISREG(policy.file_type) and policy.size > MAX_LEAF_CONTENT_BYTES:
        raise ValueError("targeted cleanup regular leaf exceeds its content cap")


def _leaf_policy_matches_identity(
    policy: LeafAccessPolicyBinding,
    identity: Identity,
) -> bool:
    return (
        identity.link_count == 1
        and policy.device == identity.device
        and policy.inode == identity.inode
        and policy.file_type == stat.S_IFMT(identity.mode)
        and policy.uid == identity.uid
        and policy.mode == stat.S_IMODE(identity.mode)
        and policy.size == identity.size
    )


def _encode_leaf_policy(binding: LeafAccessPolicyBinding) -> bytes:
    return _LEAF_POLICY_RECORD.pack(
        binding.gid,
        binding.flags,
        binding.generation,
        binding.metadata_state,
        binding.metadata_sha256,
        binding.content_state,
        binding.content_sha256,
    )


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


def _attach_custodied_manifest_close_evidence_items(
    error: BaseException,
    evidence_items: Sequence[CustodiedManifestCloseEvidence],
) -> None:
    """Attach every exact close-evidence object directly to one final error."""

    collected: list[CustodiedManifestCloseEvidence] = []

    def append(candidate: object) -> None:
        if isinstance(candidate, CustodiedManifestCloseEvidence) and all(
            existing is not candidate for existing in collected
        ):
            collected.append(candidate)

    for evidence in evidence_items:
        append(evidence)
    existing_items = getattr(
        error,
        _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ITEMS_ATTR,
        (),
    )
    if isinstance(existing_items, tuple):
        for evidence in existing_items:
            append(evidence)
    append(getattr(error, _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ATTR, None))
    if not collected:
        return
    try:
        setattr(
            error,
            _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ITEMS_ATTR,
            tuple(collected),
        )
    except BaseException:  # noqa: BLE001 - evidence cannot replace failure
        pass
    if not isinstance(
        getattr(error, _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ATTR, None),
        CustodiedManifestCloseEvidence,
    ):
        try:
            setattr(
                error,
                _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ATTR,
                collected[0],
            )
        except BaseException:  # noqa: BLE001 - compatibility evidence only
            pass


def custodied_manifest_close_evidence_items(
    error: BaseException,
) -> tuple[CustodiedManifestCloseEvidence, ...]:
    """Collect identity-distinct manifest close evidence from an error tree."""

    collected: list[CustodiedManifestCloseEvidence] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        attached = getattr(
            current,
            _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ITEMS_ATTR,
            (),
        )
        if isinstance(attached, tuple):
            for evidence in attached:
                if isinstance(evidence, CustodiedManifestCloseEvidence) and all(
                    candidate is not evidence for candidate in collected
                ):
                    collected.append(evidence)
        singular = getattr(
            current,
            _CUSTODIED_MANIFEST_CLOSE_EVIDENCE_ATTR,
            None,
        )
        if isinstance(singular, CustodiedManifestCloseEvidence) and all(
            candidate is not singular for candidate in collected
        ):
            collected.append(singular)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return tuple(collected)


@dataclass(slots=True, eq=False)
class _CustodiedManifestDescriptorSlot:
    purpose: str
    expected_identity: Identity
    descriptor: int | None = None
    state: str = "empty"
    close_error: BaseException | None = None
    observed_identity: Identity | None = None
    custody_reason: str | None = None
    protected_property: str = (
        "open-file-description-custody-and-directory-object-identity"
    )

    def publish(self, descriptor: int) -> None:
        if self.state != "empty" or self.descriptor is not None:
            raise ValueError("directory descriptor custody owner is already used")
        if type(descriptor) is not int or descriptor < 0:
            raise ValueError("directory descriptor custody result is invalid")
        self.descriptor = descriptor
        self.state = "owned"

    def close_one_shot(self) -> None:
        if self.state in {
            "closed",
            "close-outcome-unproven",
            "missing-before-close",
            "unreadable-before-close",
            "identity-mismatch-before-close",
        }:
            return
        if self.state == "empty":
            self.state = "closed"
            return
        if self.state != "owned" or self.descriptor is None:
            raise RuntimeError("directory descriptor custody close state is invalid")
        descriptor = self.descriptor
        try:
            observed = identity_from_stat(os.fstat(descriptor))
        except OSError as error:
            self.state = (
                "missing-before-close"
                if error.errno == errno.EBADF
                else "unreadable-before-close"
            )
            self.close_error = error
            self.custody_reason = f"{type(error).__name__}: {error}"
            _attach_directory_descriptor_custody(error, self)
            raise
        self.observed_identity = observed
        if not directory_identities_match(observed, self.expected_identity):
            self.state = "identity-mismatch-before-close"
            self.custody_reason = (
                "descriptor integer names a different directory object; close "
                "was not attempted"
            )
            error = CustodyLostError(
                "directory descriptor identity changed before close"
            )
            self.close_error = error
            _attach_directory_descriptor_custody(error, self)
            raise error
        # This state is terminal. An exception can arrive before the syscall or
        # after the kernel has closed the open file description, so retrying the
        # integer could close an unrelated descriptor after number reuse.
        # The owner's uninterrupted open-to-publication transition establishes
        # open-file-description custody. Matching object identity here detects
        # visible integer replacement, but does not independently prove that two
        # descriptors for the same directory share an open file description.
        try:
            self.state = "close-outcome-unproven"
            os.close(descriptor)
            self.descriptor = None
            self.state = "closed"
            self.close_error = None
            self.custody_reason = "owned descriptor close returned successfully"
        except BaseException as error:
            if self.state != "closed":
                self.close_error = error
                self.custody_reason = (
                    "close was armed; syscall completion is not safely retryable"
                )
            _attach_directory_descriptor_custody(error, self)
            raise


def _attach_directory_descriptor_custody(
    error: BaseException,
    owner: _CustodiedManifestDescriptorSlot,
) -> None:
    attached = getattr(error, _DIRECTORY_DESCRIPTOR_CUSTODY_ATTR, ())
    if not isinstance(attached, tuple) or not all(
        isinstance(item, _CustodiedManifestDescriptorSlot) for item in attached
    ):
        attached = ()
    if all(candidate is not owner for candidate in attached):
        try:
            setattr(error, _DIRECTORY_DESCRIPTOR_CUSTODY_ATTR, (*attached, owner))
        except BaseException:  # noqa: BLE001 - evidence cannot replace failure
            return
    try:
        error.add_note(
            "directory descriptor custody recovery: "
            f"purpose={owner.purpose}, state={owner.state}, "
            f"descriptor={owner.descriptor}"
        )
    except BaseException:  # noqa: BLE001,S110 - notes cannot replace failure
        pass


def _attach_directory_descriptor_custody_owners(
    error: BaseException,
    owners: Iterable[_CustodiedManifestDescriptorSlot],
) -> None:
    """Attach every currently relevant owner from a complete accumulator."""

    for owner in owners:
        if owner.state != "closed" or owner.close_error is not None:
            _attach_directory_descriptor_custody(error, owner)


def _relevant_directory_descriptor_custody_owners(
    owners: Iterable[_CustodiedManifestDescriptorSlot],
) -> tuple[_CustodiedManifestDescriptorSlot, ...]:
    return tuple(
        owner
        for owner in owners
        if owner.state != "closed" or owner.close_error is not None
    )


def directory_descriptor_custody_owners(
    error: BaseException,
) -> tuple[_CustodiedManifestDescriptorSlot, ...]:
    collected: list[_CustodiedManifestDescriptorSlot] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        attached = getattr(current, _DIRECTORY_DESCRIPTOR_CUSTODY_ATTR, ())
        if isinstance(attached, tuple):
            for owner in attached:
                if isinstance(owner, _CustodiedManifestDescriptorSlot) and all(
                    candidate is not owner for candidate in collected
                ):
                    collected.append(owner)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return tuple(collected)


class CustodiedManifest:
    def __init__(
        self,
        *,
        roots: tuple[RootSpec, ...],
        root_fd_slots: tuple[_CustodiedManifestDescriptorSlot, ...],
        records: tuple[ManifestRecord, ...],
        seal: dict[str, Any],
        children_by_parent: dict[tuple[int, bytes], dict[bytes, ManifestRecord]],
        deadline: float,
    ) -> None:
        if len(root_fd_slots) != len(roots) or any(
            slot.state != "owned" or slot.descriptor is None for slot in root_fd_slots
        ):
            raise ValueError("custodied manifest root descriptor custody is incomplete")
        self.roots = roots
        # Keep the exact pre-open owners. No integer-only handoff exists between
        # manifest construction and long-lived close/recovery custody.
        self._root_fd_slots = list(root_fd_slots)
        self.records = records
        self.seal = seal
        self.children_by_parent = children_by_parent
        self.deadline = deadline
        self._closed = False
        self._close_blocked = False
        self._close_evidence: list[CustodiedManifestCloseEvidence] = []
        self._deletion_result_owner: CustodiedDeletionResultOwner | None = None

    @property
    def root_fds(self) -> list[int]:
        return [
            slot.descriptor
            for slot in self._root_fd_slots
            if slot.state == "owned" and slot.descriptor is not None
        ]

    @property
    def close_evidence(self) -> tuple[CustodiedManifestCloseEvidence, ...]:
        return tuple(self._close_evidence)

    @property
    def deletion_result_owner(self) -> CustodiedDeletionResultOwner | None:
        return self._deletion_result_owner

    def bind_deletion_result_owner(
        self,
        owner: CustodiedDeletionResultOwner,
    ) -> None:
        if not isinstance(owner, CustodiedDeletionResultOwner):
            raise TypeError("custodied deletion result owner is invalid")
        if self._deletion_result_owner is None:
            self._deletion_result_owner = owner
            return
        if self._deletion_result_owner is not owner:
            raise ValueError("custodied deletion result owner was rebound")

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
            _attach_custodied_manifest_close_evidence_items(error, (evidence,))

    def close(self) -> None:
        if self._closed:
            return
        close_errors: list[tuple[str, BaseException]] = []
        close_error_slots: list[tuple[int, _CustodiedManifestDescriptorSlot]] = []
        for index, slot in enumerate(self._root_fd_slots):
            if slot.state in {
                "closed",
                "ownership-ambiguous-closed-or-missing",
            }:
                continue
            if slot.state != "owned":
                previous_error = slot.close_error
                blocked = CustodyLostError(
                    f"targeted cleanup descriptor close remains blocked: {slot.state}"
                )
                if previous_error is not None:
                    try:
                        blocked.add_note(
                            "previous descriptor close failure: "
                            f"{type(previous_error).__name__}: {previous_error}"
                        )
                    except BaseException:  # noqa: BLE001,S110 - evidence only
                        pass
                slot.close_error = blocked
                _attach_directory_descriptor_custody(blocked, slot)
                close_errors.append((f"root descriptor {index}", blocked))
                close_error_slots.append((index, slot))
                continue
            descriptor = slot.descriptor
            if descriptor is None:
                blocked = CustodyLostError(
                    "targeted cleanup descriptor close remains blocked: missing-owner"
                )
                slot.state = "missing-before-close"
                slot.close_error = blocked
                _attach_directory_descriptor_custody(blocked, slot)
                close_errors.append((f"root descriptor {index}", blocked))
                close_error_slots.append((index, slot))
                continue
            before = self._observe_close_descriptor(
                index,
                descriptor,
                missing_state="missing-before-close",
                live_state="live-before-close",
            )
            if before.state != "live-before-close":
                slot.state = before.state
                blocked = CustodyLostError(
                    "targeted cleanup descriptor cannot be closed safely: "
                    f"{before.state}"
                )
                slot.close_error = blocked
                slot.observed_identity = before.observed_identity
                slot.custody_reason = before.reason
                self._record_close_evidence(before, blocked)
                _attach_directory_descriptor_custody(blocked, slot)
                close_errors.append((f"root descriptor {index}", blocked))
                close_error_slots.append((index, slot))
                continue
            try:
                slot.state = "close-outcome-unproven"
                os.close(descriptor)
                slot.state = "closed"
                slot.close_error = None
                slot.observed_identity = before.observed_identity
                slot.custody_reason = "owned descriptor close returned successfully"
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
                slot.observed_identity = after.observed_identity
                slot.custody_reason = after.reason
                if after.state == "ownership-ambiguous-closed-or-missing":
                    slot.close_error = None
                self._record_close_evidence(after, error)
                _attach_directory_descriptor_custody(error, slot)
                close_errors.append((f"root descriptor {index}", error))
                close_error_slots.append((index, slot))
        self._closed = all(
            slot.state in {"closed", "ownership-ambiguous-closed-or-missing"}
            for slot in self._root_fd_slots
        )
        self._close_blocked = not self._closed
        if close_errors:
            # Freeze/selector/result publication is interruptible. Reconcile
            # every hook into the same caller-owned error list, then retry the
            # complete set/tuple freeze and publication until the selected error
            # directly carries all exact owners and plural evidence. The final
            # RAISE is deliberately outside this loop: there is no later
            # publication to recover inside this frame.
            while True:
                try:
                    close_error_indexes = {index for index, _ in close_error_slots}
                    close_error_evidence = tuple(
                        evidence
                        for evidence in self._close_evidence
                        if evidence.root_index in close_error_indexes
                    )
                    close_error_owners = tuple(slot for _, slot in close_error_slots)
                    selected = _select_leaf_cleanup_error(close_errors)
                    assert selected is not None
                    _attach_directory_descriptor_custody_owners(
                        selected,
                        close_error_owners,
                    )
                    _attach_custodied_manifest_close_evidence_items(
                        selected,
                        close_error_evidence,
                    )
                except BaseException as publication_error:
                    close_errors.append(
                        (
                            "manifest close terminal aggregation publication",
                            publication_error,
                        )
                    )
                    continue
                break
            raise selected
        if self._close_blocked:
            raise CustodyLostError("targeted cleanup descriptor close remains blocked")

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
        if slot.state != "owned" or slot.descriptor is None:
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
    """Long-lived proof and error-priority owner for destructive deletion.

    The protected property is durable deletion-proof ownership plus preservation
    of the first control-flow ``BaseException`` across one supported callback
    delivery handoff. A trace/profile callback that raises is disabled by
    CPython; re-arming callbacks or repeated independent asynchronous injection
    remains outside this bounded contract.
    """

    proof: dict[str, Any] | None = None
    transferred: bool = False
    finished: bool = False
    root_outcomes: list[CustodiedRootDeletionOutcome] = field(default_factory=list)
    leaf_cleanup_owners: list[_LeafCleanupDeliveryOwner] = field(default_factory=list)
    directory_cleanup_owners: list[_CustodiedManifestDescriptorSlot] = field(
        default_factory=list
    )
    _delivery_state: tuple[
        tuple[tuple[str, BaseException], ...],
        BaseException | None,
    ] = field(
        default=((), None),
        init=False,
        repr=False,
    )

    @property
    def authoritative_delivery_error(self) -> BaseException | None:
        return self._delivery_state[1]

    @property
    def delivery_errors(self) -> tuple[tuple[str, BaseException], ...]:
        return self._delivery_state[0]

    def capture_delivery_error(
        self,
        operation: str,
        error: BaseException,
    ) -> None:
        if not isinstance(operation, str) or not operation:
            raise ValueError("custodied deletion error operation is invalid")
        if not isinstance(error, BaseException):
            raise TypeError("custodied deletion error must be a BaseException")
        previous_errors, primary = self._delivery_state
        if any(candidate is error for _, candidate in previous_errors):
            setattr(error, _DELETION_RESULT_OWNER_ATTR, self)
            return

        next_authoritative = primary
        if primary is None:
            next_authoritative = error
        elif isinstance(primary, Exception) and not isinstance(error, Exception):
            next_authoritative = error
        # Publish dedupe membership and authoritative selection with one
        # pointer store. A supported callback can observe only the complete
        # old or complete new owner state, never a half-published transition.
        self._delivery_state = (
            (*previous_errors, (operation, error)),
            next_authoritative,
        )

        if primary is not None:
            if isinstance(primary, Exception) and not isinstance(error, Exception):
                for previous_operation, previous_error in previous_errors:
                    _add_leaf_cleanup_error_note(
                        error,
                        previous_operation,
                        previous_error,
                    )
            else:
                _add_leaf_cleanup_error_note(primary, operation, error)
        setattr(error, _DELETION_RESULT_OWNER_ATTR, self)

    def settle_delivery_boundary(
        self,
        boundary_error: BaseException,
    ) -> BaseException:
        """Reconcile one caller-owned terminal delivery against this owner."""

        return _settle_custodied_deletion_boundary(self, boundary_error)

    def register_leaf_cleanup(
        self,
        owner: _LeafCleanupDeliveryOwner,
    ) -> None:
        if not isinstance(owner, _LeafCleanupDeliveryOwner):
            raise TypeError("leaf cleanup delivery owner is invalid")
        if any(candidate is owner for candidate in self.leaf_cleanup_owners):
            return
        self.leaf_cleanup_owners.append(owner)

    def register_directory_cleanup(
        self,
        owner: _CustodiedManifestDescriptorSlot,
    ) -> None:
        if not isinstance(owner, _CustodiedManifestDescriptorSlot):
            raise TypeError("directory cleanup custody owner is invalid")
        if any(candidate is owner for candidate in self.directory_cleanup_owners):
            return
        self.directory_cleanup_owners.append(owner)

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
    if stat.S_ISREG(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(mode):
        return _KIND_ENTRY
    raise ValueError("targeted cleanup tree contains an unsupported entry type")


def _open_custodied_directory_descriptor(
    owner: _CustodiedManifestDescriptorSlot,
    name: bytes,
    *,
    directory_fd: int,
) -> int:
    """Open and publish one directory FD before supported delivery resumes."""

    if owner.state != "empty" or owner.descriptor is not None:
        raise ValueError("directory descriptor custody owner is already used")
    error_owner = _LeafCleanupErrorOwner()
    try:
        with _SupportedLeafDeletionCriticalSection(error_owner):
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            owner.publish(descriptor)
    except BaseException as error:
        _attach_directory_descriptor_custody(error, owner)
        raise
    return descriptor


def _settle_directory_descriptor_owner(
    owner: _CustodiedManifestDescriptorSlot,
    trigger_error: BaseException | None = None,
) -> BaseException | None:
    """Settle one owner without retrying an armed close syscall."""

    error_owner = _LeafCleanupErrorOwner()
    if trigger_error is not None:
        error_owner.capture("directory descriptor operation", trigger_error)
    while owner.state in {"empty", "owned"}:
        try:
            owner.close_one_shot()
        except BaseException as error:  # noqa: BLE001 - close custody
            error_owner.capture("directory descriptor close", error)
    if owner.state not in {
        "closed",
        "close-outcome-unproven",
        "missing-before-close",
        "unreadable-before-close",
        "identity-mismatch-before-close",
    }:
        error_owner.capture(
            "directory descriptor terminal-state publication",
            CustodyLostError(
                "directory descriptor custody did not reach a terminal state"
            ),
        )
    for _, error in error_owner.errors:
        _attach_directory_descriptor_custody(error, owner)
    selected = error_owner.authoritative_error
    if selected is not None:
        _attach_directory_descriptor_custody(selected, owner)
    return selected


def _settle_directory_descriptor_owners(
    owners: Sequence[_CustodiedManifestDescriptorSlot],
    trigger_error: BaseException,
) -> BaseException:
    """Settle every owner while preserving first/control-flow priority."""

    # Freeze and publish every currently relevant exact owner before settlement.
    # A hook at the relevant-scan, first-attach, selector, or selected-attach
    # boundary joins the same ordered arbitration and the whole publication is
    # retried before any descriptor state can change.
    prepublication_errors: list[tuple[str, BaseException]] = [
        ("directory descriptor trigger", trigger_error)
    ]
    while True:
        try:
            prepublished_owners = _relevant_directory_descriptor_custody_owners(owners)
            _attach_directory_descriptor_custody_owners(
                trigger_error,
                prepublished_owners,
            )
            selected = _select_leaf_cleanup_error(prepublication_errors)
            assert selected is not None
            _attach_directory_descriptor_custody_owners(
                selected,
                prepublished_owners,
            )
        except BaseException as publication_error:
            prepublication_errors.append(
                (
                    "directory descriptor pre-settlement publication",
                    publication_error,
                )
            )
            continue
        break
    for owner in reversed(owners):
        if owner.state == "closed":
            continue
        candidate = _settle_directory_descriptor_owner(owner, selected)
        if candidate is not None:
            selected = candidate
    final_publication_errors: list[tuple[str, BaseException]] = [
        ("directory descriptor settlement", selected)
    ]
    while True:
        try:
            final_selected = _select_leaf_cleanup_error(final_publication_errors)
            assert final_selected is not None
            for owner in prepublished_owners:
                _attach_directory_descriptor_custody(final_selected, owner)
            _attach_directory_descriptor_custody_owners(final_selected, owners)
        except BaseException as publication_error:
            final_publication_errors.append(
                (
                    "directory descriptor terminal publication",
                    publication_error,
                )
            )
            continue
        selected = final_selected
        break
    return selected


def _enumerate_directory(
    *,
    root_index: int,
    directory_fd: int,
    prefix: bytes,
    records: list[ManifestRecord],
    descriptor_owners: list[_CustodiedManifestDescriptorSlot],
    leaf_delivery_owners: list[_LeafCleanupDeliveryOwner],
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
        if kind != _KIND_DIRECTORY and identity.link_count != 1:
            raise ValueError("targeted cleanup tree contains a non-unique leaf entry")
        leaf_policy: LeafAccessPolicyBinding | None = None
        if kind != _KIND_DIRECTORY:
            descriptor_owner = _LeafDescriptorCustodyOwner()
            error_owner = _LeafCleanupErrorOwner()
            settlement = _LeafDescriptorCloseSettlement(
                descriptor_owner,
                error_owner,
            )
            delivery_owner = _LeafCleanupDeliveryOwner(
                descriptor_owner,
                error_owner,
                settlement,
            )
            policy_result_owner = _LeafPolicyResultOwner()
            # Register the complete delivery owner in the build-level outer
            # frame before the first descriptor-bearing call.
            leaf_delivery_owners.append(delivery_owner)
            try:
                _capture_manifest_leaf_policy(
                    directory_fd=directory_fd,
                    name=name,
                    expected=identity,
                    path_metadata=metadata,
                    deadline=budget.deadline,
                    delivery_owner=delivery_owner,
                    policy_result_owner=policy_result_owner,
                )
            except BaseException as leaf_boundary:  # noqa: BLE001 - handoff
                delivery_owner.enqueue(
                    "manifest leaf policy caller boundary",
                    leaf_boundary,
                )
            while True:
                try:
                    _drive_leaf_cleanup_delivery(delivery_owner)
                except BaseException as caller_error:
                    if (
                        delivery_owner._raise_in_progress
                        and caller_error is delivery_owner._armed_error
                    ):
                        raise
                    delivery_owner.enqueue(
                        "manifest leaf policy outer delivery boundary",
                        caller_error,
                    )
                else:
                    break
            if (
                not leaf_delivery_owners
                or leaf_delivery_owners[-1] is not delivery_owner
            ):
                raise RuntimeError("manifest leaf delivery registry is inconsistent")
            leaf_delivery_owners.pop()
            leaf_policy = policy_result_owner.binding
            if leaf_policy is None:
                raise CustodyLostError(
                    "targeted cleanup leaf policy result was not published"
                )
        records.append(
            ManifestRecord(
                root_index=root_index,
                path=relative,
                kind=kind,
                identity=identity,
                leaf_policy=leaf_policy,
            )
        )
        if kind != _KIND_DIRECTORY:
            continue
        child_owner = _CustodiedManifestDescriptorSlot(
            purpose=f"manifest-enumeration:{relative.hex()}",
            expected_identity=identity,
        )
        # The build-level accumulator outlives this recursive frame and owns
        # settlement if a callback interrupts this frame's cleanup CALL.
        descriptor_owners.append(child_owner)
        try:
            child_fd = _open_custodied_directory_descriptor(
                child_owner,
                name,
                directory_fd=directory_fd,
            )
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
                descriptor_owners=descriptor_owners,
                leaf_delivery_owners=leaf_delivery_owners,
                budget=budget,
                depth=depth + 1,
            )
        except BaseException as error:
            selected = _settle_directory_descriptor_owner(child_owner, error)
            if selected is error:
                raise
            assert selected is not None
            raise selected
        else:
            selected = _settle_directory_descriptor_owner(child_owner)
            if selected is not None:
                raise selected


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
        _validate_manifest_leaf_policy(record)
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
        if record.leaf_policy is not None:
            value.extend(_encode_leaf_policy(record.leaf_policy))
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
    root_fd_slots: list[_CustodiedManifestDescriptorSlot] = []
    build_descriptor_owners: list[_CustodiedManifestDescriptorSlot] = []
    build_leaf_delivery_owners: list[_LeafCleanupDeliveryOwner] = []
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
            root_slot = _CustodiedManifestDescriptorSlot(
                purpose=f"manifest-root:{spec.label}",
                expected_identity=spec.expected_identity,
            )
            # Publish the owner to the longer-lived build frame before open.
            # A CALL-to-STORE interruption can therefore never orphan the FD.
            root_fd_slots.append(root_slot)
            build_descriptor_owners.append(root_slot)
            root_fd = _open_custodied_directory_descriptor(
                root_slot,
                spec.name,
                directory_fd=spec.parent_fd,
            )
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
                descriptor_owners=build_descriptor_owners,
                leaf_delivery_owners=build_leaf_delivery_owners,
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
            "version": 3,
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
            root_fd_slots=tuple(root_fd_slots),
            records=records_tuple,
            seal=seal,
            children_by_parent=children_by_parent,
            deadline=operation_deadline,
        )
        if result_owner is not None:
            result_owner.publish(manifest)
        return manifest
    except BaseException as error:
        if (
            manifest is not None
            and result_owner is not None
            and result_owner.manifest is manifest
        ):
            for slot in root_fd_slots:
                _attach_directory_descriptor_custody(error, slot)
            raise
        if manifest is not None:
            try:
                manifest.close()
            except BaseException as close_error:
                selected = _select_leaf_cleanup_error(
                    (
                        ("manifest build", error),
                        ("manifest root descriptor close", close_error),
                    )
                )
                assert selected is not None
                selected = _settle_directory_descriptor_owners(
                    root_fd_slots,
                    selected,
                )
                for slot in root_fd_slots:
                    if slot.state != "closed":
                        _attach_directory_descriptor_custody(selected, slot)
                raise selected
            raise
        selected = _settle_directory_descriptor_owners(
            build_descriptor_owners,
            error,
        )
        if selected is error:
            raise
        raise selected


def _same_entry(left: Identity, right: Identity, *, directory: bool) -> bool:
    if directory:
        return directory_identities_match(left, right)
    return left == right


def _leaf_observation_failure(
    *,
    stage: str,
    missing: bool,
) -> CustodyLostError:
    state = "missing" if missing else "unreadable"
    return CustodyLostError(
        f"targeted cleanup leaf policy revalidation is {state} {stage}"
    )


def _require_leaf_snapshot_matches(
    observed: LeafSnapshot,
    expected: LeafAccessPolicyBinding,
    *,
    expected_link_count: int,
    stage: str,
    identity_error: str | None = None,
) -> None:
    if observed.policy.object_key != expected.object_key:
        raise CustodyLostError(
            identity_error or f"targeted cleanup leaf object identity mismatch {stage}"
        )
    if observed.policy.content_key != expected.content_key:
        raise CustodyLostError(
            f"targeted cleanup leaf content stability changed {stage}"
        )
    if observed.policy.access_policy_key != expected.access_policy_key:
        raise CustodyLostError(f"targeted cleanup leaf access policy drift {stage}")
    if observed.link_count != expected_link_count:
        raise CustodyLostError(f"targeted cleanup leaf link count mismatch {stage}")


def _require_leaf_identity_matches(
    observed: LeafSnapshot,
    expected: Identity,
    *,
    stage: str,
) -> None:
    expected_object_key = (
        expected.device,
        expected.inode,
        stat.S_IFMT(expected.mode),
    )
    if observed.policy.object_key[:3] != expected_object_key:
        raise CustodyLostError(
            f"targeted cleanup leaf object identity mismatch {stage}"
        )
    if observed.policy.size != expected.size:
        raise CustodyLostError(
            f"targeted cleanup leaf content stability changed {stage}"
        )
    if observed.policy.uid != expected.uid or observed.policy.mode != stat.S_IMODE(
        expected.mode
    ):
        raise CustodyLostError(f"targeted cleanup leaf access policy drift {stage}")
    if expected.link_count != 1 or observed.link_count != 1:
        raise CustodyLostError(f"targeted cleanup leaf link count mismatch {stage}")


def _require_leaf_stat_matches_binding(
    metadata: os.stat_result,
    expected: LeafAccessPolicyBinding,
    *,
    expected_link_count: int,
    stage: str,
    identity_error: str | None = None,
) -> None:
    observed = _leaf_snapshot_from_stat(
        metadata,
        metadata_state=expected.metadata_state,
        metadata_sha256=expected.metadata_sha256,
        content_state=expected.content_state,
        content_sha256=expected.content_sha256,
    )
    _require_leaf_snapshot_matches(
        observed,
        expected,
        expected_link_count=expected_link_count,
        stage=stage,
        identity_error=identity_error,
    )


def _observe_leaf_policy_fd(
    descriptor: int,
    *,
    stage: str,
    deadline: float,
) -> LeafSnapshot:
    try:
        metadata_before = os.fstat(descriptor)
    except OSError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=error.errno == errno.EBADF,
        ) from error
    try:
        metadata_state, metadata_sha256 = inspect_macos_leaf_metadata_digest(descriptor)
    except OSError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=error.errno == errno.EBADF,
        ) from error
    except ValueError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=False,
        ) from error
    try:
        content_state, content_sha256 = inspect_leaf_content_digest(
            descriptor,
            deadline=deadline,
        )
    except LeafContentDeadlineExpired:
        raise
    except OSError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=False,
        ) from error
    except ValueError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=False,
        ) from error
    try:
        metadata_after = os.fstat(descriptor)
    except OSError as error:
        raise _leaf_observation_failure(
            stage=stage,
            missing=error.errno == errno.EBADF,
        ) from error
    before = _leaf_snapshot_from_stat(
        metadata_before,
        metadata_state=metadata_state,
        metadata_sha256=metadata_sha256,
        content_state=content_state,
        content_sha256=content_sha256,
    )
    after = _leaf_snapshot_from_stat(
        metadata_after,
        metadata_state=metadata_state,
        metadata_sha256=metadata_sha256,
        content_state=content_state,
        content_sha256=content_sha256,
    )
    _require_leaf_snapshot_matches(
        after,
        before.policy,
        expected_link_count=before.link_count,
        stage=f"during {stage}",
    )
    return after


class _LeafDescriptorCustodyOwner:
    """Long-lived one-shot custody for a manifest leaf descriptor.

    ``close-outcome-unproven`` is terminal. Once close is armed, an exception
    can mean either that the syscall did not run or that the kernel closed the
    descriptor before Python observed the return. Retrying that integer could
    therefore close an unrelated descriptor after descriptor-number reuse.
    """

    __slots__ = ("_descriptor", "_state", "close_error")

    def __init__(self) -> None:
        self._descriptor: int | None = None
        self._state = "empty"
        self.close_error: BaseException | None = None

    @property
    def descriptor(self) -> int | None:
        return self._descriptor

    @property
    def state(self) -> str:
        return self._state

    def publish(self, descriptor: int) -> None:
        if self._state != "empty" or self._descriptor is not None:
            raise ValueError("leaf descriptor custody owner is already used")
        if type(descriptor) is not int or descriptor < 0:
            raise ValueError("leaf descriptor custody result is invalid")
        self._descriptor = descriptor
        self._state = "owned"

    def close(self) -> None:
        if self._state in {"closed", "close-outcome-unproven"}:
            return
        if self._state == "empty":
            self._state = "closed"
            return
        if self._state != "owned" or self._descriptor is None:
            raise RuntimeError("leaf descriptor custody has an invalid close state")

        descriptor = self._descriptor
        try:
            # Publish ambiguity before the call. A supported interruption at
            # either the pre-call or post-call bytecode boundary must not cause
            # a second close attempt on this integer.
            self._state = "close-outcome-unproven"
            os.close(descriptor)
            self._descriptor = None
            self._state = "closed"
            self.close_error = None
        except BaseException as error:
            self.close_error = error
            _attach_leaf_descriptor_custody(error, self)
            raise


def _attach_leaf_descriptor_custody(
    error: BaseException,
    owner: _LeafDescriptorCustodyOwner,
) -> None:
    attached = getattr(error, _LEAF_DESCRIPTOR_CUSTODY_ATTR, ())
    if not isinstance(attached, tuple) or not all(
        isinstance(item, _LeafDescriptorCustodyOwner) for item in attached
    ):
        attached = ()
    if owner not in attached:
        try:
            setattr(error, _LEAF_DESCRIPTOR_CUSTODY_ATTR, (*attached, owner))
        except BaseException:  # noqa: BLE001 - evidence cannot replace failure
            return
    try:
        error.add_note(
            "leaf descriptor custody recovery: "
            f"state={owner.state}, descriptor={owner.descriptor}"
        )
    except BaseException:  # noqa: BLE001,S110 - notes cannot replace failure
        pass


def leaf_descriptor_custody_owners(
    error: BaseException,
) -> tuple[_LeafDescriptorCustodyOwner, ...]:
    collected: list[_LeafDescriptorCustodyOwner] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        attached = getattr(current, _LEAF_DESCRIPTOR_CUSTODY_ATTR, ())
        if isinstance(attached, tuple):
            for owner in attached:
                if (
                    isinstance(owner, _LeafDescriptorCustodyOwner)
                    and owner not in collected
                ):
                    collected.append(owner)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return tuple(collected)


@dataclass(slots=True)
class _LeafPolicyResultOwner:
    binding: LeafAccessPolicyBinding | None = None

    def publish(self, binding: LeafAccessPolicyBinding) -> None:
        if self.binding is not None:
            raise ValueError("leaf policy result was published more than once")
        self.binding = binding


def _open_leaf_descriptor(
    directory_fd: int,
    name: bytes,
    expected: Identity,
    *,
    owner: _LeafDescriptorCustodyOwner,
    deadline: float,
    expected_policy: LeafAccessPolicyBinding | None = None,
    policy_result_owner: _LeafPolicyResultOwner | None = None,
) -> int:
    if owner.state != "empty":
        raise ValueError("leaf descriptor publication owner is already used")
    path_only = getattr(os, "O_PATH", 0)
    if stat.S_ISREG(expected.mode):
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    elif stat.S_ISLNK(expected.mode) and path_only:
        flags = path_only | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    elif stat.S_ISLNK(expected.mode):
        symlink_only = getattr(os, "O_SYMLINK", 0)
        if not symlink_only:
            raise CustodyLostError(
                "targeted cleanup cannot bind a symlink leaf descriptor"
            )
        flags = (
            symlink_only
            | getattr(os, "O_EVTONLY", os.O_RDONLY)
            | os.O_NONBLOCK
            | os.O_CLOEXEC
        )
    elif path_only:
        flags = path_only | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    else:
        flags = (
            getattr(os, "O_EVTONLY", os.O_RDONLY)
            | os.O_NONBLOCK
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
        )
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise _leaf_observation_failure(
            stage="while opening its descriptor",
            missing=error.errno == errno.ENOENT,
        ) from error
    # The caller enters the supported critical section before this function.
    # Publish the sole resource-bearing value before fstat or companion
    # validation so no supported live-FD interruption can precede custody.
    owner.publish(descriptor)
    observed = _observe_leaf_policy_fd(
        descriptor,
        stage="while opening its descriptor",
        deadline=deadline,
    )
    if expected_policy is None:
        _require_leaf_identity_matches(
            observed,
            expected,
            stage="while opening its descriptor",
        )
    else:
        if not _leaf_policy_matches_identity(expected_policy, expected):
            raise ValueError("leaf descriptor policy and identity disagree")
        _require_leaf_snapshot_matches(
            observed,
            expected_policy,
            expected_link_count=1,
            stage="while opening its descriptor",
        )
    if policy_result_owner is not None:
        policy_result_owner.publish(observed.policy)
    return descriptor


def _quarantine_leaf(
    directory_fd: int,
    name: bytes,
    *,
    deadline: float,
) -> bytes:
    for _ in range(_QUARANTINE_NAME_ATTEMPTS):
        if time.monotonic() >= deadline:
            raise TimeoutError("targeted cleanup monotonic deadline expired")
        quarantine_name = _LEAF_QUARANTINE_PREFIX + secrets.token_hex(16).encode(
            "ascii"
        )
        try:
            rename_noreplace(
                directory_fd,
                name,
                directory_fd,
                quarantine_name,
            )
        except OSError as error:
            if error.errno == errno.EEXIST:
                continue
            raise
        return quarantine_name
    raise FileExistsError("cannot allocate a fresh leaf cleanup quarantine name")


def _unlink_quarantined_leaf_critical(
    *,
    directory_fd: int,
    original_name: bytes,
    quarantine_name: bytes,
    descriptor: int,
    expected: Identity,
    expected_policy: LeafAccessPolicyBinding,
    deadline: float,
) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("targeted cleanup monotonic deadline expired")
    if not _leaf_policy_matches_identity(expected_policy, expected):
        raise ValueError("leaf unlink policy and identity disagree")
    descriptor_policy = _observe_leaf_policy_fd(
        descriptor,
        stage="after quarantine rename and before unlink",
        deadline=deadline,
    )
    _require_leaf_snapshot_matches(
        descriptor_policy,
        expected_policy,
        expected_link_count=1,
        stage="after quarantine rename and before unlink",
    )
    try:
        quarantine_metadata = os.stat(
            quarantine_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as error:
        raise CustodyLostError(
            "targeted cleanup quarantined leaf is missing before unlink"
        ) from error
    except OSError as error:
        raise CustodyLostError(
            "targeted cleanup quarantined leaf is unreadable before unlink"
        ) from error
    _require_leaf_stat_matches_binding(
        quarantine_metadata,
        expected_policy,
        expected_link_count=1,
        stage="at its quarantine name before unlink",
        identity_error=(
            "targeted cleanup quarantined leaf identity changed before unlink: "
            "object identity mismatch"
        ),
    )
    _require_name_absent(
        parent_fd=directory_fd,
        name=original_name,
        error=(
            "targeted cleanup leaf public name was replaced before unlink; "
            "original quarantine and replacement retained"
        ),
    )

    if time.monotonic() >= deadline:
        raise TimeoutError(
            "targeted cleanup deadline expired before leaf unlink; "
            "original quarantine retained"
        )
    os.unlink(quarantine_name, dir_fd=directory_fd)

    unlinked_policy = _observe_leaf_policy_fd(
        descriptor,
        stage="after unlink",
        deadline=deadline,
    )
    _require_leaf_snapshot_matches(
        unlinked_policy,
        expected_policy,
        expected_link_count=unlinked_policy.link_count,
        stage="after unlink",
    )
    if unlinked_policy.link_count != 0:
        raise CustodyLostError(
            "targeted cleanup exact leaf deletion is unproven; a link remains"
        )
    _require_name_absent(
        parent_fd=directory_fd,
        name=quarantine_name,
        error="targeted cleanup leaf quarantine name remains after unlink",
    )
    _require_name_absent(
        parent_fd=directory_fd,
        name=original_name,
        error=(
            "targeted cleanup leaf public name was replaced during unlink; "
            "replacement retained"
        ),
    )
    os.fsync(directory_fd)


def _add_leaf_cleanup_error_note(
    primary: BaseException,
    operation: str,
    secondary: BaseException,
) -> None:
    try:
        primary.add_note(
            f"{operation} also failed with {type(secondary).__name__}: {secondary}"
        )
    except BaseException:  # noqa: BLE001 - notes cannot replace cleanup failures
        return


def _select_leaf_cleanup_error(
    errors: Sequence[tuple[str, BaseException]],
) -> BaseException | None:
    if not errors:
        return None
    primary_index = next(
        (
            index
            for index, (_, error) in enumerate(errors)
            if not isinstance(error, Exception)
        ),
        0,
    )
    primary = errors[primary_index][1]
    for index, (operation, secondary) in enumerate(errors):
        if index != primary_index:
            _add_leaf_cleanup_error_note(primary, operation, secondary)
    return primary


class _LeafCleanupErrorOwner:
    """Publish cleanup errors under first/control-flow priority."""

    __slots__ = ("_authoritative_error", "_errors")

    def __init__(self) -> None:
        self._authoritative_error: BaseException | None = None
        self._errors: tuple[tuple[str, BaseException], ...] = ()

    @property
    def authoritative_error(self) -> BaseException | None:
        return self._authoritative_error

    @property
    def errors(self) -> tuple[tuple[str, BaseException], ...]:
        return self._errors

    def capture(self, operation: str, error: BaseException) -> None:
        if not isinstance(operation, str) or not operation:
            raise ValueError("leaf cleanup error operation is invalid")
        if not isinstance(error, BaseException):
            raise TypeError("leaf cleanup error must be a BaseException")

        previous_errors = self._errors
        self._errors = (*previous_errors, (operation, error))
        primary = self._authoritative_error
        if primary is None:
            self._authoritative_error = error
            return
        if isinstance(primary, Exception) and not isinstance(error, Exception):
            # A control-flow BaseException outranks all ordinary failures. The
            # first control-flow object still wins over later control flow.
            self._authoritative_error = error
            for previous_operation, previous_error in previous_errors:
                _add_leaf_cleanup_error_note(
                    error,
                    previous_operation,
                    previous_error,
                )
            return
        _add_leaf_cleanup_error_note(primary, operation, error)

    def raise_authoritative(self) -> None:
        error = self._authoritative_error
        if error is not None:
            raise error


class _LeafDescriptorCloseSettlement:
    """Close one long-lived leaf owner without retrying ambiguous outcomes."""

    __slots__ = ("error_owner", "owner")

    def __init__(
        self,
        owner: _LeafDescriptorCustodyOwner,
        error_owner: _LeafCleanupErrorOwner,
    ) -> None:
        self.owner = owner
        self.error_owner = error_owner

    def settle(self) -> None:
        while True:
            state = self.owner.state
            if state in {"closed", "close-outcome-unproven"}:
                return
            if state not in {"empty", "owned"}:
                raise RuntimeError(
                    "leaf descriptor custody has an invalid settlement state"
                )
            try:
                self.owner.close()
            except BaseException as error:  # noqa: BLE001 - close custody
                # Owner.close publishes ambiguity before os.close. Retrying
                # this loop is therefore possible only when method entry was
                # interrupted while the owner was still unambiguously owned.
                _attach_leaf_descriptor_custody(error, self.owner)
                self.error_owner.capture("leaf descriptor close attempt", error)


class _LeafCleanupDeliveryOwner:
    """Long-lived state for settlement and authoritative error delivery."""

    __slots__ = (
        "_armed_error",
        "_complete",
        "_pending_errors",
        "_raise_in_progress",
        "descriptor_owner",
        "error_owner",
        "settlement",
    )

    def __init__(
        self,
        descriptor_owner: _LeafDescriptorCustodyOwner,
        error_owner: _LeafCleanupErrorOwner,
        settlement: _LeafDescriptorCloseSettlement,
    ) -> None:
        self.descriptor_owner = descriptor_owner
        self.error_owner = error_owner
        self.settlement = settlement
        self._pending_errors: tuple[tuple[str, BaseException], ...] = ()
        self._armed_error: BaseException | None = None
        self._raise_in_progress = False
        self._complete = False

    def enqueue(self, operation: str, error: BaseException) -> None:
        self._pending_errors = (*self._pending_errors, (operation, error))
        self._armed_error = None
        self._raise_in_progress = False
        self._complete = False

    def step(self) -> None:
        # This local deliberately remains in the callee. The caller owns the
        # entire method boundary, including trace delivery at this STORE and at
        # a nested property's successful RETURN endpoint.
        authoritative: BaseException | None = None
        self._armed_error = None
        self._raise_in_progress = False

        if self.descriptor_owner.state in {"empty", "owned"}:
            self.settlement.settle()
            return
        if self._pending_errors:
            operation, pending_error = self._pending_errors[0]
            _attach_leaf_descriptor_custody(
                pending_error,
                self.descriptor_owner,
            )
            self.error_owner.capture(operation, pending_error)
            self._pending_errors = self._pending_errors[1:]
            return

        authoritative = self.error_owner.authoritative_error
        if authoritative is None:
            self._complete = True
            return
        _attach_leaf_descriptor_custody(authoritative, self.descriptor_owner)
        self._armed_error = authoritative
        self._raise_in_progress = True
        self.error_owner.raise_authoritative()


def _drive_leaf_cleanup_delivery(owner: _LeafCleanupDeliveryOwner) -> None:
    """Run delivery steps under a caller boundary owned by ``owner``."""

    while not owner._complete:
        try:
            owner.step()
        except BaseException as delivery_error:
            if owner._raise_in_progress and delivery_error is owner._armed_error:
                # The registered root-result owner survives this armed
                # re-raise and every caller boundary above it. A hook at this
                # opcode therefore becomes another owner-bound pending error,
                # not the result.
                raise
            owner.enqueue(
                "leaf cleanup owner-bound delivery boundary",
                delivery_error,
            )


class _SupportedLeafDeletionCriticalSection:
    """Suppress supported current-thread insertion across leaf custody work.

    The caller has already proven child/process closure. This boundary covers
    current-thread trace/profile callbacks plus SIGHUP, SIGINT, SIGQUIT, and
    SIGTERM. It does not promise unlink-by-inode semantics, resist another
    writable thread/process, or suppress unsupported asynchronous exceptions.
    """

    def __init__(
        self,
        error_owner: _LeafCleanupErrorOwner,
        *,
        defer_delivery: bool = False,
    ) -> None:
        if not isinstance(error_owner, _LeafCleanupErrorOwner):
            raise TypeError("leaf critical section requires an error owner")
        self._error_owner = error_owner
        self._defer_delivery = defer_delivery
        self._previous_trace: Any = None
        self._previous_profile: Any = None
        self._previous_mask: set[signal.Signals] | None = None
        self._pthread_sigmask: Callable[..., object] | None = None
        self._trace_restore_required = False
        self._profile_restore_required = False
        self._mask_restore_required = False
        self._signal_scope: DeferredSignalScope | None = None
        self._entered = False

    def __enter__(self) -> _SupportedLeafDeletionCriticalSection:
        if self._entered:
            raise RuntimeError("leaf deletion critical section is not reusable")
        pthread_sigmask = getattr(signal, "pthread_sigmask", None)
        if not callable(pthread_sigmask):
            raise CustodyLostError(
                "targeted cleanup leaf critical section requires pthread_sigmask"
            )

        self._previous_trace = sys.gettrace()
        self._previous_profile = sys.getprofile()
        self._previous_mask = set(pthread_sigmask(signal.SIG_BLOCK, ()))
        self._pthread_sigmask = pthread_sigmask
        try:
            self._trace_restore_required = True
            sys.settrace(None)
            self._profile_restore_required = True
            sys.setprofile(None)
            self._mask_restore_required = True
            pthread_sigmask(signal.SIG_BLOCK, _LEAF_DELETION_SIGNALS)
            active_mask = set(pthread_sigmask(signal.SIG_BLOCK, ()))
            if not set(_LEAF_DELETION_SIGNALS).issubset(active_mask):
                raise CustodyLostError(
                    "targeted cleanup leaf signal mask could not be established"
                )
            self._signal_scope = begin_bound_signal_deferral()
            if sys.gettrace() is not None or sys.getprofile() is not None:
                raise CustodyLostError(
                    "targeted cleanup leaf instrumentation remained active"
                )
        except BaseException as error:
            self._restore(error)
            authoritative = self._error_owner._authoritative_error
            if authoritative is error:
                raise
            assert authoritative is not None
            raise authoritative

        self._entered = True
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        error: BaseException | None,
        _traceback: object,
    ) -> bool:
        try:
            self._restore(error)
        finally:
            self._entered = False
        if self._defer_delivery:
            return error is not None
        authoritative = self._error_owner._authoritative_error
        if authoritative is error and error is not None:
            return False
        if authoritative is not None:
            raise authoritative
        return False

    def _restore(self, active_error: BaseException | None) -> None:
        # Publish the active body error before any signal is unmasked or any
        # user hook is restored. A later delivery-boundary callback can then be
        # merged by the caller without replacing the body failure.
        if active_error is not None:
            self._error_owner.capture(
                "leaf deletion critical body",
                active_error,
            )

        # Restore the mask while both Python hooks remain disabled. A signal
        # delivered by unmasking is still delayed by the bound scope.
        if self._mask_restore_required:
            self._mask_restore_required = False
            try:
                if self._pthread_sigmask is None or self._previous_mask is None:
                    raise RuntimeError(
                        "targeted cleanup leaf signal-mask state is unavailable"
                    )
                self._pthread_sigmask(signal.SIG_SETMASK, self._previous_mask)
            except BaseException as error:  # noqa: BLE001 - restoration boundary
                self._error_owner.capture("leaf signal-mask restoration", error)

        signal_scope = self._signal_scope
        self._signal_scope = None
        if signal_scope is not None:
            try:
                signal_scope.finish(deliver=False)
            except BaseException as error:  # noqa: BLE001 - restoration boundary
                self._error_owner.capture(
                    "leaf bound-signal-scope restoration",
                    error,
                )

        if self._profile_restore_required:
            self._profile_restore_required = False
            try:
                sys.setprofile(self._previous_profile)
            except BaseException as error:  # noqa: BLE001 - restore user hook
                self._error_owner.capture("leaf profile-hook restoration", error)

        if self._trace_restore_required:
            self._trace_restore_required = False
            try:
                sys.settrace(self._previous_trace)
            except BaseException as error:  # noqa: BLE001 - restore user hook
                self._error_owner.capture("leaf trace-hook restoration", error)
                try:
                    sys.settrace(self._previous_trace)
                except BaseException as retry:  # noqa: BLE001 - bounded retry
                    self._error_owner.capture(
                        "leaf trace-hook restoration retry",
                        retry,
                    )

        # This call intentionally remains outside an in-section selector. If a
        # restored hook or an owned signal raises at delivery, the caller's
        # long-lived error owner already contains every earlier failure.
        checkpoint_bound_signal_interrupt()


def _capture_manifest_leaf_policy(
    *,
    directory_fd: int,
    name: bytes,
    expected: Identity,
    path_metadata: os.stat_result,
    deadline: float,
    delivery_owner: _LeafCleanupDeliveryOwner,
    policy_result_owner: _LeafPolicyResultOwner,
) -> None:
    """Bind one manifest leaf without exposing a live descriptor to its caller."""

    descriptor_owner = delivery_owner.descriptor_owner
    error_owner = delivery_owner.error_owner
    settlement = delivery_owner.settlement
    try:
        with _SupportedLeafDeletionCriticalSection(
            error_owner,
            defer_delivery=True,
        ):
            try:
                _open_leaf_descriptor(
                    directory_fd,
                    name,
                    expected,
                    owner=descriptor_owner,
                    deadline=deadline,
                    policy_result_owner=policy_result_owner,
                )
                binding = policy_result_owner.binding
                if binding is None:
                    raise CustodyLostError(
                        "targeted cleanup leaf policy result was not published"
                    )
                _require_leaf_stat_matches_binding(
                    path_metadata,
                    binding,
                    expected_link_count=1,
                    stage="during manifest construction",
                )
            except BaseException as active_error:  # noqa: BLE001 - live custody
                error_owner.capture(
                    "manifest leaf policy binding transaction",
                    active_error,
                )
            finally:
                settlement.settle()
                if descriptor_owner.state not in {
                    "closed",
                    "close-outcome-unproven",
                }:
                    error_owner.capture(
                        "manifest leaf descriptor terminal-state publication",
                        CustodyLostError(
                            "targeted cleanup manifest leaf descriptor was not settled"
                        ),
                    )
                authoritative = error_owner._authoritative_error
                if authoritative is not None:
                    _attach_leaf_descriptor_custody(
                        authoritative,
                        descriptor_owner,
                    )
    except BaseException as publication_error:  # noqa: BLE001 - restored boundary
        delivery_owner.enqueue(
            "manifest leaf critical-section restoration boundary",
            publication_error,
        )


def _delete_manifest_leaf(
    *,
    directory_fd: int,
    name: bytes,
    expected: Identity,
    expected_policy: LeafAccessPolicyBinding | None = None,
    deadline: float,
    delivery_owner: _LeafCleanupDeliveryOwner,
) -> None:
    descriptor_owner = delivery_owner.descriptor_owner
    error_owner = delivery_owner.error_owner
    settlement = delivery_owner.settlement
    policy_result_owner = _LeafPolicyResultOwner()
    try:
        with _SupportedLeafDeletionCriticalSection(
            error_owner,
            defer_delivery=True,
        ):
            try:
                descriptor = _open_leaf_descriptor(
                    directory_fd,
                    name,
                    expected,
                    owner=descriptor_owner,
                    deadline=deadline,
                    expected_policy=expected_policy,
                    policy_result_owner=policy_result_owner,
                )
                active_policy = (
                    expected_policy
                    if expected_policy is not None
                    else policy_result_owner.binding
                )
                if active_policy is None:
                    raise CustodyLostError(
                        "targeted cleanup leaf policy result was not published"
                    )
                quarantine_name = _quarantine_leaf(
                    directory_fd,
                    name,
                    deadline=deadline,
                )
                try:
                    _unlink_quarantined_leaf_critical(
                        directory_fd=directory_fd,
                        original_name=name,
                        quarantine_name=quarantine_name,
                        descriptor=descriptor,
                        expected=expected,
                        expected_policy=active_policy,
                        deadline=deadline,
                    )
                except BaseException as error:  # noqa: BLE001 - control flow
                    error_owner.capture("leaf exact unlink", error)
            except BaseException as active_error:  # noqa: BLE001 - live custody
                error_owner.capture(
                    "leaf deletion live-descriptor transaction",
                    active_error,
                )
            finally:
                settlement.settle()
                if descriptor_owner.state not in {
                    "closed",
                    "close-outcome-unproven",
                }:
                    error_owner.capture(
                        "leaf descriptor terminal-state publication",
                        CustodyLostError(
                            "targeted cleanup leaf descriptor was not settled"
                        ),
                    )
                authoritative = error_owner._authoritative_error
                if authoritative is not None:
                    _attach_leaf_descriptor_custody(
                        authoritative,
                        descriptor_owner,
                    )
    except BaseException as publication_error:  # noqa: BLE001 - restored boundary
        # Descriptor custody is already terminal before hooks/signals restore.
        # The caller-precreated owner survives this handler and the function's
        # final RETURN boundary, so the caller can re-arbitrate either delivery.
        delivery_owner.enqueue(
            "leaf critical-section restoration boundary",
            publication_error,
        )


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
    deletion_owner: CustodiedDeletionResultOwner,
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
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as error:
                raise CustodyLostError(
                    "targeted cleanup manifest entry is missing before deletion"
                ) from error
            except OSError as error:
                raise CustodyLostError(
                    "targeted cleanup manifest entry is unreadable before deletion"
                ) from error
            directory = record.kind == _KIND_DIRECTORY
            if directory:
                if not _same_entry(
                    identity_from_stat(metadata),
                    record.identity,
                    directory=True,
                ):
                    raise CustodyLostError(
                        "targeted cleanup directory identity changed"
                    )
            else:
                _validate_manifest_leaf_policy(record)
                assert record.leaf_policy is not None
                _require_leaf_stat_matches_binding(
                    metadata,
                    record.leaf_policy,
                    expected_link_count=1,
                    stage="before descriptor open",
                )
            relative = name if not prefix else prefix + b"/" + name
            if directory:
                child_owner = _CustodiedManifestDescriptorSlot(
                    purpose=f"recursive-delete:{relative.hex()}",
                    expected_identity=record.identity,
                )
                deletion_owner.register_directory_cleanup(child_owner)
                try:
                    child_fd = _open_custodied_directory_descriptor(
                        child_owner,
                        name,
                        directory_fd=directory_fd,
                    )
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
                        deletion_owner=deletion_owner,
                    )
                except BaseException as error:
                    selected = _settle_directory_descriptor_owner(
                        child_owner,
                        error,
                    )
                    if selected is error:
                        raise
                    assert selected is not None
                    raise selected
                else:
                    selected = _settle_directory_descriptor_owner(child_owner)
                    if selected is not None:
                        raise selected
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
                descriptor_owner = _LeafDescriptorCustodyOwner()
                error_owner = _LeafCleanupErrorOwner()
                settlement = _LeafDescriptorCloseSettlement(
                    descriptor_owner,
                    error_owner,
                )
                delivery_owner = _LeafCleanupDeliveryOwner(
                    descriptor_owner,
                    error_owner,
                    settlement,
                )
                deletion_owner.register_leaf_cleanup(delivery_owner)
                try:
                    _delete_manifest_leaf(
                        directory_fd=directory_fd,
                        name=name,
                        expected=record.identity,
                        expected_policy=record.leaf_policy,
                        deadline=budget.deadline,
                        delivery_owner=delivery_owner,
                    )
                except BaseException as leaf_boundary:  # noqa: BLE001 - handoff
                    delivery_owner.enqueue(
                        "leaf function caller boundary",
                        leaf_boundary,
                    )
                while True:
                    try:
                        _drive_leaf_cleanup_delivery(delivery_owner)
                    except BaseException as caller_error:
                        if (
                            delivery_owner._raise_in_progress
                            and caller_error is delivery_owner._armed_error
                        ):
                            raise
                        delivery_owner.enqueue(
                            "leaf recursive-caller delivery boundary",
                            caller_error,
                        )
                    else:
                        break
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


def _reconcile_registered_leaf_cleanup(
    deletion_owner: CustodiedDeletionResultOwner,
    boundary_error: BaseException,
) -> BaseException:
    if not deletion_owner.leaf_cleanup_owners:
        return boundary_error
    owner = deletion_owner.leaf_cleanup_owners[-1]
    if owner._complete and owner.error_owner._authoritative_error is None:
        return boundary_error
    owner.enqueue("leaf root-owner delivery boundary", boundary_error)
    while True:
        try:
            _drive_leaf_cleanup_delivery(owner)
        except BaseException as delivery_error:  # noqa: BLE001 - root handoff
            if owner._raise_in_progress and delivery_error is owner._armed_error:
                return delivery_error
            owner.enqueue(
                "leaf root-owner reconciliation boundary",
                delivery_error,
            )
        else:
            authoritative = owner.error_owner._authoritative_error
            return boundary_error if authoritative is None else authoritative


def _reconcile_registered_directory_cleanup(
    deletion_owner: CustodiedDeletionResultOwner,
    boundary_error: BaseException,
) -> BaseException:
    # Complete the same reentrant prepublication before registry settlement.
    prepublication_errors: list[tuple[str, BaseException]] = [
        ("custodied deletion boundary", boundary_error)
    ]
    while True:
        try:
            prepublished_owners = _relevant_directory_descriptor_custody_owners(
                deletion_owner.directory_cleanup_owners
            )
            _attach_directory_descriptor_custody_owners(
                boundary_error,
                prepublished_owners,
            )
            selected = _select_leaf_cleanup_error(prepublication_errors)
            assert selected is not None
            _attach_directory_descriptor_custody_owners(
                selected,
                prepublished_owners,
            )
        except BaseException as publication_error:
            prepublication_errors.append(
                (
                    "directory deletion pre-settlement publication",
                    publication_error,
                )
            )
            continue
        break
    for owner in reversed(deletion_owner.directory_cleanup_owners):
        if owner.state == "closed":
            continue
        if owner.state in {"empty", "owned"}:
            candidate = _settle_directory_descriptor_owner(owner, selected)
            if candidate is not None:
                selected = candidate
        else:
            _attach_directory_descriptor_custody(selected, owner)
            if owner.close_error is not None and owner.close_error is not selected:
                candidate = _select_leaf_cleanup_error(
                    (
                        ("custodied deletion boundary", selected),
                        ("directory descriptor close", owner.close_error),
                    )
                )
                if candidate is not None:
                    selected = candidate
    final_publication_errors: list[tuple[str, BaseException]] = [
        ("directory deletion settlement", selected)
    ]
    while True:
        try:
            final_selected = _select_leaf_cleanup_error(final_publication_errors)
            assert final_selected is not None
            for owner in prepublished_owners:
                _attach_directory_descriptor_custody(final_selected, owner)
            _attach_directory_descriptor_custody_owners(
                final_selected,
                deletion_owner.directory_cleanup_owners,
            )
        except BaseException as publication_error:
            final_publication_errors.append(
                (
                    "directory deletion terminal publication",
                    publication_error,
                )
            )
            continue
        selected = final_selected
        break
    return selected


def _capture_custodied_deletion_error_tree(
    deletion_owner: CustodiedDeletionResultOwner,
    operation: str,
    error: BaseException,
) -> None:
    traversal: list[BaseException] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        traversal.append(current)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    # The selected/root error is the already-arbitrated primary among ordinary
    # failures. Earlier implicit context is still captured afterwards so a
    # control-flow BaseException can outrank it, while an explicit diagnostic
    # cause cannot replace the selected ordinary failure.
    for candidate in traversal:
        deletion_owner.capture_delivery_error(operation, candidate)


def _settle_custodied_deletion_boundary(
    deletion_owner: CustodiedDeletionResultOwner,
    boundary_error: BaseException,
) -> BaseException:
    selected = _reconcile_registered_directory_cleanup(
        deletion_owner,
        boundary_error,
    )
    selected = _reconcile_registered_leaf_cleanup(deletion_owner, selected)
    _capture_custodied_deletion_error_tree(
        deletion_owner,
        "custodied deletion descriptor reconciliation",
        selected,
    )
    if selected is not boundary_error:
        _capture_custodied_deletion_error_tree(
            deletion_owner,
            "custodied deletion caller boundary",
            boundary_error,
        )
    authoritative = deletion_owner.authoritative_delivery_error
    if authoritative is None:
        authoritative = selected
        deletion_owner.capture_delivery_error(
            "custodied deletion authoritative fallback",
            authoritative,
        )
    setattr(authoritative, _DELETION_RESULT_OWNER_ATTR, deletion_owner)
    return authoritative


def _delete_custodied_roots_operation(
    manifest: CustodiedManifest,
    *,
    deadline: float | None,
    deletion_owner: CustodiedDeletionResultOwner,
) -> dict[str, Any]:
    """Run deletion beneath the public function's one caller-owned boundary."""

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
                    deletion_owner=deletion_owner,
                )
                stage = "post-recursion-deadline"
                budget.check()
            except BaseException as error:
                selected = _reconcile_registered_leaf_cleanup(
                    deletion_owner,
                    error,
                )
                _attach_quarantined_root_recovery(
                    selected,
                    _quarantined_root_evidence(
                        spec,
                        root_fd,
                        quarantine_name,
                        stage=stage,
                    ),
                )
                if selected is error:
                    raise
                raise selected
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
        selected = _settle_custodied_deletion_boundary(deletion_owner, error)
        if selected is error:
            raise
        raise selected


def delete_custodied_roots(
    manifest: CustodiedManifest,
    *,
    deadline: float | None = None,
    result_owner: CustodiedDeletionResultOwner | None = None,
) -> dict[str, Any]:
    """Delete custodied roots with a caller-recoverable result/error owner.

    ``manifest.deletion_result_owner`` is published before destructive work so
    the proof remains reachable if a profile callback interrupts this function's
    successful RETURN. This frame is the single caller boundary for operation
    handler callbacks; its own terminal delivery remains caller-owned because a
    Python frame cannot cover its final opcode with its own exception table.
    """

    deletion_owner = (
        result_owner if result_owner is not None else CustodiedDeletionResultOwner()
    )
    manifest.bind_deletion_result_owner(deletion_owner)
    try:
        return _delete_custodied_roots_operation(
            manifest,
            deadline=deadline,
            deletion_owner=deletion_owner,
        )
    except BaseException as boundary_error:
        selected = _settle_custodied_deletion_boundary(
            deletion_owner,
            boundary_error,
        )
        if selected is boundary_error:
            raise
        raise selected


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
