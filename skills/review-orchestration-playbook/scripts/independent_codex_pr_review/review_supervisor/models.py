from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    size: int

    def to_json(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class Artifact:
    name: str
    size: int
    sha256: str
    record_count: int | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HelperCustody:
    state_dir: str
    state_identity: Identity
    workspace_root: str
    source_path: str
    source_identity: Identity
    cleanup_lock_path: str
    cleanup_lock_identity: Identity
    review_range: str
    base_sha: str
    head_sha: str
    diff_length: int
    diff_sha256: str
    preflight_sha256: str
    control_state_sha256: str

    def to_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["state_identity"] = self.state_identity.to_json()
        value["source_identity"] = self.source_identity.to_json()
        value["cleanup_lock_identity"] = self.cleanup_lock_identity.to_json()
        return value


@dataclass(frozen=True)
class TreeEntry:
    mode: int
    object_type: str
    object_id: str
    size: int | None
    path: bytes

    @property
    def is_regular(self) -> bool:
        return self.mode in {0o100644, 0o100755}

    @property
    def is_symlink(self) -> bool:
        return self.mode == 0o120000

    @property
    def is_gitlink(self) -> bool:
        return self.mode == 0o160000


@dataclass(frozen=True)
class TreeManifest:
    commit: str
    entries: tuple[TreeEntry, ...]
    metadata_bytes: int
    aggregate_regular_bytes: int
    gitlink_count: int

    @property
    def entry_count(self) -> int:
        return len(self.entries)


@dataclass(frozen=True)
class FilesystemMeasure:
    identity: str
    device: int
    allocation_unit: int
    free_bytes: int

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Admission:
    retention_fs: FilesystemMeasure
    checkout_fs: FilesystemMeasure
    git_fs: FilesystemMeasure
    entry_count: int
    tree_metadata_bytes: int
    unique_parent_directory_count: int
    unique_parent_path_bytes: int
    gitlink_count: int
    checkout_base_bound_without_parents: int
    checkout_root_bound: int
    git_admin_bound: int
    checkout_accounting_bound: int
    review_diff_bound: int
    targeted_manifest_entry_bound: int
    targeted_manifest_payload_bound: int
    targeted_manifest_file_bound: int
    targeted_manifest_bound: int
    process_charge: int

    def to_json(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "retention_fs": self.retention_fs.to_json(),
            "checkout_fs": self.checkout_fs.to_json(),
            "git_fs": self.git_fs.to_json(),
        }
