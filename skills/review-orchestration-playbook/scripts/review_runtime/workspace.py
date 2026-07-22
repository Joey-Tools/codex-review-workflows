from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import io
import json
import math
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from bisect import bisect_left
from collections import Counter, deque
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Mapping

from .common import (
    TRUSTED_PATH,
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    is_relative_to,
    resolve_git,
    restore_signal_mask,
    symlink_target_stays_within_workspace,
    write_text_atomic,
)
from .prompt import build_review_prompt
from .synthetic_tokens import (
    AcceptedSyntheticValue,
    GENERIC_SECRET_VALUE_BYTE_CLASS,
    LegacyExemption,
    SyntheticTokenCatalog,
    accepted_authoring_values,
    accepted_legacy_values,
    load_catalog,
    resolve_legacy_exemptions,
)


# Provider patterns with variable-length bodies capture a complete value through 512
# bytes, then use a 513-byte prefix branch for oversized values. PEM candidates need
# a larger bounded window so a complete private-key block can be used as an identity;
# keeping every event end below the overlap preserves its start across read boundaries.
MAX_PEM_SECRET_BYTES = 32 * 1024
STREAM_SCAN_OVERLAP = 64 * 1024
STREAM_SCAN_CHUNK_BYTES = 1024 * 1024
AWS_SECRET_KEY_NAME_PATTERN = rb"(?i)aws_secret_access_key"
AWS_SECRET_KEY_PATTERN = re.compile(
    AWS_SECRET_KEY_NAME_PATTERN
    + rb"\s{0,256}[:=]\s{0,256}['\"]?"
    + rb"(?P<aws_secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
)
OVERSIZED_AWS_SECRET_KEY_GAP = re.compile(
    AWS_SECRET_KEY_NAME_PATTERN + rb"(?:\s{257}|\s{0,256}[:=]\s{257})"
)
OVERSIZED_JWT_PATTERN = re.compile(
    rb"\b(?:"
    rb"eyJ[A-Za-z0-9_-]{2049}"
    rb"|eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{2049}"
    rb"|eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{0,2048}\."
    rb"[A-Za-z0-9_-]{2049}"
    rb")"
)
JWE_CONTINUATION_PATTERN = re.compile(
    rb"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{0,2048}\."
    rb"[A-Za-z0-9_-]{0,2048}\."
)
# Complete shared-prefix rules must precede broader overlapping sentinel rules.
SECRET_PATTERNS = (
    (
        "aws-access-key",
        re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    ),
    (
        "aws-secret-key",
        AWS_SECRET_KEY_PATTERN,
    ),
    (
        "anthropic-key",
        re.compile(
            rb"\bsk-ant-(?:"
            rb"[A-Za-z0-9_-]{32,512}(?![A-Za-z0-9_-])|[A-Za-z0-9_-]{513})"
        ),
    ),
    (
        "openai-key",
        re.compile(
            rb"\bsk-(?:proj-)?(?:"
            rb"[A-Za-z0-9_-]{32,512}(?![A-Za-z0-9_-])|[A-Za-z0-9_-]{513})"
        ),
    ),
    (
        "github-token",
        re.compile(
            rb"\b(?:"
            rb"gh[pousr]_(?:"
            rb"[A-Za-z0-9]{36,512}(?![A-Za-z0-9])|[A-Za-z0-9]{513})"
            rb"|github_pat_(?:"
            rb"[A-Za-z0-9_]{20,512}(?![A-Za-z0-9_])|[A-Za-z0-9_]{513})"
            rb")"
        ),
    ),
    (
        "gitlab-token",
        re.compile(
            rb"\bglpat-(?:"
            rb"[A-Za-z0-9_-]{20,512}(?![A-Za-z0-9_-])|[A-Za-z0-9_-]{513})"
        ),
    ),
    (
        "google-api-key",
        re.compile(
            rb"\bAIza(?:"
            rb"[0-9A-Za-z_-]{35,512}(?![0-9A-Za-z_-])|[0-9A-Za-z_-]{513})"
        ),
    ),
    (
        "npm-token",
        re.compile(rb"\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    ),
    (
        "pypi-token",
        re.compile(
            rb"\bpypi-(?:"
            rb"[A-Za-z0-9_-]{50,512}(?![A-Za-z0-9_-])|[A-Za-z0-9_-]{513})"
        ),
    ),
    (
        "slack-token",
        re.compile(
            rb"\bxox[baprs]-(?:"
            rb"[A-Za-z0-9-]{20,512}(?![A-Za-z0-9-])|[A-Za-z0-9-]{513})"
        ),
    ),
    (
        "stripe-live-key",
        re.compile(
            rb"\bsk_live_(?:"
            rb"[A-Za-z0-9]{16,512}(?![A-Za-z0-9])|[A-Za-z0-9]{513})"
        ),
    ),
    (
        "jwt",
        re.compile(
            rb"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{0,2048}\."
            rb"[A-Za-z0-9_-]{0,2048}\.[A-Za-z0-9_-]{0,2048}\."
            rb"[A-Za-z0-9_-]{0,2048}(?![A-Za-z0-9_.-])"
        ),
    ),
    (
        "jwt",
        re.compile(
            rb"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\."
            rb"[A-Za-z0-9_-]{8,2048}(?![A-Za-z0-9_.-])"
        ),
    ),
)
SECRET_PATTERN_MARKERS: dict[str, tuple[bytes, ...]] = {
    "aws-access-key": (b"AKIA", b"ASIA"),
    "aws-secret-key": (b"aws_secret_access_key",),
    "anthropic-key": (b"sk-ant-",),
    "openai-key": (b"sk-",),
    "github-token": (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
    "gitlab-token": (b"glpat-",),
    "google-api-key": (b"AIza",),
    "npm-token": (b"npm_",),
    "pypi-token": (b"pypi-",),
    "slack-token": (b"xoxb-", b"xoxa-", b"xoxp-", b"xoxr-", b"xoxs-"),
    "stripe-live-key": (b"sk_live_",),
    "jwt": (b"eyJ",),
}
PEM_PRIVATE_KEY_LABEL_PATTERN = (
    rb"PGP PRIVATE KEY BLOCK|(?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
)
PEM_PRIVATE_KEY_BEGIN = re.compile(
    rb"-----BEGIN (?P<label>" + PEM_PRIVATE_KEY_LABEL_PATTERN + rb")-----"
)
PEM_PRIVATE_KEY_END = re.compile(
    rb"-----END (?P<label>" + PEM_PRIVATE_KEY_LABEL_PATTERN + rb")-----"
)
SECRET_KEY_NAME_PATTERN = (
    rb"(?i)(?:aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|"
    rb"api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|"
    rb"bearer[_-]?token|client[_-]?secret|id[_-]?token|password|passwd|"
    rb"private[_-]?token|"
    rb"refresh[_-]?token|secret[_-]?(?:key|token))['\"]?"
)
STRONG_SECRET_KEY_NAME_PATTERN = re.compile(
    rb"(?i)aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)"
)
SECRET_KEY_PATTERN = SECRET_KEY_NAME_PATTERN + rb"\s{0,256}[:=]\s{0,256}"
STRING_LITERAL_PREFIX_PATTERN = rb"(?:(?:br|rb|fr|rf|b|f|r|u))?"
SECRET_ASSIGNMENT_PREFIX = re.compile(SECRET_KEY_PATTERN)
WRAPPER_CONTEXT_MARKER = re.compile(rb"""[/'"`#()[\]{}]""")
OVERSIZED_SECRET_ASSIGNMENT_GAP = re.compile(
    SECRET_KEY_NAME_PATTERN + rb"(?:\s{257}|\s{0,256}[:=]\s{257})"
)
QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN
    + STRING_LITERAL_PREFIX_PATTERN
    + rb"(['\"])([^\r\n'\"]{16,512})\1"
)
QUOTED_SECRET_ASSIGNMENT_PREFIX = re.compile(
    SECRET_KEY_PATTERN + STRING_LITERAL_PREFIX_PATTERN + rb"(['\"])([^\r\n'\"]{16,512})"
)
OVERSIZED_QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + STRING_LITERAL_PREFIX_PATTERN + rb"(['\"])[^\r\n'\"]{513}"
)
UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN
    + rb"((?:"
    + GENERIC_SECRET_VALUE_BYTE_CLASS
    + rb"){16,512})(?!"
    + GENERIC_SECRET_VALUE_BYTE_CLASS
    + rb")",
)
UNQUOTED_SECRET_VALUE = re.compile(
    rb"((?:"
    + GENERIC_SECRET_VALUE_BYTE_CLASS
    + rb"){16,512})(?!"
    + GENERIC_SECRET_VALUE_BYTE_CLASS
    + rb")",
)
OVERSIZED_UNQUOTED_SECRET_VALUE = re.compile(
    rb"(?:" + GENERIC_SECRET_VALUE_BYTE_CLASS + rb"){513}"
)
OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"(?:" + GENERIC_SECRET_VALUE_BYTE_CLASS + rb"){513}"
)
PLACEHOLDER_SECRET_PATTERN = re.compile(
    rb"(?:"
    rb"\$\{[A-Za-z_][A-Za-z0-9_]*\}"
    rb"|<[A-Za-z_][A-Za-z0-9_.-]*>"
    rb"|(?:changeme|dummy|example|fake|placeholder|redacted)"
    rb"(?:[-_ ](?:credential|key|password|sample|secret|test|token|value)){0,2}"
    rb"|(?:must[-_ ]not[-_ ]pass|not[-_ ]a[-_ ]real|parent[-_ ]only)"
    rb"(?:[-_ ](?:credential|key|password|secret|token|value))?"
    rb")",
    re.IGNORECASE,
)
SENSITIVE_ANYWHERE_NAMES = {
    ".git-credentials",
    ".netrc",
    "auth.json",
    "service-account.json",
    "service_account.json",
    "token.json",
}
SENSITIVE_PATH_SUFFIXES = (
    (".aws", "credentials"),
    (".docker", "config.json"),
    (".kube", "config"),
)
SENSITIVE_FILE_NAMES = {
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template")
PROTECTED_REVIEW_PATHS = (".codex", ".agents")
MAX_SNAPSHOT_BLOB_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 100_000
MAX_TREE_METADATA_BYTES = 128 * 1024 * 1024
MAX_PRIVATE_OBJECT_LIST_BYTES = 128 * 1024 * 1024
MAX_ENDPOINT_COMMIT_BYTES = 4 * 1024 * 1024
# Each of base, head, and a WIP snapshot can contain one content object and one
# tree object per entry, plus endpoint commits and a fixed entry margin.
MAX_PRIVATE_OBJECT_ENTRIES = 6 * MAX_SNAPSHOT_ENTRIES + 16
MAX_PRIVATE_OBJECT_BYTES = 2 * (
    MAX_SNAPSHOT_BYTES + MAX_TREE_METADATA_BYTES + MAX_ENDPOINT_COMMIT_BYTES
)
# Bound pack framing, per-object compression expansion, and checksums separately
# from the uncompressed endpoint objects.
MAX_PRIVATE_PACK_OVERHEAD_BYTES = MAX_PRIVATE_OBJECT_LIST_BYTES
MAX_PRIVATE_PACK_BYTES = MAX_PRIVATE_OBJECT_BYTES + MAX_PRIVATE_PACK_OVERHEAD_BYTES
# WIP capture can add one snapshot of blobs plus tree objects. Its encoding
# margin and the generated endpoint/WIP pack sidecars remain separately bounded.
MAX_PRIVATE_WIP_STORAGE_BYTES = (
    MAX_SNAPSHOT_BYTES + MAX_TREE_METADATA_BYTES + MAX_PRIVATE_PACK_OVERHEAD_BYTES
)
MAX_PRIVATE_PACK_SIDECAR_BYTES = 2 * MAX_PRIVATE_OBJECT_LIST_BYTES
MAX_PRIVATE_STORAGE_BYTES = (
    MAX_PRIVATE_PACK_BYTES
    + MAX_PRIVATE_WIP_STORAGE_BYTES
    + MAX_PRIVATE_PACK_SIDECAR_BYTES
)
MAX_PRIVATE_LOOSE_OBJECT_BYTES = (
    MAX_TREE_METADATA_BYTES + MAX_PRIVATE_PACK_OVERHEAD_BYTES
)
# Signature scan material adds strict decoded bytes to content already bounded by
# MAX_ENDPOINT_COMMIT_BYTES. Base64 decoding can add at most three bytes per four
# joined body bytes, so twice the endpoint limit is a conservative total bound.
MAX_ENDPOINT_COMMIT_SCAN_BYTES = 2 * MAX_ENDPOINT_COMMIT_BYTES
MAX_DIFF_BYTES = 128 * 1024 * 1024
MAX_CHANGED_METADATA_BYTES = 128 * 1024 * 1024
MAX_CHANGED_ENTRIES = 100_000
MAX_CHANGED_BLOB_SCAN_BYTES = 512 * 1024 * 1024
MAX_SECRET_SCAN_EVENTS = 1_000_000
MAX_SECRET_REDUCTION_CANDIDATES = 128
MAX_SECRET_REDUCTION_CANDIDATE_BYTES = 32 * 1024
MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES = 512
MAX_SECRET_DELTA_ADDITION_LOCATIONS = 256
MAX_LEGACY_OCCURRENCE_EVENTS = 1_000_000
MAX_LEGACY_SEARCH_BYTES = 16 * 1024 * 1024 * 1024
MAX_LEGACY_CONTAINMENT_CHECKS = 10_000_000
MAX_SECRET_ASSIGNMENT_TRAILING_BYTES = 256
MAX_SECRET_PREFIX_PROOF_BYTES = 4 * 1024 * 1024
MAX_SECRET_PREFIX_PROOF_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SECRET_PREFIX_PROOF_WORK_BYTES = 512 * 1024 * 1024
MAX_SECRET_PREFIX_PROOF_RANGES = 100_000
MAX_REVIEW_PROMPT_BYTES = 64 * 1024
MAX_SYNTHETIC_EVIDENCE_BYTES = 64 * 1024
MAX_SYNTHETIC_EVIDENCE_ENTRIES = 512
MAX_SOURCE_STATUS_BYTES = MAX_CHANGED_METADATA_BYTES
MAX_SOURCE_STATUS_RECORDS = 3 * MAX_CHANGED_ENTRIES + 4096
MAX_SOURCE_TRACKED_PATH_BYTES = MAX_CHANGED_METADATA_BYTES
MAX_SOURCE_TRACKED_PATH_RECORDS = MAX_CHANGED_ENTRIES
MAX_SOURCE_INDEX_METADATA_BYTES = MAX_TREE_METADATA_BYTES
MAX_SOURCE_INDEX_RECORDS = MAX_SNAPSHOT_ENTRIES
MAX_SOURCE_INFO_EXCLUDE_BYTES = 1024 * 1024
MAX_SOURCE_GIT_QUERY_BYTES = 64 * 1024
MAX_SOURCE_GIT_STDERR_BYTES = 64 * 1024
SOURCE_GIT_TIMEOUT_SECONDS = 120.0
SOURCE_WIP_CAPTURE_TIMEOUT_SECONDS = 300.0
MAX_SOURCE_WIP_GIT_INVOCATIONS = 16
SOURCE_WIP_PARSE_DEADLINE_CHECK_BYTES = 64 * 1024
MAX_PRIVATE_GIT_STDERR_BYTES = 64 * 1024
MAX_PRIVATE_FSCK_OUTPUT_BYTES = 4 * 1024 * 1024
PRIVATE_GIT_TIMEOUT_SECONDS = 300.0
REVIEW_ROOT_BASE = pathlib.Path("/tmp")
REVIEW_USER_ROOT_PREFIX = "codex-isolated-review-uid-"
REVIEW_CONTAINER_PATTERN = re.compile(r"isolated-review-[0-9]{8}-[0-9]{6}-[0-9a-f]{10}")
MAX_REVIEW_CLEANUP_DEPTH = 256
PRIVATE_REVIEW_GIT_CLEANUP_DEPTH = 32
REVIEW_CLEANUP_QUARANTINE_PREFIX = ".codex-review-cleanup-"
REVIEW_CLEANUP_LOCK_NAME = "cleanup.lock"
REVIEW_RUNNER_LOCK_NAME = "runner.lock"
REVIEW_STATE_MARKER_NAME = ".isolated-review-state"
MAX_PREFLIGHT_JSON_BYTES = 128 * 1024
MAX_BOUNDED_JSON_DEPTH = 64
GIT_LFS_POINTER_MAX_BYTES = 1024
GIT_LFS_V1_ALIASES = frozenset(
    {
        b"http://git-media.io/v/2",
        b"https://hawser.github.com/spec/v1",
        b"https://git-lfs.github.com/spec/v1",
    }
)
GIT_LFS_OID_PATTERN = re.compile(rb"sha256:[0-9a-f]{64}\Z")
GIT_LFS_EXTENSION_PREFIX_PATTERN = re.compile(rb"\Aext-[0-9]{1}-\w+")
GIT_LFS_SIZE_PATTERN = re.compile(rb"[+-]?[0-9]+\Z")
SYNTHETIC_MANIFEST_NAME = "synthetic-secret-manifest.json"
SYNTHETIC_PRIVATE_MANIFEST_NAME = "synthetic-secret-state.json"
SYNTHETIC_CHANGED_EVIDENCE_NAME = "synthetic-changed-evidence.json"
SYNTHETIC_MANIFEST_SCHEMA_VERSION = 5
SECRET_REDUCTION_PROVENANCE_SCHEME = "path-surface-offset-sha256-v1"
PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX = (
    "Complementary helper-private manifest rows are integrity-bound by SHA-256:"
)
CONTROL_ARTIFACT_STATE_NAME = "control-artifact-state.json"
CONTROL_ARTIFACT_SCHEMA_VERSION = 5
CHANGED_PATH_DIGESTS_NAME = "changed-path-digests.z"
PRIVATE_CHANGED_PATHS_NAME = "changed-paths-private.z"
CHANGED_PATH_DIGEST_DOMAIN = b"codex-review-changed-path-v2\0"
CHANGED_PATH_HEAD_TAG = b"H"
CHANGED_PATH_BASE_ONLY_TAG = b"B"
PRIVATE_HELPER_ARTIFACT_NAMES = (
    SYNTHETIC_PRIVATE_MANIFEST_NAME,
    PRIVATE_CHANGED_PATHS_NAME,
)
CONTROL_ARTIFACT_SPECS: dict[str, tuple[int, int | None]] = {
    CHANGED_PATH_DIGESTS_NAME: (MAX_CHANGED_METADATA_BYTES, MAX_CHANGED_ENTRIES),
    "changed-blob-findings.z": (
        MAX_CHANGED_METADATA_BYTES,
        MAX_CHANGED_ENTRIES * 3,
    ),
    SYNTHETIC_MANIFEST_NAME: (MAX_SYNTHETIC_EVIDENCE_BYTES, None),
    SYNTHETIC_CHANGED_EVIDENCE_NAME: (MAX_SYNTHETIC_EVIDENCE_BYTES, None),
    "review.diff": (MAX_DIFF_BYTES, None),
    "review.prompt": (MAX_REVIEW_PROMPT_BYTES, None),
}
LONG_ALPHANUMERIC_SECRET = re.compile(rb"[A-Za-z0-9]{24,512}")
LONG_NUMERIC_SECRET = re.compile(rb"[0-9]{16,512}")
UNIFIED_DIFF_HUNK_PATTERN = re.compile(
    rb"^@@ -[0-9]+(?:,[0-9]+)? \+(?P<head_line>[0-9]+)(?:,[0-9]+)? @@"
)


@dataclass(frozen=True)
class CleanupIdentity:
    device: int
    inode: int

    def to_json(self) -> dict[str, int]:
        return {"device": self.device, "inode": self.inode}


@dataclass(frozen=True)
class PrivateCleanupEvidence:
    container: CleanupIdentity
    artifacts: Mapping[str, CleanupIdentity]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifacts",
            MappingProxyType(dict(self.artifacts)),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "artifacts": [
                {"name": name, **identity.to_json()}
                for name, identity in sorted(self.artifacts.items())
            ],
            "container": self.container.to_json(),
            "schema_version": 1,
        }


class BoundReviewLock:
    """Own modern and compatibility cleanup-lock descriptors."""

    def __init__(self, descriptor: int) -> None:
        self._descriptor: int | None = descriptor
        self._compatibility_descriptor: int | None = None

    def fileno(self) -> int:
        if self._descriptor is None:
            raise ValueError("I/O operation on closed review lock")
        return self._descriptor

    def filenos(self) -> tuple[int, ...]:
        descriptors = [self.fileno()]
        if self._compatibility_descriptor is not None:
            descriptors.append(self._compatibility_descriptor)
        return tuple(descriptors)

    def open_compatibility_lock(self, name: str) -> str | None:
        if name != "cleanup.lock":
            return "review runtime compatibility lock name is not allowed"
        if self._compatibility_descriptor is not None:
            return None

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        created = False
        try:
            try:
                descriptor = os.open(
                    name,
                    flags | os.O_EXCL,
                    0o600,
                    dir_fd=self.fileno(),
                )
                created = True
            except FileExistsError:
                descriptor = os.open(
                    name,
                    flags & ~os.O_CREAT,
                    dir_fd=self.fileno(),
                )
            if created:
                os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            current = os.stat(
                name,
                dir_fd=self.fileno(),
                follow_symlinks=False,
            )
            for metadata in (opened, current):
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    return "review runtime compatibility lock is not a regular file"
                if metadata.st_uid != os.geteuid():
                    return "review runtime compatibility lock has an unexpected owner"
                if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    return (
                        "review runtime compatibility lock must not be group or "
                        "other writable"
                    )
            if _private_cleanup_identity(opened) != _private_cleanup_identity(current):
                return "review runtime compatibility lock changed while opening"
            self._compatibility_descriptor = descriptor
            descriptor = None
        except OSError as error:
            if created:
                try:
                    os.unlink(name, dir_fd=self.fileno())
                except OSError:
                    pass
            return f"cannot securely open review runtime compatibility lock: {error}"
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return None

    def close(self) -> None:
        first_error: OSError | None = None
        for attribute in ("_compatibility_descriptor", "_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if first_error is None:
                    first_error = error
            setattr(self, attribute, None)
        if first_error is not None:
            raise first_error

    def __enter__(self) -> BoundReviewLock:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True)
class ReviewWorkspace:
    source_root: pathlib.Path
    container_dir: pathlib.Path
    workspace_root: pathlib.Path
    base_ref: str
    head_ref: str
    diff_file: pathlib.Path
    prompt_file: pathlib.Path
    private_cleanup: PrivateCleanupEvidence
    git_dir: pathlib.Path | None = None
    content_variant: str = "head"
    snapshot_tree_sha: str = ""
    scope_identity: str = ""

    def to_json(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "base_ref": self.base_ref,
            "container_dir": str(self.container_dir),
            "content_variant": self.content_variant,
            "diff_file": str(self.diff_file),
            "head_ref": self.head_ref,
            "private_cleanup": self.private_cleanup.to_json(),
            "prompt_file": str(self.prompt_file),
            "scope_identity": self.scope_identity,
            "snapshot_tree_sha": self.snapshot_tree_sha,
            "source_root": str(self.source_root),
            "workspace_root": str(self.workspace_root),
        }
        if self.git_dir is not None:
            value["git_dir"] = str(self.git_dir)
        return value

    def has_complete_scope_identity(self) -> bool:
        if (
            self.content_variant not in {"head", "source-wip"}
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", self.snapshot_tree_sha)
            is None
            or re.fullmatch(r"[0-9a-f]{64}", self.scope_identity) is None
        ):
            return False
        return self.scope_identity == _review_scope_identity(
            base_sha=self.base_ref,
            head_sha=self.head_ref,
            content_variant=self.content_variant,
            snapshot_tree_sha=self.snapshot_tree_sha,
        )

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "ReviewWorkspace":
        required_fields = {
            "base_ref",
            "container_dir",
            "content_variant",
            "diff_file",
            "head_ref",
            "private_cleanup",
            "prompt_file",
            "scope_identity",
            "snapshot_tree_sha",
            "source_root",
            "workspace_root",
        }
        allowed_fields = required_fields | {"git_dir"}
        if not required_fields <= set(value) or not set(value) <= allowed_fields:
            raise ValueError("workspace fields are invalid")
        text_fields = required_fields - {"private_cleanup"}
        if any(not isinstance(value[field], str) for field in text_fields):
            raise ValueError("workspace text fields are invalid")
        return cls(
            source_root=pathlib.Path(value["source_root"]),
            container_dir=pathlib.Path(value["container_dir"]),
            workspace_root=pathlib.Path(value["workspace_root"]),
            base_ref=value["base_ref"],
            head_ref=value["head_ref"],
            diff_file=pathlib.Path(value["diff_file"]),
            prompt_file=pathlib.Path(value["prompt_file"]),
            private_cleanup=_parse_private_cleanup_evidence(
                value["private_cleanup"],
                require_all=True,
            ),
            git_dir=(
                pathlib.Path(value["git_dir"])
                if isinstance(value.get("git_dir"), str) and value["git_dir"]
                else pathlib.Path(value["container_dir"]) / "review.git"
            ),
            content_variant=value["content_variant"],
            snapshot_tree_sha=value["snapshot_tree_sha"],
            scope_identity=value["scope_identity"],
        )


@dataclass(frozen=True)
class SourceLocalReviewWorkspace(ReviewWorkspace):
    """Modern v2-v4 state whose container remains under source `.codex-tmp`."""

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "SourceLocalReviewWorkspace":
        required_fields = {
            "base_ref",
            "container_dir",
            "diff_file",
            "head_ref",
            "private_cleanup",
            "prompt_file",
            "source_root",
            "workspace_root",
        }
        optional_fields = {"git_dir"}
        if not required_fields <= set(value) or not set(value) <= (
            required_fields | optional_fields
        ):
            raise ValueError("legacy workspace fields are invalid")
        text_fields = (required_fields - {"private_cleanup"}) | (
            set(value) & optional_fields
        )
        if any(not isinstance(value[field], str) for field in text_fields):
            raise ValueError("legacy workspace text fields are invalid")
        container_dir = pathlib.Path(value["container_dir"])
        return cls(
            source_root=pathlib.Path(value["source_root"]),
            container_dir=container_dir,
            workspace_root=pathlib.Path(value["workspace_root"]),
            base_ref=value["base_ref"],
            head_ref=value["head_ref"],
            diff_file=pathlib.Path(value["diff_file"]),
            prompt_file=pathlib.Path(value["prompt_file"]),
            private_cleanup=_parse_private_cleanup_evidence(
                value["private_cleanup"],
                require_all=True,
            ),
            git_dir=(
                pathlib.Path(value["git_dir"])
                if value.get("git_dir")
                else container_dir / "review.git"
            ),
            content_variant="head",
            snapshot_tree_sha="",
            scope_identity="",
        )


@dataclass(frozen=True)
class LegacyReviewWorkspace:
    source_root: pathlib.Path
    container_dir: pathlib.Path
    workspace_root: pathlib.Path
    base_ref: str
    head_ref: str
    diff_file: pathlib.Path
    prompt_file: pathlib.Path

    def to_json(self) -> dict[str, str]:
        return {
            "base_ref": self.base_ref,
            "container_dir": str(self.container_dir),
            "diff_file": str(self.diff_file),
            "head_ref": self.head_ref,
            "prompt_file": str(self.prompt_file),
            "source_root": str(self.source_root),
            "workspace_root": str(self.workspace_root),
        }

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "LegacyReviewWorkspace":
        expected_fields = {
            "base_ref",
            "container_dir",
            "diff_file",
            "head_ref",
            "prompt_file",
            "source_root",
            "workspace_root",
        }
        if set(value) != expected_fields:
            raise ValueError("legacy workspace fields are invalid")
        if any(not isinstance(value[field], str) for field in expected_fields):
            raise ValueError("legacy workspace text fields are invalid")
        return cls(
            source_root=pathlib.Path(value["source_root"]),
            container_dir=pathlib.Path(value["container_dir"]),
            workspace_root=pathlib.Path(value["workspace_root"]),
            base_ref=value["base_ref"],
            head_ref=value["head_ref"],
            diff_file=pathlib.Path(value["diff_file"]),
            prompt_file=pathlib.Path(value["prompt_file"]),
        )


@dataclass(frozen=True)
class ControlArtifactEvidence:
    name: str
    sha256: str
    size: int
    record_count: int | None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "record_count": self.record_count,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class ControlDirectoryEvidence:
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    mtime_ns: int
    ctime_ns: int
    entry_count: int
    entry_names_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "ctime_ns": self.ctime_ns,
            "device": self.device,
            "entry_count": self.entry_count,
            "entry_names_sha256": self.entry_names_sha256,
            "inode": self.inode,
            "link_count": self.link_count,
            "mode": self.mode,
            "mtime_ns": self.mtime_ns,
            "uid": self.uid,
        }


@dataclass(frozen=True)
class ControlArtifactState:
    artifacts: dict[str, ControlArtifactEvidence]
    directory: ControlDirectoryEvidence
    private_cleanup: PrivateCleanupEvidence
    private_artifacts_removed: frozenset[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "artifacts": [
                artifact.to_json()
                for artifact in sorted(
                    self.artifacts.values(),
                    key=lambda item: item.name,
                )
            ],
            "directory": self.directory.to_json(),
            "private_cleanup": {
                "binding": self.private_cleanup.to_json(),
                "removed": sorted(self.private_artifacts_removed),
                "schema_version": 1,
            },
            "schema_version": CONTROL_ARTIFACT_SCHEMA_VERSION,
        }


@dataclass(frozen=True)
class ValidatedWorkspaceLaunchReceipt:
    content_variant: str
    base_ref: str
    head_ref: str
    snapshot_tree_sha: str
    scope_identity: str
    private_container: CleanupIdentity
    private_artifacts: tuple[tuple[str, CleanupIdentity], ...]
    control_artifacts: tuple[ControlArtifactEvidence, ...]
    control_directory: ControlDirectoryEvidence


@dataclass(frozen=True)
class LegacyCountState:
    base_count: int
    head_count: int
    source_head_count: int
    base_unembedded_count: int
    head_unembedded_count: int
    source_head_unembedded_count: int


class _SourceHeadSecretCountIncrease(ReviewError):
    pass


class _IncompleteSecretScanSuffix(Exception):
    def __init__(self, retention_start: int | None = None) -> None:
        super().__init__()
        self.retention_start = retention_start


_INCOMPLETE_SECRET_SCAN_SUFFIX_RULE = "__incomplete-secret-scan-suffix__"
_UNEXTRACTABLE_SECRET_CANDIDATE_END = -1


@dataclass
class SecretScanResult:
    blocking_rule: str | None
    unextractable_rule: str | None
    accepted_counts: Counter[AcceptedSyntheticValue]
    accepted_candidates: dict[AcceptedSyntheticValue, set[bytes]]
    blocking_candidates: dict[bytes, set[str]]
    raw_occurrence_counts: Counter[AcceptedSyntheticValue]
    unembedded_occurrence_counts: Counter[AcceptedSyntheticValue]
    reduction_occurrence_offsets: dict[AcceptedSyntheticValue, set[int]]
    reduction_unembedded_offsets: dict[AcceptedSyntheticValue, set[int]]
    reduction_occurrence_identities: dict[AcceptedSyntheticValue, set[str]]
    reduction_unembedded_identities: dict[AcceptedSyntheticValue, set[str]]
    incomplete_suffix_start: int | None
    incomplete_suffix_retention_start: int | None

    @classmethod
    def empty(cls) -> "SecretScanResult":
        return cls(
            None,
            None,
            Counter(),
            {},
            {},
            Counter(),
            Counter(),
            {},
            {},
            {},
            {},
            None,
            None,
        )

    def merge(self, other: "SecretScanResult") -> None:
        if self.blocking_rule is None:
            self.blocking_rule = other.blocking_rule
        if self.unextractable_rule is None:
            self.unextractable_rule = other.unextractable_rule
        self.accepted_counts.update(other.accepted_counts)
        self.raw_occurrence_counts.update(other.raw_occurrence_counts)
        self.unembedded_occurrence_counts.update(other.unembedded_occurrence_counts)
        for descriptor, offsets in other.reduction_occurrence_offsets.items():
            destination = self.reduction_occurrence_offsets.setdefault(
                descriptor,
                set(),
            )
            destination.update(offsets)
        for descriptor, offsets in other.reduction_unembedded_offsets.items():
            destination = self.reduction_unembedded_offsets.setdefault(
                descriptor,
                set(),
            )
            destination.update(offsets)
        for descriptor, identities in other.reduction_occurrence_identities.items():
            destination = self.reduction_occurrence_identities.setdefault(
                descriptor,
                set(),
            )
            destination.update(identities)
        for descriptor, identities in other.reduction_unembedded_identities.items():
            destination = self.reduction_unembedded_identities.setdefault(
                descriptor,
                set(),
            )
            destination.update(identities)
        if (
            sum(map(len, self.reduction_occurrence_offsets.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
            or sum(map(len, self.reduction_unembedded_offsets.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
            or sum(map(len, self.reduction_occurrence_identities.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
            or sum(map(len, self.reduction_unembedded_identities.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
        ):
            raise ReviewError(
                "external review secret-reduction occurrence provenance exceeds "
                "the entry limit"
            )
        for accepted, values in other.accepted_candidates.items():
            self.accepted_candidates.setdefault(accepted, set()).update(values)
        for candidate, rules in other.blocking_candidates.items():
            if (
                candidate not in self.blocking_candidates
                and len(self.blocking_candidates) >= MAX_SECRET_REDUCTION_CANDIDATES
            ):
                raise ReviewError(
                    "external review content has too many secret-reduction candidates"
                )
            self.blocking_candidates.setdefault(candidate, set()).update(rules)
        if (
            sum(map(len, self.blocking_candidates))
            > MAX_SECRET_REDUCTION_CANDIDATE_BYTES
        ):
            raise ReviewError(
                "external review secret-reduction candidates exceed the byte limit"
            )


@dataclass
class _SharedPrefixProofWorkBudget:
    remaining: int


class SecretScanBudget:
    def __init__(
        self,
        remaining: int,
        remaining_prefix_proof_bytes: int = MAX_SECRET_PREFIX_PROOF_TOTAL_BYTES,
        remaining_prefix_proof_work_bytes: int = MAX_SECRET_PREFIX_PROOF_WORK_BYTES,
        *,
        _shared_prefix_proof_work_budget: _SharedPrefixProofWorkBudget | None = None,
        _allow_prefix_proof_overdraft: bool = False,
    ) -> None:
        self.remaining = remaining
        self.remaining_prefix_proof_bytes = remaining_prefix_proof_bytes
        self._shared_prefix_proof_work_budget = (
            _shared_prefix_proof_work_budget
            or _SharedPrefixProofWorkBudget(remaining_prefix_proof_work_bytes)
        )
        self._allow_prefix_proof_overdraft = _allow_prefix_proof_overdraft

    @property
    def remaining_prefix_proof_work_bytes(self) -> int:
        return self._shared_prefix_proof_work_budget.remaining

    @classmethod
    def default(cls) -> "SecretScanBudget":
        return cls(MAX_SECRET_SCAN_EVENTS)

    def consume(self) -> None:
        if self.remaining <= 0:
            raise ReviewError(
                "external review content exceeds the sensitive scanner event limit"
            )
        self.remaining -= 1

    def consume_prefix_proof(
        self,
        byte_count: int,
        *,
        work_byte_count: int,
    ) -> bool:
        if byte_count > MAX_SECRET_PREFIX_PROOF_BYTES:
            return False
        if (
            byte_count > self.remaining_prefix_proof_bytes
            and not self._allow_prefix_proof_overdraft
        ):
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof limit"
            )
        if work_byte_count > self.remaining_prefix_proof_work_bytes:
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof work limit"
            )
        self.remaining_prefix_proof_bytes -= byte_count
        self._shared_prefix_proof_work_budget.remaining -= work_byte_count
        return True

    def clone(
        self,
        *,
        allow_prefix_proof_overdraft: bool = False,
    ) -> "SecretScanBudget":
        return SecretScanBudget(
            self.remaining,
            self.remaining_prefix_proof_bytes,
            _shared_prefix_proof_work_budget=(self._shared_prefix_proof_work_budget),
            _allow_prefix_proof_overdraft=allow_prefix_proof_overdraft,
        )

    def commit_from(self, transaction: "SecretScanBudget") -> None:
        if transaction.remaining_prefix_proof_bytes < 0:
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof limit"
            )
        if (
            transaction.remaining > self.remaining
            or transaction.remaining_prefix_proof_bytes
            > self.remaining_prefix_proof_bytes
            or transaction._shared_prefix_proof_work_budget
            is not self._shared_prefix_proof_work_budget
        ):
            raise ReviewError("sensitive scanner budget transaction is invalid")
        self.remaining = transaction.remaining
        self.remaining_prefix_proof_bytes = transaction.remaining_prefix_proof_bytes


@dataclass
class _PrefixProofRangeTracker:
    """Charge each physical proof byte once within one streamed value."""

    event_budget: SecretScanBudget
    coordinate_offset: int = 0
    ranges: list[tuple[int, int]] = field(default_factory=list)

    def clone(
        self,
        event_budget: SecretScanBudget,
        *,
        coordinate_offset: int,
    ) -> "_PrefixProofRangeTracker":
        if type(coordinate_offset) is not int or coordinate_offset < 0:
            raise ReviewError("sensitive scanner produced an invalid proof offset")
        return _PrefixProofRangeTracker(
            event_budget,
            coordinate_offset=coordinate_offset,
            ranges=list(self.ranges),
        )

    def offset_view(self, coordinate_offset: int) -> "_PrefixProofRangeTracker":
        if type(coordinate_offset) is not int or coordinate_offset < 0:
            raise ReviewError("sensitive scanner produced an invalid proof offset")
        return _PrefixProofRangeTracker(
            self.event_budget,
            coordinate_offset=self.coordinate_offset + coordinate_offset,
            ranges=self.ranges,
        )

    def commit_from(self, transaction: "_PrefixProofRangeTracker") -> None:
        transaction_index = 0
        for start, end in self.ranges:
            while (
                transaction_index < len(transaction.ranges)
                and transaction.ranges[transaction_index][1] <= start
            ):
                transaction_index += 1
            if (
                transaction_index >= len(transaction.ranges)
                or transaction.ranges[transaction_index][0] > start
                or transaction.ranges[transaction_index][1] < end
            ):
                raise ReviewError("sensitive scanner proof transaction is invalid")
        if len(transaction.ranges) > MAX_SECRET_PREFIX_PROOF_RANGES:
            raise ReviewError("sensitive scanner proof transaction is invalid")
        transaction_budget = transaction.event_budget
        if transaction_budget.remaining_prefix_proof_bytes < 0:
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof limit"
            )
        if (
            transaction_budget.remaining > self.event_budget.remaining
            or transaction_budget.remaining_prefix_proof_bytes
            > self.event_budget.remaining_prefix_proof_bytes
            or transaction_budget._shared_prefix_proof_work_budget
            is not self.event_budget._shared_prefix_proof_work_budget
        ):
            raise ReviewError("sensitive scanner budget transaction is invalid")
        proof_budget_delta = (
            self.event_budget.remaining_prefix_proof_bytes
            - transaction_budget.remaining_prefix_proof_bytes
        )
        range_growth = sum(end - start for start, end in transaction.ranges) - sum(
            end - start for start, end in self.ranges
        )
        if proof_budget_delta != range_growth:
            raise ReviewError("sensitive scanner proof transaction is invalid")
        committed_ranges = list(transaction.ranges)
        self.event_budget.remaining = transaction_budget.remaining
        self.event_budget.remaining_prefix_proof_bytes = (
            transaction_budget.remaining_prefix_proof_bytes
        )
        self.ranges = committed_ranges

    def consume(
        self,
        start: int,
        end: int,
        *,
        proof_byte_count: int | None = None,
    ) -> bool:
        if not (
            type(start) is int
            and type(end) is int
            and 0 <= start <= end
            and type(self.coordinate_offset) is int
            and self.coordinate_offset >= 0
            and (
                proof_byte_count is None
                or (
                    type(proof_byte_count) is int
                    and 0 <= proof_byte_count <= end - start
                )
            )
        ):
            raise ReviewError("sensitive scanner produced an invalid proof range")
        logical_bytes = end - start if proof_byte_count is None else proof_byte_count
        if logical_bytes > MAX_SECRET_PREFIX_PROOF_BYTES:
            return False
        if start == end:
            return True
        start += self.coordinate_offset
        end += self.coordinate_offset

        insert_at = bisect_left(self.ranges, (start, -1))
        if insert_at > 0 and self.ranges[insert_at - 1][1] >= start:
            insert_at -= 1
        merged_start = start
        merged_end = end
        uncovered_cursor = start
        newly_proved_bytes = 0
        remove_until = insert_at
        while remove_until < len(self.ranges) and self.ranges[remove_until][0] <= end:
            range_start, range_end = self.ranges[remove_until]
            if range_start > uncovered_cursor:
                newly_proved_bytes += min(range_start, end) - uncovered_cursor
            uncovered_cursor = max(uncovered_cursor, min(range_end, end))
            merged_start = min(merged_start, range_start)
            merged_end = max(merged_end, range_end)
            remove_until += 1
        if uncovered_cursor < end:
            newly_proved_bytes += end - uncovered_cursor
        if newly_proved_bytes > logical_bytes:
            raise ReviewError("sensitive scanner proof accounting is inconsistent")
        resulting_range_count = len(self.ranges) - (remove_until - insert_at) + 1
        if resulting_range_count > MAX_SECRET_PREFIX_PROOF_RANGES:
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof range limit"
            )
        if not self.event_budget.consume_prefix_proof(
            newly_proved_bytes,
            work_byte_count=logical_bytes,
        ):
            return False
        self.ranges[insert_at:remove_until] = [(merged_start, merged_end)]
        return True


@dataclass
class _AssignmentPrefixContextCache:
    """Cache the wrapper context shared by one assignment's RHS probes."""

    assignment_prefix_end: int
    loaded: bool = False
    context: tuple[tuple[int, ...], bytes | None, tuple[int, ...]] | None = None


@dataclass(frozen=True)
class DiffHunkContext:
    source_start: int
    retention_start: int


@dataclass
class LegacyOccurrenceBudget:
    remaining: int
    remaining_search_bytes: int
    remaining_containment_checks: int

    @classmethod
    def default(cls) -> "LegacyOccurrenceBudget":
        return cls(
            MAX_LEGACY_OCCURRENCE_EVENTS,
            MAX_LEGACY_SEARCH_BYTES,
            MAX_LEGACY_CONTAINMENT_CHECKS,
        )

    def consume(self) -> None:
        if self.remaining <= 0:
            raise ReviewError(
                "external review content exceeds the legacy synthetic occurrence limit"
            )
        self.remaining -= 1

    def consume_search(self, size: int) -> None:
        if size < 0 or size > self.remaining_search_bytes:
            raise ReviewError(
                "external review content exceeds the legacy synthetic search limit"
            )
        self.remaining_search_bytes -= size

    def consume_containment_check(self) -> None:
        if self.remaining_containment_checks <= 0:
            raise ReviewError(
                "external review content exceeds the legacy synthetic containment limit"
            )
        self.remaining_containment_checks -= 1


@dataclass
class FileScanByteBudget:
    remaining: int

    @classmethod
    def snapshot(cls) -> "FileScanByteBudget":
        return cls(MAX_SNAPSHOT_BYTES)

    def consume(self, size: int) -> None:
        if size < 0 or size > self.remaining:
            raise ReviewError("frozen workspace exceeds the total review scan limit")
        self.remaining -= size


@dataclass
class AcceptedValueIndex:
    exact: dict[tuple[str, bytes], list[AcceptedSyntheticValue]]
    digests: dict[tuple[str, int], dict[str, list[AcceptedSyntheticValue]]]


@dataclass(frozen=True)
class ExactValueIndex:
    patterns: tuple[tuple[bytes, AcceptedSyntheticValue], ...]
    maximum_length: int
    containers: dict[bytes, tuple[tuple[bytes, int], ...]]


@dataclass(frozen=True)
class LegacyPathMatcher:
    transitions: tuple[dict[int, int], ...]
    failures: tuple[int, ...]
    identifiers: tuple[str | None, ...]
    maximum_length: int

    def match(self, raw_path: bytes) -> str | None:
        state = 0
        for byte in raw_path:
            while state and byte not in self.transitions[state]:
                state = self.failures[state]
            state = self.transitions[state].get(byte, 0)
            identifier = self.identifiers[state]
            if identifier is not None:
                return identifier
        return None


@dataclass(frozen=True)
class BoundedProcessResult:
    output_bytes: int
    returncode: int
    stderr: bytes


@dataclass(frozen=True)
class SourceInspectionGitContext:
    source_root: pathlib.Path
    git_dir: pathlib.Path
    object_directory: pathlib.Path
    index_file: pathlib.Path
    head_sha: str
    excludes_file: str
    file_mode: bool


@dataclass
class SourceWipCaptureBudget:
    deadline: float
    git_invocations: int = 0

    def remaining_seconds(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewError(
                "source WIP capture and revalidation exceeded the shared time limit"
            )
        return remaining

    def claim_git_invocation(self) -> float:
        if self.git_invocations >= MAX_SOURCE_WIP_GIT_INVOCATIONS:
            raise ReviewError(
                "source WIP capture and revalidation exceeded the Git invocation limit"
            )
        timeout_seconds = min(
            SOURCE_GIT_TIMEOUT_SECONDS,
            self.remaining_seconds(),
        )
        self.git_invocations += 1
        return timeout_seconds


def _new_source_wip_capture_budget() -> SourceWipCaptureBudget:
    return SourceWipCaptureBudget(
        deadline=time.monotonic() + SOURCE_WIP_CAPTURE_TIMEOUT_SECONDS
    )


def _temporary_review_file() -> BinaryIO:
    return tempfile.TemporaryFile(dir=_canonical_review_root_base())


def _git_environment(
    *,
    object_directory: pathlib.Path | None = None,
    index_file: pathlib.Path | None = None,
) -> dict[str, str]:
    env = {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
        "SSH_ASKPASS": "/usr/bin/false",
    }
    if object_directory is not None:
        env["GIT_OBJECT_DIRECTORY"] = str(object_directory)
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    return env


def _source_git_home() -> pathlib.Path:
    try:
        import pwd

        raw_home = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError) as error:
        raise ReviewError(
            f"cannot resolve the current user's Git home: {error}"
        ) from error
    home = pathlib.Path(raw_home)
    if not home.is_absolute() or home == pathlib.Path("/"):
        raise ReviewError(
            "the current user's Git home must be an absolute user directory"
        )
    return home


def _source_git_config_environment(
    home: pathlib.Path,
) -> tuple[dict[str, str], pathlib.Path]:
    environment = _git_environment()
    environment.pop("GIT_CONFIG_GLOBAL", None)
    environment.pop("GIT_CONFIG_NOSYSTEM", None)
    environment["HOME"] = str(home)
    raw_xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if raw_xdg_config_home:
        xdg_config_home = pathlib.Path(raw_xdg_config_home)
        if not xdg_config_home.is_absolute():
            raise ReviewError("XDG_CONFIG_HOME must be absolute for source Git queries")
        environment["XDG_CONFIG_HOME"] = str(xdg_config_home)
    else:
        xdg_config_home = home / ".config"
    return environment, xdg_config_home / "git" / "ignore"


def _source_git_config_value(
    source_root: pathlib.Path,
    *,
    key: str,
    value_type: str,
) -> tuple[str | None, pathlib.Path]:
    environment, default_path = _source_git_config_environment(_source_git_home())
    command = (
        str(resolve_git()),
        "--no-pager",
        "-C",
        str(source_root),
        "config",
        "--includes",
        "--null",
        f"--type={value_type}",
        "--get",
        key,
    )
    completed = _run_bounded_git_capture(
        command,
        input_bytes=None,
        check=False,
        label="source Git effective-config query",
        byte_limit=MAX_SOURCE_GIT_QUERY_BYTES,
        timeout_seconds=SOURCE_GIT_TIMEOUT_SECONDS,
        timeout_label="source Git",
        environment=environment,
    )
    if completed.returncode == 1:
        if completed.stdout:
            raise ReviewError("source Git config query returned malformed output")
        return None, default_path
    if completed.returncode != 0:
        raise ReviewError("cannot resolve effective source Git configuration")
    if completed.stdout.count(b"\0") != 1 or not completed.stdout.endswith(b"\0"):
        raise ReviewError("source Git config query returned malformed output")
    return os.fsdecode(completed.stdout[:-1]), default_path


def _source_excludes_file(source_root: pathlib.Path) -> pathlib.Path | None:
    value, default_path = _source_git_config_value(
        source_root,
        key="core.excludesFile",
        value_type="path",
    )
    if value == "" or (
        value is not None and os.path.normcase(value) == os.path.normcase(os.devnull)
    ):
        return None
    path = default_path if value is None else pathlib.Path(value)
    if not path.is_absolute():
        path = source_root / path
    absolute_path = pathlib.Path(os.path.abspath(path))
    if value is not None and os.path.normcase(os.fspath(absolute_path)) == (
        os.path.normcase(os.path.abspath(os.devnull))
    ):
        return None
    return absolute_path


def _source_git_boolean_config(
    source_root: pathlib.Path,
    *,
    key: str,
) -> bool | None:
    value, _default_path = _source_git_config_value(
        source_root,
        key=key,
        value_type="bool",
    )
    if value is None:
        return None
    if value not in {"true", "false"}:
        raise ReviewError("source Git boolean config query returned malformed output")
    return value == "true"


def _git(
    repo: pathlib.Path,
    *args: str,
    check: bool = True,
    capture_budget: SourceWipCaptureBudget | None = None,
):
    command = (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.filemode=true",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        "-C",
        str(repo),
        *args,
    )
    try:
        return _run_bounded_git_capture(
            command,
            input_bytes=None,
            check=check,
            label="source Git query",
            byte_limit=MAX_SOURCE_GIT_QUERY_BYTES,
            timeout_seconds=(
                SOURCE_GIT_TIMEOUT_SECONDS
                if capture_budget is None
                else capture_budget.claim_git_invocation()
            ),
            timeout_label="source Git",
        )
    except ReviewError:
        if capture_budget is not None:
            capture_budget.remaining_seconds()
        raise


def _stop_bounded_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except PermissionError:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except PermissionError:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise ReviewError("cannot stop bounded source Git command") from error


def _stop_source_git_process(process: subprocess.Popen[bytes]) -> None:
    _stop_bounded_process(process)


def _bounded_source_git_output(
    context: SourceInspectionGitContext,
    *args: str,
    byte_limit: int,
    record_limit: int,
    label: str,
    config_overrides: tuple[str, ...] = (),
    capture_budget: SourceWipCaptureBudget | None = None,
) -> bytes:
    timeout_seconds = (
        SOURCE_GIT_TIMEOUT_SECONDS
        if capture_budget is None
        else capture_budget.claim_git_invocation()
    )
    config_args = tuple(item for value in config_overrides for item in ("-c", value))
    command = (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        *config_args,
        f"--git-dir={context.git_dir}",
        f"--work-tree={context.source_root}",
        *args,
    )
    process = subprocess.Popen(
        command,
        env=_git_environment(
            object_directory=context.object_directory,
            index_file=context.index_file,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _stop_source_git_process(process)
        raise ReviewError(f"failed to create {label} pipes")
    command_deadline = time.monotonic() + timeout_seconds
    output_bytes = 0
    records = 0
    stderr_bytes = bytearray()
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        with _temporary_review_file() as output:
            while selector.get_map():
                remaining = command_deadline - time.monotonic()
                if remaining <= 0:
                    if capture_budget is not None:
                        capture_budget.remaining_seconds()
                    raise ReviewError(f"{label} exceeded the source Git time limit")
                events = selector.select(timeout=min(remaining, 0.5))
                if not events:
                    continue
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        output_bytes += len(chunk)
                        if output_bytes > byte_limit:
                            raise ReviewError(
                                f"{label} exceeds the {byte_limit}-byte review limit"
                            )
                        records += chunk.count(b"\0")
                        if records > record_limit:
                            raise ReviewError(
                                f"{label} exceeds the {record_limit}-entry review limit"
                            )
                        output.write(chunk)
                    elif len(stderr_bytes) <= MAX_SOURCE_GIT_STDERR_BYTES:
                        remaining_stderr = (
                            MAX_SOURCE_GIT_STDERR_BYTES + 1 - len(stderr_bytes)
                        )
                        stderr_bytes.extend(chunk[:remaining_stderr])
            remaining = command_deadline - time.monotonic()
            if remaining <= 0:
                if capture_budget is not None:
                    capture_budget.remaining_seconds()
                raise ReviewError(f"{label} exceeded the source Git time limit")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                if capture_budget is not None:
                    capture_budget.remaining_seconds()
                raise ReviewError(
                    f"{label} exceeded the source Git time limit"
                ) from error
            if returncode != 0:
                detail = (
                    bytes(stderr_bytes[:MAX_SOURCE_GIT_STDERR_BYTES])
                    .decode("utf-8", errors="replace")
                    .strip()
                )
                suffix = f": {detail}" if detail else ""
                raise ReviewError(f"cannot collect {label}{suffix}")
            output.seek(0)
            return output.read(output_bytes)
    except BaseException:
        _stop_source_git_process(process)
        raise
    finally:
        selector.close()
        _close_pipe(process.stdout)
        _close_pipe(process.stderr)


def _run_bounded_process_to_file(
    command: tuple[str, ...],
    *,
    environment: dict[str, str],
    destination: BinaryIO,
    label: str,
    byte_limit: int,
    record_limit: int | None = None,
    record_separator: bytes = b"\n",
    input_handle: BinaryIO | int = subprocess.DEVNULL,
    timeout_seconds: float | None = None,
    timeout_label: str = "private Git",
    check: bool = True,
) -> BoundedProcessResult:
    if len(record_separator) != 1:
        raise ValueError("bounded process record separator must be one byte")
    if timeout_seconds is None:
        timeout_seconds = PRIVATE_GIT_TIMEOUT_SECONDS
    process = subprocess.Popen(
        command,
        env=environment,
        stdin=input_handle,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _stop_bounded_process(process)
        raise ReviewError(f"failed to create {label} pipes")
    deadline = time.monotonic() + timeout_seconds
    copied = 0
    records = 0
    stderr_bytes = bytearray()
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReviewError(f"{label} exceeded the {timeout_label} time limit")
            events = selector.select(timeout=min(remaining, 0.5))
            if not events:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 1024 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    copied += len(chunk)
                    if copied > byte_limit:
                        raise ReviewError(
                            f"{label} exceeds the {byte_limit}-byte review limit"
                        )
                    if record_limit is not None:
                        records += chunk.count(record_separator)
                        if records > record_limit:
                            raise ReviewError(
                                f"{label} exceeds the {record_limit}-entry review limit"
                            )
                    destination.write(chunk)
                elif len(stderr_bytes) <= MAX_PRIVATE_GIT_STDERR_BYTES:
                    remaining_stderr = (
                        MAX_PRIVATE_GIT_STDERR_BYTES + 1 - len(stderr_bytes)
                    )
                    stderr_bytes.extend(chunk[:remaining_stderr])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewError(f"{label} exceeded the {timeout_label} time limit")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise ReviewError(
                f"{label} exceeded the {timeout_label} time limit"
            ) from error
        retained_stderr = bytes(stderr_bytes[:MAX_PRIVATE_GIT_STDERR_BYTES])
        if check and returncode != 0:
            detail = retained_stderr.decode("utf-8", errors="replace").strip()
            suffix = f": {detail}" if detail else ""
            raise ReviewError(f"{label} failed{suffix}")
        return BoundedProcessResult(
            output_bytes=copied,
            returncode=returncode,
            stderr=retained_stderr,
        )
    except BaseException:
        _stop_bounded_process(process)
        raise
    finally:
        selector.close()
        _close_pipe(process.stdout)
        _close_pipe(process.stderr)


def _source_git_path(
    source_root: pathlib.Path,
    relative: str,
    *,
    label: str,
) -> pathlib.Path:
    result = _git(
        source_root,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        relative,
    )
    raw_path = result.stdout
    if not raw_path.endswith(b"\n") or b"\n" in raw_path[:-1] or b"\0" in raw_path:
        raise ReviewError(f"source Git {label} path is malformed")
    path = pathlib.Path(os.fsdecode(raw_path[:-1]))
    if not path.is_absolute():
        raise ReviewError(f"source Git {label} path is not absolute")
    return path


def _read_source_info_exclude(path: pathlib.Path) -> bytes:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return b""
    except OSError as error:
        raise ReviewError("cannot inspect source Git info/exclude") from error
    with _secure_file_reader(
        path,
        label="source Git info/exclude",
        max_bytes=MAX_SOURCE_INFO_EXCLUDE_BYTES,
    ) as (handle, _metadata):
        return handle.read(MAX_SOURCE_INFO_EXCLUDE_BYTES + 1)


def _read_source_excludes_file(path: pathlib.Path | None) -> bytes:
    if path is None:
        return b""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return b""
    except OSError as error:
        raise ReviewError(
            "cannot inspect the effective source Git excludes file"
        ) from error
    with _secure_file_reader(
        path,
        label="effective source Git excludes file",
        max_bytes=MAX_SOURCE_INFO_EXCLUDE_BYTES,
        allow_root_owner=True,
    ) as (handle, _metadata):
        return handle.read(MAX_SOURCE_INFO_EXCLUDE_BYTES + 1)


def _create_source_inspection_git_context(
    *,
    source_root: pathlib.Path,
    head_sha: str,
    container: pathlib.Path,
) -> SourceInspectionGitContext:
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head_sha) is None:
        raise ReviewError("source inspection HEAD is malformed")
    object_directory = _source_git_path(
        source_root,
        "objects",
        label="object directory",
    ).resolve()
    if not object_directory.is_dir():
        raise ReviewError(
            f"source Git object directory does not exist: {object_directory}"
        )
    index_file = _source_git_path(source_root, "index", label="index")
    try:
        index_status = os.lstat(index_file)
    except FileNotFoundError:
        index_status = None
    except OSError as error:
        raise ReviewError("cannot inspect the source Git index") from error
    if index_status is not None and (
        not stat.S_ISREG(index_status.st_mode) or index_status.st_uid != os.getuid()
    ):
        raise ReviewError("source Git index must be a current-user regular file")
    info_exclude = _read_source_info_exclude(
        _source_git_path(source_root, "info/exclude", label="info/exclude")
    )
    source_excludes = _read_source_excludes_file(_source_excludes_file(source_root))
    source_status_config = {
        key: _source_git_boolean_config(source_root, key=key)
        for key in ("core.fileMode", "core.ignoreCase", "core.precomposeUnicode")
    }

    git_dir = container / "source-inspection.git"
    git_dir.mkdir(mode=0o700)
    for name in ("info", "objects", "refs"):
        (git_dir / name).mkdir(mode=0o700)
    write_text_atomic(git_dir / "HEAD", f"{head_sha}\n")
    format_version = 1 if len(head_sha) == 64 else 0
    config = (
        "[core]\n"
        f"\trepositoryformatversion = {format_version}\n"
        "\tbare = false\n"
        "\tlogAllRefUpdates = false\n"
    )
    for key, value in source_status_config.items():
        if value is not None:
            config += f"\t{key.removeprefix('core.')} = {str(value).lower()}\n"
    if len(head_sha) == 64:
        config += "[extensions]\n\tobjectFormat = sha256\n"
    write_text_atomic(git_dir / "config", config)
    exclude_destination = git_dir / "info" / "exclude"
    exclude_destination.write_bytes(info_exclude)
    exclude_destination.chmod(0o600)
    effective_excludes_destination = git_dir / "effective-excludes"
    effective_excludes_destination.write_bytes(source_excludes)
    effective_excludes_destination.chmod(0o600)
    return SourceInspectionGitContext(
        source_root=source_root,
        git_dir=git_dir,
        object_directory=object_directory,
        index_file=index_file,
        head_sha=head_sha,
        excludes_file=str(effective_excludes_destination),
        file_mode=source_status_config["core.fileMode"] is not False,
    )


@contextmanager
def _temporary_source_inspection_git_context(
    *,
    source_root: pathlib.Path,
    head_sha: str,
) -> Iterator[SourceInspectionGitContext]:
    with tempfile.TemporaryDirectory(
        prefix="isolated-review-source-git-",
        dir=_canonical_review_root_base(),
    ) as raw:
        yield _create_source_inspection_git_context(
            source_root=source_root,
            head_sha=head_sha,
            container=pathlib.Path(raw),
        )


def _create_sanitized_git_view(
    *,
    source_root: pathlib.Path,
    container: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    object_result = _git(source_root, "rev-parse", "--git-path", "objects")
    object_value = pathlib.Path(object_result.stdout.decode("utf-8").strip())
    object_directory = (
        object_value if object_value.is_absolute() else source_root / object_value
    ).resolve()
    if not object_directory.is_dir():
        raise ReviewError(f"Git object directory does not exist: {object_directory}")
    format_result = _git(source_root, "rev-parse", "--show-object-format")
    object_format = format_result.stdout.decode("utf-8").strip()
    if object_format not in {"sha1", "sha256"}:
        raise ReviewError(f"unsupported Git object format: {object_format!r}")

    git_view = container / "git-view"
    git_view.mkdir(mode=0o755)
    (git_view / "objects").mkdir(mode=0o755)
    (git_view / "refs").mkdir(mode=0o755)
    write_text_atomic(git_view / "HEAD", "ref: refs/heads/unused\n")
    format_version = 1 if object_format == "sha256" else 0
    config = f"[core]\n\trepositoryformatversion = {format_version}\n\tbare = true\n"
    if object_format == "sha256":
        config += "[extensions]\n\tobjectFormat = sha256\n"
    write_text_atomic(git_view / "config", config)
    return git_view, object_directory


@contextmanager
def _temporary_sanitized_git_view(
    *,
    source_root: pathlib.Path,
) -> Iterator[tuple[pathlib.Path, pathlib.Path]]:
    with tempfile.TemporaryDirectory(
        prefix="isolated-review-git-view-",
        dir=_canonical_review_root_base(),
    ) as raw:
        yield _create_sanitized_git_view(
            source_root=source_root,
            container=pathlib.Path(raw),
        )


def _private_git_command(
    *,
    git_dir: pathlib.Path,
    args: tuple[str, ...],
    work_tree: pathlib.Path | None = None,
) -> tuple[str, ...]:
    command = [
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.logAllRefUpdates=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        f"--git-dir={git_dir}",
    ]
    if work_tree is not None:
        command.append(f"--work-tree={work_tree}")
    command.extend(args)
    return tuple(command)


def _run_private_git(
    *,
    git_dir: pathlib.Path,
    args: tuple[str, ...],
    work_tree: pathlib.Path | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = _private_git_command(
        git_dir=git_dir,
        work_tree=work_tree,
        args=args,
    )
    return _run_bounded_git_capture(
        command,
        input_bytes=input_bytes,
        check=check,
        label="private review Git command",
    )


def _run_worktree_git(
    workspace_root: pathlib.Path,
    *args: str,
    input_bytes: bytes | None = None,
    input_handle: BinaryIO | int | None = None,
    check: bool = True,
    byte_limit: int = MAX_PRIVATE_OBJECT_LIST_BYTES,
    record_limit: int | None = None,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        "-C",
        str(workspace_root),
        *args,
    )
    try:
        return _run_bounded_git_capture(
            command,
            input_bytes=input_bytes,
            input_handle=input_handle,
            check=check,
            label="detached review worktree Git command",
            byte_limit=byte_limit,
            record_limit=record_limit,
            timeout_seconds=(
                PRIVATE_GIT_TIMEOUT_SECONDS
                if capture_budget is None
                else capture_budget.claim_git_invocation()
            ),
            timeout_label=(
                "private Git" if capture_budget is None else "source WIP capture"
            ),
        )
    except ReviewError:
        if capture_budget is not None:
            capture_budget.remaining_seconds()
        raise


def _run_bounded_git_capture(
    command: tuple[str, ...],
    *,
    input_bytes: bytes | None,
    input_handle: BinaryIO | int | None = None,
    check: bool,
    label: str,
    byte_limit: int = MAX_PRIVATE_OBJECT_LIST_BYTES,
    record_limit: int | None = None,
    timeout_seconds: float = PRIVATE_GIT_TIMEOUT_SECONDS,
    timeout_label: str = "private Git",
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    with _temporary_review_file() as output, _temporary_review_file() as input_file:
        if input_bytes is not None and input_handle is not None:
            raise ReviewError(
                "bounded Git input must use bytes or one handle, not both"
            )
        selected_input: BinaryIO | int = subprocess.DEVNULL
        if input_bytes is not None:
            input_file.write(input_bytes)
            input_file.seek(0)
            selected_input = input_file
        elif input_handle is not None:
            selected_input = input_handle
        result = _run_bounded_process_to_file(
            command,
            environment=_git_environment() if environment is None else environment,
            destination=output,
            label=label,
            byte_limit=byte_limit,
            record_limit=record_limit,
            input_handle=selected_input,
            timeout_seconds=timeout_seconds,
            timeout_label=timeout_label,
            check=check,
        )
        output.seek(0)
        stdout = output.read(result.output_bytes)
    return subprocess.CompletedProcess(
        args=command,
        returncode=result.returncode,
        stdout=stdout,
        stderr=result.stderr,
    )


def _copy_review_objects(
    *,
    git_view: pathlib.Path,
    source_object_directory: pathlib.Path,
    git_dir: pathlib.Path,
    base_sha: str,
    head_sha: str,
) -> None:
    with _temporary_review_file() as object_ids:
        copied = 0
        for revisions in ((f"{base_sha}^{{tree}}",), (f"{head_sha}^{{tree}}",)):
            copied += _run_bounded_process_to_file(
                _frozen_command(
                    git_view=git_view,
                    args=("rev-list", "--objects", "--no-object-names", *revisions),
                ),
                environment=_git_environment(object_directory=source_object_directory),
                destination=object_ids,
                label="private review Git objects",
                byte_limit=MAX_PRIVATE_OBJECT_LIST_BYTES - copied,
                record_limit=MAX_PRIVATE_OBJECT_ENTRIES,
            ).output_bytes
        if copied and not _temporary_file_ends_with_newline(object_ids):
            object_ids.write(b"\n")
        object_ids.write(base_sha.encode("ascii") + b"\n")
        if head_sha != base_sha:
            object_ids.write(head_sha.encode("ascii") + b"\n")
        _validate_private_object_sizes(
            git_view=git_view,
            source_object_directory=source_object_directory,
            object_ids=object_ids,
        )
        object_ids.seek(0)
        with _temporary_review_file() as pack_file:
            _run_bounded_process_to_file(
                _frozen_command(
                    git_view=git_view,
                    args=(
                        "pack-objects",
                        "--stdout",
                        "--window=0",
                        "--depth=0",
                        "--threads=1",
                    ),
                ),
                environment=_git_environment(object_directory=source_object_directory),
                input_handle=object_ids,
                destination=pack_file,
                label="private Git pack",
                byte_limit=MAX_PRIVATE_PACK_BYTES,
            )
            pack_file.seek(0)
            with _temporary_review_file() as index_output:
                _run_bounded_process_to_file(
                    _private_git_command(
                        git_dir=git_dir,
                        args=("index-pack", "--stdin", "--threads=1"),
                    ),
                    environment=_git_environment(),
                    input_handle=pack_file,
                    destination=index_output,
                    label="private Git pack index",
                    byte_limit=4096,
                )
                index_output.seek(0)
                index_stdout = index_output.read(4097)
            if not index_stdout.strip():
                raise ReviewError("private review Git pack produced no object id")


def _validate_private_object_sizes(
    *,
    git_view: pathlib.Path,
    source_object_directory: pathlib.Path,
    object_ids: BinaryIO,
) -> None:
    object_ids.flush()
    object_ids.seek(0)
    with _temporary_review_file() as metadata:
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=(
                    "cat-file",
                    "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                ),
            ),
            environment=_git_environment(object_directory=source_object_directory),
            input_handle=object_ids,
            destination=metadata,
            label="private Git object-size metadata",
            byte_limit=MAX_PRIVATE_OBJECT_LIST_BYTES,
            record_limit=MAX_PRIVATE_OBJECT_ENTRIES,
        )
        total_bytes = 0
        metadata.seek(0)
        for line in metadata:
            fields = line.rstrip(b"\n").split(b" ")
            if len(fields) != 3 or fields[1] not in {b"blob", b"tree", b"commit"}:
                raise ReviewError("private Git object-size metadata is malformed")
            try:
                size = int(fields[2])
            except ValueError as error_value:
                raise ReviewError(
                    "private Git object-size metadata is malformed"
                ) from error_value
            if size < 0 or size > MAX_PRIVATE_OBJECT_BYTES - total_bytes:
                raise ReviewError("private Git endpoint objects exceed the byte limit")
            total_bytes += size
    object_ids.seek(0)


def _temporary_file_ends_with_newline(handle: BinaryIO) -> bool:
    position = handle.tell()
    if position == 0:
        return False
    handle.seek(-1, os.SEEK_CUR)
    value = handle.read(1) == b"\n"
    handle.seek(position)
    return value


def _scan_endpoint_commit_metadata(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    authoring_values: Iterable[AcceptedSyntheticValue],
    legacy_values: Iterable[AcceptedSyntheticValue],
) -> None:
    authoring = tuple(authoring_values)
    legacy = tuple(legacy_values)
    if any(item.kind != "authoring" for item in authoring):
        raise ReviewError("endpoint metadata authoring values are invalid")
    if any(item.kind != "legacy" for item in legacy):
        raise ReviewError("endpoint metadata legacy values are invalid")
    for revision in sorted({base_sha, head_sha}):
        with _temporary_review_file() as content:
            size = _run_bounded_process_to_file(
                _frozen_command(
                    git_view=git_view,
                    args=("cat-file", "commit", revision),
                ),
                environment=_git_environment(object_directory=object_directory),
                destination=content,
                label="endpoint commit metadata",
                byte_limit=MAX_ENDPOINT_COMMIT_BYTES,
            ).output_bytes
            content.seek(0)
            human_metadata = _human_commit_metadata(
                content.read(size),
                object_id_length=len(revision),
            )
            scan = _stream_secret_scan(
                io.BytesIO(human_metadata),
                size=len(human_metadata),
                accepted_values=authoring,
                raw_occurrence_values=legacy,
            )
            if scan.blocking_rule is not None or any(
                scan.raw_occurrence_counts.values()
            ):
                raise ReviewError(
                    "sensitive content preflight blocked external review; "
                    "an endpoint commit object contains credential-like metadata"
                )


def _human_commit_metadata(
    raw_commit: bytes,
    *,
    object_id_length: int,
) -> bytes:
    raw_headers, separator, message = raw_commit.partition(b"\n\n")
    if not separator:
        raise ReviewError("endpoint commit object has malformed headers")
    fields: list[tuple[bytes, bytes]] = []
    current_key: bytes | None = None
    current_value = bytearray()
    for line in raw_headers.split(b"\n"):
        if line.startswith(b" "):
            if current_key is None:
                raise ReviewError("endpoint commit object has malformed continuation")
            current_value.extend(b"\n" + line[1:])
            continue
        if current_key is not None:
            fields.append((current_key, bytes(current_value)))
        current_key, space, initial_value = line.partition(b" ")
        if not space or not current_key:
            raise ReviewError("endpoint commit object has malformed header")
        current_value = bytearray(initial_value)
    if current_key is not None:
        fields.append((current_key, bytes(current_value)))

    human = bytearray()
    tree_count = 0
    for key, value in fields:
        if key == b"tree":
            tree_count += 1
            if tree_count != 1 or not _valid_object_id(value, object_id_length):
                raise ReviewError("endpoint commit object has malformed tree metadata")
            continue
        if key == b"parent":
            if not _valid_object_id(value, object_id_length):
                raise ReviewError(
                    "endpoint commit object has malformed parent metadata"
                )
            continue
        if key in {b"gpgsig", b"gpgsig-sha256"}:
            human.extend(_human_signature_metadata(value))
            continue
        if key == b"mergetag":
            human.extend(
                _human_mergetag_metadata(
                    value,
                    object_id_length=object_id_length,
                )
            )
            continue
        human.extend(key + b" " + value + b"\n")
    if tree_count != 1:
        raise ReviewError("endpoint commit object must contain exactly one tree")
    human.extend(b"\n" + message)
    if len(human) > MAX_ENDPOINT_COMMIT_SCAN_BYTES:
        raise ReviewError("scannable endpoint commit metadata exceeds its byte limit")
    return bytes(human)


def _valid_object_id(value: bytes, object_id_length: int) -> bool:
    return (
        len(value) == object_id_length
        and re.fullmatch(rb"[0-9A-Fa-f]+", value) is not None
    )


SIGNATURE_ENVELOPES = {
    b"-----BEGIN PGP SIGNATURE-----": b"-----END PGP SIGNATURE-----",
    b"-----BEGIN SSH SIGNATURE-----": b"-----END SSH SIGNATURE-----",
    b"-----BEGIN SIGNED MESSAGE-----": b"-----END SIGNED MESSAGE-----",
    b"-----BEGIN CMS-----": b"-----END CMS-----",
    b"-----BEGIN PKCS7-----": b"-----END PKCS7-----",
}


def _human_signature_metadata(value: bytes) -> bytes:
    lines = value.split(b"\n")
    while lines and lines[-1] == b"":
        lines.pop()
    begin = lines[0] if lines else b""
    expected_end = SIGNATURE_ENVELOPES.get(begin)
    if expected_end is None or len(lines) < 3 or lines[-1] != expected_end:
        raise ReviewError("endpoint commit object has malformed signature metadata")
    body_lines: list[bytes] = []
    saw_checksum = False
    human = bytearray()
    for line in lines[1:-1]:
        if not line:
            continue
        if not body_lines and re.fullmatch(rb"[A-Za-z0-9-]+: [\x20-\x7e]*", line):
            human.extend(line + b"\n")
            continue
        if re.fullmatch(rb"=[A-Za-z0-9+/]{4}", line):
            if (
                begin != b"-----BEGIN PGP SIGNATURE-----"
                or not body_lines
                or saw_checksum
            ):
                raise ReviewError(
                    "endpoint commit object has malformed signature metadata"
                )
            try:
                base64.b64decode(line[1:], validate=True)
            except (binascii.Error, ValueError) as error:
                raise ReviewError(
                    "endpoint commit object has malformed signature metadata"
                ) from error
            saw_checksum = True
            continue
        if (
            saw_checksum
            or not 1 <= len(line) <= 128
            or re.fullmatch(rb"[A-Za-z0-9+/=]+", line) is None
        ):
            raise ReviewError("endpoint commit object has malformed signature metadata")
        body_lines.append(line)
    if not body_lines:
        raise ReviewError("endpoint commit object has empty signature metadata")
    joined_body = b"".join(body_lines)
    try:
        decoded = base64.b64decode(joined_body, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReviewError(
            "endpoint commit object has malformed signature metadata"
        ) from error
    if not decoded:
        raise ReviewError("endpoint commit object has empty signature metadata")
    human.extend(b"\n" + joined_body + b"\n" + decoded + b"\n")
    return bytes(human)


def _human_mergetag_metadata(
    value: bytes,
    *,
    object_id_length: int,
) -> bytes:
    raw_headers, separator, message = value.partition(b"\n\n")
    if not separator:
        raise ReviewError("endpoint commit object has malformed mergetag metadata")
    human = bytearray()
    saw_object = False
    saw_type = False
    for line in raw_headers.split(b"\n"):
        key, space, field_value = line.partition(b" ")
        if not space or not key:
            raise ReviewError("endpoint commit object has malformed mergetag header")
        if key == b"object":
            if saw_object or not _valid_object_id(field_value, object_id_length):
                raise ReviewError(
                    "endpoint commit object has malformed mergetag object"
                )
            saw_object = True
            continue
        if key == b"type":
            if saw_type or field_value != b"commit":
                raise ReviewError("endpoint commit object has malformed mergetag type")
            saw_type = True
            continue
        human.extend(key + b" " + field_value + b"\n")
    if not saw_object or not saw_type:
        raise ReviewError("endpoint commit object has incomplete mergetag metadata")
    human.extend(b"\n" + _unsigned_tag_message(message))
    return bytes(human)


def _unsigned_tag_message(message: bytes) -> bytes:
    for begin in SIGNATURE_ENVELOPES:
        if message.startswith(begin):
            signature_start = 0
            human_end = 0
        else:
            prefixed = message.find(b"\n" + begin)
            if prefixed < 0:
                continue
            signature_start = prefixed + 1
            human_end = prefixed
        signature_human = _human_signature_metadata(message[signature_start:])
        human = bytearray(message[:human_end])
        if signature_human:
            if human and not human.endswith(b"\n"):
                human.extend(b"\n")
            human.extend(signature_human)
        return bytes(human)
    return message


def _create_private_review_repository(
    *,
    container: pathlib.Path,
    git_view: pathlib.Path,
    source_object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
) -> pathlib.Path:
    git_dir = container / "review.git"
    empty_template = container / "empty-git-template"
    empty_template.mkdir(mode=0o700)
    init_args = [
        str(resolve_git()),
        "init",
        "--bare",
        f"--template={empty_template}",
        "--initial-branch=master",
    ]
    if len(base_sha) == 64:
        init_args.append("--object-format=sha256")
    init_args.append(str(git_dir))
    try:
        with _temporary_review_file() as init_output:
            _run_bounded_process_to_file(
                tuple(init_args),
                environment=_git_environment(),
                destination=init_output,
                label="private review Git initialization",
                byte_limit=4096,
            )
    finally:
        empty_template.rmdir()
    write_text_atomic(
        git_dir / "config",
        _canonical_private_git_config(object_id_length=len(base_sha)).decode("ascii"),
    )
    (git_dir / "config").chmod(0o600)
    write_text_atomic(git_dir / "HEAD", "ref: refs/heads/master\n")
    (git_dir / "HEAD").chmod(0o600)
    _copy_review_objects(
        git_view=git_view,
        source_object_directory=source_object_directory,
        git_dir=git_dir,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    for label, revision in (("base", base_sha), ("head", head_sha)):
        result = _run_private_git(
            git_dir=git_dir,
            args=("cat-file", "-e", f"{revision}^{{commit}}"),
            check=False,
        )
        if result.returncode != 0:
            raise ReviewError(f"private review Git database is missing the {label}")
    shallow_path = git_dir / "shallow"
    write_text_atomic(
        shallow_path,
        "".join(f"{revision}\n" for revision in sorted({base_sha, head_sha})),
    )
    shallow_path.chmod(0o600)
    return git_dir


def _canonical_private_git_config(*, object_id_length: int) -> bytes:
    if object_id_length == 40:
        return (
            b"[core]\n"
            b"\trepositoryformatversion = 0\n"
            b"\tfilemode = true\n"
            b"\tbare = true\n"
            b"\tlogAllRefUpdates = false\n"
        )
    if object_id_length == 64:
        return (
            b"[core]\n"
            b"\trepositoryformatversion = 1\n"
            b"\tfilemode = true\n"
            b"\tbare = true\n"
            b"\tlogAllRefUpdates = false\n"
            b"[extensions]\n"
            b"\tobjectFormat = sha256\n"
        )
    raise ReviewError("private review Git object format is invalid")


def _harden_private_git_permissions(git_dir: pathlib.Path) -> None:
    pending = [git_dir]
    visited = 0
    while pending:
        directory = pending.pop()
        try:
            metadata = os.lstat(directory)
        except OSError as error:
            raise ReviewError("cannot harden private review Git directory") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReviewError("private review Git directory is unsafe")
        directory.chmod(0o700)
        try:
            entries = os.scandir(directory)
        except OSError as error:
            raise ReviewError("cannot harden private review Git directory") from error
        try:
            with entries:
                for entry in entries:
                    visited += 1
                    if visited > 2 * MAX_PRIVATE_OBJECT_ENTRIES + 4096:
                        raise ReviewError(
                            "private review Git exceeds its hardening entry limit"
                        )
                    try:
                        entry_metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise ReviewError(
                            "cannot harden private review Git entry"
                        ) from error
                    path = pathlib.Path(entry.path)
                    if stat.S_ISDIR(entry_metadata.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(entry_metadata.st_mode):
                        path.chmod(0o600)
                    else:
                        raise ReviewError("private review Git contains an unsafe entry")
        except ReviewError:
            raise
        except OSError as error:
            raise ReviewError("cannot harden private review Git directory") from error


def _create_detached_worktree(
    *,
    git_dir: pathlib.Path,
    workspace_root: pathlib.Path,
    head_sha: str,
) -> None:
    _run_private_git(
        git_dir=git_dir,
        args=(
            "worktree",
            "add",
            "--detach",
            "--no-checkout",
            "--lock",
            str(workspace_root),
            head_sha,
        ),
    )
    git_pointer = workspace_root / ".git"
    try:
        metadata = os.lstat(git_pointer)
    except OSError as error:
        raise ReviewError(
            "detached review worktree has no .git control file"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ReviewError("detached review worktree .git control is not a private file")
    git_pointer.chmod(0o600)
    _ensure_detached_worktree_refs(
        git_dir=git_dir,
        workspace_root=workspace_root,
    )


def _ensure_detached_worktree_refs(
    *,
    git_dir: pathlib.Path,
    workspace_root: pathlib.Path,
) -> None:
    refs_dir = git_dir / "worktrees" / workspace_root.name / "refs"
    try:
        refs_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ReviewError(
            "cannot create detached review worktree refs directory"
        ) from error
    directory_flag = getattr(os, "O_DIRECTORY", None)
    no_follow_flag = getattr(os, "O_NOFOLLOW", None)
    if directory_flag is None or no_follow_flag is None:
        raise ReviewError(
            "host cannot securely inspect detached review worktree refs directory"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory_flag | no_follow_flag
    try:
        descriptor = os.open(refs_dir, flags)
    except OSError as error:
        raise ReviewError(
            "cannot securely open detached review worktree refs directory"
        ) from error
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(refs_dir)
        identity = (opened.st_dev, opened.st_ino, opened.st_uid)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or identity != (current.st_dev, current.st_ino, current.st_uid)
        ):
            raise ReviewError("detached review worktree refs directory is unsafe")
        os.fchmod(descriptor, 0o700)
        hardened = os.fstat(descriptor)
        current = os.lstat(refs_dir)
        if (
            (hardened.st_dev, hardened.st_ino, hardened.st_uid) != identity
            or (current.st_dev, current.st_ino, current.st_uid) != identity
            or stat.S_IMODE(hardened.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise ReviewError(
                "detached review worktree refs directory changed while hardening"
            )
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            "cannot harden detached review worktree refs directory"
        ) from error
    finally:
        os.close(descriptor)


def _frozen_command(
    *,
    git_view: pathlib.Path,
    args: tuple[str, ...],
) -> tuple[str, ...]:
    return (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        f"--git-dir={git_view}",
        *args,
    )


def _run_sanitized_git_query(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    args: tuple[str, ...],
    label: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return _run_bounded_git_capture(
        _frozen_command(git_view=git_view, args=args),
        input_bytes=None,
        check=check,
        label=label,
        byte_limit=MAX_SOURCE_GIT_QUERY_BYTES,
        timeout_seconds=SOURCE_GIT_TIMEOUT_SECONDS,
        timeout_label="source Git",
        environment=_git_environment(object_directory=object_directory),
    )


def _commit_uses_reserved_control_path(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    label: str,
) -> bool:
    with _temporary_review_file() as output:
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-z", "--name-only", commit),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=output,
            label=f"frozen {label} tree metadata",
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            record_separator=b"\0",
        )
        output.seek(0)
        reserved = False
        for name in _iter_nul_records(
            output,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label=f"frozen {label} tree metadata",
        ):
            if os.fsdecode(name).casefold() == ".codex-review":
                reserved = True
        return reserved


def _reject_protected_review_path_aliases(workspace_root: pathlib.Path) -> None:
    for name in PROTECTED_REVIEW_PATHS:
        candidate = workspace_root / name
        if candidate.is_symlink():
            raise ReviewError(
                f"the frozen head uses a symlink for protected top-level path {name}"
            )


def resolve_repo_root(repo: pathlib.Path) -> pathlib.Path:
    candidate = repo.expanduser().resolve()
    result = _git(candidate, "rev-parse", "--show-toplevel")
    root = pathlib.Path(result.stdout.decode("utf-8").strip()).resolve()
    if not root.is_dir():
        raise ReviewError(f"repository root does not exist: {root}")
    return root


def resolve_commit(
    repo: pathlib.Path,
    ref: str,
    *,
    label: str,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> str:
    result = _git(
        repo,
        "rev-parse",
        "--verify",
        f"{ref}^{{commit}}",
        check=False,
        capture_budget=capture_budget,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReviewError(f"cannot resolve {label} {ref!r}: {detail}")
    return result.stdout.decode("utf-8").strip()


def _require_ancestor_range(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
) -> None:
    if _is_ancestor_in_sanitized_view(
        git_view=git_view,
        object_directory=object_directory,
        ancestor=base_sha,
        descendant=head_sha,
        failure_message="cannot verify that the frozen base is an ancestor of head",
    ):
        return
    connectivity = _run_sanitized_git_query(
        git_view=git_view,
        object_directory=object_directory,
        args=(
            "rev-list",
            "--quiet",
            "--missing=error",
            base_sha,
            head_sha,
            "--",
        ),
        label="sanitized commit-connectivity Git query",
        check=False,
    )
    if connectivity.returncode != 0 or connectivity.stdout:
        raise ReviewError("cannot verify that the frozen base is an ancestor of head")
    merge_base = _run_sanitized_git_query(
        git_view=git_view,
        object_directory=object_directory,
        args=("merge-base", base_sha, head_sha),
        label="sanitized merge-base Git query",
        check=False,
    )
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        suggestion = merge_base.stdout.decode("ascii").strip()
        detail = f"; use merge base {suggestion} as --base-ref"
    elif merge_base.returncode == 1:
        detail = "; the commits have no merge base"
    else:
        raise ReviewError("cannot determine the merge base for the frozen range")
    raise ReviewError(
        f"frozen base {base_sha} is not an ancestor of head {head_sha}{detail}"
    )


def _is_ancestor_in_sanitized_view(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    ancestor: str,
    descendant: str,
    failure_message: str,
) -> bool:
    result = _run_sanitized_git_query(
        git_view=git_view,
        object_directory=object_directory,
        args=("merge-base", "--is-ancestor", ancestor, descendant),
        label="sanitized ancestry Git query",
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ReviewError(failure_message)


def _private_cleanup_directory_error(
    metadata: os.stat_result,
    *,
    label: str,
    require_private_mode: bool,
) -> str | None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return f"{label} is not a real directory"
    if metadata.st_uid != os.geteuid():
        return f"{label} has an unexpected owner"
    mode = stat.S_IMODE(metadata.st_mode)
    if require_private_mode and mode != 0o700:
        return f"{label} must have mode 0700"
    if not require_private_mode and mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{label} must not be group or other writable"
    return None


def _private_cleanup_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _cleanup_identity_evidence(metadata: os.stat_result) -> CleanupIdentity:
    return CleanupIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _private_artifact_metadata_at(
    container_descriptor: int,
    artifact_name: str,
    *,
    require_private_mode: bool = True,
) -> os.stat_result:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        artifact_before = os.stat(
            artifact_name,
            dir_fd=container_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot inspect helper-private artifact {artifact_name}: {error}"
        ) from error
    descriptor: int | None = None
    try:
        descriptor = os.open(
            artifact_name,
            flags,
            dir_fd=container_descriptor,
        )
        artifact_opened = os.fstat(descriptor)
        artifact_after = os.stat(
            artifact_name,
            dir_fd=container_descriptor,
            follow_symlinks=False,
        )
        for metadata in (artifact_before, artifact_opened, artifact_after):
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ReviewError(
                    f"helper-private artifact {artifact_name} is not a "
                    "regular file with one link"
                )
            if metadata.st_uid != os.geteuid():
                raise ReviewError(
                    f"helper-private artifact {artifact_name} has an unexpected owner"
                )
            mode = stat.S_IMODE(metadata.st_mode)
            if require_private_mode and mode != 0o600:
                raise ReviewError(
                    f"helper-private artifact {artifact_name} must have mode 0600"
                )
            if not require_private_mode and mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ReviewError(
                    f"helper-private artifact {artifact_name} must not be "
                    "group or other writable"
                )
        if (
            len(
                {
                    _private_cleanup_identity(artifact_before),
                    _private_cleanup_identity(artifact_opened),
                    _private_cleanup_identity(artifact_after),
                }
            )
            != 1
        ):
            raise ReviewError(
                f"helper-private artifact {artifact_name} changed while opening"
            )
        return artifact_opened
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot securely open helper-private artifact {artifact_name}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _private_artifact_identity_at(
    container_descriptor: int,
    artifact_name: str,
) -> CleanupIdentity:
    return _cleanup_identity_evidence(
        _private_artifact_metadata_at(container_descriptor, artifact_name)
    )


def _private_cleanup_directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _review_cleanup_directory_entry_error(metadata: os.stat_result) -> str | None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return "review cleanup directory entry is not a real directory"
    if metadata.st_uid != os.geteuid():
        return "review cleanup directory entry has an unexpected owner"
    return None


def _quarantine_cleanup_entry(
    parent_descriptor: int,
    entry_name: str,
    expected_metadata: os.stat_result,
    *,
    label: str,
    missing_is_error: bool,
) -> tuple[str | None, os.stat_result | None, list[str]]:
    quarantine_name = f"{REVIEW_CLEANUP_QUARANTINE_PREFIX}{uuid.uuid4().hex}"
    try:
        os.rename(
            entry_name,
            quarantine_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        if missing_is_error:
            return None, None, [f"{label} changed before removal"]
        return None, None, []
    except OSError as error:
        return None, None, [f"cannot quarantine {label}: {error}"]

    try:
        quarantined_metadata = os.stat(
            quarantine_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return (
            quarantine_name,
            None,
            [f"{label} quarantine changed before validation"],
        )
    except OSError as error:
        return (
            quarantine_name,
            None,
            [f"cannot inspect {label} quarantine: {error}"],
        )
    if _private_cleanup_identity(expected_metadata) != _private_cleanup_identity(
        quarantined_metadata
    ):
        return (
            quarantine_name,
            quarantined_metadata,
            [
                f"{label} changed before removal; replacement preserved as "
                f"{quarantine_name}"
            ],
        )
    return quarantine_name, quarantined_metadata, []


def _remove_quarantined_cleanup_entry(
    parent_descriptor: int,
    quarantine_name: str,
    expected_metadata: os.stat_result,
    *,
    label: str,
    is_directory: bool,
) -> list[str]:
    try:
        quarantine_final = os.stat(
            quarantine_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return [f"{label} quarantine changed before removal"]
    except OSError as error:
        return [f"cannot revalidate {label} quarantine: {error}"]
    if _private_cleanup_identity(expected_metadata) != _private_cleanup_identity(
        quarantine_final
    ):
        return [
            f"{label} quarantine changed before removal; entry preserved as "
            f"{quarantine_name}"
        ]
    try:
        if is_directory:
            os.rmdir(quarantine_name, dir_fd=parent_descriptor)
        else:
            os.unlink(quarantine_name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return [f"{label} quarantine changed before removal"]
    except OSError as error:
        return [f"cannot remove {label} quarantine {quarantine_name}: {error}"]
    return []


def _remove_open_directory_contents(
    directory_descriptor: int,
    *,
    depth: int = 0,
    depth_limit: int | None = None,
    excluded_entry_names: frozenset[str] = frozenset(),
) -> list[str]:
    if depth_limit is None:
        depth_limit = MAX_REVIEW_CLEANUP_DEPTH
    if depth >= depth_limit:
        return ["review cleanup directory depth exceeds the safety limit"]
    cleanup_errors: list[str] = []
    try:
        entry_names = os.listdir(directory_descriptor)
    except OSError as error:
        return [f"cannot enumerate review cleanup directory: {error}"]

    for entry_name in entry_names:
        if entry_name in excluded_entry_names:
            continue
        if entry_name.startswith(REVIEW_CLEANUP_QUARANTINE_PREFIX):
            cleanup_errors.append(
                "pre-existing review cleanup quarantine requires manual recovery"
            )
            continue
        try:
            entry_before = os.stat(
                entry_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            cleanup_errors.append(f"cannot inspect review cleanup entry: {error}")
            continue

        if not stat.S_ISDIR(entry_before.st_mode):
            quarantine_name, _, quarantine_errors = _quarantine_cleanup_entry(
                directory_descriptor,
                entry_name,
                entry_before,
                label="review cleanup entry",
                missing_is_error=False,
            )
            cleanup_errors.extend(quarantine_errors)
            if quarantine_errors or quarantine_name is None:
                continue
            cleanup_errors.extend(
                _remove_quarantined_cleanup_entry(
                    directory_descriptor,
                    quarantine_name,
                    entry_before,
                    label="review cleanup entry",
                    is_directory=False,
                )
            )
            continue

        directory_error = _review_cleanup_directory_entry_error(entry_before)
        if directory_error:
            cleanup_errors.append(directory_error)
            continue

        child_descriptor: int | None = None
        try:
            try:
                child_descriptor = os.open(
                    entry_name,
                    _private_cleanup_directory_flags(),
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                continue
            child_opened = os.fstat(child_descriptor)
            try:
                child_after = os.stat(
                    entry_name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                cleanup_errors.append(
                    "review cleanup directory entry changed while opening"
                )
                continue
            for metadata in (child_opened, child_after):
                directory_error = _review_cleanup_directory_entry_error(metadata)
                if directory_error:
                    cleanup_errors.append(directory_error)
                    break
            else:
                if (
                    len(
                        {
                            _private_cleanup_identity(entry_before),
                            _private_cleanup_identity(child_opened),
                            _private_cleanup_identity(child_after),
                        }
                    )
                    != 1
                ):
                    cleanup_errors.append(
                        "review cleanup directory entry changed while opening"
                    )
                    continue

                cleanup_errors.extend(
                    _remove_open_directory_tree(
                        directory_descriptor,
                        child_descriptor,
                        entry_name,
                        label="review cleanup directory entry",
                        require_private_mode=False,
                        depth=depth + 1,
                        depth_limit=depth_limit,
                        quarantine_before_recursion=True,
                    )
                )
        except OSError as error:
            cleanup_errors.append(
                f"cannot securely open review cleanup directory entry: {error}"
            )
        finally:
            if child_descriptor is not None:
                try:
                    os.close(child_descriptor)
                except OSError as error:
                    cleanup_errors.append(
                        f"cannot close review cleanup directory entry: {error}"
                    )
    return cleanup_errors


def _remove_open_directory_tree(
    parent_descriptor: int,
    directory_descriptor: int,
    directory_name: str,
    *,
    label: str,
    require_private_mode: bool,
    excluded_entry_names: frozenset[str] = frozenset(),
    final_entry_names: tuple[str, ...] = (),
    depth: int = 0,
    depth_limit: int | None = None,
    quarantine_before_recursion: bool = False,
    quarantine_before_final_entries: bool = False,
) -> list[str]:
    try:
        directory_opened = os.fstat(directory_descriptor)
    except OSError as error:
        return [f"cannot inspect {label} before quarantine: {error}"]
    directory_error = _private_cleanup_directory_error(
        directory_opened,
        label=label,
        require_private_mode=require_private_mode,
    )
    if directory_error:
        return [directory_error]

    directory_quarantine_name: str | None = None
    detached_directory_errors: list[str] = []
    if quarantine_before_recursion:
        try:
            parent_opened = os.fstat(parent_descriptor)
        except OSError as error:
            return [f"cannot inspect {label} parent before quarantine: {error}"]
        if directory_opened.st_dev != parent_opened.st_dev:
            return [f"{label} crosses a filesystem boundary"]
        (
            directory_quarantine_name,
            quarantined,
            quarantine_errors,
        ) = _quarantine_cleanup_entry(
            parent_descriptor,
            directory_name,
            directory_opened,
            label=label,
            missing_is_error=True,
        )
        if (
            quarantine_errors
            or directory_quarantine_name is None
            or quarantined is None
        ):
            return quarantine_errors
        directory_error = _private_cleanup_directory_error(
            quarantined,
            label=label,
            require_private_mode=require_private_mode,
        )
        if directory_error:
            return [directory_error]

    cleanup_errors = _remove_open_directory_contents(
        directory_descriptor,
        depth=depth,
        depth_limit=depth_limit,
        excluded_entry_names=excluded_entry_names | frozenset(final_entry_names),
    )
    if cleanup_errors:
        return cleanup_errors

    if quarantine_before_final_entries and directory_quarantine_name is None:
        try:
            os.fsync(directory_descriptor)
        except OSError as error:
            return [f"cannot sync cleaned {label} before quarantine: {error}"]
        try:
            directory_before_quarantine = os.fstat(directory_descriptor)
        except OSError as error:
            return [f"cannot revalidate {label} before quarantine: {error}"]
        directory_error = _private_cleanup_directory_error(
            directory_before_quarantine,
            label=label,
            require_private_mode=require_private_mode,
        )
        if directory_error:
            return [directory_error]
        if _private_cleanup_identity(
            directory_before_quarantine
        ) != _private_cleanup_identity(directory_opened):
            return [f"{label} changed during cleanup"]
        (
            directory_quarantine_name,
            quarantined,
            quarantine_errors,
        ) = _quarantine_cleanup_entry(
            parent_descriptor,
            directory_name,
            directory_before_quarantine,
            label=label,
            missing_is_error=True,
        )
        if quarantine_errors:
            if directory_quarantine_name is None or quarantined is None:
                return quarantine_errors
            if _private_cleanup_identity(quarantined) == _private_cleanup_identity(
                directory_before_quarantine
            ):
                return quarantine_errors
            # The canonical name was replaced while the original directory
            # remained bound to our descriptor. Retire only the original's
            # non-sensitive protocol entries, then report the detached tree.
            detached_directory_errors.extend(quarantine_errors)
        elif directory_quarantine_name is None or quarantined is None:
            return [f"cannot quarantine {label}"]
        else:
            directory_error = _private_cleanup_directory_error(
                quarantined,
                label=label,
                require_private_mode=require_private_mode,
            )
            if directory_error:
                return [directory_error]
    if quarantine_before_final_entries:
        if directory_quarantine_name is None:
            return [f"cannot establish {label} quarantine before final cleanup"]
        try:
            os.fsync(parent_descriptor)
        except OSError as error:
            return detached_directory_errors + [
                f"cannot sync {label} parent after quarantine: {error}; "
                "quarantine retained"
            ]

    for final_entry_name in final_entry_names:
        try:
            final_entry_metadata = os.stat(
                final_entry_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            return detached_directory_errors + [
                f"cannot inspect final review cleanup entry: {error}"
            ]
        if stat.S_ISDIR(final_entry_metadata.st_mode):
            return detached_directory_errors + [
                "final review cleanup entry is unexpectedly a directory"
            ]
        final_quarantine_name, _, quarantine_errors = _quarantine_cleanup_entry(
            directory_descriptor,
            final_entry_name,
            final_entry_metadata,
            label="final review cleanup entry",
            missing_is_error=True,
        )
        if quarantine_errors or final_quarantine_name is None:
            return detached_directory_errors + quarantine_errors
        cleanup_errors.extend(
            _remove_quarantined_cleanup_entry(
                directory_descriptor,
                final_quarantine_name,
                final_entry_metadata,
                label="final review cleanup entry",
                is_directory=False,
            )
        )
        if cleanup_errors:
            return detached_directory_errors + cleanup_errors

    if detached_directory_errors:
        return detached_directory_errors

    try:
        remaining_entry_names = os.listdir(directory_descriptor)
    except OSError as error:
        return [f"cannot verify empty {label}: {error}"]
    if remaining_entry_names:
        return [f"{label} still contains entries after cleanup"]

    try:
        directory_final = os.fstat(directory_descriptor)
    except OSError as error:
        return [f"cannot revalidate {label} before removal: {error}"]
    directory_error = _private_cleanup_directory_error(
        directory_final,
        label=label,
        require_private_mode=require_private_mode,
    )
    if directory_error:
        return [directory_error]
    if _private_cleanup_identity(directory_final) != _private_cleanup_identity(
        directory_opened
    ):
        suffix = (
            "; quarantine preserved" if directory_quarantine_name is not None else ""
        )
        return [f"{label} changed during cleanup{suffix}"]
    if directory_quarantine_name is None:
        (
            directory_quarantine_name,
            quarantined,
            quarantine_errors,
        ) = _quarantine_cleanup_entry(
            parent_descriptor,
            directory_name,
            directory_final,
            label=label,
            missing_is_error=True,
        )
        if (
            quarantine_errors
            or directory_quarantine_name is None
            or quarantined is None
        ):
            return quarantine_errors
        directory_error = _private_cleanup_directory_error(
            quarantined,
            label=label,
            require_private_mode=require_private_mode,
        )
        if directory_error:
            return [directory_error]
    removal_errors = _remove_quarantined_cleanup_entry(
        parent_descriptor,
        directory_quarantine_name,
        directory_opened,
        label=label,
        is_directory=True,
    )
    if removal_errors:
        return removal_errors
    if not quarantine_before_final_entries:
        return []
    try:
        os.fsync(parent_descriptor)
    except OSError as error:
        return [
            f"cannot sync {label} parent after removal: {error}; "
            "durable removal is unconfirmed"
        ]
    return []


def _remove_named_directory_tree(
    parent_descriptor: int,
    directory_name: str,
    *,
    label: str,
    require_private_mode: bool,
    depth_limit: int | None = None,
) -> list[str]:
    def preexisting_quarantine_errors() -> list[str]:
        try:
            entry_names = os.listdir(parent_descriptor)
        except OSError as error:
            return [f"cannot enumerate {label} parent before cleanup: {error}"]
        if any(
            entry_name.startswith(REVIEW_CLEANUP_QUARANTINE_PREFIX)
            for entry_name in entry_names
        ):
            return ["pre-existing review cleanup quarantine requires manual recovery"]
        return []

    quarantine_errors = preexisting_quarantine_errors()
    if quarantine_errors:
        return quarantine_errors
    try:
        directory_before = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return preexisting_quarantine_errors()
    except OSError as error:
        return [f"cannot inspect {label}: {error}"]
    directory_error = _private_cleanup_directory_error(
        directory_before,
        label=label,
        require_private_mode=require_private_mode,
    )
    if directory_error:
        return [directory_error]

    directory_descriptor: int | None = None
    cleanup_errors: list[str] = []
    try:
        try:
            directory_descriptor = os.open(
                directory_name,
                _private_cleanup_directory_flags(),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            return []
        directory_opened = os.fstat(directory_descriptor)
        try:
            directory_after = os.stat(
                directory_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            cleanup_errors.append(f"{label} changed while opening")
        else:
            for metadata in (directory_opened, directory_after):
                directory_error = _private_cleanup_directory_error(
                    metadata,
                    label=label,
                    require_private_mode=require_private_mode,
                )
                if directory_error:
                    cleanup_errors.append(directory_error)
                    break
            else:
                if (
                    len(
                        {
                            _private_cleanup_identity(directory_before),
                            _private_cleanup_identity(directory_opened),
                            _private_cleanup_identity(directory_after),
                        }
                    )
                    != 1
                ):
                    cleanup_errors.append(f"{label} changed while opening")
                else:
                    cleanup_errors.extend(
                        _remove_open_directory_tree(
                            parent_descriptor,
                            directory_descriptor,
                            directory_name,
                            label=label,
                            require_private_mode=require_private_mode,
                            depth_limit=depth_limit,
                            quarantine_before_recursion=True,
                        )
                    )
    except OSError as error:
        cleanup_errors.append(f"cannot securely open {label}: {error}")
    finally:
        if directory_descriptor is not None:
            try:
                os.close(directory_descriptor)
            except OSError as error:
                cleanup_errors.append(f"cannot close {label}: {error}")
    return cleanup_errors


def _operate_on_private_review_container(
    container: pathlib.Path,
    operation: Callable[[int, int], Iterable[str]],
) -> str | None:
    directory_flags = _private_cleanup_directory_flags()
    parent = container.parent
    try:
        parent_before = os.lstat(parent)
    except FileNotFoundError:
        return "private artifact parent is missing"
    except OSError as error:
        return f"cannot inspect private artifact parent: {error.strerror or error}"
    parent_error = _private_cleanup_directory_error(
        parent_before,
        label="private artifact parent",
        require_private_mode=False,
    )
    if parent_error:
        return parent_error

    try:
        parent_descriptor = os.open(parent, directory_flags)
    except FileNotFoundError:
        return "private artifact parent changed while opening"
    except OSError as error:
        return f"cannot securely open private artifact parent: {error}"

    cleanup_errors: list[str] = []
    container_descriptor: int | None = None
    try:
        parent_opened = os.fstat(parent_descriptor)
        parent_after = os.lstat(parent)
        for metadata in (parent_opened, parent_after):
            parent_error = _private_cleanup_directory_error(
                metadata,
                label="private artifact parent",
                require_private_mode=False,
            )
            if parent_error:
                raise ReviewError(parent_error)
        if (
            len(
                {
                    _private_cleanup_identity(parent_before),
                    _private_cleanup_identity(parent_opened),
                    _private_cleanup_identity(parent_after),
                }
            )
            != 1
        ):
            raise ReviewError("private artifact parent changed while opening")

        try:
            container_before = os.stat(
                container.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            cleanup_errors.append("private artifact container is missing")
            container_before = None
        if container_before is not None:
            container_error = _private_cleanup_directory_error(
                container_before,
                label="private artifact container",
                require_private_mode=True,
            )
            if container_error:
                raise ReviewError(container_error)
            container_descriptor = os.open(
                container.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            container_opened = os.fstat(container_descriptor)
            container_after = os.stat(
                container.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            for metadata in (container_opened, container_after):
                container_error = _private_cleanup_directory_error(
                    metadata,
                    label="private artifact container",
                    require_private_mode=True,
                )
                if container_error:
                    raise ReviewError(container_error)
            if (
                len(
                    {
                        _private_cleanup_identity(container_before),
                        _private_cleanup_identity(container_opened),
                        _private_cleanup_identity(container_after),
                    }
                )
                != 1
            ):
                raise ReviewError("private artifact container changed while opening")

        if container_descriptor is not None:
            cleanup_errors.extend(operation(parent_descriptor, container_descriptor))
    except (OSError, ReviewError) as error:
        cleanup_errors.append(str(error))
    finally:
        for label, descriptor in (
            ("private artifact container", container_descriptor),
            ("private artifact parent", parent_descriptor),
        ):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(f"cannot close {label}: {error}")
    return "; ".join(cleanup_errors) or None


def _capture_private_cleanup_evidence(
    container: pathlib.Path,
    *,
    expected_container: CleanupIdentity | None = None,
    require_all: bool,
) -> PrivateCleanupEvidence:
    captured: PrivateCleanupEvidence | None = None

    def capture(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        nonlocal captured
        container_identity = _cleanup_identity_evidence(os.fstat(container_descriptor))
        if expected_container is not None and container_identity != expected_container:
            return ["private artifact container does not match preparation identity"]
        artifacts: dict[str, CleanupIdentity] = {}
        errors: list[str] = []
        for artifact_name in PRIVATE_HELPER_ARTIFACT_NAMES:
            try:
                artifacts[artifact_name] = _private_artifact_identity_at(
                    container_descriptor,
                    artifact_name,
                )
            except FileNotFoundError:
                if require_all:
                    errors.append(f"helper-private artifact {artifact_name} is missing")
            except ReviewError as error:
                errors.append(str(error))
        if not errors:
            captured = PrivateCleanupEvidence(
                container=container_identity,
                artifacts=artifacts,
            )
        return errors

    capture_error = _operate_on_private_review_container(container, capture)
    if capture_error:
        raise ReviewError(capture_error)
    if captured is None:
        raise ReviewError("private cleanup evidence could not be captured")
    return captured


def _unlink_private_review_artifacts(
    _parent_descriptor: int,
    container_descriptor: int,
    *,
    expected: PrivateCleanupEvidence,
    removed: frozenset[str],
    record_removal: Callable[[str], None] | None,
    identity_label: str = "preparation",
) -> list[str]:
    container_identity = _cleanup_identity_evidence(os.fstat(container_descriptor))
    if container_identity != expected.container:
        return [f"private artifact container does not match {identity_label} identity"]
    cleanup_errors: list[str] = []
    removable: dict[str, os.stat_result] = {}
    for artifact_name in PRIVATE_HELPER_ARTIFACT_NAMES:
        expected_identity = expected.artifacts.get(artifact_name)
        if artifact_name in removed:
            try:
                os.stat(
                    artifact_name,
                    dir_fd=container_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as error:
                cleanup_errors.append(f"{artifact_name}: {error}")
            else:
                cleanup_errors.append(
                    f"{artifact_name}: helper-private artifact reappeared after "
                    "its recorded removal"
                )
            continue
        if expected_identity is None:
            try:
                os.stat(
                    artifact_name,
                    dir_fd=container_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as error:
                cleanup_errors.append(f"{artifact_name}: {error}")
            else:
                cleanup_errors.append(
                    f"{artifact_name}: no {identity_label} identity is available"
                )
            continue
        try:
            current_metadata = _private_artifact_metadata_at(
                container_descriptor,
                artifact_name,
                require_private_mode=False,
            )
        except FileNotFoundError:
            cleanup_errors.append(
                f"{artifact_name}: expected helper-private artifact is missing"
            )
        except ReviewError as error:
            cleanup_errors.append(str(error))
        else:
            if _cleanup_identity_evidence(current_metadata) != expected_identity:
                cleanup_errors.append(
                    f"{artifact_name}: helper-private artifact does not match "
                    f"{identity_label} identity"
                )
            else:
                removable[artifact_name] = current_metadata
    for artifact_name, artifact_metadata in removable.items():
        removal_mask = block_forwarded_signals()
        try:
            quarantine_name, quarantined, artifact_errors = _quarantine_cleanup_entry(
                container_descriptor,
                artifact_name,
                artifact_metadata,
                label=f"helper-private artifact {artifact_name}",
                missing_is_error=True,
            )
            if artifact_errors or quarantine_name is None or quarantined is None:
                cleanup_errors.extend(artifact_errors)
                continue
            artifact_errors.extend(
                _remove_quarantined_cleanup_entry(
                    container_descriptor,
                    quarantine_name,
                    artifact_metadata,
                    label=f"helper-private artifact {artifact_name}",
                    is_directory=False,
                )
            )
            cleanup_errors.extend(artifact_errors)
            if artifact_errors:
                continue
            if record_removal is not None:
                try:
                    record_removal(artifact_name)
                except ReviewError as error:
                    cleanup_errors.append(str(error))
                    continue
        finally:
            restore_signal_mask(removal_mask)
    return cleanup_errors


def _load_bound_private_cleanup_state_at(
    container_descriptor: int,
    *,
    expected: PrivateCleanupEvidence,
) -> ControlArtifactState:
    state = _load_control_artifact_state_at(container_descriptor)
    if state.private_cleanup != expected:
        raise ReviewError(
            "helper-private cleanup state does not match preparation identity"
        )
    return state


def load_bound_private_cleanup_state(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> ControlArtifactState:
    captured: ControlArtifactState | None = None

    def load_bound_state(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        nonlocal captured
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return ["private artifact container does not match preparation identity"]
        try:
            captured = _load_bound_private_cleanup_state_at(
                container_descriptor,
                expected=expected,
            )
        except ReviewError as error:
            return [str(error)]
        return []

    load_error = _operate_on_private_review_container(container, load_bound_state)
    if load_error:
        raise ReviewError(load_error)
    if captured is None:
        raise ReviewError("helper-private cleanup state could not be loaded")
    return captured


def _record_private_artifact_removal_at(
    container_descriptor: int,
    *,
    expected: PrivateCleanupEvidence,
    artifact_name: str,
) -> None:
    state = _load_bound_private_cleanup_state_at(
        container_descriptor,
        expected=expected,
    )
    if artifact_name in state.private_artifacts_removed:
        return
    removed = frozenset((*state.private_artifacts_removed, artifact_name))
    _write_control_artifact_state_at(
        container_descriptor,
        ControlArtifactState(
            artifacts=state.artifacts,
            directory=state.directory,
            private_cleanup=state.private_cleanup,
            private_artifacts_removed=removed,
        ),
    )
    persisted = _load_bound_private_cleanup_state_at(
        container_descriptor,
        expected=expected,
    )
    if persisted.private_artifacts_removed != removed:
        raise ReviewError("helper-private cleanup receipt did not persist")


def remove_private_review_artifacts(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> str | None:
    def unlink_bound_artifacts(
        parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return ["private artifact container does not match preparation identity"]
        try:
            cleanup_state = _load_bound_private_cleanup_state_at(
                container_descriptor,
                expected=expected,
            )
        except ReviewError as error:
            return [str(error)]
        removed = set(cleanup_state.private_artifacts_removed)

        def record_removal(artifact_name: str) -> None:
            _record_private_artifact_removal_at(
                container_descriptor,
                expected=expected,
                artifact_name=artifact_name,
            )
            removed.add(artifact_name)

        cleanup_errors = _unlink_private_review_artifacts(
            parent_descriptor,
            container_descriptor,
            expected=expected,
            removed=frozenset(removed),
            record_removal=record_removal,
        )
        if cleanup_errors:
            return cleanup_errors
        try:
            final_state = _load_bound_private_cleanup_state_at(
                container_descriptor,
                expected=expected,
            )
        except ReviewError as error:
            return [str(error)]
        if final_state.private_artifacts_removed != frozenset(
            PRIVATE_HELPER_ARTIFACT_NAMES
        ):
            return ["helper-private artifact removal receipts are incomplete"]
        return []

    cleanup_error = _operate_on_private_review_container(
        container,
        unlink_bound_artifacts,
    )
    if cleanup_error:
        return cleanup_error
    try:
        final_state = load_bound_private_cleanup_state(
            container,
            expected=expected,
        )
    except ReviewError as error:
        return str(error)
    if final_state.private_artifacts_removed != frozenset(
        PRIVATE_HELPER_ARTIFACT_NAMES
    ):
        return "helper-private artifact removal receipts are incomplete"
    return None


BOUND_REVIEW_TEXT_ARTIFACT_NAMES = frozenset(
    {"cleanup-error.txt", "exit-code", "runner-error.txt"}
)
BOUND_REVIEW_JSON_ARTIFACT_NAMES = frozenset(
    {REVIEW_STATE_MARKER_NAME, "attempts.json"}
)


def _write_bound_review_bytes(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    name: str,
    encoded: bytes,
    artifact_label: str,
) -> str | None:
    def persist_bytes(
        parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return ["private artifact container does not match preparation identity"]

        target_name = name
        temporary_name = f".{target_name}.{uuid.uuid4().hex}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        handle: BinaryIO | None = None
        read_descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=container_descriptor,
            )
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "wb")
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            handle = None
            os.replace(
                temporary_name,
                target_name,
                src_dir_fd=container_descriptor,
                dst_dir_fd=container_descriptor,
            )
            read_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            read_descriptor = os.open(
                target_name,
                read_flags,
                dir_fd=container_descriptor,
            )
            opened = os.fstat(read_descriptor)
            current = os.stat(
                target_name,
                dir_fd=container_descriptor,
                follow_symlinks=False,
            )
            for metadata in (opened, current):
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    return [f"{artifact_label} is not a regular file with one link"]
                if metadata.st_uid != os.geteuid():
                    return [f"{artifact_label} has an unexpected owner"]
                if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    return [f"{artifact_label} must not be group or other writable"]
            if _private_cleanup_identity(opened) != _private_cleanup_identity(current):
                return [f"{artifact_label} changed during persistence"]
            readback = bytearray()
            while len(readback) <= len(encoded):
                chunk = os.read(
                    read_descriptor,
                    min(64 * 1024, len(encoded) + 1 - len(readback)),
                )
                if not chunk:
                    break
                readback.extend(chunk)
            final = os.fstat(read_descriptor)
            current_after = os.stat(
                target_name,
                dir_fd=container_descriptor,
                follow_symlinks=False,
            )
            artifact_states = {
                (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_nlink,
                    metadata.st_uid,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
                for metadata in (opened, current, final, current_after)
            }
            if len(artifact_states) != 1 or bytes(readback) != encoded:
                return [f"{artifact_label} changed during persistence"]
            os.fsync(container_descriptor)
            bound_parent = os.fstat(parent_descriptor)
            canonical_parent = os.lstat(container.parent)
            for metadata in (bound_parent, canonical_parent):
                parent_error = _private_cleanup_directory_error(
                    metadata,
                    label="private artifact parent",
                    require_private_mode=False,
                )
                if parent_error:
                    return [parent_error]
            if _private_cleanup_identity(bound_parent) != _private_cleanup_identity(
                canonical_parent
            ):
                return [
                    "private artifact parent changed after runtime artifact persistence"
                ]
            bound_container = os.stat(
                container.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            canonical_container = os.lstat(container)
            for metadata in (bound_container, canonical_container):
                container_error = _private_cleanup_directory_error(
                    metadata,
                    label="private artifact container",
                    require_private_mode=True,
                )
                if container_error:
                    return [container_error]
            if any(
                _cleanup_identity_evidence(metadata) != expected.container
                for metadata in (bound_container, canonical_container)
            ):
                return [
                    "private artifact container changed after runtime artifact "
                    "persistence"
                ]
        except OSError as error:
            return [f"cannot persist {artifact_label}: {error}"]
        finally:
            if read_descriptor is not None:
                os.close(read_descriptor)
            if handle is not None:
                handle.close()
            elif descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=container_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        return []

    return _operate_on_private_review_container(container, persist_bytes)


def write_bound_review_text(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    name: str,
    text: str,
) -> str | None:
    """Persist one runtime text artifact inside the preparation-bound container."""

    if name not in BOUND_REVIEW_TEXT_ARTIFACT_NAMES:
        return "review runtime text artifact name is not allowed"

    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as error:
        return f"cannot encode runner diagnostic: {error}"
    return _write_bound_review_bytes(
        container,
        expected=expected,
        name=name,
        encoded=encoded,
        artifact_label="review runtime text artifact",
    )


def write_bound_review_json(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    name: str,
    value: Any,
) -> str | None:
    """Persist one runtime JSON artifact inside the preparation-bound container."""

    if name not in BOUND_REVIEW_JSON_ARTIFACT_NAMES:
        return "review runtime JSON artifact name is not allowed"
    try:
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        return f"cannot encode review runtime JSON artifact: {error}"
    return _write_bound_review_bytes(
        container,
        expected=expected,
        name=name,
        encoded=encoded,
        artifact_label="review runtime JSON artifact",
    )


def write_bound_runner_error(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    text: str,
) -> str | None:
    return write_bound_review_text(
        container,
        expected=expected,
        name="runner-error.txt",
        text=text,
    )


def remove_bound_review_text(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    name: str,
) -> str | None:
    """Remove one runtime text artifact from the preparation-bound container."""

    if name not in BOUND_REVIEW_TEXT_ARTIFACT_NAMES:
        return "review runtime text artifact name is not allowed"

    def remove_text(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return ["private artifact container does not match preparation identity"]
        try:
            os.unlink(name, dir_fd=container_descriptor)
        except FileNotFoundError:
            return []
        except OSError as error:
            return [f"cannot remove review runtime text artifact: {error}"]
        try:
            os.fsync(container_descriptor)
        except OSError as error:
            return [f"cannot sync removed review runtime text artifact: {error}"]
        return []

    return _operate_on_private_review_container(container, remove_text)


def open_bound_review_lock(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    name: str,
) -> tuple[BoundReviewLock | None, str | None]:
    """Duplicate the preparation-bound container descriptor for cleanup locking."""

    if name != "cleanup.lock":
        return None, "review runtime lock name is not allowed"

    handle: BoundReviewLock | None = None

    def open_lock(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        nonlocal handle
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return ["private artifact container does not match preparation identity"]

        duplicate: int | None = None
        try:
            duplicate = os.dup(container_descriptor)
            duplicate_identity = _cleanup_identity_evidence(os.fstat(duplicate))
        except OSError as error:
            if duplicate is not None:
                os.close(duplicate)
            return [f"cannot duplicate review runtime lock descriptor: {error}"]
        if duplicate_identity != expected.container:
            os.close(duplicate)
            return ["duplicated review runtime lock changed identity"]
        handle = BoundReviewLock(duplicate)
        return []

    lock_error = _operate_on_private_review_container(container, open_lock)
    if lock_error:
        if handle is not None:
            handle.close()
        return None, lock_error
    if handle is None:
        return None, "review runtime lock was not opened"
    return handle, None


def _remove_review_container_tree(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
    use_control_state: bool,
    identity_label: str = "preparation",
) -> str | None:
    if use_control_state:
        private_cleanup_error = remove_private_review_artifacts(
            container,
            expected=expected,
        )
        if private_cleanup_error:
            return private_cleanup_error

    def remove_tree(
        parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return [
                f"private artifact container does not match {identity_label} identity"
            ]
        if not use_control_state:
            private_cleanup_errors = _unlink_private_review_artifacts(
                parent_descriptor,
                container_descriptor,
                expected=expected,
                removed=frozenset(),
                record_removal=None,
                identity_label=identity_label,
            )
            if private_cleanup_errors:
                return private_cleanup_errors
        private_git_errors = _remove_named_directory_tree(
            container_descriptor,
            "review.git",
            label="private review Git database",
            require_private_mode=False,
            depth_limit=PRIVATE_REVIEW_GIT_CLEANUP_DEPTH,
        )
        if private_git_errors:
            return private_git_errors
        cleanup_errors = _remove_open_directory_tree(
            parent_descriptor,
            container_descriptor,
            container.name,
            label="private artifact container",
            require_private_mode=True,
            excluded_entry_names=frozenset(PRIVATE_HELPER_ARTIFACT_NAMES),
            final_entry_names=(
                (
                    CONTROL_ARTIFACT_STATE_NAME,
                    REVIEW_CLEANUP_LOCK_NAME,
                    REVIEW_RUNNER_LOCK_NAME,
                    REVIEW_STATE_MARKER_NAME,
                )
                if use_control_state
                else (
                    REVIEW_CLEANUP_LOCK_NAME,
                    REVIEW_RUNNER_LOCK_NAME,
                    REVIEW_STATE_MARKER_NAME,
                )
            ),
            quarantine_before_final_entries=True,
        )
        return cleanup_errors

    return _operate_on_private_review_container(container, remove_tree)


def _remove_partial_container(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> str | None:
    return _remove_review_container_tree(
        container,
        expected=expected,
        use_control_state=False,
    )


def remove_partial_review_container(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> str | None:
    """Remove a partial container only while its captured identities still match."""

    return _remove_partial_container(container, expected=expected)


def remove_ready_review_container(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> str | None:
    """Remove a ready container using durable private-artifact receipts."""

    return _remove_review_container_tree(
        container,
        expected=expected,
        use_control_state=True,
    )


def _bound_private_cleanup_target(
    review: ReviewWorkspace | LegacyReviewWorkspace,
) -> pathlib.Path | None:
    source_root = review.source_root.expanduser().absolute()
    container = review.container_dir.expanduser().absolute()
    expected_parent = (
        source_root / ".codex-tmp"
        if isinstance(
            review,
            (LegacyReviewWorkspace, SourceLocalReviewWorkspace),
        )
        else _review_root_for_source(source_root, require_source=False)
    )
    if (
        container.parent != expected_parent
        or REVIEW_CONTAINER_PATTERN.fullmatch(container.name) is None
    ):
        return None
    return container


def _retained_container_detail(container: pathlib.Path, cleanup_error: str) -> str:
    return (
        "review workspace preparation failed and cleanup failed; evidence may "
        f"remain near {container}; inspect cleanup state: {cleanup_error}"
    )


def _review_directory_identity(item: os.stat_result) -> tuple[int, int, int, int]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_uid)


def _canonical_review_root_base() -> pathlib.Path:
    try:
        canonical_base = REVIEW_ROOT_BASE.resolve(strict=True)
        base_status = os.lstat(canonical_base)
    except (OSError, RuntimeError) as error:
        raise ReviewError(f"cannot resolve helper review root: {error}") from error
    if (
        not stat.S_ISDIR(base_status.st_mode)
        or stat.S_ISLNK(base_status.st_mode)
        or base_status.st_uid != 0
        or stat.S_IMODE(base_status.st_mode) != 0o1777
    ):
        raise ReviewError(
            "helper review root base must be a root-owned 01777 real directory: "
            f"{canonical_base}"
        )
    return canonical_base


def _review_root_for_source(
    source_root: pathlib.Path,
    *,
    require_source: bool = True,
) -> pathlib.Path:
    try:
        canonical_source = source_root.resolve(strict=require_source)
    except (OSError, RuntimeError) as error:
        raise ReviewError(f"cannot resolve source repository: {error}") from error
    if require_source and not canonical_source.is_dir():
        raise ReviewError(f"source repository is not a directory: {canonical_source}")
    canonical_base = _canonical_review_root_base()
    digest = hashlib.sha256(os.fsencode(str(canonical_source))).hexdigest()
    review_root = canonical_base / f"{REVIEW_USER_ROOT_PREFIX}{os.geteuid()}" / digest
    if is_relative_to(review_root, canonical_source) or is_relative_to(
        canonical_source, review_root
    ):
        raise ReviewError("helper review root must be outside the source repository")
    return review_root


def _open_or_create_private_review_directory(
    *,
    parent_fd: int,
    parent_path: pathlib.Path,
    name: str,
) -> tuple[pathlib.Path, int]:
    path = parent_path / name
    try:
        path_status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        initially_missing = False
    except FileNotFoundError:
        initially_missing = True
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            # Another creator won after the missing observation. The directory
            # entry is still new relative to our observation and therefore
            # requires the same parent durability barrier.
            pass
        except OSError as error:
            raise ReviewError(
                f"cannot create private review directory {path}: {error}"
            ) from error
        try:
            path_status = os.stat(
                name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ReviewError(
                f"cannot inspect private review directory {path}: {error}"
            ) from error
    except OSError as error:
        raise ReviewError(
            f"cannot inspect private review directory {path}: {error}"
        ) from error
    if (
        not stat.S_ISDIR(path_status.st_mode)
        or stat.S_ISLNK(path_status.st_mode)
        or path_status.st_uid != os.geteuid()
        or stat.S_IMODE(path_status.st_mode) != 0o700
    ):
        raise ReviewError(
            "private review directory must be a current-user-owned 0700 real "
            f"directory: {path}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise ReviewError(
            f"cannot securely open private review directory {path}: {error}"
        ) from error
    try:
        opened_status = os.fstat(descriptor)
        absolute_status = os.lstat(path)
        if (
            not stat.S_ISDIR(opened_status.st_mode)
            or opened_status.st_uid != os.geteuid()
            or stat.S_IMODE(opened_status.st_mode) != 0o700
            or _review_directory_identity(opened_status)
            != _review_directory_identity(path_status)
            or _review_directory_identity(absolute_status)
            != _review_directory_identity(path_status)
        ):
            raise ReviewError(
                f"private review directory changed while opening it securely: {path}"
            )
        if initially_missing:
            try:
                os.fsync(parent_fd)
            except OSError as error:
                raise ReviewError(
                    f"cannot persist private review directory entry for {path}: {error}"
                ) from error
    except BaseException:
        os.close(descriptor)
        raise
    return path, descriptor


def _new_container(
    source_root: pathlib.Path,
) -> tuple[pathlib.Path, int, CleanupIdentity, set[signal.Signals] | None]:
    handoff_mask = block_forwarded_signals()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = uuid.uuid4().hex[:10]
    review_root = _review_root_for_source(source_root)
    container: pathlib.Path | None = None
    container_descriptor: int | None = None
    container_identity: CleanupIdentity | None = None
    base_descriptor: int | None = None
    user_descriptor: int | None = None
    review_root_descriptor: int | None = None
    try:
        canonical_base = review_root.parents[1]
        try:
            base_before = os.lstat(canonical_base)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect helper review root base {canonical_base}: {error}"
            ) from error
        try:
            base_descriptor = os.open(
                canonical_base,
                _private_cleanup_directory_flags(),
            )
        except OSError as error:
            raise ReviewError(
                f"cannot securely open helper review root base {canonical_base}: {error}"
            ) from error
        base_opened = os.fstat(base_descriptor)
        base_after = os.lstat(canonical_base)
        if (
            any(
                not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                for metadata in (base_before, base_opened, base_after)
            )
            or any(
                metadata.st_uid != 0
                for metadata in (base_before, base_opened, base_after)
            )
            or any(
                stat.S_IMODE(metadata.st_mode) != 0o1777
                for metadata in (base_before, base_opened, base_after)
            )
            or len(
                {
                    _private_cleanup_identity(base_before),
                    _private_cleanup_identity(base_opened),
                    _private_cleanup_identity(base_after),
                }
            )
            != 1
        ):
            raise ReviewError("helper review root base changed while opening it")

        user_root, user_descriptor = _open_or_create_private_review_directory(
            parent_fd=base_descriptor,
            parent_path=canonical_base,
            name=review_root.parent.name,
        )
        source_review_root, review_root_descriptor = (
            _open_or_create_private_review_directory(
                parent_fd=user_descriptor,
                parent_path=user_root,
                name=review_root.name,
            )
        )
        if source_review_root != review_root:
            raise ReviewError("private review namespace resolved to an unexpected path")

        name = f"isolated-review-{stamp}-{suffix}"
        container = review_root / name
        os.mkdir(name, mode=0o700, dir_fd=review_root_descriptor)
        descriptor_status = os.stat(
            name,
            dir_fd=review_root_descriptor,
            follow_symlinks=False,
        )
        container_descriptor = os.open(
            name,
            _private_cleanup_directory_flags(),
            dir_fd=review_root_descriptor,
        )
        opened_status = os.fstat(container_descriptor)
        if _private_cleanup_identity(descriptor_status) != (
            _private_cleanup_identity(opened_status)
        ):
            raise ReviewError(
                "private review container changed while opening it securely"
            )
        container_identity = _cleanup_identity_evidence(opened_status)
        path_status = os.lstat(container)
        if (
            not stat.S_ISDIR(descriptor_status.st_mode)
            or descriptor_status.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor_status.st_mode) != 0o700
            or _private_cleanup_identity(descriptor_status)
            != _private_cleanup_identity(path_status)
        ):
            raise ReviewError(
                "review root changed while creating the private container"
            )
        if _review_directory_identity(os.fstat(user_descriptor)) != (
            _review_directory_identity(os.lstat(user_root))
        ) or _review_directory_identity(os.fstat(review_root_descriptor)) != (
            _review_directory_identity(os.lstat(source_review_root))
        ):
            raise ReviewError(
                "private review namespace changed while creating the container"
            )
        try:
            os.fsync(review_root_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot persist the private review container directory entry: {error}"
            ) from error
        if container_descriptor is None or container_identity is None:
            raise ReviewError("private review container identity was not captured")
        return container, container_descriptor, container_identity, handoff_mask
    except BaseException as error:
        cleanup_error: str | None = None
        if container_descriptor is not None:
            os.close(container_descriptor)
            container_descriptor = None
        if container is not None and container_identity is not None:
            cleanup_error = _remove_partial_container(
                container,
                expected=PrivateCleanupEvidence(
                    container=container_identity,
                    artifacts={},
                ),
            )
        elif container is not None:
            cleanup_error = "private container identity was not captured"
        cleanup_signal = (
            consume_pending_forwarded_signal() if handoff_mask is not None else None
        )
        try:
            restore_signal_mask(handoff_mask)
        except ForwardedSignal as forwarded:
            detail = forwarded.detail
            if detail is None and container is not None and cleanup_error:
                detail = _retained_container_detail(container, cleanup_error)
            raise ForwardedSignal(forwarded.signum, detail=detail) from error
        if cleanup_signal is not None:
            detail = (
                _retained_container_detail(container, cleanup_error)
                if container is not None and cleanup_error
                else None
            )
            raise ForwardedSignal(cleanup_signal, detail=detail) from error
        if container is not None and cleanup_error:
            raise ReviewError(
                _retained_container_detail(container, cleanup_error)
            ) from error
        raise
    finally:
        for descriptor in (
            review_root_descriptor,
            user_descriptor,
            base_descriptor,
        ):
            if descriptor is not None:
                os.close(descriptor)


def _iter_nul_records(
    stream: BinaryIO,
    *,
    byte_limit: int | None = None,
    record_limit: int | None = None,
    label: str = "Git metadata",
) -> Iterator[bytes]:
    pending = bytearray()
    total_bytes = 0
    records = 0
    while chunk := stream.read(64 * 1024):
        total_bytes += len(chunk)
        if byte_limit is not None and total_bytes > byte_limit:
            raise ReviewError(f"{label} exceeds the {byte_limit}-byte review limit")
        pending.extend(chunk)
        while True:
            boundary = pending.find(0)
            if boundary < 0:
                break
            records += 1
            if record_limit is not None and records > record_limit:
                raise ReviewError(
                    f"{label} exceeds the {record_limit}-entry review limit"
                )
            yield bytes(pending[:boundary])
            del pending[: boundary + 1]
    if pending:
        raise ReviewError(f"unterminated record from {label}")


def _parse_tree_record(record: bytes) -> tuple[str, str, str, pathlib.PurePosixPath]:
    try:
        metadata, raw_path = record.split(b"\t", 1)
        raw_mode, raw_type, raw_object = metadata.split(b" ", 2)
        mode = raw_mode.decode("ascii")
        object_type = raw_type.decode("ascii")
        object_id = raw_object.decode("ascii")
        relative = pathlib.PurePosixPath(os.fsdecode(raw_path))
    except (UnicodeDecodeError, ValueError) as error:
        raise ReviewError("malformed record from git ls-tree") from error
    path_display = _redact_secret_path(os.fsdecode(raw_path), "snapshot path")
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ReviewError(f"unsafe path in frozen Git tree: {path_display}")
    if any(part.casefold() == ".git" for part in relative.parts):
        raise ReviewError(f"reserved .git path in frozen Git tree: {path_display}")
    return mode, object_type, object_id, relative


def _uses_review_cleanup_quarantine_namespace(
    relative: pathlib.PurePosixPath,
) -> bool:
    return any(
        part.startswith(REVIEW_CLEANUP_QUARANTINE_PREFIX) for part in relative.parts
    )


def _exact_path_matcher(needles: dict[bytes, str]) -> LegacyPathMatcher:
    transitions: list[dict[int, int]] = [{}]
    failures = [0]
    identifiers: list[str | None] = [None]
    for needle, identifier in sorted(needles.items()):
        state = 0
        for byte in needle:
            next_state = transitions[state].get(byte)
            if next_state is None:
                next_state = len(transitions)
                transitions[state][byte] = next_state
                transitions.append({})
                failures.append(0)
                identifiers.append(None)
            state = next_state
        current = identifiers[state]
        identifiers[state] = identifier if current is None else min(current, identifier)

    pending: deque[int] = deque()
    for state in transitions[0].values():
        pending.append(state)
    while pending:
        state = pending.popleft()
        for byte, next_state in transitions[state].items():
            pending.append(next_state)
            fallback = failures[state]
            while fallback and byte not in transitions[fallback]:
                fallback = failures[fallback]
            failures[next_state] = transitions[fallback].get(byte, 0)
            inherited = identifiers[failures[next_state]]
            current = identifiers[next_state]
            if inherited is not None:
                identifiers[next_state] = (
                    inherited if current is None else min(current, inherited)
                )
    return LegacyPathMatcher(
        transitions=tuple(transitions),
        failures=tuple(failures),
        identifiers=tuple(identifiers),
        maximum_length=max(map(len, needles), default=0),
    )


def _legacy_path_matcher(
    legacy_values: Iterable[AcceptedSyntheticValue],
) -> LegacyPathMatcher:
    needles: dict[bytes, str] = {}
    for descriptor in legacy_values:
        if descriptor.kind != "legacy" or descriptor.value is None:
            raise ReviewError(
                "legacy path validation requires exact catalog-backed values"
            )
        needle = descriptor.value
        previous = needles.get(needle)
        if previous is None or descriptor.identifier < previous:
            needles[needle] = descriptor.identifier
    return _exact_path_matcher(needles)


def _secret_reduction_path_matcher(
    reduction_values: Iterable[AcceptedSyntheticValue],
) -> LegacyPathMatcher:
    needles: dict[bytes, str] = {}
    for descriptor in reduction_values:
        if descriptor.kind != "secret-reduction" or descriptor.value is None:
            raise ReviewError("secret-reduction path validation requires exact values")
        needle = descriptor.value
        previous = needles.get(needle)
        if previous is None or descriptor.identifier < previous:
            needles[needle] = descriptor.identifier
    return _exact_path_matcher(needles)


def _reject_values_in_frozen_tree_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    matcher: LegacyPathMatcher,
    match_message: str,
    failure_label: str,
) -> None:
    if len(matcher.transitions) == 1:
        return
    with _temporary_review_file() as output:
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", commit),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=output,
            label="frozen Git path validation metadata",
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            record_separator=b"\0",
        )
        output.seek(0)
        for record in _iter_nul_records(
            output,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="frozen Git path validation metadata",
        ):
            _metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise ReviewError("malformed record from git ls-tree")
            identifier = matcher.match(raw_path)
            if identifier is not None:
                raise ReviewError(f"{match_message}: {identifier}")
            _parse_tree_record(record)


def _reject_legacy_values_in_frozen_tree_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    legacy_values: Iterable[AcceptedSyntheticValue],
) -> None:
    _reject_values_in_frozen_tree_paths(
        git_view=git_view,
        object_directory=object_directory,
        commit=commit,
        matcher=_legacy_path_matcher(legacy_values),
        match_message=(
            "legacy synthetic fixture values and storage encodings are not "
            "allowed in repository paths"
        ),
        failure_label="legacy synthetic-token",
    )


def _reject_secret_reduction_values_in_frozen_tree_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    reduction_values: Iterable[AcceptedSyntheticValue],
) -> None:
    _reject_values_in_frozen_tree_paths(
        git_view=git_view,
        object_directory=object_directory,
        commit=commit,
        matcher=_secret_reduction_path_matcher(reduction_values),
        match_message=(
            "unregistered secret values and storage encodings are not allowed "
            "in the frozen head paths"
        ),
        failure_label="unregistered secret path",
    )


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(min(64 * 1024, size - len(value)))
        if not chunk:
            raise ReviewError("unexpected end of git cat-file output")
        value.extend(chunk)
    return bytes(value)


def _go_is_space(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x09 <= codepoint <= 0x0D
        or codepoint
        in {
            0x20,
            0x85,
            0xA0,
            0x1680,
            0x2028,
            0x2029,
            0x202F,
            0x205F,
            0x3000,
        }
        or 0x2000 <= codepoint <= 0x200A
    )


def _go_bytes_trim_space(payload: bytes) -> bytes:
    text = payload.decode("utf-8", errors="surrogateescape")
    start = 0
    end = len(text)
    while start < end and _go_is_space(text[start]):
        start += 1
    while end > start and _go_is_space(text[end - 1]):
        end -= 1
    return text[start:end].encode("utf-8", errors="surrogateescape")


def _go_scan_lines(payload: bytes) -> list[bytes]:
    if not payload:
        return []
    records = payload.split(b"\n")
    if payload.endswith(b"\n"):
        records.pop()
    return [record[:-1] if record.endswith(b"\r") else record for record in records]


def _is_git_lfs_pointer(payload: bytes) -> bool:
    if not payload or len(payload) >= GIT_LFS_POINTER_MAX_BYTES:
        return False

    pointer_keys = (b"version", b"oid", b"size")
    core: dict[bytes, bytes] = {}
    extensions: dict[bytes, bytes] = {}
    line = 0
    for record in _go_scan_lines(_go_bytes_trim_space(payload)):
        if not record:
            continue
        parts = record.split(b" ", 1)
        if len(parts) != 2 or line >= len(pointer_keys):
            return False
        key, value = parts
        if key != pointer_keys[line]:
            if GIT_LFS_EXTENSION_PREFIX_PATTERN.match(key) is None:
                return False
            extensions[key] = value
            continue
        core[key] = value
        line += 1

    if core.get(b"version") not in GIT_LFS_V1_ALIASES:
        return False
    if GIT_LFS_OID_PATTERN.fullmatch(core.get(b"oid", b"")) is None:
        return False
    size_bytes = core.get(b"size", b"")
    if GIT_LFS_SIZE_PATTERN.fullmatch(size_bytes) is None:
        return False
    parsed_size = int(size_bytes, 10)
    if parsed_size < 0 or parsed_size > (1 << 63) - 1:
        return False

    priorities: set[int] = set()
    for key, value in extensions.items():
        key_parts = key.split(b"-", 2)
        if len(key_parts) != 3 or key_parts[0] != b"ext":
            return False
        priority = int(key_parts[1], 10)
        if priority in priorities:
            return False
        priorities.add(priority)
        if GIT_LFS_OID_PATTERN.fullmatch(value) is None:
            return False
    return True


def _copy_exact(stream: BinaryIO, destination: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ReviewError("unexpected end of git cat-file output")
        destination.write(chunk)
        remaining -= len(chunk)


def _copy_limited(
    stream: BinaryIO,
    destination: BinaryIO,
    *,
    limit: int,
    label: str,
    record_limit: int | None = None,
) -> int:
    copied = 0
    records = 0
    while chunk := stream.read(1024 * 1024):
        copied += len(chunk)
        if copied > limit:
            raise ReviewError(f"{label} exceeds the {limit}-byte review limit")
        if record_limit is not None:
            records += chunk.count(b"\0")
            if records > record_limit:
                raise ReviewError(
                    f"{label} exceeds the {record_limit}-entry review limit"
                )
        destination.write(chunk)
    return copied


def _normalize_frozen_directory_mode(
    directory: pathlib.Path,
    *,
    label: str,
) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(directory, flags)
        initial = os.fstat(descriptor)
        if not stat.S_ISDIR(initial.st_mode) or initial.st_uid != os.geteuid():
            raise ReviewError(f"{label} is unsafe")
        os.fchmod(descriptor, 0o755)
        final = os.fstat(descriptor)
        if (
            (initial.st_dev, initial.st_ino) != (final.st_dev, final.st_ino)
            or not stat.S_ISDIR(final.st_mode)
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o755
        ):
            raise ReviewError(f"{label} mode normalization failed")
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"cannot normalize {label} mode: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _mkdir_frozen_tree_parents(
    workspace_root: pathlib.Path,
    directory: pathlib.Path,
) -> None:
    try:
        relative = directory.relative_to(workspace_root)
    except ValueError as error:
        raise ReviewError("frozen Git tree parent escapes workspace") from error
    current = workspace_root
    for component in relative.parts:
        current /= component
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            pass
        _normalize_frozen_directory_mode(
            current,
            label="frozen Git tree parent directory",
        )


def _materialize_blob(
    *,
    cat_input: BinaryIO | None,
    cat_output: BinaryIO,
    workspace_root: pathlib.Path,
    destination: pathlib.Path,
    object_id: str,
    mode: str,
    materialized_bytes: int,
    legacy_value_matcher: LegacyPathMatcher,
) -> int:
    destination_display = _redact_secret_path(
        os.fspath(destination),
        "snapshot path",
    )
    if cat_input is not None:
        cat_input.write(object_id.encode("ascii") + b"\n")
        cat_input.flush()
    header = cat_output.readline()
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3:
        raise ReviewError(f"unexpected git cat-file header: {header!r}")
    actual_object, object_type, raw_size = fields
    try:
        size = int(raw_size)
    except ValueError as error:
        raise ReviewError(f"invalid git cat-file blob size: {header!r}") from error
    if size < 0:
        raise ReviewError(f"invalid git cat-file blob size: {header!r}")
    try:
        actual_object_id = actual_object.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReviewError(f"invalid git cat-file object id: {header!r}") from error
    if actual_object_id != object_id or object_type != b"blob":
        raise ReviewError(f"unexpected git cat-file object: {header!r}")

    if mode != "120000" and size > MAX_SNAPSHOT_BLOB_BYTES:
        raise ReviewError(
            "frozen Git tree blob exceeds the per-file review limit: "
            f"{destination_display}"
        )
    if size > MAX_SNAPSHOT_BYTES - materialized_bytes:
        raise ReviewError("frozen Git tree exceeds the total review snapshot limit")

    resolved_parent = destination.parent.resolve(strict=False)
    if not is_relative_to(resolved_parent, workspace_root.resolve(strict=False)):
        raise ReviewError(
            f"frozen Git tree path escapes workspace: {destination_display}"
        )
    buffered_payload: bytes | None = None
    delimiter_consumed = False
    if mode in {"100644", "100755"} and 0 < size < GIT_LFS_POINTER_MAX_BYTES:
        buffered_payload = _read_exact(cat_output, size)
        if cat_output.read(1) != b"\n":
            raise ReviewError("missing delimiter after git cat-file blob")
        delimiter_consumed = True
        if _is_git_lfs_pointer(buffered_payload):
            raise ReviewError(
                "blocked-checkout-lfs-pointer: review_status=not-run: "
                f"{destination_display}"
            )

    _mkdir_frozen_tree_parents(workspace_root, destination.parent)

    if mode == "120000":
        if size > 16 * 1024:
            raise ReviewError(
                f"oversized symlink target in frozen Git tree: {destination_display}"
            )
        target_bytes = _read_exact(cat_output, size)
        if b"\0" in target_bytes:
            raise ReviewError(
                f"NUL in frozen Git tree symlink target: {destination_display}"
            )
        target_text = os.fsdecode(target_bytes)
        link_relative_path = pathlib.PurePosixPath(
            destination.relative_to(workspace_root).as_posix()
        )
        if not symlink_target_stays_within_workspace(
            link_relative_path,
            target_text,
        ):
            target_display = (
                "<redacted symlink target>"
                if legacy_value_matcher.match(target_bytes) is not None
                else _redact_secret_path(target_text, "symlink target")
            )
            raise ReviewError(
                "frozen Git tree symlink escapes workspace: "
                f"{destination_display} -> {target_display}"
            )
        try:
            target = (destination.parent / target_text).resolve(strict=False)
        except RuntimeError as error:
            raise ReviewError(
                f"symlink loop in frozen Git tree: {destination_display}"
            ) from error
        if not is_relative_to(target, workspace_root.resolve(strict=False)):
            target_display = (
                "<redacted symlink target>"
                if legacy_value_matcher.match(target_bytes) is not None
                else _redact_secret_path(target_text, "symlink target")
            )
            raise ReviewError(
                "frozen Git tree symlink escapes workspace: "
                f"{destination_display} -> {target_display}"
            )
        destination.symlink_to(target_text)
    elif mode in {"100644", "100755"}:
        with destination.open("xb") as handle:
            if buffered_payload is None:
                _copy_exact(cat_output, handle, size)
            else:
                handle.write(buffered_payload)
        destination.chmod(0o755 if mode == "100755" else 0o644)
    else:
        raise ReviewError(
            f"unsupported mode in frozen Git tree: {mode} {destination_display}"
        )
    if not delimiter_consumed and cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after git cat-file blob")
    return materialized_bytes + size


def _close_pipe(stream: BinaryIO | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _process_stderr(handle: BinaryIO) -> str:
    handle.flush()
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    handle.seek(max(0, size - 64 * 1024))
    return handle.read().decode("utf-8", errors="replace").strip()


def _materialize_frozen_tree(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    head_sha: str,
    workspace_root: pathlib.Path,
    legacy_value_matcher: LegacyPathMatcher,
) -> None:
    if workspace_root.exists():
        if not workspace_root.is_dir() or workspace_root.is_symlink():
            raise ReviewError("detached review worktree root is not a real directory")
        entries = {item.name for item in workspace_root.iterdir()}
        if entries != {".git"}:
            raise ReviewError(
                "detached review worktree contains unexpected files before materialization"
            )
    else:
        workspace_root.mkdir(mode=0o755)
    _normalize_frozen_directory_mode(
        workspace_root,
        label="detached review worktree root",
    )
    with (
        _temporary_review_file() as tree_metadata,
        _temporary_review_file() as batch_input,
        _temporary_review_file() as batch_output,
    ):
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", head_sha),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=tree_metadata,
            label="frozen Git tree metadata",
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            record_separator=b"\0",
        )
        tree_metadata.seek(0)
        blob_count = 0
        for record in _iter_nul_records(
            tree_metadata,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="frozen Git tree metadata",
        ):
            mode, object_type, object_id, _relative = _parse_tree_record(record)
            if mode == "160000" and object_type == "commit":
                continue
            if object_type != "blob":
                raise ReviewError("unsupported object in frozen Git tree")
            batch_input.write(object_id.encode("ascii") + b"\n")
            blob_count += 1
        if blob_count:
            batch_input.seek(0)
            _run_bounded_process_to_file(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                environment=_git_environment(object_directory=object_directory),
                input_handle=batch_input,
                destination=batch_output,
                label="frozen Git batch blobs",
                byte_limit=MAX_SNAPSHOT_BYTES + MAX_TREE_METADATA_BYTES,
            )
        tree_metadata.seek(0)
        batch_output.seek(0)
        materialized_bytes = 0
        for record in _iter_nul_records(
            tree_metadata,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="frozen Git tree metadata",
        ):
            mode, object_type, object_id, relative = _parse_tree_record(record)
            if _uses_review_cleanup_quarantine_namespace(relative):
                raise ReviewError(
                    "the frozen head uses a reserved review cleanup quarantine "
                    "path component"
                )
            is_gitlink = mode == "160000" and object_type == "commit"
            cleanup_depth = len(relative.parts) + (1 if is_gitlink else 0)
            if cleanup_depth >= MAX_REVIEW_CLEANUP_DEPTH:
                raise ReviewError(
                    "frozen Git tree path depth exceeds the review cleanup safety limit"
                )
            destination = workspace_root.joinpath(*relative.parts)
            path_display = _redact_secret_path(
                os.fspath(relative),
                "snapshot path",
            )
            try:
                if is_gitlink:
                    resolved_parent = destination.parent.resolve(strict=False)
                    if not is_relative_to(
                        resolved_parent, workspace_root.resolve(strict=False)
                    ):
                        raise ReviewError(
                            f"frozen Git tree path escapes workspace: {path_display}"
                        )
                    _mkdir_frozen_tree_parents(workspace_root, destination.parent)
                    destination.mkdir(mode=0o755, exist_ok=False)
                    _normalize_frozen_directory_mode(
                        destination,
                        label="materialized Gitlink directory",
                    )
                    continue
                if object_type != "blob":
                    raise ReviewError(
                        "unsupported object in frozen Git tree: "
                        f"{object_type} {path_display}"
                    )
                materialized_bytes = _materialize_blob(
                    cat_input=None,
                    cat_output=batch_output,
                    workspace_root=workspace_root,
                    destination=destination,
                    object_id=object_id,
                    mode=mode,
                    materialized_bytes=materialized_bytes,
                    legacy_value_matcher=legacy_value_matcher,
                )
            except OSError as error:
                error_code = (
                    f" (errno {error.errno})" if error.errno is not None else ""
                )
                raise ReviewError(
                    "filesystem error while materializing frozen Git tree path "
                    f"{path_display}{error_code}"
                ) from error
        if batch_output.read(1):
            raise ReviewError(
                "frozen Git batch output contains unexpected trailing data"
            )


def _open_new_private_binary(
    path: pathlib.Path,
    *,
    identity_handoff: Callable[[CleanupIdentity], None] | None = None,
    parent_descriptor: int | None = None,
) -> BinaryIO:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    creation_mask = block_forwarded_signals() if identity_handoff is not None else None
    descriptor: int | None = None
    try:
        target: pathlib.Path | str = (
            path.name if parent_descriptor is not None else path
        )
        descriptor = os.open(
            target,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        if identity_handoff is not None:
            identity_handoff(_cleanup_identity_evidence(os.fstat(descriptor)))
        if creation_mask is not None:
            mask_to_restore = creation_mask
            creation_mask = None
            restore_signal_mask(mask_to_restore)
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        return handle
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        if creation_mask is not None:
            restore_signal_mask(creation_mask)


def _validate_prepared_private_metadata(
    metadata: os.stat_result,
    *,
    artifact_name: str,
    expected_identity: CleanupIdentity,
    require_empty: bool,
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ReviewError(
            f"prepared helper-private artifact {artifact_name} is not a "
            "regular file with one link"
        )
    if metadata.st_uid != os.geteuid():
        raise ReviewError(
            f"prepared helper-private artifact {artifact_name} has an unexpected owner"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ReviewError(
            f"prepared helper-private artifact {artifact_name} must have mode 0600"
        )
    if require_empty and metadata.st_size != 0:
        raise ReviewError(
            f"prepared helper-private artifact {artifact_name} is not empty"
        )
    if _cleanup_identity_evidence(metadata) != expected_identity:
        raise ReviewError(
            f"prepared helper-private artifact {artifact_name} does not match its "
            "preparation identity"
        )


@contextmanager
def _open_prepared_private_binary(
    path: pathlib.Path,
    *,
    expected_identity: CleanupIdentity,
    parent_descriptor: int,
) -> Iterator[BinaryIO]:
    if path.name not in PRIVATE_HELPER_ARTIFACT_NAMES:
        raise ReviewError("prepared helper-private artifact name is not allowed")
    flags = (
        os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        before = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        after = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        for metadata in (before, opened, after):
            _validate_prepared_private_metadata(
                metadata,
                artifact_name=path.name,
                expected_identity=expected_identity,
                require_empty=True,
            )
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        try:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
            opened_after_write = os.fstat(handle.fileno())
            path_after_write = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            for metadata in (opened_after_write, path_after_write):
                _validate_prepared_private_metadata(
                    metadata,
                    artifact_name=path.name,
                    expected_identity=expected_identity,
                    require_empty=False,
                )
        finally:
            handle.close()
    except FileNotFoundError as error:
        raise ReviewError(
            f"prepared helper-private artifact {path.name} is missing"
        ) from error
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            f"cannot securely access prepared helper-private artifact {path.name}: "
            f"{error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_frozen_diff(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    with _open_new_private_binary(destination) as output:
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=(
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--binary",
                    "--submodule=short",
                    base_sha,
                    head_sha,
                ),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=output,
            label="frozen review diff",
            byte_limit=MAX_DIFF_BYTES,
        )


def _write_limited_diff_metadata(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    args: tuple[str, ...],
    output: BinaryIO,
    label: str,
    record_limit: int,
) -> None:
    _run_bounded_process_to_file(
        _frozen_command(git_view=git_view, args=args),
        environment=_git_environment(object_directory=object_directory),
        destination=output,
        label=label,
        byte_limit=MAX_CHANGED_METADATA_BYTES,
        record_limit=record_limit,
        record_separator=b"\0",
    )


def _changed_path_digest(side_tag: bytes, raw_path: bytes) -> bytes:
    return (
        hashlib.sha256(CHANGED_PATH_DIGEST_DOMAIN + side_tag + b"\0" + raw_path)
        .hexdigest()
        .encode("ascii")
    )


def _write_frozen_changed_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
    private_destination: pathlib.Path,
    evidence_sensitive_values: Iterable[AcceptedSyntheticValue],
    private_expected_identity: CleanupIdentity,
    private_parent_descriptor: int,
) -> None:
    digest_evidence: list[str] = []
    with _temporary_review_file() as raw_metadata:
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--name-status",
                "-z",
                # Classify paths by side: renames become D/A and copies remain A.
                "--no-renames",
                "--diff-filter=ADMTUXB",
                base_sha,
                head_sha,
            ),
            output=raw_metadata,
            label="frozen changed paths",
            record_limit=MAX_CHANGED_ENTRIES * 2,
        )
        raw_metadata.seek(0)
        metadata_records = _iter_nul_records(
            raw_metadata,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES * 2,
            label="frozen changed paths",
        )
        logical_record_count = 0
        private_bytes = 0
        with (
            _open_prepared_private_binary(
                private_destination,
                expected_identity=private_expected_identity,
                parent_descriptor=private_parent_descriptor,
            ) as private_output,
            _open_new_private_binary(destination) as public_output,
        ):
            while (status := next(metadata_records, None)) is not None:
                raw_path = next(metadata_records, None)
                if raw_path is None:
                    raise ReviewError(
                        "frozen changed path metadata is missing a path record"
                    )
                if status == b"D":
                    side_tag = CHANGED_PATH_BASE_ONLY_TAG
                elif status in {b"A", b"M", b"T", b"U", b"X", b"B"}:
                    side_tag = CHANGED_PATH_HEAD_TAG
                else:
                    raise ReviewError(
                        "frozen changed path metadata contains an unknown status"
                    )
                if not raw_path:
                    raise ReviewError("frozen changed paths contain an empty path")
                logical_record_count += 1
                if logical_record_count > MAX_CHANGED_ENTRIES:
                    raise ReviewError(
                        "frozen changed paths exceed the review entry-count limit"
                    )
                private_record = side_tag + raw_path
                private_bytes += len(private_record) + 1
                if private_bytes > MAX_CHANGED_METADATA_BYTES:
                    raise ReviewError(
                        "frozen changed paths exceed the review byte limit"
                    )
                digest = _changed_path_digest(side_tag, raw_path)
                digest_evidence.append(digest.decode("ascii"))
                private_output.write(private_record + b"\0")
                public_output.write(digest + b"\0")
    _reject_raw_values_in_evidence(
        digest_evidence,
        accepted_values=evidence_sensitive_values,
        label="frozen changed path digest evidence",
    )


def _bounded_json_bytes(
    value: dict[str, Any],
    *,
    label: str,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
    except (TypeError, ValueError) as error:
        raise ReviewError(f"{label} is not safely JSON serializable") from error
    encoded_bytes = encoded.encode("utf-8")
    if len(encoded_bytes) > MAX_SYNTHETIC_EVIDENCE_BYTES:
        raise ReviewError(f"{label} exceeds the audit evidence size limit")
    _reject_raw_values_in_evidence(
        value,
        accepted_values=accepted_values,
        label=label,
    )
    return encoded_bytes


def _write_bounded_json(
    path: pathlib.Path,
    value: dict[str, Any],
    *,
    label: str,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
) -> None:
    encoded = _bounded_json_bytes(
        value,
        label=label,
        accepted_values=accepted_values,
    )
    write_text_atomic(path, encoded.decode("utf-8"))


def _write_private_bounded_json(
    path: pathlib.Path,
    value: dict[str, Any],
    *,
    label: str,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
    expected_identity: CleanupIdentity,
    parent_descriptor: int,
) -> None:
    encoded = _bounded_json_bytes(
        value,
        label=label,
        accepted_values=accepted_values,
    )
    with _open_prepared_private_binary(
        path,
        expected_identity=expected_identity,
        parent_descriptor=parent_descriptor,
    ) as handle:
        handle.write(encoded)


def _iter_evidence_strings(value: Any) -> Iterator[bytes]:
    if isinstance(value, str):
        try:
            yield os.fsencode(value)
        except UnicodeEncodeError as error:
            raise ReviewError(
                "synthetic-token evidence contains an invalid string"
            ) from error
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_evidence_strings(key)
            yield from _iter_evidence_strings(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_evidence_strings(item)
        return
    if type(value) is float and not math.isfinite(value):
        raise ReviewError("synthetic-token evidence contains a non-finite number")
    if value is None or type(value) in {bool, int, float}:
        yield json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        return
    raise ReviewError("synthetic-token evidence contains an unsupported value")


def _reject_raw_values_in_evidence(
    value: Any,
    *,
    accepted_values: Iterable[AcceptedSyntheticValue],
    label: str,
) -> None:
    exact_values: list[bytes] = []
    digest_values: dict[int, set[str]] = {}
    for accepted in accepted_values:
        if accepted.value is not None:
            exact_values.append(accepted.value)
            continue
        digest_values.setdefault(accepted.value_length, set()).add(
            accepted.value_sha256
        )
    for metadata in set(_iter_evidence_strings(value)):
        if any(raw_value in metadata for raw_value in exact_values):
            raise ReviewError(f"{label} would expose a raw synthetic value")
        for length, digests in digest_values.items():
            if length > len(metadata):
                continue
            for start in range(len(metadata) - length + 1):
                candidate = metadata[start : start + length]
                if hashlib.sha256(candidate).hexdigest() in digests:
                    raise ReviewError(f"{label} would expose a raw synthetic value")


def _accepted_evidence_entry(
    accepted: AcceptedSyntheticValue,
    *,
    surface: str,
    side: str,
    path_sha256: str,
    occurrence_count: int,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "catalog_version": accepted.catalog_version,
        "kind": accepted.kind,
        "occurrence_count": occurrence_count,
        "path": {"sha256": path_sha256},
        "rule": accepted.rule,
        "side": side,
        "surface": surface,
        "token_id": accepted.identifier,
        "value_sha256": accepted.value_sha256,
    }
    if accepted.exemption_id is not None:
        entry["exemption_id"] = accepted.exemption_id
    return entry


def _record_bounded_evidence_count(
    counts: Counter[tuple[Any, ...]],
    key: tuple[Any, ...],
    count: int,
    *,
    reserved_entries: int,
    overflow_message: str,
) -> None:
    if not 0 <= reserved_entries <= MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("accepted synthetic-token evidence reservation is invalid")
    if (
        key not in counts
        and reserved_entries + len(counts) >= MAX_SYNTHETIC_EVIDENCE_ENTRIES
    ):
        raise ReviewError(overflow_message)
    counts[key] += count


def _scan_batch_blob(
    *,
    cat_input: BinaryIO | None,
    cat_output: BinaryIO,
    object_id: str,
    scanned_bytes: int,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
    raw_occurrence_values: Iterable[AcceptedSyntheticValue] = (),
    capture_accepted_candidates: bool = False,
    capture_blocking_candidates: bool = False,
    capture_reduction_offsets: bool = False,
    reduced_secret_values: frozenset[bytes] = frozenset(),
    accepted_index: AcceptedValueIndex | None = None,
    event_budget: SecretScanBudget | None = None,
    exact_index: ExactValueIndex | None = None,
    occurrence_budget: LegacyOccurrenceBudget | None = None,
    exact_only: bool = False,
    _continue_after_blocking: bool = False,
) -> tuple[SecretScanResult, int]:
    if cat_input is not None:
        cat_input.write(object_id.encode("ascii") + b"\n")
        cat_input.flush()
    header = cat_output.readline()
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3 or fields[1] != b"blob":
        raise ReviewError(f"unexpected git cat-file scan header: {header!r}")
    try:
        actual_object = fields[0].decode("ascii")
        size = int(fields[2])
    except (UnicodeDecodeError, ValueError) as error:
        raise ReviewError(f"invalid git cat-file scan header: {header!r}") from error
    if actual_object != object_id:
        raise ReviewError(f"unexpected git cat-file scan object: {header!r}")
    if size > MAX_SNAPSHOT_BLOB_BYTES:
        raise ReviewError("changed Git blob exceeds the per-file review scan limit")
    if size > MAX_CHANGED_BLOB_SCAN_BYTES - scanned_bytes:
        raise ReviewError("changed Git blobs exceed the total review scan limit")
    scan = _stream_secret_scan(
        cat_output,
        size=size,
        accepted_values=accepted_values,
        raw_occurrence_values=raw_occurrence_values,
        capture_accepted_candidates=capture_accepted_candidates,
        capture_blocking_candidates=capture_blocking_candidates,
        capture_reduction_offsets=capture_reduction_offsets,
        reduced_secret_values=reduced_secret_values,
        _accepted_index=accepted_index,
        _event_budget=event_budget,
        _exact_index=exact_index,
        _occurrence_budget=occurrence_budget,
        exact_only=exact_only,
        _continue_after_blocking=_continue_after_blocking,
    )
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after scanned git cat-file blob")
    return scan, scanned_bytes + size


def _secret_reduction_occurrence_identity(
    *,
    raw_path: bytes,
    git_mode: str,
    offset: int,
) -> str:
    if git_mode not in {"100644", "100755", "120000"}:
        raise ReviewError("secret-reduction occurrence has an unsupported Git mode")
    if not raw_path or type(offset) is not int or offset < 0:
        raise ReviewError("secret-reduction occurrence identity is invalid")
    digest = hashlib.sha256()
    digest.update(b"codex-secret-reduction-occurrence-v1\0")
    surface = b"symlink-target" if git_mode == "120000" else b"blob"
    digest.update(surface)
    digest.update(len(raw_path).to_bytes(8, "big"))
    digest.update(raw_path)
    digest.update(offset.to_bytes(8, "big"))
    return digest.hexdigest()


def _secret_reduction_occurrence_commitment(identities: Iterable[str]) -> str:
    digest = hashlib.sha256()
    digest.update(b"codex-secret-reduction-occurrence-set-v1\0")
    for identity in sorted(identities):
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ReviewError("secret-reduction occurrence commitment is invalid")
        digest.update(bytes.fromhex(identity))
    return digest.hexdigest()


def _secret_reduction_provenance_commitment(
    raw_identities: dict[AcceptedSyntheticValue, set[str]],
    unembedded_identities: dict[AcceptedSyntheticValue, set[str]],
) -> str:
    digest = hashlib.sha256()
    digest.update(b"codex-secret-reduction-provenance-v1\0")
    descriptors = set(raw_identities) | set(unembedded_identities)
    for descriptor in sorted(descriptors, key=lambda item: item.value_sha256):
        if descriptor.kind != "secret-reduction":
            raise ReviewError(
                "secret-reduction provenance contains a non-dynamic value"
            )
        raw = raw_identities.get(descriptor, set())
        unembedded = unembedded_identities.get(descriptor, set())
        if not unembedded.issubset(raw):
            raise ReviewError(
                "secret-reduction unembedded provenance is not raw provenance"
            )
        digest.update(bytes.fromhex(descriptor.value_sha256))
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(bytes.fromhex(_secret_reduction_occurrence_commitment(raw)))
        digest.update(len(unembedded).to_bytes(8, "big"))
        digest.update(
            bytes.fromhex(_secret_reduction_occurrence_commitment(unembedded))
        )
    return digest.hexdigest()


def _scan_frozen_tree_values(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    accepted_values: Iterable[AcceptedSyntheticValue],
    raw_occurrence_values: Iterable[AcceptedSyntheticValue] = (),
    capture_accepted_candidates: bool = False,
    capture_blocking_candidates: bool = False,
    capture_reduction_identities: bool = False,
    reduced_secret_values: frozenset[bytes] = frozenset(),
    exact_only: bool = False,
    _continue_after_blocking: bool = False,
) -> SecretScanResult:
    accepted = tuple(accepted_values)
    raw_occurrences = tuple(raw_occurrence_values)
    accepted_index = _index_accepted_values(accepted)
    exact_index = _index_exact_values(raw_occurrences)
    event_budget = SecretScanBudget.default()
    occurrence_budget = LegacyOccurrenceBudget.default()
    result = SecretScanResult.empty()
    with (
        _temporary_review_file() as tree_metadata,
        _temporary_review_file() as batch_input,
        _temporary_review_file() as batch_output,
    ):
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", commit),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=tree_metadata,
            label="frozen Git tree scan metadata",
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            record_separator=b"\0",
        )
        tree_metadata.seek(0)
        blob_count = 0
        for record in _iter_nul_records(
            tree_metadata,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="frozen Git tree scan metadata",
        ):
            mode, object_type, object_id, _relative = _parse_tree_record(record)
            _metadata, raw_path = record.split(b"\t", 1)
            path_scan = _scan_secret_value(
                raw_path,
                accepted_values=accepted,
                raw_occurrence_values=raw_occurrences,
                capture_accepted_candidates=capture_accepted_candidates,
                capture_blocking_candidates=capture_blocking_candidates,
                reduced_secret_values=reduced_secret_values,
                _accepted_index=accepted_index,
                _event_budget=event_budget,
                _exact_index=exact_index,
                _occurrence_budget=occurrence_budget,
                exact_only=exact_only,
                _continue_after_blocking=_continue_after_blocking,
            )
            result.merge(path_scan)
            if mode == "160000" and object_type == "commit":
                continue
            if object_type != "blob":
                raise ReviewError(
                    f"unsupported object in frozen Git tree scan: {object_type}"
                )
            batch_input.write(object_id.encode("ascii") + b"\n")
            blob_count += 1
        if blob_count:
            batch_input.seek(0)
            _run_bounded_process_to_file(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                environment=_git_environment(object_directory=object_directory),
                input_handle=batch_input,
                destination=batch_output,
                label="frozen Git tree scan blobs",
                byte_limit=MAX_SNAPSHOT_BYTES + MAX_TREE_METADATA_BYTES,
            )
        tree_metadata.seek(0)
        batch_output.seek(0)
        scanned_bytes = 0
        for record in _iter_nul_records(
            tree_metadata,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="frozen Git tree scan metadata",
        ):
            mode, object_type, object_id, _relative = _parse_tree_record(record)
            _metadata, raw_path = record.split(b"\t", 1)
            if mode == "160000" and object_type == "commit":
                continue
            scan, scanned_bytes = _scan_batch_blob(
                cat_input=None,
                cat_output=batch_output,
                object_id=object_id,
                scanned_bytes=scanned_bytes,
                accepted_values=accepted,
                raw_occurrence_values=raw_occurrences,
                capture_accepted_candidates=capture_accepted_candidates,
                capture_blocking_candidates=capture_blocking_candidates,
                capture_reduction_offsets=capture_reduction_identities,
                reduced_secret_values=reduced_secret_values,
                accepted_index=accepted_index,
                event_budget=event_budget,
                exact_index=exact_index,
                occurrence_budget=occurrence_budget,
                exact_only=exact_only,
                _continue_after_blocking=_continue_after_blocking,
            )
            if capture_reduction_identities:
                for descriptor, offsets in scan.reduction_occurrence_offsets.items():
                    identities = scan.reduction_occurrence_identities.setdefault(
                        descriptor,
                        set(),
                    )
                    identities.update(
                        _secret_reduction_occurrence_identity(
                            raw_path=raw_path,
                            git_mode=mode,
                            offset=offset,
                        )
                        for offset in offsets
                    )
                for descriptor, offsets in scan.reduction_unembedded_offsets.items():
                    identities = scan.reduction_unembedded_identities.setdefault(
                        descriptor,
                        set(),
                    )
                    identities.update(
                        _secret_reduction_occurrence_identity(
                            raw_path=raw_path,
                            git_mode=mode,
                            offset=offset,
                        )
                        for offset in offsets
                    )
                scan.reduction_occurrence_offsets.clear()
                scan.reduction_unembedded_offsets.clear()
            result.merge(scan)
        if batch_output.read(1):
            raise ReviewError(
                "frozen Git scan batch output contains unexpected trailing data"
            )
    return result


def _legacy_count_manifest(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    source_head_sha: str | None = None,
    catalog: SyntheticTokenCatalog,
    exemptions: tuple[LegacyExemption, ...],
) -> dict[str, Any]:
    legacy_accepted = accepted_legacy_values(catalog, exemptions)
    authoring_accepted = accepted_authoring_values(catalog)
    scan_accepted = authoring_accepted + legacy_accepted
    if legacy_accepted:
        base_scan = _scan_frozen_tree_values(
            git_view=git_view,
            object_directory=object_directory,
            commit=base_sha,
            accepted_values=scan_accepted,
            raw_occurrence_values=legacy_accepted,
        )
        head_scan = _scan_frozen_tree_values(
            git_view=git_view,
            object_directory=object_directory,
            commit=head_sha,
            accepted_values=scan_accepted,
            raw_occurrence_values=legacy_accepted,
        )
        source_head_scan = (
            head_scan
            if source_head_sha is None or source_head_sha == head_sha
            else _scan_frozen_tree_values(
                git_view=git_view,
                object_directory=object_directory,
                commit=source_head_sha,
                accepted_values=scan_accepted,
                raw_occurrence_values=legacy_accepted,
            )
        )
    else:
        base_scan = SecretScanResult.empty()
        head_scan = SecretScanResult.empty()
        source_head_scan = head_scan
    entries: list[dict[str, Any]] = []
    for exemption in exemptions:
        envelope_used = False
        for token in exemption.values:
            descriptor = next(
                item
                for item in legacy_accepted
                if item.exemption_id == exemption.identifier
                and item.identifier == token.identifier
            )
            base_count = base_scan.raw_occurrence_counts[descriptor]
            head_count = head_scan.raw_occurrence_counts[descriptor]
            source_head_count = source_head_scan.raw_occurrence_counts[descriptor]
            base_unembedded_count = base_scan.unembedded_occurrence_counts[descriptor]
            head_unembedded_count = head_scan.unembedded_occurrence_counts[descriptor]
            source_head_unembedded_count = (
                source_head_scan.unembedded_occurrence_counts[descriptor]
            )
            envelope_used = (
                envelope_used
                or base_count > 0
                or head_count > 0
                or source_head_count > 0
            )
            if head_count > base_count:
                raise ReviewError(
                    "legacy synthetic fixture count increased for "
                    f"{token.identifier}: base={base_count}, head={head_count}"
                )
            if source_head_count > base_count:
                raise ReviewError(
                    "legacy synthetic fixture count increased in source HEAD for "
                    f"{token.identifier}: base={base_count}, "
                    f"source_head={source_head_count}"
                )
            if head_unembedded_count > base_unembedded_count:
                raise ReviewError(
                    "legacy synthetic fixture unembedded count increased for "
                    f"{token.identifier}: base={base_unembedded_count}, "
                    f"head={head_unembedded_count}"
                )
            if source_head_unembedded_count > base_unembedded_count:
                raise ReviewError(
                    "legacy synthetic fixture unembedded count increased in "
                    f"source HEAD for {token.identifier}: "
                    f"base={base_unembedded_count}, "
                    f"source_head={source_head_unembedded_count}"
                )
            entries.append(
                {
                    "base_count": base_count,
                    "base_unembedded_count": base_unembedded_count,
                    "exemption_id": exemption.identifier,
                    "head_count": head_count,
                    "head_unembedded_count": head_unembedded_count,
                    "rule": token.rule,
                    "source_head_count": source_head_count,
                    "source_head_unembedded_count": source_head_unembedded_count,
                    "token_id": token.identifier,
                    "value_length": token.value_length,
                    "value_sha256": token.value_sha256,
                }
            )
        if not envelope_used:
            raise ReviewError(
                f"selected synthetic secret exemption is unused: {exemption.identifier}"
            )
    if len(entries) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("legacy synthetic fixture evidence has too many entries")
    return {
        "catalog_schema_version": catalog.schema_version,
        "entries": entries,
        "pool_version": catalog.pool_version,
        "schema_version": SYNTHETIC_MANIFEST_SCHEMA_VERSION,
        "selected_exemptions": [item.identifier for item in exemptions],
    }


def _all_catalog_sensitive_values(
    catalog: SyntheticTokenCatalog,
) -> tuple[AcceptedSyntheticValue, ...]:
    return accepted_authoring_values(catalog) + accepted_legacy_values(
        catalog,
        catalog.legacy_exemptions,
    )


def _iter_changed_blob_sides(
    raw_output: BinaryIO,
) -> Iterator[tuple[str, str, bytes]]:
    raw_output.seek(0)
    records = iter(
        _iter_nul_records(
            raw_output,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES * 2,
            label="changed blob metadata",
        )
    )
    for metadata in records:
        if not metadata.startswith(b":"):
            raise ReviewError(f"invalid raw Git diff record: {metadata!r}")
        fields = metadata[1:].split()
        if len(fields) != 5:
            raise ReviewError(f"invalid raw Git diff metadata: {metadata!r}")
        old_mode, new_mode, old_object, new_object, _status = fields
        try:
            raw_path = next(records)
        except StopIteration as error:
            raise ReviewError("raw Git diff is missing a changed path") from error
        for side, mode, raw_object in (
            ("base", old_mode, old_object),
            ("head", new_mode, new_object),
        ):
            if mode in {b"000000", b"160000"}:
                continue
            try:
                object_id = raw_object.decode("ascii")
            except UnicodeDecodeError as error:
                raise ReviewError(
                    f"invalid changed Git object id: {raw_object!r}"
                ) from error
            yield side, object_id, raw_path


def _scan_source_head_wip_delta(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    source_head_sha: str,
    snapshot_tree_sha: str,
    accepted_values: Iterable[AcceptedSyntheticValue],
    raw_occurrence_values: Iterable[AcceptedSyntheticValue],
    accepted_index: AcceptedValueIndex,
    event_budget: SecretScanBudget,
    exact_index: ExactValueIndex,
    occurrence_budget: LegacyOccurrenceBudget,
    path_callback: Callable[[bytes], None],
    blob_callback: Callable[[bytes, SecretScanResult], None],
) -> None:
    accepted = tuple(accepted_values)
    raw_occurrences = tuple(raw_occurrence_values)
    with (
        _temporary_review_file() as raw_output,
        _temporary_review_file() as batch_input,
        _temporary_review_file() as batch_output,
    ):
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--raw",
                "-z",
                "--no-abbrev",
                "--no-renames",
                source_head_sha,
                snapshot_tree_sha,
            ),
            output=raw_output,
            label="source HEAD to WIP snapshot blob metadata",
            record_limit=MAX_CHANGED_ENTRIES * 2,
        )
        blob_count = 0
        for side, object_id, raw_path in _iter_changed_blob_sides(raw_output):
            if side != "base":
                continue
            path_callback(raw_path)
            batch_input.write(object_id.encode("ascii") + b"\n")
            blob_count += 1
        if blob_count:
            batch_input.seek(0)
            _run_bounded_process_to_file(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                environment=_git_environment(object_directory=object_directory),
                input_handle=batch_input,
                destination=batch_output,
                label="source HEAD WIP delta blob batch",
                byte_limit=MAX_CHANGED_BLOB_SCAN_BYTES + MAX_CHANGED_METADATA_BYTES,
            )
        batch_output.seek(0)
        scanned_bytes = 0
        for side, object_id, raw_path in _iter_changed_blob_sides(raw_output):
            if side != "base":
                continue
            scan, scanned_bytes = _scan_batch_blob(
                cat_input=None,
                cat_output=batch_output,
                object_id=object_id,
                scanned_bytes=scanned_bytes,
                accepted_values=accepted,
                raw_occurrence_values=raw_occurrences,
                accepted_index=accepted_index,
                event_budget=event_budget,
                exact_index=exact_index,
                occurrence_budget=occurrence_budget,
            )
            blob_callback(raw_path, scan)
        if batch_output.read(1):
            raise ReviewError(
                "source HEAD WIP delta blob batch contains unexpected trailing data"
            )


def _secret_reduction_descriptor(
    candidate: bytes,
    rules: set[str],
) -> AcceptedSyntheticValue:
    digest = hashlib.sha256(candidate).hexdigest()
    return AcceptedSyntheticValue(
        kind="secret-reduction",
        catalog_version="dynamic-v1",
        identifier=f"secret-reduction-{digest}",
        rule=sorted(rules)[0],
        value=candidate,
        value_sha256=digest,
        value_length=len(candidate),
    )


def _read_frozen_path_diff(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    raw_path: bytes,
) -> bytes:
    output = io.BytesIO()
    with tempfile.TemporaryFile() as error_output:
        environment = _git_environment(object_directory=object_directory)
        environment["GIT_LITERAL_PATHSPECS"] = "1"
        process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=(
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--unified=0",
                    base_sha,
                    head_sha,
                    "--",
                    os.fsdecode(raw_path),
                ),
            ),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_output,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError("failed to create secret-delta line diff pipe")
        try:
            _copy_limited(
                process.stdout,
                output,
                limit=MAX_DIFF_BYTES,
                label="secret-delta line diff",
            )
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                "cannot generate secret-delta line diff: "
                f"{_process_stderr(error_output)}"
            )
    return output.getvalue()


def _added_line_occurrences(
    patch: bytes,
    descriptors: Iterable[AcceptedSyntheticValue],
) -> tuple[dict[AcceptedSyntheticValue, Counter[int]], bool]:
    additions: dict[AcceptedSyntheticValue, Counter[int]] = {}
    head_line: int | None = None
    block: list[tuple[int, bytes]] = []
    saw_hunk = False

    def flush_block() -> None:
        if not block:
            return
        payload = b"".join(content for _line, content in block)
        boundaries: list[tuple[int, int]] = []
        consumed = 0
        for line_number, content in block:
            consumed += len(content)
            boundaries.append((consumed, line_number))
        for descriptor in descriptors:
            candidate = descriptor.value
            if not candidate:
                continue
            start = 0
            while True:
                offset = payload.find(candidate, start)
                if offset < 0:
                    break
                for boundary, line_number in boundaries:
                    if offset < boundary:
                        additions.setdefault(descriptor, Counter())[line_number] += 1
                        break
                start = offset + 1
        block.clear()

    for line in patch.splitlines(keepends=True):
        hunk_match = UNIFIED_DIFF_HUNK_PATTERN.match(line)
        if hunk_match is not None:
            flush_block()
            head_line = int(hunk_match.group("head_line"))
            saw_hunk = True
            continue
        if head_line is None:
            continue
        if line.startswith(b"+"):
            block.append((head_line, line[1:]))
            head_line += 1
            continue
        flush_block()
        if line.startswith(b" "):
            head_line += 1
        elif line.startswith(b"-") or line.startswith(b"\\ No newline"):
            continue
        else:
            head_line = None
    flush_block()
    return additions, saw_hunk


def _removed_line_occurrence_counts(
    patch: bytes,
    descriptors: Iterable[AcceptedSyntheticValue],
) -> Counter[AcceptedSyntheticValue]:
    descriptor_values = tuple(
        (descriptor, descriptor.value) for descriptor in descriptors if descriptor.value
    )
    removals: Counter[AcceptedSyntheticValue] = Counter()
    block: list[bytes] = []
    saw_hunk = False

    def flush_block() -> None:
        if not block:
            return
        payload = b"".join(block)
        for descriptor, candidate in descriptor_values:
            start = 0
            while True:
                offset = payload.find(candidate, start)
                if offset < 0:
                    break
                removals[descriptor] += 1
                start = offset + 1
        block.clear()

    for line in patch.splitlines(keepends=True):
        if UNIFIED_DIFF_HUNK_PATTERN.match(line) is not None:
            flush_block()
            saw_hunk = True
            continue
        if not saw_hunk:
            continue
        if line.startswith(b"-"):
            block.append(line[1:])
            continue
        flush_block()
    flush_block()
    return removals


def _secret_delta_addition_locations(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    violations: Mapping[AcceptedSyntheticValue, tuple[int, int]],
) -> tuple[dict[AcceptedSyntheticValue, dict[str, Any]], bool]:
    evidence: dict[AcceptedSyntheticValue, dict[str, Any]] = {
        descriptor: {"locations": {}, "omitted_location_count": 0}
        for descriptor in violations
    }
    if not violations:
        return evidence, True

    descriptors = tuple(violations)
    exact_index = _index_exact_values(descriptors)
    occurrence_budget = LegacyOccurrenceBudget.default()
    candidate_occurrence_counts: Counter[AcceptedSyntheticValue] = Counter()
    total_locations = 0
    location_complete = True

    def record(
        descriptor: AcceptedSyntheticValue,
        *,
        raw_path: bytes,
        line: int | None,
        surface: str,
        occurrence_count: int = 1,
    ) -> None:
        nonlocal location_complete, total_locations
        candidate_occurrence_counts[descriptor] += occurrence_count
        location = (os.fsdecode(raw_path), line, surface)
        locations: dict[tuple[str, int | None, str], int] = evidence[descriptor][
            "locations"
        ]
        if location not in locations:
            if total_locations >= MAX_SECRET_DELTA_ADDITION_LOCATIONS:
                evidence[descriptor]["omitted_location_count"] += 1
                location_complete = False
                return
            total_locations += 1
        locations[location] = locations.get(location, 0) + occurrence_count

    environment = _git_environment(object_directory=object_directory)
    with (
        _temporary_review_file() as raw_output,
        tempfile.TemporaryFile() as cat_error,
    ):
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--raw",
                "-z",
                "--no-abbrev",
                "--no-renames",
                base_sha,
                head_sha,
            ),
            output=raw_output,
            label="secret-delta changed metadata",
            record_limit=MAX_CHANGED_ENTRIES * 2,
        )
        raw_output.seek(0)
        cat_process = subprocess.Popen(
            _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=cat_error,
        )
        if cat_process.stdin is None or cat_process.stdout is None:
            _stop_process(cat_process)
            raise ReviewError("failed to create pipes for secret-delta line evidence")
        scanned_bytes = 0
        try:
            records = iter(_iter_nul_records(raw_output))
            for metadata in records:
                if not metadata.startswith(b":"):
                    raise ReviewError(
                        f"invalid secret-delta raw Git record: {metadata!r}"
                    )
                fields = metadata[1:].split()
                if len(fields) != 5:
                    raise ReviewError(
                        f"invalid secret-delta raw Git metadata: {metadata!r}"
                    )
                old_mode, new_mode, old_object, new_object, _status = fields
                try:
                    raw_path = next(records)
                except StopIteration as error:
                    raise ReviewError(
                        "secret-delta raw Git diff is missing a changed path"
                    ) from error

                if old_mode == b"000000" and new_mode != b"000000":
                    path_scan = _scan_secret_value(
                        raw_path,
                        raw_occurrence_values=descriptors,
                        _exact_index=exact_index,
                        _occurrence_budget=occurrence_budget,
                        exact_only=True,
                    )
                    for descriptor, count in path_scan.raw_occurrence_counts.items():
                        if count:
                            record(
                                descriptor,
                                raw_path=raw_path,
                                line=None,
                                surface="path",
                                occurrence_count=count,
                            )

                if new_mode in {b"000000", b"160000"}:
                    continue

                base_counts: Counter[AcceptedSyntheticValue] = Counter()
                if old_mode not in {b"000000", b"160000"}:
                    try:
                        base_object_id = old_object.decode("ascii")
                    except UnicodeDecodeError as error:
                        raise ReviewError(
                            f"invalid secret-delta Git object id: {old_object!r}"
                        ) from error
                    base_scan, scanned_bytes = _scan_batch_blob(
                        cat_input=cat_process.stdin,
                        cat_output=cat_process.stdout,
                        object_id=base_object_id,
                        scanned_bytes=scanned_bytes,
                        raw_occurrence_values=descriptors,
                        exact_index=exact_index,
                        occurrence_budget=occurrence_budget,
                        exact_only=True,
                    )
                    base_counts.update(base_scan.raw_occurrence_counts)
                try:
                    object_id = new_object.decode("ascii")
                except UnicodeDecodeError as error:
                    raise ReviewError(
                        f"invalid secret-delta Git object id: {new_object!r}"
                    ) from error
                scan, scanned_bytes = _scan_batch_blob(
                    cat_input=cat_process.stdin,
                    cat_output=cat_process.stdout,
                    object_id=object_id,
                    scanned_bytes=scanned_bytes,
                    raw_occurrence_values=descriptors,
                    capture_reduction_offsets=True,
                    exact_index=exact_index,
                    occurrence_budget=occurrence_budget,
                    exact_only=True,
                )
                present = tuple(
                    descriptor
                    for descriptor in descriptors
                    if scan.raw_occurrence_counts[descriptor] > base_counts[descriptor]
                )
                if not present:
                    continue
                if new_mode == b"120000":
                    for descriptor in present:
                        record(
                            descriptor,
                            raw_path=raw_path,
                            line=1,
                            surface="symlink-target",
                            occurrence_count=(
                                scan.raw_occurrence_counts[descriptor]
                                - base_counts[descriptor]
                            ),
                        )
                    continue

                patch = _read_frozen_path_diff(
                    git_view=git_view,
                    object_directory=object_directory,
                    base_sha=base_sha,
                    head_sha=head_sha,
                    raw_path=raw_path,
                )
                line_occurrences, saw_hunk = _added_line_occurrences(patch, present)
                removed_occurrences = _removed_line_occurrence_counts(patch, present)
                for descriptor in present:
                    local_growth = (
                        scan.raw_occurrence_counts[descriptor] - base_counts[descriptor]
                    )
                    line_counts = line_occurrences.get(descriptor, {})
                    if saw_hunk and (
                        removed_occurrences[descriptor] > 0
                        or sum(line_counts.values()) != local_growth
                    ):
                        # A retained occurrence on a replaced line or an exact
                        # value crossing an unchanged/added boundary can make
                        # an added-block match indistinguishable from retained
                        # content. Preserve the count violation but do not
                        # invent a location.
                        candidate_occurrence_counts[descriptor] += local_growth
                        location_complete = False
                        continue
                    for line_number, occurrence_count in sorted(line_counts.items()):
                        record(
                            descriptor,
                            raw_path=raw_path,
                            line=line_number,
                            surface="blob",
                            occurrence_count=occurrence_count,
                        )
                if not saw_hunk and old_object != new_object:
                    for descriptor in present:
                        record(
                            descriptor,
                            raw_path=raw_path,
                            line=None,
                            surface="binary",
                            occurrence_count=(
                                scan.raw_occurrence_counts[descriptor]
                                - base_counts[descriptor]
                            ),
                        )
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            cat_returncode = cat_process.wait()
        except BaseException:
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            _stop_process(cat_process)
            raise
        if cat_returncode != 0:
            raise ReviewError(
                f"cannot scan secret-delta changed blobs: {_process_stderr(cat_error)}"
            )

    for descriptor, item in evidence.items():
        base_count, head_count = violations[descriptor]
        delta = head_count - base_count
        candidate_count = candidate_occurrence_counts[descriptor]
        if candidate_count != delta:
            location_complete = False
        if candidate_count > delta:
            # A complete Git tree records no operation identity. When local
            # positive growth exceeds the authoritative global delta, one or
            # more head occurrences were offset by removals or moves, but the
            # endpoint trees cannot prove which candidate is retained. Do not
            # arbitrarily label any of them as the new occurrence.
            item["locations"].clear()
            item["omitted_location_count"] = 0
        locations = item["locations"]
        item["locations"] = [
            {
                "line": line,
                "occurrence_count": count,
                "path": path,
                "surface": surface,
            }
            for (path, line, surface), count in sorted(
                locations.items(),
                key=lambda entry: (
                    os.fsencode(entry[0][0]),
                    -1 if entry[0][1] is None else entry[0][1],
                    entry[0][2],
                ),
            )
        ]
    return evidence, location_complete


def _private_manifest_shard_rows_sha256(
    manifest: dict[str, Any],
    raw_reduction_values: list[Any],
) -> str:
    try:
        payload = {
            "entries": manifest["entries"],
            "secret_delta_violations": manifest["secret_delta"]["violations"],
            "secret_reduction_values": raw_reduction_values,
            "secret_reductions": manifest["secret_reductions"],
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (KeyError, TypeError, ValueError) as error:
        raise ReviewError(
            "helper-private manifest shard commitment payload is invalid"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _private_manifest_shard_commitment(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReviewError("helper-private manifest shard commitment is invalid")
    return f"{PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX}{digest}"


def _shard_catalog_count_manifest(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    secret_delta = manifest["secret_delta"]
    violations = secret_delta["violations"]
    if (
        secret_delta["status"] not in {"clean", "violations"}
        or (secret_delta["status"] == "clean" and violations)
        or (secret_delta["status"] == "violations" and not violations)
        or manifest["secret_reductions"]
    ):
        raise ReviewError(
            "synthetic secret manifest cannot represent complete bounded counts"
        )
    if any(
        limitation.startswith(PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX)
        for limitation in secret_delta["limitations"]
    ):
        raise ReviewError("synthetic secret manifest shard commitment is duplicated")
    placeholder_commitment = _private_manifest_shard_commitment("0" * 64)
    manifest = dict(manifest)
    secret_delta = dict(secret_delta)
    secret_delta["limitations"] = [
        *secret_delta["limitations"],
        placeholder_commitment,
    ]
    manifest["secret_delta"] = secret_delta
    violation_digests = {violation["value_sha256"] for violation in violations}
    retained_entries = [
        entry
        for entry in manifest["entries"]
        if entry["value_sha256"] not in violation_digests
    ]

    def build(
        entries: list[dict[str, Any]],
        shard_violations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        shard = dict(manifest)
        shard["entries"] = list(entries)
        shard_delta = dict(secret_delta)
        shard_delta["violations"] = list(shard_violations)
        shard["secret_delta"] = shard_delta
        return shard

    shard_entries: tuple[list[dict[str, Any]], list[dict[str, Any]]] = ([], [])
    shard_violations: tuple[list[dict[str, Any]], list[dict[str, Any]]] = ([], [])
    sizes = [
        len(
            _bounded_json_bytes(
                build(shard_entries[index], shard_violations[index]),
                label="synthetic secret manifest shard",
            )
        )
        for index in range(2)
    ]
    records: list[tuple[str, dict[str, Any]]] = [
        ("violations", violation) for violation in violations
    ] + [("entries", entry) for entry in retained_entries]
    records.sort(
        key=lambda item: len(
            json.dumps(item[1], separators=(",", ":"), sort_keys=True).encode("utf-8")
        ),
        reverse=True,
    )
    for kind, record in records:
        placed = False
        for index in sorted(range(2), key=lambda candidate: sizes[candidate]):
            destination = (
                shard_violations[index]
                if kind == "violations"
                else shard_entries[index]
            )
            destination.append(record)
            try:
                encoded = _bounded_json_bytes(
                    build(shard_entries[index], shard_violations[index]),
                    label="synthetic secret manifest shard",
                )
            except ReviewError:
                destination.pop()
                continue
            sizes[index] = len(encoded)
            placed = True
            break
        if not placed:
            raise ReviewError(
                "synthetic secret manifest cannot represent complete bounded counts"
            )
    shards = tuple(
        build(shard_entries[index], shard_violations[index]) for index in range(2)
    )
    private_digest = _private_manifest_shard_rows_sha256(shards[1], [])
    commitment = _private_manifest_shard_commitment(private_digest)
    committed_shards: list[dict[str, Any]] = []
    for shard in shards:
        committed = dict(shard)
        committed_delta = dict(shard["secret_delta"])
        committed_delta["limitations"] = [
            commitment if item == placeholder_commitment else item
            for item in committed_delta["limitations"]
        ]
        committed["secret_delta"] = committed_delta
        _bounded_json_bytes(committed, label="synthetic secret manifest shard")
        committed_shards.append(committed)
    return committed_shards[0], committed_shards[1]


def _secret_count_manifests(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    source_head_sha: str | None = None,
    catalog: SyntheticTokenCatalog,
    evidence_head_ref: str | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    tuple[AcceptedSyntheticValue, ...],
]:
    # Catalog-backed legacy values are automatic baselines. The deprecated
    # selection flag no longer changes admission semantics.
    legacy_accepted = accepted_legacy_values(catalog, catalog.legacy_exemptions)
    authoring_accepted = accepted_authoring_values(catalog)
    scan_accepted = authoring_accepted + legacy_accepted
    legacy_raw_values = frozenset(
        descriptor.value
        for descriptor in legacy_accepted
        if descriptor.value is not None
    )
    base_discovery = _scan_frozen_tree_values(
        git_view=git_view,
        object_directory=object_directory,
        commit=base_sha,
        accepted_values=scan_accepted,
        capture_blocking_candidates=True,
        reduced_secret_values=legacy_raw_values,
        _continue_after_blocking=True,
    )
    head_discovery = _scan_frozen_tree_values(
        git_view=git_view,
        object_directory=object_directory,
        commit=head_sha,
        accepted_values=scan_accepted,
        capture_blocking_candidates=True,
        reduced_secret_values=legacy_raw_values,
        _continue_after_blocking=True,
    )
    if head_discovery.unextractable_rule is not None:
        raise ReviewError("an exact secret candidate could not be extracted completely")
    discovery = base_discovery
    discovery.merge(head_discovery)
    # Non-exact expressions have no stable byte identity and intentionally do
    # not enter the counter. Scanner resource failures still raise and are
    # recorded by the caller as an inconclusive merge gate.
    reduction_descriptors_list: list[AcceptedSyntheticValue] = []
    for candidate, rules in sorted(
        discovery.blocking_candidates.items(),
        key=lambda item: (hashlib.sha256(item[0]).hexdigest(), item[0]),
    ):
        # Declared rules still govern accepted-fixture matching. Once an exact
        # value reaches the count stage, however, raw bytes are its identity:
        # rediscovery through another rule must not create a second counter.
        if candidate in legacy_raw_values:
            continue
        descriptor = _secret_reduction_descriptor(candidate, rules)
        reduction_descriptors_list.append(descriptor)
    reduction_descriptors = tuple(reduction_descriptors_list)
    count_values = legacy_accepted + reduction_descriptors
    discovered_values = frozenset(discovery.blocking_candidates)
    if count_values:
        base_scan = _scan_frozen_tree_values(
            git_view=git_view,
            object_directory=object_directory,
            commit=base_sha,
            accepted_values=scan_accepted,
            raw_occurrence_values=count_values,
            reduced_secret_values=discovered_values,
            exact_only=True,
        )
        head_scan = _scan_frozen_tree_values(
            git_view=git_view,
            object_directory=object_directory,
            commit=head_sha,
            accepted_values=scan_accepted,
            raw_occurrence_values=count_values,
            reduced_secret_values=discovered_values,
            exact_only=True,
        )
        source_head_scan = (
            head_scan
            if source_head_sha is None or source_head_sha == head_sha
            else _scan_frozen_tree_values(
                git_view=git_view,
                object_directory=object_directory,
                commit=source_head_sha,
                accepted_values=scan_accepted,
                raw_occurrence_values=count_values,
                reduced_secret_values=discovered_values,
                exact_only=True,
            )
        )
    else:
        base_scan = SecretScanResult.empty()
        head_scan = SecretScanResult.empty()
        source_head_scan = head_scan
    entries: list[dict[str, Any]] = []
    violations: dict[AcceptedSyntheticValue, tuple[int, int]] = {}
    for exemption in catalog.legacy_exemptions:
        for token in exemption.values:
            descriptor = next(
                item
                for item in legacy_accepted
                if item.exemption_id == exemption.identifier
                and item.identifier == token.identifier
            )
            base_count = base_scan.raw_occurrence_counts[descriptor]
            head_count = head_scan.raw_occurrence_counts[descriptor]
            source_head_count = source_head_scan.raw_occurrence_counts[descriptor]
            base_unembedded_count = base_scan.unembedded_occurrence_counts[descriptor]
            head_unembedded_count = head_scan.unembedded_occurrence_counts[descriptor]
            source_head_unembedded_count = (
                source_head_scan.unembedded_occurrence_counts[descriptor]
            )
            if source_head_sha is not None and source_head_count > base_count:
                raise _SourceHeadSecretCountIncrease(
                    "legacy synthetic fixture count increased in source HEAD for "
                    f"{token.identifier}: base={base_count}, "
                    f"source_head={source_head_count}"
                )
            if (
                source_head_sha is not None
                and source_head_unembedded_count > base_unembedded_count
            ):
                raise _SourceHeadSecretCountIncrease(
                    "legacy synthetic fixture unembedded count increased in "
                    f"source HEAD for {token.identifier}: "
                    f"base={base_unembedded_count}, "
                    f"source_head={source_head_unembedded_count}"
                )
            if head_count > base_count:
                violations[descriptor] = (base_count, head_count)
            entries.append(
                {
                    "base_count": base_count,
                    "base_unembedded_count": base_unembedded_count,
                    "exemption_id": exemption.identifier,
                    "head_count": head_count,
                    "head_unembedded_count": head_unembedded_count,
                    "rule": token.rule,
                    "source_head_count": source_head_count,
                    "source_head_unembedded_count": source_head_unembedded_count,
                    "token_id": token.identifier,
                    "value_length": token.value_length,
                    "value_sha256": token.value_sha256,
                }
            )
    if len(entries) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("legacy synthetic fixture evidence has too many entries")
    reduction_entries: list[dict[str, Any]] = []
    for descriptor in reduction_descriptors:
        base_count = base_scan.raw_occurrence_counts[descriptor]
        head_count = head_scan.raw_occurrence_counts[descriptor]
        rules = sorted(discovery.blocking_candidates[descriptor.value])
        if head_count > base_count:
            violations[descriptor] = (base_count, head_count)
        reduction_entries.append(
            {
                "base_count": base_count,
                "head_count": head_count,
                "rules": rules,
                "value_length": descriptor.value_length,
                "value_sha256": descriptor.value_sha256,
            }
        )
    if len(entries) + len(reduction_entries) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("secret count evidence has too many entries")
    location_status = "complete"
    try:
        addition_evidence, locations_complete = _secret_delta_addition_locations(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
            violations=violations,
        )
        if not locations_complete:
            location_status = "inconclusive"
    except (OSError, ReviewError):
        location_status = "inconclusive"
        addition_evidence = {
            descriptor: {"locations": [], "omitted_location_count": 0}
            for descriptor in violations
        }

    violation_entries: list[dict[str, Any]] = []
    for descriptor, (base_count, head_count) in sorted(
        violations.items(),
        key=lambda item: item[0].value_sha256,
    ):
        rules = (
            [descriptor.rule]
            if descriptor.kind == "legacy"
            else sorted(discovery.blocking_candidates[descriptor.value])
        )
        violation_entries.append(
            {
                "additions": addition_evidence[descriptor]["locations"],
                "base_count": base_count,
                "delta": head_count - base_count,
                "head_count": head_count,
                "omitted_addition_location_count": addition_evidence[descriptor][
                    "omitted_location_count"
                ],
                "rules": rules,
                "value_length": descriptor.value_length,
                "value_sha256": descriptor.value_sha256,
            }
        )

    public_manifest = {
        "base_ref": base_sha,
        "catalog_schema_version": catalog.schema_version,
        "entries": entries,
        "head_ref": evidence_head_ref or head_sha,
        "pool_version": catalog.pool_version,
        "schema_version": SYNTHETIC_MANIFEST_SCHEMA_VERSION,
        "secret_delta": {
            "location_status": location_status,
            "status": "violations" if violation_entries else "clean",
            "limitations": [
                "Only exact raw byte values are compared; alternate encodings are not derived.",
                "Dynamic expressions without a stable exact value are not counted.",
            ],
            "violations": violation_entries,
        },
        "secret_reductions": reduction_entries,
        "selected_exemptions": [item.identifier for item in catalog.legacy_exemptions],
    }
    try:
        _bounded_json_bytes(public_manifest, label="synthetic secret manifest")
    except ReviewError:
        sharded_manifests = None
        if not reduction_descriptors:
            try:
                sharded_manifests = _shard_catalog_count_manifest(public_manifest)
            except ReviewError:
                pass
        if sharded_manifests is not None:
            public_manifest, private_manifest = sharded_manifests
        else:
            if public_manifest["secret_delta"]["violations"]:
                public_manifest["secret_delta"]["location_status"] = "inconclusive"
                for violation in public_manifest["secret_delta"]["violations"]:
                    violation["omitted_addition_location_count"] += len(
                        violation["additions"]
                    )
                    violation["additions"] = []
            try:
                _bounded_json_bytes(
                    public_manifest,
                    label="synthetic secret manifest",
                )
            except ReviewError:
                if reduction_descriptors:
                    raise
                public_manifest, private_manifest = _shard_catalog_count_manifest(
                    public_manifest
                )
            else:
                private_manifest = dict(public_manifest)
    else:
        private_manifest = dict(public_manifest)
    if reduction_descriptors:
        private_manifest["secret_reduction_values"] = [
            {
                "value_base64": base64.b64encode(descriptor.value).decode("ascii"),
                "value_sha256": descriptor.value_sha256,
            }
            for descriptor in reduction_descriptors
        ]
    _bounded_json_bytes(
        private_manifest,
        label="synthetic secret helper-private state",
    )
    return public_manifest, private_manifest, reduction_descriptors


def _all_catalog_sensitive_values(
    catalog: SyntheticTokenCatalog,
) -> tuple[AcceptedSyntheticValue, ...]:
    return accepted_authoring_values(catalog) + accepted_legacy_values(
        catalog,
        catalog.legacy_exemptions,
    )


def _inconclusive_secret_count_manifests(
    *,
    base_sha: str,
    head_sha: str,
    catalog: SyntheticTokenCatalog,
    failure_class: str,
    evidence_head_ref: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], tuple[AcceptedSyntheticValue, ...]]:
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", failure_class) is None:
        raise ReviewError("secret scan failure class is invalid")
    manifest = {
        "base_ref": base_sha,
        "catalog_schema_version": catalog.schema_version,
        "entries": [],
        "head_ref": evidence_head_ref or head_sha,
        "pool_version": catalog.pool_version,
        "schema_version": SYNTHETIC_MANIFEST_SCHEMA_VERSION,
        "secret_delta": {
            "failure_class": failure_class,
            "limitations": [
                "The exact-value scan did not complete; merge admission is inconclusive."
            ],
            "location_status": "inconclusive",
            "status": "inconclusive",
            "violations": [],
        },
        "secret_reductions": [],
        "selected_exemptions": [item.identifier for item in catalog.legacy_exemptions],
    }
    return manifest, dict(manifest), ()


def _write_changed_blob_findings(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
    accepted_destination: pathlib.Path,
    accepted_values: Iterable[AcceptedSyntheticValue],
    evidence_sensitive_values: Iterable[AcceptedSyntheticValue],
    reduced_secret_values: frozenset[bytes] = frozenset(),
) -> None:
    # Secret content is not a reviewer-egress gate. The complete base/head
    # exact-value audit owns admission evidence, so this legacy control surface
    # remains present only for artifact-layout compatibility and must not run a
    # second scan that could suppress reviewer launch.
    _ = (
        git_view,
        object_directory,
        base_sha,
        head_sha,
        accepted_values,
        evidence_sensitive_values,
        reduced_secret_values,
    )
    with _open_new_private_binary(destination):
        pass
    _write_bounded_json(
        accepted_destination,
        {
            "entries": [],
            "schema_version": 1,
        },
        label="synthetic changed-blob evidence",
        accepted_values=evidence_sensitive_values,
    )


def validate_workspace_layout(
    review: ReviewWorkspace | LegacyReviewWorkspace,
) -> None:
    def resolve_path(path: pathlib.Path, *, label: str) -> pathlib.Path:
        try:
            return path.expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as error:
            raise ReviewError(f"review {label} path cannot be resolved") from error

    def canonical_path(path: pathlib.Path, *, label: str) -> pathlib.Path:
        expanded = path.expanduser()
        absolute = expanded.absolute()
        normalized = pathlib.Path(os.path.normpath(os.fspath(absolute)))
        if absolute != normalized:
            raise ReviewError(f"review {label} path is not canonical: {absolute}")
        return resolve_path(expanded, label=label)

    source_root = canonical_path(review.source_root, label="source root")
    container_dir = canonical_path(review.container_dir, label="container")
    if isinstance(
        review,
        (LegacyReviewWorkspace, SourceLocalReviewWorkspace),
    ):
        expected_parent = resolve_path(
            source_root / ".codex-tmp",
            label="legacy source review root",
        )
    else:
        expected_parent = _review_root_for_source(
            source_root,
            require_source=False,
        )
    if (
        container_dir.parent != expected_parent
        or REVIEW_CONTAINER_PATTERN.fullmatch(container_dir.name) is None
    ):
        raise ReviewError(
            f"review container is outside the helper-private review root: {container_dir}"
        )
    expected_workspace = container_dir / "workspace"
    if canonical_path(review.workspace_root, label="workspace") != expected_workspace:
        raise ReviewError(
            f"review workspace escapes its container: {review.workspace_root}"
        )
    control_dir = expected_workspace / ".codex-review"
    if canonical_path(review.diff_file, label="diff") != control_dir / "review.diff":
        raise ReviewError(
            f"review diff escapes its control directory: {review.diff_file}"
        )
    if (
        canonical_path(review.prompt_file, label="prompt")
        != control_dir / "review.prompt"
    ):
        raise ReviewError(
            f"review prompt escapes its control directory: {review.prompt_file}"
        )
    if isinstance(review, LegacyReviewWorkspace):
        return
    expected_git_dir = container_dir / "review.git"
    git_dir = (review.git_dir or expected_git_dir).resolve(strict=False)
    if git_dir != expected_git_dir:
        raise ReviewError(f"review Git database escapes its container: {git_dir}")
    if review.content_variant not in {"head", "source-wip"}:
        raise ReviewError("review workspace has an invalid content variant")
    if (
        review.snapshot_tree_sha
        and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", review.snapshot_tree_sha)
        is None
    ):
        raise ReviewError("review workspace has an invalid snapshot tree id")
    if (
        review.scope_identity
        and re.fullmatch(r"[0-9a-f]{64}", review.scope_identity) is None
    ):
        raise ReviewError("review workspace has an invalid scope identity")


def validate_legacy_workspace_layout(review: ReviewWorkspace) -> None:
    try:
        source_root = review.source_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewError("cannot resolve legacy review source repository") from error
    if review.source_root != source_root:
        raise ReviewError("legacy review source repository is not canonical")
    expected_parent = source_root / ".codex-tmp"
    container_dir = review.container_dir
    if (
        not container_dir.is_absolute()
        or container_dir.parent != expected_parent
        or REVIEW_CONTAINER_PATTERN.fullmatch(container_dir.name) is None
    ):
        raise ReviewError(
            "legacy review container is outside the source repository review root: "
            f"{container_dir}"
        )
    try:
        review_root_status = os.lstat(expected_parent)
        container_status = os.lstat(container_dir)
    except OSError as error:
        raise ReviewError("cannot inspect legacy review container layout") from error
    if (
        not stat.S_ISDIR(review_root_status.st_mode)
        or stat.S_ISLNK(review_root_status.st_mode)
        or review_root_status.st_uid != os.geteuid()
        or review_root_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReviewError("legacy review state root is not a private real directory")
    if (
        not stat.S_ISDIR(container_status.st_mode)
        or stat.S_ISLNK(container_status.st_mode)
        or container_status.st_uid != os.geteuid()
        or stat.S_IMODE(container_status.st_mode) != 0o700
    ):
        raise ReviewError("legacy review container mode must be exactly 0700")
    expected_workspace = container_dir / "workspace"
    if review.workspace_root != expected_workspace:
        raise ReviewError(
            f"legacy review workspace escapes its container: {review.workspace_root}"
        )
    control_dir = expected_workspace / ".codex-review"
    if review.diff_file != control_dir / "review.diff":
        raise ReviewError(
            f"legacy review diff escapes its control directory: {review.diff_file}"
        )
    if review.prompt_file != control_dir / "review.prompt":
        raise ReviewError(
            f"legacy review prompt escapes its control directory: {review.prompt_file}"
        )
    expected_git_dir = container_dir / "review.git"
    if (review.git_dir or expected_git_dir) != expected_git_dir:
        raise ReviewError("legacy review Git path escapes its container")
    if os.path.lexists(expected_git_dir):
        raise ReviewError(
            "legacy review state contains an unexpected private Git database"
        )
    if (
        review.content_variant != "head"
        or review.snapshot_tree_sha
        or review.scope_identity
    ):
        raise ReviewError("legacy review state contains unsupported scope metadata")


def _validate_worktree_git_control(review: ReviewWorkspace) -> pathlib.Path:
    git_pointer = review.workspace_root / ".git"
    try:
        metadata = os.lstat(git_pointer)
    except OSError as error:
        raise ReviewError("detached review worktree .git control is missing") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_size > 4096
    ):
        raise ReviewError("detached review worktree .git control is unsafe")
    try:
        value = git_pointer.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ReviewError(
            "cannot read detached review worktree .git control"
        ) from error
    prefix = "gitdir: "
    if not value.startswith(prefix) or not value.endswith("\n"):
        raise ReviewError("detached review worktree .git control is malformed")
    target = pathlib.Path(value[len(prefix) : -1]).resolve(strict=False)
    git_dir = (review.git_dir or review.container_dir / "review.git").resolve(
        strict=False
    )
    try:
        target_metadata = os.lstat(target)
    except OSError as error:
        raise ReviewError(
            "detached review worktree admin directory is missing"
        ) from error
    if (
        target.parent != git_dir / "worktrees"
        or target.name != review.workspace_root.name
        or not stat.S_ISDIR(target_metadata.st_mode)
        or target_metadata.st_uid != os.geteuid()
        or target_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReviewError(
            "detached review worktree .git control escapes helper Git data"
        )
    return target


def _validate_private_directory_inventory(
    directory: pathlib.Path,
    *,
    files: frozenset[str],
    directories: frozenset[str],
    label: str,
) -> None:
    try:
        directory_metadata = os.lstat(directory)
    except OSError as error:
        raise ReviewError(f"private review Git {label} is missing") from error
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or directory_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReviewError(f"private review Git {label} is unsafe")
    expected = files | directories
    seen: set[str] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name not in expected or entry.name in seen:
                    raise ReviewError(
                        f"private review Git {label} contains an unexpected entry"
                    )
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise ReviewError(
                        f"cannot inspect private review Git {label}"
                    ) from error
                expected_type = (
                    stat.S_ISREG(metadata.st_mode)
                    if entry.name in files
                    else stat.S_ISDIR(metadata.st_mode)
                )
                if (
                    not expected_type
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                ):
                    raise ReviewError(
                        f"private review Git {label} contains an unsafe entry"
                    )
                seen.add(entry.name)
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"cannot inspect private review Git {label}") from error
    if seen != expected:
        raise ReviewError(f"private review Git {label} is incomplete")


def _validate_private_review_endpoint_state(
    review: ReviewWorkspace,
    *,
    git_dir: pathlib.Path,
    worktree_admin: pathlib.Path,
) -> None:
    _validate_private_directory_inventory(
        git_dir,
        files=frozenset({"HEAD", "config", "shallow"}),
        directories=frozenset({"info", "objects", "refs", "worktrees"}),
        label="root inventory",
    )
    _validate_private_directory_inventory(
        git_dir / "info",
        files=frozenset({"exclude"}),
        directories=frozenset(),
        label="info inventory",
    )
    _validate_private_directory_inventory(
        git_dir / "worktrees",
        files=frozenset(),
        directories=frozenset({review.workspace_root.name}),
        label="worktree inventory",
    )
    _validate_private_directory_inventory(
        worktree_admin,
        files=frozenset({"HEAD", "commondir", "gitdir", "index", "locked"}),
        directories=frozenset({"refs"}),
        label="detached worktree admin inventory",
    )
    _validate_private_directory_inventory(
        worktree_admin / "refs",
        files=frozenset(),
        directories=frozenset(),
        label="detached worktree refs inventory",
    )
    _require_empty_private_ref_tree(git_dir / "refs")
    _require_empty_private_ref_tree(worktree_admin / "refs")
    _validate_private_directory_inventory(
        git_dir / "refs",
        files=frozenset(),
        directories=frozenset({"heads", "tags"}),
        label="refs inventory",
    )
    for ref_namespace in ("heads", "tags"):
        _validate_private_directory_inventory(
            git_dir / "refs" / ref_namespace,
            files=frozenset(),
            directories=frozenset(),
            label="empty ref namespace",
        )
    for relative, label in (
        ("objects/info/alternates", "object alternates"),
        ("objects/info/http-alternates", "HTTP object alternates"),
        ("info/grafts", "grafts"),
        ("packed-refs", "packed refs"),
    ):
        _require_absent_private_git_path(git_dir / relative, label=label)
    _validate_private_object_storage_topology(
        git_dir,
        object_id_length=len(review.head_ref),
    )
    expected_root_files = {
        "HEAD": b"ref: refs/heads/master\n",
        "config": _canonical_private_git_config(object_id_length=len(review.head_ref)),
        "info/exclude": b"/.codex-review/\n",
    }
    for name, expected in expected_root_files.items():
        with _secure_file_reader(
            git_dir / name,
            label=f"private review Git {name}",
            max_bytes=64 * 1024,
        ) as (handle, _metadata):
            actual = handle.read(64 * 1024 + 1)
        if actual != expected:
            raise ReviewError(
                f"private review Git {name} no longer matches helper state"
            )
    expected_admin_files = {
        "commondir": b"../..\n",
        "gitdir": os.fsencode(review.workspace_root / ".git") + b"\n",
        "locked": b"added with --lock\n",
    }
    for name, expected in expected_admin_files.items():
        with _secure_file_reader(
            worktree_admin / name,
            label=f"detached review worktree {name}",
            max_bytes=4096,
        ) as (handle, _metadata):
            actual = handle.read(4097)
        if actual != expected:
            raise ReviewError(
                f"detached review worktree {name} no longer matches helper state"
            )
    for name, limit in (("index", MAX_TREE_METADATA_BYTES),):
        with _secure_file_reader(
            worktree_admin / name,
            label=f"detached review worktree {name}",
            max_bytes=limit,
        ) as (handle, _metadata):
            while handle.read(1024 * 1024):
                pass

    with _secure_file_reader(
        worktree_admin / "HEAD",
        label="detached review worktree HEAD",
        max_bytes=4096,
    ) as (handle, _metadata):
        actual_head = handle.read(4097)
    endpoints = sorted({review.base_ref, review.head_ref})
    if any(
        re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", endpoint) is None
        for endpoint in endpoints
    ):
        raise ReviewError("private review Git endpoint is malformed")
    expected_shallow = b"".join(
        endpoint.encode("ascii") + b"\n" for endpoint in endpoints
    )
    shallow_path = git_dir / "shallow"
    with _secure_file_reader(
        shallow_path,
        label="private review Git shallow endpoints",
        max_bytes=2 * 65,
    ) as (handle, _metadata):
        actual_shallow = handle.read(2 * 65 + 1)

    symbolic = _run_worktree_git(
        review.workspace_root,
        "symbolic-ref",
        "--quiet",
        "HEAD",
        check=False,
    )
    if symbolic.returncode != 1:
        raise ReviewError("detached review worktree HEAD is no longer detached")
    resolved_head = (
        _run_worktree_git(
            review.workspace_root,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        )
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if resolved_head != review.head_ref:
        raise ReviewError("detached review worktree HEAD no longer matches review head")
    if actual_head != review.head_ref.encode("ascii") + b"\n":
        raise ReviewError(
            "detached review worktree HEAD no longer matches helper state"
        )
    if actual_shallow != expected_shallow:
        raise ReviewError(
            "private review Git shallow endpoints do not match the frozen range"
        )
    for label, endpoint in (("base", review.base_ref), ("head", review.head_ref)):
        available = _run_private_git(
            git_dir=git_dir,
            args=("cat-file", "-e", f"{endpoint}^{{commit}}"),
            check=False,
        )
        if available.returncode != 0:
            raise ReviewError(f"private review Git database is missing the {label}")


def _secure_file_identity(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    with _secure_file_reader(
        path,
        label=label,
        max_bytes=max_bytes,
    ) as (handle, metadata):
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return metadata.st_size, digest.hexdigest()


def _validate_canonical_worktree_index(
    review: ReviewWorkspace,
    *,
    git_dir: pathlib.Path,
    worktree_admin: pathlib.Path,
) -> None:
    with tempfile.TemporaryDirectory(dir=_canonical_review_root_base()) as temporary:
        canonical_index = pathlib.Path(temporary) / "index"
        _populate_canonical_worktree_index(
            git_dir=git_dir,
            workspace_root=review.workspace_root,
            snapshot_tree_sha=review.snapshot_tree_sha,
            index_file=canonical_index,
        )
        expected = _secure_file_identity(
            canonical_index,
            label="canonical detached review index",
            max_bytes=MAX_TREE_METADATA_BYTES,
        )
    actual = _secure_file_identity(
        worktree_admin / "index",
        label="detached review worktree index",
        max_bytes=MAX_TREE_METADATA_BYTES,
    )
    if actual != expected:
        raise ReviewError(
            "detached review worktree index contains noncanonical metadata"
        )


def _populate_canonical_worktree_index(
    *,
    git_dir: pathlib.Path,
    workspace_root: pathlib.Path,
    snapshot_tree_sha: str,
    index_file: pathlib.Path,
) -> None:
    environment = _git_environment(index_file=index_file)
    with _temporary_review_file() as output:
        _run_bounded_process_to_file(
            _private_git_command(
                git_dir=git_dir,
                work_tree=workspace_root,
                args=("read-tree", "--reset", snapshot_tree_sha),
            ),
            environment=environment,
            destination=output,
            label="canonical detached review index",
            byte_limit=4096,
        )
    index_file.chmod(0o600)


def _replace_worktree_index_with_canonical(
    *,
    git_dir: pathlib.Path,
    workspace_root: pathlib.Path,
    snapshot_tree_sha: str,
) -> None:
    worktree_admin = git_dir / "worktrees" / workspace_root.name
    destination = worktree_admin / "index"
    candidate = worktree_admin / f".canonical-index-{uuid.uuid4().hex}"
    try:
        _populate_canonical_worktree_index(
            git_dir=git_dir,
            workspace_root=workspace_root,
            snapshot_tree_sha=snapshot_tree_sha,
            index_file=candidate,
        )
        os.replace(candidate, destination)
    finally:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


def _require_absent_private_git_path(path: pathlib.Path, *, label: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReviewError(f"cannot inspect private review Git {label}") from error
    raise ReviewError(f"private review Git {label} is not allowed")


def _require_empty_private_ref_tree(root: pathlib.Path) -> None:
    pending = [root]
    visited = 0
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReviewError("cannot inspect private review Git refs") from error
        try:
            with entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_PRIVATE_OBJECT_ENTRIES:
                        raise ReviewError(
                            "private review Git refs exceed their entry limit"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(pathlib.Path(entry.path))
                        continue
                    raise ReviewError("private review Git contains an unexpected ref")
        except ReviewError:
            raise
        except OSError as error:
            raise ReviewError("cannot inspect private review Git refs") from error


def _validate_private_object_storage_topology(
    git_dir: pathlib.Path,
    *,
    object_id_length: int,
) -> None:
    objects = git_dir / "objects"
    loose_entries = 0
    pack_entries = 0
    storage_bytes = 0
    top_entries = 0
    pack_suffixes: dict[str, set[str]] = {}

    def consume_storage(size: int, *, per_file_limit: int, label: str) -> None:
        nonlocal storage_bytes
        if size < 0 or size > per_file_limit:
            raise ReviewError(f"private review Git {label} exceeds its size limit")
        if size > MAX_PRIVATE_STORAGE_BYTES - storage_bytes:
            raise ReviewError(
                "private review Git object storage exceeds its size limit"
            )
        storage_bytes += size

    try:
        with os.scandir(objects) as entries:
            for entry in entries:
                top_entries += 1
                if top_entries > 258:
                    raise ReviewError(
                        "private review Git object storage exceeds its entry limit"
                    )
                try:
                    directory_metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise ReviewError(
                        "cannot inspect private review Git object storage"
                    ) from error
                if (
                    not stat.S_ISDIR(directory_metadata.st_mode)
                    or directory_metadata.st_uid != os.geteuid()
                    or directory_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                ):
                    raise ReviewError("private review Git object directory is unsafe")
                if entry.name == "info":
                    with os.scandir(entry.path) as info_entries:
                        if next(info_entries, None) is not None:
                            raise ReviewError(
                                "private review Git object info must remain empty"
                            )
                    continue
                if entry.name == "pack":
                    with os.scandir(entry.path) as packed_objects:
                        for pack_entry in packed_objects:
                            pack_entries += 1
                            if pack_entries > MAX_PRIVATE_OBJECT_ENTRIES:
                                raise ReviewError(
                                    "private review Git pack files exceed their limit"
                                )
                            match = re.fullmatch(
                                rf"pack-([0-9a-f]{{{object_id_length}}})\.(pack|idx|rev)",
                                pack_entry.name,
                            )
                            try:
                                metadata = pack_entry.stat(follow_symlinks=False)
                            except OSError as error:
                                raise ReviewError(
                                    "cannot inspect private review Git pack"
                                ) from error
                            if (
                                match is None
                                or not stat.S_ISREG(metadata.st_mode)
                                or metadata.st_nlink != 1
                                or metadata.st_uid != os.geteuid()
                                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                            ):
                                raise ReviewError(
                                    "private review Git pack storage is unsafe"
                                )
                            consume_storage(
                                metadata.st_size,
                                per_file_limit=(
                                    MAX_PRIVATE_PACK_BYTES
                                    if match.group(2) == "pack"
                                    else MAX_PRIVATE_OBJECT_LIST_BYTES
                                ),
                                label="pack file",
                            )
                            pack_suffixes.setdefault(match.group(1), set()).add(
                                match.group(2)
                            )
                    continue
                if re.fullmatch(r"[0-9a-f]{2}", entry.name) is None:
                    raise ReviewError(
                        "private review Git contains unexpected object storage"
                    )
                with os.scandir(entry.path) as loose_objects:
                    for loose in loose_objects:
                        loose_entries += 1
                        if loose_entries > MAX_PRIVATE_OBJECT_ENTRIES:
                            raise ReviewError(
                                "private review Git loose objects exceed their limit"
                            )
                        try:
                            metadata = loose.stat(follow_symlinks=False)
                        except OSError as error:
                            raise ReviewError(
                                "cannot inspect private review Git loose object"
                            ) from error
                        if (
                            re.fullmatch(
                                rf"[0-9a-f]{{{object_id_length - 2}}}",
                                loose.name,
                            )
                            is None
                            or not stat.S_ISREG(metadata.st_mode)
                            or metadata.st_nlink != 1
                            or metadata.st_uid != os.geteuid()
                            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                        ):
                            raise ReviewError(
                                "private review Git loose object storage is unsafe"
                            )
                        consume_storage(
                            metadata.st_size,
                            per_file_limit=MAX_PRIVATE_LOOSE_OBJECT_BYTES,
                            label="loose object",
                        )
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError("cannot inspect private review Git object storage") from error
    if not pack_suffixes or any(
        not {"idx", "pack"}.issubset(suffixes)
        or not suffixes.issubset({"idx", "pack", "rev"})
        for suffixes in pack_suffixes.values()
    ):
        raise ReviewError("private review Git pack storage is incomplete")


def _private_object_id_set(
    *,
    git_dir: pathlib.Path,
    args: tuple[str, ...],
    label: str,
    object_id_length: int,
) -> set[str]:
    with _temporary_review_file() as output:
        size = _run_bounded_process_to_file(
            _private_git_command(git_dir=git_dir, args=args),
            environment=_git_environment(),
            destination=output,
            label=label,
            byte_limit=MAX_PRIVATE_OBJECT_LIST_BYTES,
            record_limit=MAX_PRIVATE_OBJECT_ENTRIES,
        ).output_bytes
        if size and not _temporary_file_ends_with_newline(output):
            raise ReviewError(f"{label} has an unterminated record")
        output.seek(0)
        object_ids: set[str] = set()
        for line in output:
            raw_object_id = line.rstrip(b"\n")
            if not _valid_object_id(raw_object_id, object_id_length):
                raise ReviewError(f"{label} contains a malformed object id")
            object_ids.add(raw_object_id.decode("ascii"))
        return object_ids


def _validate_private_review_integrity(
    review: ReviewWorkspace,
    *,
    git_dir: pathlib.Path,
) -> None:
    object_id_length = len(review.head_ref)
    for relative, label in (
        ("objects/info/alternates", "object alternates"),
        ("objects/info/http-alternates", "HTTP object alternates"),
        ("info/grafts", "grafts"),
        ("packed-refs", "packed refs"),
    ):
        _require_absent_private_git_path(git_dir / relative, label=label)
    _require_empty_private_ref_tree(git_dir / "refs")
    for worktree in (git_dir / "worktrees").iterdir():
        _require_empty_private_ref_tree(worktree / "refs")

    with _secure_file_reader(
        git_dir / "config",
        label="private review Git config",
        max_bytes=64 * 1024,
    ) as (handle, _metadata):
        config = handle.read(64 * 1024 + 1).lower()
    forbidden_config = (
        b"promisor",
        b"partialclone",
        b"alternate",
        b"[include",
        b"[remote ",
    )
    if any(value in config for value in forbidden_config):
        raise ReviewError("private review Git config enables an external object source")

    _validate_private_object_storage_topology(
        git_dir,
        object_id_length=object_id_length,
    )
    with _temporary_review_file() as fsck_output:
        _run_bounded_process_to_file(
            _private_git_command(
                git_dir=git_dir,
                args=(
                    "fsck",
                    "--full",
                    "--strict",
                    "--no-reflogs",
                    "--no-progress",
                    "--no-dangling",
                ),
            ),
            environment=_git_environment(),
            destination=fsck_output,
            label="private review Git integrity check",
            byte_limit=MAX_PRIVATE_FSCK_OUTPUT_BYTES,
            record_limit=MAX_PRIVATE_OBJECT_ENTRIES,
        )

    expected = _private_object_id_set(
        git_dir=git_dir,
        args=(
            "rev-list",
            "--objects",
            "--no-object-names",
            f"{review.base_ref}^{{tree}}",
            f"{review.head_ref}^{{tree}}",
            review.snapshot_tree_sha,
        ),
        label="private review Git expected objects",
        object_id_length=object_id_length,
    )
    expected.update({review.base_ref, review.head_ref})
    actual = _private_object_id_set(
        git_dir=git_dir,
        args=(
            "cat-file",
            "--batch-check=%(objectname)",
            "--batch-all-objects",
        ),
        label="private review Git actual objects",
        object_id_length=object_id_length,
    )
    if actual != expected:
        raise ReviewError(
            "private review Git object set does not match the frozen review scope"
        )


def _reject_duplicate_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewError(f"synthetic audit evidence has duplicate key: {key}")
        value[key] = item
    return value


class _DigestingReader:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self._digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        value = self._handle.read(size)
        self._digest.update(value)
        self.bytes_read += len(value)
        return value

    def fileno(self) -> int:
        return self._handle.fileno()

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()


@contextmanager
def _secure_file_reader(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int | None = None,
    expected_artifact: ControlArtifactEvidence | None = None,
    allow_root_owner: bool = False,
    expected_identity: CleanupIdentity | None = None,
) -> Iterator[tuple[_DigestingReader, os.stat_result]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        error_code = f" (errno {error.errno})" if error.errno is not None else ""
        raise ReviewError(f"cannot open {label}{error_code}") from error
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise ReviewError(f"{label} is not a regular file with one link")
        allowed_uids = (
            {os.getuid(), 0}
            if allow_root_owner and expected_identity is None
            else {os.getuid()}
        )
        if initial.st_uid not in allowed_uids:
            owner_requirement = (
                "the current user or root" if allow_root_owner else "the current user"
            )
            raise ReviewError(f"{label} must be owned by {owner_requirement}")
        if expected_identity is not None and stat.S_IMODE(initial.st_mode) != 0o600:
            raise ReviewError(f"{label} must have mode 0600")
        if initial.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(f"{label} must not be group or other writable")
        if (
            expected_identity is not None
            and _cleanup_identity_evidence(initial) != expected_identity
        ):
            raise ReviewError(f"{label} does not match preparation identity")
        if max_bytes is not None and initial.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds its review size limit")
        if expected_artifact is not None:
            if (
                path.name != expected_artifact.name
                or initial.st_size != expected_artifact.size
            ):
                raise ReviewError(
                    f"{label} does not match helper-private control state"
                )
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        reader = _DigestingReader(handle)
        yield reader, initial
        final = os.fstat(reader.fileno())
        if reader.bytes_read != initial.st_size or (
            initial.st_dev,
            initial.st_ino,
            initial.st_mode,
            initial.st_nlink,
            initial.st_uid,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_uid,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise ReviewError(f"{label} changed while it was read")
        if expected_artifact is not None and reader.sha256 != expected_artifact.sha256:
            raise ReviewError(f"{label} does not match helper-private control state")
    except OSError as error:
        error_code = f" (errno {error.errno})" if error.errno is not None else ""
        raise ReviewError(f"cannot read {label}{error_code}") from error
    finally:
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)


def _read_bounded_json(
    path: pathlib.Path,
    *,
    label: str,
    expected_artifact: ControlArtifactEvidence | None = None,
    expected_identity: CleanupIdentity | None = None,
    max_bytes: int = MAX_SYNTHETIC_EVIDENCE_BYTES,
) -> dict[str, Any]:
    chunks: list[bytes] = []
    with _secure_file_reader(
        path,
        label=label,
        max_bytes=max_bytes,
        expected_artifact=expected_artifact,
        expected_identity=expected_identity,
    ) as (reader, _metadata):
        remaining = max_bytes
        while chunk := reader.read(min(64 * 1024, remaining + 1)):
            if len(chunk) > remaining:
                raise ReviewError(f"{label} exceeds its review size limit")
            chunks.append(chunk)
            remaining -= len(chunk)
    encoded = b"".join(chunks)
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
        )
    except RecursionError as error:
        raise ReviewError(f"{label} exceeds the JSON nesting depth limit") from error
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OverflowError,
        ValueError,
    ) as error:
        raise ReviewError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    _validate_bounded_json_depth(value, label=label)
    return value


def _read_bounded_json_at(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
    max_bytes: int = MAX_SYNTHETIC_EVIDENCE_BYTES,
) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise ReviewError(f"{label} is not a regular file with one link")
        if initial.st_uid != os.geteuid():
            raise ReviewError(f"{label} has an unexpected owner")
        if initial.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(f"{label} must not be group or other writable")
        if initial.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds its review size limit")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        encoded = handle.read(max_bytes + 1)
        if len(encoded) != initial.st_size:
            raise ReviewError(f"{label} changed while it was read")
        final = os.fstat(handle.fileno())
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_mode,
            initial.st_nlink,
            initial.st_uid,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_uid,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise ReviewError(f"{label} changed while it was read")
    except OSError as error:
        raise ReviewError(f"cannot read {label}: {error}") from error
    finally:
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
        )
    except RecursionError as error:
        raise ReviewError(f"{label} exceeds the JSON nesting depth limit") from error
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OverflowError,
        ValueError,
    ) as error:
        raise ReviewError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    _validate_bounded_json_depth(value, label=label)
    return value


def _validate_bounded_json_depth(value: dict[str, Any], *, label: str) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        candidate, depth = pending.pop()
        if depth > MAX_BOUNDED_JSON_DEPTH:
            raise ReviewError(f"{label} exceeds the JSON nesting depth limit")
        if isinstance(candidate, dict):
            children = candidate.values()
        elif isinstance(candidate, list):
            children = candidate
        else:
            continue
        next_depth = depth + 1
        for child in children:
            if isinstance(child, (dict, list)):
                pending.append((child, next_depth))


def encode_preflight_json(value: dict[str, Any]) -> str:
    encoded = (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_PREFLIGHT_JSON_BYTES:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    if len(encoded) > MAX_PREFLIGHT_JSON_BYTES:
        raise ReviewError("serialized preflight evidence exceeds the size limit")
    return encoded.decode("utf-8")


def _encode_synthetic_evidence_json(value: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_SYNTHETIC_EVIDENCE_BYTES:
        raise ReviewError("synthetic-token preflight evidence exceeds the size limit")
    return encoded


def _control_entry_names_sha256(names: Iterable[str]) -> str:
    encoded = b"\0".join(name.encode("ascii") for name in sorted(names))
    return hashlib.sha256(encoded).hexdigest()


def _inspect_control_directory(
    control_dir: pathlib.Path,
    *,
    expected: ControlDirectoryEvidence | None = None,
) -> ControlDirectoryEvidence:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(control_dir, flags)
        initial = os.fstat(descriptor)
        if not stat.S_ISDIR(initial.st_mode):
            raise ReviewError("review control path is not a directory")
        if initial.st_uid != os.getuid():
            raise ReviewError(
                "review control directory must be owned by the current user"
            )
        if initial.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(
                "review control directory must not be group or other writable"
            )
        entry_names = tuple(sorted(os.listdir(descriptor)))
        if entry_names != tuple(sorted(CONTROL_ARTIFACT_SPECS)):
            raise ReviewError("review control directory entries are invalid")
        final = os.fstat(descriptor)
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_mode,
            initial.st_nlink,
            initial.st_uid,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_uid,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise ReviewError("review control directory changed while it was inspected")
        evidence = ControlDirectoryEvidence(
            device=initial.st_dev,
            inode=initial.st_ino,
            mode=initial.st_mode,
            link_count=initial.st_nlink,
            uid=initial.st_uid,
            mtime_ns=initial.st_mtime_ns,
            ctime_ns=initial.st_ctime_ns,
            entry_count=len(entry_names),
            entry_names_sha256=_control_entry_names_sha256(entry_names),
        )
        if expected is not None and evidence != expected:
            raise ReviewError(
                "review control directory does not match helper-private control state"
            )
        return evidence
    except OSError as error:
        raise ReviewError(
            f"cannot inspect review control directory: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _build_control_artifact_state(
    *,
    control_dir: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
) -> dict[str, Any]:
    directory = _inspect_control_directory(control_dir)
    artifacts: dict[str, ControlArtifactEvidence] = {}
    for name in sorted(CONTROL_ARTIFACT_SPECS):
        max_bytes, record_limit = CONTROL_ARTIFACT_SPECS[name]
        record_count: int | None = 0 if record_limit is not None else None
        last_byte: int | None = None
        with _secure_file_reader(
            control_dir / name,
            label=f"generated review control artifact {name}",
            max_bytes=max_bytes,
        ) as (reader, metadata):
            while chunk := reader.read(64 * 1024):
                if record_count is not None:
                    record_count += chunk.count(b"\0")
                    if record_count > record_limit:
                        raise ReviewError(
                            f"generated review control artifact {name} "
                            "exceeds its record limit"
                        )
                    last_byte = chunk[-1]
            artifact_sha256 = reader.sha256
        if record_count is not None:
            if metadata.st_size and last_byte != 0:
                raise ReviewError(
                    f"generated review control artifact {name} has an unterminated record"
                )
            if name == "changed-blob-findings.z" and record_count % 3:
                raise ReviewError(
                    "generated changed-blob findings are not complete record triples"
                )
        artifacts[name] = ControlArtifactEvidence(
            name=name,
            record_count=record_count,
            sha256=artifact_sha256,
            size=metadata.st_size,
        )
    _inspect_control_directory(control_dir, expected=directory)
    return ControlArtifactState(
        artifacts=artifacts,
        directory=directory,
        private_cleanup=private_cleanup,
        private_artifacts_removed=frozenset(),
    ).to_json()


def _parse_cleanup_identity(value: Any, *, label: str) -> CleanupIdentity:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "inode"}
        or type(value["device"]) is not int
        or type(value["inode"]) is not int
        or value["device"] < 0
        or value["inode"] <= 0
    ):
        raise ReviewError(f"{label} is invalid")
    return CleanupIdentity(device=value["device"], inode=value["inode"])


def _parse_private_cleanup_evidence(
    value: Any,
    *,
    require_all: bool,
) -> PrivateCleanupEvidence:
    if (
        not isinstance(value, dict)
        or set(value) != {"artifacts", "container", "schema_version"}
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or not isinstance(value["artifacts"], list)
        or len(value["artifacts"]) > len(PRIVATE_HELPER_ARTIFACT_NAMES)
    ):
        raise ReviewError("helper-private cleanup identity state is malformed")
    container = _parse_cleanup_identity(
        value["container"],
        label="helper-private container cleanup identity",
    )
    artifacts: dict[str, CleanupIdentity] = {}
    for raw_artifact in value["artifacts"]:
        if not isinstance(raw_artifact, dict) or set(raw_artifact) != {
            "device",
            "inode",
            "name",
        }:
            raise ReviewError("helper-private artifact cleanup identity is malformed")
        name = raw_artifact["name"]
        if (
            not isinstance(name, str)
            or name not in PRIVATE_HELPER_ARTIFACT_NAMES
            or name in artifacts
        ):
            raise ReviewError("helper-private artifact cleanup identity is invalid")
        artifacts[name] = _parse_cleanup_identity(
            {"device": raw_artifact["device"], "inode": raw_artifact["inode"]},
            label=f"helper-private artifact cleanup identity {name}",
        )
    if require_all and set(artifacts) != set(PRIVATE_HELPER_ARTIFACT_NAMES):
        raise ReviewError("helper-private artifact cleanup identities are incomplete")
    return PrivateCleanupEvidence(container=container, artifacts=artifacts)


def parse_private_cleanup_evidence(value: Any) -> PrivateCleanupEvidence:
    return _parse_private_cleanup_evidence(value, require_all=True)


def parse_partial_private_cleanup_evidence(value: Any) -> PrivateCleanupEvidence:
    return _parse_private_cleanup_evidence(value, require_all=False)


def _parse_private_cleanup_state(
    value: Any,
) -> tuple[PrivateCleanupEvidence, frozenset[str]]:
    if (
        not isinstance(value, dict)
        or set(value) != {"binding", "removed", "schema_version"}
        or value.get("schema_version") != 1
        or not isinstance(value["removed"], list)
    ):
        raise ReviewError("helper-private cleanup state is malformed")
    removed_items = value["removed"]
    if (
        any(
            not isinstance(item, str) or item not in PRIVATE_HELPER_ARTIFACT_NAMES
            for item in removed_items
        )
        or len(set(removed_items)) != len(removed_items)
        or removed_items != sorted(removed_items)
    ):
        raise ReviewError("helper-private cleanup removal receipts are invalid")
    return (
        _parse_private_cleanup_evidence(
            value["binding"],
            require_all=True,
        ),
        frozenset(removed_items),
    )


def _parse_control_artifact_state(payload: dict[str, Any]) -> ControlArtifactState:
    if (
        set(payload) != {"artifacts", "directory", "private_cleanup", "schema_version"}
        or payload.get("schema_version") != CONTROL_ARTIFACT_SCHEMA_VERSION
    ):
        raise ReviewError("helper-private review control state fields are invalid")
    raw_entries = payload["artifacts"]
    if not isinstance(raw_entries, list) or len(raw_entries) != len(
        CONTROL_ARTIFACT_SPECS
    ):
        raise ReviewError("helper-private review control state entries are invalid")
    raw_directory = payload["directory"]
    directory_fields = {
        "ctime_ns",
        "device",
        "entry_count",
        "entry_names_sha256",
        "inode",
        "link_count",
        "mode",
        "mtime_ns",
        "uid",
    }
    if not isinstance(raw_directory, dict) or set(raw_directory) != directory_fields:
        raise ReviewError("helper-private review control directory state is malformed")
    integer_fields = directory_fields - {"entry_names_sha256"}
    if any(type(raw_directory[field]) is not int for field in integer_fields):
        raise ReviewError("helper-private review control directory state is invalid")
    expected_entry_names_sha256 = _control_entry_names_sha256(CONTROL_ARTIFACT_SPECS)
    if (
        raw_directory["device"] < 0
        or raw_directory["inode"] <= 0
        or raw_directory["link_count"] <= 0
        or raw_directory["mtime_ns"] < 0
        or raw_directory["ctime_ns"] < 0
        or raw_directory["uid"] != os.getuid()
        or not stat.S_ISDIR(raw_directory["mode"])
        or raw_directory["mode"] & (stat.S_IWGRP | stat.S_IWOTH)
        or raw_directory["entry_count"] != len(CONTROL_ARTIFACT_SPECS)
        or raw_directory["entry_names_sha256"] != expected_entry_names_sha256
    ):
        raise ReviewError("helper-private review control directory state is invalid")
    directory = ControlDirectoryEvidence(
        device=raw_directory["device"],
        inode=raw_directory["inode"],
        mode=raw_directory["mode"],
        link_count=raw_directory["link_count"],
        uid=raw_directory["uid"],
        mtime_ns=raw_directory["mtime_ns"],
        ctime_ns=raw_directory["ctime_ns"],
        entry_count=raw_directory["entry_count"],
        entry_names_sha256=raw_directory["entry_names_sha256"],
    )
    artifacts: dict[str, ControlArtifactEvidence] = {}
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "name",
            "record_count",
            "sha256",
            "size",
        }:
            raise ReviewError("helper-private review control state entry is malformed")
        name = raw_entry["name"]
        if not isinstance(name, str) or name not in CONTROL_ARTIFACT_SPECS:
            raise ReviewError("helper-private review control state entry is unknown")
        if name in artifacts:
            raise ReviewError("helper-private review control state entry is duplicate")
        max_bytes, record_limit = CONTROL_ARTIFACT_SPECS[name]
        size = raw_entry["size"]
        sha256 = raw_entry["sha256"]
        record_count = raw_entry["record_count"]
        if (
            type(size) is not int
            or not 0 <= size <= max_bytes
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise ReviewError(
                "helper-private review control state entry is inconsistent"
            )
        if record_limit is None:
            if record_count is not None:
                raise ReviewError(
                    "helper-private review control state record count is invalid"
                )
        elif (
            type(record_count) is not int
            or not 0 <= record_count <= record_limit
            or (size == 0) != (record_count == 0)
            or (name == "changed-blob-findings.z" and record_count % 3 != 0)
        ):
            raise ReviewError(
                "helper-private review control state record count is invalid"
            )
        artifacts[name] = ControlArtifactEvidence(
            name=name,
            sha256=sha256,
            size=size,
            record_count=record_count,
        )
    if set(artifacts) != set(CONTROL_ARTIFACT_SPECS):
        raise ReviewError("helper-private review control state is incomplete")
    private_cleanup, private_artifacts_removed = _parse_private_cleanup_state(
        payload["private_cleanup"]
    )
    return ControlArtifactState(
        artifacts=artifacts,
        directory=directory,
        private_cleanup=private_cleanup,
        private_artifacts_removed=private_artifacts_removed,
    )


def _load_control_artifact_state(
    *,
    container_dir: pathlib.Path,
) -> ControlArtifactState:
    return _parse_control_artifact_state(
        _read_bounded_json(
            container_dir / CONTROL_ARTIFACT_STATE_NAME,
            label="helper-private review control state",
        )
    )


def _load_control_artifact_state_at(
    container_descriptor: int,
) -> ControlArtifactState:
    return _parse_control_artifact_state(
        _read_bounded_json_at(
            container_descriptor,
            CONTROL_ARTIFACT_STATE_NAME,
            label="helper-private review control state",
        )
    )


def _write_control_artifact_state_at(
    container_descriptor: int,
    state: ControlArtifactState,
) -> None:
    encoded = _bounded_json_bytes(
        state.to_json(),
        label="helper-private review control state",
    )
    temporary_name = f".{CONTROL_ARTIFACT_STATE_NAME}.{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=container_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.replace(
            temporary_name,
            CONTROL_ARTIFACT_STATE_NAME,
            src_dir_fd=container_descriptor,
            dst_dir_fd=container_descriptor,
        )
        os.fsync(container_descriptor)
    except OSError as error:
        raise ReviewError(
            f"cannot persist helper-private cleanup receipt: {error}"
        ) from error
    finally:
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=container_descriptor)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def validate_secret_delta_summary(
    value: Any,
    *,
    label: str = "secret-delta",
) -> dict[str, Any]:
    required_fields = {"limitations", "location_status", "status", "violations"}
    if (
        not isinstance(value, dict)
        or not required_fields.issubset(value)
        or not set(value).issubset(required_fields | {"failure_class"})
        or value.get("location_status") not in {"complete", "inconclusive"}
        or value.get("status") not in {"clean", "violations", "inconclusive"}
        or not isinstance(value.get("limitations"), list)
        or not all(isinstance(item, str) for item in value.get("limitations", []))
        or not isinstance(value.get("violations"), list)
        or len(value.get("violations", [])) > MAX_SYNTHETIC_EVIDENCE_ENTRIES
    ):
        raise ReviewError(f"{label} is invalid")

    allowed_rules = {rule for rule, _pattern in SECRET_PATTERNS} | {
        "generic-secret-assignment",
        "pgp-private-key",
        "private-key",
    }
    seen_digests: set[str] = set()
    total_additions = 0
    violations = value["violations"]
    for violation in violations:
        if not isinstance(violation, dict) or set(violation) != {
            "additions",
            "base_count",
            "delta",
            "head_count",
            "omitted_addition_location_count",
            "rules",
            "value_length",
            "value_sha256",
        }:
            raise ReviewError(f"{label} violation is malformed")
        base_count = violation["base_count"]
        head_count = violation["head_count"]
        delta = violation["delta"]
        omitted = violation["omitted_addition_location_count"]
        rules = violation["rules"]
        value_length = violation["value_length"]
        digest = violation["value_sha256"]
        additions = violation["additions"]
        if (
            type(base_count) is not int
            or type(head_count) is not int
            or type(delta) is not int
            or base_count < 0
            or head_count <= base_count
            or delta != head_count - base_count
            or type(omitted) is not int
            or omitted < 0
            or not isinstance(rules, list)
            or not rules
            or len(rules) > len(allowed_rules)
            or not all(
                isinstance(rule, str) and rule in allowed_rules for rule in rules
            )
            or rules != sorted(set(rules))
            or type(value_length) is not int
            or not 0 < value_length <= MAX_PEM_SECRET_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest in seen_digests
            or not isinstance(additions, list)
            or len(additions) > MAX_SECRET_DELTA_ADDITION_LOCATIONS
        ):
            raise ReviewError(f"{label} violation is inconsistent")
        total_additions += len(additions)
        if total_additions > MAX_SECRET_DELTA_ADDITION_LOCATIONS:
            raise ReviewError(f"{label} has too many addition locations")
        addition_occurrence_count = 0
        for addition in additions:
            if not isinstance(addition, dict) or set(addition) != {
                "line",
                "occurrence_count",
                "path",
                "surface",
            }:
                raise ReviewError(f"{label} addition is malformed")
            line = addition["line"]
            occurrence_count = addition["occurrence_count"]
            path = addition["path"]
            surface = addition["surface"]
            if (
                (line is not None and (type(line) is not int or line <= 0))
                or type(occurrence_count) is not int
                or occurrence_count <= 0
                or not isinstance(path, str)
                or not path
                or "\x00" in path
                or not isinstance(surface, str)
                or surface not in {"binary", "blob", "path", "symlink-target"}
            ):
                raise ReviewError(f"{label} addition is inconsistent")
            addition_occurrence_count += occurrence_count
        if addition_occurrence_count > delta or (
            value["location_status"] == "complete"
            and (addition_occurrence_count != delta or omitted != 0)
        ):
            raise ReviewError(f"{label} addition evidence is inconsistent")
        seen_digests.add(digest)

    status = value["status"]
    failure_class = value.get("failure_class")
    if status == "inconclusive":
        valid_state = (
            set(value) == required_fields | {"failure_class"}
            and value["location_status"] == "inconclusive"
            and violations == []
            and isinstance(failure_class, str)
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", failure_class) is not None
        )
    elif status == "clean":
        valid_state = (
            set(value) == required_fields
            and value["location_status"] == "complete"
            and violations == []
        )
    else:
        valid_state = set(value) == required_fields and len(violations) > 0
    if not valid_state:
        raise ReviewError(f"{label} state is invalid")
    return dict(value)


def _merge_secret_count_manifest_shards(
    workspace_manifest: dict[str, Any],
    private_manifest: dict[str, Any],
) -> tuple[dict[str, Any], bool, list[Any]]:
    expected_fields = {
        "base_ref",
        "catalog_schema_version",
        "entries",
        "head_ref",
        "pool_version",
        "schema_version",
        "secret_delta",
        "secret_reductions",
        "selected_exemptions",
    }
    private_only_fields = {"secret_reduction_values"}
    private_fields = set(private_manifest)
    if set(workspace_manifest) != expected_fields or private_fields not in (
        expected_fields,
        expected_fields | private_only_fields,
    ):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    raw_reduction_values = private_manifest.get("secret_reduction_values", [])
    if not isinstance(raw_reduction_values, list):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    private_public_fields = dict(private_manifest)
    private_public_fields.pop("secret_reduction_values", None)
    if workspace_manifest == private_public_fields:
        standard_delta = private_public_fields.get("secret_delta")
        standard_limitations = (
            standard_delta.get("limitations", [])
            if isinstance(standard_delta, dict)
            else []
        )
        if any(
            isinstance(item, str)
            and item.startswith(PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX)
            for item in standard_limitations
        ):
            raise ReviewError(
                "unsharded synthetic secret manifest has a shard commitment"
            )
        return dict(private_public_fields), False, list(raw_reduction_values)
    varying_fields = {"entries", "secret_delta", "secret_reductions"}
    if any(
        workspace_manifest[field] != private_public_fields[field]
        for field in expected_fields - varying_fields
    ):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    if (
        raw_reduction_values
        or workspace_manifest["secret_reductions"]
        or private_public_fields["secret_reductions"]
    ):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    deltas = (
        workspace_manifest["secret_delta"],
        private_public_fields["secret_delta"],
    )
    if any(not isinstance(delta, dict) for delta in deltas):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    delta_fixed_fields = {"limitations", "location_status", "status"}
    if any(
        set(delta) != delta_fixed_fields | {"violations"}
        or delta.get("status") not in {"clean", "violations"}
        or not isinstance(delta.get("violations"), list)
        for delta in deltas
    ):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    if any(deltas[0][field] != deltas[1][field] for field in delta_fixed_fields):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    status = deltas[0]["status"]
    has_violations = any(delta["violations"] for delta in deltas)
    if (status == "clean" and has_violations) or (
        status == "violations" and not has_violations
    ):
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    limitations = deltas[0]["limitations"]
    if not isinstance(limitations, list):
        raise ReviewError("helper-private manifest shard commitment is missing")
    commitments = [
        item
        for item in limitations
        if isinstance(item, str)
        and item.startswith(PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX)
    ]
    if (
        len(commitments) != 1
        or re.fullmatch(
            re.escape(PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX) + r"[0-9a-f]{64}",
            commitments[0],
        )
        is None
    ):
        raise ReviewError("helper-private manifest shard commitment is invalid")
    expected_private_digest = commitments[0][
        len(PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX) :
    ]
    actual_private_digest = _private_manifest_shard_rows_sha256(
        private_public_fields,
        raw_reduction_values,
    )
    if expected_private_digest != actual_private_digest:
        raise ReviewError("helper-private manifest shard commitment does not match")
    violation_digests: set[str] = set()
    violations: list[dict[str, Any]] = []
    for delta in deltas:
        for violation in delta["violations"]:
            if not isinstance(violation, dict):
                raise ReviewError(
                    "synthetic secret manifest does not match helper-private state"
                )
            digest = violation.get("value_sha256")
            if not isinstance(digest, str) or digest in violation_digests:
                raise ReviewError(
                    "synthetic secret manifest does not match helper-private state"
                )
            violation_digests.add(digest)
            violations.append(violation)
    entries: list[dict[str, Any]] = []
    entry_keys: set[tuple[str, str]] = set()
    for shard in (workspace_manifest, private_public_fields):
        shard_entries = shard["entries"]
        if not isinstance(shard_entries, list):
            raise ReviewError(
                "synthetic secret manifest does not match helper-private state"
            )
        for entry in shard_entries:
            if not isinstance(entry, dict):
                raise ReviewError(
                    "synthetic secret manifest does not match helper-private state"
                )
            key = (entry.get("exemption_id"), entry.get("token_id"))
            if not all(isinstance(item, str) for item in key) or key in entry_keys:
                raise ReviewError(
                    "synthetic secret manifest does not match helper-private state"
                )
            entry_keys.add(key)
            entries.append(entry)
    merged = dict(workspace_manifest)
    merged["entries"] = sorted(
        entries,
        key=lambda entry: (entry["exemption_id"], entry["token_id"]),
    )
    merged_delta = dict(deltas[0])
    merged_delta["violations"] = sorted(
        violations,
        key=lambda violation: violation["value_sha256"],
    )
    merged["secret_delta"] = merged_delta
    merged["secret_reductions"] = []
    return merged, True, []


def secret_admission(
    *,
    repo: pathlib.Path,
    base_ref: str,
    head_ref: str,
) -> tuple[int, dict[str, Any]]:
    """Evaluate exact-secret growth for one frozen range without a reviewer run."""

    try:
        source_root = resolve_repo_root(repo)
        base_sha = resolve_commit(source_root, base_ref, label="base ref")
        head_sha = resolve_commit(source_root, head_ref, label="head ref")
        with _temporary_sanitized_git_view(
            source_root=source_root,
        ) as (ancestry_git_view, ancestry_object_directory):
            _require_ancestor_range(
                git_view=ancestry_git_view,
                object_directory=ancestry_object_directory,
                base_sha=base_sha,
                head_sha=head_sha,
            )
        catalog = load_catalog()
        validate_authoring_catalog_scanner_contract(catalog)
    except OSError as error:
        raise ReviewError(
            "direct secret-admission input or policy could not be read"
        ) from error

    failure_class: str | None = None
    cleanup_failure_class: str | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        temporary = tempfile.TemporaryDirectory(prefix="isolated-secret-admission-")
        git_view, object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=pathlib.Path(temporary.name),
        )
        public_manifest, private_manifest, _reductions = _secret_count_manifests(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
            catalog=catalog,
        )
        merged_manifest, _was_sharded, _private_values = (
            _merge_secret_count_manifest_shards(
                public_manifest,
                private_manifest,
            )
        )
        secret_delta = validate_secret_delta_summary(
            merged_manifest["secret_delta"],
            label="admission-only secret-delta",
        )
    except (OSError, ReviewError):
        failure_class = "exact-value-scan-incomplete"
        secret_delta = {
            "failure_class": failure_class,
            "limitations": [
                "The exact-value scan did not complete; merge admission is inconclusive."
            ],
            "location_status": "inconclusive",
            "status": "inconclusive",
            "violations": [],
        }
        secret_delta = validate_secret_delta_summary(
            secret_delta,
            label="admission-only secret-delta",
        )
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                cleanup_failure_class = "temporary-cleanup-incomplete"

    if cleanup_failure_class is not None and secret_delta["status"] == "clean":
        failure_class = cleanup_failure_class
        secret_delta = validate_secret_delta_summary(
            {
                "failure_class": failure_class,
                "limitations": [
                    "The temporary sanitized Git view could not be removed completely."
                ],
                "location_status": "inconclusive",
                "status": "inconclusive",
                "violations": [],
            },
            label="admission-only secret-delta",
        )

    status = secret_delta["status"]
    exit_code = {"clean": 0, "violations": 1, "inconclusive": 75}[status]
    summary: dict[str, Any] = {
        "base_sha": base_sha,
        "exit_code": exit_code,
        "head_sha": head_sha,
        "operation": "exact-secret-admission",
        "review_contract": "admission-only-no-reviewer",
        "review_range": f"{base_sha}..{head_sha}",
        "reviewer_started": False,
        "schema_version": 1,
        "secret_delta": secret_delta,
        "source": "direct-git-tree-scan",
        "status": status,
        "temporary_cleanup_status": (
            "complete" if cleanup_failure_class is None else "inconclusive"
        ),
    }
    if failure_class is not None:
        summary["failure_class"] = failure_class
    if cleanup_failure_class is not None:
        summary["temporary_cleanup_failure_class"] = cleanup_failure_class
    return exit_code, summary


def _load_legacy_manifest(
    *,
    control_dir: pathlib.Path,
    container_dir: pathlib.Path,
    catalog: SyntheticTokenCatalog,
    expected_artifact: ControlArtifactEvidence,
    expected_private_identity: CleanupIdentity,
    expected_base_ref: str,
    expected_head_ref: str,
) -> tuple[
    tuple[LegacyExemption, ...],
    tuple[AcceptedSyntheticValue, ...],
    dict[AcceptedSyntheticValue, LegacyCountState],
    list[dict[str, Any]],
    tuple[AcceptedSyntheticValue, ...],
    dict[AcceptedSyntheticValue, tuple[int, int, int, int]],
    dict[str, Any],
    list[dict[str, Any]],
]:
    manifest_path = control_dir / SYNTHETIC_MANIFEST_NAME
    private_manifest_path = container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME
    if not manifest_path.exists() and not private_manifest_path.exists():
        return (
            (),
            (),
            {},
            [],
            (),
            {},
            {
                "limitations": [],
                "location_status": "complete",
                "status": "clean",
                "violations": [],
            },
            [],
        )
    if not manifest_path.exists() or not private_manifest_path.exists():
        raise ReviewError("synthetic secret helper-private state is missing")
    workspace_manifest = _read_bounded_json(
        manifest_path,
        label="synthetic secret manifest",
        expected_artifact=expected_artifact,
    )
    private_manifest = _read_bounded_json(
        private_manifest_path,
        label="synthetic secret helper-private state",
        expected_identity=expected_private_identity,
    )
    (
        manifest,
        manifest_was_sharded,
        raw_reduction_values,
    ) = _merge_secret_count_manifest_shards(
        workspace_manifest,
        private_manifest,
    )
    if set(manifest) != {
        "base_ref",
        "catalog_schema_version",
        "entries",
        "head_ref",
        "pool_version",
        "schema_version",
        "secret_delta",
        "secret_reductions",
        "selected_exemptions",
    }:
        raise ReviewError("synthetic secret manifest fields are invalid")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != SYNTHETIC_MANIFEST_SCHEMA_VERSION
        or type(manifest["catalog_schema_version"]) is not int
        or manifest["catalog_schema_version"] != catalog.schema_version
        or manifest["pool_version"] != catalog.pool_version
        or manifest["base_ref"] != expected_base_ref
        or manifest["head_ref"] != expected_head_ref
    ):
        raise ReviewError(
            "synthetic secret manifest version or review range is invalid"
        )
    secret_delta = validate_secret_delta_summary(manifest["secret_delta"])
    selected_ids = manifest["selected_exemptions"]
    if not isinstance(selected_ids, list) or not all(
        isinstance(item, str) for item in selected_ids
    ):
        raise ReviewError("synthetic secret manifest selection is invalid")
    exemptions = resolve_legacy_exemptions(catalog, selected_ids)
    if tuple(item.identifier for item in exemptions) != tuple(
        item.identifier for item in catalog.legacy_exemptions
    ):
        raise ReviewError(
            "synthetic secret manifest does not cover every catalog legacy value"
        )
    accepted = accepted_legacy_values(catalog, exemptions)
    expected = {(item.exemption_id, item.identifier): item for item in accepted}
    raw_entries = manifest["entries"]
    if (
        not isinstance(raw_entries, list)
        or len(raw_entries) > MAX_SYNTHETIC_EVIDENCE_ENTRIES
    ):
        raise ReviewError("synthetic secret manifest entries are invalid")
    counts: dict[AcceptedSyntheticValue, LegacyCountState] = {}
    evidence: list[dict[str, Any]] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "base_count",
            "base_unembedded_count",
            "exemption_id",
            "head_count",
            "head_unembedded_count",
            "rule",
            "source_head_count",
            "source_head_unembedded_count",
            "token_id",
            "value_length",
            "value_sha256",
        }:
            raise ReviewError("synthetic secret manifest entry is malformed")
        key = (raw_entry["exemption_id"], raw_entry["token_id"])
        descriptor = expected.get(key)
        if descriptor is None or descriptor in counts:
            raise ReviewError("synthetic secret manifest entry is unknown or duplicate")
        base_count = raw_entry["base_count"]
        head_count = raw_entry["head_count"]
        source_head_count = raw_entry["source_head_count"]
        base_unembedded_count = raw_entry["base_unembedded_count"]
        head_unembedded_count = raw_entry["head_unembedded_count"]
        source_head_unembedded_count = raw_entry["source_head_unembedded_count"]
        if (
            type(base_count) is not int
            or type(head_count) is not int
            or type(source_head_count) is not int
            or type(base_unembedded_count) is not int
            or type(head_unembedded_count) is not int
            or type(source_head_unembedded_count) is not int
            or base_count < 0
            or head_count < 0
            or source_head_count < 0
            or base_unembedded_count < 0
            or head_unembedded_count < 0
            or source_head_unembedded_count < 0
            or base_unembedded_count > base_count
            or head_unembedded_count > head_count
            or source_head_unembedded_count > source_head_count
            or raw_entry["rule"] != descriptor.rule
            or raw_entry["value_sha256"] != descriptor.value_sha256
            or raw_entry["value_length"] != descriptor.value_length
        ):
            raise ReviewError("synthetic secret manifest entry is inconsistent")
        counts[descriptor] = LegacyCountState(
            base_count=base_count,
            head_count=head_count,
            source_head_count=source_head_count,
            base_unembedded_count=base_unembedded_count,
            head_unembedded_count=head_unembedded_count,
            source_head_unembedded_count=source_head_unembedded_count,
        )
        evidence.append(dict(raw_entry))
    if manifest_was_sharded:
        legacy_by_digest = {item.value_sha256: item for item in accepted}
        for violation in secret_delta["violations"]:
            descriptor = legacy_by_digest.get(violation["value_sha256"])
            if (
                descriptor is None
                or descriptor in counts
                or violation["rules"] != [descriptor.rule]
                or violation["value_length"] != descriptor.value_length
            ):
                raise ReviewError(
                    "sharded synthetic secret manifest violation is inconsistent"
                )
            counts[descriptor] = LegacyCountState(
                base_count=violation["base_count"],
                head_count=violation["head_count"],
                source_head_count=violation["head_count"],
                base_unembedded_count=0,
                head_unembedded_count=0,
                source_head_unembedded_count=0,
            )
    if secret_delta["status"] != "inconclusive" and set(counts) != set(accepted):
        raise ReviewError("synthetic secret manifest does not cover its selection")
    raw_reductions = manifest["secret_reductions"]
    if (
        not isinstance(raw_reductions, list)
        or len(raw_entries) + len(raw_reductions) > MAX_SYNTHETIC_EVIDENCE_ENTRIES
        or len(raw_reductions) > MAX_SECRET_REDUCTION_CANDIDATES
        or not isinstance(raw_reduction_values, list)
        or len(raw_reduction_values) > MAX_SECRET_REDUCTION_CANDIDATES
    ):
        raise ReviewError("secret-reduction manifest entries are invalid")
    private_values: dict[str, bytes] = {}
    for raw_private in raw_reduction_values:
        if not isinstance(raw_private, dict) or set(raw_private) != {
            "value_base64",
            "value_sha256",
        }:
            raise ReviewError("secret-reduction helper-private entry is malformed")
        digest = raw_private["value_sha256"]
        encoded = raw_private["value_base64"]
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(encoded, str)
        ):
            raise ReviewError("secret-reduction helper-private entry is inconsistent")
        try:
            encoded_bytes = encoded.encode("ascii")
            candidate = base64.b64decode(encoded_bytes, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise ReviewError(
                "secret-reduction helper-private entry is not canonical Base64"
            ) from error
        if (
            base64.b64encode(candidate) != encoded_bytes
            or not candidate
            or len(candidate) > MAX_PEM_SECRET_BYTES
            or hashlib.sha256(candidate).hexdigest() != digest
            or digest in private_values
        ):
            raise ReviewError("secret-reduction helper-private entry is inconsistent")
        private_values[digest] = candidate
    reduction_rules = {rule for rule, _pattern in SECRET_PATTERNS} | {
        "generic-secret-assignment",
        "pgp-private-key",
        "private-key",
    }
    reduction_values: list[AcceptedSyntheticValue] = []
    reduction_counts: dict[AcceptedSyntheticValue, tuple[int, int, int, int]] = {}
    reduction_evidence: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for raw_entry in raw_reductions:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "base_count",
            "head_count",
            "rules",
            "value_length",
            "value_sha256",
        }:
            raise ReviewError("secret-reduction manifest entry is malformed")
        digest = raw_entry["value_sha256"]
        candidate = private_values.get(digest)
        rules = raw_entry["rules"]
        base_count = raw_entry["base_count"]
        head_count = raw_entry["head_count"]
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest in seen_digests
            or candidate is None
            or type(raw_entry["value_length"]) is not int
            or raw_entry["value_length"] != len(candidate)
            or not isinstance(rules, list)
            or not rules
            or rules != sorted(set(rules))
            or not all(
                isinstance(rule, str) and rule in reduction_rules for rule in rules
            )
            or type(base_count) is not int
            or type(head_count) is not int
            or base_count < 0
            or head_count < 0
        ):
            raise ReviewError("secret-reduction manifest entry is inconsistent")
        seen_digests.add(digest)
        descriptor = _secret_reduction_descriptor(candidate, set(rules))
        reduction_values.append(descriptor)
        reduction_counts[descriptor] = (
            base_count,
            head_count,
            0,
            0,
        )
        reduction_evidence.append(dict(raw_entry))
    if seen_digests != set(private_values):
        raise ReviewError(
            "secret-reduction manifest does not match helper-private values"
        )
    if (
        sum(len(value) for value in private_values.values())
        > MAX_SECRET_REDUCTION_CANDIDATE_BYTES
    ):
        raise ReviewError(
            "secret-reduction helper-private values exceed the byte limit"
        )
    if secret_delta["status"] == "inconclusive" and (
        raw_entries
        or raw_reductions
        or raw_reduction_values
        or secret_delta["violations"]
    ):
        raise ReviewError("inconclusive secret-delta evidence must not claim counts")

    expected_violations: dict[str, tuple[int, int, list[str], int]] = {}
    count_items = [
        (
            descriptor,
            (
                count_state.base_count,
                count_state.head_count,
                count_state.base_unembedded_count,
                count_state.head_unembedded_count,
            ),
        )
        for descriptor, count_state in counts.items()
    ] + list(reduction_counts.items())
    for descriptor, (base_count, head_count, _unused_base, _unused_head) in count_items:
        if head_count <= base_count:
            continue
        rules = [descriptor.rule]
        if descriptor.kind == "secret-reduction":
            rules = next(
                entry["rules"]
                for entry in reduction_evidence
                if entry["value_sha256"] == descriptor.value_sha256
            )
        expected_violations[descriptor.value_sha256] = (
            base_count,
            head_count,
            rules,
            descriptor.value_length,
        )
    raw_violations = secret_delta["violations"]
    seen_violation_digests: set[str] = set()
    for raw_violation in raw_violations:
        if not isinstance(raw_violation, dict) or set(raw_violation) != {
            "additions",
            "base_count",
            "delta",
            "head_count",
            "omitted_addition_location_count",
            "rules",
            "value_length",
            "value_sha256",
        }:
            raise ReviewError("secret-delta violation evidence is malformed")
        digest = raw_violation["value_sha256"]
        if not isinstance(digest, str):
            raise ReviewError("secret-delta violation evidence is inconsistent")
        expected_violation = expected_violations.get(digest)
        if expected_violation is None or digest in seen_violation_digests:
            raise ReviewError("secret-delta violation evidence is inconsistent")
        base_count, head_count, rules, value_length = expected_violation
        additions = raw_violation["additions"]
        omitted = raw_violation["omitted_addition_location_count"]
        if (
            raw_violation["base_count"] != base_count
            or raw_violation["head_count"] != head_count
            or raw_violation["delta"] != head_count - base_count
            or raw_violation["rules"] != rules
            or raw_violation["value_length"] != value_length
            or not isinstance(additions, list)
            or len(additions) > MAX_SECRET_DELTA_ADDITION_LOCATIONS
            or type(omitted) is not int
            or omitted < 0
        ):
            raise ReviewError("secret-delta violation evidence is inconsistent")
        for addition in additions:
            if not isinstance(addition, dict) or set(addition) != {
                "line",
                "occurrence_count",
                "path",
                "surface",
            }:
                raise ReviewError("secret-delta addition evidence is malformed")
            line = addition["line"]
            occurrence_count = addition["occurrence_count"]
            path = addition["path"]
            if (
                (line is not None and (type(line) is not int or line <= 0))
                or type(occurrence_count) is not int
                or occurrence_count <= 0
                or not isinstance(path, str)
                or not path
                or "\x00" in path
                or addition["surface"]
                not in {"binary", "blob", "path", "symlink-target"}
            ):
                raise ReviewError("secret-delta addition evidence is inconsistent")
        seen_violation_digests.add(digest)
    if seen_violation_digests != set(expected_violations):
        raise ReviewError("secret-delta evidence does not cover every violation")
    expected_status = "violations" if expected_violations else "clean"
    if (
        secret_delta["status"] != "inconclusive"
        and secret_delta["status"] != expected_status
    ):
        raise ReviewError("secret-delta status is inconsistent")
    return (
        exemptions,
        accepted,
        counts,
        evidence,
        tuple(reduction_values),
        reduction_counts,
        dict(secret_delta),
        reduction_evidence,
    )


def _load_changed_synthetic_evidence(
    *,
    control_dir: pathlib.Path,
    accepted_values: tuple[AcceptedSyntheticValue, ...],
    required: bool,
    expected_artifact: ControlArtifactEvidence,
) -> list[dict[str, Any]]:
    evidence_path = control_dir / SYNTHETIC_CHANGED_EVIDENCE_NAME
    if not evidence_path.exists():
        if required:
            raise ReviewError("synthetic changed-blob evidence is missing")
        return []
    payload = _read_bounded_json(
        evidence_path,
        label="synthetic changed-blob evidence",
        expected_artifact=expected_artifact,
    )
    if (
        set(payload) != {"entries", "schema_version"}
        or payload.get("schema_version") != 1
    ):
        raise ReviewError("synthetic changed-blob evidence fields are invalid")
    entries = payload["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("synthetic changed-blob evidence entries are invalid")
    descriptors = {
        (item.kind, item.identifier, item.exemption_id): item
        for item in accepted_values
    }
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReviewError("synthetic changed-blob evidence entry is malformed")
        optional = {"exemption_id"} if "exemption_id" in entry else set()
        if (
            set(entry)
            != {
                "catalog_version",
                "kind",
                "occurrence_count",
                "path",
                "rule",
                "side",
                "surface",
                "token_id",
                "value_sha256",
            }
            | optional
        ):
            raise ReviewError(
                "synthetic changed-blob evidence entry fields are invalid"
            )
        descriptor = descriptors.get(
            (entry["kind"], entry["token_id"], entry.get("exemption_id"))
        )
        path_value = entry["path"]
        if (
            descriptor is None
            or entry["catalog_version"] != descriptor.catalog_version
            or entry["rule"] != descriptor.rule
            or entry["value_sha256"] != descriptor.value_sha256
            or entry["side"] not in {"base", "head"}
            or entry["surface"] != "changed-blob"
            or type(entry["occurrence_count"]) is not int
            or entry["occurrence_count"] <= 0
            or not isinstance(path_value, dict)
            or set(path_value) != {"sha256"}
            or not isinstance(path_value["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", path_value["sha256"]) is None
        ):
            raise ReviewError("synthetic changed-blob evidence entry is inconsistent")
    return [dict(entry) for entry in entries]


def _reject_materialized_cleanup_quarantine_paths(
    workspace_root: pathlib.Path,
) -> None:
    pending = [workspace_root]
    inspected_entries = 0
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError as error:
            raise ReviewError(
                "cannot inspect external review snapshot for reserved cleanup paths"
            ) from error
        for entry in entries:
            inspected_entries += 1
            if inspected_entries > MAX_SNAPSHOT_ENTRIES * 2:
                raise ReviewError(
                    "external review snapshot exceeds the quarantine validation limit"
                )
            if entry.name.startswith(REVIEW_CLEANUP_QUARANTINE_PREFIX):
                raise ReviewError(
                    "external review snapshot uses a reserved review cleanup "
                    "quarantine path component"
                )
            if entry.is_dir(follow_symlinks=False):
                pending.append(pathlib.Path(entry.path))


def _validate_external_private_artifacts(
    review: ReviewWorkspace,
    *,
    post_attempt_receipt: ValidatedWorkspaceLaunchReceipt | None,
) -> ControlArtifactState:
    control_state = load_bound_private_cleanup_state(
        review.container_dir,
        expected=review.private_cleanup,
    )
    removed = control_state.private_artifacts_removed
    if post_attempt_receipt is None:
        if removed:
            raise ReviewError(
                "helper-private artifacts were removed before external review "
                "validation"
            )
        current_private_cleanup = _capture_private_cleanup_evidence(
            review.container_dir,
            expected_container=review.private_cleanup.container,
            require_all=True,
        )
        if current_private_cleanup != review.private_cleanup:
            raise ReviewError(
                "helper-private artifacts do not match preparation identities"
            )
        return control_state
    receipt = post_attempt_receipt
    if (
        receipt.content_variant != review.content_variant
        or receipt.base_ref != review.base_ref
        or receipt.head_ref != review.head_ref
        or receipt.snapshot_tree_sha != review.snapshot_tree_sha
        or receipt.scope_identity != review.scope_identity
        or receipt.private_container != review.private_cleanup.container
        or receipt.private_artifacts
        != tuple(sorted(review.private_cleanup.artifacts.items()))
        or receipt.control_artifacts
        != tuple(sorted(control_state.artifacts.values(), key=lambda item: item.name))
        or receipt.control_directory != control_state.directory
    ):
        raise ReviewError(
            "post-attempt workspace state does not match its validated preflight "
            "receipt"
        )
    if removed != frozenset(PRIVATE_HELPER_ARTIFACT_NAMES):
        raise ReviewError(
            "post-attempt helper-private artifact removal receipts are incomplete"
        )
    current_private_cleanup = _capture_private_cleanup_evidence(
        review.container_dir,
        expected_container=review.private_cleanup.container,
        require_all=False,
    )
    if current_private_cleanup != PrivateCleanupEvidence(
        container=review.private_cleanup.container,
        artifacts={},
    ):
        raise ReviewError(
            "post-attempt helper-private artifacts reappeared after recorded removal"
        )
    return control_state


def _validated_workspace_launch_receipt(
    review: ReviewWorkspace,
    *,
    control_state: ControlArtifactState,
) -> ValidatedWorkspaceLaunchReceipt:
    if control_state.private_artifacts_removed:
        raise ReviewError(
            "cannot issue a post-attempt receipt after helper-private cleanup"
        )
    return ValidatedWorkspaceLaunchReceipt(
        content_variant=review.content_variant,
        base_ref=review.base_ref,
        head_ref=review.head_ref,
        snapshot_tree_sha=review.snapshot_tree_sha,
        scope_identity=review.scope_identity,
        private_container=review.private_cleanup.container,
        private_artifacts=tuple(sorted(review.private_cleanup.artifacts.items())),
        control_artifacts=tuple(
            sorted(control_state.artifacts.values(), key=lambda item: item.name)
        ),
        control_directory=control_state.directory,
    )


def _validate_remaining_control_artifacts(
    control_dir: pathlib.Path,
    *,
    control_state: ControlArtifactState,
) -> None:
    for artifact_name, (max_bytes, _record_limit) in sorted(
        CONTROL_ARTIFACT_SPECS.items()
    ):
        with _secure_file_reader(
            control_dir / artifact_name,
            label=f"post-attempt review control artifact {artifact_name}",
            max_bytes=max_bytes,
            expected_artifact=control_state.artifacts[artifact_name],
        ) as (artifact_handle, _artifact_metadata):
            while artifact_handle.read(64 * 1024):
                pass


def _validate_external_workspace(
    review: ReviewWorkspace,
    *,
    post_attempt_receipt: ValidatedWorkspaceLaunchReceipt | None,
) -> tuple[dict[str, Any], ValidatedWorkspaceLaunchReceipt | None]:
    validate_workspace_layout(review)
    worktree_admin = _validate_worktree_git_control(review)
    control_state = _validate_external_private_artifacts(
        review,
        post_attempt_receipt=post_attempt_receipt,
    )
    workspace_root = review.workspace_root.resolve(strict=True)
    _reject_materialized_cleanup_quarantine_paths(workspace_root)
    if not review.has_complete_scope_identity():
        raise ReviewError("external review scope identity does not match its snapshot")
    git_dir = (review.git_dir or review.container_dir / "review.git").resolve(
        strict=True
    )
    _validate_private_review_endpoint_state(
        review,
        git_dir=git_dir,
        worktree_admin=worktree_admin,
    )
    _validate_canonical_worktree_index(
        review,
        git_dir=git_dir,
        worktree_admin=worktree_admin,
    )
    _validate_private_review_integrity(review, git_dir=git_dir)
    _verify_materialized_snapshot(
        git_view=git_dir,
        object_directory=git_dir / "objects",
        workspace_root=workspace_root,
        snapshot_tree_sha=review.snapshot_tree_sha,
        allow_control_dir=True,
        verify_index_tree=False,
    )
    control_dir = workspace_root / ".codex-review"
    _inspect_control_directory(control_dir, expected=control_state.directory)
    control_artifacts = control_state.artifacts
    if post_attempt_receipt is not None:
        _validate_remaining_control_artifacts(
            control_dir,
            control_state=control_state,
        )
        _inspect_control_directory(control_dir, expected=control_state.directory)
        final_control_state = _validate_external_private_artifacts(
            review,
            post_attempt_receipt=post_attempt_receipt,
        )
        if final_control_state != control_state:
            raise ReviewError(
                "post-attempt helper-private cleanup state changed during validation"
            )
        return {}, None
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    catalog_legacy_values = accepted_legacy_values(catalog, catalog.legacy_exemptions)
    (
        _exemptions,
        legacy_values,
        legacy_counts,
        legacy_evidence,
        reduction_values,
        reduction_counts,
        secret_delta_evidence,
        reduction_evidence,
    ) = _load_legacy_manifest(
        control_dir=control_dir,
        container_dir=review.container_dir,
        catalog=catalog,
        expected_artifact=control_artifacts[SYNTHETIC_MANIFEST_NAME],
        expected_private_identity=review.private_cleanup.artifacts[
            SYNTHETIC_PRIVATE_MANIFEST_NAME
        ],
        expected_base_ref=review.base_ref,
        expected_head_ref=review.head_ref,
    )
    authoring_values = accepted_authoring_values(catalog)
    accepted_values = authoring_values + legacy_values
    if review.content_variant == "head" and any(
        count_state.source_head_count != count_state.head_count
        or count_state.source_head_unembedded_count != count_state.head_unembedded_count
        for count_state in legacy_counts.values()
    ):
        raise ReviewError("synthetic secret manifest head counts are inconsistent")
    if review.content_variant == "source-wip" and any(
        count_state.source_head_count > count_state.base_count
        or count_state.source_head_unembedded_count > count_state.base_unembedded_count
        for count_state in legacy_counts.values()
    ):
        raise ReviewError(
            "synthetic secret manifest source HEAD counts are inconsistent"
        )
    _scan_endpoint_commit_metadata(
        git_view=git_dir,
        object_directory=git_dir / "objects",
        base_sha=review.base_ref,
        head_sha=review.head_ref,
        authoring_values=authoring_values,
        legacy_values=catalog_legacy_values,
    )
    evidence_sensitive_values = (
        _all_catalog_sensitive_values(catalog) + reduction_values
    )
    admission_counts_available = secret_delta_evidence["status"] != "inconclusive"
    scan_values = (
        accepted_values + reduction_values if admission_counts_available else ()
    )
    expected_counts = (
        {
            descriptor: (
                count_state.base_count,
                count_state.head_count,
                count_state.base_unembedded_count,
                count_state.head_unembedded_count,
            )
            for descriptor, count_state in legacy_counts.items()
        }
        if admission_counts_available
        else {}
    )
    if admission_counts_available:
        expected_counts.update(reduction_counts)
    changed_accepted_evidence = _load_changed_synthetic_evidence(
        control_dir=control_dir,
        accepted_values=accepted_values,
        required=(control_dir / SYNTHETIC_MANIFEST_NAME).exists(),
        expected_artifact=control_artifacts[SYNTHETIC_CHANGED_EVIDENCE_NAME],
    )
    counted_exact_index = _index_exact_values(scan_values)
    occurrence_budget = LegacyOccurrenceBudget.default()
    snapshot_byte_budget = FileScanByteBudget.snapshot()

    accepted_evidence_counts: Counter[tuple[AcceptedSyntheticValue, str, str, str]] = (
        Counter()
    )
    frozen_head_counts: Counter[AcceptedSyntheticValue] = Counter()
    frozen_head_unembedded_counts: Counter[AcceptedSyntheticValue] = Counter()

    def record_scan(
        scan: SecretScanResult,
        *,
        surface: str,
        side: str,
        path_bytes: bytes,
    ) -> None:
        side_tag = (
            CHANGED_PATH_HEAD_TAG if side == "head" else CHANGED_PATH_BASE_ONLY_TAG
        )
        path_sha256 = _changed_path_digest(side_tag, path_bytes).decode("ascii")
        for accepted in accepted_values:
            count = scan.raw_occurrence_counts[accepted]
            if not count:
                continue
            _record_bounded_evidence_count(
                accepted_evidence_counts,
                (accepted, surface, side, path_sha256),
                count,
                reserved_entries=len(changed_accepted_evidence),
                overflow_message=(
                    "accepted synthetic-token evidence has too many entries"
                ),
            )

    if review.content_variant == "source-wip" and legacy_values:
        source_head_scan = _scan_frozen_tree_values(
            git_view=git_dir,
            object_directory=git_dir / "objects",
            commit=review.head_ref,
            accepted_values=accepted_values,
            raw_occurrence_values=legacy_values,
            exact_only=True,
        )
        for descriptor, count_state in legacy_counts.items():
            if (
                source_head_scan.raw_occurrence_counts[descriptor]
                != count_state.source_head_count
                or source_head_scan.unembedded_occurrence_counts[descriptor]
                != count_state.source_head_unembedded_count
            ):
                raise ReviewError(
                    "source HEAD legacy synthetic fixture count changed after "
                    f"preparation for {descriptor.identifier}"
                )

    if review.content_variant == "source-wip":
        source_head_findings: list[str] = []
        source_head_finding_count = 0
        source_head_event_budget = SecretScanBudget.default()
        accepted_index = _index_accepted_values(accepted_values)
        legacy_exact_index = _index_exact_values(legacy_values)

        def record_source_head_finding(value: str) -> None:
            nonlocal source_head_finding_count
            source_head_finding_count += 1
            if len(source_head_findings) < 10:
                source_head_findings.append(value)

        def inspect_source_head_path(raw_path: bytes) -> None:
            rule = _value_secret_rule(
                raw_path,
                event_budget=source_head_event_budget,
            )
            path = os.fsdecode(raw_path)
            if rule is None:
                rule = _sensitive_path_rule(path)
            if rule is not None:
                path_display = _redact_secret_path(path, "source HEAD path")
                record_source_head_finding(f"{path_display} ({rule}; source-head-path)")

        def inspect_source_head_blob(
            raw_path: bytes,
            scan: SecretScanResult,
        ) -> None:
            if scan.blocking_rule is None:
                return
            path_display = _redact_secret_path(
                os.fsdecode(raw_path),
                "source HEAD blob path",
            )
            record_source_head_finding(
                f"{path_display} ({scan.blocking_rule}; source-head-blob)"
            )

        _scan_source_head_wip_delta(
            git_view=git_dir,
            object_directory=git_dir / "objects",
            source_head_sha=review.head_ref,
            snapshot_tree_sha=review.snapshot_tree_sha,
            accepted_values=accepted_values,
            raw_occurrence_values=legacy_values,
            accepted_index=accepted_index,
            event_budget=source_head_event_budget,
            exact_index=legacy_exact_index,
            occurrence_budget=occurrence_budget,
            path_callback=inspect_source_head_path,
            blob_callback=inspect_source_head_blob,
        )
        if source_head_finding_count:
            summary = ", ".join(source_head_findings)
            if source_head_finding_count > len(source_head_findings):
                summary += (
                    f", and {source_head_finding_count - len(source_head_findings)} "
                    "more"
                )
            raise ReviewError(
                "sensitive content preflight blocked external review; remove or "
                f"narrow these paths before egress: {summary}"
            )

    changed_path_digests_file = (
        review.workspace_root / ".codex-review" / CHANGED_PATH_DIGESTS_NAME
    )
    private_changed_paths_file = review.container_dir / PRIVATE_CHANGED_PATHS_NAME
    changed_path_count = 0
    changed_path_digest_evidence: list[str] = []
    changed_path_artifact = control_artifacts[CHANGED_PATH_DIGESTS_NAME]
    with (
        _secure_file_reader(
            changed_path_digests_file,
            label="external review changed path digests",
            max_bytes=MAX_CHANGED_METADATA_BYTES,
            expected_artifact=changed_path_artifact,
        ) as (digest_handle, _digest_metadata),
        _secure_file_reader(
            private_changed_paths_file,
            label="helper-private frozen changed paths",
            max_bytes=MAX_CHANGED_METADATA_BYTES,
            expected_identity=review.private_cleanup.artifacts[
                PRIVATE_CHANGED_PATHS_NAME
            ],
        ) as (path_handle, _path_metadata),
    ):
        digest_records = _iter_nul_records(
            digest_handle,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES,
            label="external review changed path digests",
        )
        for private_record in _iter_nul_records(
            path_handle,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES,
            label="helper-private frozen changed paths",
        ):
            changed_path_count += 1
            if len(private_record) < 2:
                raise ReviewError(
                    "helper-private frozen changed path record is malformed"
                )
            side_tag = private_record[:1]
            raw_path = private_record[1:]
            if side_tag not in {CHANGED_PATH_HEAD_TAG, CHANGED_PATH_BASE_ONLY_TAG}:
                raise ReviewError(
                    "helper-private frozen changed path record has an unknown side"
                )
            expected_digest = _changed_path_digest(side_tag, raw_path)
            if next(digest_records, None) != expected_digest:
                raise ReviewError(
                    "external review changed path digests do not match "
                    "helper-private changed paths"
                )
            changed_path_digest_evidence.append(expected_digest.decode("ascii"))
            if side_tag == CHANGED_PATH_BASE_ONLY_TAG:
                continue
        if next(digest_records, None) is not None:
            raise ReviewError(
                "external review changed path digests do not match "
                "helper-private changed paths"
            )
    if changed_path_count != changed_path_artifact.record_count:
        raise ReviewError(
            "external review changed paths do not match helper-private record state"
        )
    _reject_raw_values_in_evidence(
        changed_path_digest_evidence,
        accepted_values=evidence_sensitive_values,
        label="frozen changed path digest evidence",
    )
    changed_blob_findings = (
        review.workspace_root / ".codex-review/changed-blob-findings.z"
    )
    changed_blob_record_count = 0
    changed_blob_path_digest_evidence: list[str] = []
    changed_blob_artifact = control_artifacts["changed-blob-findings.z"]
    with _secure_file_reader(
        changed_blob_findings,
        label="external review changed-blob findings",
        max_bytes=MAX_CHANGED_METADATA_BYTES,
        expected_artifact=changed_blob_artifact,
    ) as (handle, _metadata):
        records = iter(
            _iter_nul_records(
                handle,
                byte_limit=MAX_CHANGED_METADATA_BYTES,
                record_limit=MAX_CHANGED_ENTRIES * 3,
                label="external review changed-blob findings",
            )
        )
        for raw_side in records:
            try:
                raw_path_digest = next(records)
                raw_rule = next(records)
                side = raw_side.decode("ascii")
                path_digest = raw_path_digest.decode("ascii")
                rule = raw_rule.decode("ascii")
            except (StopIteration, UnicodeDecodeError) as error:
                raise ReviewError(
                    "external review changed-blob findings are malformed"
                ) from error
            if re.fullmatch(r"[0-9a-f]{64}", path_digest) is None:
                raise ReviewError("external review changed-blob findings are malformed")
            changed_blob_path_digest_evidence.append(path_digest)
            changed_blob_record_count += 3
            _ = (rule, side)
    if changed_blob_record_count != changed_blob_artifact.record_count:
        raise ReviewError(
            "external review changed-blob findings do not match "
            "helper-private record state"
        )
    _reject_raw_values_in_evidence(
        changed_blob_path_digest_evidence,
        accepted_values=evidence_sensitive_values,
        label="changed-blob finding path digest evidence",
    )
    snapshot_entries = 0
    for candidate in review.workspace_root.rglob("*"):
        relative_path = candidate.relative_to(review.workspace_root)
        if relative_path.parts == (".git",):
            continue
        if _uses_review_cleanup_quarantine_namespace(relative_path):
            raise ReviewError(
                "external review snapshot uses a reserved review cleanup "
                "quarantine path component"
            )
        if relative_path.parts and relative_path.parts[0] == ".codex-review":
            continue
        snapshot_entries += 1
        if snapshot_entries > MAX_SNAPSHOT_ENTRIES:
            raise ReviewError("frozen workspace exceeds the review entry-count limit")
        relative = relative_path.as_posix()
        raw_relative = os.fsencode(relative)
        try:
            candidate_status = os.lstat(candidate)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect external review path {relative}"
            ) from error
        is_symlink = stat.S_ISLNK(candidate_status.st_mode)
        is_directory = stat.S_ISDIR(candidate_status.st_mode)
        materialized_gitlink = False
        if is_directory:
            try:
                with os.scandir(candidate) as entries:
                    materialized_gitlink = next(entries, None) is None
            except OSError as error:
                raise ReviewError(
                    f"cannot inspect external review directory {relative}"
                ) from error
        if is_symlink or not is_directory or materialized_gitlink:
            path_count_scan = _scan_secret_value(
                raw_relative,
                raw_occurrence_values=scan_values,
                _exact_index=counted_exact_index,
                _occurrence_budget=occurrence_budget,
                exact_only=True,
            )
            frozen_head_counts.update(path_count_scan.raw_occurrence_counts)
            frozen_head_unembedded_counts.update(
                path_count_scan.unembedded_occurrence_counts
            )
        path_display = relative
        if is_symlink:
            try:
                initial_link = os.lstat(candidate)
                target = os.readlink(candidate)
                raw_target = os.fsencode(target)
                resolved_target = (candidate.parent / target).resolve(strict=False)
                final_link = os.lstat(candidate)
                if target != os.readlink(candidate) or (
                    initial_link.st_dev,
                    initial_link.st_ino,
                    initial_link.st_size,
                    initial_link.st_mtime_ns,
                    initial_link.st_ctime_ns,
                ) != (
                    final_link.st_dev,
                    final_link.st_ino,
                    final_link.st_size,
                    final_link.st_mtime_ns,
                    final_link.st_ctime_ns,
                ):
                    raise ReviewError(
                        f"external review symlink changed while inspected: {path_display}"
                    )
            except RuntimeError as error:
                raise ReviewError(
                    f"external review symlink loop: {path_display}"
                ) from error
            except OSError as error:
                error_code = (
                    f" (errno {error.errno})" if error.errno is not None else ""
                )
                raise ReviewError(
                    f"cannot inspect external review symlink {path_display}{error_code}"
                ) from error
            if not is_relative_to(resolved_target, workspace_root):
                target_display = os.fspath(resolved_target)
                raise ReviewError(
                    "external review symlink escapes the frozen workspace: "
                    f"{path_display} -> {target_display}"
                )
            snapshot_byte_budget.consume(len(raw_target))
            target_scan = _scan_secret_value(
                raw_target,
                raw_occurrence_values=scan_values,
                _exact_index=counted_exact_index,
                _occurrence_budget=occurrence_budget,
                exact_only=True,
            )
            record_scan(
                target_scan,
                surface="symlink-target",
                side="head",
                path_bytes=raw_relative,
            )
            frozen_head_counts.update(target_scan.raw_occurrence_counts)
            frozen_head_unembedded_counts.update(
                target_scan.unembedded_occurrence_counts
            )
            continue
        if is_directory:
            continue
        scan = _file_secret_scan(
            candidate,
            raw_occurrence_values=scan_values,
            exact_index=counted_exact_index,
            occurrence_budget=occurrence_budget,
            max_bytes=MAX_SNAPSHOT_BLOB_BYTES,
            byte_budget=snapshot_byte_budget,
            diagnostic_path=path_display,
            exact_only=True,
        )
        record_scan(
            scan,
            surface="frozen-head",
            side="head",
            path_bytes=raw_relative,
        )
        frozen_head_counts.update(scan.raw_occurrence_counts)
        frozen_head_unembedded_counts.update(scan.unembedded_occurrence_counts)

    for accepted, (
        _base_count,
        expected_head_count,
        _unused_base,
        _unused_head,
    ) in expected_counts.items():
        actual_head_count = frozen_head_counts[accepted]
        if actual_head_count != expected_head_count:
            raise ReviewError(
                "frozen head secret count changed after preparation "
                f"for {accepted.identifier}: expected={expected_head_count}, "
                f"actual={actual_head_count}"
            )

    primary_diff_artifact = control_artifacts["review.diff"]
    with _secure_file_reader(
        review.diff_file,
        label="external review diff",
        max_bytes=MAX_DIFF_BYTES,
        expected_artifact=primary_diff_artifact,
    ) as (diff_handle, _diff_metadata):
        while diff_handle.read(64 * 1024):
            pass
    with _secure_file_reader(
        review.prompt_file,
        label="external review prompt",
        max_bytes=MAX_REVIEW_PROMPT_BYTES,
        expected_artifact=control_artifacts["review.prompt"],
    ) as (prompt_handle, _prompt_metadata):
        while prompt_handle.read(64 * 1024):
            pass
    accepted_evidence = list(changed_accepted_evidence)
    accepted_evidence.extend(
        _accepted_evidence_entry(
            accepted,
            surface=surface,
            side=side,
            path_sha256=path_sha256,
            occurrence_count=count,
        )
        for (accepted, surface, side, path_sha256), count in sorted(
            accepted_evidence_counts.items(),
            key=lambda item: (
                item[0][1],
                item[0][2],
                item[0][3],
                item[0][0].identifier,
            ),
        )
    )
    if len(accepted_evidence) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("accepted synthetic-token evidence has too many entries")
    evidence = {
        "primary_diff": {
            "path": ".codex-review/review.diff",
            "sha256": primary_diff_artifact.sha256,
            "size": primary_diff_artifact.size,
        },
        "secret_delta": secret_delta_evidence,
        "synthetic_tokens": {
            "accepted": accepted_evidence,
            "catalog_schema_version": catalog.schema_version,
            "legacy_counts": legacy_evidence,
            "pool_version": catalog.pool_version,
            "secret_reductions": reduction_evidence,
        },
    }
    _reject_raw_values_in_evidence(
        [entry["path"]["sha256"] for entry in accepted_evidence],
        accepted_values=evidence_sensitive_values,
        label="accepted synthetic-token path digest evidence",
    )
    try:
        _encode_synthetic_evidence_json(evidence)
    except ReviewError:
        # The manifest has already validated every catalog and reduction count.
        # For large evidence, keep the authoritative secret-delta admission
        # result and omit its optional secondary audit rows. The 64-KiB bound
        # applies to that secondary section; the complete preflight is
        # independently bounded by MAX_PREFLIGHT_JSON_BYTES.
        synthetic_tokens = dict(evidence["synthetic_tokens"])
        for field in ("accepted", "legacy_counts", "secret_reductions"):
            synthetic_tokens[field] = []
        evidence = dict(evidence)
        evidence["synthetic_tokens"] = synthetic_tokens
        _encode_synthetic_evidence_json(synthetic_tokens)
    complete_preflight_evidence = build_preflight_evidence(review, evidence)
    encode_preflight_json(complete_preflight_evidence)
    _inspect_control_directory(control_dir, expected=control_state.directory)
    final_control_state = _validate_external_private_artifacts(
        review,
        post_attempt_receipt=None,
    )
    if final_control_state != control_state:
        raise ReviewError(
            "helper-private cleanup state changed during external review validation"
        )
    return evidence, _validated_workspace_launch_receipt(
        review,
        control_state=control_state,
    )


def validate_external_workspace(
    review: ReviewWorkspace,
) -> dict[str, Any]:
    evidence, _receipt = _validate_external_workspace(
        review,
        post_attempt_receipt=None,
    )
    return evidence


def validate_external_workspace_for_launch(
    review: ReviewWorkspace,
) -> tuple[dict[str, Any], ValidatedWorkspaceLaunchReceipt]:
    evidence, receipt = _validate_external_workspace(
        review,
        post_attempt_receipt=None,
    )
    if receipt is None:
        raise ReviewError("external review preflight did not issue a launch receipt")
    return evidence, receipt


def validate_external_workspace_post_attempt(
    review: ReviewWorkspace,
    *,
    receipt: ValidatedWorkspaceLaunchReceipt,
) -> None:
    evidence, next_receipt = _validate_external_workspace(
        review,
        post_attempt_receipt=receipt,
    )
    if evidence or next_receipt is not None:
        raise ReviewError("post-attempt workspace validation returned preflight state")


def review_preflight_scope(content_variant: str) -> str:
    if content_variant == "source-wip":
        return (
            "digest-bound source WIP snapshot, scanned endpoint Git objects, "
            "diff, and review prompt"
        )
    if content_variant == "head":
        return (
            "detached clean head worktree, scanned endpoint Git objects, "
            "diff, and review prompt"
        )
    raise ReviewError("review preflight scope has an invalid content variant")


def build_preflight_evidence(
    review: ReviewWorkspace,
    synthetic_evidence: dict[str, Any],
) -> dict[str, Any]:
    fixed_evidence = {
        "content_variant": review.content_variant,
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "private_artifacts": "removed",
        "scope": review_preflight_scope(review.content_variant),
        "scope_identity": review.scope_identity,
        "snapshot_tree_sha": review.snapshot_tree_sha,
        "status": "review workspace containment and integrity checks passed",
    }
    overlap = set(fixed_evidence).intersection(synthetic_evidence)
    if overlap:
        raise ReviewError("synthetic-token evidence shadows fixed preflight fields")
    fixed_evidence.update(synthetic_evidence)
    return fixed_evidence


def _redact_secret_path(value: str, label: str) -> str:
    if _value_secret_rule(os.fsencode(value)):
        return f"<redacted {label}>"
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character.isprintable() and not 0xD800 <= codepoint <= 0xDFFF:
            escaped.append(character)
        elif codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def _sensitive_path_rule(relative: str) -> str | None:
    normalized = relative.casefold()
    parts = pathlib.PurePosixPath(normalized).parts
    name = parts[-1] if parts else ""
    if name in SENSITIVE_ANYWHERE_NAMES or name in SENSITIVE_FILE_NAMES:
        return "credential-path"
    if any(
        len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix
        for suffix in SENSITIVE_PATH_SUFFIXES
    ):
        return "credential-path"
    if (
        name == ".env"
        or name.endswith(".env")
        or (
            name.startswith(".env.")
            and not any(name.endswith(suffix) for suffix in SAFE_ENV_SUFFIXES)
        )
    ):
        return "environment-file"
    if name.endswith(SENSITIVE_SUFFIXES):
        return "credential-container"
    return None


def _file_secret_scan(
    path: pathlib.Path,
    *,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
    raw_occurrence_values: Iterable[AcceptedSyntheticValue] = (),
    capture_accepted_candidates: bool = False,
    capture_blocking_candidates: bool = False,
    capture_reduction_offsets: bool = False,
    reduced_secret_values: frozenset[bytes] = frozenset(),
    diff_surface: bool = False,
    accepted_index: AcceptedValueIndex | None = None,
    event_budget: SecretScanBudget | None = None,
    exact_index: ExactValueIndex | None = None,
    occurrence_budget: LegacyOccurrenceBudget | None = None,
    blocking_exact_matcher: LegacyPathMatcher | None = None,
    max_bytes: int | None = None,
    byte_budget: FileScanByteBudget | None = None,
    expected_artifact: ControlArtifactEvidence | None = None,
    diagnostic_path: str | None = None,
    exact_only: bool = False,
    _continue_after_blocking: bool = False,
) -> SecretScanResult:
    path_display = (
        diagnostic_path
        if diagnostic_path is not None
        else _redact_secret_path(os.fspath(path), "snapshot path")
    )
    with _secure_file_reader(
        path,
        label=f"external review content {path_display}",
        max_bytes=max_bytes,
        expected_artifact=expected_artifact,
    ) as (handle, initial):
        if byte_budget is not None:
            byte_budget.consume(initial.st_size)
        return _stream_secret_scan(
            handle,
            size=initial.st_size,
            accepted_values=accepted_values,
            raw_occurrence_values=raw_occurrence_values,
            capture_accepted_candidates=capture_accepted_candidates,
            capture_blocking_candidates=capture_blocking_candidates,
            capture_reduction_offsets=capture_reduction_offsets,
            reduced_secret_values=reduced_secret_values,
            diff_surface=diff_surface,
            _accepted_index=accepted_index,
            _event_budget=event_budget,
            _exact_index=exact_index,
            _occurrence_budget=occurrence_budget,
            _blocking_exact_matcher=blocking_exact_matcher,
            exact_only=exact_only,
            _continue_after_blocking=_continue_after_blocking,
        )


def _file_secret_rule(
    path: pathlib.Path,
    *,
    event_budget: SecretScanBudget | None = None,
) -> str | None:
    return _file_secret_scan(path, event_budget=event_budget).blocking_rule


def _starts_quoted_literal(value: bytes) -> bool:
    prefixes = (
        b"",
        b"r",
        b"u",
        b"b",
        b"f",
        b"t",
        b"l",
        b"br",
        b"rb",
        b"fr",
        b"rf",
        b"lr",
        b"rl",
        b"u8",
        b"ur",
        b"u8r",
        b"@",
        b"$",
        b"$@",
        b"@$",
    )
    lowered = value[:5].lower()
    return (
        any(
            lowered.startswith(prefix + quote)
            for prefix in prefixes
            for quote in (b"'", b'"', b"`")
        )
        or re.match(rb"(?i)(?:br|r)#{1,8}['\"]", value) is not None
    )


def _bounded_diff_hunk_context_before(
    value: bytes,
    before: int,
    *,
    prefix_context_complete: bool,
    lookbehind_bytes: int | None = None,
) -> tuple[DiffHunkContext | None, int]:
    if lookbehind_bytes is None:
        lookbehind_bytes = MAX_SECRET_PREFIX_PROOF_BYTES
    lower_bound = max(0, before - lookbehind_bytes)
    hunk_marker = max(
        value.rfind(b"\n@@ ", lower_bound, before),
        value.rfind(b"\n@@@ ", lower_bound, before),
    )
    if (
        lower_bound == 0
        and prefix_context_complete
        and value.startswith((b"@@ ", b"@@@ "))
    ):
        hunk_marker = max(hunk_marker, 0)
    file_marker = value.rfind(
        b"\ndiff --git ",
        lower_bound,
        before,
    )
    if (
        lower_bound == 0
        and prefix_context_complete
        and value.startswith(b"diff --git ")
    ):
        file_marker = max(file_marker, 0)
    if hunk_marker < 0 or hunk_marker <= file_marker:
        return None, lower_bound
    hunk_start = value.find(b"\n", hunk_marker + 1, before)
    if hunk_start < 0:
        return None, lower_bound
    return (
        DiffHunkContext(
            source_start=hunk_start + 1,
            retention_start=hunk_marker,
        ),
        lower_bound,
    )


def _assignment_proof_retention_start(
    value: bytes,
    *,
    assignment_start: int,
    diff_surface: bool,
    prefix_context_complete: bool,
) -> int:
    if not diff_surface:
        return 0 if prefix_context_complete else assignment_start
    line_start = (
        max(
            value.rfind(b"\n", 0, assignment_start),
            value.rfind(b"\r", 0, assignment_start),
        )
        + 1
    )
    hunk_context, lower_bound = _bounded_diff_hunk_context_before(
        value,
        line_start,
        prefix_context_complete=prefix_context_complete,
    )
    if hunk_context is not None:
        return hunk_context.retention_start
    if prefix_context_complete:
        return 0
    return lower_bound


def _secret_assignment_rhs_is_closed(
    value: bytes,
    *,
    prefix_proof_start: int = 0,
    assignment_start: int,
    assignment_end: int,
    assignment_line_start: int,
    proof_end: int,
    diff_surface: bool,
    prefix_context_complete: bool,
    suffix_context_complete: bool,
    event_budget: SecretScanBudget,
    prefix_proof_tracker: _PrefixProofRangeTracker | None = None,
    closure_recorder: Callable[[int], None] | None = None,
    literal_rhs_recorder: (
        Callable[[int, int | None, bytes, bytes, int | None], None] | None
    ) = None,
    unquoted_rhs_recorder: Callable[[int, int | None], None] | None = None,
) -> bool:
    if not (
        0
        <= prefix_proof_start
        <= assignment_start
        <= assignment_end
        <= proof_end
        <= len(value)
        and 0 <= assignment_line_start <= assignment_start
    ):
        raise ReviewError("sensitive scanner produced an invalid RHS proof range")
    proof_range_tracker = prefix_proof_tracker or _PrefixProofRangeTracker(event_budget)
    if proof_range_tracker.event_budget is not event_budget:
        raise ReviewError("sensitive scanner proof tracker uses the wrong budget")
    proof_suffix_context_complete = suffix_context_complete and proof_end == len(value)
    prefix_context_cache = _AssignmentPrefixContextCache(
        assignment_prefix_end=assignment_end,
    )
    cursor = assignment_end
    inspected_end = cursor
    wrapper_closers: list[int] = []
    wrapper_mismatch = False
    wrapper_token_seen = False
    wrapper_closed_before_literal = False
    pending_expression_continuation = False
    rhs_prefix_is_wrapper_only = True
    literal_prefixes = (b"br", b"rb", b"fr", b"rf", b"b", b"f", b"r", b"u")
    continuation_operators = frozenset(b"+-*/%&|^!=<>?:,.`")
    has_strong_secret_key = (
        STRONG_SECRET_KEY_NAME_PATTERN.search(value[assignment_start:assignment_end])
        is not None
    )

    def unquoted_candidate_is_sensitive(candidate: bytes) -> bool:
        return (
            not _is_placeholder_secret(candidate.lower())
            and not _is_secret_pattern_marker(candidate)
            and (_looks_like_unquoted_secret(candidate) or has_strong_secret_key)
        )

    assignment_diff_side: int | None = None
    if (
        diff_surface
        and assignment_line_start < proof_end
        and value[assignment_line_start] in (0x2B, 0x2D)
        and not value.startswith(
            (b"+++ ", b"--- "),
            assignment_line_start,
            proof_end,
        )
    ):
        assignment_diff_side = value[assignment_line_start]

    def record_inspected(end: int) -> None:
        nonlocal inspected_end
        inspected_end = max(inspected_end, min(end, proof_end))

    def finish(closed: bool) -> bool:
        if not proof_range_tracker.consume(assignment_end, inspected_end):
            raise ReviewError("sensitive scanner exceeded one RHS proof window")
        if closed and closure_recorder is not None:
            closure_recorder(inspected_end)
        return closed

    def tail_is_proven(
        *,
        rhs_end: int,
        required_closers: tuple[int, ...],
    ) -> bool:
        def record_tail_inspected(byte_count: int) -> None:
            record_inspected(rhs_end + byte_count)

        try:
            return _quoted_assignment_may_accept(
                value,
                assignment_start=assignment_start,
                assignment_end=rhs_end,
                prefix_proof_start=prefix_proof_start,
                required_closers=required_closers,
                diff_surface=diff_surface,
                prefix_context_complete=prefix_context_complete,
                suffix_context_complete=proof_suffix_context_complete,
                event_budget=event_budget,
                prefix_proof_tracker=proof_range_tracker,
                maximum_end=proof_end,
                inspection_recorder=record_tail_inspected,
                prefix_context_cache=prefix_context_cache,
            )
        except _IncompleteSecretScanSuffix:
            return False

    def external_closer_is_proven(closer_start: int) -> bool:
        try:
            return _quoted_assignment_may_accept(
                value,
                assignment_start=assignment_start,
                assignment_end=closer_start,
                prefix_proof_start=prefix_proof_start,
                diff_surface=diff_surface,
                prefix_context_complete=prefix_context_complete,
                suffix_context_complete=True,
                event_budget=event_budget,
                prefix_proof_tracker=proof_range_tracker,
                maximum_end=closer_start + 1,
                matching_external_closer_only=True,
                prefix_context_cache=prefix_context_cache,
            )
        except _IncompleteSecretScanSuffix:
            return False

    direct_unquoted_match = UNQUOTED_SECRET_ASSIGNMENT.match(
        value,
        assignment_start,
        proof_end,
    )
    if direct_unquoted_match is not None:
        unquoted_end = direct_unquoted_match.end()
        record_inspected(unquoted_end)
        return finish(
            tail_is_proven(
                rhs_end=unquoted_end,
                required_closers=(),
            )
        )

    def next_line_content_start(position: int) -> int:
        nonlocal inspected_end
        while position < proof_end:
            record_prefix = value[position]
            if not diff_surface or record_prefix not in (0x20, 0x2B, 0x2D):
                break
            if (
                assignment_diff_side is not None
                and record_prefix in (0x2B, 0x2D)
                and record_prefix != assignment_diff_side
            ):
                boundaries = tuple(
                    boundary
                    for boundary in (
                        value.find(b"\n", position, proof_end),
                        value.find(b"\r", position, proof_end),
                    )
                    if boundary >= 0
                )
                if not boundaries:
                    record_inspected(proof_end)
                    return proof_end
                boundary = min(boundaries)
                position = boundary + (
                    2 if value.startswith(b"\r\n", boundary, proof_end) else 1
                )
                record_inspected(position)
                continue
            position += 1
            break
        while position < proof_end and value[position] in (0x09, 0x20):
            position += 1
        record_inspected(position)
        return position

    while cursor < proof_end:
        record_inspected(cursor + 1)
        byte = value[cursor]
        if rhs_prefix_is_wrapper_only:
            placeholder_match = PLACEHOLDER_SECRET_PATTERN.match(
                value,
                cursor,
                proof_end,
            )
            if placeholder_match is not None:
                placeholder_end = placeholder_match.end()
                if placeholder_end == proof_end or value[placeholder_end] in (
                    0x09,
                    0x0A,
                    0x0D,
                    0x20,
                    0x29,
                    0x2C,
                    0x3B,
                    0x5D,
                    0x7D,
                ):
                    cursor = placeholder_end
                    record_inspected(cursor)
                    if tail_is_proven(
                        rhs_end=placeholder_end,
                        required_closers=tuple(reversed(wrapper_closers)),
                    ):
                        return finish(True)
                    rhs_prefix_is_wrapper_only = False
                    continue
        lowered_prefix = value[cursor : min(cursor + 3, proof_end)].lower()
        literal_prefix_length = 0
        quote = b""
        if byte in (0x22, 0x27):
            quote = value[cursor : cursor + 1]
        elif byte == 0x60:
            continuation_end = cursor + 1
            while continuation_end < proof_end and value[continuation_end] in (
                0x09,
                0x20,
            ):
                continuation_end += 1
            record_inspected(continuation_end)
            if continuation_end >= proof_end or value[continuation_end] not in (
                0x0A,
                0x0D,
            ):
                quote = b"`"
        else:
            for prefix in literal_prefixes:
                if lowered_prefix.startswith(prefix) and value[
                    cursor + len(prefix) : min(cursor + len(prefix) + 1, proof_end)
                ] in (b"'", b'"'):
                    literal_prefix_length = len(prefix)
                    quote = value[
                        cursor + literal_prefix_length : cursor
                        + literal_prefix_length
                        + 1
                    ]
                    break
        if quote:
            literal_prefix_is_valid = not wrapper_closed_before_literal and (
                not wrapper_token_seen or bool(wrapper_closers)
            )
            delimiter_start = cursor + literal_prefix_length
            delimiter = quote * (
                3
                if quote != b"`"
                and value.startswith(quote * 3, delimiter_start, proof_end)
                else 1
            )
            content_start = delimiter_start + len(delimiter)
            closing_start = _find_unescaped_delimiter(
                value,
                delimiter=delimiter,
                start=content_start,
                diff_side=assignment_diff_side,
                maximum_end=proof_end,
            )
            if closing_start is None:
                record_inspected(proof_end)
                if literal_rhs_recorder is not None:
                    literal_rhs_recorder(
                        content_start,
                        None,
                        delimiter,
                        value[cursor:delimiter_start],
                        assignment_diff_side,
                    )
                return finish(False)
            closing_end = closing_start + len(delimiter)
            record_inspected(closing_end)
            if not rhs_prefix_is_wrapper_only:
                literal_prefix_is_valid = False
            tail_closed = tail_is_proven(
                rhs_end=closing_end,
                required_closers=tuple(reversed(wrapper_closers)),
            )
            literal_candidate = value[content_start:closing_start]
            literal_is_sensitive = (
                closing_start - content_start >= 16
                and not _is_placeholder_secret(literal_candidate.lower())
                and not _is_secret_pattern_marker(literal_candidate)
                and (
                    rhs_prefix_is_wrapper_only
                    or unquoted_candidate_is_sensitive(literal_candidate)
                )
            )
            literal_is_closed = (
                tail_closed and literal_prefix_is_valid and not wrapper_mismatch
            )
            if literal_rhs_recorder is not None and (
                literal_is_closed or literal_is_sensitive
            ):
                literal_rhs_recorder(
                    content_start,
                    closing_start,
                    delimiter,
                    value[cursor:delimiter_start],
                    assignment_diff_side,
                )
            if literal_is_closed:
                return finish(True)
            if literal_is_sensitive:
                return finish(False)
            rhs_prefix_is_wrapper_only = False
            cursor = closing_end
            continue
        if byte in (0x09, 0x20):
            cursor += 1
            continue
        if byte in (0x28, 0x5B, 0x7B):
            wrapper_token_seen = True
            wrapper_closers.append({0x28: 0x29, 0x5B: 0x5D, 0x7B: 0x7D}[byte])
            pending_expression_continuation = False
            cursor += 1
            continue
        if byte in (0x29, 0x5D, 0x7D):
            if (
                not wrapper_closers
                and not wrapper_mismatch
                and not rhs_prefix_is_wrapper_only
                and external_closer_is_proven(cursor)
            ):
                return finish(True)
            wrapper_token_seen = True
            wrapper_closed_before_literal = True
            if wrapper_closers:
                if byte == wrapper_closers[-1]:
                    wrapper_closers.pop()
                else:
                    wrapper_mismatch = True
            else:
                wrapper_mismatch = True
            pending_expression_continuation = False
            cursor += 1
            continue
        if value.startswith(b"/*", cursor, proof_end):
            comment_end = value.find(b"*/", cursor + 2, proof_end)
            if comment_end < 0:
                record_inspected(proof_end)
                return finish(False)
            cursor = comment_end + 2
            record_inspected(cursor)
            continue
        if value.startswith(b"//", cursor, proof_end) or byte == 0x23:
            boundaries = tuple(
                boundary
                for boundary in (
                    value.find(b"\n", cursor, proof_end),
                    value.find(b"\r", cursor, proof_end),
                )
                if boundary >= 0
            )
            if not boundaries:
                record_inspected(proof_end)
                return finish(False)
            cursor = min(boundaries)
            record_inspected(cursor)
            continue
        if byte in (0x0A, 0x0D):
            previous = cursor - 1
            while previous >= assignment_end and value[previous] in (0x09, 0x20):
                previous -= 1
            next_cursor = cursor + (
                2 if value.startswith(b"\r\n", cursor, proof_end) else 1
            )
            logical_next = next_line_content_start(next_cursor)
            previous_continues = previous >= assignment_end and (
                value[previous] == 0x5C or value[previous] in continuation_operators
            )
            next_continues = (
                logical_next < proof_end
                and value[logical_next] in continuation_operators
            )
            line_continues = (
                bool(wrapper_closers)
                or wrapper_mismatch
                or pending_expression_continuation
                or previous_continues
                or next_continues
            )
            if not line_continues:
                record_inspected(next_cursor)
                return finish(
                    tail_is_proven(
                        rhs_end=cursor,
                        required_closers=(),
                    )
                )
            pending_expression_continuation = (
                pending_expression_continuation or previous_continues or next_continues
            )
            cursor = logical_next
            continue
        if byte == 0x3B and not wrapper_closers and not wrapper_mismatch:
            return finish(
                tail_is_proven(
                    rhs_end=cursor,
                    required_closers=(),
                )
            )
        if (
            byte == 0x2C
            and not wrapper_mismatch
            and tail_is_proven(
                rhs_end=cursor,
                required_closers=tuple(reversed(wrapper_closers)),
            )
        ):
            return finish(True)
        oversized_unquoted = OVERSIZED_UNQUOTED_SECRET_VALUE.match(
            value,
            cursor,
            proof_end,
        )
        if oversized_unquoted is not None:
            record_inspected(oversized_unquoted.end())
            if unquoted_rhs_recorder is not None:
                unquoted_rhs_recorder(cursor, None)
            return finish(False)
        unquoted_match = UNQUOTED_SECRET_VALUE.match(
            value,
            cursor,
            proof_end,
        )
        if unquoted_match is not None:
            candidate_start, candidate_end = unquoted_match.span(1)
            candidate = value[candidate_start:candidate_end]
            record_inspected(candidate_end)
            candidate_is_sensitive = unquoted_candidate_is_sensitive(candidate)
            candidate_is_closed = (
                rhs_prefix_is_wrapper_only
                and wrapper_token_seen
                and not wrapper_closed_before_literal
                and not wrapper_mismatch
                and tail_is_proven(
                    rhs_end=candidate_end,
                    required_closers=tuple(reversed(wrapper_closers)),
                )
            )
            if candidate_is_closed or candidate_is_sensitive:
                if unquoted_rhs_recorder is not None:
                    unquoted_rhs_recorder(candidate_start, candidate_end)
                return finish(candidate_is_closed)
            rhs_prefix_is_wrapper_only = False
            cursor = candidate_end
            continue
        rhs_prefix_is_wrapper_only = False
        pending_expression_continuation = byte in continuation_operators
        cursor += 1

    record_inspected(proof_end)
    return finish(False)


def _wrapper_ranges_are_balanced(
    value: bytes,
    *,
    prefix_start: int,
    prefix_end: int,
    suffix_start: int,
    suffix_end: int,
    require_complete: bool = True,
) -> bool:
    if not (
        0 <= prefix_start <= prefix_end <= suffix_start <= suffix_end <= len(value)
    ):
        raise ReviewError("sensitive scanner produced invalid wrapper proof ranges")
    expected_closers: list[int] = []
    closer_by_opener = {
        0x28: 0x29,
        0x5B: 0x5D,
        0x7B: 0x7D,
    }
    trivia = frozenset((0x09, 0x0A, 0x0D, 0x20))
    for index in range(prefix_start, prefix_end):
        byte = value[index]
        if byte in trivia:
            continue
        closer = closer_by_opener.get(byte)
        if closer is None:
            return False
        expected_closers.append(closer)
    for index in range(suffix_start, suffix_end):
        byte = value[index]
        if byte in trivia:
            continue
        if not expected_closers or byte != expected_closers.pop():
            return False
    return not expected_closers or not require_complete


def _quoted_assignment_may_accept(
    value: bytes,
    *,
    prefix_proof_start: int = 0,
    assignment_start: int,
    assignment_end: int,
    required_closers: tuple[int, ...] = (),
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    event_budget: SecretScanBudget,
    prefix_proof_tracker: _PrefixProofRangeTracker | None = None,
    maximum_end: int | None = None,
    inspection_recorder: Callable[[int], None] | None = None,
    matching_external_closer_only: bool = False,
    prefix_context_cache: _AssignmentPrefixContextCache | None = None,
) -> bool:
    logical_end = len(value) if maximum_end is None else min(len(value), maximum_end)
    if not (
        0 <= prefix_proof_start <= assignment_start <= assignment_end <= logical_end
    ):
        raise ReviewError(
            "sensitive scanner produced an invalid assignment proof range"
        )
    if prefix_context_cache is not None and not (
        assignment_start <= prefix_context_cache.assignment_prefix_end <= assignment_end
    ):
        raise ReviewError(
            "sensitive scanner produced an invalid cached assignment prefix"
        )
    proof_range_tracker = prefix_proof_tracker or _PrefixProofRangeTracker(event_budget)
    if proof_range_tracker.event_budget is not event_budget:
        raise ReviewError("sensitive scanner proof tracker uses the wrong budget")
    suffix_context_complete = suffix_context_complete and logical_end == len(value)
    cursor = assignment_end
    inspected = 0
    crossed_line_boundary = False
    skipped_diff_bytes = 0
    diff_source_proof_bytes = 0
    match_line_start = (
        max(
            value.rfind(b"\n", 0, assignment_start),
            value.rfind(b"\r", 0, assignment_start),
        )
        + 1
    )
    proof_retention_start = _assignment_proof_retention_start(
        value,
        assignment_start=assignment_start,
        diff_surface=diff_surface,
        prefix_context_complete=prefix_context_complete,
    )

    def logical_startswith(prefix: bytes | tuple[bytes, ...], start: int) -> bool:
        return value.startswith(prefix, start, logical_end)

    def logical_find(needle: bytes, start: int) -> int:
        return value.find(needle, start, logical_end)

    def triple_prefix_is_hunk_content() -> bool:
        hunk_context, lower_bound = _bounded_diff_hunk_context_before(
            value,
            match_line_start,
            prefix_context_complete=prefix_context_complete,
        )
        if not proof_range_tracker.consume(lower_bound, match_line_start):
            return False
        return hunk_context is not None

    match_diff_side: int | None = None
    if (
        diff_surface
        and match_line_start < logical_end
        and value[match_line_start] in (0x2B, 0x2D)
    ):
        if (
            logical_startswith(
                (b"+++ ", b"--- "),
                match_line_start,
            )
            and not triple_prefix_is_hunk_content()
        ):
            return False
        match_diff_side = value[match_line_start]

    def advance(count: int) -> bool:
        nonlocal crossed_line_boundary, cursor, inspected
        if inspected + count > MAX_SECRET_ASSIGNMENT_TRAILING_BYTES:
            return False
        if cursor + count > logical_end:
            if not suffix_context_complete:
                raise _IncompleteSecretScanSuffix(proof_retention_start)
            return False
        if (
            b"\n" in value[cursor : cursor + count]
            or b"\r" in value[cursor : cursor + count]
        ):
            crossed_line_boundary = True
        inspected += count
        if inspection_recorder is not None:
            inspection_recorder(inspected)
        cursor += count
        return True

    def trim_space() -> bool:
        while cursor < logical_end and value[cursor] in (0x20, 0x09):
            if not advance(1):
                return False
        return True

    def trim_continuation_trivia() -> bool:
        while cursor < logical_end:
            if not trim_space():
                return False
            if logical_startswith(b"\r\n", cursor):
                if not advance(2):
                    return False
            elif logical_startswith((b"\r", b"\n"), cursor):
                if not advance(1):
                    return False
            elif logical_startswith(b"#", cursor):
                if not advance(1):
                    return False
                while cursor < logical_end and value[cursor] not in (0x0A, 0x0D):
                    if not advance(1):
                        return False
            elif logical_startswith(b"/*", cursor):
                if not advance(2):
                    return False
                while cursor < logical_end and not logical_startswith(b"*/", cursor):
                    if not advance(1):
                        return False
                if cursor < logical_end and not advance(2):
                    return False
            else:
                return True
        return True

    def starts_trivia() -> bool:
        return logical_startswith((b"\r", b"\n", b"#", b"/*"), cursor)

    def starts_literal() -> bool:
        return _starts_quoted_literal(value[cursor : min(cursor + 16, logical_end)])

    def skip_opposite_diff_records() -> tuple[bool, bool]:
        nonlocal crossed_line_boundary, cursor, skipped_diff_bytes
        skipped = False
        while (
            match_diff_side is not None
            and cursor < logical_end
            and cursor > 0
            and value[cursor - 1] == 0x0A
            and value[cursor] in (0x2B, 0x2D)
            and value[cursor] != match_diff_side
        ):
            line_end = logical_find(b"\n", cursor)
            record_end = logical_end if line_end < 0 else line_end + 1
            record_size = record_end - cursor
            if skipped_diff_bytes + record_size > MAX_SECRET_PREFIX_PROOF_BYTES:
                return False, skipped
            if not proof_range_tracker.consume(cursor, record_end):
                return False, skipped
            if record_end == logical_end and not suffix_context_complete:
                raise _IncompleteSecretScanSuffix(proof_retention_start)
            skipped_diff_bytes += record_size
            cursor = record_end
            crossed_line_boundary = True
            skipped = True
        return True, skipped

    def trim_diff_record_prefix() -> bool:
        skip_succeeded, skipped = skip_opposite_diff_records()
        if not skip_succeeded:
            return False
        if skipped and not trim_space():
            return False
        if (
            diff_surface
            and cursor < logical_end
            and value[cursor] in (0x2B, 0x2D)
            and cursor > 0
            and value[cursor - 1] == 0x0A
        ):
            if not advance(1) or not trim_space():
                return False
        return True

    def starts_diff_metadata_boundary() -> bool:
        if not diff_surface or cursor == 0 or value[cursor - 1] != 0x0A:
            return False
        markers = (
            b"@@ -",
            b"@@@ -",
            b"diff --git ",
            b"\\ No newline at end of file",
        )
        return any(
            inspected + len(marker) <= MAX_SECRET_ASSIGNMENT_TRAILING_BYTES
            and logical_startswith(marker, cursor)
            for marker in markers
        )

    def starts_named_assignment() -> bool:
        limit = min(
            logical_end,
            cursor + MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - inspected + 1,
        )
        index = cursor

        def skip_space(position: int) -> int:
            while position < limit and value[position] in (0x20, 0x09):
                position += 1
            return position

        def skip_json_space(position: int) -> int:
            while position < limit:
                if value[position] in (0x09, 0x0A, 0x0D, 0x20):
                    position += 1
                    continue
                if (
                    diff_surface
                    and position > 0
                    and value[position - 1] in (0x0A, 0x0D)
                    and value[position] in (0x2B, 0x2D)
                ):
                    position += 1
                    continue
                break
            return position

        def skip_identifier(position: int) -> int:
            if position >= limit or not (
                0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                return position
            position += 1
            while position < limit and (
                0x30 <= value[position] <= 0x39
                or 0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] in (0x2D, 0x2E, 0x5F)
            ):
                position += 1
            return position

        while index < limit and value[index] in (0x5B, 0x7B):
            index = skip_json_space(index + 1)

        if index < limit and value[index] in (0x22, 0x27):
            quote = value[index]
            index += 1
            while index < limit:
                if value[index] == 0x5C:
                    index += 2
                    continue
                if value[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                return False
            index = skip_space(index)
            return index < limit and value[index] == 0x3A

        identifier_start = index
        index = skip_identifier(index)
        if index == identifier_start:
            return False
        first_identifier = value[identifier_start:index].lower()
        index = skip_space(index)
        if first_identifier in (b"const", b"let", b"var"):
            next_identifier = index
            index = skip_identifier(index)
            if index == next_identifier:
                return False
            index = skip_space(index)
        if index >= limit or value[index] not in (0x3A, 0x3D):
            return False
        if index + 1 < limit and value[index + 1] in (0x3A, 0x3D, 0x3E):
            return False
        return True

    def starts_python_call_statement() -> bool:
        limit = min(
            logical_end,
            cursor + MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - inspected + 1,
        )
        index = cursor

        def skip_identifier(position: int) -> int:
            if position >= limit or not (
                0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                return position
            position += 1
            while position < limit and (
                0x30 <= value[position] <= 0x39
                or 0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                position += 1
            return position

        first_start = index
        index = skip_identifier(index)
        if index == first_start:
            return False
        first_identifier = value[first_start:index].lower()
        if first_identifier in {
            b"and",
            b"as",
            b"assert",
            b"await",
            b"else",
            b"for",
            b"if",
            b"in",
            b"is",
            b"lambda",
            b"not",
            b"or",
            b"return",
            b"yield",
        }:
            return False
        while index < limit and value[index] == 0x2E:
            next_start = index + 1
            index = skip_identifier(next_start)
            if index == next_start:
                return False
        while index < limit and value[index] in (0x20, 0x09):
            index += 1
        return index < limit and value[index] == 0x28

    def starts_top_level_python_declaration() -> bool:
        if not crossed_line_boundary:
            return False
        line_start = (
            max(
                value.rfind(b"\n", 0, cursor),
                value.rfind(b"\r", 0, cursor),
            )
            + 1
        )
        prefix = value[line_start:cursor]
        if diff_surface and prefix[:1] in (b"+", b"-", b" "):
            prefix = prefix[1:]
        if prefix:
            return False

        limit = min(
            logical_end,
            cursor + MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - inspected + 1,
        )
        index = cursor

        def skip_horizontal_space(position: int) -> int:
            while position < limit and value[position] in (0x20, 0x09):
                position += 1
            return position

        def skip_identifier(position: int) -> int:
            if position >= limit or not (
                0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                return position
            position += 1
            while position < limit and (
                0x30 <= value[position] <= 0x39
                or 0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                position += 1
            return position

        def consume_keyword(position: int, keyword: bytes) -> int | None:
            end = position + len(keyword)
            if (
                end >= limit
                or not value.startswith(keyword, position, limit)
                or value[end] not in (0x20, 0x09)
            ):
                return None
            return skip_horizontal_space(end)

        async_end = consume_keyword(index, b"async")
        if async_end is not None:
            index = async_end
        declaration = b"def" if value.startswith(b"def", index, limit) else b"class"
        if async_end is not None and declaration != b"def":
            return False
        declaration_end = consume_keyword(index, declaration)
        if declaration_end is None:
            return False
        identifier_end = skip_identifier(declaration_end)
        if identifier_end == declaration_end:
            return False
        index = skip_horizontal_space(identifier_end)
        if declaration == b"def":
            return index < limit and value[index] == 0x28
        return index < limit and value[index] in (0x28, 0x3A)

    def diff_source_prefix(*, end: int | None = None) -> bytes | None:
        nonlocal diff_source_proof_bytes
        hunk_context, lower_bound = _bounded_diff_hunk_context_before(
            value,
            match_line_start,
            prefix_context_complete=prefix_context_complete,
        )
        if hunk_context is None and lower_bound == 0 and prefix_context_complete:
            hunk_start = 0
        elif hunk_context is None:
            return None
        else:
            hunk_start = hunk_context.source_start
        prefix_end = cursor if end is None else end
        skipped_bytes = skipped_diff_bytes if end is None else 0
        source_proof_bytes = prefix_end - hunk_start - skipped_bytes
        if not 0 <= source_proof_bytes <= MAX_SECRET_PREFIX_PROOF_BYTES:
            return None
        newly_proved_bytes = source_proof_bytes - diff_source_proof_bytes
        if newly_proved_bytes > 0 and not proof_range_tracker.consume(
            hunk_start,
            prefix_end,
            proof_byte_count=source_proof_bytes,
        ):
            return None
        diff_source_proof_bytes = max(
            diff_source_proof_bytes,
            source_proof_bytes,
        )
        raw_prefix = value[hunk_start:prefix_end]
        source_side = match_diff_side if match_diff_side is not None else 0x2B
        source_lines: list[bytes] = []
        for line in raw_prefix.splitlines(keepends=True):
            if line.startswith(b" "):
                source_lines.append(line[1:])
            elif line.startswith(bytes((source_side,))):
                source_lines.append(line[1:])
            elif line.startswith((b"+", b"-")):
                continue
            elif line.startswith(b"\\ No newline at end of file"):
                continue
            elif line:
                return None
        return b"".join(source_lines)

    def wrapper_context_before_assignment() -> (
        tuple[tuple[int, ...], bytes | None, tuple[int, ...]] | None
    ):
        if diff_surface:
            prefix = diff_source_prefix(end=assignment_start)
            if prefix is None:
                return None
        else:
            if not prefix_context_complete:
                return None
            if not proof_range_tracker.consume(
                prefix_proof_start,
                assignment_start,
            ):
                return None
            prefix = value[prefix_proof_start:assignment_start]

        closer_by_opener = {
            0x28: 0x29,
            0x5B: 0x5D,
            0x7B: 0x7D,
        }
        closers: list[int] = []
        mapping_key_end = (
            prefix_context_cache.assignment_prefix_end
            if prefix_context_cache is not None
            else assignment_end
        )

        def quote_starts_mapping_key(
            prefix_value: bytes,
            quote_start: int,
            delimiter: bytes,
        ) -> bool:
            backslash_start = quote_start
            while backslash_start > 0 and prefix_value[backslash_start - 1] == 0x5C:
                backslash_start -= 1
            if (quote_start - backslash_start) % 2 != 0:
                return False
            key_quote_end = _find_unescaped_delimiter(
                value,
                delimiter=delimiter,
                start=assignment_start,
                diff_side=match_diff_side,
                maximum_end=mapping_key_end,
            )
            if key_quote_end is None or key_quote_end >= mapping_key_end:
                return False
            key_separator = key_quote_end + len(delimiter)
            while key_separator < mapping_key_end and value[
                key_separator : key_separator + 1
            ] in (b" ", b"\t"):
                key_separator += 1
            return (
                key_separator < mapping_key_end
                and value[key_separator : key_separator + 1] == b":"
            )

        def logical_wrapper_closers(prefix_value: bytes) -> tuple[int, ...] | None:
            logical_closers: list[int] = []
            logical_index = 0
            while logical_index < len(prefix_value):
                if prefix_value.startswith(b"/*", logical_index):
                    comment_end = prefix_value.find(b"*/", logical_index + 2)
                    if comment_end < 0:
                        return None
                    logical_index = comment_end + 2
                    continue
                if (
                    prefix_value.startswith(b"//", logical_index)
                    or prefix_value[logical_index] == 0x23
                ):
                    line_end_candidates = tuple(
                        boundary
                        for boundary in (
                            prefix_value.find(b"\n", logical_index),
                            prefix_value.find(b"\r", logical_index),
                        )
                        if boundary >= 0
                    )
                    if not line_end_candidates:
                        return None
                    logical_index = min(line_end_candidates)
                    continue
                if prefix_value[logical_index] in (0x22, 0x27, 0x60):
                    quote = prefix_value[logical_index : logical_index + 1]
                    delimiter = quote * (
                        3
                        if quote != b"`"
                        and prefix_value.startswith(quote * 3, logical_index)
                        else 1
                    )
                    closing_start = _find_unescaped_delimiter(
                        prefix_value,
                        delimiter=delimiter,
                        start=logical_index + len(delimiter),
                    )
                    if closing_start is None:
                        if quote_starts_mapping_key(
                            prefix_value,
                            logical_index,
                            delimiter,
                        ):
                            logical_index = len(prefix_value)
                            continue
                        if logical_index + len(delimiter) == len(prefix_value):
                            return tuple(logical_closers)
                        return None
                    logical_index = closing_start + len(delimiter)
                    continue
                closer = closer_by_opener.get(prefix_value[logical_index])
                if closer is not None:
                    logical_closers.append(closer)
                    logical_index += 1
                    continue
                if prefix_value[logical_index] in (0x29, 0x5D, 0x7D):
                    if (
                        not logical_closers
                        or prefix_value[logical_index] != logical_closers.pop()
                    ):
                        return None
                next_marker = WRAPPER_CONTEXT_MARKER.search(
                    prefix_value,
                    logical_index + 1,
                )
                logical_index = (
                    next_marker.start()
                    if next_marker is not None
                    else len(prefix_value)
                )
            return tuple(logical_closers)

        index = 0
        while index < len(prefix):
            if prefix.startswith(b"/*", index):
                comment_end = prefix.find(b"*/", index + 2)
                if comment_end < 0:
                    return None
                index = comment_end + 2
                continue
            if prefix.startswith(b"//", index) or prefix[index] == 0x23:
                line_end_candidates = tuple(
                    boundary
                    for boundary in (
                        prefix.find(b"\n", index),
                        prefix.find(b"\r", index),
                    )
                    if boundary >= 0
                )
                if not line_end_candidates:
                    return None
                index = min(line_end_candidates)
                continue
            if prefix[index] in (0x22, 0x27, 0x60):
                quote = prefix[index : index + 1]
                delimiter = quote * (
                    3 if quote != b"`" and prefix.startswith(quote * 3, index) else 1
                )
                closing_start = _find_unescaped_delimiter(
                    prefix,
                    delimiter=delimiter,
                    start=index + len(delimiter),
                )
                if closing_start is None:
                    if quote_starts_mapping_key(prefix, index, delimiter):
                        index = len(prefix)
                        continue
                    if len(prefix) - index >= MAX_SECRET_ASSIGNMENT_TRAILING_BYTES:
                        return None
                    content_prefix = prefix[index + len(delimiter) :]
                    if b"\\" in content_prefix:
                        return None
                    logical_closers = logical_wrapper_closers(content_prefix)
                    if logical_closers is None:
                        return None
                    return tuple(closers), delimiter, logical_closers
                index = closing_start + len(delimiter)
                continue
            closer = closer_by_opener.get(prefix[index])
            if closer is not None:
                closers.append(closer)
                index += 1
                continue
            if prefix[index] in (0x29, 0x5D, 0x7D):
                if not closers or prefix[index] != closers.pop():
                    return None
            next_marker = WRAPPER_CONTEXT_MARKER.search(prefix, index + 1)
            index = next_marker.start() if next_marker is not None else len(prefix)
        return tuple(closers), None, ()

    def python_prefix_is_complete() -> bool:
        if diff_surface:
            prefix = diff_source_prefix()
            if prefix is None:
                return False
        else:
            if not prefix_context_complete:
                return False
            if not proof_range_tracker.consume(prefix_proof_start, cursor):
                return False
            prefix = value[prefix_proof_start:cursor]
        try:
            compile(
                prefix,
                "<synthetic-token-prefix>",
                "exec",
                flags=ast.PyCF_ONLY_AST,
                dont_inherit=True,
            )
        except (SyntaxError, UnicodeDecodeError, ValueError):
            return False
        return True

    if not trim_space():
        return False
    source_wrapper_closers: list[int] = []
    outer_delimiter: bytes | None = None
    outer_quote_pending = False
    source_literal_wrapper = False
    crossed_boundary = False
    required_closer_index = 0
    external_wrapper_closers: list[int] | None = None
    external_wrapper_context_loaded = False

    def starts_proven_python_declaration() -> bool:
        return starts_top_level_python_declaration() and python_prefix_is_complete()

    def load_external_wrapper_context() -> bool:
        nonlocal external_wrapper_closers, external_wrapper_context_loaded
        nonlocal outer_delimiter, outer_quote_pending, source_wrapper_closers
        if external_wrapper_context_loaded:
            return True
        if prefix_context_cache is not None and prefix_context_cache.loaded:
            external_wrapper_context = prefix_context_cache.context
        else:
            external_wrapper_context = wrapper_context_before_assignment()
            if prefix_context_cache is not None:
                prefix_context_cache.context = external_wrapper_context
                prefix_context_cache.loaded = True
        if external_wrapper_context is None:
            return False
        physical_closers, outer_delimiter, logical_closers = external_wrapper_context
        external_wrapper_closers = list(physical_closers)
        source_wrapper_closers = list(logical_closers)
        outer_quote_pending = outer_delimiter is not None
        external_wrapper_context_loaded = True
        return True

    if matching_external_closer_only:
        if (
            required_closers
            or cursor >= logical_end
            or value[cursor] not in (0x29, 0x5D, 0x7D)
            or not load_external_wrapper_context()
        ):
            return False
        if source_wrapper_closers:
            return value[cursor] == source_wrapper_closers[-1]
        if outer_quote_pending:
            return False
        return (
            bool(external_wrapper_closers)
            and value[cursor] == (external_wrapper_closers[-1])
        )

    def external_wrappers_are_closed() -> bool:
        return (
            load_external_wrapper_context()
            and not source_wrapper_closers
            and not outer_quote_pending
            and not external_wrapper_closers
        )

    def at_proven_end() -> bool:
        if cursor != logical_end:
            return False
        if not suffix_context_complete:
            raise _IncompleteSecretScanSuffix(proof_retention_start)
        return external_wrappers_are_closed()

    def consume_external_wrapper_closers() -> bool:
        if source_wrapper_closers or outer_quote_pending:
            return True
        while logical_startswith((b")", b"]", b"}"), cursor):
            if not load_external_wrapper_context():
                return False
            if (
                not external_wrapper_closers
                or value[cursor] != external_wrapper_closers.pop()
            ):
                return False
            if not advance(1) or not trim_space():
                return False
        return True

    def consume_direct_source_context() -> bool:
        nonlocal outer_quote_pending, source_literal_wrapper
        if not load_external_wrapper_context():
            return False
        while source_wrapper_closers and logical_startswith((b")", b"]", b"}"), cursor):
            if value[cursor] != source_wrapper_closers.pop():
                return False
            if not advance(1) or not trim_space():
                return False
        if source_wrapper_closers:
            return True
        if (
            outer_quote_pending
            and outer_delimiter is not None
            and logical_startswith(outer_delimiter, cursor)
        ):
            if not advance(len(outer_delimiter)) or not trim_space():
                return False
            outer_quote_pending = False
            source_literal_wrapper = True
        return True

    def consume_nested_literal() -> bool:
        quote = value[cursor : min(cursor + 1, logical_end)]
        delimiter = quote * (
            3 if quote != b"`" and logical_startswith(quote * 3, cursor) else 1
        )
        if not advance(len(delimiter)):
            return False
        while True:
            if cursor == logical_end:
                if not suffix_context_complete:
                    raise _IncompleteSecretScanSuffix(proof_retention_start)
                return False
            if starts_diff_metadata_boundary():
                return False
            if (
                diff_surface
                and cursor > 0
                and value[cursor - 1] in (0x0A, 0x0D)
                and not trim_diff_record_prefix()
            ):
                return False
            if logical_startswith(delimiter, cursor):
                return advance(len(delimiter))
            if value[cursor] == 0x5C:
                if cursor + 1 == logical_end:
                    if not suffix_context_complete:
                        raise _IncompleteSecretScanSuffix(proof_retention_start)
                    return False
                if not advance(2):
                    return False
                continue
            if not advance(1):
                return False

    def consume_block_comment() -> bool:
        if not advance(2):
            return False
        while not logical_startswith(b"*/", cursor):
            if cursor == logical_end:
                if not suffix_context_complete:
                    raise _IncompleteSecretScanSuffix(proof_retention_start)
                return False
            if not advance(1):
                return False
        return advance(2)

    def consume_line_comment(prefix_size: int) -> bool:
        if not advance(prefix_size):
            return False
        while cursor < logical_end and value[cursor] not in (0x0A, 0x0D):
            if not advance(1):
                return False
        return True

    def consume_following_wrapper_context() -> bool:
        nonlocal outer_quote_pending, source_literal_wrapper
        if not load_external_wrapper_context():
            return False
        closer_by_opener = {
            0x28: 0x29,
            0x5B: 0x5D,
            0x7B: 0x7D,
        }
        while source_wrapper_closers or outer_quote_pending or external_wrapper_closers:
            if cursor == logical_end:
                if not suffix_context_complete:
                    raise _IncompleteSecretScanSuffix(proof_retention_start)
                return False
            if starts_diff_metadata_boundary():
                return False
            if (
                diff_surface
                and cursor > 0
                and value[cursor - 1] in (0x0A, 0x0D)
                and not trim_diff_record_prefix()
            ):
                return False
            if not trim_space():
                return False
            if cursor == logical_end:
                if not suffix_context_complete:
                    raise _IncompleteSecretScanSuffix(proof_retention_start)
                return False
            if starts_trivia():
                if not trim_continuation_trivia():
                    return False
                continue

            if not source_wrapper_closers and outer_quote_pending:
                if outer_delimiter is None or not logical_startswith(
                    outer_delimiter, cursor
                ):
                    return False
                if not advance(len(outer_delimiter)):
                    return False
                outer_quote_pending = False
                source_literal_wrapper = True
                continue

            active_closers = (
                source_wrapper_closers
                if source_wrapper_closers
                else external_wrapper_closers
            )
            if logical_startswith(b"/*", cursor):
                if not consume_block_comment():
                    return False
                continue
            if logical_startswith(b"//", cursor):
                if not consume_line_comment(2):
                    return False
                continue
            if value[cursor] == 0x23:
                if not consume_line_comment(1):
                    return False
                continue
            if value[cursor] in (0x22, 0x27, 0x60):
                if not consume_nested_literal():
                    return False
                continue
            closer = closer_by_opener.get(value[cursor])
            if closer is not None:
                active_closers.append(closer)
                if not advance(1):
                    return False
                continue
            if value[cursor] in (0x29, 0x5D, 0x7D):
                if not active_closers or value[cursor] != active_closers.pop():
                    return False
                if not advance(1):
                    return False
                continue
            if not advance(1):
                return False
        return True

    def context_tail_is_proven() -> bool:
        tail_crossed_boundary = False
        if not trim_space():
            return False
        while starts_trivia():
            tail_crossed_boundary = True
            if not trim_continuation_trivia():
                return False
            if not trim_diff_record_prefix() or not trim_space():
                return False
        if at_proven_end():
            return True
        if starts_diff_metadata_boundary():
            return True
        if logical_startswith(b";", cursor):
            if not advance(1) or not trim_space():
                return False
            while starts_trivia():
                tail_crossed_boundary = True
                if not trim_continuation_trivia():
                    return False
                if not trim_diff_record_prefix() or not trim_space():
                    return False
            if at_proven_end() or starts_diff_metadata_boundary():
                return True
            return starts_named_assignment() or starts_proven_python_declaration()
        return tail_crossed_boundary and (
            starts_named_assignment() or starts_proven_python_declaration()
        )

    while required_closer_index < len(required_closers):
        expected_closer = required_closers[required_closer_index]
        if cursor < logical_end and value[cursor] == expected_closer:
            if not advance(1):
                return False
            required_closer_index += 1
            if not trim_space():
                return False
            continue
        if starts_trivia():
            crossed_boundary = True
            if not trim_continuation_trivia():
                return False
            if not trim_diff_record_prefix():
                return False
            continue
        if cursor == logical_end and not suffix_context_complete:
            raise _IncompleteSecretScanSuffix(proof_retention_start)
        return False
    if not consume_direct_source_context():
        return False

    while True:
        if not consume_direct_source_context():
            return False
        if not consume_external_wrapper_closers():
            return False
        if starts_trivia():
            crossed_boundary = True
            if not trim_continuation_trivia():
                return False
            if not trim_diff_record_prefix():
                return False
            continue
        break
    if at_proven_end():
        return True
    if logical_startswith(b";", cursor):
        if not advance(1) or not trim_space():
            return False
        if starts_trivia():
            if not trim_continuation_trivia():
                return False
        if at_proven_end():
            return True
        return external_wrappers_are_closed() and (
            starts_diff_metadata_boundary()
            or starts_named_assignment()
            or starts_proven_python_declaration()
        )
    if logical_startswith(b",", cursor):
        if not advance(1) or not trim_space():
            return False
        while True:
            if not consume_direct_source_context():
                return False
            if not consume_external_wrapper_closers():
                return False
            if starts_trivia():
                if not trim_continuation_trivia():
                    return False
                if not trim_diff_record_prefix():
                    return False
                continue
            if logical_startswith(b",", cursor):
                if not advance(1) or not trim_space():
                    return False
                continue
            break
        if at_proven_end():
            return True
        if starts_diff_metadata_boundary():
            return external_wrappers_are_closed()
        if logical_startswith(b";", cursor):
            if not advance(1) or not trim_space():
                return False
            if starts_trivia() and not trim_continuation_trivia():
                return False
            if at_proven_end():
                return True
            return external_wrappers_are_closed() and (
                starts_diff_metadata_boundary()
                or starts_named_assignment()
                or starts_proven_python_declaration()
            )
        if not (starts_named_assignment() or starts_proven_python_declaration()):
            return False
        if external_wrappers_are_closed():
            return True
        if not consume_following_wrapper_context():
            return False
        return context_tail_is_proven()
    if crossed_boundary:
        if not external_wrappers_are_closed():
            return False
        if starts_diff_metadata_boundary():
            return True
        if source_literal_wrapper:
            return (
                starts_named_assignment()
                or starts_python_call_statement()
                or starts_proven_python_declaration()
            )
        return starts_named_assignment() or starts_proven_python_declaration()
    return False


def _unquoted_assignment_may_accept(
    value: bytes,
    *,
    assignment_start: int,
    assignment_end: int,
    diff_surface: bool = False,
    allow_inline_hash_comment: bool = False,
) -> bool:
    cursor = assignment_end
    inspected = 0

    def advance(count: int) -> bool:
        nonlocal cursor, inspected
        if inspected + count > MAX_SECRET_ASSIGNMENT_TRAILING_BYTES:
            return False
        inspected += count
        cursor += count
        return True

    def trim_horizontal_space(*, indentation: bool = False) -> tuple[bool, int]:
        width = 0
        while cursor < len(value) and value[cursor] in (0x20, 0x09):
            if indentation and value[cursor] == 0x09:
                return False, width
            if not advance(1):
                return False, width
            width += 1
        return True, width

    def consume_line_break() -> bool:
        if value.startswith(b"\r\n", cursor):
            return advance(2)
        if value.startswith((b"\r", b"\n"), cursor):
            return advance(1)
        return False

    def consume_comment() -> bool:
        while cursor < len(value) and value[cursor] not in (0x0A, 0x0D):
            if not advance(1):
                return False
        return True

    def starts_named_assignment() -> bool:
        limit = min(
            len(value),
            cursor + MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - inspected + 1,
        )
        index = cursor

        def skip_space(position: int) -> int:
            while position < limit and value[position] in (0x20, 0x09):
                position += 1
            return position

        def skip_identifier(position: int) -> int:
            if position >= limit or not (
                0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] == 0x5F
            ):
                return position
            position += 1
            while position < limit and (
                0x30 <= value[position] <= 0x39
                or 0x41 <= value[position] <= 0x5A
                or 0x61 <= value[position] <= 0x7A
                or value[position] in (0x2D, 0x2E, 0x5F)
            ):
                position += 1
            return position

        while (
            index + 1 < limit
            and value[index] in (0x2D, 0x3F)
            and value[index + 1] in (0x20, 0x09)
        ):
            index = skip_space(index + 1)
        if index < limit and value[index] in (0x22, 0x27):
            quote = value[index]
            index += 1
            while index < limit:
                if value[index] == 0x5C:
                    index += 2
                    continue
                if value[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                return False
            index = skip_space(index)
            return index < limit and value[index] == 0x3A

        identifier_start = index
        index = skip_identifier(index)
        if index == identifier_start:
            return False
        first_identifier = value[identifier_start:index].lower()
        index = skip_space(index)
        if first_identifier in (b"const", b"let", b"var"):
            next_identifier = index
            index = skip_identifier(index)
            if index == next_identifier:
                return False
            index = skip_space(index)
        if index >= limit or value[index] not in (0x3A, 0x3D):
            return False
        if index + 1 < len(value) and value[index + 1] in (0x3A, 0x3D, 0x3E):
            return False
        return True

    lookbehind_start = max(
        0,
        assignment_start - MAX_SECRET_ASSIGNMENT_TRAILING_BYTES,
    )
    last_line_break = max(
        value.rfind(b"\n", lookbehind_start, assignment_start),
        value.rfind(b"\r", lookbehind_start, assignment_start),
    )
    if last_line_break < 0 and lookbehind_start > 0:
        return False
    line_start = last_line_break + 1
    content_start = line_start
    if (
        diff_surface
        and content_start < len(value)
        and value[content_start] in (0x20, 0x2B, 0x2D)
    ):
        content_start += 1
    key_start = content_start
    while key_start < assignment_start and value[key_start] == 0x20:
        key_start += 1
    if key_start < assignment_start and value[key_start] == 0x09:
        return False
    while (
        key_start + 1 < assignment_start
        and value[key_start] in (0x2D, 0x3F)
        and value[key_start + 1] in (0x20, 0x09)
    ):
        key_start += 1
        while key_start < assignment_start and value[key_start] == 0x20:
            key_start += 1
        if key_start < assignment_start and value[key_start] == 0x09:
            return False
    key_indentation = key_start - content_start

    trimmed, _width = trim_horizontal_space()
    if not trimmed:
        return False
    if cursor == len(value):
        return True
    if value[cursor] == 0x23:
        if not allow_inline_hash_comment or not consume_comment():
            return False
        if cursor == len(value):
            return True
        if not consume_line_break():
            return False
    elif value[cursor] == 0x3B:
        return False
    elif not consume_line_break():
        return False

    diff_boundaries = (
        b"@@ -",
        b"@@@ -",
        b"diff --git ",
        b"\\ No newline at end of file",
    )
    while True:
        if cursor == len(value):
            return True
        if diff_surface and any(
            value.startswith(marker, cursor) for marker in diff_boundaries
        ):
            return True
        if (
            diff_surface
            and cursor < len(value)
            and value[cursor] in (0x20, 0x2B, 0x2D)
            and not advance(1)
        ):
            return False
        trimmed, indentation = trim_horizontal_space(indentation=True)
        if not trimmed:
            return False
        if cursor == len(value):
            return True
        if value[cursor] == 0x23:
            if not consume_comment():
                return False
            if cursor == len(value):
                return True
            if not consume_line_break():
                return False
            continue
        if value.startswith((b"\r", b"\n"), cursor):
            if not consume_line_break():
                return False
            continue
        # Placeholder-only parsing may finish at source/container closers after a
        # consumed hash comment. Canonical synthetic values never enable this path.
        if allow_inline_hash_comment and value[cursor] in (0x29, 0x5D, 0x7D):
            while cursor < len(value) and value[cursor] in (0x29, 0x5D, 0x7D):
                if not advance(1):
                    return False
            trimmed, _width = trim_horizontal_space()
            if not trimmed:
                return False
            if cursor == len(value):
                return True
            return consume_line_break()
        if indentation > key_indentation:
            return False
        if value.startswith((b"---", b"..."), cursor):
            marker_end = cursor + 3
            return marker_end == len(value) or value[marker_end] in (
                0x09,
                0x0A,
                0x0D,
                0x20,
            )
        return starts_named_assignment()


def _provider_candidate_is_prefix_only(rule: str, candidate: bytes) -> bool:
    prefixes = {
        "anthropic-key": (b"sk-ant-",),
        "openai-key": (b"sk-", b"sk-proj-"),
        "github-token": (
            b"ghp_",
            b"gho_",
            b"ghu_",
            b"ghs_",
            b"ghr_",
            b"github_pat_",
        ),
        "gitlab-token": (b"glpat-",),
        "google-api-key": (b"AIza",),
        "pypi-token": (b"pypi-",),
        "slack-token": (
            b"xoxb-",
            b"xoxa-",
            b"xoxp-",
            b"xoxr-",
            b"xoxs-",
        ),
        "stripe-live-key": (b"sk_live_",),
    }
    actual_prefix = max(
        (prefix for prefix in prefixes.get(rule, ()) if candidate.startswith(prefix)),
        key=len,
        default=None,
    )
    return actual_prefix is not None and len(candidate) - len(actual_prefix) == 513


def _find_unescaped_delimiter(
    value: bytes,
    *,
    delimiter: bytes,
    start: int,
    diff_side: int | None = None,
    maximum_end: int | None = None,
) -> int | None:
    logical_end = len(value) if maximum_end is None else min(len(value), maximum_end)
    if not 0 <= start <= logical_end:
        raise ReviewError("sensitive scanner produced an invalid delimiter proof range")
    search_start = start
    while True:
        delimiter_start = value.find(delimiter, search_start, logical_end)
        if delimiter_start < 0:
            return None
        if diff_side is not None:
            line_start = (
                max(
                    value.rfind(b"\n", 0, delimiter_start),
                    value.rfind(b"\r", 0, delimiter_start),
                )
                + 1
            )
            record_prefix = value[line_start : line_start + 1]
            if record_prefix not in (b" ", bytes((diff_side,))):
                search_start = delimiter_start + 1
                continue
        backslash_start = delimiter_start
        while backslash_start > start and value[backslash_start - 1] == 0x5C:
            backslash_start -= 1
        if (delimiter_start - backslash_start) % 2 == 0:
            return delimiter_start
        search_start = delimiter_start + 1


def _exact_raw_literal_candidate(
    value: bytes,
    *,
    literal_prefix: bytes,
    delimiter: bytes,
    content_start: int,
    closing_start: int,
    diff_surface: bool,
    diff_side: int | None,
) -> bytes | None:
    closing_end = closing_start + len(delimiter)
    if not 0 <= content_start <= closing_start <= closing_end <= len(value):
        raise ReviewError("sensitive scanner produced an invalid literal proof range")
    if (
        _find_unescaped_delimiter(
            value,
            delimiter=delimiter,
            start=content_start,
            diff_side=diff_side,
            maximum_end=closing_end,
        )
        != closing_start
    ):
        raise ReviewError("sensitive scanner lost an exact literal delimiter")

    candidate = value[content_start:closing_start]
    has_line_break = b"\r" in candidate or b"\n" in candidate
    # A multi-record diff slice includes record prefixes and possibly the
    # opposite side, so it is not a raw identity from either source tree.
    if diff_surface and has_line_break:
        return None
    # Escape processing and line continuations normalize the source spelling.
    # Fail closed even for raw prefixes rather than treating that spelling as
    # a stable reduction identity.
    if b"\\" in candidate:
        return None
    try:
        parsed = ast.literal_eval(
            (literal_prefix + delimiter + candidate + delimiter).decode("ascii")
        )
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return None
    if isinstance(parsed, str):
        try:
            parsed_bytes = parsed.encode("ascii")
        except UnicodeEncodeError:
            return None
    elif isinstance(parsed, bytes):
        parsed_bytes = parsed
    else:
        return None
    if parsed_bytes != candidate:
        return None
    return candidate


def _oversized_assignment_is_exact_specific_candidate(
    value: bytes,
    *,
    assignment_start: int,
    candidate_start: int,
    prefix_end: int,
    quote: bytes | None,
    long_specific_candidate_ends: dict[int, set[int]],
    diff_surface: bool,
    prefix_context_complete: bool,
    suffix_context_complete: bool,
    event_budget: SecretScanBudget,
    prefix_proof_tracker: _PrefixProofRangeTracker,
) -> bool:
    for specific_end in long_specific_candidate_ends.get(candidate_start, ()):
        if specific_end < prefix_end:
            continue
        if quote is not None:
            if value[specific_end : specific_end + 1] == quote and (
                _quoted_assignment_may_accept(
                    value,
                    assignment_start=assignment_start,
                    assignment_end=specific_end + 1,
                    diff_surface=diff_surface,
                    prefix_context_complete=prefix_context_complete,
                    suffix_context_complete=suffix_context_complete,
                    event_budget=event_budget,
                    prefix_proof_tracker=prefix_proof_tracker,
                )
            ):
                return True
            continue
        if _unquoted_assignment_may_accept(
            value,
            assignment_start=assignment_start,
            assignment_end=specific_end,
            diff_surface=diff_surface,
        ):
            return True
    return False


def _record_long_specific_candidate(
    long_specific_candidate_ends: dict[int, set[int]],
    *,
    start: int,
    end: int,
) -> None:
    if end - start >= 513:
        long_specific_candidate_ends.setdefault(start, set()).add(end)


def _iter_secret_events(
    value: bytes,
    *,
    minimum_end: int = 0,
    maximum_end: int | None = None,
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    _event_budget: SecretScanBudget | None = None,
    _prefix_proof_tracker: _PrefixProofRangeTracker | None = None,
    _specific_spans: set[tuple[int, int, bytes]] | None = None,
    _capture_only_assignment_spans: set[tuple[int, int, bytes]] | None = None,
) -> Iterator[tuple[str, bytes | None, int, bool, int | None, int | None]]:
    event_budget = _event_budget or SecretScanBudget.default()
    prefix_proof_tracker = _prefix_proof_tracker or _PrefixProofRangeTracker(
        event_budget
    )
    if prefix_proof_tracker.event_budget is not event_budget:
        raise ReviewError("sensitive scanner proof tracker uses the wrong budget")

    def end_is_committable(end: int) -> bool:
        return minimum_end < end and (maximum_end is None or end <= maximum_end)

    def match_is_committable(match: re.Match[bytes]) -> bool:
        return end_is_committable(match.end())

    long_specific_candidate_ends: dict[int, set[int]] = {}
    pem_end_starts: dict[bytes, list[int]] = {}
    for end_match in PEM_PRIVATE_KEY_END.finditer(value):
        pem_end_starts.setdefault(end_match.group("label"), []).append(
            end_match.start()
        )
    for match in PEM_PRIVATE_KEY_BEGIN.finditer(value):
        start = match.start()
        label = match.group("label")
        rule = "pgp-private-key" if label == b"PGP PRIVATE KEY BLOCK" else "private-key"
        end_marker = b"-----END " + label + b"-----"
        search_end = min(len(value), start + MAX_PEM_SECRET_BYTES)
        end_starts = pem_end_starts.get(label, ())
        end_index = bisect_left(end_starts, match.end())
        end_start = (
            end_starts[end_index]
            if end_index < len(end_starts) and end_starts[end_index] < search_end
            else -1
        )
        if end_start >= 0:
            candidate_end = end_start + len(end_marker)
            candidate = value[start:candidate_end]
            _record_long_specific_candidate(
                long_specific_candidate_ends,
                start=start,
                end=candidate_end,
            )
            if _specific_spans is not None:
                _specific_spans.add((start, candidate_end, candidate))
            if not end_is_committable(candidate_end):
                continue
            event_budget.consume()
            yield (
                rule,
                candidate,
                candidate_end,
                True,
                start,
                candidate_end,
            )
            continue
        event_end = (
            start + MAX_PEM_SECRET_BYTES
            if len(value) - start >= MAX_PEM_SECRET_BYTES
            else len(value)
        )
        if not end_is_committable(event_end):
            continue
        event_budget.consume()
        yield (
            rule,
            None,
            event_end,
            False,
            None,
            _UNEXTRACTABLE_SECRET_CANDIDATE_END,
        )
    for rule, pattern in SECRET_PATTERNS:
        markers = SECRET_PATTERN_MARKERS.get(rule)
        marker_surface = value.lower() if rule == "aws-secret-key" else value
        if markers is not None and not any(
            marker in marker_surface for marker in markers
        ):
            continue
        for match in pattern.finditer(value):
            candidate_group: str | int = "aws_secret" if rule == "aws-secret-key" else 0
            start, candidate_end = match.span(candidate_group)
            candidate = match.group(candidate_group)
            prefix_only = _provider_candidate_is_prefix_only(rule, candidate)
            if not prefix_only:
                _record_long_specific_candidate(
                    long_specific_candidate_ends,
                    start=start,
                    end=candidate_end,
                )
                if _specific_spans is not None:
                    _specific_spans.add((start, candidate_end, candidate))
            if not match_is_committable(match):
                continue
            event_budget.consume()
            if prefix_only:
                if any(
                    end >= match.end()
                    for end in long_specific_candidate_ends.get(start, ())
                ):
                    continue
                yield (
                    rule,
                    None,
                    match.end(),
                    False,
                    None,
                    _UNEXTRACTABLE_SECRET_CANDIDATE_END,
                )
            else:
                yield rule, candidate, match.end(), True, start, candidate_end
    specific_ranges = sorted(
        {
            (start, candidate_end)
            for start, candidate_end, _candidate in (_specific_spans or ())
        }
    )
    specific_max_end_by_start: dict[int, int] = {}
    for start, candidate_end in specific_ranges:
        specific_max_end_by_start[start] = candidate_end
    # A dot-continued three-part prefix is not a stable identity unless the
    # earlier complete-pattern pass proved one bounded five-part JWE.
    for match in JWE_CONTINUATION_PATTERN.finditer(value):
        if not match_is_committable(match):
            continue
        if specific_max_end_by_start.get(match.start(), -1) > match.end():
            continue
        event_budget.consume()
        yield (
            "jwt",
            None,
            match.end(),
            False,
            None,
            _UNEXTRACTABLE_SECRET_CANDIDATE_END,
        )
    for rule, pattern in (
        ("aws-secret-key", OVERSIZED_AWS_SECRET_KEY_GAP),
        ("jwt", OVERSIZED_JWT_PATTERN),
        ("generic-secret-assignment", OVERSIZED_SECRET_ASSIGNMENT_GAP),
    ):
        for match in pattern.finditer(value):
            if not match_is_committable(match):
                continue
            event_budget.consume()
            yield (
                rule,
                None,
                match.end(),
                False,
                None,
                _UNEXTRACTABLE_SECRET_CANDIDATE_END,
            )
    for pattern, quoted in (
        (OVERSIZED_QUOTED_SECRET_ASSIGNMENT, True),
        (OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT, False),
    ):
        for match in pattern.finditer(value):
            if not match_is_committable(match):
                continue
            event_budget.consume()
            candidate_start = match.end() - 513
            try:
                exact_specific_candidate = (
                    _oversized_assignment_is_exact_specific_candidate(
                        value,
                        assignment_start=match.start(),
                        candidate_start=candidate_start,
                        prefix_end=match.end(),
                        quote=match.group(1) if quoted else None,
                        long_specific_candidate_ends=long_specific_candidate_ends,
                        diff_surface=diff_surface,
                        prefix_context_complete=prefix_context_complete,
                        suffix_context_complete=suffix_context_complete,
                        event_budget=event_budget,
                        prefix_proof_tracker=prefix_proof_tracker,
                    )
                )
            except _IncompleteSecretScanSuffix as incomplete:
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    match.end(),
                    False,
                    match.start(),
                    incomplete.retention_start
                    if incomplete.retention_start is not None
                    else match.start(),
                )
                continue
            if exact_specific_candidate:
                continue
            yield (
                "generic-secret-assignment",
                None,
                match.end(),
                False,
                None,
                _UNEXTRACTABLE_SECRET_CANDIDATE_END,
            )
    pending_specific_ranges = tuple(
        specific_range
        for specific_range in specific_ranges
        if specific_range[1] > minimum_end
    )

    def contains_specific_candidate(start: int, candidate_end: int) -> bool:
        index = bisect_left(specific_ranges, (start, -1))
        while (
            index < len(specific_ranges) and specific_ranges[index][0] < candidate_end
        ):
            _specific_start, specific_end = specific_ranges[index]
            if specific_end <= candidate_end:
                return True
            index += 1
        return False

    quoted_assignment_acceptance: dict[tuple[int, int], bool] = {}
    for match in QUOTED_SECRET_ASSIGNMENT_PREFIX.finditer(value):
        start, candidate_end = match.span(2)
        if not contains_specific_candidate(start, candidate_end):
            continue
        if value[candidate_end : candidate_end + 1] in (b"'", b'"'):
            continue
        if not match_is_committable(match):
            continue
        event_budget.consume()
        if candidate_end == len(value) and not suffix_context_complete:
            yield (
                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                None,
                match.end(),
                False,
                match.start(),
                match.start(),
            )
            continue
        yield (
            "generic-secret-assignment",
            match.group(2),
            match.end(),
            False,
            start,
            candidate_end,
        )
    for match in QUOTED_SECRET_ASSIGNMENT.finditer(value):
        if not match_is_committable(match):
            continue
        event_budget.consume()
        candidate = match.group(2)
        quoted_proof_limit = match.start() + MAX_SECRET_PREFIX_PROOF_BYTES
        quoted_proof_end = min(len(value), quoted_proof_limit)
        if match.end() > quoted_proof_end:
            if end_is_committable(quoted_proof_limit):
                yield (
                    "generic-secret-assignment",
                    None,
                    quoted_proof_limit,
                    False,
                    match.start(),
                    _UNEXTRACTABLE_SECRET_CANDIDATE_END,
                )
            continue
        closing_start = _find_unescaped_delimiter(
            value,
            delimiter=match.group(1),
            start=match.start(2),
            maximum_end=match.end(),
        )
        try:
            may_accept = closing_start == match.end() - len(match.group(1)) and (
                _quoted_assignment_may_accept(
                    value,
                    assignment_start=match.start(),
                    assignment_end=match.end(),
                    diff_surface=diff_surface,
                    prefix_context_complete=prefix_context_complete,
                    suffix_context_complete=suffix_context_complete,
                    event_budget=event_budget,
                    prefix_proof_tracker=prefix_proof_tracker,
                    maximum_end=quoted_proof_end,
                )
            )
        except _IncompleteSecretScanSuffix as incomplete:
            if quoted_proof_limit <= len(value) and end_is_committable(
                quoted_proof_limit
            ):
                yield (
                    "generic-secret-assignment",
                    None,
                    quoted_proof_limit,
                    False,
                    match.start(),
                    _UNEXTRACTABLE_SECRET_CANDIDATE_END,
                )
                continue
            yield (
                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                None,
                match.end(),
                False,
                match.start(),
                incomplete.retention_start
                if incomplete.retention_start is not None
                else match.start(),
            )
            continue
        if (
            closing_start == match.end() - len(match.group(1))
            and not may_accept
            and _capture_only_assignment_spans is not None
            and not prefix_context_complete
            and not diff_surface
        ):
            local_end = min(
                len(value),
                match.end() + MAX_SECRET_ASSIGNMENT_TRAILING_BYTES + 1,
            )
            local_value = value[match.start() : local_end]
            try:
                local_may_accept = _quoted_assignment_may_accept(
                    local_value,
                    assignment_start=0,
                    assignment_end=match.end() - match.start(),
                    prefix_context_complete=True,
                    suffix_context_complete=(
                        suffix_context_complete and local_end == len(value)
                    ),
                    event_budget=event_budget,
                    prefix_proof_tracker=prefix_proof_tracker.offset_view(
                        match.start()
                    ),
                )
            except _IncompleteSecretScanSuffix:
                local_may_accept = False
            if local_may_accept:
                local_start, local_end = match.span(2)
                _capture_only_assignment_spans.add((local_start, local_end, candidate))
        quoted_assignment_acceptance[(match.start(), match.end())] = may_accept
        if not may_accept or not _is_placeholder_secret(candidate.lower()):
            start, candidate_end = match.span(2)
            yield (
                "generic-secret-assignment",
                candidate,
                match.end(),
                may_accept,
                start,
                candidate_end,
            )
    direct_quoted_assignments = {
        start: (end, may_accept)
        for (start, end), may_accept in quoted_assignment_acceptance.items()
    }
    literal_prefixes = (b"br", b"rb", b"fr", b"rf", b"b", b"f", b"r", b"u")
    continuation_operators = frozenset(b"+-*/%&|^!=<>?:,.`")
    assignment_matches: Iterable[re.Match[bytes]] = (
        SECRET_ASSIGNMENT_PREFIX.finditer(value) if minimum_end < len(value) else ()
    )
    assignment_line_search_start = 0
    assignment_line_start = 0
    pending_specific_cursor = 0
    closed_assignment_proof_frontier: int | None = (
        0 if prefix_context_complete and not diff_surface else None
    )
    for assignment_match in assignment_matches:
        line_break = max(
            value.rfind(
                b"\n",
                assignment_line_search_start,
                assignment_match.start(),
            ),
            value.rfind(
                b"\r",
                assignment_line_search_start,
                assignment_match.start(),
            ),
        )
        if line_break >= 0:
            assignment_line_start = line_break + 1
        assignment_line_search_start = assignment_match.start()

        while (
            pending_specific_cursor < len(pending_specific_ranges)
            and pending_specific_ranges[pending_specific_cursor][0]
            < assignment_match.end()
        ):
            pending_specific_cursor += 1
        if (
            closed_assignment_proof_frontier is not None
            and assignment_match.start() < closed_assignment_proof_frontier
        ):
            continue
        if maximum_end is not None and assignment_match.start() >= maximum_end:
            continue
        direct_quoted = direct_quoted_assignments.get(assignment_match.start())
        if direct_quoted is not None:
            direct_end, direct_may_accept = direct_quoted
            if direct_may_accept and closed_assignment_proof_frontier is not None:
                closed_assignment_proof_frontier = max(
                    closed_assignment_proof_frontier,
                    direct_end,
                )
            continue
        proof_limit_end = assignment_match.start() + MAX_SECRET_PREFIX_PROOF_BYTES
        proof_end = min(len(value), proof_limit_end)
        proof_limit_visible = proof_limit_end <= len(value)
        proof_suffix_context_complete = suffix_context_complete and proof_end == len(
            value
        )
        pending_specific_within_proof = (
            pending_specific_cursor < len(pending_specific_ranges)
            and pending_specific_ranges[pending_specific_cursor][0] < proof_end
            and pending_specific_ranges[pending_specific_cursor][1] <= proof_end
        )
        if not pending_specific_within_proof:
            prefix_proof_start = 0
            if (
                closed_assignment_proof_frontier is not None
                and closed_assignment_proof_frontier > 0
                and closed_assignment_proof_frontier <= assignment_match.start()
                and assignment_match.start() <= MAX_SECRET_PREFIX_PROOF_BYTES
            ):
                prefix_proof_start = closed_assignment_proof_frontier
            recorded_closure_frontiers: list[int] = []
            recorded_literal_rhs: list[
                tuple[int, int | None, bytes, bytes, int | None]
            ] = []
            recorded_unquoted_rhs: list[tuple[int, int | None]] = []
            assignment_closed = _secret_assignment_rhs_is_closed(
                value,
                prefix_proof_start=prefix_proof_start,
                assignment_start=assignment_match.start(),
                assignment_end=assignment_match.end(),
                assignment_line_start=assignment_line_start,
                proof_end=proof_end,
                diff_surface=diff_surface,
                prefix_context_complete=prefix_context_complete,
                suffix_context_complete=suffix_context_complete,
                event_budget=event_budget,
                prefix_proof_tracker=prefix_proof_tracker,
                closure_recorder=recorded_closure_frontiers.append,
                literal_rhs_recorder=lambda start, end, delimiter, prefix, diff_side: (
                    recorded_literal_rhs.append(
                        (start, end, delimiter, prefix, diff_side)
                    )
                ),
                unquoted_rhs_recorder=lambda start, end: (
                    recorded_unquoted_rhs.append((start, end))
                ),
            )
            if assignment_closed:
                if (
                    closed_assignment_proof_frontier is not None
                    and recorded_closure_frontiers
                ):
                    closure_frontier = recorded_closure_frontiers[-1]
                    sibling_search_start = assignment_match.end()
                    if recorded_literal_rhs:
                        (
                            _candidate_start,
                            candidate_end,
                            delimiter,
                            _literal_prefix,
                            _literal_diff_side,
                        ) = recorded_literal_rhs[-1]
                        if candidate_end is not None:
                            sibling_search_start = candidate_end + len(delimiter)
                    elif recorded_unquoted_rhs:
                        _candidate_start, candidate_end = recorded_unquoted_rhs[-1]
                        if candidate_end is not None:
                            sibling_search_start = candidate_end
                    else:
                        direct_unquoted = UNQUOTED_SECRET_ASSIGNMENT.match(
                            value,
                            assignment_match.start(),
                            proof_end,
                        )
                        if direct_unquoted is not None:
                            sibling_search_start = direct_unquoted.end(1)
                    # Structural closure can cross a sibling assignment without
                    # classifying its RHS, so only reuse a fully covered frontier.
                    crossed_sibling = SECRET_ASSIGNMENT_PREFIX.search(
                        value,
                        sibling_search_start,
                        closure_frontier,
                    )
                    if crossed_sibling is None:
                        closed_assignment_proof_frontier = max(
                            closed_assignment_proof_frontier,
                            closure_frontier,
                        )
                if recorded_literal_rhs:
                    (
                        candidate_start,
                        candidate_end,
                        delimiter,
                        literal_prefix,
                        literal_diff_side,
                    ) = recorded_literal_rhs[-1]
                    if candidate_end is None:
                        raise ReviewError(
                            "sensitive scanner closed an incomplete literal RHS"
                        )
                    raw_candidate = value[candidate_start:candidate_end]
                    candidate = _exact_raw_literal_candidate(
                        value,
                        literal_prefix=literal_prefix,
                        delimiter=delimiter,
                        content_start=candidate_start,
                        closing_start=candidate_end,
                        diff_surface=diff_surface,
                        diff_side=literal_diff_side,
                    )
                    closure_end = (
                        recorded_closure_frontiers[-1]
                        if recorded_closure_frontiers
                        else candidate_end
                    )
                    if len(raw_candidate) >= 16 and not _is_placeholder_secret(
                        raw_candidate.lower()
                    ):
                        candidate_is_supported = (
                            candidate is not None
                            and len(candidate) <= 512
                            and delimiter != b"`"
                        )
                        if end_is_committable(closure_end):
                            event_budget.consume()
                            yield (
                                "generic-secret-assignment",
                                candidate if candidate_is_supported else None,
                                closure_end,
                                candidate_is_supported,
                                candidate_start
                                if candidate_is_supported
                                else assignment_match.start(),
                                candidate_end if candidate_is_supported else None,
                            )
                        elif (
                            maximum_end is not None
                            and closure_end > maximum_end
                            and maximum_end > minimum_end
                        ):
                            event_budget.consume()
                            yield (
                                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                                None,
                                maximum_end,
                                False,
                                assignment_match.start(),
                                _assignment_proof_retention_start(
                                    value,
                                    assignment_start=assignment_match.start(),
                                    diff_surface=diff_surface,
                                    prefix_context_complete=prefix_context_complete,
                                ),
                            )
                elif recorded_unquoted_rhs:
                    candidate_start, candidate_end = recorded_unquoted_rhs[-1]
                    if candidate_end is None:
                        raise ReviewError(
                            "sensitive scanner closed an incomplete unquoted RHS"
                        )
                    candidate = value[candidate_start:candidate_end]
                    closure_end = (
                        recorded_closure_frontiers[-1]
                        if recorded_closure_frontiers
                        else candidate_end
                    )
                    has_strong_secret_key = (
                        STRONG_SECRET_KEY_NAME_PATTERN.search(
                            value[assignment_match.start() : candidate_start]
                        )
                        is not None
                    )
                    if (
                        not _is_placeholder_secret(candidate.lower())
                        and not _is_secret_pattern_marker(candidate)
                        and (
                            _looks_like_unquoted_secret(candidate)
                            or has_strong_secret_key
                        )
                    ):
                        if end_is_committable(closure_end):
                            event_budget.consume()
                            yield (
                                "generic-secret-assignment",
                                candidate,
                                closure_end,
                                True,
                                candidate_start,
                                candidate_end,
                            )
                        elif (
                            maximum_end is not None
                            and closure_end > maximum_end
                            and maximum_end > minimum_end
                        ):
                            event_budget.consume()
                            yield (
                                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                                None,
                                maximum_end,
                                False,
                                assignment_match.start(),
                                _assignment_proof_retention_start(
                                    value,
                                    assignment_start=assignment_match.start(),
                                    diff_surface=diff_surface,
                                    prefix_context_complete=prefix_context_complete,
                                ),
                            )
                continue
            if recorded_literal_rhs and proof_suffix_context_complete:
                (
                    candidate_start,
                    candidate_end,
                    delimiter,
                    _literal_prefix,
                    _literal_diff_side,
                ) = recorded_literal_rhs[-1]
                candidate = (
                    value[candidate_start:candidate_end]
                    if candidate_end is not None
                    else value[candidate_start:proof_end]
                )
                if (
                    len(candidate) >= 16
                    and not _is_placeholder_secret(candidate.lower())
                    and not _is_secret_pattern_marker(candidate)
                    and end_is_committable(proof_end)
                ):
                    event_budget.consume()
                    yield (
                        "generic-secret-assignment",
                        None,
                        proof_end,
                        False,
                        assignment_match.start(),
                        (
                            _UNEXTRACTABLE_SECRET_CANDIDATE_END
                            if candidate_end is None
                            else None
                        ),
                    )
                continue
            if recorded_unquoted_rhs and proof_suffix_context_complete:
                candidate_start, candidate_end = recorded_unquoted_rhs[-1]
                candidate = (
                    value[candidate_start:candidate_end]
                    if candidate_end is not None
                    else b""
                )
                has_strong_secret_key = (
                    STRONG_SECRET_KEY_NAME_PATTERN.search(
                        value[assignment_match.start() : candidate_start]
                    )
                    is not None
                )
                if (
                    candidate_end is None
                    or (
                        not _is_placeholder_secret(candidate.lower())
                        and not _is_secret_pattern_marker(candidate)
                        and (
                            _looks_like_unquoted_secret(candidate)
                            or has_strong_secret_key
                        )
                    )
                ) and end_is_committable(proof_end):
                    event_budget.consume()
                    yield (
                        "generic-secret-assignment",
                        None,
                        proof_end,
                        False,
                        assignment_match.start(),
                        None,
                    )
                continue
            if proof_suffix_context_complete:
                continue
            if proof_limit_visible and end_is_committable(proof_limit_end):
                event_budget.consume()
                yield (
                    "generic-secret-assignment",
                    None,
                    proof_limit_end,
                    False,
                    assignment_match.start(),
                    None,
                )
            elif end_is_committable(assignment_match.end()):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    assignment_match.end(),
                    False,
                    assignment_match.start(),
                    _assignment_proof_retention_start(
                        value,
                        assignment_start=assignment_match.start(),
                        diff_surface=diff_surface,
                        prefix_context_complete=prefix_context_complete,
                    ),
                )
            continue
        if (
            maximum_end is not None
            and pending_specific_ranges[pending_specific_cursor][1] > maximum_end
        ):
            if maximum_end > minimum_end:
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    maximum_end,
                    False,
                    assignment_match.start(),
                    _assignment_proof_retention_start(
                        value,
                        assignment_start=assignment_match.start(),
                        diff_surface=diff_surface,
                        prefix_context_complete=prefix_context_complete,
                    ),
                )
            continue
        if maximum_end is not None and assignment_match.end() >= maximum_end:
            if maximum_end > minimum_end:
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    maximum_end,
                    False,
                    assignment_match.start(),
                    _assignment_proof_retention_start(
                        value,
                        assignment_start=assignment_match.start(),
                        diff_surface=diff_surface,
                        prefix_context_complete=prefix_context_complete,
                    ),
                )
            continue
        if not prefix_proof_tracker.consume(assignment_match.end(), proof_end):
            raise ReviewError("sensitive scanner exceeded one RHS proof window")
        assignment_retention_start = _assignment_proof_retention_start(
            value,
            assignment_start=assignment_match.start(),
            diff_surface=diff_surface,
            prefix_context_complete=prefix_context_complete,
        )

        assignment_diff_side: int | None = None
        if (
            diff_surface
            and assignment_line_start < proof_end
            and value[assignment_line_start] in (0x2B, 0x2D)
            and not value.startswith(
                (b"+++ ", b"--- "),
                assignment_line_start,
                proof_end,
            )
        ):
            assignment_diff_side = value[assignment_line_start]
        cursor = assignment_match.end()
        wrapper_prefix = False
        wrapper_closers: list[int] = []
        wrapper_mismatch = False
        quoted_prefix_wrapper_only = True
        pending_expression_continuation = False
        while cursor < proof_end:
            lowered_prefix = value[cursor : min(cursor + 3, proof_end)].lower()
            backtick_continuation = False
            if value[cursor] == 0x60:
                backtick_suffix = cursor + 1
                while backtick_suffix < proof_end and value[backtick_suffix] in (
                    0x09,
                    0x20,
                ):
                    backtick_suffix += 1
                backtick_continuation = backtick_suffix < proof_end and value[
                    backtick_suffix
                ] in (0x0A, 0x0D)
            if (
                value[cursor] in (0x22, 0x27)
                or (value[cursor] == 0x60 and not backtick_continuation)
                or any(
                    lowered_prefix.startswith(prefix)
                    and value[
                        cursor + len(prefix) : min(cursor + len(prefix) + 1, proof_end)
                    ]
                    in (b"'", b'"')
                    for prefix in literal_prefixes
                )
            ):
                break
            if value[cursor] in (0x09, 0x20):
                cursor += 1
                continue
            if value[cursor] in (0x28, 0x5B, 0x7B):
                wrapper_prefix = True
                wrapper_closers.append(
                    {
                        0x28: 0x29,
                        0x5B: 0x5D,
                        0x7B: 0x7D,
                    }[value[cursor]]
                )
                pending_expression_continuation = False
                cursor += 1
                continue
            if value[cursor] in (0x29, 0x5D, 0x7D):
                wrapper_prefix = True
                quoted_prefix_wrapper_only = False
                if wrapper_closers and value[cursor] == wrapper_closers[-1]:
                    wrapper_closers.pop()
                else:
                    wrapper_mismatch = True
                pending_expression_continuation = False
                cursor += 1
                continue
            if value.startswith(b"/*", cursor, proof_end):
                wrapper_prefix = True
                quoted_prefix_wrapper_only = False
                comment_end = value.find(b"*/", cursor + 2, proof_end)
                if comment_end < 0:
                    cursor = proof_end
                    continue
                cursor = comment_end + 2
                continue
            if value.startswith(b"//", cursor, proof_end):
                quoted_prefix_wrapper_only = False
                previous = cursor - 1
                while previous >= assignment_match.end() and value[previous] in (
                    0x09,
                    0x20,
                ):
                    previous -= 1
                pending_expression_continuation = (
                    pending_expression_continuation
                    or bool(wrapper_closers)
                    or (
                        previous >= assignment_match.end()
                        and value[previous] in continuation_operators
                    )
                )
                line_end_candidates = tuple(
                    boundary
                    for boundary in (
                        value.find(b"\n", cursor, proof_end),
                        value.find(b"\r", cursor, proof_end),
                    )
                    if boundary >= 0
                )
                cursor = min(line_end_candidates, default=proof_end)
                continue
            if value[cursor] in (0x0A, 0x0D):
                previous = cursor - 1
                while previous >= assignment_match.end() and value[previous] in (
                    0x09,
                    0x20,
                ):
                    previous -= 1
                next_cursor = cursor + (
                    2 if value.startswith(b"\r\n", cursor, proof_end) else 1
                )
                if (
                    diff_surface
                    and next_cursor < proof_end
                    and value[next_cursor] in (0x20, 0x2B, 0x2D)
                ):
                    next_cursor += 1
                while next_cursor < proof_end and value[next_cursor] in (
                    0x09,
                    0x20,
                ):
                    next_cursor += 1
                previous_continues = previous >= assignment_match.end() and (
                    value[previous] == 0x5C or value[previous] in continuation_operators
                )
                next_continues = (
                    next_cursor < proof_end
                    and value[next_cursor] in continuation_operators
                )
                line_continues = (
                    bool(wrapper_closers)
                    or pending_expression_continuation
                    or previous_continues
                    or next_continues
                )
                if not wrapper_closers and (not line_continues):
                    break
                pending_expression_continuation = (
                    pending_expression_continuation
                    or previous_continues
                    or next_continues
                )
                cursor += 2 if value.startswith(b"\r\n", cursor, proof_end) else 1
                continue
            if value[cursor] == 0x23:
                quoted_prefix_wrapper_only = False
                line_end_candidates = tuple(
                    boundary
                    for boundary in (
                        value.find(b"\n", cursor, proof_end),
                        value.find(b"\r", cursor, proof_end),
                    )
                    if boundary >= 0
                )
                line_end = min(line_end_candidates, default=proof_end)
                if not wrapper_closers and not pending_expression_continuation:
                    cursor = line_end
                    break
                cursor = line_end
                continue
            if value[cursor] == 0x3B and not wrapper_closers:
                break
            if (
                diff_surface
                and cursor > 0
                and value[cursor - 1] in (0x0A, 0x0D)
                and value[cursor] in (0x2B, 0x2D)
            ):
                cursor += 1
                continue
            wrapper_prefix = True
            quoted_prefix_wrapper_only = False
            pending_expression_continuation = value[cursor] in continuation_operators
            cursor += 1
        lowered_suffix = value[cursor : min(cursor + 3, proof_end)].lower()
        literal_prefix = b""
        for prefix in literal_prefixes:
            if lowered_suffix.startswith(prefix) and value[
                cursor + len(prefix) : min(cursor + len(prefix) + 1, proof_end)
            ] in (b"'", b'"'):
                literal_prefix = value[cursor : cursor + len(prefix)]
                cursor += len(prefix)
                break
        quote = value[cursor : min(cursor + 1, proof_end)]
        if quote not in (b"'", b'"', b"`"):
            direct_unquoted_match = UNQUOTED_SECRET_ASSIGNMENT.match(
                value,
                assignment_match.start(),
                proof_end,
            )
            if direct_unquoted_match is not None:
                continue
            range_index = bisect_left(
                specific_ranges,
                (assignment_match.end(), -1),
            )
            rhs_specific_ranges: list[tuple[int, int]] = []
            while (
                range_index < len(specific_ranges)
                and specific_ranges[range_index][0] < cursor
            ):
                specific_start, candidate_end = specific_ranges[range_index]
                if candidate_end <= cursor:
                    rhs_specific_ranges.append((specific_start, candidate_end))
                range_index += 1
            if rhs_specific_ranges:
                specific_start, specific_end = rhs_specific_ranges[0]
                exact_wrapped_candidate = len(
                    rhs_specific_ranges
                ) == 1 and _wrapper_ranges_are_balanced(
                    value,
                    prefix_start=assignment_match.end(),
                    prefix_end=specific_start,
                    suffix_start=specific_end,
                    suffix_end=cursor,
                )
                wrapper_may_complete = len(
                    rhs_specific_ranges
                ) == 1 and _wrapper_ranges_are_balanced(
                    value,
                    prefix_start=assignment_match.end(),
                    prefix_end=specific_start,
                    suffix_start=specific_end,
                    suffix_end=cursor,
                    require_complete=False,
                )
                if (
                    not exact_wrapped_candidate
                    and end_is_committable(specific_end)
                    and not (
                        not proof_suffix_context_complete
                        and cursor == proof_end
                        and wrapper_may_complete
                    )
                ):
                    event_budget.consume()
                    yield (
                        "generic-secret-assignment",
                        None,
                        specific_end,
                        False,
                        assignment_match.start(),
                        None,
                    )
                    continue
            if (
                wrapper_prefix
                and proof_limit_visible
                and end_is_committable(proof_limit_end)
            ):
                event_budget.consume()
                yield (
                    "generic-secret-assignment",
                    None,
                    proof_limit_end,
                    False,
                    assignment_match.start(),
                    None,
                )
            elif (
                wrapper_prefix
                and not proof_suffix_context_complete
                and end_is_committable(assignment_match.end())
            ):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    assignment_match.end(),
                    False,
                    assignment_match.start(),
                    assignment_retention_start,
                )
            continue
        delimiter = quote * (
            3 if quote != b"`" and value.startswith(quote * 3, cursor, proof_end) else 1
        )
        content_start = cursor + len(delimiter)
        closing_start = _find_unescaped_delimiter(
            value,
            delimiter=delimiter,
            start=content_start,
            diff_side=assignment_diff_side,
            maximum_end=proof_end,
        )
        closing_end = None if closing_start is None else closing_start + len(delimiter)
        if closing_start is None:
            if proof_limit_visible and end_is_committable(proof_limit_end):
                event_budget.consume()
                yield (
                    "generic-secret-assignment",
                    None,
                    proof_limit_end,
                    False,
                    assignment_match.start(),
                    None,
                )
                continue
            range_index = bisect_left(specific_ranges, (content_start, -1))
            specific_end = (
                specific_ranges[range_index][1]
                if range_index < len(specific_ranges)
                else None
            )
            if not proof_suffix_context_complete and end_is_committable(content_start):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    content_start,
                    False,
                    assignment_match.start(),
                    assignment_retention_start,
                )
                continue
            if specific_end is None or not end_is_committable(specific_end):
                continue
            event_budget.consume()
            yield (
                "generic-secret-assignment",
                None,
                specific_end,
                False,
                assignment_match.start(),
                None,
            )
            continue

        if closing_end is None:
            raise ReviewError("sensitive scanner lost a quoted delimiter boundary")
        if maximum_end is not None and closing_end > maximum_end:
            if proof_limit_visible and end_is_committable(proof_limit_end):
                event_budget.consume()
                yield (
                    "generic-secret-assignment",
                    None,
                    proof_limit_end,
                    False,
                    assignment_match.start(),
                    None,
                )
                continue
            if end_is_committable(content_start):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    content_start,
                    False,
                    assignment_match.start(),
                    assignment_retention_start,
                )
            continue

        assignment_key = (assignment_match.start(), closing_end)
        assignment_incomplete = False
        assignment_incomplete_start = assignment_retention_start
        assignment_closure_frontiers: list[int] = []
        if wrapper_mismatch:
            assignment_complete = False
        elif proof_end == len(value) and assignment_key in quoted_assignment_acceptance:
            assignment_complete = quoted_assignment_acceptance[assignment_key]
        else:
            try:
                assignment_complete = _quoted_assignment_may_accept(
                    value,
                    assignment_start=assignment_match.start(),
                    assignment_end=closing_end,
                    required_closers=tuple(reversed(wrapper_closers)),
                    diff_surface=diff_surface,
                    prefix_context_complete=prefix_context_complete,
                    suffix_context_complete=proof_suffix_context_complete,
                    event_budget=event_budget,
                    prefix_proof_tracker=prefix_proof_tracker,
                    maximum_end=proof_end,
                    inspection_recorder=lambda inspected: (
                        assignment_closure_frontiers.append(closing_end + inspected)
                    ),
                )
            except _IncompleteSecretScanSuffix as incomplete:
                assignment_complete = False
                assignment_incomplete = True
                if incomplete.retention_start is not None:
                    assignment_incomplete_start = incomplete.retention_start

        if (
            assignment_incomplete
            and proof_limit_visible
            and end_is_committable(proof_limit_end)
        ):
            event_budget.consume()
            yield (
                "generic-secret-assignment",
                None,
                proof_limit_end,
                False,
                assignment_match.start(),
                None,
            )
            continue

        relevant_end = closing_start if assignment_complete else proof_end
        range_index = bisect_left(specific_ranges, (content_start, -1))
        relevant_ranges: list[tuple[int, int]] = []
        while (
            range_index < len(specific_ranges)
            and specific_ranges[range_index][0] < relevant_end
        ):
            specific_start, candidate_end = specific_ranges[range_index]
            if candidate_end <= relevant_end:
                relevant_ranges.append((specific_start, candidate_end))
            range_index += 1
        if not relevant_ranges:
            if (
                not assignment_complete
                and not proof_suffix_context_complete
                and end_is_committable(content_start)
            ):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    closing_end,
                    False,
                    assignment_match.start(),
                    assignment_incomplete_start,
                )
            continue

        exact_specific_candidate = (
            assignment_complete
            and quoted_prefix_wrapper_only
            and all(
                specific_start == content_start and candidate_end == closing_start
                for specific_start, candidate_end in relevant_ranges
            )
        )
        if exact_specific_candidate:
            continue
        full_literal_candidate = (
            _exact_raw_literal_candidate(
                value,
                literal_prefix=literal_prefix,
                delimiter=delimiter,
                content_start=content_start,
                closing_start=closing_start,
                diff_surface=diff_surface,
                diff_side=assignment_diff_side,
            )
            if (
                assignment_complete and quoted_prefix_wrapper_only and delimiter != b"`"
            )
            else None
        )
        if (
            full_literal_candidate is not None
            and 16 <= len(full_literal_candidate) <= 512
            and not _is_placeholder_secret(full_literal_candidate.lower())
        ):
            closure_end = (
                assignment_closure_frontiers[-1]
                if assignment_closure_frontiers
                else closing_end
            )
            if end_is_committable(closure_end):
                event_budget.consume()
                yield (
                    "generic-secret-assignment",
                    full_literal_candidate,
                    closure_end,
                    True,
                    content_start,
                    closing_start,
                )
            elif (
                maximum_end is not None
                and closure_end > maximum_end
                and maximum_end > minimum_end
            ):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    maximum_end,
                    False,
                    assignment_match.start(),
                    assignment_retention_start,
                )
            continue
        if assignment_incomplete and all(
            specific_start == content_start and candidate_end == closing_start
            for specific_start, candidate_end in relevant_ranges
        ):
            event_budget.consume()
            yield (
                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                None,
                closing_end,
                False,
                assignment_match.start(),
                assignment_incomplete_start,
            )
            continue
        specific_end = relevant_ranges[0][1]
        if not end_is_committable(specific_end):
            if end_is_committable(content_start):
                event_budget.consume()
                yield (
                    _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                    None,
                    content_start,
                    False,
                    assignment_match.start(),
                    assignment_retention_start,
                )
            continue
        event_budget.consume()
        yield (
            "generic-secret-assignment",
            None,
            specific_end,
            False,
            assignment_match.start(),
            None,
        )
    for match in UNQUOTED_SECRET_ASSIGNMENT.finditer(value):
        if not match_is_committable(match):
            continue
        event_budget.consume()
        candidate = match.group(1)
        may_accept = _unquoted_assignment_may_accept(
            value,
            assignment_start=match.start(),
            assignment_end=match.end(),
            diff_surface=diff_surface,
        )
        placeholder = _is_placeholder_secret(candidate.lower())
        if placeholder and not may_accept:
            may_accept = _unquoted_assignment_may_accept(
                value,
                assignment_start=match.start(),
                assignment_end=match.end(),
                diff_surface=diff_surface,
                allow_inline_hash_comment=True,
            )
        start, candidate_end = match.span(1)
        contains_specific = contains_specific_candidate(start, candidate_end)
        has_strong_secret_key = (
            STRONG_SECRET_KEY_NAME_PATTERN.search(value[match.start() : start])
            is not None
        )
        if (
            not placeholder
            and (
                _looks_like_unquoted_secret(candidate)
                or contains_specific
                or has_strong_secret_key
            )
        ) or (placeholder and not may_accept):
            yield (
                "generic-secret-assignment",
                candidate,
                match.end(),
                may_accept,
                start,
                candidate_end,
            )


def _index_accepted_values(
    accepted_values: tuple[AcceptedSyntheticValue, ...],
) -> AcceptedValueIndex:
    exact: dict[tuple[str, bytes], list[AcceptedSyntheticValue]] = {}
    digests: dict[tuple[str, int], dict[str, list[AcceptedSyntheticValue]]] = {}
    for accepted in accepted_values:
        if accepted.value is not None:
            exact.setdefault((accepted.rule, accepted.value), []).append(accepted)
            continue
        by_digest = digests.setdefault(
            (accepted.rule, accepted.value_length),
            {},
        )
        by_digest.setdefault(accepted.value_sha256, []).append(accepted)
    return AcceptedValueIndex(exact=exact, digests=digests)


def _index_exact_values(
    accepted_values: tuple[AcceptedSyntheticValue, ...],
) -> ExactValueIndex:
    descriptors: dict[bytes, AcceptedSyntheticValue] = {}
    for accepted in accepted_values:
        if accepted.value is None:
            raise ReviewError(
                "legacy synthetic occurrence counting requires exact catalog values"
            )
        if accepted.value in descriptors:
            raise ReviewError(
                "synthetic token catalog produced an ambiguous exact occurrence match"
            )
        descriptors[accepted.value] = accepted
    if not descriptors:
        return ExactValueIndex((), 0, {})
    containers: dict[bytes, tuple[tuple[bytes, int], ...]] = {}
    for raw_value, raw_descriptor in descriptors.items():
        containing_matches: list[tuple[bytes, int]] = []
        for longer_value, longer_descriptor in descriptors.items():
            if longer_descriptor.kind != raw_descriptor.kind:
                continue
            if (
                raw_descriptor.kind == "legacy"
                and longer_descriptor.exemption_id != raw_descriptor.exemption_id
            ):
                continue
            if len(longer_value) <= len(raw_value):
                continue
            offset = longer_value.find(raw_value)
            while offset >= 0:
                containing_matches.append((longer_value, offset))
                offset = longer_value.find(raw_value, offset + 1)
        containers[raw_value] = tuple(containing_matches)
    return ExactValueIndex(
        tuple(
            (value, descriptors[value])
            for value in sorted(descriptors, key=lambda item: (-len(item), item))
        ),
        max(len(value) for value in descriptors),
        containers,
    )


def _count_exact_value_occurrences(
    value: bytes,
    *,
    exact_index: ExactValueIndex,
    minimum_start: int,
    maximum_start: int,
    event_budget: LegacyOccurrenceBudget,
    capture_reduction_offsets: bool = False,
) -> tuple[
    Counter[AcceptedSyntheticValue],
    Counter[AcceptedSyntheticValue],
    dict[AcceptedSyntheticValue, set[int]],
    dict[AcceptedSyntheticValue, set[int]],
]:
    counts: Counter[AcceptedSyntheticValue] = Counter()
    unembedded_counts: Counter[AcceptedSyntheticValue] = Counter()
    reduction_offsets: dict[AcceptedSyntheticValue, set[int]] = {}
    reduction_unembedded_offsets: dict[AcceptedSyntheticValue, set[int]] = {}
    if not exact_index.patterns or minimum_start >= maximum_start:
        return (
            counts,
            unembedded_counts,
            reduction_offsets,
            reduction_unembedded_offsets,
        )
    event_budget.consume_search(
        len(exact_index.patterns) * max(0, len(value) - minimum_start)
    )
    for raw_value, descriptor in exact_index.patterns:
        next_start = minimum_start
        while True:
            start = value.find(raw_value, next_start)
            if start < 0 or start >= maximum_start:
                break
            event_budget.consume()
            counts[descriptor] += 1
            if capture_reduction_offsets and descriptor.kind == "secret-reduction":
                offsets = reduction_offsets.setdefault(descriptor, set())
                offsets.add(start)
                if (
                    sum(map(len, reduction_offsets.values()))
                    > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
                ):
                    raise ReviewError(
                        "external review secret-reduction occurrence provenance "
                        "exceeds the entry limit"
                    )
            embedded = False
            for longer_value, offset in exact_index.containers[raw_value]:
                event_budget.consume_containment_check()
                longer_start = start - offset
                if longer_start >= 0 and value.startswith(
                    longer_value,
                    longer_start,
                ):
                    embedded = True
                    break
            if not embedded:
                unembedded_counts[descriptor] += 1
                if capture_reduction_offsets and descriptor.kind == "secret-reduction":
                    reduction_unembedded_offsets.setdefault(descriptor, set()).add(
                        start
                    )
            next_start = start + 1
    return (
        counts,
        unembedded_counts,
        reduction_offsets,
        reduction_unembedded_offsets,
    )


def _matching_accepted_values(
    *,
    rule: str,
    candidate: bytes,
    accepted_index: AcceptedValueIndex,
) -> list[AcceptedSyntheticValue]:
    matches = list(accepted_index.exact.get((rule, candidate), ()))
    by_digest = accepted_index.digests.get((rule, len(candidate)))
    if by_digest:
        candidate_digest = hashlib.sha256(candidate).hexdigest()
        matches.extend(by_digest.get(candidate_digest, ()))
    if len(matches) > 1:
        raise ReviewError("synthetic token catalog produced an ambiguous scanner match")
    return matches


def _scan_secret_value(
    value: bytes,
    *,
    accepted_values: tuple[AcceptedSyntheticValue, ...] = (),
    raw_occurrence_values: tuple[AcceptedSyntheticValue, ...] = (),
    minimum_end: int = 0,
    maximum_end: int | None = None,
    capture_accepted_candidates: bool = False,
    capture_blocking_candidates: bool = False,
    capture_reduction_offsets: bool = False,
    reduced_secret_values: frozenset[bytes] = frozenset(),
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    _accepted_index: AcceptedValueIndex | None = None,
    _event_budget: SecretScanBudget | None = None,
    _prefix_proof_tracker: _PrefixProofRangeTracker | None = None,
    _exact_index: ExactValueIndex | None = None,
    _occurrence_budget: LegacyOccurrenceBudget | None = None,
    exact_only: bool = False,
    _continue_after_blocking: bool = False,
    _capture_only_legacy_evidence: bool = False,
) -> SecretScanResult:
    if _continue_after_blocking and not (
        capture_accepted_candidates or capture_blocking_candidates
    ):
        raise ReviewError(
            "exhaustive secret scanning requires accepted-candidate capture "
            "or blocking-candidate capture"
        )
    if _capture_only_legacy_evidence and not (
        _continue_after_blocking
        and capture_accepted_candidates
        and not prefix_context_complete
        and not diff_surface
    ):
        raise ReviewError("capture-only legacy evidence scope is invalid")
    result = SecretScanResult.empty()
    exact_index = _exact_index or _index_exact_values(raw_occurrence_values)
    occurrence_budget = _occurrence_budget or LegacyOccurrenceBudget.default()
    (
        raw_counts,
        unembedded_counts,
        reduction_offsets,
        reduction_unembedded_offsets,
    ) = _count_exact_value_occurrences(
        value,
        exact_index=exact_index,
        minimum_start=0,
        maximum_start=len(value),
        event_budget=occurrence_budget,
        capture_reduction_offsets=capture_reduction_offsets,
    )
    result.raw_occurrence_counts.update(raw_counts)
    result.unembedded_occurrence_counts.update(unembedded_counts)
    result.reduction_occurrence_offsets.update(reduction_offsets)
    result.reduction_unembedded_offsets.update(reduction_unembedded_offsets)
    if exact_only:
        return result
    upper = len(value) if maximum_end is None else maximum_end
    accepted_index = _accepted_index or _index_accepted_values(accepted_values)
    event_budget = _event_budget or SecretScanBudget.default()
    specific_spans: set[tuple[int, int, bytes]] = set()
    capture_only_assignment_spans: set[tuple[int, int, bytes]] | None = (
        set() if _capture_only_legacy_evidence else None
    )
    for rule, candidate, end, may_accept, start, candidate_end in _iter_secret_events(
        value,
        minimum_end=minimum_end,
        maximum_end=upper,
        diff_surface=diff_surface,
        prefix_context_complete=prefix_context_complete,
        suffix_context_complete=suffix_context_complete,
        _event_budget=event_budget,
        _prefix_proof_tracker=_prefix_proof_tracker,
        _specific_spans=specific_spans,
        _capture_only_assignment_spans=capture_only_assignment_spans,
    ):
        if not minimum_end < end <= upper:
            continue
        if rule == _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE:
            if start is None or candidate_end is None:
                raise ReviewError(
                    "sensitive scanner lost an incomplete diff suffix boundary"
                )
            if not 0 <= candidate_end <= start < end:
                raise ReviewError(
                    "sensitive scanner produced invalid incomplete suffix boundaries"
                )
            result.incomplete_suffix_start = start
            result.incomplete_suffix_retention_start = candidate_end
            return result
        if (
            rule == "generic-secret-assignment"
            and may_accept
            and candidate is not None
            and start is not None
            and candidate_end is not None
            and (start, candidate_end, candidate) in specific_spans
        ):
            continue
        capture_only_accept = (
            candidate is not None
            and start is not None
            and candidate_end is not None
            and capture_only_assignment_spans is not None
            and (start, candidate_end, candidate) in capture_only_assignment_spans
        )
        matches = (
            _matching_accepted_values(
                rule=rule,
                candidate=candidate,
                accepted_index=accepted_index,
            )
            if (may_accept or capture_only_accept) and candidate is not None
            else []
        )
        accepted_match = matches[0] if matches else None
        if accepted_match is not None and (
            may_accept or (capture_only_accept and accepted_match.kind == "legacy")
        ):
            accepted = accepted_match
            result.accepted_counts[accepted] += 1
            if capture_accepted_candidates:
                result.accepted_candidates.setdefault(accepted, set()).add(candidate)
            if may_accept:
                continue
        if may_accept and candidate is not None and candidate in reduced_secret_values:
            continue
        elif capture_blocking_candidates and may_accept and candidate is not None:
            if (
                candidate not in result.blocking_candidates
                and len(result.blocking_candidates) >= MAX_SECRET_REDUCTION_CANDIDATES
            ):
                raise ReviewError(
                    "external review content has too many secret-reduction candidates"
                )
            result.blocking_candidates.setdefault(candidate, set()).add(rule)
            if (
                sum(map(len, result.blocking_candidates))
                > MAX_SECRET_REDUCTION_CANDIDATE_BYTES
            ):
                raise ReviewError(
                    "external review secret-reduction candidates exceed the byte limit"
                )
        else:
            if (
                candidate is None
                and candidate_end == _UNEXTRACTABLE_SECRET_CANDIDATE_END
                and result.unextractable_rule is None
            ):
                result.unextractable_rule = rule
            if result.blocking_rule is None:
                result.blocking_rule = rule
            if not _continue_after_blocking:
                return result
    return result


def validate_authoring_catalog_scanner_contract(
    catalog: SyntheticTokenCatalog,
) -> None:
    key = b"access_" + b"token"
    separator = b" = "
    for accepted in accepted_authoring_values(catalog):
        probes = (
            key + separator + b'"' + accepted.value + b'"\n',
            key + separator + b"'" + accepted.value + b"'\n",
            key + separator + accepted.value + b"\n",
        )
        for probe in probes:
            result = _scan_secret_value(
                probe,
                accepted_values=(accepted,),
            )
            if result.blocking_rule is not None or result.accepted_counts != Counter(
                {accepted: 1}
            ):
                raise ReviewError(
                    "synthetic token catalog authoring token is not captured "
                    f"exactly once by its scanner rule: {accepted.identifier}"
                )


def _stream_secret_scan(
    stream: BinaryIO,
    *,
    size: int | None = None,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
    raw_occurrence_values: Iterable[AcceptedSyntheticValue] = (),
    capture_accepted_candidates: bool = False,
    capture_blocking_candidates: bool = False,
    capture_reduction_offsets: bool = False,
    reduced_secret_values: frozenset[bytes] = frozenset(),
    diff_surface: bool = False,
    _accepted_index: AcceptedValueIndex | None = None,
    _event_budget: SecretScanBudget | None = None,
    _exact_index: ExactValueIndex | None = None,
    _occurrence_budget: LegacyOccurrenceBudget | None = None,
    _blocking_exact_matcher: LegacyPathMatcher | None = None,
    exact_only: bool = False,
    _continue_after_blocking: bool = False,
) -> SecretScanResult:
    if size is not None and size < 0:
        raise ReviewError("sensitive scan size must be nonnegative")
    overlap = STREAM_SCAN_OVERLAP
    accepted = tuple(accepted_values)
    accepted_index = _accepted_index or _index_accepted_values(accepted)
    event_budget = _event_budget or SecretScanBudget.default()
    prefix_proof_tracker = _PrefixProofRangeTracker(event_budget)
    exact_values = tuple(raw_occurrence_values)
    exact_index = _exact_index or _index_exact_values(exact_values)
    exact_retention_length = max(
        exact_index.maximum_length,
        (
            _blocking_exact_matcher.maximum_length
            if _blocking_exact_matcher is not None
            else 0
        ),
    )
    occurrence_budget = _occurrence_budget or LegacyOccurrenceBudget.default()
    pending = b""
    pending_offset = 0
    exact_pending = b""
    exact_pending_offset = 0
    total_read = 0
    committed_end = 0
    committed_start = 0
    remaining = size
    result = SecretScanResult.empty()
    blocked = False
    while True:
        if remaining == 0:
            chunk = b""
            reached_eof = True
        else:
            preferred_read_size = (
                MAX_SECRET_PREFIX_PROOF_BYTES + overlap
                if total_read == 0
                else STREAM_SCAN_CHUNK_BYTES
            )
            read_size = (
                preferred_read_size
                if remaining is None
                else min(preferred_read_size, remaining)
            )
            chunk_buffer = bytearray()
            reached_eof = False
            # Normalize transport-level short reads into bounded logical chunks
            # so speculative suffix scans do not depend on stream fragmentation.
            while len(chunk_buffer) < read_size:
                requested = read_size - len(chunk_buffer)
                part = stream.read(requested)
                if not part:
                    reached_eof = True
                    break
                if len(part) > requested:
                    raise ReviewError(
                        "sensitive scan stream returned more bytes than requested"
                    )
                chunk_buffer.extend(part)
            chunk = bytes(chunk_buffer)
        if reached_eof and remaining not in (None, 0):
            raise ReviewError("unexpected end of Git blob during sensitive scan")
        if remaining is not None:
            remaining -= len(chunk)
        total_read += len(chunk)
        at_end = reached_eof or remaining == 0
        exact_pending += chunk
        if (
            _blocking_exact_matcher is not None
            and result.blocking_rule is None
            and _blocking_exact_matcher.match(exact_pending) is not None
        ):
            result.blocking_rule = "base-only-path-secret-retained"
            blocked = True
        next_committed_start = (
            total_read
            if at_end
            else max(0, total_read - max(0, exact_retention_length - 1))
        )
        (
            raw_counts,
            unembedded_counts,
            reduction_offsets,
            reduction_unembedded_offsets,
        ) = _count_exact_value_occurrences(
            exact_pending,
            exact_index=exact_index,
            minimum_start=max(0, committed_start - exact_pending_offset),
            maximum_start=max(0, next_committed_start - exact_pending_offset),
            event_budget=occurrence_budget,
            capture_reduction_offsets=capture_reduction_offsets,
        )
        result.raw_occurrence_counts.update(raw_counts)
        result.unembedded_occurrence_counts.update(unembedded_counts)
        for descriptor, offsets in reduction_offsets.items():
            destination = result.reduction_occurrence_offsets.setdefault(
                descriptor,
                set(),
            )
            destination.update(exact_pending_offset + offset for offset in offsets)
        for descriptor, offsets in reduction_unembedded_offsets.items():
            destination = result.reduction_unembedded_offsets.setdefault(
                descriptor,
                set(),
            )
            destination.update(exact_pending_offset + offset for offset in offsets)
        if (
            sum(map(len, result.reduction_occurrence_offsets.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
            or sum(map(len, result.reduction_unembedded_offsets.values()))
            > MAX_SECRET_REDUCTION_PROVENANCE_OCCURRENCES
        ):
            raise ReviewError(
                "external review secret-reduction occurrence provenance exceeds "
                "the entry limit"
            )
        committed_start = next_committed_start
        if not at_end:
            retain_exact_from = max(
                exact_pending_offset,
                committed_start - max(0, exact_retention_length - 1),
            )
            exact_pending = exact_pending[retain_exact_from - exact_pending_offset :]
            exact_pending_offset = retain_exact_from
        if exact_only:
            if at_end:
                break
            continue
        if blocked:
            if at_end:
                break
            continue
        pending += chunk
        if (
            pending_offset == 0
            and not at_end
            and total_read < MAX_SECRET_PREFIX_PROOF_BYTES + overlap
        ):
            continue
        next_committed_end = total_read if at_end else max(0, total_read - overlap)
        local_minimum = max(0, committed_end - pending_offset)
        local_maximum = max(0, next_committed_end - pending_offset)
        # A suffix scan is speculative until its full commit range is proven.
        # Only the complete scan, or its safe-prefix replay, may commit event
        # and coverage budget. Actual proof work remains globally charged.
        pending_budget = event_budget.clone(allow_prefix_proof_overdraft=True)
        pending_proof_tracker = prefix_proof_tracker.clone(
            pending_budget,
            coordinate_offset=pending_offset,
        )
        capture_only_legacy_evidence = (
            _continue_after_blocking
            and capture_accepted_candidates
            and result.blocking_rule is not None
            and pending_offset != 0
            and not diff_surface
        )
        pending_scan = _scan_secret_value(
            pending,
            accepted_values=accepted,
            minimum_end=local_minimum,
            maximum_end=local_maximum,
            capture_accepted_candidates=capture_accepted_candidates,
            capture_blocking_candidates=capture_blocking_candidates,
            reduced_secret_values=reduced_secret_values,
            diff_surface=diff_surface,
            prefix_context_complete=pending_offset == 0,
            suffix_context_complete=at_end,
            _accepted_index=accepted_index,
            _event_budget=pending_budget,
            _prefix_proof_tracker=pending_proof_tracker,
            _continue_after_blocking=_continue_after_blocking,
            _capture_only_legacy_evidence=capture_only_legacy_evidence,
        )
        incomplete_retention_start: int | None = None
        if pending_scan.incomplete_suffix_start is not None:
            if pending_scan.incomplete_suffix_retention_start is None:
                raise ReviewError(
                    "sensitive scanner lost an incomplete retention boundary"
                )
            incomplete_retention_start = (
                pending_offset + pending_scan.incomplete_suffix_retention_start
            )
            safe_local_maximum = max(
                local_minimum,
                min(local_maximum, pending_scan.incomplete_suffix_start),
            )
            if safe_local_maximum > local_minimum:
                committed_budget = event_budget.clone()
                committed_proof_tracker = prefix_proof_tracker.clone(
                    committed_budget,
                    coordinate_offset=pending_offset,
                )
                committed_scan = _scan_secret_value(
                    pending,
                    accepted_values=accepted,
                    minimum_end=local_minimum,
                    maximum_end=safe_local_maximum,
                    capture_accepted_candidates=capture_accepted_candidates,
                    capture_blocking_candidates=capture_blocking_candidates,
                    reduced_secret_values=reduced_secret_values,
                    diff_surface=diff_surface,
                    prefix_context_complete=pending_offset == 0,
                    suffix_context_complete=at_end,
                    _accepted_index=accepted_index,
                    _event_budget=committed_budget,
                    _prefix_proof_tracker=committed_proof_tracker,
                    _continue_after_blocking=_continue_after_blocking,
                    _capture_only_legacy_evidence=capture_only_legacy_evidence,
                )
                if committed_scan.incomplete_suffix_start is not None:
                    raise ReviewError(
                        "sensitive scanner could not establish a complete diff prefix"
                    )
                prefix_proof_tracker.commit_from(committed_proof_tracker)
                result.merge(committed_scan)
            # Commit the complete prefix, but retain the deferred assignment
            # inside the overlap so it is re-evaluated with the next read.
            next_committed_end = pending_offset + safe_local_maximum
        else:
            prefix_proof_tracker.commit_from(pending_proof_tracker)
            result.merge(pending_scan)
        if result.blocking_rule is not None and not _continue_after_blocking:
            blocked = True
            pending = b""
        committed_end = next_committed_end
        if at_end:
            break
        retain_from = max(pending_offset, committed_end - overlap)
        if diff_surface and pending:
            local_committed_end = min(
                len(pending),
                max(0, committed_end - pending_offset),
            )
            hunk_context, _lower_bound = _bounded_diff_hunk_context_before(
                pending,
                local_committed_end,
                prefix_context_complete=pending_offset == 0,
                # A future event may begin inside the retained overlap. Keep
                # the latest enclosing hunk only while it can still fall
                # inside that event's bounded proof window.
                lookbehind_bytes=MAX_SECRET_PREFIX_PROOF_BYTES + overlap,
            )
            if hunk_context is not None:
                retain_from = min(
                    retain_from,
                    pending_offset + hunk_context.retention_start,
                )
        if incomplete_retention_start is not None:
            retain_from = min(retain_from, incomplete_retention_start)
        pending = pending[retain_from - pending_offset :]
        pending_offset = retain_from
    return result


def _stream_secret_rule(stream: BinaryIO, *, size: int | None = None) -> str | None:
    return _stream_secret_scan(stream, size=size).blocking_rule


def _value_secret_rule(
    value: bytes,
    *,
    event_budget: SecretScanBudget | None = None,
) -> str | None:
    return _scan_secret_value(value, _event_budget=event_budget).blocking_rule


def _is_placeholder_secret(candidate: bytes) -> bool:
    return PLACEHOLDER_SECRET_PATTERN.fullmatch(candidate.strip()) is not None


def _is_secret_pattern_marker(candidate: bytes) -> bool:
    normalized = candidate.strip().lower()
    return any(
        normalized == marker.lower()
        for markers in SECRET_PATTERN_MARKERS.values()
        for marker in markers
    )


def _looks_like_unquoted_secret(candidate: bytes) -> bool:
    if LONG_NUMERIC_SECRET.fullmatch(candidate):
        return True
    if LONG_ALPHANUMERIC_SECRET.fullmatch(candidate):
        return True
    character_classes = sum(
        (
            any(97 <= value <= 122 for value in candidate),
            any(65 <= value <= 90 for value in candidate),
            any(48 <= value <= 57 for value in candidate),
            any(
                33 <= value <= 126
                and not 48 <= value <= 57
                and not 65 <= value <= 90
                and not 97 <= value <= 122
                for value in candidate
            ),
        )
    )
    return character_classes >= 3 and any(48 <= value <= 57 for value in candidate)


def _read_prompt_template(path: pathlib.Path) -> str:
    with _secure_file_reader(
        path,
        label="review prompt override",
    ) as (handle, metadata):
        if metadata.st_size > MAX_REVIEW_PROMPT_BYTES:
            raise ReviewError(
                f"review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
            )
        encoded = handle.read(MAX_REVIEW_PROMPT_BYTES + 1)
        if len(encoded) > MAX_REVIEW_PROMPT_BYTES:
            raise ReviewError(
                f"review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
            )
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError("review prompt override is not valid UTF-8") from error


def _validate_prompt_size(prompt: str) -> None:
    if len(prompt.encode("utf-8")) > MAX_REVIEW_PROMPT_BYTES:
        raise ReviewError(
            f"review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
        )


def _source_status(
    context: SourceInspectionGitContext,
    *,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> bytes:
    return _bounded_source_git_output(
        context,
        "status",
        "--porcelain=v2",
        "-z",
        "--no-renames",
        "--untracked-files=all",
        "--ignore-submodules=all",
        byte_limit=MAX_SOURCE_STATUS_BYTES,
        record_limit=MAX_SOURCE_STATUS_RECORDS,
        label="source WIP status metadata",
        config_overrides=(f"core.excludesFile={context.excludes_file}",),
        capture_budget=capture_budget,
    )


def _source_index_snapshot(
    context: SourceInspectionGitContext,
    *,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> dict[bytes, tuple[str, str]]:
    value = _bounded_source_git_output(
        context,
        "ls-files",
        "--stage",
        "-v",
        "-z",
        "--cached",
        "--",
        byte_limit=MAX_SOURCE_INDEX_METADATA_BYTES,
        record_limit=MAX_SOURCE_INDEX_RECORDS,
        label="source index-flag metadata",
        capture_budget=capture_budget,
    )
    if value and not value.endswith(b"\0"):
        raise ReviewError("unterminated source index-flag metadata")
    object_id_length = len(context.head_sha)
    lowercase_hex = b"0123456789abcdef"
    metadata_by_path: dict[bytes, tuple[str, str]] = {}
    for record in value.split(b"\0")[:-1]:
        if len(record) < 3 or record[1:2] != b" ":
            raise ReviewError("source index-flag metadata is malformed")
        tag = record[:1]
        if tag == b"S" or tag.islower():
            raise ReviewError(
                "source index contains assume-unchanged or skip-worktree entries; "
                "clear hidden index flags before preparing a review"
            )
        metadata, separator, raw_path = record[2:].partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ReviewError("source index-flag metadata is malformed")
        raw_mode, raw_object_id, raw_stage = fields
        if raw_mode not in {b"100644", b"100755", b"120000", b"160000"}:
            raise ReviewError("source index contains an unsupported mode")
        if raw_stage != b"0":
            raise ReviewError("source index contains an unmerged entry")
        if len(raw_object_id) != object_id_length or any(
            byte not in lowercase_hex for byte in raw_object_id
        ):
            raise ReviewError("source index object id is malformed")
        if not raw_path or raw_path in metadata_by_path:
            raise ReviewError("source index path metadata is malformed")
        metadata_by_path[raw_path] = (
            raw_mode.decode("ascii"),
            raw_object_id.decode("ascii"),
        )
    return metadata_by_path


def _require_unchanged_source_gitlinks(
    context: SourceInspectionGitContext,
    index_snapshot: Mapping[bytes, tuple[str, str]],
    *,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> None:
    value = _bounded_source_git_output(
        context,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        context.head_sha,
        "--",
        byte_limit=MAX_SOURCE_INDEX_METADATA_BYTES,
        record_limit=MAX_SOURCE_INDEX_RECORDS,
        label="source HEAD tree metadata",
        capture_budget=capture_budget,
    )
    if value and not value.endswith(b"\0"):
        raise ReviewError("unterminated source HEAD tree metadata")
    object_id_length = len(context.head_sha)
    lowercase_hex = b"0123456789abcdef"
    head_gitlinks: dict[bytes, str] = {}
    for record in value.split(b"\0")[:-1]:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ReviewError("source HEAD tree metadata is malformed")
        raw_mode, raw_object_type, raw_object_id = fields
        if raw_mode not in {b"100644", b"100755", b"120000", b"160000"}:
            raise ReviewError("source HEAD tree contains an unsupported mode")
        expected_object_type = b"commit" if raw_mode == b"160000" else b"blob"
        if raw_object_type != expected_object_type:
            raise ReviewError("source HEAD tree metadata is malformed")
        if len(raw_object_id) != object_id_length or any(
            byte not in lowercase_hex for byte in raw_object_id
        ):
            raise ReviewError("source HEAD tree object id is malformed")
        if not raw_path:
            raise ReviewError("source HEAD tree path metadata is malformed")
        if raw_mode == b"160000":
            if raw_path in head_gitlinks:
                raise ReviewError("source HEAD tree path metadata is malformed")
            head_gitlinks[raw_path] = raw_object_id.decode("ascii")

    index_gitlinks = {
        raw_path: object_id
        for raw_path, (mode, object_id) in index_snapshot.items()
        if mode == "160000"
    }
    if index_gitlinks != head_gitlinks:
        raise ReviewError(
            "source index gitlinks do not match source HEAD; staged gitlink "
            "changes are not supported"
        )


def _require_clean_source(context: SourceInspectionGitContext) -> None:
    index_snapshot = _source_index_snapshot(context)
    _require_unchanged_source_gitlinks(context, index_snapshot)
    if _source_status(context):
        raise ReviewError(
            "source repository has staged, unstaged, or nonignored untracked "
            "changes; commit or clean them, or explicitly use --include-source-wip"
        )
    if _source_index_snapshot(context) != index_snapshot:
        raise ReviewError("source index changed while clean source was verified")


def _parse_wip_path(raw_path: bytes) -> pathlib.PurePosixPath:
    relative = pathlib.PurePosixPath(os.fsdecode(raw_path))
    display = _redact_secret_path(os.fsdecode(raw_path), "source WIP path")
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ReviewError(f"unsafe source WIP path: {display}")
    if any(part.casefold() == ".git" for part in relative.parts):
        raise ReviewError(f"reserved .git path in source WIP: {display}")
    if relative.parts[0].casefold() in {".codex-review", ".codex-tmp"}:
        raise ReviewError(f"reserved helper path in source WIP: {display}")
    return relative


def _porcelain_v2_groups(value: bytes) -> list[tuple[bytes, ...]]:
    if not value:
        return []
    records = value.split(b"\0")
    if records[-1] != b"":
        raise ReviewError("unterminated source WIP status metadata")
    groups: list[tuple[bytes, ...]] = []
    index = 0
    while index < len(records) - 1:
        record = records[index]
        if record.startswith(b"2 "):
            if index + 1 >= len(records) - 1:
                raise ReviewError("source WIP rename status metadata is malformed")
            groups.append((record, records[index + 1]))
            index += 2
        else:
            groups.append((record,))
            index += 1
    return groups


def _source_wip_status_paths(
    status_bytes: bytes,
) -> tuple[
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
]:
    staged_paths: set[pathlib.PurePosixPath] = set()
    staged_deleted_paths: set[pathlib.PurePosixPath] = set()
    unstaged_paths: set[pathlib.PurePosixPath] = set()
    unstaged_deleted_paths: set[pathlib.PurePosixPath] = set()
    untracked_paths: set[pathlib.PurePosixPath] = set()

    def add_status_path(
        status: int,
        *,
        current: pathlib.PurePosixPath,
        original: pathlib.PurePosixPath | None,
        changed: set[pathlib.PurePosixPath],
        deleted: set[pathlib.PurePosixPath],
    ) -> None:
        if status == ord("."):
            return
        if status not in b"MTADRC":
            raise ReviewError("source WIP status metadata is malformed")
        changed.add(current)
        if status in b"RC":
            if original is None:
                raise ReviewError("source WIP rename status metadata is malformed")
            changed.add(original)
        elif status == ord("D"):
            deleted.add(current)

    for group in _porcelain_v2_groups(status_bytes):
        record = group[0]
        if record.startswith(b"u "):
            raise ReviewError("source WIP contains unresolved merge conflicts")
        if record.startswith(b"? "):
            if len(group) != 1:
                raise ReviewError("source WIP status metadata is malformed")
            raw_path = record[2:]
            if raw_path.endswith(b"/"):
                raise ReviewError(
                    "source WIP contains an unexpanded untracked directory; "
                    "nested repositories are not supported"
                )
            untracked_paths.add(_parse_wip_path(raw_path))
            continue
        if record.startswith(b"1 "):
            if len(group) != 1:
                raise ReviewError("source WIP status metadata is malformed")
            fields = record.split(b" ", 8)
            if len(fields) != 9:
                raise ReviewError("source WIP status metadata is malformed")
            raw_path = fields[8]
            raw_original = None
        elif record.startswith(b"2 "):
            if len(group) != 2:
                raise ReviewError("source WIP rename status metadata is malformed")
            fields = record.split(b" ", 9)
            if len(fields) != 10:
                raise ReviewError("source WIP rename status metadata is malformed")
            raw_path = fields[9]
            raw_original = group[1]
        else:
            raise ReviewError("source WIP status metadata is malformed")
        xy = fields[1]
        if len(xy) != 2 or fields[2].startswith(b"S"):
            if fields[2].startswith(b"S"):
                raise ReviewError(
                    "source WIP contains a changed or dirty submodule, which is not supported"
                )
            raise ReviewError("source WIP status metadata is malformed")
        current = _parse_wip_path(raw_path)
        original = None if raw_original is None else _parse_wip_path(raw_original)
        add_status_path(
            xy[0],
            current=current,
            original=original,
            changed=staged_paths,
            deleted=staged_deleted_paths,
        )
        add_status_path(
            xy[1],
            current=current,
            original=original,
            changed=unstaged_paths,
            deleted=unstaged_deleted_paths,
        )
    return (
        staged_paths,
        staged_deleted_paths,
        unstaged_paths,
        unstaged_deleted_paths,
        untracked_paths,
    )


def _source_final_worktree_paths(
    context: SourceInspectionGitContext,
    *,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> tuple[set[pathlib.PurePosixPath], set[pathlib.PurePosixPath]]:
    label = "source WIP tracked paths"
    value = _bounded_source_git_output(
        context,
        "diff",
        "--name-status",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=all",
        context.head_sha,
        "--",
        byte_limit=MAX_SOURCE_TRACKED_PATH_BYTES,
        record_limit=2 * MAX_SOURCE_TRACKED_PATH_RECORDS,
        label=label,
        capture_budget=capture_budget,
    )

    def next_record(cursor: int) -> tuple[bytes, int]:
        search_start = cursor
        while search_start < len(value):
            if capture_budget is not None:
                capture_budget.remaining_seconds()
            search_end = min(
                len(value),
                search_start + SOURCE_WIP_PARSE_DEADLINE_CHECK_BYTES,
            )
            separator = value.find(b"\0", search_start, search_end)
            if separator >= 0:
                return value[cursor:separator], separator + 1
            search_start = search_end
        raise ReviewError("source WIP tracked path metadata is malformed")

    paths: set[pathlib.PurePosixPath] = set()
    deleted_paths: set[pathlib.PurePosixPath] = set()
    cursor = 0
    while cursor < len(value):
        raw_status, cursor = next_record(cursor)
        raw_path, cursor = next_record(cursor)
        if raw_status not in {b"A", b"D", b"M", b"T", b"U", b"X", b"B"}:
            raise ReviewError("source WIP tracked path metadata is malformed")
        relative = _parse_wip_path(raw_path)
        paths.add(relative)
        if len(paths) > MAX_CHANGED_ENTRIES:
            raise ReviewError(
                "source WIP tracked paths exceeds the review entry-count limit"
            )
        if raw_status == b"D":
            deleted_paths.add(relative)
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    return paths, deleted_paths


def _source_wip_paths(
    context: SourceInspectionGitContext,
    initial_status: bytes,
    *,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> tuple[
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
    set[pathlib.PurePosixPath],
]:
    (
        staged_paths,
        staged_deleted_paths,
        unstaged_paths,
        unstaged_deleted_paths,
        untracked_paths,
    ) = _source_wip_status_paths(initial_status)
    (
        final_worktree_paths,
        final_worktree_deleted_paths,
    ) = _source_final_worktree_paths(
        context,
        capture_budget=capture_budget,
    )
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    if not final_worktree_deleted_paths.issubset(final_worktree_paths):
        raise ReviewError("source WIP tracked path metadata is inconsistent")
    if not staged_deleted_paths.issubset(staged_paths):
        raise ReviewError("source WIP staged path metadata is inconsistent")
    if not unstaged_deleted_paths.issubset(unstaged_paths):
        raise ReviewError("source WIP unstaged path metadata is inconsistent")
    deleted_status_paths = staged_deleted_paths | unstaged_deleted_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    if not final_worktree_deleted_paths.issubset(deleted_status_paths):
        raise ReviewError("source WIP deleted path metadata is inconsistent")
    status_changed_paths = staged_paths | unstaged_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    final_changed_paths = staged_paths | final_worktree_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    if status_changed_paths != final_changed_paths:
        raise ReviewError(
            "source WIP staged and unstaged path metadata is inconsistent"
        )
    paths = status_changed_paths | untracked_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    if len(paths) > MAX_CHANGED_ENTRIES:
        raise ReviewError("source WIP exceeds the review entry-count limit")
    worktree_capture_paths = (
        final_worktree_paths - final_worktree_deleted_paths
    ) | untracked_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    index_capture_paths = staged_paths - staged_deleted_paths - final_worktree_paths
    if capture_budget is not None:
        capture_budget.remaining_seconds()
    return paths, worktree_capture_paths, index_capture_paths


def _read_wip_entry(
    *,
    source_root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    remaining_bytes: int,
    expected_materialized_mode: str | None = None,
    regular_mode_override: str | None = None,
) -> tuple[str, bytes] | None:
    if regular_mode_override not in {None, "100644", "100755"}:
        raise ValueError("source WIP regular mode override is invalid")
    display = _redact_secret_path(relative.as_posix(), "source WIP path")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(source_root, directory_flags)
    except OSError as error:
        raise ReviewError("cannot securely open the source WIP root") from error
    try:
        for component in relative.parts[:-1]:
            try:
                component_status = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as error:
                raise ReviewError(
                    f"cannot inspect source WIP parent for {display}"
                ) from error
            if stat.S_ISLNK(component_status.st_mode):
                return None
            if not stat.S_ISDIR(component_status.st_mode):
                if stat.S_ISREG(component_status.st_mode):
                    return None
                raise ReviewError(
                    f"source WIP path has a special-file parent: {display}"
                )
            try:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            except OSError as error:
                raise ReviewError(
                    f"source WIP parent changed while opened: {display}"
                ) from error
            opened_status = os.fstat(next_fd)
            if (opened_status.st_dev, opened_status.st_ino) != (
                component_status.st_dev,
                component_status.st_ino,
            ):
                os.close(next_fd)
                raise ReviewError(f"source WIP parent changed while opened: {display}")
            os.close(parent_fd)
            parent_fd = next_fd
        name = relative.parts[-1]
        try:
            initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as error:
            raise ReviewError(f"cannot inspect source WIP path {display}") from error
        if stat.S_ISDIR(initial.st_mode):
            return None
        if stat.S_ISLNK(initial.st_mode):
            target = os.readlink(name, dir_fd=parent_fd)
            raw_target = os.fsencode(target)
            if len(raw_target) > 16 * 1024:
                raise ReviewError(f"oversized symlink target in source WIP: {display}")
            if len(raw_target) > remaining_bytes:
                raise ReviewError(
                    f"source WIP symlink exceeds the review snapshot limit: {display}"
                )
            if not symlink_target_stays_within_workspace(relative, target):
                raise ReviewError(
                    f"source WIP symlink escapes review workspace: {display}"
                )
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if os.readlink(name, dir_fd=parent_fd) != target or _wip_stat_identity(
                initial
            ) != _wip_stat_identity(final):
                raise ReviewError(f"source WIP symlink changed while copied: {display}")
            return "120000", raw_target
        if not stat.S_ISREG(initial.st_mode):
            raise ReviewError(f"unsupported special file in source WIP: {display}")
        if initial.st_nlink != 1:
            raise ReviewError(
                f"source WIP regular file must have exactly one hard link: {display}"
            )
        if initial.st_uid != os.geteuid():
            raise ReviewError(
                f"source WIP regular file must be owned by the current user: {display}"
            )
        if expected_materialized_mode in {"100644", "100755"}:
            expected_permissions = (
                0o755 if expected_materialized_mode == "100755" else 0o644
            )
            if stat.S_IMODE(initial.st_mode) != expected_permissions:
                raise ReviewError(
                    "materialized review workspace metadata does not match snapshot tree"
                )
        if (
            initial.st_size > MAX_SNAPSHOT_BLOB_BYTES
            or initial.st_size > remaining_bytes
        ):
            raise ReviewError(
                f"source WIP file exceeds the review snapshot limit: {display}"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
                raise ReviewError(f"source WIP file changed while opened: {display}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(MAX_SNAPSHOT_BLOB_BYTES + 1)
            final_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            final_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            raise ReviewError(
                f"source WIP file changed while copied: {display}"
            ) from error
    finally:
        os.close(parent_fd)
    if (
        len(data) > MAX_SNAPSHOT_BLOB_BYTES
        or _wip_stat_identity(initial) != _wip_stat_identity(final_fd)
        or _wip_stat_identity(initial) != _wip_stat_identity(final_path)
    ):
        raise ReviewError(f"source WIP file changed while copied: {display}")
    mode = regular_mode_override or (
        "100755" if initial.st_mode & stat.S_IXUSR else "100644"
    )
    return mode, data


def _wip_stat_identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _capture_source_wip_entries(
    *,
    source_root: pathlib.Path,
    paths: set[pathlib.PurePosixPath],
    regular_mode_overrides: Mapping[pathlib.PurePosixPath, str] | None = None,
    capture_budget: SourceWipCaptureBudget | None = None,
) -> dict[pathlib.PurePosixPath, tuple[str, bytes]]:
    selected_mode_overrides = (
        {} if regular_mode_overrides is None else regular_mode_overrides
    )
    if not set(selected_mode_overrides).issubset(paths):
        raise ValueError("source WIP regular mode override paths are inconsistent")
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]] = {}
    remaining_bytes = MAX_SNAPSHOT_BYTES
    for relative in sorted(paths, key=lambda item: item.as_posix()):
        if capture_budget is not None:
            capture_budget.remaining_seconds()
        entry = _read_wip_entry(
            source_root=source_root,
            relative=relative,
            remaining_bytes=remaining_bytes,
            regular_mode_override=selected_mode_overrides.get(relative),
        )
        if entry is None:
            raise ReviewError(
                "source WIP planned worktree path is missing during capture"
            )
        entries[relative] = entry
        remaining_bytes -= len(entry[1])
    if entries.keys() != paths:
        raise ReviewError("source WIP worktree capture is incomplete")
    return entries


def _source_index_wip_metadata(
    *,
    index_snapshot: Mapping[bytes, tuple[str, str]],
    paths: set[pathlib.PurePosixPath],
    required_paths: set[pathlib.PurePosixPath],
) -> dict[pathlib.PurePosixPath, tuple[str, str]]:
    if not required_paths.issubset(paths):
        raise ValueError("source WIP required index paths are inconsistent")
    selected_raw_paths = {
        os.fsencode(relative.as_posix()): relative for relative in paths
    }
    if len(selected_raw_paths) != len(paths):
        raise ReviewError("source WIP staged index path encoding is ambiguous")
    metadata_by_path = {
        relative: index_snapshot[raw_path]
        for raw_path, relative in selected_raw_paths.items()
        if raw_path in index_snapshot
    }
    if not required_paths.issubset(metadata_by_path):
        raise ReviewError("source WIP staged index metadata is incomplete")
    return metadata_by_path


def _source_wip_regular_mode_overrides(
    *,
    context: SourceInspectionGitContext,
    metadata_by_path: Mapping[pathlib.PurePosixPath, tuple[str, str]],
) -> dict[pathlib.PurePosixPath, str]:
    if context.file_mode:
        return {}
    return {
        relative: mode
        for relative, (mode, _object_id) in metadata_by_path.items()
        if mode in {"100644", "100755"}
    }


def _capture_source_index_wip_entries(
    *,
    context: SourceInspectionGitContext,
    metadata_by_path: Mapping[pathlib.PurePosixPath, tuple[str, str]],
    remaining_bytes: int,
    capture_budget: SourceWipCaptureBudget,
) -> dict[pathlib.PurePosixPath, tuple[str, bytes]]:
    if not 0 <= remaining_bytes <= MAX_SNAPSHOT_BYTES:
        raise ValueError("source WIP staged blob budget is invalid")
    if not metadata_by_path:
        return {}
    sorted_metadata = sorted(
        metadata_by_path.items(),
        key=lambda item: item[0].as_posix(),
    )
    with (
        _temporary_review_file() as batch_input,
        _temporary_review_file() as batch_output,
    ):
        for _relative, (_mode, object_id) in sorted_metadata:
            batch_input.write(object_id.encode("ascii") + b"\n")
        batch_input.seek(0)
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=context.git_dir,
                args=("cat-file", "--batch"),
            ),
            environment=_git_environment(
                object_directory=context.object_directory,
            ),
            input_handle=batch_input,
            destination=batch_output,
            label="source WIP staged blobs",
            byte_limit=remaining_bytes + MAX_SOURCE_INDEX_METADATA_BYTES,
            timeout_seconds=capture_budget.claim_git_invocation(),
            timeout_label="source Git",
        )
        batch_output.seek(0)
        entries: dict[pathlib.PurePosixPath, tuple[str, bytes]] = {}
        for relative, (mode, object_id) in sorted_metadata:
            header = batch_output.readline()
            fields = header.rstrip(b"\n").split(b" ")
            if len(fields) != 3:
                raise ReviewError("source WIP staged blob header is malformed")
            raw_actual_object, object_type, raw_size = fields
            if raw_actual_object != object_id.encode("ascii") or object_type != b"blob":
                raise ReviewError("source WIP staged blob metadata is inconsistent")
            try:
                size = int(raw_size)
            except ValueError as error:
                raise ReviewError("source WIP staged blob size is malformed") from error
            display = _redact_secret_path(relative.as_posix(), "source WIP path")
            if size < 0 or size > remaining_bytes:
                raise ReviewError(
                    f"source WIP staged blob exceeds the review snapshot limit: {display}"
                )
            if mode == "120000":
                if size > 16 * 1024:
                    raise ReviewError(
                        f"oversized symlink target in source WIP: {display}"
                    )
            elif size > MAX_SNAPSHOT_BLOB_BYTES:
                raise ReviewError(
                    f"source WIP file exceeds the review snapshot limit: {display}"
                )
            data = _read_exact(batch_output, size)
            if batch_output.read(1) != b"\n":
                raise ReviewError("missing delimiter after source WIP staged blob")
            if mode == "120000":
                if b"\0" in data:
                    raise ReviewError(f"NUL in source WIP symlink target: {display}")
                target = os.fsdecode(data)
                if not symlink_target_stays_within_workspace(relative, target):
                    raise ReviewError(
                        f"source WIP symlink escapes review workspace: {display}"
                    )
            entries[relative] = (mode, data)
            remaining_bytes -= size
        if batch_output.read(1):
            raise ReviewError(
                "source WIP staged blobs contain unexpected trailing data"
            )
    return entries


def _import_source_wip_blobs(
    *,
    workspace_root: pathlib.Path,
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]],
    capture_budget: SourceWipCaptureBudget | None = None,
) -> tuple[str, dict[pathlib.PurePosixPath, str]]:
    """Import captured WIP blobs with one bounded Git process."""

    object_format = (
        _run_worktree_git(
            workspace_root,
            "rev-parse",
            "--show-object-format",
            capture_budget=capture_budget,
        )
        .stdout.decode("ascii")
        .strip()
    )
    if object_format not in {"sha1", "sha256"}:
        raise ReviewError(f"unsupported Git object format: {object_format!r}")
    object_ids: dict[pathlib.PurePosixPath, str] = {}
    if not entries:
        return object_format, object_ids

    object_id_length = {"sha1": 40, "sha256": 64}[object_format]
    sorted_entries = sorted(entries.items(), key=lambda item: item[0].as_posix())
    expected_ids: list[str] = []
    with _temporary_review_file() as stream:
        stream.write(b"feature get-mark\n")
        for mark, (_relative, (_mode, data)) in enumerate(sorted_entries, start=1):
            digest = hashlib.new(object_format)
            digest.update(f"blob {len(data)}\0".encode("ascii"))
            digest.update(data)
            expected_ids.append(digest.hexdigest())
            stream.write(b"blob\n")
            stream.write(f"mark :{mark}\n".encode("ascii"))
            stream.write(f"data {len(data)}\n".encode("ascii"))
            stream.write(data)
            stream.write(b"\n")
        for mark in range(1, len(sorted_entries) + 1):
            stream.write(f"get-mark :{mark}\n".encode("ascii"))
        stream.write(b"done\n")
        stream.seek(0)
        completed = _run_worktree_git(
            workspace_root,
            "fast-import",
            "--quiet",
            "--done",
            input_handle=stream,
            byte_limit=len(sorted_entries) * (object_id_length + 1),
            record_limit=len(sorted_entries),
            capture_budget=capture_budget,
        )
    output = completed.stdout
    if not output.endswith(b"\n"):
        raise ReviewError("source WIP blob import produced truncated object metadata")
    actual_ids = output[:-1].split(b"\n")
    if len(actual_ids) != len(sorted_entries):
        raise ReviewError("source WIP blob import produced incomplete object metadata")
    lowercase_hex = b"0123456789abcdef"
    for (relative, _entry), expected_id, raw_actual in zip(
        sorted_entries,
        expected_ids,
        actual_ids,
        strict=True,
    ):
        if len(raw_actual) != object_id_length or any(
            byte not in lowercase_hex for byte in raw_actual
        ):
            raise ReviewError("source WIP blob import produced invalid object metadata")
        actual_id = raw_actual.decode("ascii")
        if actual_id != expected_id:
            raise ReviewError(
                "source WIP blob import produced mismatched object metadata"
            )
        object_ids[relative] = actual_id
    return object_format, object_ids


def _apply_source_wip_index_overlay(
    *,
    workspace_root: pathlib.Path,
    paths: set[pathlib.PurePosixPath],
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]],
    object_format: str,
    object_ids: dict[pathlib.PurePosixPath, str],
    capture_budget: SourceWipCaptureBudget,
) -> None:
    """Apply all WIP removals and additions with one NUL-delimited index update."""

    object_id_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if object_id_length is None:
        raise ReviewError(f"unsupported Git object format: {object_format!r}")
    zero_object_id = b"0" * object_id_length
    with _temporary_review_file() as index_info:
        for relative in sorted(
            paths,
            key=lambda item: (len(item.parts), item.as_posix()),
            reverse=True,
        ):
            index_info.write(b"0 " + zero_object_id + b"\t")
            index_info.write(os.fsencode(relative.as_posix()))
            index_info.write(b"\0")
        for relative, (mode, _data) in sorted(
            entries.items(), key=lambda item: (len(item[0].parts), item[0].as_posix())
        ):
            object_id = object_ids.get(relative)
            if object_id is None or len(object_id) != object_id_length:
                raise ReviewError(
                    "source WIP blob import produced invalid object metadata"
                )
            index_info.write(mode.encode("ascii") + b" ")
            index_info.write(object_id.encode("ascii") + b"\t")
            index_info.write(os.fsencode(relative.as_posix()))
            index_info.write(b"\0")
        index_info.seek(0)
        _run_worktree_git(
            workspace_root,
            "update-index",
            "-z",
            "--index-info",
            input_handle=index_info,
            capture_budget=capture_budget,
        )


def _overlay_source_wip(
    *,
    source_inspection: SourceInspectionGitContext,
    source_root: pathlib.Path,
    workspace_root: pathlib.Path,
    head_sha: str,
    initial_status: bytes,
    paths: set[pathlib.PurePosixPath],
    worktree_capture_paths: set[pathlib.PurePosixPath],
    index_capture_paths: set[pathlib.PurePosixPath],
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]],
    initial_index_snapshot: Mapping[bytes, tuple[str, str]],
    capture_budget: SourceWipCaptureBudget,
) -> str:
    capture_budget.remaining_seconds()
    object_format, object_ids = _import_source_wip_blobs(
        workspace_root=workspace_root,
        entries=entries,
        capture_budget=capture_budget,
    )
    _apply_source_wip_index_overlay(
        workspace_root=workspace_root,
        paths=paths,
        entries=entries,
        object_format=object_format,
        object_ids=object_ids,
        capture_budget=capture_budget,
    )
    snapshot_tree_sha = (
        _run_worktree_git(
            workspace_root,
            "write-tree",
            capture_budget=capture_budget,
        )
        .stdout.decode("ascii")
        .strip()
    )
    if (
        resolve_commit(
            source_root,
            "HEAD",
            label="source WIP HEAD",
            capture_budget=capture_budget,
        )
        != head_sha
    ):
        raise ReviewError("source HEAD changed while the WIP snapshot was prepared")
    rechecked_index_snapshot = _source_index_snapshot(
        source_inspection,
        capture_budget=capture_budget,
    )
    if rechecked_index_snapshot != initial_index_snapshot:
        raise ReviewError(
            "source WIP index changed while the private snapshot was prepared"
        )
    rechecked_index_metadata = _source_index_wip_metadata(
        index_snapshot=rechecked_index_snapshot,
        paths=worktree_capture_paths | index_capture_paths,
        required_paths=index_capture_paths,
    )
    rechecked_worktree_metadata = {
        relative: rechecked_index_metadata[relative]
        for relative in worktree_capture_paths
        if relative in rechecked_index_metadata
    }
    rechecked_worktree_entries = _capture_source_wip_entries(
        source_root=source_root,
        paths=worktree_capture_paths,
        regular_mode_overrides=_source_wip_regular_mode_overrides(
            context=source_inspection,
            metadata_by_path=rechecked_worktree_metadata,
        ),
        capture_budget=capture_budget,
    )
    if not worktree_capture_paths.issubset(entries):
        raise ReviewError("source WIP initial worktree capture is incomplete")
    expected_worktree_entries = {
        relative: entries[relative] for relative in worktree_capture_paths
    }
    if rechecked_worktree_entries != expected_worktree_entries:
        raise ReviewError(
            "source WIP content changed while the private snapshot was prepared"
        )
    rechecked_index_entries = _capture_source_index_wip_entries(
        context=source_inspection,
        metadata_by_path={
            relative: rechecked_index_metadata[relative]
            for relative in index_capture_paths
        },
        remaining_bytes=MAX_SNAPSHOT_BYTES
        - sum(len(entry[1]) for entry in rechecked_worktree_entries.values()),
        capture_budget=capture_budget,
    )
    if not index_capture_paths.issubset(entries):
        raise ReviewError("source WIP initial staged capture is incomplete")
    expected_index_entries = {
        relative: entries[relative] for relative in index_capture_paths
    }
    if rechecked_index_entries != expected_index_entries:
        raise ReviewError(
            "source WIP staged content changed while the private snapshot was prepared"
        )
    final_status = _source_status(
        source_inspection,
        capture_budget=capture_budget,
    )
    if final_status != initial_status:
        raise ReviewError("source WIP changed while the review snapshot was prepared")
    final_path_plan = _source_wip_paths(
        source_inspection,
        final_status,
        capture_budget=capture_budget,
    )
    if final_path_plan != (
        paths,
        worktree_capture_paths,
        index_capture_paths,
    ):
        raise ReviewError(
            "source WIP path selection changed while the review snapshot was prepared"
        )
    capture_budget.remaining_seconds()
    return snapshot_tree_sha


def _clear_materialized_workspace(workspace_root: pathlib.Path) -> None:
    workspace_descriptor = os.open(
        workspace_root,
        _private_cleanup_directory_flags(),
    )
    try:
        opened = os.fstat(workspace_descriptor)
        path_status = os.lstat(workspace_root)
        if _private_cleanup_identity(opened) != _private_cleanup_identity(path_status):
            raise ReviewError(
                "detached review worktree changed while opening it for rematerialization"
            )
        cleanup_errors = _remove_open_directory_contents(
            workspace_descriptor,
            depth=0,
            excluded_entry_names=frozenset({".git"}),
        )
        if cleanup_errors:
            raise ReviewError(
                "cannot clear detached review worktree before rematerialization: "
                + "; ".join(cleanup_errors)
            )
    finally:
        os.close(workspace_descriptor)
    if {entry.name for entry in os.scandir(workspace_root)} != {".git"}:
        raise ReviewError(
            "cannot clear detached review worktree before rematerialization"
        )


def _workspace_inventory(
    workspace_root: pathlib.Path,
    *,
    allow_control_dir: bool,
) -> set[pathlib.PurePosixPath]:
    inventory: set[pathlib.PurePosixPath] = set()

    def visit(directory: pathlib.Path, prefix: pathlib.PurePosixPath) -> None:
        for entry in os.scandir(directory):
            if not prefix.parts and entry.name == ".git":
                continue
            if allow_control_dir and not prefix.parts and entry.name == ".codex-review":
                continue
            relative = prefix / entry.name
            inventory.add(relative)
            if len(inventory) > MAX_SNAPSHOT_ENTRIES * 2:
                raise ReviewError(
                    "materialized review workspace exceeds the verification entry limit"
                )
            if entry.is_dir(follow_symlinks=False):
                visit(pathlib.Path(entry.path), relative)

    visit(workspace_root, pathlib.PurePosixPath())
    return inventory


def _verify_materialized_snapshot(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    workspace_root: pathlib.Path,
    snapshot_tree_sha: str,
    allow_control_dir: bool = False,
    verify_index_tree: bool = True,
) -> None:
    object_format = (
        _run_private_git(
            git_dir=git_view,
            args=("rev-parse", "--show-object-format"),
        )
        .stdout.decode("ascii")
        .strip()
    )
    expected_oid_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if expected_oid_length is None or len(snapshot_tree_sha) != expected_oid_length:
        raise ReviewError("snapshot tree does not match the private Git object format")
    if verify_index_tree:
        index_tree = (
            _run_worktree_git(workspace_root, "write-tree")
            .stdout.decode("ascii")
            .strip()
        )
        if index_tree != snapshot_tree_sha:
            raise ReviewError(
                "detached review worktree index does not match snapshot tree"
            )
    expected_paths: set[pathlib.PurePosixPath] = set()
    expected_directories: set[pathlib.PurePosixPath] = set()
    byte_budget = MAX_SNAPSHOT_BYTES
    with _temporary_review_file() as metadata:
        _run_bounded_process_to_file(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", snapshot_tree_sha),
            ),
            environment=_git_environment(object_directory=object_directory),
            destination=metadata,
            label="snapshot verification metadata",
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            record_separator=b"\0",
        )
        metadata.seek(0)
        for record in _iter_nul_records(
            metadata,
            byte_limit=MAX_TREE_METADATA_BYTES,
            record_limit=MAX_SNAPSHOT_ENTRIES,
            label="snapshot verification metadata",
        ):
            mode, object_type, object_id, relative = _parse_tree_record(record)
            expected_paths.add(relative)
            for depth in range(1, len(relative.parts)):
                expected_directories.add(pathlib.PurePosixPath(*relative.parts[:depth]))
            if mode == "160000" and object_type == "commit":
                expected_directories.add(relative)
                gitlink = workspace_root.joinpath(*relative.parts)
                try:
                    gitlink_metadata = os.lstat(gitlink)
                except OSError as error:
                    raise ReviewError(
                        "materialized review workspace is missing a gitlink directory"
                    ) from error
                if (
                    not stat.S_ISDIR(gitlink_metadata.st_mode)
                    or gitlink_metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(gitlink_metadata.st_mode) != 0o755
                ):
                    raise ReviewError(
                        "materialized review workspace gitlink is not a safe directory"
                    )
                with os.scandir(gitlink) as gitlink_entries:
                    if any(gitlink_entries):
                        raise ReviewError(
                            "materialized review workspace gitlink is not empty"
                        )
                continue
            if object_type != "blob":
                raise ReviewError("snapshot verification found an unsupported object")
            entry = _read_wip_entry(
                source_root=workspace_root,
                relative=relative,
                remaining_bytes=byte_budget,
                expected_materialized_mode=mode,
            )
            if entry is None:
                raise ReviewError(
                    "materialized review workspace is missing a snapshot blob"
                )
            actual_mode, data = entry
            byte_budget -= len(data)
            if actual_mode != mode:
                raise ReviewError(
                    "materialized review workspace mode does not match snapshot tree"
                )
            digest = hashlib.new(object_format)
            digest.update(f"blob {len(data)}\0".encode("ascii"))
            digest.update(data)
            actual_object = digest.hexdigest()
            if actual_object != object_id:
                raise ReviewError(
                    "materialized review workspace content does not match snapshot tree"
                )
    if (
        _workspace_inventory(
            workspace_root,
            allow_control_dir=allow_control_dir,
        )
        != expected_paths | expected_directories
    ):
        raise ReviewError(
            "materialized review workspace topology does not match snapshot tree"
        )


def _review_scope_identity(
    *,
    base_sha: str,
    head_sha: str,
    content_variant: str,
    snapshot_tree_sha: str,
) -> str:
    return hashlib.sha256(
        b"isolated-review-scope-v1\0"
        + base_sha.encode("ascii")
        + b"\0"
        + head_sha.encode("ascii")
        + b"\0"
        + content_variant.encode("ascii")
        + b"\0"
        + snapshot_tree_sha.encode("ascii")
    ).hexdigest()


def _canonical_github_repository(remote_url: str) -> str | None:
    patterns = (
        r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
        r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",
        r"ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote_url.strip())
        if match:
            return match.group(1)
    return None


def audit_legacy_exemption(
    *,
    repo: pathlib.Path,
    ref: str,
    exemption: LegacyExemption,
) -> dict[str, Any]:
    source_root = resolve_repo_root(repo)
    tip = resolve_commit(source_root, ref, label="audited master ref")
    if tip != exemption.verified_master_tip:
        raise ReviewError(
            "audited master ref does not match the catalog's verified master tip"
        )
    origin_result = _git(
        source_root,
        "config",
        "--get",
        "remote.origin.url",
        check=False,
    )
    if origin_result.returncode != 0:
        raise ReviewError("cannot verify the audited repository origin")
    try:
        origin_url = origin_result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ReviewError("audited repository origin is not valid UTF-8") from error
    origin = _canonical_github_repository(origin_url)
    if origin != exemption.repository:
        raise ReviewError(
            "audited repository origin does not match the catalog provenance"
        )

    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    if catalog.legacy_exemption(exemption.identifier) != exemption:
        raise ReviewError("legacy exemption changed while the audit was prepared")
    accepted = accepted_legacy_values(catalog, (exemption,))
    authoring_accepted = accepted_authoring_values(catalog)
    scan_accepted = authoring_accepted + accepted
    descriptors = {item.identifier: item for item in accepted}
    evidence: list[dict[str, Any]] = []

    with _temporary_sanitized_git_view(
        source_root=source_root,
    ) as (git_view, object_directory):
        by_commit: dict[str, list[AcceptedSyntheticValue]] = {}
        for token in exemption.values:
            ancestry_error = (
                "legacy provenance commit is not an ancestor of the verified "
                f"master tip: {token.identifier}"
            )
            is_ancestor = _is_ancestor_in_sanitized_view(
                git_view=git_view,
                object_directory=object_directory,
                ancestor=token.containing_commit,
                descendant=tip,
                failure_message=ancestry_error,
            )
            if not is_ancestor:
                raise ReviewError(ancestry_error)
            by_commit.setdefault(token.containing_commit, []).append(
                descriptors[token.identifier]
            )
        for commit, commit_descriptors in sorted(by_commit.items()):
            scan = _scan_frozen_tree_values(
                git_view=git_view,
                object_directory=object_directory,
                commit=commit,
                accepted_values=scan_accepted,
                raw_occurrence_values=commit_descriptors,
                capture_accepted_candidates=True,
                _continue_after_blocking=True,
            )
            for descriptor in sorted(
                commit_descriptors,
                key=lambda item: item.identifier,
            ):
                token = next(
                    item
                    for item in exemption.values
                    if item.identifier == descriptor.identifier
                )
                count = scan.raw_occurrence_counts[descriptor]
                captured = scan.accepted_candidates.get(descriptor, set())
                if (
                    count != token.source_occurrences
                    or scan.accepted_counts[descriptor] <= 0
                    or captured != {descriptor.value}
                ):
                    raise ReviewError(
                        "legacy master provenance occurrence evidence does not match "
                        f"the catalog for {token.identifier}"
                    )
                evidence.append(
                    {
                        "containing_commit": commit,
                        "rule": token.rule,
                        "source_occurrences": count,
                        "token_id": token.identifier,
                        "value_length": token.value_length,
                        "value_sha256": token.value_sha256,
                    }
                )
    if len(evidence) > MAX_SYNTHETIC_EVIDENCE_ENTRIES:
        raise ReviewError("legacy master audit evidence has too many entries")
    result = {
        "exemption_id": exemption.identifier,
        "match": exemption.match,
        "repository": exemption.repository,
        "status": "verified",
        "values": sorted(evidence, key=lambda item: item["token_id"]),
        "verified_master_tip": tip,
    }
    if (
        len(json.dumps(result, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        > MAX_SYNTHETIC_EVIDENCE_BYTES
    ):
        raise ReviewError("legacy master audit evidence exceeds the size limit")
    _reject_raw_values_in_evidence(
        result,
        accepted_values=_all_catalog_sensitive_values(catalog),
        label="legacy master audit evidence",
    )
    return result


def prepare_workspace(
    *,
    repo: pathlib.Path,
    base_ref: str,
    head_ref: str,
    ownership_handoff: Callable[[ReviewWorkspace], None],
    preparation_cleanup_handoff: (
        Callable[[pathlib.Path, PrivateCleanupEvidence], None] | None
    ) = None,
    synthetic_secret_exemptions: tuple[str, ...] = (),
    prompt_override: pathlib.Path | None = None,
    include_source_wip: bool = False,
) -> ReviewWorkspace:
    source_root = resolve_repo_root(repo)
    base_sha = resolve_commit(source_root, base_ref, label="base ref")
    head_sha = resolve_commit(source_root, head_ref, label="head ref")
    with _temporary_sanitized_git_view(
        source_root=source_root,
    ) as (ancestry_git_view, ancestry_object_directory):
        _require_ancestor_range(
            git_view=ancestry_git_view,
            object_directory=ancestry_object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
        )
    source_head_sha = resolve_commit(source_root, "HEAD", label="source HEAD")
    source_inspection_stack = ExitStack()
    try:
        source_inspection = source_inspection_stack.enter_context(
            _temporary_source_inspection_git_context(
                source_root=source_root,
                head_sha=source_head_sha,
            )
        )
        if include_source_wip:
            if source_head_sha != head_sha:
                raise ReviewError(
                    "--include-source-wip requires --head-ref to resolve to source HEAD"
                )
            source_wip_capture_budget = _new_source_wip_capture_budget()
            source_wip_index_snapshot = _source_index_snapshot(
                source_inspection,
                capture_budget=source_wip_capture_budget,
            )
            _require_unchanged_source_gitlinks(
                source_inspection,
                source_wip_index_snapshot,
                capture_budget=source_wip_capture_budget,
            )
            source_status = _source_status(
                source_inspection,
                capture_budget=source_wip_capture_budget,
            )
            (
                source_wip_paths,
                source_wip_worktree_capture_paths,
                source_wip_index_capture_paths,
            ) = _source_wip_paths(
                source_inspection,
                source_status,
                capture_budget=source_wip_capture_budget,
            )
            if source_wip_worktree_capture_paths & source_wip_index_capture_paths:
                raise ReviewError("source WIP capture path metadata is inconsistent")
            source_wip_index_metadata = _source_index_wip_metadata(
                index_snapshot=source_wip_index_snapshot,
                paths=(
                    source_wip_worktree_capture_paths | source_wip_index_capture_paths
                ),
                required_paths=source_wip_index_capture_paths,
            )
            source_wip_worktree_metadata = {
                relative: source_wip_index_metadata[relative]
                for relative in source_wip_worktree_capture_paths
                if relative in source_wip_index_metadata
            }
            source_wip_worktree_entries = _capture_source_wip_entries(
                source_root=source_root,
                paths=source_wip_worktree_capture_paths,
                regular_mode_overrides=_source_wip_regular_mode_overrides(
                    context=source_inspection,
                    metadata_by_path=source_wip_worktree_metadata,
                ),
                capture_budget=source_wip_capture_budget,
            )
            source_wip_index_entries = _capture_source_index_wip_entries(
                context=source_inspection,
                metadata_by_path={
                    relative: source_wip_index_metadata[relative]
                    for relative in source_wip_index_capture_paths
                },
                remaining_bytes=MAX_SNAPSHOT_BYTES
                - sum(len(entry[1]) for entry in source_wip_worktree_entries.values()),
                capture_budget=source_wip_capture_budget,
            )
            source_wip_entries = {
                **source_wip_index_entries,
                **source_wip_worktree_entries,
            }
            if (
                sum(len(entry[1]) for entry in source_wip_entries.values())
                > MAX_SNAPSHOT_BYTES
            ):
                raise ReviewError("source WIP exceeds the total review snapshot limit")
            if source_wip_entries.keys() != (
                source_wip_worktree_capture_paths | source_wip_index_capture_paths
            ):
                raise ReviewError("source WIP initial capture is incomplete")
            if (
                resolve_commit(
                    source_root,
                    "HEAD",
                    label="source WIP HEAD",
                    capture_budget=source_wip_capture_budget,
                )
                != head_sha
            ):
                raise ReviewError(
                    "source HEAD changed while the WIP snapshot was captured"
                )
            if (
                _source_status(
                    source_inspection,
                    capture_budget=source_wip_capture_budget,
                )
                != source_status
            ):
                raise ReviewError("source WIP changed while its content was captured")
        else:
            _require_clean_source(source_inspection)
            source_status = b""
            source_wip_paths = set()
            source_wip_worktree_capture_paths = set()
            source_wip_index_capture_paths = set()
            source_wip_entries = {}
            source_wip_index_snapshot = {}
            source_wip_capture_budget = None
        catalog = load_catalog()
        validate_authoring_catalog_scanner_contract(catalog)
        # Keep validating the deprecated option for typo detection, but every
        # catalog legacy value participates automatically.
        resolve_legacy_exemptions(
            catalog,
            synthetic_secret_exemptions,
        )
        selected_exemptions = catalog.legacy_exemptions
        authoring_values = accepted_authoring_values(catalog)
        accepted_values = authoring_values + accepted_legacy_values(
            catalog, selected_exemptions
        )
        catalog_legacy_values = accepted_legacy_values(
            catalog,
            catalog.legacy_exemptions,
        )
        catalog_legacy_value_matcher = _legacy_path_matcher(catalog_legacy_values)
        evidence_sensitive_values = _all_catalog_sensitive_values(catalog)
        (
            container,
            container_descriptor,
            container_identity,
            handoff_mask,
        ) = _new_container(source_root)
    except BaseException:
        source_inspection_stack.close()
        raise
    private_artifact_identities: dict[str, CleanupIdentity] = {}

    def capture_private_identity(
        artifact_name: str,
        identity: CleanupIdentity,
    ) -> None:
        if artifact_name in private_artifact_identities:
            raise ReviewError(
                f"helper-private artifact identity was captured twice: {artifact_name}"
            )
        private_artifact_identities[artifact_name] = identity

    ownership_transferred = False

    try:
        for artifact_name in PRIVATE_HELPER_ARTIFACT_NAMES:
            with _open_new_private_binary(
                container / artifact_name,
                parent_descriptor=container_descriptor,
            ) as empty_private_artifact:
                os.fchmod(empty_private_artifact.fileno(), 0o600)
                metadata = os.fstat(empty_private_artifact.fileno())
                identity = _cleanup_identity_evidence(metadata)
                _validate_prepared_private_metadata(
                    metadata,
                    artifact_name=artifact_name,
                    expected_identity=identity,
                    require_empty=True,
                )
                capture_private_identity(artifact_name, identity)
                empty_private_artifact.flush()
                os.fsync(empty_private_artifact.fileno())
        if set(private_artifact_identities) != set(PRIVATE_HELPER_ARTIFACT_NAMES):
            raise ReviewError("helper-private preparation identities are incomplete")
        try:
            os.fsync(container_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot persist prepared helper-private artifact entries: {error}"
            ) from error
        if preparation_cleanup_handoff is not None:
            preparation_cleanup_handoff(
                container,
                PrivateCleanupEvidence(
                    container=container_identity,
                    artifacts=private_artifact_identities,
                ),
            )
        restore_signal_mask(handoff_mask)
        handoff_mask = None
        workspace_root = container / "workspace"
        source_git_view, source_object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=container,
        )
        git_dir = _create_private_review_repository(
            container=container,
            git_view=source_git_view,
            source_object_directory=source_object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
        )
        _scan_endpoint_commit_metadata(
            git_view=git_dir,
            object_directory=git_dir / "objects",
            base_sha=base_sha,
            head_sha=head_sha,
            authoring_values=authoring_values,
            legacy_values=catalog_legacy_values,
        )
        source_view_cleanup_errors = _remove_named_directory_tree(
            container_descriptor,
            source_git_view.name,
            label="temporary sanitized source Git view",
            require_private_mode=False,
        )
        if source_view_cleanup_errors:
            raise ReviewError(
                "cannot remove temporary sanitized source Git view: "
                + "; ".join(source_view_cleanup_errors)
            )
        git_view = git_dir
        object_directory = git_dir / "objects"
        _create_detached_worktree(
            git_dir=git_dir,
            workspace_root=workspace_root,
            head_sha=head_sha,
        )
        for label, commit in (("base", base_sha), ("head", head_sha)):
            if _commit_uses_reserved_control_path(
                git_view=git_view,
                object_directory=object_directory,
                commit=commit,
                label=label,
            ):
                raise ReviewError(
                    f"the frozen {label} uses the reserved top-level .codex-review path"
                )
        _materialize_frozen_tree(
            git_view=git_view,
            object_directory=object_directory,
            head_sha=head_sha,
            workspace_root=workspace_root,
            legacy_value_matcher=catalog_legacy_value_matcher,
        )
        _run_worktree_git(workspace_root, "read-tree", "--reset", head_sha)
        if include_source_wip:
            snapshot_tree_sha = _overlay_source_wip(
                source_inspection=source_inspection,
                source_root=source_root,
                workspace_root=workspace_root,
                head_sha=head_sha,
                initial_status=source_status,
                paths=source_wip_paths,
                worktree_capture_paths=source_wip_worktree_capture_paths,
                index_capture_paths=source_wip_index_capture_paths,
                entries=source_wip_entries,
                initial_index_snapshot=source_wip_index_snapshot,
                capture_budget=source_wip_capture_budget,
            )
            content_variant = "source-wip"
        else:
            snapshot_tree_sha = (
                _run_private_git(
                    git_dir=git_dir,
                    args=("rev-parse", f"{head_sha}^{{tree}}"),
                )
                .stdout.decode("ascii")
                .strip()
            )
            content_variant = "head"
        _run_worktree_git(
            workspace_root,
            "read-tree",
            "--reset",
            snapshot_tree_sha,
        )
        (git_dir / "worktrees" / workspace_root.name / "index").chmod(0o600)
        if include_source_wip:
            _clear_materialized_workspace(workspace_root)
            _materialize_frozen_tree(
                git_view=git_view,
                object_directory=object_directory,
                head_sha=snapshot_tree_sha,
                workspace_root=workspace_root,
                legacy_value_matcher=catalog_legacy_value_matcher,
            )
        _verify_materialized_snapshot(
            git_view=git_view,
            object_directory=object_directory,
            workspace_root=workspace_root,
            snapshot_tree_sha=snapshot_tree_sha,
        )
        _replace_worktree_index_with_canonical(
            git_dir=git_dir,
            workspace_root=workspace_root,
            snapshot_tree_sha=snapshot_tree_sha,
        )
        scope_identity = _review_scope_identity(
            base_sha=base_sha,
            head_sha=head_sha,
            content_variant=content_variant,
            snapshot_tree_sha=snapshot_tree_sha,
        )
        if _commit_uses_reserved_control_path(
            git_view=git_view,
            object_directory=object_directory,
            commit=snapshot_tree_sha,
            label="snapshot",
        ):
            raise ReviewError(
                "the review snapshot uses the reserved top-level .codex-review path"
            )
        try:
            (
                synthetic_manifest,
                private_synthetic_manifest,
                secret_reductions,
            ) = _secret_count_manifests(
                git_view=git_view,
                object_directory=object_directory,
                base_sha=base_sha,
                head_sha=snapshot_tree_sha,
                source_head_sha=head_sha if include_source_wip else None,
                catalog=catalog,
                evidence_head_ref=head_sha,
            )
        except _SourceHeadSecretCountIncrease:
            raise
        except (OSError, ReviewError):
            (
                synthetic_manifest,
                private_synthetic_manifest,
                secret_reductions,
            ) = _inconclusive_secret_count_manifests(
                base_sha=base_sha,
                head_sha=snapshot_tree_sha,
                catalog=catalog,
                failure_class="exact-value-scan-incomplete",
                evidence_head_ref=head_sha,
            )
        manifest_sensitive_values = evidence_sensitive_values + secret_reductions
        _reject_protected_review_path_aliases(workspace_root)
        control_dir = workspace_root / ".codex-review"
        if control_dir.exists() or control_dir.is_symlink():
            raise ReviewError(
                "the frozen head uses the reserved top-level .codex-review path"
            )
        control_dir.mkdir(mode=0o700)
        write_text_atomic(git_dir / "info" / "exclude", "/.codex-review/\n")
        diff_file = control_dir / "review.diff"
        _write_frozen_diff(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            destination=diff_file,
        )
        _write_bounded_json(
            control_dir / SYNTHETIC_MANIFEST_NAME,
            synthetic_manifest,
            label="synthetic secret manifest",
        )
        _write_private_bounded_json(
            container / SYNTHETIC_PRIVATE_MANIFEST_NAME,
            private_synthetic_manifest,
            label="synthetic secret helper-private state",
            expected_identity=private_artifact_identities[
                SYNTHETIC_PRIVATE_MANIFEST_NAME
            ],
            parent_descriptor=container_descriptor,
        )
        changed_path_digests_file = control_dir / CHANGED_PATH_DIGESTS_NAME
        _write_frozen_changed_paths(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            destination=changed_path_digests_file,
            private_destination=container / PRIVATE_CHANGED_PATHS_NAME,
            evidence_sensitive_values=manifest_sensitive_values,
            private_expected_identity=private_artifact_identities[
                PRIVATE_CHANGED_PATHS_NAME
            ],
            private_parent_descriptor=container_descriptor,
        )
        changed_blob_findings = control_dir / "changed-blob-findings.z"
        _write_changed_blob_findings(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            destination=changed_blob_findings,
            accepted_destination=control_dir / SYNTHETIC_CHANGED_EVIDENCE_NAME,
            accepted_values=accepted_values,
            evidence_sensitive_values=manifest_sensitive_values,
            reduced_secret_values=frozenset(
                descriptor.value
                for descriptor in secret_reductions
                if descriptor.value is not None
            ),
        )
        prompt_file = control_dir / "review.prompt"
        supplemental_template = None
        if prompt_override is not None:
            supplemental_template = _read_prompt_template(
                prompt_override.expanduser().absolute()
            )
        prompt = build_review_prompt(
            workspace=workspace_root,
            diff_file=diff_file,
            base_ref=base_sha,
            head_ref=head_sha,
            content_variant=content_variant,
            snapshot_tree_sha=snapshot_tree_sha,
            scope_identity=scope_identity,
            supplemental_template=supplemental_template,
        )
        _validate_prompt_size(prompt)
        write_text_atomic(prompt_file, prompt)
        if set(private_artifact_identities) != set(PRIVATE_HELPER_ARTIFACT_NAMES):
            raise ReviewError("helper-private preparation identities are incomplete")
        private_cleanup = PrivateCleanupEvidence(
            container=container_identity,
            artifacts=private_artifact_identities,
        )
        control_artifact_state = _build_control_artifact_state(
            control_dir=control_dir,
            private_cleanup=private_cleanup,
        )
        _write_bounded_json(
            container / CONTROL_ARTIFACT_STATE_NAME,
            control_artifact_state,
            label="helper-private review control state",
            accepted_values=manifest_sensitive_values,
        )
        review = ReviewWorkspace(
            source_root=source_root,
            container_dir=container,
            workspace_root=workspace_root,
            base_ref=base_sha,
            head_ref=head_sha,
            diff_file=diff_file,
            prompt_file=prompt_file,
            private_cleanup=private_cleanup,
            git_dir=git_dir,
            content_variant=content_variant,
            snapshot_tree_sha=snapshot_tree_sha,
            scope_identity=scope_identity,
        )
        _harden_private_git_permissions(git_dir)
        validate_workspace_layout(review)
        ownership_mask = block_forwarded_signals()
        try:
            ownership_handoff(review)
            ownership_transferred = True
        finally:
            restore_signal_mask(ownership_mask)
        return review
    except BaseException as error:
        if ownership_transferred:
            raise
        cleanup_mask = block_forwarded_signals()
        cleanup_signal: signal.Signals | None = None
        cleanup_error: str | None = None
        try:
            if container_descriptor is not None:
                os.close(container_descriptor)
                container_descriptor = None
            cleanup_error = _remove_partial_container(
                container,
                expected=PrivateCleanupEvidence(
                    container=container_identity,
                    artifacts=private_artifact_identities,
                ),
            )
            if cleanup_mask is not None:
                cleanup_signal = consume_pending_forwarded_signal()
        finally:
            try:
                restore_signal_mask(cleanup_mask)
            except ForwardedSignal as forwarded:
                detail = forwarded.detail
                if detail is None and cleanup_error:
                    detail = _retained_container_detail(container, cleanup_error)
                raise ForwardedSignal(forwarded.signum, detail=detail) from error
        if cleanup_signal is not None:
            detail = (
                _retained_container_detail(container, cleanup_error)
                if cleanup_error
                else None
            )
            raise ForwardedSignal(cleanup_signal, detail=detail) from error
        if cleanup_error:
            raise ReviewError(
                _retained_container_detail(container, cleanup_error)
            ) from error
        raise
    finally:
        if container_descriptor is not None:
            os.close(container_descriptor)
        try:
            if handoff_mask is not None:
                restore_signal_mask(handoff_mask)
        finally:
            source_inspection_stack.close()


def _validated_legacy_cleanup_binding(
    review: LegacyReviewWorkspace,
) -> tuple[pathlib.Path, PrivateCleanupEvidence]:
    validate_workspace_layout(review)
    target = _bound_private_cleanup_target(review)
    if target is None:
        raise ReviewError(
            "legacy review container is not lexically bound to its source-root "
            "review directory"
        )
    # Legacy v1 state has no preparation-time identities. Capture current identities
    # only after the complete canonical layout has been validated.
    return target, _capture_private_cleanup_evidence(target, require_all=False)


def _remove_legacy_private_artifacts(
    container: pathlib.Path,
    *,
    expected: PrivateCleanupEvidence,
) -> str | None:
    def unlink_captured_artifacts(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != expected.container
        ):
            return [
                "private artifact container does not match validated cleanup identity"
            ]
        return _unlink_private_review_artifacts(
            _parent_descriptor,
            container_descriptor,
            expected=expected,
            removed=frozenset(),
            record_removal=None,
            identity_label="validated cleanup",
        )

    return _operate_on_private_review_container(
        container,
        unlink_captured_artifacts,
    )


def remove_legacy_private_review_artifacts(
    review: LegacyReviewWorkspace,
) -> str | None:
    container, current_cleanup = _validated_legacy_cleanup_binding(review)
    return _remove_legacy_private_artifacts(
        container,
        expected=current_cleanup,
    )


def cleanup_legacy_workspace(
    review: LegacyReviewWorkspace,
    *,
    keep_container: bool,
) -> str | None:
    container, current_cleanup = _validated_legacy_cleanup_binding(review)
    if not keep_container:
        return _remove_review_container_tree(
            container,
            expected=current_cleanup,
            use_control_state=False,
            identity_label="validated cleanup",
        )

    private_cleanup_error = _remove_legacy_private_artifacts(
        container,
        expected=current_cleanup,
    )
    if private_cleanup_error is not None:
        return private_cleanup_error

    def remove_workspace(
        _parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        if (
            _cleanup_identity_evidence(os.fstat(container_descriptor))
            != current_cleanup.container
        ):
            return [
                "private artifact container does not match validated cleanup identity"
            ]
        return _remove_named_directory_tree(
            container_descriptor,
            "workspace",
            label="legacy review workspace",
            require_private_mode=False,
        )

    return _operate_on_private_review_container(container, remove_workspace)


def cleanup_workspace(review: ReviewWorkspace, *, keep_container: bool) -> str | None:
    cleanup_errors: list[str] = []
    validation_error: ReviewError | None = None
    private_cleanup_target = _bound_private_cleanup_target(review)
    if private_cleanup_target is not None:
        try:
            os.lstat(private_cleanup_target)
        except FileNotFoundError:
            return None
        except OSError as error:
            validation_error = ReviewError(
                f"cannot inspect review container before cleanup: {error}"
            )
    try:
        if validation_error is None:
            validate_workspace_layout(review)
    except ReviewError as error:
        validation_error = error
    if validation_error is None and private_cleanup_target is None:
        validation_error = ReviewError(
            "review container is not lexically bound to its source-root review directory"
        )

    if private_cleanup_target is not None:
        if validation_error is not None:
            private_cleanup_error = remove_private_review_artifacts(
                private_cleanup_target,
                expected=review.private_cleanup,
            )
        elif keep_container:
            private_cleanup_error = remove_private_review_artifacts(
                private_cleanup_target,
                expected=review.private_cleanup,
            )

            def remove_workspace_and_private_git(
                _parent_descriptor: int,
                container_descriptor: int,
            ) -> list[str]:
                if (
                    _cleanup_identity_evidence(os.fstat(container_descriptor))
                    != review.private_cleanup.container
                ):
                    return [
                        "private artifact container does not match preparation identity"
                    ]
                workspace_errors = _remove_named_directory_tree(
                    container_descriptor,
                    "workspace",
                    label="review workspace",
                    require_private_mode=False,
                )
                if workspace_errors:
                    return workspace_errors
                return _remove_named_directory_tree(
                    container_descriptor,
                    "review.git",
                    label="private review Git database",
                    require_private_mode=False,
                    depth_limit=PRIVATE_REVIEW_GIT_CLEANUP_DEPTH,
                )

            if private_cleanup_error is None:
                private_cleanup_error = _operate_on_private_review_container(
                    private_cleanup_target,
                    remove_workspace_and_private_git,
                )
        else:
            private_cleanup_error = _remove_review_container_tree(
                private_cleanup_target,
                expected=review.private_cleanup,
                use_control_state=True,
            )
        if private_cleanup_error:
            cleanup_errors.append(private_cleanup_error)
    if validation_error is not None:
        if cleanup_errors:
            raise ReviewError(
                f"{validation_error}; private artifact cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from validation_error
        raise validation_error
    return "; ".join(cleanup_errors) or None


def validate_retained_cleanup_postcondition(review: ReviewWorkspace) -> str | None:
    """Prove that retained state contains no reviewer runtime trees or secrets."""

    def validate(
        parent_descriptor: int,
        container_descriptor: int,
    ) -> list[str]:
        errors: list[str] = []
        opened_identity = _cleanup_identity_evidence(os.fstat(container_descriptor))
        if opened_identity != review.private_cleanup.container:
            return ["retained review container does not match preparation identity"]
        for entry_name in ("workspace", "review.git"):
            try:
                os.stat(
                    entry_name,
                    dir_fd=container_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(
                    f"cannot verify retained cleanup entry {entry_name}: {error}"
                )
            else:
                errors.append(
                    f"retained cleanup left reviewer runtime entry {entry_name}"
                )
        try:
            current_state = load_bound_private_cleanup_state(
                review.container_dir,
                expected=review.private_cleanup,
            )
        except ReviewError as error:
            errors.append(f"cannot verify retained cleanup receipts: {error}")
        else:
            expected_removed = frozenset(PRIVATE_HELPER_ARTIFACT_NAMES)
            if current_state.private_artifacts_removed != expected_removed:
                errors.append("retained cleanup receipts are incomplete")
        try:
            path_metadata = os.stat(
                review.container_dir.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            errors.append(
                f"cannot revalidate retained review container identity: {error}"
            )
        else:
            if _cleanup_identity_evidence(path_metadata) != opened_identity:
                errors.append(
                    "retained review container changed during cleanup validation"
                )
        return errors

    return _operate_on_private_review_container(review.container_dir, validate)
