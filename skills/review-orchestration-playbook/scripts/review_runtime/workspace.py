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
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from collections import Counter, deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any, BinaryIO, Callable, Iterable, Iterator

from .common import (
    TRUSTED_PATH,
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    is_relative_to,
    resolve_git,
    restore_signal_mask,
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
# bytes, then use a 513-byte prefix branch for oversized values. Keeping every event
# end below this overlap prevents a match start from being discarded at a read boundary.
STREAM_SCAN_OVERLAP = 8192
STREAM_SCAN_CHUNK_BYTES = 1024 * 1024
AWS_SECRET_KEY_NAME_PATTERN = rb"(?i)aws_secret_access_key"
AWS_SECRET_KEY_PATTERN = re.compile(
    AWS_SECRET_KEY_NAME_PATTERN
    + rb"\s{0,256}[:=]\s{0,256}['\"]?"
    + rb"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
)
OVERSIZED_AWS_SECRET_KEY_GAP = re.compile(
    AWS_SECRET_KEY_NAME_PATTERN + rb"(?:\s{257}|\s{0,256}[:=]\s{257})"
)
OVERSIZED_JWT_PATTERN = re.compile(
    rb"\b(?:"
    rb"eyJ[A-Za-z0-9_-]{2049}"
    rb"|eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{2049}"
    rb"|eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\."
    rb"[A-Za-z0-9_-]{2049}"
    rb")"
)
SECRET_PATTERNS = (
    (
        "pgp-private-key",
        re.compile(rb"-----BEGIN PGP PRIVATE[ ]KEY BLOCK-----"),
    ),
    (
        "private-key",
        re.compile(
            rb"-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws-secret-key",
        AWS_SECRET_KEY_PATTERN,
    ),
    (
        "anthropic-key",
        re.compile(rb"\bsk-ant-(?:[A-Za-z0-9_-]{32,512}\b|[A-Za-z0-9_-]{513})"),
    ),
    (
        "openai-key",
        re.compile(rb"\bsk-(?:proj-)?(?:[A-Za-z0-9_-]{32,512}\b|[A-Za-z0-9_-]{513})"),
    ),
    (
        "github-token",
        re.compile(
            rb"\b(?:"
            rb"gh[pousr]_(?:[A-Za-z0-9]{36,512}\b|[A-Za-z0-9]{513})"
            rb"|github_pat_(?:[A-Za-z0-9_]{20,512}\b|[A-Za-z0-9_]{513})"
            rb")"
        ),
    ),
    (
        "gitlab-token",
        re.compile(rb"\bglpat-(?:[A-Za-z0-9_-]{20,512}\b|[A-Za-z0-9_-]{513})"),
    ),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm-token", re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b")),
    (
        "pypi-token",
        re.compile(rb"\bpypi-(?:[A-Za-z0-9_-]{50,512}\b|[A-Za-z0-9_-]{513})"),
    ),
    (
        "slack-token",
        re.compile(rb"\bxox[baprs]-(?:[A-Za-z0-9-]{20,512}\b|[A-Za-z0-9-]{513})"),
    ),
    (
        "stripe-live-key",
        re.compile(rb"\bsk_live_(?:[A-Za-z0-9]{16,512}\b|[A-Za-z0-9]{513})"),
    ),
    (
        "jwt",
        re.compile(
            rb"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\."
            rb"[A-Za-z0-9_-]{8,2048}\b"
        ),
    ),
)
SECRET_KEY_NAME_PATTERN = (
    rb"(?i)(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|"
    rb"bearer[_-]?token|client[_-]?secret|id[_-]?token|password|passwd|"
    rb"private[_-]?token|"
    rb"refresh[_-]?token|secret[_-]?(?:key|token))['\"]?"
)
SECRET_KEY_PATTERN = SECRET_KEY_NAME_PATTERN + rb"\s{0,256}[:=]\s{0,256}"
OVERSIZED_SECRET_ASSIGNMENT_GAP = re.compile(
    SECRET_KEY_NAME_PATTERN + rb"(?:\s{257}|\s{0,256}[:=]\s{257})"
)
QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"(['\"])([^\r\n'\"]{16,512})\1"
)
OVERSIZED_QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"(['\"])[^\r\n'\"]{513}"
)
UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"((?:" + GENERIC_SECRET_VALUE_BYTE_CLASS + rb"){16,512})",
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
MAX_LEGACY_OCCURRENCE_EVENTS = 1_000_000
MAX_LEGACY_SEARCH_BYTES = 16 * 1024 * 1024 * 1024
MAX_LEGACY_CONTAINMENT_CHECKS = 10_000_000
MAX_SECRET_ASSIGNMENT_TRAILING_BYTES = 256
MAX_SECRET_PREFIX_PROOF_BYTES = 4 * 1024 * 1024
MAX_SECRET_PREFIX_PROOF_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REVIEW_PROMPT_BYTES = 64 * 1024
MAX_SYNTHETIC_EVIDENCE_BYTES = 64 * 1024
MAX_SYNTHETIC_EVIDENCE_ENTRIES = 512
MAX_SOURCE_STATUS_BYTES = MAX_CHANGED_METADATA_BYTES
MAX_SOURCE_STATUS_RECORDS = 3 * MAX_CHANGED_ENTRIES + 4096
MAX_SOURCE_TRACKED_PATH_BYTES = MAX_CHANGED_METADATA_BYTES
MAX_SOURCE_TRACKED_PATH_RECORDS = MAX_CHANGED_ENTRIES
MAX_SOURCE_INDEX_METADATA_BYTES = MAX_TREE_METADATA_BYTES
MAX_SOURCE_INDEX_RECORDS = MAX_SNAPSHOT_ENTRIES
MAX_SOURCE_GIT_QUERY_BYTES = 64 * 1024
MAX_SOURCE_GIT_STDERR_BYTES = 64 * 1024
SOURCE_GIT_TIMEOUT_SECONDS = 120.0
MAX_PRIVATE_GIT_STDERR_BYTES = 64 * 1024
MAX_PRIVATE_FSCK_OUTPUT_BYTES = 4 * 1024 * 1024
PRIVATE_GIT_TIMEOUT_SECONDS = 300.0
REVIEW_ROOT_BASE = pathlib.Path("/tmp")
REVIEW_USER_ROOT_PREFIX = "codex-isolated-review-uid-"
REVIEW_CONTAINER_PATTERN = re.compile(r"isolated-review-[0-9]{8}-[0-9]{6}-[0-9a-f]{10}")
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
SYNTHETIC_MANIFEST_SCHEMA_VERSION = 3
CONTROL_ARTIFACT_STATE_NAME = "control-artifact-state.json"
CONTROL_ARTIFACT_SCHEMA_VERSION = 2
CONTROL_ARTIFACT_SPECS: dict[str, tuple[int, int | None]] = {
    "changed-paths.z": (MAX_CHANGED_METADATA_BYTES, MAX_CHANGED_ENTRIES),
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


def symlink_target_stays_within_workspace(
    link_relative_path: pathlib.PurePosixPath,
    target_text: str,
) -> bool:
    """Return whether a relative symlink target stays inside the frozen root."""

    target = pathlib.PurePosixPath(target_text)
    if target.is_absolute():
        return False
    depth = len(link_relative_path.parent.parts)
    for component in target.parts:
        if component == "..":
            if depth == 0:
                return False
            depth -= 1
        elif component not in {"", "."}:
            depth += 1
    return True


@dataclass(frozen=True)
class ReviewWorkspace:
    source_root: pathlib.Path
    container_dir: pathlib.Path
    workspace_root: pathlib.Path
    base_ref: str
    head_ref: str
    diff_file: pathlib.Path
    prompt_file: pathlib.Path
    git_dir: pathlib.Path | None = None
    content_variant: str = "head"
    snapshot_tree_sha: str = ""
    scope_identity: str = ""

    def to_json(self) -> dict[str, str]:
        return {
            key: str(value) for key, value in asdict(self).items() if value is not None
        }

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
    def from_json(cls, value: dict[str, str]) -> "ReviewWorkspace":
        return cls(
            source_root=pathlib.Path(value["source_root"]),
            container_dir=pathlib.Path(value["container_dir"]),
            workspace_root=pathlib.Path(value["workspace_root"]),
            base_ref=value["base_ref"],
            head_ref=value["head_ref"],
            diff_file=pathlib.Path(value["diff_file"]),
            prompt_file=pathlib.Path(value["prompt_file"]),
            git_dir=(
                pathlib.Path(value["git_dir"])
                if value.get("git_dir")
                else pathlib.Path(value["container_dir"]) / "review.git"
            ),
            content_variant=value.get("content_variant", "head"),
            snapshot_tree_sha=value.get("snapshot_tree_sha", ""),
            scope_identity=value.get("scope_identity", ""),
        )


@dataclass(frozen=True)
class ControlArtifactEvidence:
    name: str
    sha256: str
    size: int
    record_count: int | None


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


@dataclass(frozen=True)
class ControlArtifactState:
    artifacts: dict[str, ControlArtifactEvidence]
    directory: ControlDirectoryEvidence


@dataclass(frozen=True)
class LegacyCountState:
    base_count: int
    head_count: int
    source_head_count: int
    base_unembedded_count: int
    head_unembedded_count: int
    source_head_unembedded_count: int


class _IncompleteSecretScanSuffix(Exception):
    pass


_INCOMPLETE_SECRET_SCAN_SUFFIX_RULE = "__incomplete-secret-scan-suffix__"


@dataclass
class SecretScanResult:
    blocking_rule: str | None
    accepted_counts: Counter[AcceptedSyntheticValue]
    accepted_candidates: dict[AcceptedSyntheticValue, set[bytes]]
    raw_occurrence_counts: Counter[AcceptedSyntheticValue]
    unembedded_occurrence_counts: Counter[AcceptedSyntheticValue]
    incomplete_suffix_start: int | None

    @classmethod
    def empty(cls) -> "SecretScanResult":
        return cls(None, Counter(), {}, Counter(), Counter(), None)

    def merge(self, other: "SecretScanResult") -> None:
        if self.blocking_rule is None:
            self.blocking_rule = other.blocking_rule
        self.accepted_counts.update(other.accepted_counts)
        self.raw_occurrence_counts.update(other.raw_occurrence_counts)
        self.unembedded_occurrence_counts.update(other.unembedded_occurrence_counts)
        for accepted, values in other.accepted_candidates.items():
            self.accepted_candidates.setdefault(accepted, set()).update(values)


@dataclass
class SecretScanBudget:
    remaining: int
    remaining_prefix_proof_bytes: int = MAX_SECRET_PREFIX_PROOF_TOTAL_BYTES

    @classmethod
    def default(cls) -> "SecretScanBudget":
        return cls(MAX_SECRET_SCAN_EVENTS)

    def consume(self) -> None:
        if self.remaining <= 0:
            raise ReviewError(
                "external review content exceeds the sensitive scanner event limit"
            )
        self.remaining -= 1

    def consume_prefix_proof(self, byte_count: int) -> bool:
        if byte_count > MAX_SECRET_PREFIX_PROOF_BYTES:
            return False
        if byte_count > self.remaining_prefix_proof_bytes:
            raise ReviewError(
                "external review content exceeds the sensitive scanner prefix "
                "proof limit"
            )
        self.remaining_prefix_proof_bytes -= byte_count
        return True

    def clone(self) -> "SecretScanBudget":
        return SecretScanBudget(
            self.remaining,
            self.remaining_prefix_proof_bytes,
        )

    def commit_from(self, transaction: "SecretScanBudget") -> None:
        if (
            transaction.remaining > self.remaining
            or transaction.remaining_prefix_proof_bytes
            > self.remaining_prefix_proof_bytes
        ):
            raise ReviewError("sensitive scanner budget transaction is invalid")
        self.remaining = transaction.remaining
        self.remaining_prefix_proof_bytes = transaction.remaining_prefix_proof_bytes


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
    rules: frozenset[str]


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


def _source_excludes_file(repo: pathlib.Path) -> str:
    environment, default_path = _source_git_config_environment(_source_git_home())
    command = (
        str(resolve_git()),
        "--no-pager",
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
        "config",
        "--includes",
        "--null",
        "--path",
        "--get",
        "core.excludesFile",
    )
    completed = _run_bounded_git_capture(
        command,
        input_bytes=None,
        check=False,
        label="source Git excludes-file query",
        byte_limit=MAX_SOURCE_GIT_QUERY_BYTES,
        timeout_seconds=SOURCE_GIT_TIMEOUT_SECONDS,
        timeout_label="source Git",
        environment=environment,
    )
    if completed.returncode == 1:
        if completed.stdout:
            raise ReviewError(
                "source Git excludes-file query returned malformed output"
            )
        return str(default_path)
    if completed.returncode != 0:
        raise ReviewError("cannot resolve the source Git excludes file")
    if completed.stdout.count(b"\0") != 1 or not completed.stdout.endswith(b"\0"):
        raise ReviewError("source Git excludes-file query returned malformed output")
    return os.fsdecode(completed.stdout[:-1])


def _git(repo: pathlib.Path, *args: str, check: bool = True):
    command = (
        str(resolve_git()),
        "--no-pager",
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
    return _run_bounded_git_capture(
        command,
        input_bytes=None,
        check=check,
        label="source Git query",
        byte_limit=MAX_SOURCE_GIT_QUERY_BYTES,
        timeout_seconds=SOURCE_GIT_TIMEOUT_SECONDS,
        timeout_label="source Git",
    )


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
    repo: pathlib.Path,
    *args: str,
    byte_limit: int,
    record_limit: int,
    label: str,
    config_overrides: tuple[str, ...] = (),
) -> bytes:
    config_args = tuple(item for value in config_overrides for item in ("-c", value))
    command = (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.filemode=true",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        *config_args,
        "-C",
        str(repo),
        *args,
    )
    process = subprocess.Popen(
        command,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _stop_source_git_process(process)
        raise ReviewError(f"failed to create {label} pipes")
    deadline = time.monotonic() + SOURCE_GIT_TIMEOUT_SECONDS
    output_bytes = 0
    records = 0
    stderr_bytes = bytearray()
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        with tempfile.TemporaryFile() as output:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReviewError(f"{label} exceeded the source Git time limit")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
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
    (git_view / "objects").mkdir(parents=True)
    (git_view / "refs").mkdir()
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
    with tempfile.TemporaryDirectory(prefix="isolated-review-git-view-") as raw:
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
    return _run_bounded_git_capture(
        command,
        input_bytes=input_bytes,
        input_handle=input_handle,
        check=check,
        label="detached review worktree Git command",
        byte_limit=byte_limit,
        record_limit=record_limit,
    )


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
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as input_file:
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
    with tempfile.TemporaryFile() as object_ids:
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
        with tempfile.TemporaryFile() as pack_file:
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
            with tempfile.TemporaryFile() as index_output:
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
    with tempfile.TemporaryFile() as metadata:
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
        with tempfile.TemporaryFile() as content:
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
        with tempfile.TemporaryFile() as init_output:
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
    with tempfile.TemporaryFile() as output:
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


def resolve_commit(repo: pathlib.Path, ref: str, *, label: str) -> str:
    result = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
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


def _remove_partial_container(container: pathlib.Path) -> str | None:
    try:
        shutil.rmtree(container)
    except FileNotFoundError:
        return None
    except OSError as error:
        return str(error)
    return None


def _retained_container_detail(container: pathlib.Path, cleanup_error: str) -> str:
    return (
        "review workspace preparation failed and cleanup failed; evidence retained at "
        f"{container}: {cleanup_error}"
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
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        path_status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
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
    except BaseException:
        os.close(descriptor)
        raise
    return path, descriptor


def _new_container(
    source_root: pathlib.Path,
) -> tuple[pathlib.Path, set[signal.Signals] | None]:
    handoff_mask = block_forwarded_signals()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = uuid.uuid4().hex[:10]
    review_root = _review_root_for_source(source_root)
    container: pathlib.Path | None = None
    try:
        canonical_base = review_root.parents[1]
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            base_fd = os.open(canonical_base, flags)
        except OSError as error:
            raise ReviewError(
                f"cannot securely open helper review root base {canonical_base}: {error}"
            ) from error
        try:
            base_status = os.fstat(base_fd)
            base_path_status = os.lstat(canonical_base)
            if (
                not stat.S_ISDIR(base_status.st_mode)
                or base_status.st_uid != 0
                or stat.S_IMODE(base_status.st_mode) != 0o1777
                or _review_directory_identity(base_status)
                != _review_directory_identity(base_path_status)
            ):
                raise ReviewError("helper review root base changed while opening it")
            user_root, user_fd = _open_or_create_private_review_directory(
                parent_fd=base_fd,
                parent_path=canonical_base,
                name=review_root.parent.name,
            )
            try:
                source_review_root, source_fd = (
                    _open_or_create_private_review_directory(
                        parent_fd=user_fd,
                        parent_path=user_root,
                        name=review_root.name,
                    )
                )
                try:
                    name = f"isolated-review-{stamp}-{suffix}"
                    container = source_review_root / name
                    os.mkdir(name, mode=0o700, dir_fd=source_fd)
                    descriptor_status = os.stat(
                        name,
                        dir_fd=source_fd,
                        follow_symlinks=False,
                    )
                    path_status = os.lstat(container)
                    if (
                        not stat.S_ISDIR(descriptor_status.st_mode)
                        or descriptor_status.st_uid != os.geteuid()
                        or stat.S_IMODE(descriptor_status.st_mode) != 0o700
                        or _review_directory_identity(descriptor_status)
                        != _review_directory_identity(path_status)
                    ):
                        raise ReviewError(
                            "review root changed while creating the private container"
                        )
                    if _review_directory_identity(os.fstat(user_fd)) != (
                        _review_directory_identity(os.lstat(user_root))
                    ) or _review_directory_identity(os.fstat(source_fd)) != (
                        _review_directory_identity(os.lstat(source_review_root))
                    ):
                        raise ReviewError(
                            "private review namespace changed while creating the container"
                        )
                finally:
                    os.close(source_fd)
            finally:
                os.close(user_fd)
        finally:
            os.close(base_fd)
        return container, handoff_mask
    except BaseException as error:
        cleanup_error: str | None = None
        if container is not None:
            cleanup_error = _remove_partial_container(container)
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


def _legacy_path_matcher(
    legacy_values: Iterable[AcceptedSyntheticValue],
) -> LegacyPathMatcher:
    needles: dict[bytes, str] = {}
    for descriptor in legacy_values:
        if descriptor.kind != "legacy" or descriptor.value is None:
            raise ReviewError(
                "legacy path validation requires exact catalog-backed values"
            )
        for needle in (descriptor.value, base64.b64encode(descriptor.value)):
            previous = needles.get(needle)
            if previous is None or descriptor.identifier < previous:
                needles[needle] = descriptor.identifier

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
    )


def _reject_legacy_values_in_frozen_tree_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    legacy_values: Iterable[AcceptedSyntheticValue],
) -> None:
    matcher = _legacy_path_matcher(legacy_values)
    if len(matcher.transitions) == 1:
        return
    with tempfile.TemporaryFile() as output:
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
                raise ReviewError(
                    "legacy synthetic fixture values and storage encodings "
                    "are not allowed in repository paths: "
                    f"{identifier}"
                )
            _parse_tree_record(record)


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

    destination.parent.mkdir(parents=True, exist_ok=True)

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
        workspace_root.mkdir()
    with (
        tempfile.TemporaryFile() as tree_metadata,
        tempfile.TemporaryFile() as batch_input,
        tempfile.TemporaryFile() as batch_output,
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
            destination = workspace_root.joinpath(*relative.parts)
            path_display = _redact_secret_path(
                os.fspath(relative),
                "snapshot path",
            )
            try:
                if mode == "160000" and object_type == "commit":
                    resolved_parent = destination.parent.resolve(strict=False)
                    if not is_relative_to(
                        resolved_parent, workspace_root.resolve(strict=False)
                    ):
                        raise ReviewError(
                            f"frozen Git tree path escapes workspace: {path_display}"
                        )
                    destination.mkdir(parents=True, exist_ok=False)
                    destination.chmod(0o755)
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


def _open_new_private_binary(path: pathlib.Path) -> BinaryIO:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


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
                    "--submodule=diff",
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


def _write_frozen_changed_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    with _open_new_private_binary(destination) as output:
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                base_sha,
                head_sha,
            ),
            output=output,
            label="frozen changed paths",
            record_limit=MAX_CHANGED_ENTRIES,
        )


def _write_bounded_json(
    path: pathlib.Path,
    value: dict[str, Any],
    *,
    label: str,
    accepted_values: Iterable[AcceptedSyntheticValue] = (),
) -> None:
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
    if len(encoded.encode("utf-8")) > MAX_SYNTHETIC_EVIDENCE_BYTES:
        raise ReviewError(f"{label} exceeds the audit evidence size limit")
    _reject_raw_values_in_evidence(
        value,
        accepted_values=accepted_values,
        label=label,
    )
    write_text_atomic(path, encoded)


def _iter_evidence_strings(value: Any) -> Iterator[bytes]:
    if isinstance(value, str):
        yield value.encode("utf-8")
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
    encoded_legacy_values: list[bytes] = []
    digest_values: dict[int, set[str]] = {}
    for accepted in accepted_values:
        if accepted.value is not None:
            exact_values.append(accepted.value)
            if accepted.kind == "legacy":
                encoded_legacy_values.append(base64.b64encode(accepted.value))
            continue
        digest_values.setdefault(accepted.value_length, set()).add(
            accepted.value_sha256
        )
    for metadata in set(_iter_evidence_strings(value)):
        if any(raw_value in metadata for raw_value in exact_values):
            raise ReviewError(f"{label} would expose a raw synthetic value")
        if any(encoded_value in metadata for encoded_value in encoded_legacy_values):
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
    accepted_index: AcceptedValueIndex | None = None,
    event_budget: SecretScanBudget | None = None,
    exact_index: ExactValueIndex | None = None,
    occurrence_budget: LegacyOccurrenceBudget | None = None,
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
        _accepted_index=accepted_index,
        _event_budget=event_budget,
        _exact_index=exact_index,
        _occurrence_budget=occurrence_budget,
        _continue_after_blocking=_continue_after_blocking,
    )
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after scanned git cat-file blob")
    return scan, scanned_bytes + size


def _scan_frozen_tree_values(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    accepted_values: Iterable[AcceptedSyntheticValue],
    raw_occurrence_values: Iterable[AcceptedSyntheticValue] = (),
    capture_accepted_candidates: bool = False,
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
        tempfile.TemporaryFile() as tree_metadata,
        tempfile.TemporaryFile() as batch_input,
        tempfile.TemporaryFile() as batch_output,
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
                accepted_index=accepted_index,
                event_budget=event_budget,
                exact_index=exact_index,
                occurrence_budget=occurrence_budget,
                _continue_after_blocking=_continue_after_blocking,
            )
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
        tempfile.TemporaryFile() as changed_paths,
        tempfile.TemporaryFile() as raw_output,
        tempfile.TemporaryFile() as batch_input,
        tempfile.TemporaryFile() as batch_output,
    ):
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                source_head_sha,
                snapshot_tree_sha,
            ),
            output=changed_paths,
            label="source HEAD to WIP snapshot changed paths",
            record_limit=MAX_CHANGED_ENTRIES,
        )
        changed_paths.seek(0)
        for raw_path in _iter_nul_records(
            changed_paths,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES,
            label="source HEAD to WIP snapshot changed paths",
        ):
            path_callback(raw_path)

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
        for side, object_id, _raw_path in _iter_changed_blob_sides(raw_output):
            if side != "base":
                continue
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
) -> None:
    accepted = tuple(accepted_values)
    accepted_index = _index_accepted_values(accepted)
    event_budget = SecretScanBudget.default()
    accepted_evidence: Counter[tuple[AcceptedSyntheticValue, str, str]] = Counter()
    with (
        tempfile.TemporaryFile() as raw_output,
        tempfile.TemporaryFile() as batch_input,
        tempfile.TemporaryFile() as batch_output,
        _open_new_private_binary(destination) as findings_output,
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
            label="changed blob metadata",
            record_limit=MAX_CHANGED_ENTRIES * 2,
        )
        blob_count = 0
        for _side, object_id, _raw_path in _iter_changed_blob_sides(raw_output):
            batch_input.write(object_id.encode("ascii") + b"\n")
            blob_count += 1
        if blob_count:
            batch_input.seek(0)
            _run_bounded_process_to_file(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                environment=_git_environment(object_directory=object_directory),
                input_handle=batch_input,
                destination=batch_output,
                label="changed Git blob batch",
                byte_limit=MAX_CHANGED_BLOB_SCAN_BYTES + MAX_CHANGED_METADATA_BYTES,
            )
        batch_output.seek(0)
        scanned_bytes = 0
        for side, object_id, raw_path in _iter_changed_blob_sides(raw_output):
            scan, scanned_bytes = _scan_batch_blob(
                cat_input=None,
                cat_output=batch_output,
                object_id=object_id,
                scanned_bytes=scanned_bytes,
                accepted_values=accepted,
                accepted_index=accepted_index,
                event_budget=event_budget,
            )
            if scan.blocking_rule:
                findings_output.write(
                    side.encode("ascii")
                    + b"\0"
                    + raw_path
                    + b"\0"
                    + scan.blocking_rule.encode("ascii")
                    + b"\0"
                )
            path_sha256 = hashlib.sha256(raw_path).hexdigest()
            for accepted_value, count in scan.accepted_counts.items():
                _record_bounded_evidence_count(
                    accepted_evidence,
                    (accepted_value, side, path_sha256),
                    count,
                    reserved_entries=0,
                    overflow_message=(
                        "synthetic changed-blob evidence has too many entries"
                    ),
                )
        if batch_output.read(1):
            raise ReviewError(
                "changed Git blob batch output contains unexpected trailing data"
            )
    _write_bounded_json(
        accepted_destination,
        {
            "entries": [
                _accepted_evidence_entry(
                    accepted_value,
                    surface="changed-blob",
                    side=side,
                    path_sha256=path_sha256,
                    occurrence_count=count,
                )
                for (accepted_value, side, path_sha256), count in sorted(
                    accepted_evidence.items(),
                    key=lambda item: (
                        item[0][1],
                        item[0][2],
                        item[0][0].identifier,
                    ),
                )
            ],
            "schema_version": 1,
        },
        label="synthetic changed-blob evidence",
        accepted_values=evidence_sensitive_values,
    )


def validate_workspace_layout(review: ReviewWorkspace) -> None:
    source_root = review.source_root.resolve(strict=False)
    container_dir = review.container_dir.resolve(strict=False)
    expected_parent = _review_root_for_source(source_root, require_source=False)
    if (
        container_dir.parent != expected_parent
        or REVIEW_CONTAINER_PATTERN.fullmatch(container_dir.name) is None
    ):
        raise ReviewError(
            f"review container is outside the helper-private review root: {container_dir}"
        )
    expected_workspace = container_dir / "workspace"
    if review.workspace_root.resolve(strict=False) != expected_workspace:
        raise ReviewError(
            f"review workspace escapes its container: {review.workspace_root}"
        )
    control_dir = expected_workspace / ".codex-review"
    if review.diff_file.resolve(strict=False) != control_dir / "review.diff":
        raise ReviewError(
            f"review diff escapes its control directory: {review.diff_file}"
        )
    if review.prompt_file.resolve(strict=False) != control_dir / "review.prompt":
        raise ReviewError(
            f"review prompt escapes its control directory: {review.prompt_file}"
        )
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
    with tempfile.TemporaryDirectory() as temporary:
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
    with tempfile.TemporaryFile() as output:
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
    with tempfile.TemporaryFile() as output:
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
    with tempfile.TemporaryFile() as fsck_output:
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
        if initial.st_uid != os.getuid():
            raise ReviewError(f"{label} must be owned by the current user")
        if initial.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(f"{label} must not be group or other writable")
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
    max_bytes: int = MAX_SYNTHETIC_EVIDENCE_BYTES,
) -> dict[str, Any]:
    chunks: list[bytes] = []
    with _secure_file_reader(
        path,
        label=label,
        max_bytes=max_bytes,
        expected_artifact=expected_artifact,
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
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
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
) -> dict[str, Any]:
    directory = _inspect_control_directory(control_dir)
    entries: list[dict[str, Any]] = []
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
        entries.append(
            {
                "name": name,
                "record_count": record_count,
                "sha256": artifact_sha256,
                "size": metadata.st_size,
            }
        )
    _inspect_control_directory(control_dir, expected=directory)
    return {
        "artifacts": entries,
        "directory": {
            "ctime_ns": directory.ctime_ns,
            "device": directory.device,
            "entry_count": directory.entry_count,
            "entry_names_sha256": directory.entry_names_sha256,
            "inode": directory.inode,
            "link_count": directory.link_count,
            "mode": directory.mode,
            "mtime_ns": directory.mtime_ns,
            "uid": directory.uid,
        },
        "schema_version": CONTROL_ARTIFACT_SCHEMA_VERSION,
    }


def _load_control_artifact_state(
    *,
    container_dir: pathlib.Path,
) -> ControlArtifactState:
    payload = _read_bounded_json(
        container_dir / CONTROL_ARTIFACT_STATE_NAME,
        label="helper-private review control state",
    )
    if (
        set(payload) != {"artifacts", "directory", "schema_version"}
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
    return ControlArtifactState(artifacts=artifacts, directory=directory)


def _load_legacy_manifest(
    *,
    control_dir: pathlib.Path,
    container_dir: pathlib.Path,
    catalog: SyntheticTokenCatalog,
    expected_artifact: ControlArtifactEvidence,
) -> tuple[
    tuple[LegacyExemption, ...],
    tuple[AcceptedSyntheticValue, ...],
    dict[AcceptedSyntheticValue, LegacyCountState],
    list[dict[str, Any]],
]:
    manifest_path = control_dir / SYNTHETIC_MANIFEST_NAME
    private_manifest_path = container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME
    if not manifest_path.exists() and not private_manifest_path.exists():
        return (), (), {}, []
    if not manifest_path.exists() or not private_manifest_path.exists():
        raise ReviewError("synthetic secret helper-private state is missing")
    workspace_manifest = _read_bounded_json(
        manifest_path,
        label="synthetic secret manifest",
        expected_artifact=expected_artifact,
    )
    manifest = _read_bounded_json(
        private_manifest_path,
        label="synthetic secret helper-private state",
    )
    if workspace_manifest != manifest:
        raise ReviewError(
            "synthetic secret manifest does not match helper-private state"
        )
    if set(manifest) != {
        "catalog_schema_version",
        "entries",
        "pool_version",
        "schema_version",
        "selected_exemptions",
    }:
        raise ReviewError("synthetic secret manifest fields are invalid")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != SYNTHETIC_MANIFEST_SCHEMA_VERSION
        or type(manifest["catalog_schema_version"]) is not int
        or manifest["catalog_schema_version"] != catalog.schema_version
        or manifest["pool_version"] != catalog.pool_version
    ):
        raise ReviewError("synthetic secret manifest catalog version is invalid")
    selected_ids = manifest["selected_exemptions"]
    if not isinstance(selected_ids, list) or not all(
        isinstance(item, str) for item in selected_ids
    ):
        raise ReviewError("synthetic secret manifest selection is invalid")
    exemptions = resolve_legacy_exemptions(catalog, selected_ids)
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
            or head_count > base_count
            or source_head_count > base_count
            or head_unembedded_count > base_unembedded_count
            or source_head_unembedded_count > base_unembedded_count
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
    if set(counts) != set(accepted):
        raise ReviewError("synthetic secret manifest does not cover its selection")
    for exemption in exemptions:
        if not any(
            count_state.base_count
            or count_state.head_count
            or count_state.source_head_count
            for descriptor, count_state in counts.items()
            if descriptor.exemption_id == exemption.identifier
        ):
            raise ReviewError(
                f"selected synthetic secret exemption is unused: {exemption.identifier}"
            )
    return exemptions, accepted, counts, evidence


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


def validate_external_workspace(review: ReviewWorkspace) -> dict[str, Any]:
    validate_workspace_layout(review)
    worktree_admin = _validate_worktree_git_control(review)
    workspace_root = review.workspace_root.resolve(strict=True)
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
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    catalog_legacy_values = accepted_legacy_values(catalog, catalog.legacy_exemptions)
    catalog_legacy_path_matcher = _legacy_path_matcher(catalog_legacy_values)
    control_state = _load_control_artifact_state(
        container_dir=review.container_dir,
    )
    _inspect_control_directory(control_dir, expected=control_state.directory)
    control_artifacts = control_state.artifacts
    _exemptions, legacy_values, legacy_counts, legacy_evidence = _load_legacy_manifest(
        control_dir=control_dir,
        container_dir=review.container_dir,
        catalog=catalog,
        expected_artifact=control_artifacts[SYNTHETIC_MANIFEST_NAME],
    )
    authoring_values = accepted_authoring_values(catalog)
    accepted_values = authoring_values + legacy_values
    if review.content_variant == "head" and any(
        count_state.source_head_count != count_state.head_count
        or count_state.source_head_unembedded_count != count_state.head_unembedded_count
        for count_state in legacy_counts.values()
    ):
        raise ReviewError("synthetic secret manifest head counts are inconsistent")
    _scan_endpoint_commit_metadata(
        git_view=git_dir,
        object_directory=git_dir / "objects",
        base_sha=review.base_ref,
        head_sha=review.head_ref,
        authoring_values=authoring_values,
        legacy_values=catalog_legacy_values,
    )
    evidence_sensitive_values = _all_catalog_sensitive_values(catalog)
    changed_accepted_evidence = _load_changed_synthetic_evidence(
        control_dir=control_dir,
        accepted_values=accepted_values,
        required=(control_dir / SYNTHETIC_MANIFEST_NAME).exists(),
        expected_artifact=control_artifacts[SYNTHETIC_CHANGED_EVIDENCE_NAME],
    )
    accepted_index = _index_accepted_values(accepted_values)
    authoring_index = _index_accepted_values(authoring_values)
    legacy_exact_index = _index_exact_values(legacy_values)
    event_budget = SecretScanBudget.default()
    occurrence_budget = LegacyOccurrenceBudget.default()
    snapshot_byte_budget = FileScanByteBudget.snapshot()

    sensitive_findings: list[str] = []
    sensitive_finding_count = 0
    accepted_evidence_counts: Counter[tuple[AcceptedSyntheticValue, str, str, str]] = (
        Counter()
    )
    frozen_head_legacy_counts: Counter[AcceptedSyntheticValue] = Counter()
    frozen_head_legacy_unembedded_counts: Counter[AcceptedSyntheticValue] = Counter()

    def record_finding(value: str) -> None:
        nonlocal sensitive_finding_count
        sensitive_finding_count += 1
        if len(sensitive_findings) < 10:
            sensitive_findings.append(value)

    def record_scan(
        scan: SecretScanResult,
        *,
        surface: str,
        side: str,
        path_bytes: bytes,
        finding_label: str,
        diagnostic_surface: str | None = None,
    ) -> None:
        if scan.blocking_rule:
            suffix = f"; {diagnostic_surface}" if diagnostic_surface is not None else ""
            record_finding(f"{finding_label} ({scan.blocking_rule}{suffix})")
        path_sha256 = hashlib.sha256(path_bytes).hexdigest()
        for accepted, count in scan.accepted_counts.items():
            _record_bounded_evidence_count(
                accepted_evidence_counts,
                (accepted, surface, side, path_sha256),
                count,
                reserved_entries=len(changed_accepted_evidence),
                overflow_message=(
                    "accepted synthetic-token evidence has too many entries"
                ),
            )

    if review.content_variant == "source-wip":
        if legacy_counts:
            source_head_scan = _scan_frozen_tree_values(
                git_view=git_dir,
                object_directory=git_dir / "objects",
                commit=review.head_ref,
                accepted_values=legacy_values,
                raw_occurrence_values=legacy_values,
            )
            for accepted, count_state in legacy_counts.items():
                actual_source_head_count = source_head_scan.raw_occurrence_counts[
                    accepted
                ]
                if actual_source_head_count != count_state.source_head_count:
                    raise ReviewError(
                        "source HEAD legacy synthetic fixture count changed after "
                        f"preparation for {accepted.identifier}: "
                        f"expected={count_state.source_head_count}, "
                        f"actual={actual_source_head_count}"
                    )
                actual_source_head_unembedded_count = (
                    source_head_scan.unembedded_occurrence_counts[accepted]
                )
                if (
                    actual_source_head_unembedded_count
                    != count_state.source_head_unembedded_count
                ):
                    raise ReviewError(
                        "source HEAD legacy synthetic fixture unembedded count changed "
                        f"after preparation for {accepted.identifier}: "
                        f"expected={count_state.source_head_unembedded_count}, "
                        f"actual={actual_source_head_unembedded_count}"
                    )

        def record_source_head_path(raw_path: bytes) -> None:
            legacy_path_token_id = catalog_legacy_path_matcher.match(raw_path)
            if legacy_path_token_id is not None:
                record_finding(
                    "<redacted source HEAD path> "
                    "(legacy-synthetic-value; source-head-path)"
                )
                return
            path_secret_rule = _value_secret_rule(
                raw_path,
                event_budget=event_budget,
            )
            if path_secret_rule:
                record_finding(
                    "<redacted source HEAD path> "
                    f"({path_secret_rule}; source-head-path)"
                )
                return
            path = os.fsdecode(raw_path)
            if path_rule := _sensitive_path_rule(path):
                path_display = _redact_secret_path(path, "source HEAD path")
                record_finding(f"{path_display} ({path_rule}; source-head-path)")

        def record_source_head_blob(
            raw_path: bytes,
            scan: SecretScanResult,
        ) -> None:
            path_display = (
                "<redacted source HEAD blob path>"
                if catalog_legacy_path_matcher.match(raw_path) is not None
                else _redact_secret_path(
                    os.fsdecode(raw_path),
                    "source HEAD blob path",
                )
            )
            record_scan(
                scan,
                surface="source-head-blob",
                side="head",
                path_bytes=raw_path,
                finding_label=path_display,
                diagnostic_surface="source-head-blob",
            )

        _scan_source_head_wip_delta(
            git_view=git_dir,
            object_directory=git_dir / "objects",
            source_head_sha=review.head_ref,
            snapshot_tree_sha=review.snapshot_tree_sha,
            accepted_values=accepted_values,
            raw_occurrence_values=legacy_values,
            accepted_index=accepted_index,
            event_budget=event_budget,
            exact_index=legacy_exact_index,
            occurrence_budget=occurrence_budget,
            path_callback=record_source_head_path,
            blob_callback=record_source_head_blob,
        )

    changed_paths_file = review.workspace_root / ".codex-review/changed-paths.z"
    changed_path_count = 0
    changed_path_artifact = control_artifacts["changed-paths.z"]
    with _secure_file_reader(
        changed_paths_file,
        label="external review changed paths",
        max_bytes=MAX_CHANGED_METADATA_BYTES,
        expected_artifact=changed_path_artifact,
    ) as (handle, _metadata):
        for raw_path in _iter_nul_records(
            handle,
            byte_limit=MAX_CHANGED_METADATA_BYTES,
            record_limit=MAX_CHANGED_ENTRIES,
            label="external review changed paths",
        ):
            changed_path_count += 1
            legacy_path_token_id = catalog_legacy_path_matcher.match(raw_path)
            if legacy_path_token_id is not None:
                record_finding(
                    "<redacted changed path> "
                    "(legacy-synthetic-value; changed-path-name)"
                )
                continue
            path_secret_rule = _value_secret_rule(
                raw_path,
                event_budget=event_budget,
            )
            if path_secret_rule:
                record_finding(
                    f"<redacted changed path> ({path_secret_rule}; changed-path-name)"
                )
                continue
            changed_path = os.fsdecode(raw_path)
            path_rule = _sensitive_path_rule(changed_path)
            if path_rule:
                path_display = _redact_secret_path(changed_path, "changed path")
                record_finding(f"{path_display} ({path_rule}; changed-path)")
    if changed_path_count != changed_path_artifact.record_count:
        raise ReviewError(
            "external review changed paths do not match helper-private record state"
        )
    changed_blob_findings = (
        review.workspace_root / ".codex-review/changed-blob-findings.z"
    )
    changed_blob_record_count = 0
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
                raw_path = next(records)
                raw_rule = next(records)
                side = raw_side.decode("ascii")
                rule = raw_rule.decode("ascii")
            except (StopIteration, UnicodeDecodeError) as error:
                raise ReviewError(
                    "external review changed-blob findings are malformed"
                ) from error
            changed_blob_record_count += 3
            legacy_path_token_id = catalog_legacy_path_matcher.match(raw_path)
            path_display = (
                "<redacted changed blob path>"
                if legacy_path_token_id is not None
                else _redact_secret_path(
                    os.fsdecode(raw_path),
                    "changed blob path",
                )
            )
            record_finding(f"{path_display} ({rule}; {side}-blob)")
    if changed_blob_record_count != changed_blob_artifact.record_count:
        raise ReviewError(
            "external review changed-blob findings do not match "
            "helper-private record state"
        )
    snapshot_entries = 0
    for candidate in review.workspace_root.rglob("*"):
        relative_path = candidate.relative_to(review.workspace_root)
        if relative_path.parts == (".git",):
            continue
        if relative_path.parts and relative_path.parts[0] == ".codex-review":
            continue
        snapshot_entries += 1
        if snapshot_entries > MAX_SNAPSHOT_ENTRIES:
            raise ReviewError("frozen workspace exceeds the review entry-count limit")
        relative = relative_path.as_posix()
        raw_relative = os.fsencode(relative)
        legacy_path_token_id = catalog_legacy_path_matcher.match(raw_relative)
        if legacy_path_token_id is not None:
            record_finding(
                "<redacted snapshot path> (legacy-synthetic-value; path-name)"
            )
        path_secret_rule = _value_secret_rule(
            raw_relative,
            event_budget=event_budget,
        )
        if path_secret_rule:
            record_finding(f"<redacted snapshot path> ({path_secret_rule}; path-name)")
        path_display = (
            "<redacted snapshot path>"
            if legacy_path_token_id is not None
            else _redact_secret_path(relative, "snapshot path")
        )
        path_rule = _sensitive_path_rule(relative)
        if path_rule:
            record_finding(f"{path_display} ({path_rule})")
        if candidate.is_symlink():
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
                raw_resolved_target = os.fsencode(os.fspath(resolved_target))
                target_display = (
                    "<redacted symlink target>"
                    if catalog_legacy_path_matcher.match(raw_target) is not None
                    or catalog_legacy_path_matcher.match(raw_resolved_target)
                    is not None
                    else _redact_secret_path(
                        os.fspath(resolved_target),
                        "symlink target",
                    )
                )
                raise ReviewError(
                    "external review symlink escapes the frozen workspace: "
                    f"{path_display} -> {target_display}"
                )
            snapshot_byte_budget.consume(len(raw_target))
            target_scan = _scan_secret_value(
                raw_target,
                accepted_values=accepted_values,
                raw_occurrence_values=legacy_values,
                _accepted_index=accepted_index,
                _event_budget=event_budget,
                _exact_index=legacy_exact_index,
                _occurrence_budget=occurrence_budget,
            )
            record_scan(
                target_scan,
                surface="symlink-target",
                side="head",
                path_bytes=raw_relative,
                finding_label=f"{path_display} -> <redacted symlink target>",
                diagnostic_surface="symlink-target",
            )
            frozen_head_legacy_counts.update(target_scan.raw_occurrence_counts)
            frozen_head_legacy_unembedded_counts.update(
                target_scan.unembedded_occurrence_counts
            )
            continue
        if candidate.is_dir():
            continue
        scan = _file_secret_scan(
            candidate,
            accepted_values=accepted_values,
            raw_occurrence_values=legacy_values,
            accepted_index=accepted_index,
            event_budget=event_budget,
            exact_index=legacy_exact_index,
            occurrence_budget=occurrence_budget,
            max_bytes=MAX_SNAPSHOT_BLOB_BYTES,
            byte_budget=snapshot_byte_budget,
            diagnostic_path=path_display,
        )
        record_scan(
            scan,
            surface="frozen-head",
            side="head",
            path_bytes=raw_relative,
            finding_label=path_display,
        )
        frozen_head_legacy_counts.update(scan.raw_occurrence_counts)
        frozen_head_legacy_unembedded_counts.update(scan.unembedded_occurrence_counts)

    for accepted, count_state in legacy_counts.items():
        actual_head_count = frozen_head_legacy_counts[accepted]
        if actual_head_count != count_state.head_count:
            raise ReviewError(
                "frozen head legacy synthetic fixture count changed after preparation "
                f"for {accepted.identifier}: expected={count_state.head_count}, "
                f"actual={actual_head_count}"
            )
        actual_head_unembedded_count = frozen_head_legacy_unembedded_counts[accepted]
        if actual_head_unembedded_count != count_state.head_unembedded_count:
            raise ReviewError(
                "frozen head legacy synthetic fixture unembedded count changed "
                f"after preparation for {accepted.identifier}: "
                f"expected={count_state.head_unembedded_count}, "
                f"actual={actual_head_unembedded_count}"
            )

    primary_diff_artifact = control_artifacts["review.diff"]
    diff_scan = _file_secret_scan(
        review.diff_file,
        accepted_values=accepted_values,
        diff_surface=True,
        accepted_index=accepted_index,
        event_budget=event_budget,
        max_bytes=MAX_DIFF_BYTES,
        expected_artifact=primary_diff_artifact,
    )
    record_scan(
        diff_scan,
        surface="frozen-diff",
        side="range",
        path_bytes=b".codex-review/review.diff",
        finding_label="review.diff",
    )
    prompt_scan = _file_secret_scan(
        review.prompt_file,
        accepted_values=authoring_values,
        accepted_index=authoring_index,
        event_budget=event_budget,
        max_bytes=MAX_REVIEW_PROMPT_BYTES,
        expected_artifact=control_artifacts["review.prompt"],
    )
    record_scan(
        prompt_scan,
        surface="review-prompt",
        side="generated",
        path_bytes=b".codex-review/review.prompt",
        finding_label="review.prompt",
    )
    if sensitive_finding_count:
        summary = ", ".join(sensitive_findings)
        if sensitive_finding_count > len(sensitive_findings):
            summary += f", and {sensitive_finding_count - len(sensitive_findings)} more"
        raise ReviewError(
            "sensitive content preflight blocked external review; remove or narrow "
            f"these paths before egress: {summary}"
        )

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
        "synthetic_tokens": {
            "accepted": accepted_evidence,
            "catalog_schema_version": catalog.schema_version,
            "legacy_counts": legacy_evidence,
            "pool_version": catalog.pool_version,
        },
    }
    _encode_synthetic_evidence_json(evidence)
    complete_preflight_evidence = {
        "content_variant": review.content_variant,
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "scope": (
            "digest-bound source WIP snapshot, diff, and review prompt"
            if review.content_variant == "source-wip"
            else "detached clean head worktree, diff, and review prompt"
        ),
        "scope_identity": review.scope_identity,
        "snapshot_tree_sha": review.snapshot_tree_sha,
        "status": "sensitive-content and escaping-symlink checks passed",
    }
    complete_preflight_evidence.update(evidence)
    encode_preflight_json(complete_preflight_evidence)
    _reject_raw_values_in_evidence(
        complete_preflight_evidence,
        accepted_values=evidence_sensitive_values,
        label="synthetic-token preflight evidence",
    )
    _inspect_control_directory(control_dir, expected=control_state.directory)
    return evidence


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
    diff_surface: bool = False,
    accepted_index: AcceptedValueIndex | None = None,
    event_budget: SecretScanBudget | None = None,
    exact_index: ExactValueIndex | None = None,
    occurrence_budget: LegacyOccurrenceBudget | None = None,
    max_bytes: int | None = None,
    byte_budget: FileScanByteBudget | None = None,
    expected_artifact: ControlArtifactEvidence | None = None,
    diagnostic_path: str | None = None,
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
            diff_surface=diff_surface,
            _accepted_index=accepted_index,
            _event_budget=event_budget,
            _exact_index=exact_index,
            _occurrence_budget=occurrence_budget,
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


def _quoted_assignment_may_accept(
    value: bytes,
    match: re.Match[bytes],
    *,
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    event_budget: SecretScanBudget,
) -> bool:
    cursor = match.end()
    inspected = 0
    crossed_line_boundary = False
    skipped_diff_bytes = 0
    match_line_start = (
        max(
            value.rfind(b"\n", 0, match.start()),
            value.rfind(b"\r", 0, match.start()),
        )
        + 1
    )

    def triple_prefix_is_hunk_content() -> bool:
        hunk_context, lower_bound = _bounded_diff_hunk_context_before(
            value,
            match_line_start,
            prefix_context_complete=prefix_context_complete,
        )
        if not event_budget.consume_prefix_proof(match_line_start - lower_bound):
            return False
        return hunk_context is not None

    match_diff_side: int | None = None
    if (
        diff_surface
        and match_line_start < len(value)
        and value[match_line_start] in (0x2B, 0x2D)
    ):
        if (
            value.startswith(
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
        if (
            b"\n" in value[cursor : cursor + count]
            or b"\r" in value[cursor : cursor + count]
        ):
            crossed_line_boundary = True
        inspected += count
        cursor += count
        return True

    def trim_space() -> bool:
        while cursor < len(value) and value[cursor] in (0x20, 0x09):
            if not advance(1):
                return False
        return True

    def trim_continuation_trivia() -> bool:
        while cursor < len(value):
            if not trim_space():
                return False
            if value.startswith(b"\r\n", cursor):
                if not advance(2):
                    return False
            elif value.startswith((b"\r", b"\n"), cursor):
                if not advance(1):
                    return False
            elif value.startswith(b"#", cursor):
                if not advance(1):
                    return False
                while cursor < len(value) and value[cursor] not in (0x0A, 0x0D):
                    if not advance(1):
                        return False
            elif value.startswith(b"/*", cursor):
                if not advance(2):
                    return False
                while cursor < len(value) and not value.startswith(b"*/", cursor):
                    if not advance(1):
                        return False
                if cursor < len(value) and not advance(2):
                    return False
            else:
                return True
        return True

    def starts_trivia() -> bool:
        return value.startswith((b"\r", b"\n", b"#", b"/*"), cursor)

    def starts_literal() -> bool:
        return _starts_quoted_literal(value[cursor : cursor + 16])

    def skip_opposite_diff_records() -> tuple[bool, bool]:
        nonlocal crossed_line_boundary, cursor, skipped_diff_bytes
        skipped = False
        while (
            match_diff_side is not None
            and cursor < len(value)
            and cursor > 0
            and value[cursor - 1] == 0x0A
            and value[cursor] in (0x2B, 0x2D)
            and value[cursor] != match_diff_side
        ):
            line_end = value.find(b"\n", cursor)
            record_end = len(value) if line_end < 0 else line_end + 1
            record_size = record_end - cursor
            if skipped_diff_bytes + record_size > MAX_SECRET_PREFIX_PROOF_BYTES:
                return False, skipped
            if not event_budget.consume_prefix_proof(record_size):
                return False, skipped
            if record_end == len(value) and not suffix_context_complete:
                raise _IncompleteSecretScanSuffix
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
            and cursor < len(value)
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
            and value.startswith(marker, cursor)
            for marker in markers
        )

    def source_literal_quote() -> int | None:
        start = match.start()
        lookbehind_start = max(0, start - MAX_SECRET_ASSIGNMENT_TRAILING_BYTES)
        last_line_break = max(
            value.rfind(b"\n", lookbehind_start, start),
            value.rfind(b"\r", lookbehind_start, start),
        )
        line_start = max(lookbehind_start, last_line_break + 1)
        prefix_was_truncated = lookbehind_start > 0 and last_line_break < 0
        prefix = value[line_start:start]
        lowered = prefix.lower()
        for marker in (
            b"br'",
            b"rb'",
            b"fr'",
            b"rf'",
            b'br"',
            b'rb"',
            b'fr"',
            b'rf"',
            b"b'",
            b"f'",
            b"r'",
            b"u'",
            b'b"',
            b'f"',
            b'r"',
            b'u"',
            b"'",
            b'"',
        ):
            marker_index = lowered.rfind(marker)
            if marker_index < 0:
                continue
            if len(marker) == 1 and marker_index == 0 and prefix_was_truncated:
                continue
            if marker_index > 0 and (
                lowered[marker_index - 1 : marker_index].isalnum()
                or lowered[marker_index - 1] == 0x5F
            ):
                continue
            quote = marker[-1]
            content_prefix = prefix[marker_index + len(marker) :]
            if bytes((quote,)) in content_prefix or b"\\" in content_prefix:
                continue
            return quote
        return None

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
        if index + 1 < len(value) and value[index + 1] in (0x3A, 0x3D, 0x3E):
            return False
        return True

    def starts_python_call_statement() -> bool:
        limit = min(
            len(value),
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
            len(value),
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
                or not value.startswith(keyword, position)
                or value[end] not in (0x20, 0x09)
            ):
                return None
            return skip_horizontal_space(end)

        async_end = consume_keyword(index, b"async")
        if async_end is not None:
            index = async_end
        declaration = b"def" if value.startswith(b"def", index) else b"class"
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

    def diff_source_prefix() -> bytes | None:
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
        raw_prefix = value[hunk_start:cursor]
        source_proof_bytes = len(raw_prefix) - skipped_diff_bytes
        if source_proof_bytes < 0 or not event_budget.consume_prefix_proof(
            source_proof_bytes
        ):
            return None
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

    def python_prefix_is_complete() -> bool:
        if diff_surface:
            prefix = diff_source_prefix()
            if prefix is None:
                return False
        else:
            if not prefix_context_complete:
                return False
            prefix = value[:cursor]
            if not event_budget.consume_prefix_proof(len(prefix)):
                return False
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
    source_literal_wrapper = False
    outer_quote = source_literal_quote()
    if outer_quote is not None:
        if cursor < len(value) and value[cursor] == outer_quote:
            if not advance(1) or not trim_space():
                return False
            source_literal_wrapper = True
    crossed_boundary = False

    def starts_proven_python_declaration() -> bool:
        return starts_top_level_python_declaration() and python_prefix_is_complete()

    def at_proven_end() -> bool:
        if cursor != len(value):
            return False
        if diff_surface and crossed_line_boundary and not suffix_context_complete:
            raise _IncompleteSecretScanSuffix
        return True

    while True:
        while value.startswith((b")", b"]", b"}"), cursor):
            if not advance(1):
                return False
            if not trim_space():
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
    if value.startswith(b";", cursor):
        if not advance(1) or not trim_space():
            return False
        if starts_trivia():
            if not trim_continuation_trivia():
                return False
        return (
            at_proven_end()
            or starts_diff_metadata_boundary()
            or starts_named_assignment()
            or starts_proven_python_declaration()
        )
    if value.startswith(b",", cursor):
        if not advance(1) or not trim_space():
            return False
        while True:
            while value.startswith((b")", b"]", b"}"), cursor):
                if not advance(1) or not trim_space():
                    return False
            if starts_trivia():
                if not trim_continuation_trivia():
                    return False
                if not trim_diff_record_prefix():
                    return False
                continue
            if value.startswith(b",", cursor):
                if not advance(1) or not trim_space():
                    return False
                continue
            break
        if at_proven_end():
            return True
        if starts_diff_metadata_boundary():
            return True
        if value.startswith(b";", cursor):
            if not advance(1) or not trim_space():
                return False
            if starts_trivia() and not trim_continuation_trivia():
                return False
            return (
                at_proven_end()
                or starts_diff_metadata_boundary()
                or starts_named_assignment()
                or starts_proven_python_declaration()
            )
        return starts_named_assignment() or starts_proven_python_declaration()
    if crossed_boundary:
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
    match: re.Match[bytes],
    *,
    diff_surface: bool = False,
    allow_inline_hash_comment: bool = False,
) -> bool:
    cursor = match.end()
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
        match.start() - MAX_SECRET_ASSIGNMENT_TRAILING_BYTES,
    )
    last_line_break = max(
        value.rfind(b"\n", lookbehind_start, match.start()),
        value.rfind(b"\r", lookbehind_start, match.start()),
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
    while key_start < match.start() and value[key_start] == 0x20:
        key_start += 1
    if key_start < match.start() and value[key_start] == 0x09:
        return False
    while (
        key_start + 1 < match.start()
        and value[key_start] in (0x2D, 0x3F)
        and value[key_start + 1] in (0x20, 0x09)
    ):
        key_start += 1
        while key_start < match.start() and value[key_start] == 0x20:
            key_start += 1
        if key_start < match.start() and value[key_start] == 0x09:
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


def _iter_secret_events(
    value: bytes,
    *,
    minimum_end: int = 0,
    maximum_end: int | None = None,
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    _event_budget: SecretScanBudget | None = None,
) -> Iterator[tuple[str, bytes | None, int, bool, int | None, int | None]]:
    event_budget = _event_budget or SecretScanBudget.default()

    def match_is_committable(match: re.Match[bytes]) -> bool:
        return minimum_end < match.end() and (
            maximum_end is None or match.end() <= maximum_end
        )

    for rule, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            if not match_is_committable(match):
                continue
            event_budget.consume()
            start, candidate_end = match.span(0)
            yield rule, match.group(0), match.end(), True, start, candidate_end
    for rule, pattern in (
        ("aws-secret-key", OVERSIZED_AWS_SECRET_KEY_GAP),
        ("jwt", OVERSIZED_JWT_PATTERN),
        ("generic-secret-assignment", OVERSIZED_SECRET_ASSIGNMENT_GAP),
    ):
        for match in pattern.finditer(value):
            if not match_is_committable(match):
                continue
            event_budget.consume()
            yield rule, None, match.end(), False, None, None
    for pattern in (
        OVERSIZED_QUOTED_SECRET_ASSIGNMENT,
        OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT,
    ):
        for match in pattern.finditer(value):
            if not match_is_committable(match):
                continue
            event_budget.consume()
            yield (
                "generic-secret-assignment",
                None,
                match.end(),
                False,
                None,
                None,
            )
    for match in QUOTED_SECRET_ASSIGNMENT.finditer(value):
        if not match_is_committable(match):
            continue
        event_budget.consume()
        candidate = match.group(2)
        try:
            may_accept = _quoted_assignment_may_accept(
                value,
                match,
                diff_surface=diff_surface,
                prefix_context_complete=prefix_context_complete,
                suffix_context_complete=suffix_context_complete,
                event_budget=event_budget,
            )
        except _IncompleteSecretScanSuffix:
            yield (
                _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE,
                None,
                match.end(),
                False,
                match.start(),
                None,
            )
            continue
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
    for match in UNQUOTED_SECRET_ASSIGNMENT.finditer(value):
        if not match_is_committable(match):
            continue
        event_budget.consume()
        candidate = match.group(1)
        may_accept = _unquoted_assignment_may_accept(
            value,
            match,
            diff_surface=diff_surface,
        )
        placeholder = _is_placeholder_secret(candidate.lower())
        if placeholder and not may_accept:
            may_accept = _unquoted_assignment_may_accept(
                value,
                match,
                diff_surface=diff_surface,
                allow_inline_hash_comment=True,
            )
        if (not placeholder and _looks_like_unquoted_secret(candidate)) or (
            placeholder and not may_accept
        ):
            start, candidate_end = match.span(1)
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
    rules: set[str] = set()
    for accepted in accepted_values:
        rules.add(accepted.rule)
        if accepted.value is not None:
            exact.setdefault((accepted.rule, accepted.value), []).append(accepted)
            continue
        by_digest = digests.setdefault(
            (accepted.rule, accepted.value_length),
            {},
        )
        by_digest.setdefault(accepted.value_sha256, []).append(accepted)
    return AcceptedValueIndex(exact=exact, digests=digests, rules=frozenset(rules))


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
    for raw_value in descriptors:
        containing_matches: list[tuple[bytes, int]] = []
        for longer_value in descriptors:
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
) -> tuple[
    Counter[AcceptedSyntheticValue],
    Counter[AcceptedSyntheticValue],
]:
    counts: Counter[AcceptedSyntheticValue] = Counter()
    unembedded_counts: Counter[AcceptedSyntheticValue] = Counter()
    if not exact_index.patterns or minimum_start >= maximum_start:
        return counts, unembedded_counts
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
            next_start = start + 1
    return counts, unembedded_counts


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
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    suffix_context_complete: bool = True,
    _accepted_index: AcceptedValueIndex | None = None,
    _event_budget: SecretScanBudget | None = None,
    _exact_index: ExactValueIndex | None = None,
    _occurrence_budget: LegacyOccurrenceBudget | None = None,
    _continue_after_blocking: bool = False,
) -> SecretScanResult:
    if _continue_after_blocking and not capture_accepted_candidates:
        raise ReviewError(
            "exhaustive secret scanning requires accepted-candidate capture"
        )
    result = SecretScanResult.empty()
    exact_index = _exact_index or _index_exact_values(raw_occurrence_values)
    occurrence_budget = _occurrence_budget or LegacyOccurrenceBudget.default()
    raw_counts, unembedded_counts = _count_exact_value_occurrences(
        value,
        exact_index=exact_index,
        minimum_start=0,
        maximum_start=len(value),
        event_budget=occurrence_budget,
    )
    result.raw_occurrence_counts.update(raw_counts)
    result.unembedded_occurrence_counts.update(unembedded_counts)
    upper = len(value) if maximum_end is None else maximum_end
    accepted_index = _accepted_index or _index_accepted_values(accepted_values)
    event_budget = _event_budget or SecretScanBudget.default()
    accepted_specific_spans: set[tuple[int, int, bytes]] = set()
    accepted_specific_rules = {
        rule for rule in accepted_index.rules if rule != "generic-secret-assignment"
    }
    for rule, pattern in SECRET_PATTERNS:
        if rule not in accepted_specific_rules:
            continue
        for match in pattern.finditer(value):
            if match.end() > upper:
                continue
            # Keep older provider spans available when the corresponding generic
            # assignment ends across the commit frontier, but charge each
            # provider event only in its own commit range.
            if minimum_end < match.end():
                event_budget.consume()
            candidate = match.group(0)
            if _matching_accepted_values(
                rule=rule,
                candidate=candidate,
                accepted_index=accepted_index,
            ):
                start, candidate_end = match.span(0)
                accepted_specific_spans.add((start, candidate_end, candidate))

    for rule, candidate, end, may_accept, start, candidate_end in _iter_secret_events(
        value,
        minimum_end=minimum_end,
        maximum_end=upper,
        diff_surface=diff_surface,
        prefix_context_complete=prefix_context_complete,
        suffix_context_complete=suffix_context_complete,
        _event_budget=event_budget,
    ):
        if not minimum_end < end <= upper:
            continue
        if rule == _INCOMPLETE_SECRET_SCAN_SUFFIX_RULE:
            if start is None:
                raise ReviewError(
                    "sensitive scanner lost an incomplete diff suffix boundary"
                )
            result.incomplete_suffix_start = start
            return result
        if (
            rule == "generic-secret-assignment"
            and may_accept
            and candidate is not None
            and start is not None
            and candidate_end is not None
            and (start, candidate_end, candidate) in accepted_specific_spans
        ):
            continue
        matches = (
            _matching_accepted_values(
                rule=rule,
                candidate=candidate,
                accepted_index=accepted_index,
            )
            if may_accept and candidate is not None
            else []
        )
        if matches:
            accepted = matches[0]
            result.accepted_counts[accepted] += 1
            if capture_accepted_candidates:
                result.accepted_candidates.setdefault(accepted, set()).add(candidate)
        elif result.blocking_rule is None:
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
    diff_surface: bool = False,
    _accepted_index: AcceptedValueIndex | None = None,
    _event_budget: SecretScanBudget | None = None,
    _exact_index: ExactValueIndex | None = None,
    _occurrence_budget: LegacyOccurrenceBudget | None = None,
    _continue_after_blocking: bool = False,
) -> SecretScanResult:
    if size is not None and size < 0:
        raise ReviewError("sensitive scan size must be nonnegative")
    overlap = STREAM_SCAN_OVERLAP
    accepted = tuple(accepted_values)
    accepted_index = _accepted_index or _index_accepted_values(accepted)
    event_budget = _event_budget or SecretScanBudget.default()
    exact_values = tuple(raw_occurrence_values)
    exact_index = _exact_index or _index_exact_values(exact_values)
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
        next_committed_start = (
            total_read
            if at_end
            else max(0, total_read - max(0, exact_index.maximum_length - 1))
        )
        raw_counts, unembedded_counts = _count_exact_value_occurrences(
            exact_pending,
            exact_index=exact_index,
            minimum_start=max(0, committed_start - exact_pending_offset),
            maximum_start=max(0, next_committed_start - exact_pending_offset),
            event_budget=occurrence_budget,
        )
        result.raw_occurrence_counts.update(raw_counts)
        result.unembedded_occurrence_counts.update(unembedded_counts)
        committed_start = next_committed_start
        if not at_end:
            retain_exact_from = max(
                exact_pending_offset,
                committed_start - max(0, exact_index.maximum_length - 1),
            )
            exact_pending = exact_pending[retain_exact_from - exact_pending_offset :]
            exact_pending_offset = retain_exact_from
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
        # Only the complete scan, or its safe-prefix replay, may spend the
        # caller-visible logical budget.
        pending_budget = event_budget.clone()
        pending_scan = _scan_secret_value(
            pending,
            accepted_values=accepted,
            minimum_end=local_minimum,
            maximum_end=local_maximum,
            capture_accepted_candidates=capture_accepted_candidates,
            diff_surface=diff_surface,
            prefix_context_complete=pending_offset == 0,
            suffix_context_complete=at_end,
            _accepted_index=accepted_index,
            _event_budget=pending_budget,
            _continue_after_blocking=_continue_after_blocking,
        )
        if pending_scan.incomplete_suffix_start is not None:
            safe_local_maximum = max(
                local_minimum,
                min(local_maximum, pending_scan.incomplete_suffix_start),
            )
            if safe_local_maximum > local_minimum:
                committed_budget = event_budget.clone()
                committed_scan = _scan_secret_value(
                    pending,
                    accepted_values=accepted,
                    minimum_end=local_minimum,
                    maximum_end=safe_local_maximum,
                    capture_accepted_candidates=capture_accepted_candidates,
                    diff_surface=diff_surface,
                    prefix_context_complete=pending_offset == 0,
                    suffix_context_complete=at_end,
                    _accepted_index=accepted_index,
                    _event_budget=committed_budget,
                    _continue_after_blocking=_continue_after_blocking,
                )
                if committed_scan.incomplete_suffix_start is not None:
                    raise ReviewError(
                        "sensitive scanner could not establish a complete diff prefix"
                    )
                event_budget.commit_from(committed_budget)
                result.merge(committed_scan)
            # Commit the complete prefix, but retain the deferred assignment
            # inside the overlap so it is re-evaluated with the next read.
            next_committed_end = pending_offset + safe_local_maximum
        else:
            event_budget.commit_from(pending_budget)
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


def _source_status(repo: pathlib.Path) -> bytes:
    _reject_hidden_index_entries(repo)
    excludes_file = _source_excludes_file(repo)
    return _bounded_source_git_output(
        repo,
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
        byte_limit=MAX_SOURCE_STATUS_BYTES,
        record_limit=MAX_SOURCE_STATUS_RECORDS,
        label="source WIP status metadata",
        config_overrides=(f"core.excludesFile={excludes_file}",),
    )


def _reject_hidden_index_entries(repo: pathlib.Path) -> None:
    value = _bounded_source_git_output(
        repo,
        "ls-files",
        "-v",
        "-z",
        "--cached",
        "--",
        byte_limit=MAX_SOURCE_INDEX_METADATA_BYTES,
        record_limit=MAX_SOURCE_INDEX_RECORDS,
        label="source index-flag metadata",
    )
    if value and not value.endswith(b"\0"):
        raise ReviewError("unterminated source index-flag metadata")
    for record in value.split(b"\0")[:-1]:
        if len(record) < 3 or record[1:2] != b" ":
            raise ReviewError("source index-flag metadata is malformed")
        tag = record[:1]
        if tag == b"S" or tag.islower():
            raise ReviewError(
                "source index contains assume-unchanged or skip-worktree entries; "
                "clear hidden index flags before preparing a review"
            )


def _require_clean_source(repo: pathlib.Path) -> None:
    if _source_status(repo):
        raise ReviewError(
            "source repository has staged, unstaged, or nonignored untracked "
            "changes; commit or clean them, or explicitly use --include-source-wip"
        )


def _parse_wip_status(status_bytes: bytes) -> None:
    for record in status_bytes.split(b"\0"):
        if not record:
            continue
        if record.startswith(b"u "):
            raise ReviewError("source WIP contains unresolved merge conflicts")
        if record.startswith((b"1 ", b"2 ")):
            fields = record.split(b" ", 3)
            if len(fields) < 3:
                raise ReviewError("source WIP status metadata is malformed")
            if fields[2].startswith(b"S"):
                raise ReviewError(
                    "source WIP contains a changed or dirty submodule, which is not supported"
                )


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


def _nul_path_set(value: bytes, *, label: str) -> set[pathlib.PurePosixPath]:
    if len(value) > MAX_CHANGED_METADATA_BYTES:
        raise ReviewError(f"{label} exceeds the review metadata limit")
    records = value.split(b"\0")
    if records[-1:] != [b""]:
        raise ReviewError(f"unterminated record from {label}")
    if len(records) - 1 > MAX_CHANGED_ENTRIES:
        raise ReviewError(f"{label} exceeds the review entry-count limit")
    return {_parse_wip_path(record) for record in records[:-1]}


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


def _initial_untracked_wip_paths(
    initial_status: bytes,
) -> set[pathlib.PurePosixPath]:
    paths: set[pathlib.PurePosixPath] = set()
    for group in _porcelain_v2_groups(initial_status):
        if group[0].startswith(b"? "):
            raw_path = group[0][2:]
            if raw_path.endswith(b"/"):
                raise ReviewError(
                    "source WIP contains an unexpanded untracked directory; "
                    "nested repositories are not supported"
                )
            paths.add(_parse_wip_path(raw_path))
    return paths


def _source_wip_paths(
    repo: pathlib.Path,
    head_sha: str,
    initial_status: bytes,
) -> tuple[set[pathlib.PurePosixPath], set[pathlib.PurePosixPath]]:
    _reject_hidden_index_entries(repo)
    tracked = _bounded_source_git_output(
        repo,
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        head_sha,
        "--",
        byte_limit=MAX_SOURCE_TRACKED_PATH_BYTES,
        record_limit=MAX_SOURCE_TRACKED_PATH_RECORDS,
        label="source WIP tracked paths",
    )
    tracked_paths = _nul_path_set(tracked, label="source WIP tracked paths")
    deleted = _bounded_source_git_output(
        repo,
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        "--diff-filter=D",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        head_sha,
        "--",
        byte_limit=MAX_SOURCE_TRACKED_PATH_BYTES,
        record_limit=MAX_SOURCE_TRACKED_PATH_RECORDS,
        label="source WIP deleted tracked paths",
    )
    deleted_paths = _nul_path_set(
        deleted,
        label="source WIP deleted tracked paths",
    )
    if not deleted_paths.issubset(tracked_paths):
        raise ReviewError("source WIP tracked path metadata is inconsistent")
    untracked_paths = _initial_untracked_wip_paths(initial_status)
    paths = tracked_paths | untracked_paths
    if len(paths) > MAX_CHANGED_ENTRIES:
        raise ReviewError("source WIP exceeds the review entry-count limit")
    capture_paths = (tracked_paths - deleted_paths) | untracked_paths
    return paths, capture_paths


def _read_wip_entry(
    *,
    source_root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    remaining_bytes: int,
    expected_materialized_mode: str | None = None,
) -> tuple[str, bytes] | None:
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
        if expected_materialized_mode in {"100644", "100755"}:
            expected_permissions = (
                0o755 if expected_materialized_mode == "100755" else 0o644
            )
            if (
                stat.S_IMODE(initial.st_mode) != expected_permissions
                or initial.st_nlink != 1
                or initial.st_uid != os.geteuid()
            ):
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
    return ("100755" if initial.st_mode & stat.S_IXUSR else "100644"), data


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
) -> dict[pathlib.PurePosixPath, tuple[str, bytes]]:
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]] = {}
    remaining_bytes = MAX_SNAPSHOT_BYTES
    for relative in sorted(paths, key=lambda item: item.as_posix()):
        entry = _read_wip_entry(
            source_root=source_root,
            relative=relative,
            remaining_bytes=remaining_bytes,
        )
        if entry is not None:
            entries[relative] = entry
            remaining_bytes -= len(entry[1])
    return entries


def _import_source_wip_blobs(
    *,
    workspace_root: pathlib.Path,
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]],
) -> tuple[str, dict[pathlib.PurePosixPath, str]]:
    """Import captured WIP blobs with one bounded Git process."""

    object_format = (
        _run_worktree_git(workspace_root, "rev-parse", "--show-object-format")
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
    with tempfile.TemporaryFile() as stream:
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
) -> None:
    """Apply all WIP removals and additions with one NUL-delimited index update."""

    object_id_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if object_id_length is None:
        raise ReviewError(f"unsupported Git object format: {object_format!r}")
    zero_object_id = b"0" * object_id_length
    with tempfile.TemporaryFile() as index_info:
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
        )


def _overlay_source_wip(
    *,
    source_root: pathlib.Path,
    workspace_root: pathlib.Path,
    head_sha: str,
    initial_status: bytes,
    paths: set[pathlib.PurePosixPath],
    capture_paths: set[pathlib.PurePosixPath],
    entries: dict[pathlib.PurePosixPath, tuple[str, bytes]],
) -> str:
    object_format, object_ids = _import_source_wip_blobs(
        workspace_root=workspace_root,
        entries=entries,
    )
    _apply_source_wip_index_overlay(
        workspace_root=workspace_root,
        paths=paths,
        entries=entries,
        object_format=object_format,
        object_ids=object_ids,
    )
    snapshot_tree_sha = (
        _run_worktree_git(
            workspace_root,
            "write-tree",
        )
        .stdout.decode("ascii")
        .strip()
    )
    if resolve_commit(source_root, "HEAD", label="source WIP HEAD") != head_sha:
        raise ReviewError("source HEAD changed while the WIP snapshot was prepared")
    recheck_remaining_bytes = MAX_SNAPSHOT_BYTES
    for relative in sorted(capture_paths, key=lambda item: item.as_posix()):
        rechecked = _read_wip_entry(
            source_root=source_root,
            relative=relative,
            remaining_bytes=recheck_remaining_bytes,
        )
        if rechecked != entries.get(relative):
            raise ReviewError(
                "source WIP content changed while the private snapshot was prepared"
            )
        if rechecked is not None:
            recheck_remaining_bytes -= len(rechecked[1])
    final_status = _source_status(source_root)
    if final_status != initial_status:
        raise ReviewError("source WIP changed while the review snapshot was prepared")
    return snapshot_tree_sha


def _clear_materialized_workspace(workspace_root: pathlib.Path) -> None:
    for entry in os.scandir(workspace_root):
        if entry.name == ".git":
            continue
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)
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
    with tempfile.TemporaryFile() as metadata:
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
    catalog_legacy_values = accepted_legacy_values(
        catalog,
        catalog.legacy_exemptions,
    )
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
        for commit in sorted({tip, *by_commit}):
            _reject_legacy_values_in_frozen_tree_paths(
                git_view=git_view,
                object_directory=object_directory,
                commit=commit,
                legacy_values=catalog_legacy_values,
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
    if include_source_wip:
        if resolve_commit(source_root, "HEAD", label="source HEAD") != head_sha:
            raise ReviewError(
                "--include-source-wip requires --head-ref to resolve to source HEAD"
            )
        source_status = _source_status(source_root)
        _parse_wip_status(source_status)
        source_wip_paths, source_wip_capture_paths = _source_wip_paths(
            source_root,
            head_sha,
            source_status,
        )
        source_wip_entries = _capture_source_wip_entries(
            source_root=source_root,
            paths=source_wip_capture_paths,
        )
        if resolve_commit(source_root, "HEAD", label="source WIP HEAD") != head_sha:
            raise ReviewError("source HEAD changed while the WIP snapshot was captured")
        if _source_status(source_root) != source_status:
            raise ReviewError("source WIP changed while its content was captured")
    else:
        _require_clean_source(source_root)
        source_status = b""
        source_wip_paths = set()
        source_wip_capture_paths = set()
        source_wip_entries = {}
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    selected_exemptions = resolve_legacy_exemptions(
        catalog,
        synthetic_secret_exemptions,
    )
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
    container, handoff_mask = _new_container(source_root)
    ownership_transferred = False

    try:
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
        shutil.rmtree(source_git_view)
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
            _reject_legacy_values_in_frozen_tree_paths(
                git_view=git_view,
                object_directory=object_directory,
                commit=commit,
                legacy_values=catalog_legacy_values,
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
                source_root=source_root,
                workspace_root=workspace_root,
                head_sha=head_sha,
                initial_status=source_status,
                paths=source_wip_paths,
                capture_paths=source_wip_capture_paths,
                entries=source_wip_entries,
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
        _reject_legacy_values_in_frozen_tree_paths(
            git_view=git_view,
            object_directory=object_directory,
            commit=snapshot_tree_sha,
            legacy_values=catalog_legacy_values,
        )
        _reject_protected_review_path_aliases(workspace_root)
        control_dir = workspace_root / ".codex-review"
        if control_dir.exists() or control_dir.is_symlink():
            raise ReviewError(
                "the frozen head uses the reserved top-level .codex-review path"
            )
        control_dir.mkdir(mode=0o700)
        write_text_atomic(git_dir / "info" / "exclude", "/.codex-review/\n")
        synthetic_manifest = _legacy_count_manifest(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            source_head_sha=head_sha if include_source_wip else None,
            catalog=catalog,
            exemptions=selected_exemptions,
        )
        _write_bounded_json(
            control_dir / SYNTHETIC_MANIFEST_NAME,
            synthetic_manifest,
            label="synthetic secret manifest",
            accepted_values=evidence_sensitive_values,
        )
        _write_bounded_json(
            container / SYNTHETIC_PRIVATE_MANIFEST_NAME,
            synthetic_manifest,
            label="synthetic secret helper-private state",
            accepted_values=evidence_sensitive_values,
        )
        changed_paths_file = control_dir / "changed-paths.z"
        _write_frozen_changed_paths(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            destination=changed_paths_file,
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
            evidence_sensitive_values=evidence_sensitive_values,
        )
        diff_file = control_dir / "review.diff"
        _write_frozen_diff(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=snapshot_tree_sha,
            destination=diff_file,
        )
        prompt_file = control_dir / "review.prompt"
        if prompt_override is None:
            prompt = build_review_prompt(
                workspace=workspace_root,
                diff_file=diff_file,
                base_ref=base_sha,
                head_ref=head_sha,
                content_variant=content_variant,
                snapshot_tree_sha=snapshot_tree_sha,
                scope_identity=scope_identity,
            )
        else:
            template = _read_prompt_template(prompt_override.expanduser().absolute())
            replacements = {
                "workspace": str(workspace_root),
                "diff_file": str(diff_file),
                "base_ref": base_sha,
                "head_ref": head_sha,
                "review_range": f"{base_sha}..{head_sha}",
                "content_variant": content_variant,
                "snapshot_tree_sha": snapshot_tree_sha,
                "scope_identity": scope_identity,
            }
            prompt = re.sub(
                r"\{(workspace|diff_file|base_ref|head_ref|review_range|content_variant|snapshot_tree_sha|scope_identity)\}",
                lambda match: replacements[match.group(1)],
                template,
            )
        _validate_prompt_size(prompt)
        write_text_atomic(prompt_file, prompt)
        control_artifact_state = _build_control_artifact_state(
            control_dir=control_dir,
        )
        _write_bounded_json(
            container / CONTROL_ARTIFACT_STATE_NAME,
            control_artifact_state,
            label="helper-private review control state",
            accepted_values=evidence_sensitive_values,
        )
        review = ReviewWorkspace(
            source_root=source_root,
            container_dir=container,
            workspace_root=workspace_root,
            base_ref=base_sha,
            head_ref=head_sha,
            diff_file=diff_file,
            prompt_file=prompt_file,
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
            cleanup_error = _remove_partial_container(container)
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
        if handoff_mask is not None:
            restore_signal_mask(handoff_mask)


def cleanup_workspace(
    review: ReviewWorkspace,
    *,
    keep_container: bool,
    allow_legacy: bool = False,
) -> str | None:
    if allow_legacy:
        validate_legacy_workspace_layout(review)
    else:
        validate_workspace_layout(review)
    try:
        if allow_legacy:
            if review.workspace_root.exists():
                shutil.rmtree(review.workspace_root)
            if not keep_container and review.container_dir.exists():
                shutil.rmtree(review.container_dir)
            return None
        git_dir = review.git_dir or review.container_dir / "review.git"
        if review.workspace_root.exists():
            if git_dir.is_dir():
                removed = _run_private_git(
                    git_dir=git_dir,
                    args=(
                        "worktree",
                        "remove",
                        "--force",
                        "--force",
                        str(review.workspace_root),
                    ),
                    check=False,
                )
                if removed.returncode != 0:
                    detail = removed.stderr.decode("utf-8", errors="replace").strip()
                    return detail or "cannot remove detached review worktree"
            else:
                shutil.rmtree(review.workspace_root)
            if review.workspace_root.exists():
                return "detached review worktree still exists after removal"
        if git_dir.exists():
            shutil.rmtree(git_dir)
        if not keep_container and review.container_dir.exists():
            shutil.rmtree(review.container_dir)
    except OSError as error:
        return str(error)
    return None
