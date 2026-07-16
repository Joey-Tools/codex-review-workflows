from __future__ import annotations

import ast
import base64
import hashlib
import json
import math
import os
import pathlib
import re
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
    run,
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
SYNTHETIC_MANIFEST_NAME = "synthetic-secret-manifest.json"
SYNTHETIC_PRIVATE_MANIFEST_NAME = "synthetic-secret-state.json"
SYNTHETIC_CHANGED_EVIDENCE_NAME = "synthetic-changed-evidence.json"
SYNTHETIC_MANIFEST_SCHEMA_VERSION = 2
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

    def to_json(self) -> dict[str, str]:
        return {key: str(value) for key, value in asdict(self).items()}

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


@dataclass
class SecretScanResult:
    blocking_rule: str | None
    accepted_counts: Counter[AcceptedSyntheticValue]
    accepted_candidates: dict[AcceptedSyntheticValue, set[bytes]]
    raw_occurrence_counts: Counter[AcceptedSyntheticValue]
    unembedded_occurrence_counts: Counter[AcceptedSyntheticValue]

    @classmethod
    def empty(cls) -> "SecretScanResult":
        return cls(None, Counter(), {}, Counter(), Counter())

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


def _git_environment(*, object_directory: pathlib.Path | None = None) -> dict[str, str]:
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
    return env


def _git(repo: pathlib.Path, *args: str, check: bool = True):
    return run(
        (
            str(resolve_git()),
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "diff.external=",
            "-C",
            str(repo),
            *args,
        ),
        env=_git_environment(),
        check=check,
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
    (git_view / "objects").mkdir(parents=True)
    (git_view / "refs").mkdir()
    write_text_atomic(git_view / "HEAD", "ref: refs/heads/unused\n")
    format_version = 1 if object_format == "sha256" else 0
    config = f"[core]\n\trepositoryformatversion = {format_version}\n\tbare = true\n"
    if object_format == "sha256":
        config += "[extensions]\n\tobjectFormat = sha256\n"
    write_text_atomic(git_view / "config", config)
    return git_view, object_directory


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
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        f"--git-dir={git_view}",
        *args,
    )


def _commit_uses_reserved_control_path(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    label: str,
) -> bool:
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-z", "--name-only", commit),
            ),
            env=_git_environment(object_directory=object_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_output,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError(f"failed to create frozen {label} tree metadata pipe")
        reserved = False
        try:
            for name in _iter_nul_records(
                process.stdout,
                byte_limit=MAX_TREE_METADATA_BYTES,
                record_limit=MAX_SNAPSHOT_ENTRIES,
                label=f"frozen {label} tree metadata",
            ):
                if os.fsdecode(name).casefold() == ".codex-review":
                    reserved = True
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                f"cannot inspect frozen {label} tree metadata: "
                f"{_process_stderr(error_output)}"
            )
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
    repo: pathlib.Path,
    *,
    base_sha: str,
    head_sha: str,
) -> None:
    ancestor = _git(
        repo,
        "merge-base",
        "--is-ancestor",
        base_sha,
        head_sha,
        check=False,
    )
    if ancestor.returncode == 0:
        return
    if ancestor.returncode != 1:
        raise ReviewError("cannot verify that the frozen base is an ancestor of head")
    merge_base = _git(repo, "merge-base", base_sha, head_sha, check=False)
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        suggestion = merge_base.stdout.decode("ascii").strip()
        detail = f"; use merge base {suggestion} as --base-ref"
    else:
        detail = "; the commits have no merge base"
    raise ReviewError(
        f"frozen base {base_sha} is not an ancestor of head {head_sha}{detail}"
    )


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


def _new_container(
    source_root: pathlib.Path,
) -> tuple[pathlib.Path, set[signal.Signals] | None]:
    handoff_mask = block_forwarded_signals()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = uuid.uuid4().hex[:10]
    review_root = source_root / ".codex-tmp"
    container: pathlib.Path | None = None
    try:
        try:
            os.mkdir(review_root, mode=0o700)
        except FileExistsError:
            pass
        try:
            root_status = os.lstat(review_root)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect review root {review_root}: {error}"
            ) from error
        if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
            raise ReviewError(
                f"review root must be a real directory, not a symlink: {review_root}"
            )
        if root_status.st_uid != os.geteuid():
            raise ReviewError(
                f"review root must be owned by the current user: {review_root}"
            )
        if root_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(
                f"review root must not be group or other writable: {review_root}"
            )
        if review_root.resolve() != review_root.absolute():
            raise ReviewError(
                f"review root resolves outside the source repository: {review_root}"
            )

        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_fd = os.open(review_root, flags)
        except OSError as error:
            raise ReviewError(
                f"cannot securely open review root {review_root}: {error}"
            ) from error
        try:
            opened_status = os.fstat(root_fd)
            if (opened_status.st_dev, opened_status.st_ino) != (
                root_status.st_dev,
                root_status.st_ino,
            ):
                raise ReviewError("review root changed while opening it securely")
            name = f"isolated-review-{stamp}-{suffix}"
            container = review_root / name
            os.mkdir(name, mode=0o700, dir_fd=root_fd)
            descriptor_status = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            path_status = os.lstat(container)
            if (descriptor_status.st_dev, descriptor_status.st_ino) != (
                path_status.st_dev,
                path_status.st_ino,
            ):
                raise ReviewError(
                    "review root changed while creating the private container"
                )
        finally:
            os.close(root_fd)
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
    with tempfile.TemporaryFile() as tree_stderr:
        process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", commit),
            ),
            env=_git_environment(object_directory=object_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=tree_stderr,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError("failed to create frozen Git path validation pipe")
        try:
            for record in _iter_nul_records(
                process.stdout,
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
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                "cannot enumerate frozen Git paths for legacy synthetic-token "
                f"validation: {_process_stderr(tree_stderr)}"
            )


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(min(64 * 1024, size - len(value)))
        if not chunk:
            raise ReviewError("unexpected end of git cat-file output")
        value.extend(chunk)
    return bytes(value)


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


def _materialize_blob(
    *,
    cat_input: BinaryIO,
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
            _copy_exact(cat_output, handle, size)
        destination.chmod(0o755 if mode == "100755" else 0o644)
    else:
        raise ReviewError(
            f"unsupported mode in frozen Git tree: {mode} {destination_display}"
        )
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after git cat-file blob")
    return materialized_bytes + size


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _close_pipe(stream: BinaryIO | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


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
    workspace_root.mkdir()
    environment = _git_environment(object_directory=object_directory)
    with (
        tempfile.TemporaryFile() as tree_stderr,
        tempfile.TemporaryFile() as cat_stderr,
    ):
        tree_process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", head_sha),
            ),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=tree_stderr,
        )
        try:
            cat_process = subprocess.Popen(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=cat_stderr,
            )
        except BaseException:
            _close_pipe(tree_process.stdout)
            _stop_process(tree_process)
            raise
        if (
            tree_process.stdout is None
            or cat_process.stdin is None
            or cat_process.stdout is None
        ):
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise ReviewError(
                "failed to create pipes for frozen Git tree materialization"
            )
        materialized_bytes = 0
        materialized_entries = 0
        try:
            for record in _iter_nul_records(
                tree_process.stdout,
                byte_limit=MAX_TREE_METADATA_BYTES,
                label="frozen Git tree metadata",
            ):
                materialized_entries += 1
                if materialized_entries > MAX_SNAPSHOT_ENTRIES:
                    raise ReviewError(
                        "frozen Git tree exceeds the review entry-count limit"
                    )
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
                                "frozen Git tree path escapes workspace: "
                                f"{path_display}"
                            )
                        destination.mkdir(parents=True, exist_ok=False)
                        continue
                    if object_type != "blob":
                        raise ReviewError(
                            "unsupported object in frozen Git tree: "
                            f"{object_type} {path_display}"
                        )
                    materialized_bytes = _materialize_blob(
                        cat_input=cat_process.stdin,
                        cat_output=cat_process.stdout,
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
            _close_pipe(tree_process.stdout)
            tree_returncode = tree_process.wait()
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            cat_returncode = cat_process.wait()
        except BaseException:
            _close_pipe(cat_process.stdin)
            _close_pipe(tree_process.stdout)
            _close_pipe(cat_process.stdout)
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise
        if tree_returncode != 0:
            raise ReviewError(
                f"cannot enumerate frozen Git tree: {_process_stderr(tree_stderr)}"
            )
        if cat_returncode != 0:
            raise ReviewError(
                f"cannot materialize frozen Git blobs: {_process_stderr(cat_stderr)}"
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
    with (
        _open_new_private_binary(destination) as output,
        tempfile.TemporaryFile() as error_output,
    ):
        process = subprocess.Popen(
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
            env=_git_environment(object_directory=object_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_output,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError("failed to create frozen review diff pipe")
        try:
            _copy_limited(
                process.stdout,
                output,
                limit=MAX_DIFF_BYTES,
                label="frozen review diff",
            )
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                f"cannot generate frozen review diff: {_process_stderr(error_output)}"
            )


def _write_limited_diff_metadata(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    args: tuple[str, ...],
    output: BinaryIO,
    error_output: BinaryIO,
    label: str,
    record_limit: int,
) -> None:
    process = subprocess.Popen(
        _frozen_command(git_view=git_view, args=args),
        env=_git_environment(object_directory=object_directory),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=error_output,
    )
    if process.stdout is None:
        _stop_process(process)
        raise ReviewError(f"failed to create {label} pipe")
    try:
        _copy_limited(
            process.stdout,
            output,
            limit=MAX_CHANGED_METADATA_BYTES,
            label=label,
            record_limit=record_limit,
        )
        _close_pipe(process.stdout)
        returncode = process.wait()
    except BaseException:
        _close_pipe(process.stdout)
        _stop_process(process)
        raise
    if returncode != 0:
        raise ReviewError(f"cannot generate {label}: {_process_stderr(error_output)}")


def _write_frozen_changed_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    with (
        _open_new_private_binary(destination) as output,
        tempfile.TemporaryFile() as error_output,
    ):
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
            error_output=error_output,
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
    cat_input: BinaryIO,
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
    environment = _git_environment(object_directory=object_directory)
    with (
        tempfile.TemporaryFile() as tree_stderr,
        tempfile.TemporaryFile() as cat_stderr,
    ):
        tree_process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", commit),
            ),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=tree_stderr,
        )
        try:
            cat_process = subprocess.Popen(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=cat_stderr,
            )
        except BaseException:
            _close_pipe(tree_process.stdout)
            _stop_process(tree_process)
            raise
        if (
            tree_process.stdout is None
            or cat_process.stdin is None
            or cat_process.stdout is None
        ):
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise ReviewError("failed to create pipes for frozen Git tree scanning")
        scanned_bytes = 0
        scanned_entries = 0
        try:
            for record in _iter_nul_records(
                tree_process.stdout,
                byte_limit=MAX_TREE_METADATA_BYTES,
                label="frozen Git tree scan metadata",
            ):
                scanned_entries += 1
                if scanned_entries > MAX_SNAPSHOT_ENTRIES:
                    raise ReviewError(
                        "frozen Git tree scan exceeds the review entry-count limit"
                    )
                mode, object_type, object_id, _relative = _parse_tree_record(record)
                if mode == "160000" and object_type == "commit":
                    continue
                if object_type != "blob":
                    raise ReviewError(
                        f"unsupported object in frozen Git tree scan: {object_type}"
                    )
                scan, scanned_bytes = _scan_batch_blob(
                    cat_input=cat_process.stdin,
                    cat_output=cat_process.stdout,
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
            _close_pipe(tree_process.stdout)
            tree_returncode = tree_process.wait()
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            cat_returncode = cat_process.wait()
        except BaseException:
            _close_pipe(cat_process.stdin)
            _close_pipe(tree_process.stdout)
            _close_pipe(cat_process.stdout)
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise
        if tree_returncode != 0:
            raise ReviewError(
                "cannot enumerate frozen Git tree for synthetic-token counts: "
                f"{_process_stderr(tree_stderr)}"
            )
        if cat_returncode != 0:
            raise ReviewError(
                "cannot scan frozen Git blobs for synthetic-token counts: "
                f"{_process_stderr(cat_stderr)}"
            )
    return result


def _legacy_count_manifest(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
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
    else:
        base_scan = SecretScanResult.empty()
        head_scan = SecretScanResult.empty()
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
            base_unembedded_count = base_scan.unembedded_occurrence_counts[descriptor]
            head_unembedded_count = head_scan.unembedded_occurrence_counts[descriptor]
            envelope_used = envelope_used or base_count > 0 or head_count > 0
            if head_count > base_count:
                raise ReviewError(
                    "legacy synthetic fixture count increased for "
                    f"{token.identifier}: base={base_count}, head={head_count}"
                )
            if head_unembedded_count > base_unembedded_count:
                raise ReviewError(
                    "legacy synthetic fixture unembedded count increased for "
                    f"{token.identifier}: base={base_unembedded_count}, "
                    f"head={head_unembedded_count}"
                )
            entries.append(
                {
                    "base_count": base_count,
                    "base_unembedded_count": base_unembedded_count,
                    "exemption_id": exemption.identifier,
                    "head_count": head_count,
                    "head_unembedded_count": head_unembedded_count,
                    "rule": token.rule,
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
    environment = _git_environment(object_directory=object_directory)
    with (
        tempfile.TemporaryFile() as raw_output,
        tempfile.TemporaryFile() as raw_error,
        tempfile.TemporaryFile() as cat_error,
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
            error_output=raw_error,
            label="changed blob metadata",
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
            raise ReviewError("failed to create pipes for changed Git blob scanning")
        try:
            records = iter(_iter_nul_records(raw_output))
            scanned_bytes = 0
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
                    raise ReviewError(
                        "raw Git diff is missing a changed path"
                    ) from error
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
                    scan, scanned_bytes = _scan_batch_blob(
                        cat_input=cat_process.stdin,
                        cat_output=cat_process.stdout,
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
                f"cannot scan changed Git blobs: {_process_stderr(cat_error)}"
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
    expected_parent = (source_root / ".codex-tmp").resolve(strict=False)
    if container_dir.parent != expected_parent or not container_dir.name.startswith(
        "isolated-review-"
    ):
        raise ReviewError(
            f"review container is outside the source repository review root: {container_dir}"
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
) -> dict[str, Any]:
    chunks: list[bytes] = []
    with _secure_file_reader(
        path,
        label=label,
        max_bytes=MAX_SYNTHETIC_EVIDENCE_BYTES,
        expected_artifact=expected_artifact,
    ) as (reader, _metadata):
        while chunk := reader.read(64 * 1024):
            chunks.append(chunk)
    encoded = b"".join(chunks)
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    return value


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
    dict[AcceptedSyntheticValue, tuple[int, int, int, int]],
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
    counts: dict[AcceptedSyntheticValue, tuple[int, int, int, int]] = {}
    evidence: list[dict[str, Any]] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "base_count",
            "base_unembedded_count",
            "exemption_id",
            "head_count",
            "head_unembedded_count",
            "rule",
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
        base_unembedded_count = raw_entry["base_unembedded_count"]
        head_unembedded_count = raw_entry["head_unembedded_count"]
        if (
            type(base_count) is not int
            or type(head_count) is not int
            or type(base_unembedded_count) is not int
            or type(head_unembedded_count) is not int
            or base_count < 0
            or head_count < 0
            or base_unembedded_count < 0
            or head_unembedded_count < 0
            or head_count > base_count
            or head_unembedded_count > base_unembedded_count
            or base_unembedded_count > base_count
            or head_unembedded_count > head_count
            or raw_entry["rule"] != descriptor.rule
            or raw_entry["value_sha256"] != descriptor.value_sha256
            or raw_entry["value_length"] != descriptor.value_length
        ):
            raise ReviewError("synthetic secret manifest entry is inconsistent")
        counts[descriptor] = (
            base_count,
            head_count,
            base_unembedded_count,
            head_unembedded_count,
        )
        evidence.append(dict(raw_entry))
    if set(counts) != set(accepted):
        raise ReviewError("synthetic secret manifest does not cover its selection")
    for exemption in exemptions:
        if not any(
            base_count or head_count
            for descriptor, (
                base_count,
                head_count,
                _base_unembedded_count,
                _head_unembedded_count,
            ) in counts.items()
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
    workspace_root = review.workspace_root.resolve(strict=True)
    control_dir = workspace_root / ".codex-review"
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    catalog_legacy_path_matcher = _legacy_path_matcher(
        accepted_legacy_values(catalog, catalog.legacy_exemptions)
    )
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

    for accepted, (
        _base_count,
        expected_head_count,
        _base_unembedded_count,
        expected_head_unembedded_count,
    ) in legacy_counts.items():
        actual_head_count = frozen_head_legacy_counts[accepted]
        if actual_head_count != expected_head_count:
            raise ReviewError(
                "frozen head legacy synthetic fixture count changed after preparation "
                f"for {accepted.identifier}: expected={expected_head_count}, "
                f"actual={actual_head_count}"
            )
        actual_head_unembedded_count = frozen_head_legacy_unembedded_counts[accepted]
        if actual_head_unembedded_count != expected_head_unembedded_count:
            raise ReviewError(
                "frozen head legacy synthetic fixture unembedded count changed "
                f"after preparation for {accepted.identifier}: "
                f"expected={expected_head_unembedded_count}, "
                f"actual={actual_head_unembedded_count}"
            )

    diff_scan = _file_secret_scan(
        review.diff_file,
        accepted_values=accepted_values,
        diff_surface=True,
        accepted_index=accepted_index,
        event_budget=event_budget,
        max_bytes=MAX_DIFF_BYTES,
        expected_artifact=control_artifacts["review.diff"],
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
        "synthetic_tokens": {
            "accepted": accepted_evidence,
            "catalog_schema_version": catalog.schema_version,
            "legacy_counts": legacy_evidence,
            "pool_version": catalog.pool_version,
        }
    }
    encoded_evidence = json.dumps(
        evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded_evidence) > MAX_SYNTHETIC_EVIDENCE_BYTES:
        raise ReviewError("synthetic-token preflight evidence exceeds the size limit")
    complete_preflight_evidence = {
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "scope": "frozen tracked workspace, diff, and review prompt",
        "status": "sensitive-content and escaping-symlink checks passed",
    }
    complete_preflight_evidence.update(evidence)
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


def _quoted_assignment_may_accept(
    value: bytes,
    match: re.Match[bytes],
    *,
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    event_budget: SecretScanBudget,
) -> bool:
    cursor = match.end()
    inspected = 0
    crossed_line_boundary = False

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

    def trim_diff_record_prefix() -> bool:
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

    def diff_head_prefix() -> bytes | None:
        lower_bound = max(0, cursor - MAX_SECRET_PREFIX_PROOF_BYTES)
        markers = (
            value.rfind(b"\n@@ ", lower_bound, cursor),
            value.rfind(b"\n@@@ ", lower_bound, cursor),
        )
        marker = max(markers)
        if marker >= 0:
            hunk_start = value.find(b"\n", marker + 1, cursor)
            if hunk_start < 0:
                return None
            hunk_start += 1
        elif lower_bound == 0 and value.startswith((b"@@ ", b"@@@ ")):
            hunk_start = value.find(b"\n", 0, cursor)
            if hunk_start < 0:
                return None
            hunk_start += 1
        elif lower_bound == 0:
            hunk_start = 0
        else:
            return None
        raw_prefix = value[hunk_start:cursor]
        if not event_budget.consume_prefix_proof(len(raw_prefix)):
            return None
        head_lines: list[bytes] = []
        for line in raw_prefix.splitlines(keepends=True):
            if line.startswith((b"+", b" ")):
                if line.startswith(b"+++ "):
                    return None
                head_lines.append(line[1:])
            elif line.startswith(b"-"):
                if line.startswith(b"--- "):
                    return None
            elif line.startswith(b"\\ No newline at end of file"):
                continue
            elif line:
                return None
        return b"".join(head_lines)

    def python_prefix_is_complete() -> bool:
        if not prefix_context_complete:
            return False
        if diff_surface:
            prefix = diff_head_prefix()
            if prefix is None:
                return False
        else:
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
    if cursor == len(value):
        return True
    if value.startswith(b";", cursor):
        if not advance(1) or not trim_space():
            return False
        if starts_trivia():
            if not trim_continuation_trivia():
                return False
        return (
            cursor == len(value)
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
        if cursor == len(value):
            return True
        if starts_diff_metadata_boundary():
            return True
        if value.startswith(b";", cursor):
            if not advance(1) or not trim_space():
                return False
            if starts_trivia() and not trim_continuation_trivia():
                return False
            return (
                cursor == len(value)
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
    diff_surface: bool = False,
    prefix_context_complete: bool = True,
    _event_budget: SecretScanBudget | None = None,
) -> Iterator[tuple[str, bytes | None, int, bool, int | None, int | None]]:
    event_budget = _event_budget or SecretScanBudget.default()
    for rule, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            event_budget.consume()
            start, candidate_end = match.span(0)
            yield rule, match.group(0), match.end(), True, start, candidate_end
    for rule, pattern in (
        ("aws-secret-key", OVERSIZED_AWS_SECRET_KEY_GAP),
        ("jwt", OVERSIZED_JWT_PATTERN),
        ("generic-secret-assignment", OVERSIZED_SECRET_ASSIGNMENT_GAP),
    ):
        for match in pattern.finditer(value):
            event_budget.consume()
            yield rule, None, match.end(), False, None, None
    for pattern in (
        OVERSIZED_QUOTED_SECRET_ASSIGNMENT,
        OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT,
    ):
        for match in pattern.finditer(value):
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
        event_budget.consume()
        candidate = match.group(2)
        may_accept = _quoted_assignment_may_accept(
            value,
            match,
            diff_surface=diff_surface,
            prefix_context_complete=prefix_context_complete,
            event_budget=event_budget,
        )
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
        diff_surface=diff_surface,
        prefix_context_complete=prefix_context_complete,
        _event_budget=event_budget,
    ):
        if not minimum_end < end <= upper:
            continue
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
        else:
            preferred_read_size = (
                MAX_SECRET_PREFIX_PROOF_BYTES + overlap
                if total_read == 0
                else 1024 * 1024
            )
            read_size = (
                preferred_read_size
                if remaining is None
                else min(preferred_read_size, remaining)
            )
            chunk = stream.read(read_size)
        if not chunk and remaining not in (None, 0):
            raise ReviewError("unexpected end of Git blob during sensitive scan")
        if remaining is not None:
            remaining -= len(chunk)
        total_read += len(chunk)
        at_end = not chunk or remaining == 0
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
        result.merge(
            _scan_secret_value(
                pending,
                accepted_values=accepted,
                minimum_end=local_minimum,
                maximum_end=local_maximum,
                capture_accepted_candidates=capture_accepted_candidates,
                diff_surface=diff_surface,
                prefix_context_complete=pending_offset == 0,
                _accepted_index=accepted_index,
                _event_budget=event_budget,
                _continue_after_blocking=_continue_after_blocking,
            )
        )
        if result.blocking_rule is not None and not _continue_after_blocking:
            blocked = True
            pending = b""
        committed_end = next_committed_end
        if at_end:
            break
        retain_from = max(pending_offset, committed_end - overlap)
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

    with tempfile.TemporaryDirectory(prefix="synthetic-token-master-audit-") as raw:
        container = pathlib.Path(raw)
        git_view, object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=container,
        )
        by_commit: dict[str, list[AcceptedSyntheticValue]] = {}
        for token in exemption.values:
            ancestor = _git(
                source_root,
                "merge-base",
                "--is-ancestor",
                token.containing_commit,
                tip,
                check=False,
            )
            if ancestor.returncode != 0:
                raise ReviewError(
                    "legacy provenance commit is not an ancestor of the verified master tip: "
                    f"{token.identifier}"
                )
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
) -> ReviewWorkspace:
    source_root = resolve_repo_root(repo)
    base_sha = resolve_commit(source_root, base_ref, label="base ref")
    head_sha = resolve_commit(source_root, head_ref, label="head ref")
    _require_ancestor_range(
        source_root,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    selected_exemptions = resolve_legacy_exemptions(
        catalog,
        synthetic_secret_exemptions,
    )
    accepted_values = accepted_authoring_values(catalog) + accepted_legacy_values(
        catalog,
        selected_exemptions,
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
        git_view, object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=container,
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
        _reject_protected_review_path_aliases(workspace_root)
        control_dir = workspace_root / ".codex-review"
        if control_dir.exists() or control_dir.is_symlink():
            raise ReviewError(
                "the frozen head uses the reserved top-level .codex-review path"
            )
        control_dir.mkdir(mode=0o700)
        synthetic_manifest = _legacy_count_manifest(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
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
            head_sha=head_sha,
            destination=changed_paths_file,
        )
        changed_blob_findings = control_dir / "changed-blob-findings.z"
        _write_changed_blob_findings(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
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
            head_sha=head_sha,
            destination=diff_file,
        )
        shutil.rmtree(git_view)

        prompt_file = control_dir / "review.prompt"
        if prompt_override is None:
            prompt = build_review_prompt(
                workspace=workspace_root,
                diff_file=diff_file,
                base_ref=base_sha,
                head_ref=head_sha,
            )
        else:
            template = _read_prompt_template(prompt_override.expanduser().absolute())
            replacements = {
                "workspace": str(workspace_root),
                "diff_file": str(diff_file),
                "base_ref": base_sha,
                "head_ref": head_sha,
                "review_range": f"{base_sha}..{head_sha}",
            }
            prompt = re.sub(
                r"\{(workspace|diff_file|base_ref|head_ref|review_range)\}",
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
        )
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


def cleanup_workspace(review: ReviewWorkspace, *, keep_container: bool) -> str | None:
    validate_workspace_layout(review)
    try:
        if review.workspace_root.exists():
            shutil.rmtree(review.workspace_root)
        if not keep_container:
            shutil.rmtree(review.container_dir)
    except OSError as error:
        return str(error)
    return None
