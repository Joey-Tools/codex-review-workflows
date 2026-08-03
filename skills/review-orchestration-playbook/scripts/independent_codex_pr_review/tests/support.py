from __future__ import annotations

import atexit
import errno
import fcntl
import functools
import hashlib
import json
import os
import pathlib
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import FrameType

from review_supervisor.constants import (
    CONTROL_ARTIFACT_SPECS,
    HELPER_PREFLIGHT_STATUS,
    HELPER_STATE_MARKER_TEXT,
)
from review_supervisor.models import Identity
from review_supervisor.recovery_cleanup import (
    CustodiedDeletionResultOwner,
    CustodiedManifestResultOwner,
    QuarantinedRootRecoveryEvidence,
    RootSpec,
    build_custodied_manifest,
    delete_custodied_roots,
    quarantine_and_remove_empty_root,
    quarantined_root_recovery_evidence,
    remove_published_manifest,
)
from review_supervisor.secureio import (
    DirectoryPolicyBinding,
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    rename_noreplace,
    validate_directory_policy_fd,
)

from .async_fd_custody import (
    FdIdentityCustody,
    RawFdCustody,
    supported_async_fd_publication,
    supported_async_publication,
)

_EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
_DARWIN_F_GETPATH = 50
_DARWIN_MAXPATHLEN = 1024
_OWNED_TEMPORARY_CLEANUP_ENTRY_CAP = 8192
_OWNED_TEMPORARY_CLEANUP_MANIFEST_BYTES = 4 * 1024 * 1024
_OWNED_TEMPORARY_CLEANUP_SECONDS = 60.0


def _canonical_ascii_directory(raw_path: str | pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        raise ValueError("directory path must be absolute")
    canonical = candidate.resolve(strict=True)
    try:
        str(canonical).encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("directory path must be ASCII") from error
    return canonical


def _require_owned_private_parent_policy(
    policy: DirectoryPolicyBinding,
    *,
    path: pathlib.Path,
) -> None:
    forbidden_mode = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
    required_mode = stat.S_IWUSR | stat.S_IXUSR
    if (
        policy.file_type != stat.S_IFDIR
        or policy.uid != os.getuid()
        or policy.mode & forbidden_mode
        or policy.mode & required_mode != required_mode
    ):
        raise OSError(
            errno.EPERM,
            f"test runtime parent has an unsafe access policy: {path}",
        )


def _prefer_control_flow_error(
    earlier: BaseException,
    later: BaseException,
) -> tuple[BaseException, BaseException]:
    """Return ``(primary, secondary)`` with control flow outranking errors."""

    if isinstance(earlier, Exception) and not isinstance(later, Exception):
        return later, earlier
    return earlier, later


@dataclass(slots=True)
class _DirectoryParentBinding:
    path: pathlib.Path
    fd: int
    identity: Identity
    policy: DirectoryPolicyBinding
    require_owned_private_parent: bool
    fd_close_outcome: str = field(init=False, default="owned")
    fd_close_error: BaseException | None = field(init=False, default=None)

    def close(self) -> None:
        if self.fd_close_outcome == "closed":
            return
        if self.fd_close_outcome == "close-outcome-unproven":
            return
        if self.fd_close_outcome != "owned" or self.fd < 0:
            raise RuntimeError(
                "directory parent binding has an invalid descriptor close state"
            )

        descriptor = self.fd
        # Publish ambiguity before entering close. An asynchronous exception
        # may arrive before the syscall or after a successful close, and either
        # case makes retry unsafe because the integer may have been reused.
        self.fd_close_outcome = "close-outcome-unproven"
        try:
            os.close(descriptor)
        except BaseException as error:
            self.fd_close_error = error
            try:
                setattr(error, "directory_parent_binding_close_owner", self)
            except BaseException:
                pass
            raise
        self.fd = -1
        self.fd_close_outcome = "closed"
        self.fd_close_error = None

    def object_locator(self) -> dict[str, int]:
        return {
            "device": self.policy.device,
            "inode": self.policy.inode,
            "file_type": self.policy.file_type,
            "generation": self.policy.generation,
        }

    def _object_key(self) -> tuple[int, int, int, int]:
        return (
            self.policy.device,
            self.policy.inode,
            self.policy.file_type,
            self.policy.generation,
        )

    @staticmethod
    def _metadata_object_key(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            getattr(metadata, "st_gen", 0),
        )

    def revalidate_held_identity(self) -> None:
        if self._metadata_object_key(os.fstat(self.fd)) != self._object_key():
            raise OSError(
                errno.ESTALE,
                f"test runtime parent object identity changed: {self.path}",
            )

    def access_policy_status(self) -> str:
        try:
            held_policy = validate_directory_policy_fd(
                self.fd,
                self.path,
                private=False,
            )
        except (OSError, ValueError):
            return "unreadable"
        return "same" if held_policy == self.policy else "changed"

    def original_path_identity_status(self) -> str:
        try:
            metadata = os.stat(self.path, follow_symlinks=False)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        if self._metadata_object_key(metadata) != self._object_key():
            return "replaced"
        descriptor_owner = RawFdCustody()
        try:
            with supported_async_fd_publication(descriptor_owner):
                try:
                    descriptor = os.open(
                        self.path,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                    descriptor_owner.publish(descriptor)
                    observed = self._metadata_object_key(os.fstat(descriptor))
                finally:
                    descriptor_owner.close()
        except FileNotFoundError:
            return "missing"
        except OSError:
            # Restoration errors from the guarded region are classified the
            # same way as reopen failures; control-flow exceptions still pass.
            return "unreadable"
        return "same" if observed == self._object_key() else "replaced"

    def revalidate_held(self) -> None:
        self.revalidate_held_identity()
        held_policy = validate_directory_policy_fd(
            self.fd,
            self.path,
            private=False,
        )
        if self.require_owned_private_parent:
            _require_owned_private_parent_policy(held_policy, path=self.path)
        if held_policy != self.policy:
            raise OSError(
                errno.ESTALE,
                f"test runtime parent access policy changed: {self.path}",
            )

    def current_path(self) -> pathlib.Path:
        self.revalidate_held_identity()
        if sys.platform != "darwin":
            raise OSError(
                errno.ENOTSUP,
                "held directory path recovery is unsupported",
                str(self.path),
            )
        raw = fcntl.fcntl(
            self.fd,
            _DARWIN_F_GETPATH,
            b"\0" * _DARWIN_MAXPATHLEN,
        )
        raw_path, separator, _ = raw.partition(b"\0")
        if not separator or not raw_path or not raw_path.startswith(b"/"):
            raise OSError(
                errno.ESTALE,
                "held directory current path is unavailable",
                str(self.path),
            )
        try:
            decoded = os.fsdecode(raw_path)
            decoded.encode("ascii")
        except (UnicodeDecodeError, UnicodeEncodeError) as error:
            raise OSError(
                errno.ESTALE,
                "held directory current path is not canonical ASCII",
                str(self.path),
            ) from error
        current = pathlib.Path(decoded)
        reopened_owner = RawFdCustody()
        with supported_async_fd_publication(reopened_owner):
            try:
                reopened_fd = os.open(
                    current,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                reopened_owner.publish(reopened_fd)
                if (
                    self._metadata_object_key(os.fstat(reopened_fd))
                    != self._object_key()
                ):
                    raise OSError(
                        errno.ESTALE,
                        f"held directory current path changed: {current}",
                    )
            finally:
                reopened_owner.close()
        self.revalidate_held_identity()
        return current

    def revalidate(self) -> None:
        self.revalidate_held()

        reopened_owner = FdIdentityCustody()
        with supported_async_fd_publication(reopened_owner):
            try:
                result = open_absolute_directory_chain(
                    self.path,
                    allow_sticky_writable_ancestors=(
                        not self.require_owned_private_parent
                    ),
                )
                reopened_owner.publish(result)
                reopened_fd, reopened_identity = result
                reopened_policy = validate_directory_policy_fd(
                    reopened_fd,
                    self.path,
                    private=False,
                )
                if self.require_owned_private_parent:
                    _require_owned_private_parent_policy(
                        reopened_policy,
                        path=self.path,
                    )
                if (
                    not directory_identities_match(self.identity, reopened_identity)
                    or reopened_policy != self.policy
                ):
                    raise OSError(
                        errno.ESTALE,
                        f"test runtime parent path changed: {self.path}",
                    )
            finally:
                reopened_owner.close()


@dataclass(slots=True)
class _DirectoryParentBindingResultOwner:
    """Caller-precreated fallback custody for one parent binding result."""

    binding: _DirectoryParentBinding | None = None
    transferred: bool = False
    settled: bool = False

    def publish(self, binding: _DirectoryParentBinding) -> None:
        if self.settled:
            raise ValueError("directory parent binding result owner is settled")
        if self.binding is None:
            self.binding = binding
            return
        if self.binding is not binding:
            raise ValueError("directory parent binding result owner was rebound")

    def owns(self, binding: _DirectoryParentBinding) -> bool:
        return self.binding is binding and not self.settled

    def transfer(self, binding: _DirectoryParentBinding) -> None:
        """Record the caller's claim after its result local has been stored."""

        if self.binding is not binding or self.settled:
            raise ValueError("directory parent binding result transfer is inconsistent")
        self.transferred = True

    @staticmethod
    def _attach_secondary_error(
        primary: BaseException,
        secondary: BaseException,
    ) -> None:
        try:
            primary.add_note(
                "directory parent binding settlement also failed: "
                f"{type(secondary).__name__}: {secondary}"
            )
        except BaseException:
            pass

    def close(self) -> None:
        if self.settled:
            return
        binding = self.binding
        if binding is None:
            self.settled = True
            return

        first_error: BaseException | None = None
        if binding.fd_close_outcome == "owned":
            try:
                binding.close()
            except BaseException as error:
                first_error = error
            if binding.fd_close_outcome == "owned":
                # The first invocation was interrupted before the binding
                # entered its close-ambiguity boundary. Retrying is safe while
                # the binding still proves that it owns the same integer.
                try:
                    binding.close()
                except BaseException as error:
                    if first_error is None:
                        first_error = error
                    else:
                        first_error, secondary = _prefer_control_flow_error(
                            first_error,
                            error,
                        )
                        self._attach_secondary_error(first_error, secondary)

        if binding.fd_close_outcome in {"closed", "close-outcome-unproven"}:
            self.settled = True
        elif binding.fd_close_outcome != "owned":
            raise RuntimeError(
                "directory parent binding result has an invalid close state"
            )

        if first_error is not None:
            try:
                setattr(
                    first_error,
                    "directory_parent_binding_result_owner",
                    self,
                )
            except BaseException:
                pass
            raise first_error


def _settle_directory_parent_binding_result_preserving_trigger(
    result_owner: _DirectoryParentBindingResultOwner,
    trigger_error: BaseException,
) -> BaseException:
    """Settle a published binding without replacing earlier control flow."""

    try:
        result_owner.close()
    except BaseException as close_error:
        preserved = (
            close_error
            if isinstance(trigger_error, Exception)
            and not isinstance(close_error, Exception)
            else trigger_error
        )
        if preserved is not close_error:
            _DirectoryParentBindingResultOwner._attach_secondary_error(
                preserved,
                close_error,
            )
        try:
            setattr(
                preserved,
                "directory_parent_binding_result_owner",
                result_owner,
            )
            setattr(
                preserved,
                "directory_parent_binding_settlement_error",
                close_error,
            )
        except BaseException:
            pass
        return preserved
    return trigger_error


def _open_directory_parent(
    raw_path: str | pathlib.Path,
    *,
    require_owned_private_parent: bool,
    result_owner: _DirectoryParentBindingResultOwner,
) -> _DirectoryParentBinding:
    if not isinstance(result_owner, _DirectoryParentBindingResultOwner):
        raise TypeError("directory parent binding result owner is required")
    if (
        result_owner.binding is not None
        or result_owner.transferred
        or result_owner.settled
    ):
        raise ValueError("directory parent binding result owner is already used")
    canonical = _canonical_ascii_directory(raw_path)
    descriptor_owner = FdIdentityCustody()
    binding: _DirectoryParentBinding | None = None
    with supported_async_fd_publication(descriptor_owner):
        try:
            result = open_absolute_directory_chain(
                canonical,
                allow_sticky_writable_ancestors=(not require_owned_private_parent),
            )
            descriptor_owner.publish(result)
            fd, identity = result
            policy = validate_directory_policy_fd(fd, canonical, private=False)
            if require_owned_private_parent:
                _require_owned_private_parent_policy(policy, path=canonical)
            binding = _DirectoryParentBinding(
                path=canonical,
                fd=fd,
                identity=identity,
                policy=policy,
                require_owned_private_parent=require_owned_private_parent,
            )
            binding.revalidate()
            result_owner.publish(binding)
            descriptor_owner.transfer(fd, identity)
        except BaseException:
            if descriptor_owner.state in {"empty", "owned"}:
                descriptor_owner.close()
            raise
    assert binding is not None
    return binding


def _duplicate_directory_parent(
    source: _DirectoryParentBinding,
    *,
    creation_result_owner: _PrivateDirectoryCreationResultOwner,
) -> _DirectoryParentBinding:
    """Duplicate a held directory without trusting its pathname again."""

    source.revalidate()
    descriptor_owner = RawFdCustody()
    binding: _DirectoryParentBinding | None = None
    with supported_async_fd_publication(descriptor_owner):
        try:
            descriptor = os.dup(source.fd)
            descriptor_owner.publish(descriptor)
            identity = identity_from_stat(os.fstat(descriptor))
            policy = validate_directory_policy_fd(
                descriptor,
                source.path,
                private=False,
            )
            if source.require_owned_private_parent:
                _require_owned_private_parent_policy(policy, path=source.path)
            if (
                not directory_identities_match(identity, source.identity)
                or policy != source.policy
            ):
                raise OSError(
                    errno.ESTALE,
                    f"held test runtime parent changed: {source.path}",
                )
            binding = _DirectoryParentBinding(
                path=source.path,
                fd=descriptor,
                identity=identity,
                policy=policy,
                require_owned_private_parent=source.require_owned_private_parent,
            )
            creation_result_owner.publish_creation_parent(binding)
            descriptor_owner.transfer(descriptor)
            source.revalidate()
        except BaseException:
            if descriptor_owner.state in {"empty", "owned"}:
                descriptor_owner.close()
            elif binding is not None and binding.fd_close_outcome == "owned":
                binding.close()
            raise
    assert binding is not None
    return binding


def _validated_private_runtime_parent(
    raw_path: str,
    *,
    rejection_errors: list[BaseException] | None = None,
) -> pathlib.Path | None:
    result_owner = _DirectoryParentBindingResultOwner()
    try:
        binding = _open_directory_parent(
            raw_path,
            require_owned_private_parent=True,
            result_owner=result_owner,
        )
        result_owner.transfer(binding)
    except (OSError, ValueError) as error:
        preserved = _settle_directory_parent_binding_result_preserving_trigger(
            result_owner,
            error,
        )
        if preserved is error:
            if rejection_errors is not None:
                rejection_errors.append(error)
            return None
        raise preserved
    except BaseException as error:
        preserved = _settle_directory_parent_binding_result_preserving_trigger(
            result_owner,
            error,
        )
        if preserved is error:
            raise
        raise preserved
    try:
        return binding.path
    finally:
        first_close_error: BaseException | None = None
        try:
            result_owner.close()
        except BaseException as close_error:
            first_close_error = close_error
            if not result_owner.settled:
                try:
                    result_owner.close()
                except BaseException as retry_error:
                    _DirectoryParentBindingResultOwner._attach_secondary_error(
                        first_close_error,
                        retry_error,
                    )
        if first_close_error is not None:
            raise first_close_error


def _directory_object_identity_key(metadata: os.stat_result) -> tuple[int, ...]:
    """Return only signals that identify the live directory object.

    Owner, mode, flags, and extended metadata are access-policy signals. They are
    validated separately so benign mode normalization is not misclassified as
    object replacement.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
    )


def _test_entry_object_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind the exact test-created namespace object, not mutable metadata."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
    )


def _remove_exact_test_entry(
    directory_fd: int,
    name: bytes,
    expected_object: tuple[int, ...],
) -> None:
    """Quarantine and unlink only the exact special test fixture object.

    The protected property is object identity. Content, link count, ownership,
    and mode may change without replacing that object and are therefore not
    deletion-authority signals. The random no-replace quarantine is in an
    owner-private test directory; a mismatch is retained for diagnosis rather
    than deleting a same-name replacement.
    """

    if not name or name in {b".", b".."} or b"/" in name or b"\0" in name:
        raise ValueError("test cleanup entry name is unsafe")
    quarantine_name = b".codex-test-entry-quarantine-" + secrets.token_hex(16).encode(
        "ascii"
    )
    rename_noreplace(directory_fd, name, directory_fd, quarantine_name)
    observed = _test_entry_object_identity(
        os.stat(
            quarantine_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    )
    if observed != expected_object:
        raise OSError(
            errno.ESTALE,
            "test cleanup quarantined a replacement object",
        )
    # The final identity proof and unlink are one non-interruptible transaction
    # for the supported current-thread trace/profile/signal threat model. A
    # replacement that wins before entry is retained by the final mismatch.
    with supported_async_publication():
        final_observed = _test_entry_object_identity(
            os.stat(
                quarantine_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        )
        if final_observed != expected_object:
            raise OSError(
                errno.ESTALE,
                "test cleanup quarantine changed before unlink",
            )
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError(
                errno.ESTALE,
                "test cleanup original name reappeared after quarantine",
            )
        os.unlink(quarantine_name, dir_fd=directory_fd)


def _normalize_created_private_directory_mode(
    parent_binding: _DirectoryParentBinding,
    name: bytes,
    child_path: pathlib.Path,
    child_fd: int,
    created_metadata: os.stat_result,
) -> tuple[Identity, tuple[int, ...]]:
    created_object = _directory_object_identity_key(created_metadata)
    descriptor_before = os.fstat(child_fd)
    path_before = os.stat(
        name,
        dir_fd=parent_binding.fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(created_metadata.st_mode)
        or created_metadata.st_uid != os.getuid()
        or _directory_object_identity_key(descriptor_before) != created_object
        or _directory_object_identity_key(path_before) != created_object
    ):
        raise OSError(
            errno.EPERM,
            f"new temporary directory has an unsafe identity: {child_path}",
        )

    os.fchmod(child_fd, 0o700)
    descriptor_after = os.fstat(child_fd)
    path_after = os.stat(
        name,
        dir_fd=parent_binding.fd,
        follow_symlinks=False,
    )
    if (
        _directory_object_identity_key(descriptor_after) != created_object
        or _directory_object_identity_key(path_after) != created_object
    ):
        raise OSError(
            errno.ESTALE,
            f"new temporary directory changed during mode normalization: {child_path}",
        )
    if (
        descriptor_after.st_uid != os.getuid()
        or stat.S_IMODE(descriptor_after.st_mode) != 0o700
        or path_after.st_uid != os.getuid()
        or stat.S_IMODE(path_after.st_mode) != 0o700
    ):
        raise OSError(
            errno.EPERM,
            f"new temporary directory mode was not normalized: {child_path}",
        )
    return identity_from_stat(descriptor_after), created_object


@dataclass(frozen=True, slots=True)
class _PrivateDirectoryCreationRecoveryEvidence:
    stage: str
    parent_path: str
    entry_name: str
    parent_fd: int
    directory_fd: int | None
    parent_identity: Identity
    directory_identity: Identity | None
    directory_object_identity: tuple[int, ...] | None
    observed_identity: Identity | None
    entry_state: str
    trigger_kind: str
    trigger_message: str
    observation_kind: str | None
    observation_message: str | None
    rollback_kind: str | None
    rollback_message: str | None
    protected_property: str = "object-identity"
    access_policy_gate: str = "private-fail-closed"


class _PrivateDirectoryRecoveryCloseError(RuntimeError):
    def __init__(self, errors: tuple[BaseException, ...]) -> None:
        self.errors = errors
        super().__init__("private-directory recovery descriptor close failed")


def _raise_first_private_directory_close_control_flow(
    errors: tuple[BaseException, ...],
) -> None:
    for error in errors:
        if isinstance(error, Exception):
            continue
        secondary = tuple(candidate for candidate in errors if candidate is not error)
        try:
            setattr(
                error,
                "private_directory_secondary_close_errors",
                secondary,
            )
        except BaseException:
            pass
        if secondary:
            try:
                error.add_note(
                    "additional private-directory descriptor close failures: "
                    + "; ".join(
                        f"{type(candidate).__name__}: {candidate}"
                        for candidate in secondary
                    )
                )
            except BaseException:
                pass
        raise error


@dataclass(slots=True)
class _PrivateDirectoryCreationRecovery:
    parent_binding: _DirectoryParentBinding
    name: bytes
    path: pathlib.Path
    directory_fd: int | None
    directory_identity: Identity | None
    directory_object_identity: tuple[int, ...] | None
    observed_identity: Identity | None
    entry_state: str
    retained: bool = True
    directory_fd_close_outcome: str = field(init=False)
    directory_fd_close_error: BaseException | None = field(
        init=False,
        default=None,
    )

    def __post_init__(self) -> None:
        self.directory_fd_close_outcome = (
            "owned" if self.directory_fd is not None else "absent"
        )

    def publish_directory_descriptor(self, descriptor: int) -> None:
        if self.directory_fd is not None or self.directory_fd_close_outcome != "absent":
            raise ValueError(
                "private-directory creation descriptor was already published"
            )
        self.directory_fd = descriptor
        self.directory_fd_close_outcome = "owned"

    def publish_directory_identity(
        self,
        identity: Identity,
        object_identity: tuple[int, ...],
    ) -> None:
        if self.directory_fd is None or self.directory_fd_close_outcome != "owned":
            raise ValueError(
                "private-directory creation descriptor custody is unavailable"
            )
        if (
            self.directory_identity is not None
            or self.directory_object_identity is not None
        ):
            raise ValueError(
                "private-directory creation identity was already published"
            )
        self.directory_identity = identity
        self.directory_object_identity = object_identity

    @property
    def parent_fd(self) -> int:
        return self.parent_binding.fd

    def current_directory_path(self) -> pathlib.Path:
        if self.directory_fd is None or self.directory_object_identity is None:
            raise OSError(
                errno.ENODATA,
                "retained private-directory descriptor identity is unavailable",
                str(self.path),
            )
        if (
            _directory_object_identity_key(os.fstat(self.directory_fd))
            != self.directory_object_identity
        ):
            raise OSError(
                errno.ESTALE,
                "retained private-directory descriptor identity changed",
                str(self.path),
            )
        if sys.platform != "darwin":
            raise OSError(
                errno.ENOTSUP,
                "retained private-directory path recovery is unsupported",
                str(self.path),
            )
        raw = fcntl.fcntl(
            self.directory_fd,
            _DARWIN_F_GETPATH,
            b"\0" * _DARWIN_MAXPATHLEN,
        )
        raw_path, separator, _ = raw.partition(b"\0")
        if not separator or not raw_path or not raw_path.startswith(b"/"):
            raise OSError(
                errno.ESTALE,
                "retained private-directory current path is unavailable",
                str(self.path),
            )
        try:
            decoded = os.fsdecode(raw_path)
            decoded.encode("ascii")
        except (UnicodeDecodeError, UnicodeEncodeError) as error:
            raise OSError(
                errno.ESTALE,
                "retained private-directory current path is not canonical ASCII",
                str(self.path),
            ) from error
        current = pathlib.Path(decoded)
        reopened_owner = RawFdCustody()
        with supported_async_fd_publication(reopened_owner):
            try:
                reopened_fd = os.open(
                    current,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                reopened_owner.publish(reopened_fd)
                if (
                    _directory_object_identity_key(os.fstat(reopened_fd))
                    != self.directory_object_identity
                ):
                    raise OSError(
                        errno.ESTALE,
                        f"retained private-directory current path changed: {current}",
                    )
            finally:
                reopened_owner.close()
        if (
            _directory_object_identity_key(os.fstat(self.directory_fd))
            != self.directory_object_identity
        ):
            raise OSError(
                errno.ESTALE,
                "retained private-directory descriptor identity changed",
                str(self.path),
            )
        return current

    def close_descriptors_for_recovery(self) -> None:
        close_errors: list[BaseException] = []
        descriptor = self.directory_fd
        if descriptor is not None and self.directory_fd_close_outcome == "owned":
            # Retain the descriptor number as recovery evidence until close is
            # known to have returned without interruption. An unproven result
            # is final for this integer and is never retried.
            self.directory_fd_close_outcome = "close-outcome-unproven"
            try:
                os.close(descriptor)
            except BaseException as error:
                self.directory_fd_close_error = error
                try:
                    setattr(
                        error,
                        "private_directory_creation_recovery_close_owner",
                        self,
                    )
                except BaseException:
                    pass
                close_errors.append(error)
            else:
                self.directory_fd = None
                self.directory_fd_close_outcome = "closed"
                self.directory_fd_close_error = None
        try:
            self.parent_binding.close()
        except BaseException as error:
            close_errors.append(error)
            if self.parent_binding.fd_close_outcome == "owned":
                try:
                    self.parent_binding.close()
                except BaseException as retry_error:
                    close_errors.append(retry_error)
        if close_errors:
            failures = tuple(close_errors)
            _raise_first_private_directory_close_control_flow(failures)
            raise _PrivateDirectoryRecoveryCloseError(failures)


class _PrivateDirectoryCreationRetentionRequired(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        recovery: _PrivateDirectoryCreationRecovery,
        evidence: _PrivateDirectoryCreationRecoveryEvidence,
        trigger_error: BaseException,
        observation_error: BaseException | None,
        rollback_error: BaseException | None,
    ) -> None:
        super().__init__(message)
        self.recovery = recovery
        self.evidence = evidence
        self.trigger_error = trigger_error
        self.observation_error = observation_error
        self.rollback_error = rollback_error
        self.retained_resources = [recovery]
        self.recovery_evidence = [evidence]
        self.quarantined_root_recovery_evidence: tuple[
            QuarantinedRootRecoveryEvidence, ...
        ] = (
            quarantined_root_recovery_evidence(rollback_error)
            if rollback_error is not None
            else ()
        )
        self.recovery_evidence.extend(self.quarantined_root_recovery_evidence)

    @property
    def retained_path(self) -> pathlib.Path:
        return self.recovery.path

    def close_descriptors_for_recovery(self) -> None:
        self.recovery.close_descriptors_for_recovery()


@dataclass(frozen=True, slots=True)
class _PrivateDirectoryBindingPublication:
    binding: _DirectoryParentBinding
    descriptor: int


@dataclass(slots=True)
class _PrivateDirectoryCreationResultOwner:
    creation_parent_binding: _DirectoryParentBinding | None = None
    pending: _PrivateDirectoryCreationRecovery | None = None
    retention: _PrivateDirectoryCreationRetentionRequired | None = None
    _binding_publication: _PrivateDirectoryBindingPublication | None = None
    transferred: bool = False
    settled: bool = False

    @property
    def binding(self) -> _DirectoryParentBinding | None:
        publication = self._binding_publication
        return publication.binding if publication is not None else None

    @property
    def binding_descriptor(self) -> int | None:
        publication = self._binding_publication
        return publication.descriptor if publication is not None else None

    def publish_creation_parent(
        self,
        binding: _DirectoryParentBinding,
    ) -> None:
        if self.settled:
            raise ValueError("private-directory creation result owner is settled")
        if self.creation_parent_binding is None:
            self.creation_parent_binding = binding
            return
        if self.creation_parent_binding is not binding:
            raise ValueError("private-directory creation parent owner was rebound")

    def arm_pending(
        self,
        *,
        name: bytes,
        path: pathlib.Path,
    ) -> _PrivateDirectoryCreationRecovery:
        parent_binding = self.creation_parent_binding
        if parent_binding is None:
            raise ValueError("private-directory creation parent is unpublished")
        if self.settled or self.binding is not None or self.retention is not None:
            raise ValueError("private-directory creation result owner is already used")
        if self.pending is not None:
            raise ValueError("private-directory creation is already pending")
        pending = _PrivateDirectoryCreationRecovery(
            parent_binding=parent_binding,
            name=name,
            path=path,
            directory_fd=None,
            directory_identity=None,
            directory_object_identity=None,
            observed_identity=None,
            entry_state="mkdir-outcome-unproven",
        )
        self.pending = pending
        return pending

    def release_collision(self, pending: _PrivateDirectoryCreationRecovery) -> None:
        if self.pending is not pending:
            raise ValueError("private-directory collision owner is inconsistent")
        if pending.directory_fd is not None:
            raise ValueError(
                "private-directory collision unexpectedly owns a descriptor"
            )
        self.pending = None

    def publish_retention(
        self,
        retention: _PrivateDirectoryCreationRetentionRequired,
    ) -> None:
        if self.settled:
            raise ValueError("private-directory creation result owner is settled")
        if self.retention is None:
            if self.pending is not retention.recovery:
                raise ValueError(
                    "private-directory creation retention does not own the pending state"
                )
            self.retention = retention
            return
        if self.retention is not retention:
            raise ValueError("private-directory creation retention was rebound")

    def publish(self, binding: _DirectoryParentBinding) -> None:
        if self.settled:
            raise ValueError("private-directory creation result owner is settled")
        publication = self._binding_publication
        if publication is None:
            # Construct both values before one STORE_ATTR. An interruption can
            # observe either no binding result or the complete descriptor-bound
            # publication, never a binding with an absent descriptor key.
            self._binding_publication = _PrivateDirectoryBindingPublication(
                binding=binding,
                descriptor=binding.fd,
            )
            return
        if publication.binding is not binding:
            raise ValueError("private-directory creation result owner was rebound")

    def owns(self, binding: _DirectoryParentBinding) -> bool:
        return self.binding is binding and not self.settled

    def transfer(
        self,
        binding: _DirectoryParentBinding,
    ) -> _DirectoryParentBinding:
        if self.binding is not binding or self.settled:
            raise ValueError(
                "private-directory creation result transfer is inconsistent"
            )
        self.transferred = True
        return binding

    def retained_creation_for(
        self,
        trigger_error: BaseException,
    ) -> _PrivateDirectoryCreationRetentionRequired | None:
        if self.retention is not None:
            return self.retention
        pending = self.pending
        if pending is None or self.binding is not None or self.settled:
            return None
        entry_state, observed_identity, observation_error = (
            _unbound_creation_entry_state(
                pending.parent_binding,
                pending.name,
            )
        )
        pending.observed_identity = observed_identity
        pending.entry_state = entry_state
        return _retained_private_directory_creation(
            pending=pending,
            result_owner=self,
            trigger_error=trigger_error,
            observation_error=observation_error,
            rollback_error=None,
        )

    def _recoveries(self) -> tuple[_PrivateDirectoryCreationRecovery, ...]:
        recoveries: list[_PrivateDirectoryCreationRecovery] = []
        seen: set[int] = set()
        for recovery in (
            self.pending,
            self.retention.recovery if self.retention is not None else None,
        ):
            if recovery is None or id(recovery) in seen:
                continue
            seen.add(id(recovery))
            recoveries.append(recovery)
        return tuple(recoveries)

    @staticmethod
    def _close_outcome_is_final(outcome: str) -> bool:
        return outcome in {
            "absent",
            "closed",
            "closed-by-result-binding",
            "close-outcome-unproven",
        }

    def _descriptor_settlement_is_final(
        self,
        recoveries: tuple[_PrivateDirectoryCreationRecovery, ...],
    ) -> bool:
        binding_final = self.binding is None or self.binding.fd_close_outcome in {
            "closed",
            "close-outcome-unproven",
        }
        parent_final = (
            self.creation_parent_binding is None
            or self.creation_parent_binding.fd_close_outcome
            in {"closed", "close-outcome-unproven"}
        )
        return (
            binding_final
            and parent_final
            and all(
                self._close_outcome_is_final(recovery.directory_fd_close_outcome)
                and recovery.parent_binding.fd_close_outcome
                in {"closed", "close-outcome-unproven"}
                for recovery in recoveries
            )
        )

    def close_descriptors_for_recovery(self) -> None:
        if self.settled:
            return
        close_errors: list[BaseException] = []
        recoveries = self._recoveries()
        binding = self.binding
        shared_descriptor = self.binding_descriptor
        if binding is not None:
            if binding.fd_close_outcome == "owned":
                if shared_descriptor != binding.fd:
                    raise RuntimeError(
                        "private-directory result binding descriptor is inconsistent"
                    )
                for recovery in recoveries:
                    if (
                        recovery.directory_fd == shared_descriptor
                        and recovery.directory_fd_close_outcome == "owned"
                    ):
                        # Publish shared close ambiguity before entering the
                        # binding close. The binding remains the sole syscall
                        # owner for this integer; recovery never retries it.
                        recovery.directory_fd_close_outcome = "close-outcome-unproven"
                try:
                    binding.close()
                except BaseException as error:
                    close_errors.append(error)
                if binding.fd_close_outcome == "owned":
                    # The first close attempt did not enter the binding's
                    # ambiguity boundary. A still-owned descriptor must be
                    # settled before this owner can become terminal.
                    try:
                        binding.close()
                    except BaseException as error:
                        close_errors.append(error)
            for recovery in recoveries:
                if recovery.directory_fd != shared_descriptor:
                    continue
                if binding.fd_close_outcome == "closed":
                    recovery.directory_fd = None
                    recovery.directory_fd_close_outcome = "closed-by-result-binding"
                    recovery.directory_fd_close_error = None
                elif binding.fd_close_outcome == "close-outcome-unproven":
                    recovery.directory_fd_close_outcome = "close-outcome-unproven"
                    recovery.directory_fd_close_error = binding.fd_close_error

        for recovery in recoveries:
            try:
                recovery.close_descriptors_for_recovery()
            except BaseException as error:
                close_errors.append(error)

        parent_binding = self.creation_parent_binding
        if parent_binding is not None and not any(
            recovery.parent_binding is parent_binding for recovery in recoveries
        ):
            try:
                parent_binding.close()
            except BaseException as error:
                close_errors.append(error)
                if parent_binding.fd_close_outcome == "owned":
                    try:
                        parent_binding.close()
                    except BaseException as retry_error:
                        close_errors.append(retry_error)

        self.settled = self._descriptor_settlement_is_final(recoveries)
        if close_errors:
            failures = tuple(close_errors)
            _raise_first_private_directory_close_control_flow(failures)
            if len(failures) == 1:
                raise failures[0]
            raise _PrivateDirectoryRecoveryCloseError(failures)


def _settle_private_directory_result_owner_preserving_trigger(
    result_owner: _PrivateDirectoryCreationResultOwner,
    trigger_error: BaseException,
) -> BaseException:
    """Settle every descriptor without replacing an earlier control flow.

    The trigger remains authoritative when it is already a control-flow
    exception. A later close-time control flow outranks an ordinary trigger.
    Ordinary close failures are attached to the preserved trigger together
    with the owner whose terminal states record whether each integer was
    closed or became ambiguous; an ambiguous close is never retried.
    """

    try:
        result_owner.close_descriptors_for_recovery()
    except BaseException as close_error:
        preserved = (
            close_error
            if isinstance(trigger_error, Exception)
            and not isinstance(close_error, Exception)
            else trigger_error
        )
        try:
            setattr(
                preserved,
                "private_directory_result_settlement_owner",
                result_owner,
            )
            setattr(
                preserved,
                "private_directory_result_settlement_error",
                close_error,
            )
        except BaseException:
            pass
        try:
            preserved.add_note(
                "private-directory result descriptor settlement also failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        except BaseException:
            pass
        return preserved
    return trigger_error


def _unbound_creation_entry_state(
    parent_binding: _DirectoryParentBinding,
    name: bytes,
) -> tuple[str, Identity | None, BaseException | None]:
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_binding.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return "missing", None, None
    except BaseException as error:
        return "unreadable", None, error
    return "present-unbound", identity_from_stat(metadata), None


def _retained_private_directory_creation(
    *,
    pending: _PrivateDirectoryCreationRecovery,
    result_owner: _PrivateDirectoryCreationResultOwner,
    trigger_error: BaseException,
    observation_error: BaseException | None,
    rollback_error: BaseException | None,
) -> _PrivateDirectoryCreationRetentionRequired:
    if result_owner.pending is not pending:
        raise ValueError("private-directory creation pending owner is inconsistent")
    observation_detail = (
        "none"
        if observation_error is None
        else f"{type(observation_error).__name__}: {observation_error}"
    )
    rollback_detail = (
        "none"
        if rollback_error is None
        else f"{type(rollback_error).__name__}: {rollback_error}"
    )
    evidence = _PrivateDirectoryCreationRecoveryEvidence(
        stage=(
            "private-directory-creation-pending"
            if pending.directory_identity is None
            else "private-directory-creation-rollback"
        ),
        parent_path=str(pending.parent_binding.path),
        entry_name=os.fsdecode(pending.name),
        parent_fd=pending.parent_binding.fd,
        directory_fd=pending.directory_fd,
        parent_identity=pending.parent_binding.identity,
        directory_identity=pending.directory_identity,
        directory_object_identity=pending.directory_object_identity,
        observed_identity=pending.observed_identity,
        entry_state=pending.entry_state,
        trigger_kind=type(trigger_error).__name__,
        trigger_message=str(trigger_error),
        observation_kind=(
            type(observation_error).__name__ if observation_error is not None else None
        ),
        observation_message=(
            str(observation_error) if observation_error is not None else None
        ),
        rollback_kind=(
            type(rollback_error).__name__ if rollback_error is not None else None
        ),
        rollback_message=(str(rollback_error) if rollback_error is not None else None),
    )
    retained = _PrivateDirectoryCreationRetentionRequired(
        "private-directory creation custody was retained: "
        f"trigger={type(trigger_error).__name__}: {trigger_error}; "
        f"observation={observation_detail}; "
        f"rollback={rollback_detail}",
        recovery=pending,
        evidence=evidence,
        trigger_error=trigger_error,
        observation_error=observation_error,
        rollback_error=rollback_error,
    )
    result_owner.publish_retention(retained)
    if rollback_error is None:
        retained.add_note(
            "descriptor-bound rollback was not attempted without a bound "
            "directory identity"
        )
    return retained


def _create_bound_owned_private_directory(
    parent: pathlib.Path,
    prefix: str,
    *,
    result_owner: _PrivateDirectoryCreationResultOwner,
    require_owned_private_parent: bool = True,
    held_parent_binding: _DirectoryParentBinding | None = None,
) -> _DirectoryParentBinding:
    if not isinstance(result_owner, _PrivateDirectoryCreationResultOwner):
        raise TypeError("private-directory creation result owner is required")
    if (
        result_owner.creation_parent_binding is not None
        or result_owner.pending is not None
        or result_owner.retention is not None
        or result_owner.binding is not None
        or result_owner.transferred
        or result_owner.settled
    ):
        raise ValueError("private-directory creation result owner is already used")
    try:
        raw_prefix = prefix.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("temporary-directory prefix must be ASCII") from error
    if (
        not raw_prefix
        or len(raw_prefix) > 160
        or b"/" in raw_prefix
        or b"\0" in raw_prefix
        or raw_prefix in {b".", b".."}
    ):
        raise ValueError("temporary-directory prefix is unsafe")

    if held_parent_binding is None:
        parent_result_owner = _DirectoryParentBindingResultOwner()
        try:
            parent_binding = _open_directory_parent(
                parent,
                require_owned_private_parent=require_owned_private_parent,
                result_owner=parent_result_owner,
            )
            parent_result_owner.transfer(parent_binding)
            result_owner.publish_creation_parent(parent_binding)
        except BaseException as error:
            trigger_error = error
            published_parent = parent_result_owner.binding
            if published_parent is not None:
                try:
                    result_owner.publish_creation_parent(published_parent)
                except BaseException as publication_error:
                    error = _settle_directory_parent_binding_result_preserving_trigger(
                        parent_result_owner,
                        error,
                    )
                    error, secondary = _prefer_control_flow_error(
                        error,
                        publication_error,
                    )
                    _DirectoryParentBindingResultOwner._attach_secondary_error(
                        error,
                        secondary,
                    )
                else:
                    raise
            preserved = _settle_directory_parent_binding_result_preserving_trigger(
                parent_result_owner,
                error,
            )
            if preserved is trigger_error:
                raise
            raise preserved from trigger_error
    else:
        if (
            parent != held_parent_binding.path
            or require_owned_private_parent
            != held_parent_binding.require_owned_private_parent
        ):
            raise ValueError("held temporary-directory parent is inconsistent")
        parent_binding = _duplicate_directory_parent(
            held_parent_binding,
            creation_result_owner=result_owner,
        )
    for _ in range(128):
        name = raw_prefix + secrets.token_hex(16).encode("ascii")
        child_path = parent_binding.path / os.fsdecode(name)
        parent_binding.revalidate()
        pending = result_owner.arm_pending(name=name, path=child_path)
        child_fd: int | None = None
        child_identity: Identity | None = None
        child_fd_acquisition_owner = RawFdCustody()
        try:
            os.mkdir(name, 0o700, dir_fd=parent_binding.fd)
        except FileExistsError:
            result_owner.release_collision(pending)
            continue
        except BaseException as error:
            entry_state, observed_identity, observation_error = (
                _unbound_creation_entry_state(parent_binding, name)
            )
            pending.observed_identity = observed_identity
            pending.entry_state = entry_state
            retained = _retained_private_directory_creation(
                pending=pending,
                result_owner=result_owner,
                trigger_error=error,
                observation_error=observation_error,
                rollback_error=None,
            )
            raise retained from (observation_error or error)
        try:
            created_metadata = os.stat(
                name,
                dir_fd=parent_binding.fd,
                follow_symlinks=False,
            )
            with supported_async_fd_publication(child_fd_acquisition_owner):
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=parent_binding.fd,
                    )
                    child_fd_acquisition_owner.publish(child_fd)
                    pending.publish_directory_descriptor(child_fd)
                    child_fd_acquisition_owner.transfer(child_fd)
                except BaseException:
                    if (
                        child_fd is not None
                        and pending.directory_fd == child_fd
                        and pending.directory_fd_close_outcome == "owned"
                        and child_fd_acquisition_owner.state == "owned"
                    ):
                        # Pending recovery was published first and is now the
                        # durable syscall owner for this integer.
                        child_fd_acquisition_owner.transfer(child_fd)
                    elif child_fd_acquisition_owner.state in {"empty", "owned"}:
                        child_fd_acquisition_owner.close()
                    raise
            child_identity, child_object_identity = (
                _normalize_created_private_directory_mode(
                    parent_binding,
                    name,
                    child_path,
                    child_fd,
                    created_metadata,
                )
            )
            pending.publish_directory_identity(
                child_identity,
                child_object_identity,
            )
            os.fsync(parent_binding.fd)
            parent_binding.revalidate()
            child_policy = validate_directory_policy_fd(
                child_fd,
                child_path,
                private=True,
            )
            parent_binding.revalidate()
            path_owner = FdIdentityCustody()
            with supported_async_fd_publication(path_owner):
                try:
                    path_result = open_absolute_directory_chain(
                        child_path,
                        private_leaf=True,
                        allow_sticky_writable_ancestors=(
                            not require_owned_private_parent
                        ),
                    )
                    path_owner.publish(path_result)
                    path_fd, path_identity = path_result
                    path_policy = validate_directory_policy_fd(
                        path_fd,
                        child_path,
                        private=True,
                    )
                    if (
                        not directory_identities_match(
                            child_identity,
                            path_identity,
                        )
                        or child_policy != path_policy
                    ):
                        raise OSError(
                            errno.ESTALE,
                            "temporary-directory path identity or access policy changed",
                        )
                finally:
                    path_owner.close()
            binding = _DirectoryParentBinding(
                path=child_path,
                fd=child_fd,
                identity=child_identity,
                policy=child_policy,
                require_owned_private_parent=require_owned_private_parent,
            )
            binding.revalidate()
            result_owner.publish(binding)
            if not result_owner.owns(binding):
                raise RuntimeError(
                    "private-directory creation result ownership was not published"
                )
            return binding
        except BaseException as error:
            published = result_owner.binding
            if published is not None:
                if child_fd is not None and published.fd != child_fd:
                    raise RuntimeError(
                        "private-directory creation result owner was rebound"
                    ) from error
                raise
            if child_fd is None or child_identity is None:
                entry_state, observed_identity, observation_error = (
                    _unbound_creation_entry_state(parent_binding, name)
                )
                pending.observed_identity = observed_identity
                pending.entry_state = entry_state
                retained = _retained_private_directory_creation(
                    pending=pending,
                    result_owner=result_owner,
                    trigger_error=error,
                    observation_error=observation_error,
                    rollback_error=None,
                )
                raise retained from (observation_error or error)
            try:
                quarantine_and_remove_empty_root(
                    RootSpec(
                        label="readonly-install-private-directory-creation",
                        parent_fd=parent_binding.fd,
                        parent_identity=parent_binding.identity,
                        name=name,
                        expected_identity=child_identity,
                        private_metadata=True,
                    ),
                    child_fd,
                )
            except BaseException as rollback_error:
                pending.entry_state = "rollback-unproven"
                retained = _retained_private_directory_creation(
                    pending=pending,
                    result_owner=result_owner,
                    trigger_error=error,
                    observation_error=None,
                    rollback_error=rollback_error,
                )
                raise retained from rollback_error
            pending.entry_state = "rollback-complete"
            preserved = _settle_private_directory_result_owner_preserving_trigger(
                result_owner,
                error,
            )
            if preserved is not error:
                raise preserved from error
            raise
    result_owner.close_descriptors_for_recovery()
    raise FileExistsError("temporary-directory name collision limit reached")


def _create_owned_private_directory(
    parent: pathlib.Path,
    prefix: str,
    *,
    result_owner: _PrivateDirectoryCreationResultOwner,
    require_owned_private_parent: bool = True,
    held_parent_binding: _DirectoryParentBinding | None = None,
) -> pathlib.Path:
    if not isinstance(result_owner, _PrivateDirectoryCreationResultOwner):
        raise TypeError("private-directory creation result owner is required")
    binding = _create_bound_owned_private_directory(
        parent,
        prefix,
        result_owner=result_owner,
        require_owned_private_parent=require_owned_private_parent,
        held_parent_binding=held_parent_binding,
    )
    result_owner.transfer(binding)
    return binding.path


def _rollback_unstored_owned_private_directory(
    result_owner: _PrivateDirectoryCreationResultOwner,
    trigger_error: BaseException,
) -> BaseException:
    retained = result_owner.retention
    if retained is not None:
        return retained
    binding = result_owner.binding
    pending = result_owner.pending
    if binding is None or pending is None:
        retained = result_owner.retained_creation_for(trigger_error)
        if retained is not None:
            return retained
        result_owner.close_descriptors_for_recovery()
        return trigger_error
    try:
        quarantine_and_remove_empty_root(
            RootSpec(
                label="readonly-install-private-directory-result-store",
                parent_fd=pending.parent_binding.fd,
                parent_identity=pending.parent_binding.identity,
                name=pending.name,
                expected_identity=binding.identity,
                private_metadata=True,
            ),
            binding.fd,
        )
    except BaseException as rollback_error:
        pending.entry_state = "rollback-unproven"
        return _retained_private_directory_creation(
            pending=pending,
            result_owner=result_owner,
            trigger_error=trigger_error,
            observation_error=None,
            rollback_error=rollback_error,
        )
    pending.entry_state = "rollback-complete"
    return _settle_private_directory_result_owner_preserving_trigger(
        result_owner,
        trigger_error,
    )


def _private_runtime_parent() -> pathlib.Path:
    explicit_parent = os.environ.get(_EXPLICIT_RUNTIME_PARENT_ENV)
    if explicit_parent is not None:
        rejection_errors: list[BaseException] = []
        validated = _validated_private_runtime_parent(
            explicit_parent,
            rejection_errors=rejection_errors,
        )
        if validated is None:
            rejection = rejection_errors[0] if rejection_errors else None
            rejection_detail = ""
            if rejection is not None:
                rejection_errno = getattr(rejection, "errno", None)
                rejection_detail = (
                    f" ({type(rejection).__name__}, errno={rejection_errno}: "
                    f"{rejection})"
                )
            raise RuntimeError(
                f"{_EXPLICIT_RUNTIME_PARENT_ENV} is not a trusted private "
                f"test runtime parent{rejection_detail}"
            )
        return validated

    account_home = pwd.getpwuid(os.getuid()).pw_dir
    # Shared OS runtime roots have unrelated metadata churn that invalidates
    # executable path-identity checks while a fixture is under authentication.
    candidates = (
        *_repository_runtime_candidates(),
        account_home,
        os.environ.get("XDG_RUNTIME_DIR"),
        os.environ.get("TMPDIR"),
    )
    for raw_path in candidates:
        if raw_path and (parent := _validated_private_runtime_parent(raw_path)):
            return parent
    raise RuntimeError("no trusted private test runtime parent is available")


def _repository_runtime_candidates() -> tuple[str, ...]:
    git = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
    if git is None:
        return ()
    environment = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    try:
        result = subprocess.run(
            (
                git,
                "-C",
                str(pathlib.Path(__file__).resolve().parent),
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
                "--git-common-dir",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0 or len(result.stdout) > 8192:
        return ()
    try:
        checkout_text, common_text = result.stdout.decode("utf-8").splitlines()
    except (UnicodeDecodeError, ValueError):
        return ()
    checkout = pathlib.Path(checkout_text)
    common_dir = pathlib.Path(common_text)
    candidates = [str(checkout.parent)]
    if common_dir.name == ".git":
        candidates.append(str(common_dir.parent.parent))
    return tuple(dict.fromkeys(candidates))


@dataclass(slots=True)
class _RuntimeRootCleanupOwner:
    state: str = "live"
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _RuntimeRootState:
    pid: int
    path: pathlib.Path
    result_owner: _PrivateDirectoryCreationResultOwner
    binding: _DirectoryParentBinding
    cleanup_owner: _RuntimeRootCleanupOwner
    protected_property: str = "object-identity-and-private-access-policy"


_RUNTIME_ROOT_STATE: _RuntimeRootState | None = None
_RUNTIME_ROOT_LOCK = threading.RLock()
_RUNTIME_ROOT_LOCK_PID = os.getpid()
_RUNTIME_ROOT_REENTRY = threading.local()
_RUNTIME_ROOT_CONTEXT_SCAN_LIMIT = 64
_RUNTIME_ROOT_TRACEBACK_SCAN_LIMIT = 256


def _pid_aware_runtime_root_lock() -> threading.RLock:
    global _RUNTIME_ROOT_LOCK, _RUNTIME_ROOT_LOCK_PID

    current_pid = os.getpid()
    if _RUNTIME_ROOT_LOCK_PID != current_pid:
        # A lock held by a vanished parent thread must never be acquired in the
        # fork child. Only the forking thread exists at this point, so replacing
        # the pair before new child threads can start is sufficient.
        _RUNTIME_ROOT_LOCK = threading.RLock()
        _RUNTIME_ROOT_LOCK_PID = current_pid
    return _RUNTIME_ROOT_LOCK


def _retain_runtime_root_failure(
    error: BaseException,
    state: _RuntimeRootState,
) -> None:
    try:
        setattr(error, "runtime_root_state_owner", state)
        resources = getattr(error, "retained_resources", None)
        if not isinstance(resources, list):
            resources = []
            setattr(error, "retained_resources", resources)
        if not any(resource is state for resource in resources):
            resources.append(state)
    except BaseException:
        pass


def _root_spec_for_creation_owner(
    *,
    label: str,
    result_owner: _PrivateDirectoryCreationResultOwner,
    binding: _DirectoryParentBinding,
) -> RootSpec:
    pending = result_owner.pending
    if (
        pending is None
        or result_owner.binding is not binding
        or pending.directory_identity is None
        or pending.name != os.fsencode(binding.path.name)
    ):
        raise RuntimeError("private-directory lifetime owner is inconsistent")
    return RootSpec(
        label=label,
        parent_fd=pending.parent_binding.fd,
        parent_identity=pending.parent_binding.identity,
        name=pending.name,
        expected_identity=binding.identity,
        private_metadata=True,
    )


def _cleanup_process_runtime_root(state: _RuntimeRootState) -> None:
    """Remove only the exact empty runtime-root object held by ``state``."""

    global _RUNTIME_ROOT_STATE

    if os.getpid() != state.pid or state.cleanup_owner.state == "settled":
        return
    cleanup_owner = state.cleanup_owner
    if cleanup_owner.state == "remove-outcome-unproven":
        error = RuntimeError("process runtime-root removal outcome is unproven")
        cleanup_owner.error = error
        _retain_runtime_root_failure(error, state)
        raise error
    if cleanup_owner.state == "live":
        try:
            state.binding.revalidate()
            spec = _root_spec_for_creation_owner(
                label="test-process-runtime-root",
                result_owner=state.result_owner,
                binding=state.binding,
            )
            cleanup_owner.state = "remove-outcome-unproven"
            quarantine_and_remove_empty_root(spec, state.binding.fd)
            cleanup_owner.state = "removed"
        except BaseException as error:
            cleanup_owner.error = error
            _retain_runtime_root_failure(error, state)
            raise

    if _RUNTIME_ROOT_STATE is state:
        _RUNTIME_ROOT_STATE = None
    try:
        state.result_owner.close_descriptors_for_recovery()
    except BaseException as error:
        cleanup_owner.error = error
        _retain_runtime_root_failure(error, state)
        raise
    cleanup_owner.state = "settled"


def _rollback_runtime_root_registration(
    *,
    state: _RuntimeRootState,
    callback: functools.partial[None],
    trigger_error: BaseException,
) -> BaseException:
    recovered = _rollback_unstored_owned_private_directory(
        state.result_owner,
        trigger_error,
    )
    if recovered is not trigger_error:
        # The exact object was not proved removed. Keep the registered callback
        # together with the retained owner so a later process-exit attempt still
        # has custody; unregistering first would strand the live root.
        _retain_runtime_root_failure(recovered, state)
        try:
            setattr(recovered, "runtime_root_registration_callback", callback)
        except BaseException:
            pass
        return recovered
    try:
        atexit.unregister(callback)
    except BaseException as unregister_error:
        preserved = (
            unregister_error
            if isinstance(trigger_error, Exception)
            and not isinstance(unregister_error, Exception)
            else trigger_error
        )
        _retain_runtime_root_failure(preserved, state)
        try:
            setattr(
                preserved,
                "runtime_root_registration_unregister_error",
                unregister_error,
            )
        except BaseException:
            pass
        return preserved
    return trigger_error


@dataclass(slots=True)
class _RuntimeRootReentryCleanup:
    """Settle one published reentry marker under the bounded async contract.

    The protected properties are the exact invocation-body exception object,
    the exact published runtime-root state object, and terminal removal of this
    invocation's thread-local marker. Traceback membership is retained only as
    diagnostic evidence; it never grants ownership because a hook raised from
    the core frame has the same membership.

    One trace callback and one profile callback may each interrupt a different
    unguarded boundary. The settlement driver retries until the marker owner is
    terminal, then delivers the error selected by this owner. Re-armed hooks,
    ``PyThreadState_SetAsyncExc``, and signals outside
    ``supported_async_publication`` remain outside this bounded contract.
    """

    current_pid: int
    local_error_frame: FrameType | None = None
    invocation_body_error: BaseException | None = None
    local_active_error: BaseException | None = None
    clear_error: BaseException | None = None
    published_state: _RuntimeRootState | None = None
    marker_state: str = "absent"
    boundary_errors: tuple[BaseException, ...] = ()
    handoff_state: str = "settling"
    _delivery_error: BaseException | None = None
    _delivery_generation: int = 0

    def bind_local_error_frame(self, frame: FrameType) -> None:
        """Bind this cleanup owner to its exact core invocation frame."""

        if not isinstance(frame, FrameType):
            raise TypeError("runtime-root local-error frame must be exact")
        with supported_async_publication():
            if self.local_error_frame is not None:
                raise RuntimeError("runtime-root local-error frame is already bound")
            self.local_error_frame = frame

    def publish_invocation_body_error(self, error: BaseException) -> None:
        """Publish the exact caught body object and active-error claim together."""

        with supported_async_publication():
            if (
                self.invocation_body_error is not None
                and self.invocation_body_error is not error
            ):
                raise RuntimeError("runtime-root invocation body owner was rebound")
            if (
                self.local_active_error is not None
                and self.local_active_error is not error
            ):
                raise RuntimeError("runtime-root active error owner was rebound")
            self.invocation_body_error = error
            self.local_active_error = error
            try:
                setattr(error, "runtime_root_reentry_cleanup_owner", self)
            except BaseException:
                pass

    def publish_marker(self) -> None:
        """Publish this invocation's reentry marker and owner state together."""

        with supported_async_publication():
            if getattr(_RUNTIME_ROOT_REENTRY, "pid", None) == self.current_pid:
                raise RuntimeError(
                    "same-thread process runtime-root initialization reentry"
                )
            _RUNTIME_ROOT_REENTRY.cleanup_owner = self
            _RUNTIME_ROOT_REENTRY.pid = self.current_pid
            self.marker_state = "published"

    def publish_runtime_state(self, state: _RuntimeRootState) -> None:
        """Commit the exact live state to its owner and the process global."""

        global _RUNTIME_ROOT_STATE

        with supported_async_publication():
            if state.pid != self.current_pid:
                raise RuntimeError("runtime-root state owner has a foreign PID")
            if self.published_state is not None and self.published_state is not state:
                raise RuntimeError("runtime-root state owner was rebound")
            if _RUNTIME_ROOT_STATE is not None and _RUNTIME_ROOT_STATE is not state:
                raise RuntimeError("runtime-root global state was rebound")
            self.published_state = state
            _RUNTIME_ROOT_STATE = state

    def retain_published_state(self, error: BaseException) -> None:
        """Attach exact cleanup/state owner evidence to an escaping exception."""

        try:
            setattr(error, "runtime_root_reentry_cleanup_owner", self)
        except BaseException:
            pass
        state = self.published_state
        if state is not None:
            _retain_runtime_root_failure(error, state)

    def _traceback_contains_local_error_frame(self, error: BaseException) -> bool:
        local_error_frame = self.local_error_frame
        if local_error_frame is None:
            return False
        try:
            traceback = error.__traceback__
        except BaseException:
            return False
        seen: set[int] = set()
        for _depth in range(_RUNTIME_ROOT_TRACEBACK_SCAN_LIMIT):
            if traceback is None:
                return False
            traceback_id = id(traceback)
            if traceback_id in seen:
                return False
            seen.add(traceback_id)
            try:
                if traceback.tb_frame is local_error_frame:
                    return True
                traceback = traceback.tb_next
            except BaseException:
                return False
        return False

    def is_verified_local_active_error(self, error: BaseException) -> bool:
        """Return whether ``error`` is this invocation's exact body object."""

        return error is self.invocation_body_error

    def recover_local_active_error(self, boundary_error: BaseException) -> None:
        """Recover only the invocation-owned body object, never a traceback peer."""

        invocation_body_error = self.invocation_body_error
        if invocation_body_error is None:
            return
        if self.local_active_error is not invocation_body_error:
            raise RuntimeError("runtime-root active error owner is inconsistent")
        if boundary_error is not invocation_body_error:
            self.capture(boundary_error)

    def capture(self, error: BaseException) -> None:
        """Record one independently delivered settlement-boundary error."""

        with supported_async_publication():
            try:
                setattr(error, "runtime_root_reentry_cleanup_owner", self)
            except BaseException:
                pass
            if not any(candidate is error for candidate in self.boundary_errors):
                self.boundary_errors = (*self.boundary_errors, error)
            if self.clear_error is None:
                self.clear_error = error
                return
            primary, secondary = _prefer_control_flow_error(self.clear_error, error)
            self.clear_error = primary
        try:
            primary.add_note(
                "runtime-root reentry-marker cleanup also failed: "
                f"{type(secondary).__name__}: {secondary}"
            )
        except BaseException:
            pass

    def capture_boundary(self, boundary_error: BaseException) -> None:
        if (
            boundary_error is not self.local_active_error
            and boundary_error is not self.invocation_body_error
            and boundary_error is not self.clear_error
        ):
            self.capture(boundary_error)

    @property
    def marker_cleared(self) -> bool:
        """Return whether this owner's marker has reached its terminal state."""

        return (
            self.marker_state == "cleared"
            and getattr(_RUNTIME_ROOT_REENTRY, "cleanup_owner", None) is not self
        )

    def clear(self) -> None:
        """Retry once-delivered supported interruptions until the marker clears.

        The caller constructs this settlement and establishes its handler before
        marker publication. That longer-lived boundary covers this method's own
        CPython loop/try NOPs. Re-armed hooks and repeated independent signals
        remain outside the bounded contract.
        """

        while not self.marker_cleared:
            try:
                marker_error: BaseException | None = None
                with supported_async_publication():
                    current_error = sys.exception()
                    if isinstance(current_error, BaseException):
                        self.recover_local_active_error(current_error)
                    marker_pid = getattr(_RUNTIME_ROOT_REENTRY, "pid", None)
                    marker_owner = getattr(
                        _RUNTIME_ROOT_REENTRY,
                        "cleanup_owner",
                        None,
                    )
                    if marker_owner is self:
                        if marker_pid != self.current_pid:
                            marker_error = RuntimeError(
                                "runtime-root marker owner has a mismatched PID"
                            )
                        elif hasattr(_RUNTIME_ROOT_REENTRY, "pid"):
                            del _RUNTIME_ROOT_REENTRY.pid
                        del _RUNTIME_ROOT_REENTRY.cleanup_owner
                    elif self.marker_state == "published":
                        marker_error = RuntimeError(
                            "runtime-root marker object identity changed"
                        )
                    self.local_error_frame = None
                    self.marker_state = "cleared"
                if marker_error is not None:
                    raise marker_error
            except BaseException as error:
                self.capture(error)

    def _arm_delivery(self, error: BaseException) -> None:
        """Publish terminal owner evidence and one exact delivery identity."""

        with supported_async_publication():
            self._validate_handoff_ready()
            try:
                setattr(error, "runtime_root_reentry_cleanup_owner", self)
            except BaseException:
                pass
            state = self.published_state
            if state is not None:
                _retain_runtime_root_failure(error, state)
            self.handoff_state = "ready-for-caller"
            self._delivery_error = error
            self._delivery_generation += 1

    def _validate_handoff_ready(self) -> None:
        if not self.marker_cleared:
            raise RuntimeError("runtime-root marker is not terminal before handoff")
        if (
            self.invocation_body_error is not None
            and self.local_active_error is not self.invocation_body_error
        ):
            raise RuntimeError("runtime-root body provenance is not terminal")
        state = self.published_state
        if state is not None and _RUNTIME_ROOT_STATE is not state:
            raise RuntimeError("runtime-root state custody is not terminal")

    def publish_successful_handoff(self) -> None:
        """Publish a no-error handoff after all protected properties settle."""

        with supported_async_publication():
            self._validate_handoff_ready()
            self.handoff_state = "ready-for-caller"

    def is_armed_delivery(
        self,
        error: BaseException,
        *,
        after_generation: int,
    ) -> bool:
        return (
            self._delivery_generation > after_generation
            and self._delivery_error is error
        )

    def finish(self, *, resume_active: bool) -> None:
        clear_error = self.clear_error
        active_error = self.local_active_error
        if clear_error is None:
            if not resume_active and active_error is not None:
                self._arm_delivery(active_error)
                raise active_error
            return
        if active_error is None:
            self._arm_delivery(clear_error)
            raise clear_error
        primary, secondary = _prefer_control_flow_error(
            active_error,
            clear_error,
        )
        try:
            primary.add_note(
                "runtime-root reentry-marker cleanup also failed: "
                f"{type(secondary).__name__}: {secondary}"
            )
        except BaseException:
            pass
        if primary is clear_error:
            self._arm_delivery(clear_error)
            raise clear_error from active_error
        if not resume_active:
            self._arm_delivery(active_error)
            raise active_error from clear_error


def _drive_runtime_root_reentry_cleanup(
    cleanup: _RuntimeRootReentryCleanup,
    *,
    resume_active: bool,
) -> None:
    """Settle marker ownership before delivering the owner's selected error."""

    pending_boundary_error: BaseException | None = None
    while True:
        if pending_boundary_error is not None:
            boundary_error = pending_boundary_error
            pending_boundary_error = None
            try:
                cleanup.capture_boundary(boundary_error)
            except BaseException as capture_error:
                pending_boundary_error = capture_error
                continue

        delivery_generation = cleanup._delivery_generation
        try:
            current_error = sys.exception()
            if isinstance(current_error, BaseException):
                cleanup.recover_local_active_error(current_error)
            if not cleanup.marker_cleared:
                cleanup.clear()
                continue
            cleanup.finish(resume_active=resume_active)
            cleanup.publish_successful_handoff()
            return
        except BaseException as delivery_error:
            if cleanup.is_armed_delivery(
                delivery_error,
                after_generation=delivery_generation,
            ):
                raise
            pending_boundary_error = delivery_error


def _settle_runtime_root_owner_boundary(
    cleanup: _RuntimeRootReentryCleanup,
) -> None:
    """Retry the owner driver across one trace and one profile call boundary."""

    pending_boundary_error: BaseException | None = None
    while True:
        if pending_boundary_error is not None:
            boundary_error = pending_boundary_error
            pending_boundary_error = None
            try:
                cleanup.capture_boundary(boundary_error)
            except BaseException as capture_error:
                pending_boundary_error = capture_error
                continue

        delivery_generation = cleanup._delivery_generation
        try:
            _drive_runtime_root_reentry_cleanup(
                cleanup,
                resume_active=False,
            )
            return
        except BaseException as delivery_error:
            if cleanup.is_armed_delivery(
                delivery_error,
                after_generation=delivery_generation,
            ):
                raise
            pending_boundary_error = delivery_error


def _initialize_process_runtime_root_core(
    current_pid: int,
    cleanup: _RuntimeRootReentryCleanup,
) -> _RuntimeRootState:
    """Run the exact initialization body used as local-error provenance."""

    global _RUNTIME_ROOT_STATE

    # Bind the caller-precreated owner before marker publication or resource
    # acquisition. An interruption before this protected store has no cleanup
    # side effect to settle and propagates directly.
    cleanup.bind_local_error_frame(sys._getframe())
    result_owner = _PrivateDirectoryCreationResultOwner()
    state: _RuntimeRootState | None = None
    callback: functools.partial[None] | None = None
    try:
        # A supported interruption before this guard may initialize the state
        # reentrantly, but it cannot leave a half-published marker. Recheck both
        # the marker and global state after entering.
        cleanup.publish_marker()
        reentrant_state = _RUNTIME_ROOT_STATE
        if reentrant_state is not None:
            if reentrant_state.pid != current_pid:
                raise RuntimeError("runtime-root reentry published a foreign PID")
            cleanup.publish_runtime_state(reentrant_state)
            reentrant_state.binding.revalidate()
            return reentrant_state
        binding = _create_bound_owned_private_directory(
            _private_runtime_parent(),
            ".codex-review-tests-",
            result_owner=result_owner,
        )
        result_owner.transfer(binding)
        state = _RuntimeRootState(
            pid=current_pid,
            path=binding.path,
            result_owner=result_owner,
            binding=binding,
            cleanup_owner=_RuntimeRootCleanupOwner(),
        )
        callback = functools.partial(_cleanup_process_runtime_root, state)
        atexit.register(callback)
        # Publish the exact state object to the invocation owner and process
        # global in one supported transaction. A hook at the subsequent return
        # can therefore recover and retain that same live owner.
        cleanup.publish_runtime_state(state)
        return state
    except BaseException as error:
        published_state = cleanup.published_state
        if published_state is not None and _RUNTIME_ROOT_STATE is published_state:
            _retain_runtime_root_failure(error, published_state)
            raise
        # This object-identity publication is the sole authority for a failed
        # initialization body. A hook raised later from this same core frame is
        # only a boundary error, even though its traceback also contains the
        # bound frame.
        cleanup.publish_invocation_body_error(error)
        if state is not None and callback is not None:
            recovered = _rollback_runtime_root_registration(
                state=state,
                callback=callback,
                trigger_error=error,
            )
        else:
            recovered = _rollback_unstored_owned_private_directory(
                result_owner,
                error,
            )
        if recovered is error:
            raise
        raise recovered from error


def _initialize_process_runtime_root_locked(
    current_pid: int,
    cleanup: _RuntimeRootReentryCleanup,
) -> _RuntimeRootState:
    resume_owned_active = False
    try:
        try:
            return _initialize_process_runtime_root_core(current_pid, cleanup)
        except BaseException as local_active_error:
            cleanup.recover_local_active_error(local_active_error)
            cleanup.retain_published_state(local_active_error)
            resume_owned_active = cleanup.is_verified_local_active_error(
                local_active_error
            )
            raise
    finally:
        _drive_runtime_root_reentry_cleanup(
            cleanup,
            resume_active=resume_owned_active,
        )


def _process_runtime_root_state_owned(
    current_pid: int,
    cleanup: _RuntimeRootReentryCleanup,
) -> _RuntimeRootState:
    global _RUNTIME_ROOT_STATE

    lock = _pid_aware_runtime_root_lock()
    with lock:
        cached = _RUNTIME_ROOT_STATE
        if cached is not None and cached.pid != current_pid:
            try:
                cached.result_owner.close_descriptors_for_recovery()
            except BaseException as error:
                _retain_runtime_root_failure(error, cached)
                raise
            _RUNTIME_ROOT_STATE = None
            cached = None
        if cached is not None:
            cleanup.publish_runtime_state(cached)
            cached.binding.revalidate()
            return cached

        if getattr(_RUNTIME_ROOT_REENTRY, "pid", None) == current_pid:
            raise RuntimeError(
                "same-thread process runtime-root initialization reentry"
            )
        try:
            return _initialize_process_runtime_root_locked(current_pid, cleanup)
        except BaseException as boundary_error:
            cleanup.recover_local_active_error(boundary_error)
            cleanup.capture_boundary(boundary_error)
            cleanup.retain_published_state(boundary_error)
            _settle_runtime_root_owner_boundary(cleanup)
            raise AssertionError("runtime-root cleanup settlement returned")


def _process_runtime_root_state_with_owner(
    current_pid: int,
    cleanup: _RuntimeRootReentryCleanup,
) -> _RuntimeRootState:
    """Settle one operation and hand terminal custody to exactly one caller."""

    try:
        return _process_runtime_root_state_owned(current_pid, cleanup)
    except BaseException as boundary_error:
        cleanup.recover_local_active_error(boundary_error)
        cleanup.capture_boundary(boundary_error)
        cleanup.retain_published_state(boundary_error)
        _settle_runtime_root_owner_boundary(cleanup)
        raise AssertionError("runtime-root owner delivery boundary returned")


def _process_runtime_root_state() -> _RuntimeRootState:
    """Production state caller for the finite one-owner handoff contract.

    This is the one caller boundary around ``_process_runtime_root_state_with_owner``
    used by ``owned_temporary_directory``. Before this function's terminal
    return or raise, the reentry marker is cleared and body/state/resource
    custody is published. Pure Python cannot protect this boundary's own final
    endpoint; that terminal delivery belongs to its direct caller.
    """

    current_pid = os.getpid()
    cleanup = _RuntimeRootReentryCleanup(current_pid)
    try:
        return _process_runtime_root_state_with_owner(current_pid, cleanup)
    except BaseException as boundary_error:
        cleanup.recover_local_active_error(boundary_error)
        cleanup.capture_boundary(boundary_error)
        cleanup.retain_published_state(boundary_error)
        _settle_runtime_root_owner_boundary(cleanup)
        raise AssertionError("runtime-root production state boundary returned")


def _process_runtime_root() -> pathlib.Path:
    """Derive the path after the production state handoff is terminal."""

    return _process_runtime_root_state().path


def _retain_owned_temporary_cleanup_failure(
    error: BaseException,
    *,
    state: _RuntimeRootState,
    result_owner: _PrivateDirectoryCreationResultOwner,
    manifest_owner: CustodiedManifestResultOwner,
    deletion_owner: CustodiedDeletionResultOwner,
) -> None:
    _retain_runtime_root_failure(error, state)
    try:
        setattr(error, "owned_temporary_directory_result_owner", result_owner)
        setattr(error, "custodied_manifest_result_owner", manifest_owner)
        setattr(error, "custodied_deletion_result_owner", deletion_owner)
        resources = getattr(error, "retained_resources")
        if not any(resource is result_owner for resource in resources):
            resources.append(result_owner)
        if manifest_owner.manifest is not None:
            manifest_owner.retain(error)
    except BaseException as retention_error:
        try:
            error.add_note(
                "owned temporary-directory recovery retention failed: "
                f"{type(retention_error).__name__}: {retention_error}"
            )
        except BaseException:
            pass


def _retain_owned_temporary_lifetime(
    error: BaseException,
    *,
    state: _RuntimeRootState,
    result_owner: _PrivateDirectoryCreationResultOwner,
) -> None:
    _retain_runtime_root_failure(error, state)
    try:
        setattr(error, "owned_temporary_directory_result_owner", result_owner)
        resources = getattr(error, "retained_resources")
        if not any(resource is result_owner for resource in resources):
            resources.append(result_owner)
    except BaseException:
        pass


def _cleanup_owned_temporary_directory(
    *,
    state: _RuntimeRootState,
    result_owner: _PrivateDirectoryCreationResultOwner,
    binding: _DirectoryParentBinding,
) -> None:
    manifest_owner = CustodiedManifestResultOwner()
    deletion_owner = CustodiedDeletionResultOwner()
    manifest_path = state.path / (
        ".codex-review-cleanup-" + secrets.token_hex(16) + ".manifest"
    )
    manifest = None
    seal: dict[str, object] | None = None
    try:
        state.binding.revalidate()
        binding.revalidate()
        deadline = time.monotonic() + _OWNED_TEMPORARY_CLEANUP_SECONDS
        manifest = build_custodied_manifest(
            roots=(
                _root_spec_for_creation_owner(
                    label="owned-temporary-directory",
                    result_owner=result_owner,
                    binding=binding,
                ),
            ),
            manifest_path=manifest_path,
            entry_cap=_OWNED_TEMPORARY_CLEANUP_ENTRY_CAP,
            payload_cap=_OWNED_TEMPORARY_CLEANUP_MANIFEST_BYTES,
            deadline=deadline,
            result_owner=manifest_owner,
        )
        manifest_owner.transfer(manifest)
        seal = manifest.seal
        state.binding.revalidate()
        proof = delete_custodied_roots(
            manifest,
            deadline=deadline,
            result_owner=deletion_owner,
        )
        deletion_owner.transfer(proof)
        deletion_owner.finish()
        if result_owner.pending is not None:
            result_owner.pending.entry_state = "cleanup-complete"
        manifest.close()
        remove_published_manifest(seal)
        result_owner.close_descriptors_for_recovery()
    except BaseException as error:
        _retain_owned_temporary_cleanup_failure(
            error,
            state=state,
            result_owner=result_owner,
            manifest_owner=manifest_owner,
            deletion_owner=deletion_owner,
        )
        try:
            setattr(error, "owned_temporary_manifest_seal", seal)
        except BaseException:
            pass
        raise


def _raise_with_owned_temporary_cleanup(
    trigger_error: BaseException,
    cleanup_error: BaseException,
) -> None:
    preserved = (
        cleanup_error
        if isinstance(trigger_error, Exception)
        and not isinstance(cleanup_error, Exception)
        else trigger_error
    )
    try:
        setattr(preserved, "owned_temporary_directory_cleanup_error", cleanup_error)
        preserved.add_note(
            "owned temporary-directory cleanup also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
    except BaseException:
        pass
    if preserved is cleanup_error:
        raise cleanup_error from trigger_error
    raise preserved from cleanup_error


@contextmanager
def owned_temporary_directory(prefix: str) -> Iterator[pathlib.Path]:
    runtime_root = _process_runtime_root()
    state = _RUNTIME_ROOT_STATE
    if state is None or state.pid != os.getpid() or state.path != runtime_root:
        raise RuntimeError("process runtime-root state handoff is inconsistent")
    result_owner = _PrivateDirectoryCreationResultOwner()
    try:
        binding = _create_bound_owned_private_directory(
            state.path,
            f".codex-review-{prefix}",
            result_owner=result_owner,
            held_parent_binding=state.binding,
        )
        result_owner.transfer(binding)
    except BaseException as error:
        recovered = _rollback_unstored_owned_private_directory(
            result_owner,
            error,
        )
        if recovered is error:
            raise
        raise recovered from error
    try:
        yield binding.path
    except BaseException as trigger_error:
        try:
            _cleanup_owned_temporary_directory(
                state=state,
                result_owner=result_owner,
                binding=binding,
            )
        except BaseException as cleanup_error:
            # This caller-owned publication closes the pre-CALL interruption
            # gap: even if the callee frame never starts, the live creation
            # owner remains attached to the authoritative control flow.
            _retain_owned_temporary_lifetime(
                trigger_error,
                state=state,
                result_owner=result_owner,
            )
            _retain_owned_temporary_lifetime(
                cleanup_error,
                state=state,
                result_owner=result_owner,
            )
            _raise_with_owned_temporary_cleanup(trigger_error, cleanup_error)
        raise
    else:
        try:
            _cleanup_owned_temporary_directory(
                state=state,
                result_owner=result_owner,
                binding=binding,
            )
        except BaseException as cleanup_error:
            _retain_owned_temporary_lifetime(
                cleanup_error,
                state=state,
                result_owner=result_owner,
            )
            raise


def _write(path: pathlib.Path, content: bytes) -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _names_digest(names: set[str]) -> str:
    return _digest(b"\0".join(name.encode("ascii") for name in sorted(names)))


def bind_attempt_state(
    state: dict[str, object],
    *,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> dict[str, object]:
    if attempt_dir.parent != retention_root:
        raise ValueError("test attempt is not an exact retention-root child")
    state.update(
        {
            "retention_root_binding": {
                "path": str(retention_root),
                "identity": identity_from_stat(
                    os.stat(retention_root, follow_symlinks=False)
                ).to_json(),
            },
            "attempt_directory_binding": {
                "path": str(attempt_dir),
                "identity": identity_from_stat(
                    os.stat(attempt_dir, follow_symlinks=False)
                ).to_json(),
            },
        }
    )
    return state


def build_helper_fixture(
    root: pathlib.Path,
    *,
    source_repo: pathlib.Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    primary_diff: bytes | None = None,
) -> dict[str, object]:
    repo = source_repo or root / "repo"
    state_dir = root / "helper-state"
    workspace = state_dir / "workspace"
    control = workspace / ".codex-review"
    directories = (
        (state_dir, workspace, control)
        if source_repo is not None
        else (repo, state_dir, workspace, control)
    )
    for directory in directories:
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)

    base = base_sha or "1" * 40
    head = head_sha or "2" * 40
    artifacts: dict[str, bytes] = {
        "changed-paths.z": b"paths",
        "changed-blob-findings.z": b"findings",
        "synthetic-secret-manifest.json": b"{}\n",
        "synthetic-changed-evidence.json": b"{}\n",
        "review.diff": (
            primary_diff
            if primary_diff is not None
            else b"diff --git a/a.txt b/a.txt\n+new\n"
        ),
        "review.prompt": b"review\n",
    }
    artifact_records: list[dict[str, object]] = []
    for name in CONTROL_ARTIFACT_SPECS:
        content = artifacts[name]
        _write(control / name, content)
        if name == "changed-paths.z":
            record_count: int | None = 1
        elif name == "changed-blob-findings.z":
            record_count = 3
        else:
            record_count = None
        artifact_records.append(
            {
                "name": name,
                "record_count": record_count,
                "sha256": _digest(content),
                "size": len(content),
            }
        )

    control_stat = os.stat(control, follow_symlinks=False)
    control_state = {
        "artifacts": artifact_records,
        "directory": {
            "ctime_ns": control_stat.st_ctime_ns,
            "device": control_stat.st_dev,
            "entry_count": len(artifacts),
            "entry_names_sha256": _names_digest(set(artifacts)),
            "inode": control_stat.st_ino,
            "link_count": control_stat.st_nlink,
            "mode": control_stat.st_mode,
            "mtime_ns": control_stat.st_mtime_ns,
            "uid": control_stat.st_uid,
        },
        "schema_version": 2,
    }
    diff = artifacts["review.diff"]
    preflight = {
        "status": HELPER_PREFLIGHT_STATUS,
        "review_range": f"{base}..{head}",
        "primary_diff": {
            "path": ".codex-review/review.diff",
            "sha256": _digest(diff),
            "size": len(diff),
        },
    }
    helper_state = {
        "version": 1,
        "reviewer": "codex",
        "keep_workspace": True,
        "workspace": {
            "source_root": str(repo),
            "container_dir": str(state_dir),
            "workspace_root": str(workspace),
            "base_ref": base,
            "head_ref": head,
            "diff_file": str(control / "review.diff"),
            "prompt_file": str(control / "review.prompt"),
        },
    }
    _write(state_dir / ".isolated-review-state", HELPER_STATE_MARKER_TEXT)
    _write(state_dir / "runner.lock", b"")
    _write(state_dir / "cleanup.lock", b"")
    _write(state_dir / "exit-code", b"0\n")
    _write(
        state_dir / "state.json",
        (
            json.dumps(helper_state, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    )
    _write(
        state_dir / "preflight.json",
        (json.dumps(preflight, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    _write(
        state_dir / "control-artifact-state.json",
        (
            json.dumps(control_state, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    )
    return {
        "repo": repo,
        "state_dir": state_dir,
        "workspace": workspace,
        "base": base,
        "head": head,
        "diff": diff,
    }
