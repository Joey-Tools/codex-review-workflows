from __future__ import annotations

import atexit
import ctypes
import errno
import fcntl
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
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from review_supervisor.constants import (
    CONTROL_ARTIFACT_SPECS,
    HELPER_PREFLIGHT_STATUS,
    HELPER_STATE_MARKER_TEXT,
)
from review_supervisor.models import Identity
from review_supervisor.secureio import (
    DirectoryPolicyBinding,
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_directory_at,
    validate_directory_policy_fd,
)


_RUNTIME_ROOT: pathlib.Path | None = None
_RUNTIME_ROOT_PID: int | None = None
_RUNTIME_ROOT_BINDING: _CreatedPrivateDirectoryBinding | None = None
_EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
CREATION_ORIGIN_GUARANTEE = (
    "best-effort-256-bit-leaf-immediate-nofollow-open-same-uid-host-tcb"
)
CLEANUP_GUARANTEE = (
    "receipt-bound-exclusive-stage-fd-traversal-same-uid-final-unlink-host-tcb"
)
F_GETPATH = 50
DARWIN_MAXPATHLEN = 1024
DARWIN_RENAME_EXCL = 0x00000004
LINUX_RENAME_NOREPLACE = 0x00000001


class UnprovenCreatedDirectoryError(RuntimeError):
    def __init__(
        self,
        error: BaseException,
        *,
        recovery_locator: str,
        untrusted_path_hint: pathlib.Path,
    ) -> None:
        self.error = error
        self.recovery_locator = recovery_locator
        self.untrusted_path_hint = untrusted_path_hint
        error_errno = getattr(error, "errno", None)
        self.errno = error_errno if isinstance(error_errno, int) else None
        super().__init__(
            "created-directory ownership receipt was not established: "
            f"{type(error).__name__}: {error}"
        )
        self.add_note(f"recovery_locator={recovery_locator}")
        self.add_note(f"untrusted_path_hint={untrusted_path_hint}")
        for note in getattr(error, "__notes__", ()):
            self.add_note(str(note))


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


@dataclass(slots=True)
class _DirectoryParentBinding:
    path: pathlib.Path
    fd: int
    identity: Identity
    policy: DirectoryPolicyBinding
    require_owned_private_parent: bool

    def close(self) -> None:
        os.close(self.fd)

    def revalidate(self) -> None:
        held_policy = validate_directory_policy_fd(
            self.fd,
            self.path,
            private=False,
        )
        held_identity = identity_from_stat(os.fstat(self.fd))
        if self.require_owned_private_parent:
            _require_owned_private_parent_policy(held_policy, path=self.path)
        if (
            not directory_identities_match(self.identity, held_identity)
            or held_policy != self.policy
        ):
            raise OSError(
                errno.ESTALE,
                f"test runtime parent identity or access policy changed: {self.path}",
            )

        reopened_fd, reopened_identity = open_absolute_directory_chain(
            self.path,
            allow_sticky_writable_ancestors=(not self.require_owned_private_parent),
        )
        try:
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
        except BaseException as error:
            try:
                os.close(reopened_fd)
            except BaseException as close_error:
                error.add_note(
                    "test runtime parent revalidation close failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            os.close(reopened_fd)


@dataclass(slots=True)
class _CreatedPrivateDirectoryBinding:
    path: pathlib.Path
    parent_binding: _DirectoryParentBinding
    leaf_name: bytes
    fd: int
    identity: Identity
    policy: DirectoryPolicyBinding
    require_owned_private_parent: bool
    creation_origin_guarantee: str = CREATION_ORIGIN_GUARANTEE
    creation_origin_proven: bool = False
    cleanup_guarantee: str = CLEANUP_GUARANTEE

    def revalidate(self) -> None:
        self.parent_binding.revalidate()
        held_policy = validate_directory_policy_fd(
            self.fd,
            self.path,
            private=True,
        )
        held_identity = identity_from_stat(os.fstat(self.fd))
        if (
            not directory_identities_match(self.identity, held_identity)
            or held_policy != self.policy
        ):
            raise OSError(
                errno.ESTALE,
                f"created private directory identity or access policy changed: "
                f"{self.path}",
            )

        reopened_fd, reopened_identity = open_directory_at(
            self.parent_binding.fd,
            self.leaf_name,
            path_hint=self.path,
            private=True,
        )
        try:
            reopened_policy = validate_directory_policy_fd(
                reopened_fd,
                self.path,
                private=True,
            )
            if (
                not directory_identities_match(self.identity, reopened_identity)
                or reopened_policy != self.policy
            ):
                raise OSError(
                    errno.ESTALE,
                    f"created private directory parent-relative binding changed: "
                    f"{self.path}",
                )
        except BaseException as error:
            try:
                os.close(reopened_fd)
            except BaseException as close_error:
                error.add_note(
                    "created-directory revalidation close failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            os.close(reopened_fd)
        self.parent_binding.revalidate()

    def close(self) -> None:
        failures: list[BaseException] = []
        for descriptor in (self.fd, self.parent_binding.fd):
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        if failures:
            primary = failures[0]
            for secondary in failures[1:]:
                primary.add_note(
                    "additional created-directory binding close failure: "
                    f"{type(secondary).__name__}: {secondary}"
                )
            raise primary


def _open_directory_parent(
    raw_path: str | pathlib.Path,
    *,
    require_owned_private_parent: bool,
) -> _DirectoryParentBinding:
    canonical = _canonical_ascii_directory(raw_path)
    fd, identity = open_absolute_directory_chain(
        canonical,
        allow_sticky_writable_ancestors=not require_owned_private_parent,
    )
    try:
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
        return binding
    except BaseException:
        os.close(fd)
        raise


def _validated_private_runtime_parent(raw_path: str) -> pathlib.Path | None:
    try:
        binding = _open_directory_parent(
            raw_path,
            require_owned_private_parent=True,
        )
    except (OSError, ValueError):
        return None
    try:
        return binding.path
    finally:
        binding.close()


def _normalize_created_private_directory_mode(
    parent_binding: _DirectoryParentBinding,
    name: bytes,
    child_path: pathlib.Path,
    child_fd: int,
    first_open_identity: Identity,
) -> tuple[Identity, DirectoryPolicyBinding]:
    first_open_metadata = os.fstat(child_fd)
    if not stat.S_ISDIR(first_open_metadata.st_mode) or (
        first_open_metadata.st_uid != os.getuid()
    ):
        raise OSError(
            errno.EPERM,
            f"new temporary directory has an unsafe identity: {child_path}",
        )
    if os.listdir(child_fd):
        raise OSError(
            errno.ESTALE,
            f"new temporary directory was not empty at first open: {child_path}",
        )
    os.fchmod(child_fd, 0o700)
    normalized_identity = identity_from_stat(os.fstat(child_fd))
    normalized_policy = validate_directory_policy_fd(
        child_fd,
        child_path,
        private=True,
    )
    if (
        first_open_identity.device,
        first_open_identity.inode,
        stat.S_IFMT(first_open_identity.mode),
        first_open_identity.uid,
    ) != (
        normalized_identity.device,
        normalized_identity.inode,
        stat.S_IFMT(normalized_identity.mode),
        normalized_identity.uid,
    ):
        raise OSError(
            errno.ESTALE,
            f"new temporary directory changed during mode normalization: {child_path}",
        )

    reopened_fd, reopened_identity = open_directory_at(
        parent_binding.fd,
        name,
        path_hint=child_path,
        private=True,
    )
    try:
        reopened_policy = validate_directory_policy_fd(
            reopened_fd,
            child_path,
            private=True,
        )
        if (
            not directory_identities_match(normalized_identity, reopened_identity)
            or normalized_policy != reopened_policy
        ):
            raise OSError(
                errno.ESTALE,
                "new temporary directory parent-relative binding changed "
                "during mode normalization",
            )
    except BaseException as error:
        try:
            os.close(reopened_fd)
        except BaseException as close_error:
            error.add_note(
                "normalized-directory reopen close failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        raise
    else:
        os.close(reopened_fd)
    return normalized_identity, normalized_policy


def _unproven_created_directory_locator(
    parent_binding: _DirectoryParentBinding,
    name: bytes,
) -> str:
    return (
        "parent-directory://"
        f"{parent_binding.identity.device}/{parent_binding.identity.inode}/"
        f"leaf/{name.hex()}"
    )


def _create_owned_private_directory_binding(
    parent: pathlib.Path,
    prefix: str,
    *,
    require_owned_private_parent: bool = True,
) -> _CreatedPrivateDirectoryBinding:
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

    parent_binding = _open_directory_parent(
        parent,
        require_owned_private_parent=require_owned_private_parent,
    )
    try:
        for _ in range(128):
            name = raw_prefix + secrets.token_hex(32).encode("ascii")
            child_path = parent_binding.path / os.fsdecode(name)
            parent_binding.revalidate()
            try:
                os.mkdir(name, 0o700, dir_fd=parent_binding.fd)
            except FileExistsError:
                continue
            child_fd: int | None = None
            try:
                child_fd, first_open_identity = open_directory_at(
                    parent_binding.fd,
                    name,
                    path_hint=child_path,
                    private=False,
                )
                try:
                    child_identity, child_policy = (
                        _normalize_created_private_directory_mode(
                            parent_binding,
                            name,
                            child_path,
                            child_fd,
                            first_open_identity,
                        )
                    )
                    os.fsync(child_fd)
                    os.fsync(parent_binding.fd)
                    parent_binding.revalidate()
                    held_policy = validate_directory_policy_fd(
                        child_fd,
                        child_path,
                        private=True,
                    )
                    if held_policy != child_policy:
                        raise OSError(
                            errno.ESTALE,
                            "temporary-directory access policy changed after fsync",
                        )
                    parent_binding.revalidate()
                    path_fd, path_identity = open_absolute_directory_chain(
                        child_path,
                        private_leaf=True,
                        allow_sticky_writable_ancestors=(
                            not require_owned_private_parent
                        ),
                    )
                    try:
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
                                "temporary-directory path identity or access "
                                "policy changed",
                            )
                    except BaseException as error:
                        try:
                            os.close(path_fd)
                        except BaseException as close_error:
                            error.add_note(
                                "temporary-directory path binding close failed: "
                                f"{type(close_error).__name__}: {close_error}"
                            )
                        raise
                    else:
                        os.close(path_fd)
                    created_binding = _CreatedPrivateDirectoryBinding(
                        path=child_path,
                        parent_binding=parent_binding,
                        leaf_name=name,
                        fd=child_fd,
                        identity=child_identity,
                        policy=child_policy,
                        require_owned_private_parent=require_owned_private_parent,
                    )
                    created_binding.revalidate()
                    child_fd = None
                    return created_binding
                except BaseException as error:
                    if child_fd is not None:
                        try:
                            os.close(child_fd)
                        except BaseException as close_error:
                            error.add_note(
                                "created-directory child binding close failed: "
                                f"{type(close_error).__name__}: {close_error}"
                            )
                    raise
            except BaseException as error:
                raise UnprovenCreatedDirectoryError(
                    error,
                    recovery_locator=_unproven_created_directory_locator(
                        parent_binding,
                        name,
                    ),
                    untrusted_path_hint=child_path,
                ) from error
        raise FileExistsError("temporary-directory name collision limit reached")
    except BaseException as error:
        try:
            parent_binding.close()
        except BaseException as close_error:
            error.add_note(
                "created-directory parent binding close failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        raise


def _private_runtime_parent() -> pathlib.Path:
    explicit_parent = os.environ.get(_EXPLICIT_RUNTIME_PARENT_ENV)
    if explicit_parent is not None:
        validated = _validated_private_runtime_parent(explicit_parent)
        if validated is None:
            raise RuntimeError(
                f"{_EXPLICIT_RUNTIME_PARENT_ENV} is not a trusted private "
                "test runtime parent"
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


def _cleanup_node_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
        metadata.st_uid,
        metadata.st_gid,
        getattr(metadata, "st_flags", 0),
    )


def _descriptor_path(descriptor: int) -> pathlib.Path:
    if sys.platform == "darwin":
        payload = fcntl.fcntl(
            descriptor,
            F_GETPATH,
            b"\0" * DARWIN_MAXPATHLEN,
        )
        raw_path = payload.split(b"\0", 1)[0]
        if not raw_path or not raw_path.startswith(b"/"):
            raise OSError(errno.ESTALE, "bound cleanup path is unavailable")
        return pathlib.Path(os.fsdecode(raw_path))
    if sys.platform.startswith("linux"):
        raw_path = os.readlink(f"/proc/self/fd/{descriptor}")
        if not raw_path.startswith("/"):
            raise OSError(errno.ESTALE, "bound cleanup path is unavailable")
        return pathlib.Path(raw_path.removesuffix(" (deleted)"))
    raise OSError(errno.ENOTSUP, "descriptor path lookup is unavailable")


def _rename_exclusive(
    source_parent_fd: int,
    source_name: str | bytes,
    target_parent_fd: int,
    target_name: str | bytes,
) -> None:
    source = source_name if isinstance(source_name, bytes) else os.fsencode(source_name)
    target = target_name if isinstance(target_name, bytes) else os.fsencode(target_name)
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = libc.renameatx_np
        flags = DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = libc.renameat2
        flags = LINUX_RENAME_NOREPLACE
    else:
        raise OSError(errno.ENOTSUP, "exclusive directory rename is unavailable")
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(
        source_parent_fd,
        source,
        target_parent_fd,
        target,
        flags,
    )
    if result != 0:
        raise OSError(
            ctypes.get_errno() or errno.EIO,
            "cannot exclusively stage a bound cleanup entry",
        )


def _entry_absent(parent_fd: int, name: str | bytes) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _exclusive_cleanup_stage(
    parent_fd: int,
    source_name: str | bytes,
) -> bytes:
    for _ in range(128):
        staged_name = b".cr-" + secrets.token_hex(16).encode("ascii")
        try:
            _rename_exclusive(
                parent_fd,
                source_name,
                parent_fd,
                staged_name,
            )
        except FileExistsError:
            continue
        return staged_name
    raise FileExistsError(
        errno.EEXIST,
        "temporary cleanup name collision limit reached",
    )


def _open_cleanup_entry(
    parent_fd: int,
    name: str,
    *,
    restore_owner_write: bool,
) -> tuple[int, os.stat_result]:
    initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if restore_owner_write and not stat.S_ISLNK(initial.st_mode):
        required_mode = stat.S_IRUSR
        if stat.S_ISDIR(initial.st_mode):
            required_mode |= stat.S_IWUSR | stat.S_IXUSR
        if stat.S_IMODE(initial.st_mode) & required_mode != required_mode:
            if initial.st_uid != os.getuid():
                raise OSError(
                    errno.EPERM,
                    "cannot restore cleanup access for an unowned entry",
                )
            os.chmod(
                name,
                stat.S_IMODE(initial.st_mode) | required_mode,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            normalized = os.stat(
                name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if _cleanup_node_key(normalized) != _cleanup_node_key(initial):
                raise OSError(
                    errno.ESTALE,
                    "cleanup entry changed during access restoration",
                )
            initial = normalized
    common_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if stat.S_ISDIR(initial.st_mode):
        flags = common_flags | os.O_DIRECTORY | os.O_NOFOLLOW
    elif stat.S_ISREG(initial.st_mode):
        flags = common_flags | os.O_NOFOLLOW
    elif stat.S_ISFIFO(initial.st_mode):
        flags = common_flags | os.O_NOFOLLOW
    elif stat.S_ISLNK(initial.st_mode):
        if sys.platform == "darwin":
            flags = common_flags | os.O_SYMLINK
        elif sys.platform.startswith("linux"):
            flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        else:
            raise OSError(
                errno.ENOTSUP,
                "symlink descriptor opens are unavailable",
            )
    else:
        raise OSError(errno.EPERM, "unsupported entry in bound cleanup tree")
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if _cleanup_node_key(opened) != _cleanup_node_key(initial):
            raise OSError(errno.ESTALE, "cleanup entry changed while opening")
        return descriptor, opened
    except BaseException as error:
        try:
            os.close(descriptor)
        except BaseException as close_error:
            error.add_note(
                "cleanup entry descriptor close failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        raise


def _verify_staged_cleanup_entry(
    parent_fd: int,
    staged_name: str | bytes,
    descriptor: int,
    expected_path: pathlib.Path,
) -> None:
    staged = os.stat(staged_name, dir_fd=parent_fd, follow_symlinks=False)
    if _cleanup_node_key(staged) != _cleanup_node_key(os.fstat(descriptor)):
        raise OSError(errno.ESTALE, "cleanup staging moved a different object")
    if _descriptor_path(descriptor) != expected_path:
        raise OSError(errno.ESTALE, "cleanup staging path changed")


def _remove_bound_directory_contents(
    descriptor: int,
    expected_path: pathlib.Path,
    *,
    restore_owner_write: bool,
) -> None:
    if restore_owner_write:
        metadata = os.fstat(descriptor)
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
    for name in tuple(sorted(os.listdir(descriptor))):
        entry_fd, initial = _open_cleanup_entry(
            descriptor,
            name,
            restore_owner_write=restore_owner_write,
        )
        try:
            staged_name = _exclusive_cleanup_stage(descriptor, name)
            staged_path = expected_path / os.fsdecode(staged_name)
            _verify_staged_cleanup_entry(
                descriptor,
                staged_name,
                entry_fd,
                staged_path,
            )
            if not _entry_absent(descriptor, name):
                raise OSError(
                    errno.ESTALE,
                    "cleanup source name was repopulated after staging",
                )
            if stat.S_ISDIR(initial.st_mode):
                _remove_bound_directory_contents(
                    entry_fd,
                    staged_path,
                    restore_owner_write=restore_owner_write,
                )
                _verify_staged_cleanup_entry(
                    descriptor,
                    staged_name,
                    entry_fd,
                    staged_path,
                )
                os.rmdir(staged_name, dir_fd=descriptor)
            else:
                _verify_staged_cleanup_entry(
                    descriptor,
                    staged_name,
                    entry_fd,
                    staged_path,
                )
                os.unlink(staged_name, dir_fd=descriptor)
            final_metadata = os.fstat(entry_fd)
            if _cleanup_node_key(final_metadata) != _cleanup_node_key(
                initial
            ) or not _entry_absent(descriptor, staged_name):
                raise OSError(
                    errno.ESTALE,
                    "bound cleanup entry survived final removal",
                )
        except BaseException as error:
            try:
                os.close(entry_fd)
            except BaseException as close_error:
                error.add_note(
                    "bound cleanup entry close failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            os.close(entry_fd)
    if os.listdir(descriptor):
        raise OSError(errno.ESTALE, "bound cleanup directory gained new entries")


def _cleanup_created_private_directory_binding(
    binding: _CreatedPrivateDirectoryBinding,
    *,
    restore_owner_write: bool = False,
) -> None:
    binding.revalidate()
    staged_name = _exclusive_cleanup_stage(
        binding.parent_binding.fd,
        binding.leaf_name,
    )
    staged_path = binding.parent_binding.path / os.fsdecode(staged_name)
    _verify_staged_cleanup_entry(
        binding.parent_binding.fd,
        staged_name,
        binding.fd,
        staged_path,
    )
    if not _entry_absent(binding.parent_binding.fd, binding.leaf_name):
        raise OSError(
            errno.ESTALE,
            "temporary cleanup source leaf was repopulated",
        )
    _remove_bound_directory_contents(
        binding.fd,
        staged_path,
        restore_owner_write=restore_owner_write,
    )
    _verify_staged_cleanup_entry(
        binding.parent_binding.fd,
        staged_name,
        binding.fd,
        staged_path,
    )
    os.rmdir(staged_name, dir_fd=binding.parent_binding.fd)
    final_metadata = os.fstat(binding.fd)
    if not directory_identities_match(
        binding.identity,
        identity_from_stat(final_metadata),
    ) or not _entry_absent(binding.parent_binding.fd, staged_name):
        raise OSError(
            errno.ESTALE,
            "temporary cleanup root survived final removal",
        )
    if not _entry_absent(binding.parent_binding.fd, binding.leaf_name):
        raise OSError(
            errno.ESTALE,
            "temporary cleanup source leaf was repopulated before completion",
        )
    os.fsync(binding.parent_binding.fd)
    binding.parent_binding.revalidate()


def _cleanup_process_runtime_root(
    binding: _CreatedPrivateDirectoryBinding,
    owner_pid: int,
) -> None:
    if os.getpid() != owner_pid:
        return
    cleanup_error: BaseException | None = None
    try:
        _cleanup_created_private_directory_binding(
            binding,
            restore_owner_write=True,
        )
    except BaseException as error:
        cleanup_error = error
    try:
        binding.close()
    except BaseException as close_error:
        if cleanup_error is not None:
            cleanup_error.add_note(
                "process runtime binding close failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        else:
            cleanup_error = close_error
    if cleanup_error is not None:
        raise cleanup_error


def _process_runtime_root() -> pathlib.Path:
    global _RUNTIME_ROOT, _RUNTIME_ROOT_BINDING, _RUNTIME_ROOT_PID

    current_pid = os.getpid()
    if _RUNTIME_ROOT is not None and _RUNTIME_ROOT_PID == current_pid:
        return _RUNTIME_ROOT

    binding = _create_owned_private_directory_binding(
        _private_runtime_parent(),
        ".codex-review-tests-",
    )
    root = binding.path
    _RUNTIME_ROOT = root
    _RUNTIME_ROOT_BINDING = binding
    _RUNTIME_ROOT_PID = current_pid
    atexit.register(_cleanup_process_runtime_root, binding, current_pid)
    return root


@contextmanager
def owned_temporary_directory(prefix: str) -> Iterator[pathlib.Path]:
    binding = _create_owned_private_directory_binding(
        _process_runtime_root(),
        f".codex-review-{prefix}",
    )
    path = binding.path
    try:
        yield path
    except BaseException as primary_error:
        try:
            _cleanup_created_private_directory_binding(
                binding,
                restore_owner_write=True,
            )
        except BaseException as cleanup_error:
            primary_error.add_note(
                "owned temporary directory cleanup failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        try:
            binding.close()
        except BaseException as close_error:
            primary_error.add_note(
                "owned temporary directory binding close failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        raise
    else:
        cleanup_error: BaseException | None = None
        try:
            _cleanup_created_private_directory_binding(
                binding,
                restore_owner_write=True,
            )
        except BaseException as error:
            cleanup_error = error
        try:
            binding.close()
        except BaseException as close_error:
            if cleanup_error is not None:
                cleanup_error.add_note(
                    "owned temporary directory binding close failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
            else:
                cleanup_error = close_error
        if cleanup_error is not None:
            raise cleanup_error


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
