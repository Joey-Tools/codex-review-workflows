"""Descriptor-bound access to the current user's macOS login Keychain.

The pathname binding is protected against transient component replacement. The
expected-payload check and item update are deliberately sequential rather than
an atomic compare-and-swap; callers must retain the helper's certified writer
lock when coordinating supported Claude credential writers.
"""

from __future__ import annotations

import ctypes
import errno
import hmac
import json
import math
import os
import pathlib
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol


MAXIMUM_CREDENTIAL_BYTES = 1024 * 1024
_UINT32_MAX = (1 << 32) - 1
_ERR_SEC_ITEM_NOT_FOUND = -25300
_SECURITY_FRAMEWORK = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION_FRAMEWORK = (
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)
_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0
_ACL_NEXT_ENTRY = -1
_ACL_EXTENDED_ALLOW = 1
_ACL_EXTENDED_DENY = 2
_MNT_LOCAL = 0x00001000
_MFSTYPENAMELEN = 16
_MAXPATHLEN = 1024
_DARWIN_STATFS_SIZE = 2168
_DARWIN_STATFS_FSTYPENAME_OFFSET = 72
KEYCHAIN_WORKER_TIMEOUT_SECONDS = 20.0
_KEYCHAIN_WORKER_KILL_GRACE_SECONDS = 1.0
_KEYCHAIN_WORKER_SELF_DESTRUCT_SECONDS = 25.0
_KEYCHAIN_WORKER_METADATA_BYTES = 64 * 1024
_KEYCHAIN_WORKER_MAX_IDENTITY_COMPONENTS = 64
_KEYCHAIN_WORKER_PROTOCOL = 1
_KEYCHAIN_WORKER_FLAG = "--keychain-worker-fd"
_FRAME_LENGTH = struct.Struct("!I")


class MacOSKeychainError(RuntimeError):
    """Base class for fail-closed local-login Keychain failures."""


class MacOSKeychainUnavailable(MacOSKeychainError):
    """The required local-login Keychain facility is unavailable."""


class MacOSKeychainUnsafe(MacOSKeychainError):
    """The Keychain path or native result violated a safety invariant."""


class MacOSKeychainInspectionInconclusive(MacOSKeychainError):
    """A race, event, I/O failure, or cleanup failure prevented proof."""


class MacOSKeychainWriteOutcomeUnknown(MacOSKeychainInspectionInconclusive):
    """A supervised replacement may have reached the native Keychain."""


class MacOSKeychainWorkerTerminationInconclusive(MacOSKeychainInspectionInconclusive):
    """A killed native worker could not be proven reaped promptly."""


class MacOSKeychainIdentityMismatch(MacOSKeychainError):
    """The update target is not the target returned by the prior read."""


class MacOSKeychainPayloadMismatch(MacOSKeychainError):
    """The item payload did not match the guarded update expectation."""


class _MacOSKeychainCleanupDiagnostic(Exception):
    """Python 3.10-visible diagnostic for a secondary cleanup failure."""


@dataclass(frozen=True)
class KeychainDescriptorPolicyIdentity:
    filesystem_id: tuple[int, int]
    filesystem_type: str
    filesystem_flags: int
    deny_acl_entries: int


@dataclass(frozen=True)
class KeychainPathComponentIdentity:
    name: str
    device: int
    inode: int
    file_type: int
    owner: int
    group: int
    mode: int
    flags: int | None
    generation: int | None
    link_count: int | None
    descriptor_policy: KeychainDescriptorPolicyIdentity


@dataclass(frozen=True)
class KeychainIdentity:
    path: str
    components: tuple[KeychainPathComponentIdentity, ...]


@dataclass
class _FoundCredential:
    payload: bytearray
    item: object


class _SecurityBackend(Protocol):
    def restore_user_interaction(self) -> None: ...

    def open_keychain(self, path: pathlib.Path) -> object: ...

    def find_generic_password(
        self,
        keychain: object,
        account: str,
        service: str,
    ) -> _FoundCredential | None: ...

    def modify_item(self, item: object, payload: bytearray) -> None: ...

    def copy_item_content(self, item: object) -> bytearray: ...

    def release_item(self, item: object) -> None: ...

    def release_keychain(self, keychain: object) -> None: ...


class _PathWatcher(Protocol):
    def assert_quiet(self) -> None: ...

    def consume_expected_update_events(self) -> None: ...

    def close(self) -> None: ...


_WatcherFactory = Callable[[tuple[int, ...], int], _PathWatcher]
_DescriptorPolicy = Callable[[int], KeychainDescriptorPolicyIdentity]


@dataclass(frozen=True)
class _Runtime:
    path: pathlib.Path
    anchor: pathlib.Path
    user_owned_from: int
    uid: int
    backend: _SecurityBackend
    watcher_factory: _WatcherFactory
    descriptor_policy: _DescriptorPolicy


@dataclass
class _WorkerRequest:
    operation: str
    account: str
    service: str
    expected: bytearray
    replacement: bytearray
    expected_identity: KeychainIdentity | None


@dataclass
class _WorkerResponse:
    kind: str
    payload: bytearray | None
    identity: KeychainIdentity | None


@dataclass
class _WorkerDispatchState:
    replacement_dispatched: bool = False
    outcome_resolved: bool = False
    worker_spawned: bool = False
    worker_termination_proven: bool = False
    worker_termination_failure: MacOSKeychainWorkerTerminationInconclusive | None = None


class _KeychainWorkerProtocolError(RuntimeError):
    """The private worker exchanged malformed or oversized control data."""


class _KeychainWorkerTimedOut(RuntimeError):
    """The private worker exceeded its one operation deadline."""


def _worker_error_types() -> dict[str, type[MacOSKeychainError]]:
    return {
        error_type.__name__: error_type
        for error_type in (
            MacOSKeychainUnavailable,
            MacOSKeychainUnsafe,
            MacOSKeychainInspectionInconclusive,
            MacOSKeychainWriteOutcomeUnknown,
            MacOSKeychainWorkerTerminationInconclusive,
            MacOSKeychainIdentityMismatch,
            MacOSKeychainPayloadMismatch,
        )
    }


def _worker_require_keys(
    value: object,
    expected: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise _KeychainWorkerProtocolError(
            f"the Keychain worker {label} schema is invalid"
        )
    return value


def _worker_string(
    value: object,
    *,
    label: str,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _KeychainWorkerProtocolError(f"the Keychain worker {label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise _KeychainWorkerProtocolError(
            f"the Keychain worker {label} is not valid UTF-8"
        ) from error
    if len(encoded) > maximum_bytes:
        raise _KeychainWorkerProtocolError(f"the Keychain worker {label} is oversized")
    return value


def _worker_int(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _KeychainWorkerProtocolError(
            f"the Keychain worker {label} is not an integer"
        )
    return value


def _worker_optional_int(value: object, *, label: str) -> int | None:
    if value is None:
        return None
    return _worker_int(value, label=label)


def _identity_to_worker_metadata(identity: KeychainIdentity) -> dict[str, object]:
    if not isinstance(identity, KeychainIdentity):
        raise MacOSKeychainIdentityMismatch(
            "the expected login Keychain identity is invalid"
        )
    return {
        "path": identity.path,
        "components": [
            {
                "name": component.name,
                "device": component.device,
                "inode": component.inode,
                "file_type": component.file_type,
                "owner": component.owner,
                "group": component.group,
                "mode": component.mode,
                "flags": component.flags,
                "generation": component.generation,
                "link_count": component.link_count,
                "descriptor_policy": {
                    "filesystem_id": list(component.descriptor_policy.filesystem_id),
                    "filesystem_type": (component.descriptor_policy.filesystem_type),
                    "filesystem_flags": (component.descriptor_policy.filesystem_flags),
                    "deny_acl_entries": (component.descriptor_policy.deny_acl_entries),
                },
            }
            for component in identity.components
        ],
    }


def _identity_from_worker_metadata(value: object) -> KeychainIdentity:
    payload = _worker_require_keys(
        value,
        {"path", "components"},
        label="Keychain identity",
    )
    path = _worker_string(
        payload["path"],
        label="Keychain identity path",
        maximum_bytes=_MAXPATHLEN,
    )
    if not os.path.isabs(path) or os.path.normpath(path) != path or path == "/":
        raise _KeychainWorkerProtocolError(
            "the Keychain worker identity path is not canonical"
        )
    raw_components = payload["components"]
    if (
        not isinstance(raw_components, list)
        or not raw_components
        or len(raw_components) > _KEYCHAIN_WORKER_MAX_IDENTITY_COMPONENTS
    ):
        raise _KeychainWorkerProtocolError(
            "the Keychain worker identity component count is invalid"
        )
    components: list[KeychainPathComponentIdentity] = []
    component_keys = {
        "name",
        "device",
        "inode",
        "file_type",
        "owner",
        "group",
        "mode",
        "flags",
        "generation",
        "link_count",
        "descriptor_policy",
    }
    for index, raw_component in enumerate(raw_components):
        component = _worker_require_keys(
            raw_component,
            component_keys,
            label=f"Keychain identity component {index}",
        )
        policy = _worker_require_keys(
            component["descriptor_policy"],
            {
                "filesystem_id",
                "filesystem_type",
                "filesystem_flags",
                "deny_acl_entries",
            },
            label=f"Keychain descriptor policy {index}",
        )
        raw_filesystem_id = policy["filesystem_id"]
        if not isinstance(raw_filesystem_id, list) or len(raw_filesystem_id) != 2:
            raise _KeychainWorkerProtocolError(
                "the Keychain worker filesystem identity is invalid"
            )
        descriptor_policy = KeychainDescriptorPolicyIdentity(
            filesystem_id=(
                _worker_int(
                    raw_filesystem_id[0],
                    label=f"filesystem id {index}.0",
                ),
                _worker_int(
                    raw_filesystem_id[1],
                    label=f"filesystem id {index}.1",
                ),
            ),
            filesystem_type=_worker_string(
                policy["filesystem_type"],
                label=f"filesystem type {index}",
                maximum_bytes=_MFSTYPENAMELEN,
            ),
            filesystem_flags=_worker_int(
                policy["filesystem_flags"],
                label=f"filesystem flags {index}",
            ),
            deny_acl_entries=_worker_int(
                policy["deny_acl_entries"],
                label=f"deny ACL count {index}",
            ),
        )
        if descriptor_policy.deny_acl_entries < 0:
            raise _KeychainWorkerProtocolError(
                "the Keychain worker deny ACL count is negative"
            )
        components.append(
            KeychainPathComponentIdentity(
                name=_worker_string(
                    component["name"],
                    label=f"component name {index}",
                    maximum_bytes=_MAXPATHLEN,
                ),
                device=_worker_int(
                    component["device"],
                    label=f"component device {index}",
                ),
                inode=_worker_int(
                    component["inode"],
                    label=f"component inode {index}",
                ),
                file_type=_worker_int(
                    component["file_type"],
                    label=f"component file type {index}",
                ),
                owner=_worker_int(
                    component["owner"],
                    label=f"component owner {index}",
                ),
                group=_worker_int(
                    component["group"],
                    label=f"component group {index}",
                ),
                mode=_worker_int(
                    component["mode"],
                    label=f"component mode {index}",
                ),
                flags=_worker_optional_int(
                    component["flags"],
                    label=f"component flags {index}",
                ),
                generation=_worker_optional_int(
                    component["generation"],
                    label=f"component generation {index}",
                ),
                link_count=_worker_optional_int(
                    component["link_count"],
                    label=f"component link count {index}",
                ),
                descriptor_policy=descriptor_policy,
            )
        )
    return KeychainIdentity(path=path, components=tuple(components))


def _encode_worker_metadata(value: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise _KeychainWorkerProtocolError(
            "the Keychain worker metadata cannot be encoded"
        ) from error
    if len(encoded) > _KEYCHAIN_WORKER_METADATA_BYTES:
        raise _KeychainWorkerProtocolError("the Keychain worker metadata is oversized")
    return encoded


def _reject_worker_json_constant(value: str) -> object:
    raise _KeychainWorkerProtocolError(
        f"the Keychain worker metadata contains invalid constant {value}"
    )


def _worker_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _KeychainWorkerProtocolError(
                "the Keychain worker metadata contains a duplicate key"
            )
        result[key] = value
    return result


def _decode_worker_metadata(payload: bytearray) -> dict[str, object]:
    if len(payload) > _KEYCHAIN_WORKER_METADATA_BYTES:
        raise _KeychainWorkerProtocolError("the Keychain worker metadata is oversized")
    try:
        decoded = json.loads(
            payload.decode("ascii", errors="strict"),
            object_pairs_hook=_worker_json_object,
            parse_constant=_reject_worker_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _KeychainWorkerProtocolError(
            "the Keychain worker metadata is malformed"
        ) from error
    if not isinstance(decoded, dict):
        raise _KeychainWorkerProtocolError(
            "the Keychain worker metadata is not a mapping"
        )
    return decoded


def _zero(payload: bytearray | None) -> None:
    if payload:
        target = (ctypes.c_ubyte * len(payload)).from_buffer(payload)
        ctypes.memset(ctypes.addressof(target), 0, len(payload))


def _zero_all(payloads: tuple[bytearray | None, ...]) -> list[BaseException]:
    errors: list[BaseException] = []
    for payload in payloads:
        try:
            _zero(payload)
        except BaseException as error:
            errors.append(error)
    return errors


def _worker_remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _KeychainWorkerTimedOut(
            "the native Keychain worker exceeded its hard timeout"
        )
    return remaining


def _send_worker_buffer(
    connection: socket.socket,
    payload: bytes | bytearray | memoryview,
    *,
    deadline: float,
) -> None:
    view = memoryview(payload)
    offset = 0
    try:
        while offset < len(view):
            connection.settimeout(_worker_remaining(deadline))
            try:
                written = connection.send(view[offset:])
            except (TimeoutError, socket.timeout) as error:
                raise _KeychainWorkerTimedOut(
                    "the native Keychain worker request timed out"
                ) from error
            except OSError as error:
                raise _KeychainWorkerProtocolError(
                    "cannot write the native Keychain worker protocol"
                ) from error
            if written <= 0:
                raise _KeychainWorkerProtocolError(
                    "the native Keychain worker protocol closed during write"
                )
            offset += written
    finally:
        view.release()


def _send_worker_frame(
    connection: socket.socket,
    payload: bytes | bytearray | memoryview,
    *,
    maximum_bytes: int,
    deadline: float,
) -> None:
    if len(payload) > maximum_bytes or len(payload) > _UINT32_MAX:
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker frame is oversized"
        )
    _send_worker_buffer(
        connection,
        _FRAME_LENGTH.pack(len(payload)),
        deadline=deadline,
    )
    _send_worker_buffer(connection, payload, deadline=deadline)


def _receive_worker_exact(
    connection: socket.socket,
    length: int,
    *,
    deadline: float,
) -> bytearray:
    result = bytearray(length)
    view = memoryview(result)
    offset = 0
    try:
        while offset < length:
            connection.settimeout(_worker_remaining(deadline))
            try:
                received = connection.recv_into(view[offset:], length - offset)
            except (TimeoutError, socket.timeout) as error:
                raise _KeychainWorkerTimedOut(
                    "the native Keychain worker response timed out"
                ) from error
            except OSError as error:
                raise _KeychainWorkerProtocolError(
                    "cannot read the native Keychain worker protocol"
                ) from error
            if received <= 0:
                raise _KeychainWorkerProtocolError(
                    "the native Keychain worker protocol closed during read"
                )
            offset += received
        return result
    except BaseException:
        _zero(result)
        raise
    finally:
        view.release()


def _receive_worker_frame(
    connection: socket.socket,
    *,
    maximum_bytes: int,
    deadline: float,
) -> bytearray:
    header = _receive_worker_exact(
        connection,
        _FRAME_LENGTH.size,
        deadline=deadline,
    )
    try:
        (length,) = _FRAME_LENGTH.unpack(header)
    finally:
        _zero(header)
    if length > maximum_bytes:
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker frame is oversized"
        )
    return _receive_worker_exact(connection, length, deadline=deadline)


def _require_worker_protocol_eof(
    connection: socket.socket,
    *,
    deadline: float,
) -> None:
    trailing = bytearray(1)
    view = memoryview(trailing)
    try:
        connection.settimeout(_worker_remaining(deadline))
        try:
            received = connection.recv_into(view, 1)
        except (TimeoutError, socket.timeout) as error:
            raise _KeychainWorkerTimedOut(
                "the native Keychain worker did not finish before its deadline"
            ) from error
        except OSError as error:
            raise _KeychainWorkerProtocolError(
                "cannot finish the native Keychain worker protocol"
            ) from error
        if received != 0:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker protocol has trailing data"
            )
    finally:
        view.release()
        _zero(trailing)


def _worker_command(descriptor: int) -> tuple[str, ...]:
    interpreter = pathlib.Path(sys.executable)
    try:
        interpreter = interpreter.resolve(strict=True)
        script = pathlib.Path(__file__).resolve(strict=True)
    except OSError as error:
        raise MacOSKeychainUnavailable(
            "cannot resolve the native Keychain worker runtime"
        ) from error
    if (
        not interpreter.is_absolute()
        or not interpreter.is_file()
        or not script.is_absolute()
        or not script.is_file()
    ):
        raise MacOSKeychainUnavailable(
            "the native Keychain worker runtime is unavailable"
        )
    return (
        os.fspath(interpreter),
        "-I",
        "-S",
        os.fspath(script),
        _KEYCHAIN_WORKER_FLAG,
        str(descriptor),
    )


def _background_reap_worker(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait()
    except BaseException:
        pass


def _kill_and_reap_worker(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is not None:
            return
    except BaseException as error:
        raise MacOSKeychainWorkerTerminationInconclusive(
            "cannot inspect the native Keychain worker before termination"
        ) from error
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except BaseException as error:
        if not isinstance(error, OSError):
            raise MacOSKeychainWorkerTerminationInconclusive(
                "cannot terminate the native Keychain worker"
            ) from error
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except BaseException as kill_error:
            raise MacOSKeychainWorkerTerminationInconclusive(
                "cannot terminate the native Keychain worker"
            ) from kill_error
    try:
        process.wait(timeout=_KEYCHAIN_WORKER_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        try:
            threading.Thread(
                target=_background_reap_worker,
                args=(process,),
                daemon=True,
            ).start()
        except BaseException as reaper_error:
            raise MacOSKeychainWorkerTerminationInconclusive(
                "cannot arrange a background reap for the native Keychain worker"
            ) from reaper_error
        raise MacOSKeychainWorkerTerminationInconclusive(
            "the timed-out native Keychain worker could not be reaped promptly"
        ) from error
    except BaseException as error:
        raise MacOSKeychainWorkerTerminationInconclusive(
            "cannot reap the native Keychain worker safely"
        ) from error


def _supervisor_cleanup_signals() -> tuple[signal.Signals, ...]:
    signals = [signal.SIGTERM, signal.SIGINT]
    for name in ("SIGHUP", "SIGQUIT"):
        candidate = getattr(signal, name, None)
        if candidate is not None and candidate not in signals:
            signals.append(candidate)
    return tuple(signals)


def _consume_pending_supervisor_signal() -> signal.Signals | None:
    if not hasattr(signal, "sigpending") or not hasattr(signal, "sigwait"):
        return None
    pending = set(signal.sigpending()).intersection(_supervisor_cleanup_signals())
    if not pending:
        return None
    ordered = sorted(pending, key=int)
    for pending_signal in ordered:
        signal.sigwait({pending_signal})
    return ordered[0]


def _forwarded_signal_error(signum: signal.Signals) -> BaseException:
    # The worker executes this module directly under ``python -I -S``. Import
    # the orchestration exception only on the parent-side cleanup path.
    from .common import ForwardedSignal

    return ForwardedSignal(signum)


def _is_supervisor_control_flow(error: BaseException) -> bool:
    if not isinstance(error, Exception):
        return True
    try:
        from .common import ForwardedSignal
    except (ImportError, ValueError):
        return False
    return isinstance(error, ForwardedSignal)


def _supervisor_control_flow_from_cause_chain(
    error: BaseException | None,
) -> BaseException | None:
    current = error
    seen: set[int] = set()
    for _ in range(16):
        if current is None or id(current) in seen:
            return None
        seen.add(id(current))
        if _is_supervisor_control_flow(current):
            return current
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return None


def _add_exception_note_compat(error: BaseException, note: str) -> None:
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    # BaseException.add_note() was added in Python 3.11. Preserve the same
    # structured evidence for callers that inspect exceptions on Python 3.10.
    existing = getattr(error, "__notes__", ())
    setattr(error, "__notes__", [*existing, note])


def _cleanup_supervised_keychain_worker(
    *,
    process: subprocess.Popen[bytes] | None,
    connections: tuple[socket.socket | None, ...],
    payloads: tuple[bytearray | None, ...],
    primary: BaseException | None,
    dispatch_state: _WorkerDispatchState,
) -> None:
    cleanup_errors: list[BaseException] = []
    previous_signal_mask: set[signal.Signals] | None = None
    pending_signal: signal.Signals | None = None
    if (
        os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and hasattr(signal, "pthread_sigmask")
    ):
        try:
            previous_signal_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                _supervisor_cleanup_signals(),
            )
        except BaseException as error:
            cleanup_errors.append(error)

    try:
        cleanup_errors.extend(_zero_all(payloads))
    except BaseException as error:
        cleanup_errors.append(error)
    for connection in connections:
        if connection is None:
            continue
        try:
            connection.close()
        except BaseException as error:
            cleanup_errors.append(error)

    termination_failure: MacOSKeychainWorkerTerminationInconclusive | None = None
    if process is not None:
        dispatch_state.worker_spawned = True
        try:
            _kill_and_reap_worker(process)
            dispatch_state.worker_termination_proven = True
        except MacOSKeychainWorkerTerminationInconclusive as error:
            termination_failure = error
            dispatch_state.worker_termination_failure = error
            cleanup_errors.append(error)
        except BaseException as error:
            termination_failure = MacOSKeychainWorkerTerminationInconclusive(
                "the native Keychain worker termination result is inconclusive"
            )
            termination_failure.__cause__ = error
            dispatch_state.worker_termination_failure = termination_failure
            cleanup_errors.append(error)

    if previous_signal_mask is not None:
        try:
            pending_signal = _consume_pending_supervisor_signal()
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        except BaseException as error:
            cleanup_errors.append(error)

    pending_control_flow = (
        _forwarded_signal_error(pending_signal) if pending_signal is not None else None
    )
    primary_control_flow = _supervisor_control_flow_from_cause_chain(primary)
    termination_control_flow = _supervisor_control_flow_from_cause_chain(
        termination_failure.__cause__ if termination_failure is not None else None
    )
    cleanup_control_flow = next(
        (
            control_flow
            for error in cleanup_errors
            if (control_flow := _supervisor_control_flow_from_cause_chain(error))
            is not None
        ),
        None,
    )
    selected_control_flow = (
        primary_control_flow
        or termination_control_flow
        or pending_control_flow
        or cleanup_control_flow
    )

    if termination_failure is not None:
        original_termination_cause = termination_failure.__cause__
        for error in (
            original_termination_cause,
            primary,
            pending_control_flow,
            *cleanup_errors,
        ):
            if error is None or error is termination_failure:
                continue
            _add_exception_note_compat(
                termination_failure,
                "native Keychain worker termination cleanup also failed: "
                f"{type(error).__name__}: {error}",
            )
        if selected_control_flow is not None:
            raise termination_failure from selected_control_flow
        if primary is None:
            raise termination_failure
        raise termination_failure from primary
    if selected_control_flow is not None and selected_control_flow is not primary:
        if primary is None:
            raise selected_control_flow
        raise selected_control_flow from primary
    _cleanup_failure(
        primary,
        cleanup_errors,
        message="cannot clean up the native Keychain worker safely",
    )


def _credential_copy(
    payload: bytes | bytearray | memoryview,
    *,
    label: str,
) -> bytearray:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise MacOSKeychainUnsafe(f"the {label} Keychain payload is not bytes-like")
    try:
        return bytearray(payload)
    except (TypeError, ValueError) as error:
        raise MacOSKeychainUnsafe(
            f"the {label} Keychain payload cannot be copied exactly"
        ) from error


def _cleanup_failure(
    primary: BaseException | None,
    errors: list[BaseException],
    *,
    message: str,
) -> None:
    if not errors:
        return
    detail = "; ".join(f"{type(error).__name__}: {error}" for error in errors)
    cleanup_control_flow = next(
        (error for error in errors if _is_supervisor_control_flow(error)),
        None,
    )
    if primary is not None and _is_supervisor_control_flow(primary):
        selected = primary
    elif cleanup_control_flow is not None:
        selected = cleanup_control_flow
    elif primary is not None:
        selected = primary
    else:
        selected = MacOSKeychainInspectionInconclusive(message)
        selected.__cause__ = errors[0]
    note = f"{message}: {detail}"
    for error in (primary, *errors):
        if error is None or error is selected:
            continue
        add_note = getattr(selected, "add_note", None)
        if callable(add_note):
            add_note(note)
            continue
        diagnostic = _MacOSKeychainCleanupDiagnostic(note)
        if selected.__cause__ is not None:
            diagnostic.__cause__ = selected.__cause__
        elif selected.__context__ is not None:
            diagnostic.__context__ = selected.__context__
        selected.__cause__ = diagnostic
    if selected is not primary:
        raise selected


class _DarwinFSID(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _DarwinStatFS(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFSID),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * _MFSTYPENAMELEN),
        ("f_mntonname", ctypes.c_char * _MAXPATHLEN),
        ("f_mntfromname", ctypes.c_char * _MAXPATHLEN),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


class _DarwinDescriptorPolicy:
    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise MacOSKeychainUnavailable(
                "descriptor-bound Keychain policy is available only on macOS"
            )
        if (
            ctypes.sizeof(_DarwinStatFS) != _DARWIN_STATFS_SIZE
            or _DarwinStatFS.f_fstypename.offset != _DARWIN_STATFS_FSTYPENAME_OFFSET
        ):
            raise MacOSKeychainUnavailable("the macOS statfs ABI layout is unsupported")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.fstatfs.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(_DarwinStatFS),
            ]
            libc.fstatfs.restype = ctypes.c_int
            libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.acl_get_fd_np.restype = ctypes.c_void_p
            libc.acl_get_entry.argtypes = [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            libc.acl_get_entry.restype = ctypes.c_int
            libc.acl_get_tag_type.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_int),
            ]
            libc.acl_get_tag_type.restype = ctypes.c_int
            libc.acl_free.argtypes = [ctypes.c_void_p]
            libc.acl_free.restype = ctypes.c_int
        except (AttributeError, OSError) as error:
            raise MacOSKeychainUnavailable(
                "the required descriptor-bound macOS ACL or fstatfs API is unavailable"
            ) from error
        self._libc = libc

    def _filesystem_identity(self, descriptor: int) -> tuple[tuple[int, int], str, int]:
        filesystem = _DarwinStatFS()
        ctypes.set_errno(0)
        if self._libc.fstatfs(descriptor, ctypes.byref(filesystem)) != 0:
            error_number = ctypes.get_errno()
            raise MacOSKeychainInspectionInconclusive(
                "cannot inspect the login Keychain filesystem"
                + (f" (errno {error_number})" if error_number else "")
            )
        filesystem_type = bytes(filesystem.f_fstypename).split(b"\x00", 1)[0]
        try:
            decoded_type = filesystem_type.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain filesystem type is not trustworthy"
            ) from error
        flags = int(filesystem.f_flags)
        if not flags & _MNT_LOCAL or decoded_type != "apfs":
            raise MacOSKeychainUnsafe(
                "the login Keychain descriptor chain must be on local APFS"
            )
        return (
            (
                int(filesystem.f_fsid.values[0]),
                int(filesystem.f_fsid.values[1]),
            ),
            decoded_type,
            flags,
        )

    def _deny_acl_entry_count(self, descriptor: int) -> int:
        ctypes.set_errno(0)
        acl = self._libc.acl_get_fd_np(descriptor, _ACL_TYPE_EXTENDED)
        if not acl:
            error_number = ctypes.get_errno()
            if error_number == errno.ENOENT:
                return 0
            raise MacOSKeychainInspectionInconclusive(
                "cannot parse the login Keychain descriptor ACL"
                + (f" (errno {error_number})" if error_number else "")
            )
        primary: BaseException | None = None
        deny_entries = 0
        try:
            entry = ctypes.c_void_p()
            entry_id = _ACL_FIRST_ENTRY
            while True:
                ctypes.set_errno(0)
                result = int(
                    self._libc.acl_get_entry(
                        acl,
                        entry_id,
                        ctypes.byref(entry),
                    )
                )
                if result == -1:
                    error_number = ctypes.get_errno()
                    if error_number == errno.EINVAL:
                        break
                    raise MacOSKeychainInspectionInconclusive(
                        "cannot enumerate the login Keychain descriptor ACL"
                        + (f" (errno {error_number})" if error_number else "")
                    )
                if result != 0 or not entry.value:
                    raise MacOSKeychainInspectionInconclusive(
                        "the login Keychain descriptor ACL returned an invalid entry"
                    )
                tag = ctypes.c_int()
                if self._libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                    raise MacOSKeychainInspectionInconclusive(
                        "cannot parse a login Keychain descriptor ACL entry"
                    )
                if tag.value == _ACL_EXTENDED_ALLOW:
                    raise MacOSKeychainUnsafe(
                        "the login Keychain path must not contain an ALLOW ACL entry"
                    )
                if tag.value != _ACL_EXTENDED_DENY:
                    raise MacOSKeychainUnsafe(
                        "the login Keychain path contains an unknown ACL entry"
                    )
                deny_entries += 1
                entry_id = _ACL_NEXT_ENTRY
            return deny_entries
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            try:
                if self._libc.acl_free(acl) != 0:
                    cleanup_errors.append(
                        MacOSKeychainInspectionInconclusive(
                            "cannot release the login Keychain descriptor ACL"
                        )
                    )
            except BaseException as error:
                cleanup_errors.append(error)
            _cleanup_failure(
                primary,
                cleanup_errors,
                message="cannot release the login Keychain descriptor ACL safely",
            )

    def __call__(self, descriptor: int) -> KeychainDescriptorPolicyIdentity:
        filesystem_id, filesystem_type, filesystem_flags = self._filesystem_identity(
            descriptor
        )
        deny_acl_entries = self._deny_acl_entry_count(descriptor)
        return KeychainDescriptorPolicyIdentity(
            filesystem_id=filesystem_id,
            filesystem_type=filesystem_type,
            filesystem_flags=filesystem_flags,
            deny_acl_entries=deny_acl_entries,
        )


def _component_identity(
    name: str,
    metadata: os.stat_result,
    *,
    leaf: bool,
    descriptor_policy: KeychainDescriptorPolicyIdentity,
) -> KeychainPathComponentIdentity:
    return KeychainPathComponentIdentity(
        name=name,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
        owner=metadata.st_uid,
        group=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
        flags=getattr(metadata, "st_flags", None),
        generation=getattr(metadata, "st_gen", None),
        link_count=metadata.st_nlink if leaf else None,
        descriptor_policy=descriptor_policy,
    )


def _component_matches_metadata(
    expected: KeychainPathComponentIdentity,
    metadata: os.stat_result,
    *,
    leaf: bool,
) -> bool:
    return (
        expected.device == metadata.st_dev
        and expected.inode == metadata.st_ino
        and expected.file_type == stat.S_IFMT(metadata.st_mode)
        and expected.owner == metadata.st_uid
        and expected.group == metadata.st_gid
        and expected.mode == stat.S_IMODE(metadata.st_mode)
        and expected.flags == getattr(metadata, "st_flags", None)
        and expected.generation == getattr(metadata, "st_gen", None)
        and expected.link_count == (metadata.st_nlink if leaf else None)
    )


def _validate_component(
    metadata: os.stat_result,
    *,
    leaf: bool,
    uid: int,
    require_current_user: bool,
    root: bool,
) -> None:
    if leaf:
        if not stat.S_ISREG(metadata.st_mode):
            raise MacOSKeychainUnsafe("the login Keychain must be a regular file")
        if metadata.st_uid != uid:
            raise MacOSKeychainUnsafe(
                "the login Keychain must be owned by the current user"
            )
        if metadata.st_nlink != 1:
            raise MacOSKeychainUnsafe(
                "the login Keychain must have exactly one hard link"
            )
    else:
        if not stat.S_ISDIR(metadata.st_mode):
            raise MacOSKeychainUnsafe(
                "the login Keychain path must contain only real directories"
            )
        if root:
            if metadata.st_uid != 0:
                raise MacOSKeychainUnsafe("the filesystem root must be root-owned")
        elif require_current_user:
            if metadata.st_uid != uid:
                raise MacOSKeychainUnsafe(
                    "the current user's Keychain path must be user-owned"
                )
        elif metadata.st_uid not in {0, uid}:
            raise MacOSKeychainUnsafe(
                "Keychain ancestors must be root- or current-user-owned"
            )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise MacOSKeychainUnsafe(
            "the login Keychain path must not be group- or world-writable"
        )


def _open_flags(*, leaf: bool) -> int:
    missing = [
        name
        for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")
        if not hasattr(os, name)
    ]
    if missing:
        raise MacOSKeychainInspectionInconclusive(
            "the host lacks safe no-follow descriptor support"
        )
    flags = getattr(os, "O_EVTONLY", os.O_RDONLY)
    flags |= os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    if leaf:
        flags |= os.O_NONBLOCK
    else:
        flags |= os.O_DIRECTORY
    return flags


def _path_parts(path: pathlib.Path, anchor: pathlib.Path) -> tuple[str, ...]:
    if not path.is_absolute() or not anchor.is_absolute():
        raise MacOSKeychainUnsafe("the login Keychain path must be absolute")
    if "\x00" in os.fspath(path) or "\x00" in os.fspath(anchor):
        raise MacOSKeychainUnsafe("the login Keychain path contains NUL")
    try:
        relative = path.relative_to(anchor)
    except ValueError as error:
        raise MacOSKeychainUnsafe(
            "the login Keychain path is outside its trusted anchor"
        ) from error
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise MacOSKeychainUnsafe("the login Keychain path has an invalid component")
    return parts


class _PathBinding:
    def __init__(
        self,
        *,
        path: pathlib.Path,
        anchor: pathlib.Path,
        names: tuple[str, ...],
        descriptors: list[int],
        identity: KeychainIdentity,
        user_owned_from: int,
        uid: int,
        descriptor_policy: _DescriptorPolicy,
    ) -> None:
        self.path = path
        self.anchor = anchor
        self.names = names
        self._descriptors = descriptors
        self.identity = identity
        self.user_owned_from = user_owned_from
        self.uid = uid
        self.descriptor_policy = descriptor_policy
        self.poisoned = False

    @property
    def descriptors(self) -> tuple[int, ...]:
        return tuple(self._descriptors)

    @property
    def leaf_descriptor(self) -> int:
        if not self._descriptors:
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain binding is already closed"
            )
        return self._descriptors[-1]

    def assert_stable(self) -> None:
        if self.poisoned or not self._descriptors:
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain binding is not usable"
            )
        expected = self.identity.components
        try:
            root_metadata = os.fstat(self._descriptors[0])
            _validate_component(
                root_metadata,
                leaf=False,
                uid=self.uid,
                require_current_user=self.user_owned_from == 0,
                root=self.anchor == pathlib.Path("/"),
            )
            root_policy = self.descriptor_policy(self._descriptors[0])
            if (
                _component_identity(
                    self.names[0],
                    root_metadata,
                    leaf=False,
                    descriptor_policy=root_policy,
                )
                != expected[0]
            ):
                raise MacOSKeychainInspectionInconclusive(
                    "the login Keychain anchor identity changed"
                )
            if self.anchor == pathlib.Path("/"):
                named_root = os.stat("/", follow_symlinks=False)
                if not _component_matches_metadata(
                    expected[0],
                    named_root,
                    leaf=False,
                ):
                    raise MacOSKeychainInspectionInconclusive(
                        "the filesystem root identity changed"
                    )
            for index in range(1, len(self._descriptors)):
                leaf = index == len(self._descriptors) - 1
                require_current_user = index >= self.user_owned_from
                descriptor_metadata = os.fstat(self._descriptors[index])
                descriptor_policy = self.descriptor_policy(self._descriptors[index])
                named_metadata = os.stat(
                    self.names[index],
                    dir_fd=self._descriptors[index - 1],
                    follow_symlinks=False,
                )
                for metadata in (descriptor_metadata, named_metadata):
                    _validate_component(
                        metadata,
                        leaf=leaf,
                        uid=self.uid,
                        require_current_user=require_current_user,
                        root=False,
                    )
                descriptor_identity = _component_identity(
                    self.names[index],
                    descriptor_metadata,
                    leaf=leaf,
                    descriptor_policy=descriptor_policy,
                )
                if descriptor_identity != expected[index] or not (
                    _component_matches_metadata(
                        expected[index],
                        named_metadata,
                        leaf=leaf,
                    )
                ):
                    raise MacOSKeychainInspectionInconclusive(
                        "the login Keychain path identity changed"
                    )
        except MacOSKeychainError:
            self.poisoned = True
            raise
        except OSError as error:
            self.poisoned = True
            raise MacOSKeychainInspectionInconclusive(
                "cannot revalidate the login Keychain descriptor chain"
                + _errno_suffix(error)
            ) from None

    def close(self) -> None:
        errors: list[BaseException] = []
        while self._descriptors:
            descriptor = self._descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
        _cleanup_failure(
            None,
            errors,
            message="cannot close the login Keychain descriptor chain",
        )


def _open_path_binding(runtime: _Runtime) -> _PathBinding:
    parts = _path_parts(runtime.path, runtime.anchor)
    descriptors: list[int] = []
    names = (os.fspath(runtime.anchor), *parts)
    identities: list[KeychainPathComponentIdentity] = []
    primary: BaseException | None = None
    try:
        anchor_descriptor = os.open(runtime.anchor, _open_flags(leaf=False))
        descriptors.append(anchor_descriptor)
        anchor_metadata = os.fstat(anchor_descriptor)
        anchor_policy = runtime.descriptor_policy(anchor_descriptor)
        _validate_component(
            anchor_metadata,
            leaf=False,
            uid=runtime.uid,
            require_current_user=runtime.user_owned_from == 0,
            root=runtime.anchor == pathlib.Path("/"),
        )
        identities.append(
            _component_identity(
                names[0],
                anchor_metadata,
                leaf=False,
                descriptor_policy=anchor_policy,
            )
        )
        for part_index, part in enumerate(parts, start=1):
            leaf = part_index == len(parts)
            require_current_user = part_index >= runtime.user_owned_from
            before = os.stat(
                part,
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
            _validate_component(
                before,
                leaf=leaf,
                uid=runtime.uid,
                require_current_user=require_current_user,
                root=False,
            )
            try:
                descriptor = os.open(
                    part,
                    _open_flags(leaf=leaf),
                    dir_fd=descriptors[-1],
                )
            except FileNotFoundError:
                raise MacOSKeychainInspectionInconclusive(
                    "the login Keychain path disappeared while it was opened"
                ) from None
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            descriptor_policy = runtime.descriptor_policy(descriptor)
            try:
                after = os.stat(
                    part,
                    dir_fd=descriptors[-2],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                raise MacOSKeychainInspectionInconclusive(
                    "the login Keychain path disappeared after it was opened"
                ) from None
            for metadata in (opened, after):
                _validate_component(
                    metadata,
                    leaf=leaf,
                    uid=runtime.uid,
                    require_current_user=require_current_user,
                    root=False,
                )
            expected = _component_identity(
                part,
                opened,
                leaf=leaf,
                descriptor_policy=descriptor_policy,
            )
            if not (
                _component_matches_metadata(expected, before, leaf=leaf)
                and _component_matches_metadata(expected, after, leaf=leaf)
            ):
                raise MacOSKeychainInspectionInconclusive(
                    "the login Keychain path changed while it was opened"
                )
            identities.append(expected)
        binding = _PathBinding(
            path=runtime.path,
            anchor=runtime.anchor,
            names=names,
            descriptors=descriptors,
            identity=KeychainIdentity(
                path=os.fspath(runtime.path),
                components=tuple(identities),
            ),
            user_owned_from=runtime.user_owned_from,
            uid=runtime.uid,
            descriptor_policy=runtime.descriptor_policy,
        )
        descriptors = []
        return binding
    except FileNotFoundError as error:
        primary = error
        raise
    except MacOSKeychainError as error:
        primary = error
        raise
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            converted: MacOSKeychainError = MacOSKeychainUnsafe(
                "the login Keychain path contains a symlink or non-directory"
            )
        else:
            converted = MacOSKeychainInspectionInconclusive(
                "cannot open the login Keychain descriptor chain" + _errno_suffix(error)
            )
        primary = converted
        raise converted from None
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        while descriptors:
            descriptor = descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        _cleanup_failure(
            None if isinstance(primary, FileNotFoundError) else primary,
            cleanup_errors,
            message="cannot close an incomplete login Keychain descriptor chain",
        )


class _KqueuePathWatcher:
    def __init__(self, descriptors: tuple[int, ...], leaf_descriptor: int) -> None:
        required = (
            "kqueue",
            "kevent",
            "KQ_FILTER_VNODE",
            "KQ_EV_ADD",
            "KQ_EV_ENABLE",
            "KQ_EV_CLEAR",
            "KQ_EV_ERROR",
            "KQ_EV_EOF",
            "KQ_NOTE_DELETE",
            "KQ_NOTE_WRITE",
            "KQ_NOTE_EXTEND",
            "KQ_NOTE_ATTRIB",
            "KQ_NOTE_LINK",
            "KQ_NOTE_RENAME",
            "KQ_NOTE_REVOKE",
        )
        if any(not hasattr(select, name) for name in required):
            raise MacOSKeychainUnavailable(
                "macOS kqueue vnode monitoring is unavailable"
            )
        self._descriptors = descriptors
        self._descriptor_set = frozenset(descriptors)
        self._leaf_descriptor = leaf_descriptor
        self._closed = False
        self._poisoned = False
        self._kqueue = select.kqueue()
        try:
            os.set_inheritable(self._kqueue.fileno(), False)
            flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR
            fflags = (
                select.KQ_NOTE_DELETE
                | select.KQ_NOTE_WRITE
                | select.KQ_NOTE_EXTEND
                | select.KQ_NOTE_ATTRIB
                | select.KQ_NOTE_LINK
                | select.KQ_NOTE_RENAME
                | select.KQ_NOTE_REVOKE
            )
            changes = [
                select.kevent(
                    descriptor,
                    filter=select.KQ_FILTER_VNODE,
                    flags=flags,
                    fflags=fflags,
                )
                for descriptor in descriptors
            ]
            self._kqueue.control(changes, 0, 0)
        except BaseException:
            self._closed = True
            self._kqueue.close()
            raise

    def _events(self) -> tuple[object, ...]:
        if self._closed or self._poisoned:
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain watcher is not usable"
            )
        try:
            return tuple(self._kqueue.control(None, max(1, len(self._descriptors)), 0))
        except OSError as error:
            self._poisoned = True
            raise MacOSKeychainInspectionInconclusive(
                "cannot inspect login Keychain vnode events" + _errno_suffix(error)
            ) from None

    def _validate_event(self, event: object, *, update: bool) -> None:
        known_event_flags = (
            select.KQ_EV_ADD
            | select.KQ_EV_ENABLE
            | select.KQ_EV_CLEAR
            | select.KQ_EV_ERROR
            | select.KQ_EV_EOF
        )
        ident = int(event.ident)
        flags = int(event.flags)
        fflags = int(event.fflags)
        if (
            ident not in self._descriptor_set
            or int(event.filter) != select.KQ_FILTER_VNODE
            or flags & ~known_event_flags
            or flags & (select.KQ_EV_ERROR | select.KQ_EV_EOF)
            or fflags == 0
        ):
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain watcher returned an invalid event"
            )
        allowed = 0
        if update and ident == self._leaf_descriptor:
            allowed = select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
        if fflags & ~allowed:
            raise MacOSKeychainInspectionInconclusive(
                "the login Keychain descriptor chain changed during access"
            )

    def assert_quiet(self) -> None:
        try:
            events = self._events()
            for event in events:
                self._validate_event(event, update=False)
        except BaseException:
            self._poisoned = True
            raise

    def consume_expected_update_events(self) -> None:
        try:
            events = self._events()
            for event in events:
                self._validate_event(event, update=True)
        except BaseException:
            self._poisoned = True
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._kqueue.close()


def _default_watcher_factory(
    descriptors: tuple[int, ...],
    leaf_descriptor: int,
) -> _PathWatcher:
    try:
        return _KqueuePathWatcher(descriptors, leaf_descriptor)
    except MacOSKeychainError:
        raise
    except OSError as error:
        raise MacOSKeychainInspectionInconclusive(
            "cannot establish login Keychain vnode monitoring" + _errno_suffix(error)
        ) from None


def _strict_stability_barrier(
    binding: _PathBinding,
    watcher: _PathWatcher,
) -> None:
    watcher.assert_quiet()
    binding.assert_stable()
    watcher.assert_quiet()


class _CtypesSecurityBackend:
    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise MacOSKeychainUnavailable(
                "the local-login Keychain binding is available only on macOS"
            )
        try:
            security = ctypes.CDLL(_SECURITY_FRAMEWORK)
            core_foundation = ctypes.CDLL(_CORE_FOUNDATION_FRAMEWORK)
            self._configure_symbols(security, core_foundation)
        except (AttributeError, OSError) as error:
            raise MacOSKeychainUnavailable(
                "the required macOS Security framework API is unavailable"
            ) from error
        self._security = security
        self._core_foundation = core_foundation
        previous_interaction = ctypes.c_ubyte()
        status = int(
            self._security.SecKeychainGetUserInteractionAllowed(
                ctypes.byref(previous_interaction)
            )
        )
        if status != 0:
            raise MacOSKeychainInspectionInconclusive(
                f"cannot inspect native Keychain user interaction (OSStatus {status})"
            )
        self._interaction_state_to_restore: int | None = None
        status = int(
            self._security.SecKeychainSetUserInteractionAllowed(ctypes.c_ubyte(0))
        )
        if status != 0:
            raise MacOSKeychainInspectionInconclusive(
                f"cannot disable native Keychain user interaction (OSStatus {status})"
            )
        self._interaction_state_to_restore = int(previous_interaction.value)

    @staticmethod
    def _configure_symbols(security: object, core_foundation: object) -> None:
        os_status = ctypes.c_int32
        uint32 = ctypes.c_uint32
        reference = ctypes.c_void_p
        security.SecKeychainOpen.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(reference),
        ]
        security.SecKeychainOpen.restype = os_status
        security.SecKeychainFindGenericPassword.argtypes = [
            reference,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(reference),
        ]
        security.SecKeychainFindGenericPassword.restype = os_status
        security.SecKeychainItemModifyAttributesAndData.argtypes = [
            reference,
            ctypes.c_void_p,
            uint32,
            ctypes.c_void_p,
        ]
        security.SecKeychainItemModifyAttributesAndData.restype = os_status
        security.SecKeychainItemCopyContent.argtypes = [
            reference,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainItemCopyContent.restype = os_status
        security.SecKeychainItemFreeContent.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        security.SecKeychainItemFreeContent.restype = os_status
        security.SecKeychainSetUserInteractionAllowed.argtypes = [
            ctypes.c_ubyte,
        ]
        security.SecKeychainSetUserInteractionAllowed.restype = os_status
        security.SecKeychainGetUserInteractionAllowed.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        security.SecKeychainGetUserInteractionAllowed.restype = os_status
        core_foundation.CFRelease.argtypes = [reference]
        core_foundation.CFRelease.restype = None

    def restore_user_interaction(self) -> None:
        previous_interaction = self._interaction_state_to_restore
        if previous_interaction is None:
            return
        self._interaction_state_to_restore = None
        status = int(
            self._security.SecKeychainSetUserInteractionAllowed(
                ctypes.c_ubyte(previous_interaction)
            )
        )
        if status != 0:
            raise MacOSKeychainInspectionInconclusive(
                f"cannot restore native Keychain user interaction (OSStatus {status})"
            )

    @staticmethod
    def _encoded_label(value: str, *, label: str) -> bytes:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise MacOSKeychainUnsafe(f"the Keychain {label} is invalid")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise MacOSKeychainUnsafe(
                f"the Keychain {label} is not valid UTF-8"
            ) from error
        if len(encoded) > _UINT32_MAX:
            raise MacOSKeychainUnsafe(f"the Keychain {label} is too long")
        return encoded

    def _free_content(
        self,
        data: ctypes.c_void_p,
        length: int,
        *,
        scrub: bool = True,
    ) -> None:
        errors: list[BaseException] = []
        if data.value and length and scrub:
            try:
                ctypes.memset(data.value, 0, length)
            except BaseException as error:
                errors.append(error)
        try:
            status = int(self._security.SecKeychainItemFreeContent(None, data))
            if status != 0:
                errors.append(
                    MacOSKeychainInspectionInconclusive(
                        f"SecKeychainItemFreeContent failed with OSStatus {status}"
                    )
                )
        except BaseException as error:
            errors.append(error)
        _cleanup_failure(
            None,
            errors,
            message="cannot clear and release native Keychain content safely",
        )

    def _copy_and_free_content(
        self,
        data: ctypes.c_void_p,
        length: int,
    ) -> bytearray:
        result: bytearray | None = None
        primary: BaseException | None = None
        try:
            if length < 0 or length > MAXIMUM_CREDENTIAL_BYTES:
                raise MacOSKeychainUnsafe(
                    "the Keychain credential exceeds its bounded size"
                )
            if length and not data.value:
                raise MacOSKeychainInspectionInconclusive(
                    "the Security framework returned missing credential content"
                )
            result = bytearray(length)
            if length:
                target = (ctypes.c_ubyte * length).from_buffer(result)
                ctypes.memmove(target, data.value, length)
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_errors = _zero_all((result,)) if primary is not None else []
            if data.value:
                try:
                    self._free_content(
                        data,
                        length,
                        scrub=True,
                    )
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors and primary is None:
                cleanup_errors.extend(_zero_all((result,)))
            _cleanup_failure(
                primary,
                cleanup_errors,
                message="cannot release native Keychain content safely",
            )

    def _release_unexpected_outputs(
        self,
        data: ctypes.c_void_p,
        length: int,
        item: ctypes.c_void_p,
    ) -> None:
        errors: list[BaseException] = []
        if data.value:
            try:
                self._free_content(
                    data,
                    length,
                    scrub=True,
                )
            except BaseException as error:
                errors.append(error)
        if item.value:
            try:
                self._core_foundation.CFRelease(item)
            except BaseException as error:
                errors.append(error)
        _cleanup_failure(
            None,
            errors,
            message="cannot release unexpected Security framework outputs",
        )

    def _release_reference_after_failure(
        self,
        reference: ctypes.c_void_p,
        primary: BaseException,
        *,
        message: str,
    ) -> None:
        cleanup_errors: list[BaseException] = []
        try:
            self._core_foundation.CFRelease(reference)
        except BaseException as error:
            cleanup_errors.append(error)
        _cleanup_failure(primary, cleanup_errors, message=message)

    def open_keychain(self, path: pathlib.Path) -> object:
        path_bytes = os.fsencode(path)
        if b"\x00" in path_bytes:
            raise MacOSKeychainUnsafe("the login Keychain path contains NUL")
        keychain = ctypes.c_void_p()
        status = int(
            self._security.SecKeychainOpen(
                ctypes.c_char_p(path_bytes),
                ctypes.byref(keychain),
            )
        )
        if status != 0 or not keychain.value:
            failure = MacOSKeychainInspectionInconclusive(
                f"SecKeychainOpen failed with OSStatus {status}"
            )
            if keychain.value:
                self._release_reference_after_failure(
                    keychain,
                    failure,
                    message="cannot release an unexpected Keychain reference safely",
                )
            raise failure
        return keychain

    def find_generic_password(
        self,
        keychain: object,
        account: str,
        service: str,
    ) -> _FoundCredential | None:
        account_bytes = self._encoded_label(account, label="account")
        service_bytes = self._encoded_label(service, label="service")
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = int(
            self._security.SecKeychainFindGenericPassword(
                keychain,
                ctypes.c_uint32(len(service_bytes)),
                ctypes.c_char_p(service_bytes),
                ctypes.c_uint32(len(account_bytes)),
                ctypes.c_char_p(account_bytes),
                ctypes.byref(length),
                ctypes.byref(data),
                ctypes.byref(item),
            )
        )
        if status == _ERR_SEC_ITEM_NOT_FOUND:
            self._release_unexpected_outputs(data, int(length.value), item)
            return None
        if status != 0:
            self._release_unexpected_outputs(data, int(length.value), item)
            raise MacOSKeychainInspectionInconclusive(
                f"SecKeychainFindGenericPassword failed with OSStatus {status}"
            )
        if not item.value:
            self._release_unexpected_outputs(data, int(length.value), item)
            raise MacOSKeychainInspectionInconclusive(
                "the Security framework returned a missing item reference"
            )
        try:
            payload = self._copy_and_free_content(data, int(length.value))
        except BaseException as error:
            self._release_reference_after_failure(
                item,
                error,
                message="cannot release a failed Keychain item reference safely",
            )
            raise
        return _FoundCredential(payload=payload, item=item)

    def modify_item(self, item: object, payload: bytearray) -> None:
        if len(payload) > MAXIMUM_CREDENTIAL_BYTES or len(payload) > _UINT32_MAX:
            raise MacOSKeychainUnsafe(
                "the replacement Keychain credential exceeds its bounded size"
            )
        if payload:
            backing = (ctypes.c_ubyte * len(payload)).from_buffer(payload)
        else:
            backing = (ctypes.c_ubyte * 1)()
        pointer = ctypes.cast(backing, ctypes.c_void_p)
        try:
            status = int(
                self._security.SecKeychainItemModifyAttributesAndData(
                    item,
                    None,
                    ctypes.c_uint32(len(payload)),
                    pointer,
                )
            )
        finally:
            if not payload:
                ctypes.memset(pointer, 0, 1)
        if status != 0:
            raise MacOSKeychainInspectionInconclusive(
                f"SecKeychainItemModifyAttributesAndData failed with OSStatus {status}"
            )

    def copy_item_content(self, item: object) -> bytearray:
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        status = int(
            self._security.SecKeychainItemCopyContent(
                item,
                None,
                None,
                ctypes.byref(length),
                ctypes.byref(data),
            )
        )
        if status != 0:
            if data.value:
                content_length = int(length.value)
                self._free_content(
                    data,
                    content_length,
                    scrub=True,
                )
            raise MacOSKeychainInspectionInconclusive(
                f"SecKeychainItemCopyContent failed with OSStatus {status}"
            )
        return self._copy_and_free_content(data, int(length.value))

    def release_item(self, item: object) -> None:
        self._core_foundation.CFRelease(item)

    def release_keychain(self, keychain: object) -> None:
        self._core_foundation.CFRelease(keychain)


def _login_keychain_runtime() -> _Runtime:
    if sys.platform != "darwin":
        raise MacOSKeychainUnavailable(
            "the local-login Keychain binding is available only on macOS"
        )
    try:
        import pwd

        home_raw = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError) as error:
        raise MacOSKeychainInspectionInconclusive(
            "cannot resolve the current user's pwd home"
        ) from error
    if (
        not home_raw
        or "\x00" in home_raw
        or not os.path.isabs(home_raw)
        or os.path.normpath(home_raw) != home_raw
        or home_raw == "/"
    ):
        raise MacOSKeychainUnsafe(
            "the current user's pwd home must be a canonical absolute path"
        )
    home = pathlib.Path(home_raw)
    path = home / "Library" / "Keychains" / "login.keychain-db"
    user_owned_from = len(home.parts) - 1
    return _Runtime(
        path=path,
        anchor=pathlib.Path("/"),
        user_owned_from=user_owned_from,
        uid=os.getuid(),
        backend=_CtypesSecurityBackend(),
        watcher_factory=_default_watcher_factory,
        descriptor_policy=_DarwinDescriptorPolicy(),
    )


def _close_operation_resources(
    *,
    backend: _SecurityBackend,
    item: object | None,
    keychain: object | None,
    watcher: _PathWatcher | None,
    binding: _PathBinding | None,
) -> list[BaseException]:
    errors: list[BaseException] = []
    for release, value in (
        (backend.release_item, item),
        (backend.release_keychain, keychain),
    ):
        if value is None:
            continue
        try:
            release(value)
        except BaseException as error:
            errors.append(error)
    if watcher is not None:
        try:
            watcher.close()
        except BaseException as error:
            errors.append(error)
    if binding is not None:
        try:
            binding.close()
        except BaseException as error:
            errors.append(error)
    return errors


def _read_with_runtime(
    account: str,
    service: str,
    runtime: _Runtime,
) -> tuple[bytearray, KeychainIdentity] | None:
    try:
        binding = _open_path_binding(runtime)
    except FileNotFoundError:
        return None
    watcher: _PathWatcher | None = None
    keychain: object | None = None
    item: object | None = None
    credential: bytearray | None = None
    primary: BaseException | None = None
    try:
        watcher = runtime.watcher_factory(
            binding.descriptors,
            binding.leaf_descriptor,
        )
        _strict_stability_barrier(binding, watcher)
        keychain = runtime.backend.open_keychain(runtime.path)
        _strict_stability_barrier(binding, watcher)
        found = runtime.backend.find_generic_password(keychain, account, service)
        if found is None:
            _strict_stability_barrier(binding, watcher)
            return None
        credential = found.payload
        item = found.item
        if len(credential) > MAXIMUM_CREDENTIAL_BYTES:
            raise MacOSKeychainUnsafe(
                "the Keychain credential exceeds its bounded size"
            )
        _strict_stability_barrier(binding, watcher)
        return credential, binding.identity
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors = _close_operation_resources(
            backend=runtime.backend,
            item=item,
            keychain=keychain,
            watcher=watcher,
            binding=binding,
        )
        if primary is not None or cleanup_errors:
            cleanup_errors.extend(_zero_all((credential,)))
        _cleanup_failure(
            primary,
            cleanup_errors,
            message="cannot clean up the login Keychain read safely",
        )


def _replace_with_runtime(
    account: str,
    service: str,
    expected: bytes | bytearray | memoryview,
    replacement: bytes | bytearray | memoryview,
    expected_identity: KeychainIdentity,
    runtime: _Runtime,
) -> KeychainIdentity:
    expected_copy: bytearray | None = None
    replacement_copy: bytearray | None = None
    try:
        expected_copy = _credential_copy(expected, label="expected")
        replacement_copy = _credential_copy(replacement, label="replacement")
    except BaseException as error:
        zero_errors = _zero_all((expected_copy, replacement_copy))
        _cleanup_failure(
            error,
            zero_errors,
            message="cannot clear incomplete guarded Keychain payload copies",
        )
        raise
    assert expected_copy is not None
    assert replacement_copy is not None
    if (
        len(expected_copy) > MAXIMUM_CREDENTIAL_BYTES
        or len(replacement_copy) > MAXIMUM_CREDENTIAL_BYTES
    ):
        failure = MacOSKeychainUnsafe(
            "the guarded Keychain credential exceeds its bounded size"
        )
        zero_errors = _zero_all((expected_copy, replacement_copy))
        _cleanup_failure(
            failure,
            zero_errors,
            message="cannot clear oversized guarded Keychain payload copies",
        )
        raise failure
    binding: _PathBinding | None = None
    watcher: _PathWatcher | None = None
    keychain: object | None = None
    item: object | None = None
    current: bytearray | None = None
    readback: bytearray | None = None
    primary: BaseException | None = None
    try:
        try:
            binding = _open_path_binding(runtime)
        except FileNotFoundError as error:
            raise MacOSKeychainUnavailable(
                "the login Keychain is unavailable for guarded replacement"
            ) from error
        if not isinstance(expected_identity, KeychainIdentity):
            raise MacOSKeychainIdentityMismatch(
                "the expected login Keychain identity is invalid"
            )
        if binding.identity != expected_identity:
            raise MacOSKeychainIdentityMismatch(
                "the login Keychain identity changed before replacement"
            )
        watcher = runtime.watcher_factory(
            binding.descriptors,
            binding.leaf_descriptor,
        )
        _strict_stability_barrier(binding, watcher)
        keychain = runtime.backend.open_keychain(runtime.path)
        _strict_stability_barrier(binding, watcher)
        found = runtime.backend.find_generic_password(keychain, account, service)
        if found is None:
            raise MacOSKeychainPayloadMismatch(
                "the guarded Keychain item disappeared before replacement"
            )
        current = found.payload
        item = found.item
        if len(current) > MAXIMUM_CREDENTIAL_BYTES or not hmac.compare_digest(
            current,
            expected_copy,
        ):
            raise MacOSKeychainPayloadMismatch(
                "the guarded Keychain payload changed before replacement"
            )
        _strict_stability_barrier(binding, watcher)
        runtime.backend.modify_item(item, replacement_copy)
        watcher.consume_expected_update_events()
        binding.assert_stable()
        watcher.assert_quiet()
        readback = runtime.backend.copy_item_content(item)
        if len(readback) > MAXIMUM_CREDENTIAL_BYTES or not hmac.compare_digest(
            readback,
            replacement_copy,
        ):
            raise MacOSKeychainPayloadMismatch(
                "the guarded Keychain replacement did not read back exactly"
            )
        _strict_stability_barrier(binding, watcher)
        return binding.identity
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors = _zero_all((current, readback, expected_copy, replacement_copy))
        cleanup_errors.extend(
            _close_operation_resources(
                backend=runtime.backend,
                item=item,
                keychain=keychain,
                watcher=watcher,
                binding=binding,
            )
        )
        _cleanup_failure(
            primary,
            cleanup_errors,
            message="cannot clean up the login Keychain replacement safely",
        )


def _receive_worker_request(
    connection: socket.socket,
    *,
    deadline: float,
) -> _WorkerRequest:
    metadata_payload = _receive_worker_frame(
        connection,
        maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
        deadline=deadline,
    )
    try:
        metadata = _decode_worker_metadata(metadata_payload)
    finally:
        _zero(metadata_payload)
    request = _worker_require_keys(
        metadata,
        {
            "protocol",
            "operation",
            "account",
            "service",
            "expected_identity",
        },
        label="request",
    )
    if _worker_int(request["protocol"], label="protocol") != _KEYCHAIN_WORKER_PROTOCOL:
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker protocol version is unsupported"
        )
    operation = _worker_string(
        request["operation"],
        label="operation",
        maximum_bytes=16,
    )
    if operation not in {"read", "replace"}:
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker operation is unsupported"
        )
    account = _worker_string(
        request["account"],
        label="account",
        maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
    )
    service = _worker_string(
        request["service"],
        label="service",
        maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
    )
    expected = _receive_worker_frame(
        connection,
        maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
        deadline=deadline,
    )
    replacement: bytearray | None = None
    try:
        replacement = _receive_worker_frame(
            connection,
            maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
            deadline=deadline,
        )
        raw_identity = request["expected_identity"]
        if operation == "read":
            if raw_identity is not None or expected or replacement:
                raise _KeychainWorkerProtocolError(
                    "the native Keychain read request contains replacement state"
                )
            expected_identity = None
        else:
            if raw_identity is None:
                raise _KeychainWorkerProtocolError(
                    "the native Keychain replace request is missing its identity"
                )
            expected_identity = _identity_from_worker_metadata(raw_identity)
        result = _WorkerRequest(
            operation=operation,
            account=account,
            service=service,
            expected=expected,
            replacement=replacement,
            expected_identity=expected_identity,
        )
        expected = bytearray()
        replacement = bytearray()
        return result
    finally:
        _zero(expected)
        _zero(replacement)


def _send_worker_response(
    connection: socket.socket,
    metadata: dict[str, object],
    payload: bytearray | None,
    *,
    deadline: float,
) -> None:
    encoded = _encode_worker_metadata(metadata)
    _send_worker_frame(
        connection,
        encoded,
        maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
        deadline=deadline,
    )
    _send_worker_frame(
        connection,
        payload if payload is not None else bytearray(),
        maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
        deadline=deadline,
    )


def _success_worker_metadata(
    *,
    kind: str,
    identity: KeychainIdentity | None,
) -> dict[str, object]:
    return {
        "protocol": _KEYCHAIN_WORKER_PROTOCOL,
        "status": "ok",
        "kind": kind,
        "identity": (
            _identity_to_worker_metadata(identity) if identity is not None else None
        ),
        "error_type": None,
        "message": None,
    }


def _error_worker_metadata(error: MacOSKeychainError) -> dict[str, object]:
    error_type = type(error)
    if error_type.__name__ not in _worker_error_types():
        error_type = MacOSKeychainInspectionInconclusive
        message = "the native Keychain worker failed unexpectedly"
    else:
        message = str(error)
    return {
        "protocol": _KEYCHAIN_WORKER_PROTOCOL,
        "status": "error",
        "kind": "error",
        "identity": None,
        "error_type": error_type.__name__,
        "message": message,
    }


def _decode_worker_response(
    metadata: dict[str, object],
    payload: bytearray,
    *,
    operation: str,
) -> _WorkerResponse:
    response = _worker_require_keys(
        metadata,
        {
            "protocol",
            "status",
            "kind",
            "identity",
            "error_type",
            "message",
        },
        label="response",
    )
    if _worker_int(response["protocol"], label="protocol") != _KEYCHAIN_WORKER_PROTOCOL:
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker protocol version is unsupported"
        )
    status = _worker_string(
        response["status"],
        label="response status",
        maximum_bytes=16,
    )
    kind = _worker_string(
        response["kind"],
        label="response kind",
        maximum_bytes=16,
    )
    if status == "error":
        if kind != "error" or response["identity"] is not None or payload:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker error response is invalid"
            )
        error_name = _worker_string(
            response["error_type"],
            label="error type",
            maximum_bytes=128,
        )
        message = _worker_string(
            response["message"],
            label="error message",
            maximum_bytes=4096,
        )
        error_type = _worker_error_types().get(error_name)
        if error_type is None:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker error type is unsupported"
            )
        raise error_type(message)
    if (
        status != "ok"
        or response["error_type"] is not None
        or response["message"] is not None
    ):
        raise _KeychainWorkerProtocolError(
            "the native Keychain worker success response is invalid"
        )
    raw_identity = response["identity"]
    if operation == "read" and kind == "none":
        if raw_identity is not None or payload:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker empty read response is invalid"
            )
        return _WorkerResponse(kind=kind, payload=None, identity=None)
    if operation == "read" and kind == "read":
        if raw_identity is None:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker read response is missing its identity"
            )
        return _WorkerResponse(
            kind=kind,
            payload=payload,
            identity=_identity_from_worker_metadata(raw_identity),
        )
    if operation == "replace" and kind == "replace":
        if raw_identity is None or payload:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker replace response is invalid"
            )
        return _WorkerResponse(
            kind=kind,
            payload=None,
            identity=_identity_from_worker_metadata(raw_identity),
        )
    raise _KeychainWorkerProtocolError(
        "the native Keychain worker response does not match its request"
    )


def _serve_keychain_worker(connection: socket.socket) -> int:
    deadline = time.monotonic() + _KEYCHAIN_WORKER_SELF_DESTRUCT_SECONDS
    request: _WorkerRequest | None = None
    result_payload: bytearray | None = None
    runtime: _Runtime | None = None
    try:
        request = _receive_worker_request(connection, deadline=deadline)
        runtime = _login_keychain_runtime()
        if request.operation == "read":
            result = _read_with_runtime(
                request.account,
                request.service,
                runtime,
            )
            if result is None:
                _send_worker_response(
                    connection,
                    _success_worker_metadata(kind="none", identity=None),
                    None,
                    deadline=deadline,
                )
                return 0
            result_payload, identity = result
            _send_worker_response(
                connection,
                _success_worker_metadata(kind="read", identity=identity),
                result_payload,
                deadline=deadline,
            )
            return 0
        assert request.expected_identity is not None
        identity = _replace_with_runtime(
            request.account,
            request.service,
            request.expected,
            request.replacement,
            request.expected_identity,
            runtime,
        )
        _send_worker_response(
            connection,
            _success_worker_metadata(kind="replace", identity=identity),
            None,
            deadline=deadline,
        )
        return 0
    except MacOSKeychainError as error:
        try:
            _send_worker_response(
                connection,
                _error_worker_metadata(error),
                None,
                deadline=deadline,
            )
            return 0
        except BaseException:
            return 1
    except BaseException:
        try:
            _send_worker_response(
                connection,
                _error_worker_metadata(
                    MacOSKeychainInspectionInconclusive(
                        "the native Keychain worker failed unexpectedly"
                    )
                ),
                None,
                deadline=deadline,
            )
            return 0
        except BaseException:
            return 1
    finally:
        cleanup_errors = _zero_all(
            (
                request.expected if request is not None else None,
                request.replacement if request is not None else None,
                result_payload,
            )
        )
        if runtime is not None:
            try:
                runtime.backend.restore_user_interaction()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            return 1


def _run_supervised_keychain_operation(
    *,
    operation: str,
    account: str,
    service: str,
    expected: bytes | bytearray | memoryview = b"",
    replacement: bytes | bytearray | memoryview = b"",
    expected_identity: KeychainIdentity | None = None,
    timeout_seconds: float = KEYCHAIN_WORKER_TIMEOUT_SECONDS,
) -> _WorkerResponse:
    dispatch_state = _WorkerDispatchState()
    try:
        return _run_supervised_keychain_operation_once(
            operation=operation,
            account=account,
            service=service,
            expected=expected,
            replacement=replacement,
            expected_identity=expected_identity,
            timeout_seconds=timeout_seconds,
            dispatch_state=dispatch_state,
        )
    except BaseException as error:
        if (
            dispatch_state.worker_spawned
            and not dispatch_state.worker_termination_proven
        ):
            failure = dispatch_state.worker_termination_failure
            if failure is None:
                failure = MacOSKeychainWorkerTerminationInconclusive(
                    "the native Keychain worker termination result is inconclusive"
                )
            if error is failure:
                raise
            control_flow = _supervisor_control_flow_from_cause_chain(error)
            if control_flow is None:
                control_flow = _supervisor_control_flow_from_cause_chain(
                    failure.__cause__
                )
            raise failure from (control_flow or error)
        if isinstance(
            error,
            (
                MacOSKeychainWorkerTerminationInconclusive,
                MacOSKeychainWriteOutcomeUnknown,
            ),
        ):
            raise
        if not (
            dispatch_state.replacement_dispatched
            and not dispatch_state.outcome_resolved
        ):
            raise
        failure = MacOSKeychainWriteOutcomeUnknown(
            "the native Keychain replacement was interrupted after dispatch"
        )
        raise failure from error


def _run_supervised_keychain_operation_once(
    *,
    operation: str,
    account: str,
    service: str,
    expected: bytes | bytearray | memoryview = b"",
    replacement: bytes | bytearray | memoryview = b"",
    expected_identity: KeychainIdentity | None = None,
    timeout_seconds: float = KEYCHAIN_WORKER_TIMEOUT_SECONDS,
    dispatch_state: _WorkerDispatchState,
) -> _WorkerResponse:
    if operation not in {"read", "replace"}:
        raise MacOSKeychainUnsafe("the native Keychain worker operation is invalid")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or timeout_seconds > _KEYCHAIN_WORKER_SELF_DESTRUCT_SECONDS
    ):
        raise MacOSKeychainUnsafe("the native Keychain worker timeout is invalid")
    try:
        _worker_string(
            account,
            label="account",
            maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
        )
        _worker_string(
            service,
            label="service",
            maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
        )
    except _KeychainWorkerProtocolError as error:
        raise MacOSKeychainUnsafe(str(error)) from error
    expected_copy: bytearray | None = None
    replacement_copy: bytearray | None = None
    response_metadata: bytearray | None = None
    response_payload: bytearray | None = None
    parent_connection: socket.socket | None = None
    child_connection: socket.socket | None = None
    process: subprocess.Popen[bytes] | None = None
    primary: BaseException | None = None
    write_outcome_may_be_unknown = False
    try:
        if operation == "read":
            if expected_identity is not None or expected or replacement:
                raise MacOSKeychainUnsafe(
                    "the native Keychain read request contains replacement state"
                )
            identity_metadata = None
            expected_copy = bytearray()
            replacement_copy = bytearray()
        else:
            if expected_identity is None:
                raise MacOSKeychainIdentityMismatch(
                    "the expected login Keychain identity is invalid"
                )
            identity_metadata = _identity_to_worker_metadata(expected_identity)
            expected_copy = _credential_copy(expected, label="expected")
            replacement_copy = _credential_copy(replacement, label="replacement")
            if (
                len(expected_copy) > MAXIMUM_CREDENTIAL_BYTES
                or len(replacement_copy) > MAXIMUM_CREDENTIAL_BYTES
            ):
                raise MacOSKeychainUnsafe(
                    "the guarded Keychain credential exceeds its bounded size"
                )
        request_metadata = _encode_worker_metadata(
            {
                "protocol": _KEYCHAIN_WORKER_PROTOCOL,
                "operation": operation,
                "account": account,
                "service": service,
                "expected_identity": identity_metadata,
            }
        )
        parent_connection, child_connection = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        command = _worker_command(child_connection.fileno())
        process = subprocess.Popen(
            command,
            cwd="/",
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(child_connection.fileno(),),
            start_new_session=True,
        )
        dispatch_state.worker_spawned = True
        child_connection.close()
        child_connection = None
        deadline = time.monotonic() + float(timeout_seconds)
        _send_worker_frame(
            parent_connection,
            request_metadata,
            maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
            deadline=deadline,
        )
        _send_worker_frame(
            parent_connection,
            expected_copy,
            maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
            deadline=deadline,
        )
        write_outcome_may_be_unknown = operation == "replace"
        dispatch_state.replacement_dispatched = write_outcome_may_be_unknown
        _send_worker_frame(
            parent_connection,
            replacement_copy,
            maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
            deadline=deadline,
        )
        try:
            parent_connection.shutdown(socket.SHUT_WR)
        except OSError as error:
            raise _KeychainWorkerProtocolError(
                "cannot finish the native Keychain worker request"
            ) from error
        response_metadata = _receive_worker_frame(
            parent_connection,
            maximum_bytes=_KEYCHAIN_WORKER_METADATA_BYTES,
            deadline=deadline,
        )
        response_payload = _receive_worker_frame(
            parent_connection,
            maximum_bytes=MAXIMUM_CREDENTIAL_BYTES,
            deadline=deadline,
        )
        _require_worker_protocol_eof(
            parent_connection,
            deadline=deadline,
        )
        try:
            returncode = process.wait(timeout=_worker_remaining(deadline))
        except subprocess.TimeoutExpired as error:
            raise _KeychainWorkerTimedOut(
                "the native Keychain worker exceeded its hard timeout"
            ) from error
        if returncode != 0:
            raise _KeychainWorkerProtocolError(
                "the native Keychain worker exited without a safe result"
            )
        metadata = _decode_worker_metadata(response_metadata)
        try:
            response = _decode_worker_response(
                metadata,
                response_payload,
                operation=operation,
            )
        except MacOSKeychainError:
            dispatch_state.outcome_resolved = True
            raise
        dispatch_state.outcome_resolved = True
        if response.payload is response_payload:
            response_payload = None
        return response
    except _KeychainWorkerTimedOut as error:
        failure_type = (
            MacOSKeychainWriteOutcomeUnknown
            if write_outcome_may_be_unknown
            else MacOSKeychainInspectionInconclusive
        )
        primary = failure_type(
            f"native Keychain {operation} timed out after "
            f"{float(timeout_seconds):g} seconds"
        )
        raise primary from error
    except _KeychainWorkerProtocolError as error:
        failure_type = (
            MacOSKeychainWriteOutcomeUnknown
            if write_outcome_may_be_unknown
            else MacOSKeychainInspectionInconclusive
        )
        primary = failure_type(
            "the native Keychain worker returned an inconclusive result"
        )
        raise primary from error
    except (OSError, subprocess.SubprocessError) as error:
        failure_type = (
            MacOSKeychainWriteOutcomeUnknown
            if write_outcome_may_be_unknown
            else MacOSKeychainInspectionInconclusive
        )
        primary = failure_type("cannot supervise the native Keychain worker safely")
        raise primary from error
    except BaseException as error:
        primary = error
        raise
    finally:
        _cleanup_supervised_keychain_worker(
            process=process,
            connections=(child_connection, parent_connection),
            payloads=(
                expected_copy,
                replacement_copy,
                response_metadata,
                response_payload,
            ),
            primary=primary,
            dispatch_state=dispatch_state,
        )


def read_login_keychain_credential(
    account: str,
    service: str,
) -> tuple[bytearray, KeychainIdentity] | None:
    """Read an exact generic-password payload from the real login Keychain."""

    if sys.platform != "darwin":
        raise MacOSKeychainUnavailable(
            "the local-login Keychain binding is available only on macOS"
        )
    response = _run_supervised_keychain_operation(
        operation="read",
        account=account,
        service=service,
    )
    if response.kind == "none":
        return None
    if response.payload is None or response.identity is None:
        raise MacOSKeychainInspectionInconclusive(
            "the native Keychain worker returned an incomplete read result"
        )
    return response.payload, response.identity


def replace_login_keychain_credential(
    account: str,
    service: str,
    expected: bytes | bytearray | memoryview,
    replacement: bytes | bytearray | memoryview,
    expected_identity: KeychainIdentity,
) -> KeychainIdentity:
    """Guardedly replace one generic-password item on its bound item ref."""

    if sys.platform != "darwin":
        raise MacOSKeychainUnavailable(
            "the local-login Keychain binding is available only on macOS"
        )
    response = _run_supervised_keychain_operation(
        operation="replace",
        account=account,
        service=service,
        expected=expected,
        replacement=replacement,
        expected_identity=expected_identity,
    )
    if response.identity is None:
        raise MacOSKeychainInspectionInconclusive(
            "the native Keychain worker returned an incomplete replacement result"
        )
    return response.identity


def _errno_suffix(error: OSError) -> str:
    if isinstance(error.errno, int):
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return " (unsafe symlink or non-directory component)"
        return f" (errno {error.errno})"
    return ""


def _keychain_worker_entrypoint(arguments: list[str]) -> int:
    if (
        len(arguments) != 2
        or arguments[0] != _KEYCHAIN_WORKER_FLAG
        or not arguments[1].isdigit()
    ):
        return 2
    descriptor = int(arguments[1])
    if descriptor < 3 or sys.platform != "darwin":
        return 2
    os.umask(0o077)
    connection: socket.socket | None = None
    timer_armed = False
    try:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.setitimer(
            signal.ITIMER_REAL,
            _KEYCHAIN_WORKER_SELF_DESTRUCT_SECONDS,
        )
        timer_armed = True
        connection = socket.socket(fileno=descriptor)
        connection.set_inheritable(False)
        if (
            connection.family != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_STREAM
        ):
            return 2
        return _serve_keychain_worker(connection)
    except BaseException:
        return 1
    finally:
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


__all__ = [
    "KeychainDescriptorPolicyIdentity",
    "KeychainIdentity",
    "KeychainPathComponentIdentity",
    "MacOSKeychainError",
    "MacOSKeychainIdentityMismatch",
    "MacOSKeychainInspectionInconclusive",
    "MacOSKeychainPayloadMismatch",
    "MacOSKeychainUnavailable",
    "MacOSKeychainUnsafe",
    "MacOSKeychainWorkerTerminationInconclusive",
    "MacOSKeychainWriteOutcomeUnknown",
    "read_login_keychain_credential",
    "replace_login_keychain_credential",
]


if __name__ == "__main__":
    raise SystemExit(_keychain_worker_entrypoint(sys.argv[1:]))
