from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Literal

from review_supervisor.models import Identity
from review_supervisor.signal_relay import (
    DeferredSignalScope,
    begin_bound_signal_deferral,
    checkpoint_bound_signal_interrupt,
)

FdCustodyState = Literal[
    "empty",
    "owned",
    "transferred",
    "close-outcome-unproven",
    "closed",
]

_SUPPORTED_SIGNALS = (
    signal.SIGHUP,
    signal.SIGINT,
    signal.SIGQUIT,
    signal.SIGTERM,
)


def _add_secondary_error_note(
    primary: BaseException,
    operation: str,
    secondary: BaseException,
) -> None:
    try:
        primary.add_note(
            f"{operation} also failed with {type(secondary).__name__}: {secondary}"
        )
    except BaseException:
        pass


class _SupportedAsyncCriticalSection:
    """Suppress the explicitly supported current-thread interruption sources.

    This is deliberately not a general Python asynchronous-exception guard. It
    covers current-thread ``sys.settrace`` and ``sys.setprofile`` callbacks and
    SIGHUP, SIGINT, SIGQUIT, and SIGTERM delivered to this thread. When a
    ``DeferredSignalInterrupt`` is bound, its deferral scope remains active
    until the signal mask and both hooks have been restored.

    The acquisition callback is trusted infrastructure and must not change the
    current thread's trace/profile hooks or signal mask, install a signal
    handler, or invoke code that does so before publishing the result. This
    helper cannot enforce that non-interference precondition after the callback
    has acquired an otherwise unreachable integer descriptor.

    It does not protect against ``PyThreadState_SetAsyncExc``, SIGKILL, either
    the callback or another thread changing the hooks or signal mask, or
    process-directed signal delivery to another unblocked thread in a
    multithreaded process. Once the descriptor is published, restoration runs
    best-effort: a previously installed hook that raises while being restored
    may be disabled by CPython, but it cannot make the descriptor unreachable
    or leave a bound signal-deferral scope active.
    """

    def __init__(self) -> None:
        self._previous_trace: object = None
        self._previous_profile: object = None
        self._previous_mask: set[signal.Signals] | None = None
        self._pthread_sigmask: Callable[..., object] | None = None
        self._trace_restore_required = False
        self._profile_restore_required = False
        self._mask_restore_required = False
        self._signal_scope: DeferredSignalScope | None = None
        self._entered = False

    def __enter__(self) -> _SupportedAsyncCriticalSection:
        if self._entered:
            raise RuntimeError("supported async critical section is not reusable")

        pthread_sigmask = getattr(signal, "pthread_sigmask", None)
        if not callable(pthread_sigmask):
            raise RuntimeError("FD custody requires pthread_sigmask")

        self._previous_trace = sys.gettrace()
        self._previous_profile = sys.getprofile()
        # Querying with an empty set does not change the mask. Publishing this
        # snapshot before the mutating call lets entry cleanup restore an exact
        # prior mask even if that later call has an ambiguous outcome.
        self._previous_mask = set(pthread_sigmask(signal.SIG_BLOCK, ()))
        self._pthread_sigmask = pthread_sigmask

        try:
            self._trace_restore_required = True
            sys.settrace(None)
            self._profile_restore_required = True
            sys.setprofile(None)

            self._mask_restore_required = True
            pthread_sigmask(signal.SIG_BLOCK, _SUPPORTED_SIGNALS)
            # Hooks are suspended and the supported signals are blocked before
            # the bound scope is created, closing its own CALL-to-STORE gap for
            # the interruption sources in this module's stated contract.
            self._signal_scope = begin_bound_signal_deferral()
        except BaseException as error:
            self._restore(error)
            raise

        self._entered = True
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        error: BaseException | None,
        _traceback: object,
    ) -> bool:
        first_error = self._restore(error)
        self._entered = False
        if error is not None:
            return False
        if first_error is not None:
            raise first_error
        return False

    def _restore(self, primary: BaseException | None) -> BaseException | None:
        first_error = primary
        secondary_errors: list[tuple[str, BaseException]] = []

        # Restore the mask while both Python hooks are still quiescent. A
        # delivered project-owned signal remains deferred by ``signal_scope``.
        if self._mask_restore_required:
            self._mask_restore_required = False
            pthread_sigmask = self._pthread_sigmask
            previous_mask = self._previous_mask
            try:
                if pthread_sigmask is None or previous_mask is None:
                    raise RuntimeError("FD custody signal-mask state is unavailable")
                pthread_sigmask(signal.SIG_SETMASK, previous_mask)

            except BaseException as restore_error:
                if first_error is None:
                    first_error = restore_error
                else:
                    secondary_errors.append(("signal-mask restoration", restore_error))

        # End the bound deferral before re-enabling arbitrary user callbacks.
        # Delivery is checkpointed only after hook restoration. This prevents a
        # restored hook from interrupting the sole scope-finishing call and
        # leaving the signal relay permanently deferred.
        signal_scope = self._signal_scope
        self._signal_scope = None
        if signal_scope is not None:
            try:
                signal_scope.finish(deliver=False)
            except BaseException as restore_error:
                if first_error is None:
                    first_error = restore_error
                else:
                    secondary_errors.append(
                        ("bound-signal-scope restoration", restore_error)
                    )

        if self._profile_restore_required:
            self._profile_restore_required = False
            previous_profile = self._previous_profile
            try:
                sys.setprofile(previous_profile)
            except BaseException as restore_error:
                if first_error is None:
                    first_error = restore_error
                else:
                    secondary_errors.append(("profile-hook restoration", restore_error))

        if self._trace_restore_required:
            self._trace_restore_required = False
            previous_trace = self._previous_trace
            try:
                sys.settrace(previous_trace)
            except BaseException as restore_error:
                if first_error is None:
                    first_error = restore_error
                else:
                    secondary_errors.append(("trace-hook restoration", restore_error))
                # A just-restored profile callback can interrupt the C call
                # before ``settrace`` executes. CPython disables a callback
                # that raises, so make one bounded second attempt. If the trace
                # callback itself raised after installation, this may fail
                # again and remains a best-effort restoration outcome.
                try:
                    sys.settrace(previous_trace)
                except BaseException as retry_error:
                    secondary_errors.append(
                        ("trace-hook restoration retry", retry_error)
                    )

        # A project-owned signal requested while masked is now safe to expose:
        # the descriptor is published, the mask is restored, and no bound scope
        # remains active. Preserve an existing body/restoration exception and
        # leave its pending signal for the caller's next explicit checkpoint.
        if first_error is None:
            try:
                checkpoint_bound_signal_interrupt()
            except BaseException as checkpoint_error:
                first_error = checkpoint_error

        if first_error is not None:
            for operation, secondary in secondary_errors:
                _add_secondary_error_note(first_error, operation, secondary)
        return first_error


class _DescriptorCustody:
    """One-shot descriptor custody with publish-before-close evidence."""

    __slots__ = ("_descriptor", "_state", "close_error")

    def __init__(self) -> None:
        self._descriptor: int | None = None
        self._state: FdCustodyState = "empty"
        self.close_error: BaseException | None = None

    @property
    def state(self) -> FdCustodyState:
        return self._state

    @property
    def descriptor(self) -> int | None:
        return self._descriptor

    def _publish_descriptor(self, descriptor: int) -> None:
        if self._state != "empty" or self._descriptor is not None:
            raise ValueError("FD custody owner is already used")
        if type(descriptor) is not int or descriptor < 0:
            raise ValueError("FD custody result is not a valid descriptor")
        self._descriptor = descriptor
        self._state = "owned"

    def _transfer_descriptor(self, descriptor: int) -> None:
        if self._state != "owned" or self._descriptor != descriptor:
            raise ValueError("FD custody transfer is inconsistent")
        self._state = "transferred"

    def close(self) -> None:
        if self._state in {"closed", "close-outcome-unproven"}:
            return
        if self._state == "empty":
            self._state = "closed"
            return
        if self._state == "transferred":
            raise RuntimeError("transferred FD custody cannot close the descriptor")
        if self._state != "owned" or self._descriptor is None:
            raise RuntimeError("FD custody has an invalid close state")

        descriptor = self._descriptor
        # Publish ambiguity before entering close. An exception may arrive
        # before the syscall or after the kernel closed the descriptor. Either
        # outcome makes retry unsafe because the integer may have been reused.
        self._state = "close-outcome-unproven"
        try:
            os.close(descriptor)
        except BaseException as error:
            self.close_error = error
            try:
                setattr(error, "async_fd_custody_owner", self)
            except BaseException:
                pass
            raise
        self._descriptor = None
        self._state = "closed"
        self.close_error = None


class RawFdCustody(_DescriptorCustody):
    """Caller-precreated custody for one raw file descriptor."""

    def publish(self, descriptor: int) -> None:
        self._publish_descriptor(descriptor)

    def transfer(self, descriptor: int) -> None:
        """Settle the handoff after the caller has stored ``descriptor``."""

        self._transfer_descriptor(descriptor)


class FdIdentityCustody(_DescriptorCustody):
    """Caller-precreated custody for an ``(fd, Identity)`` result."""

    __slots__ = ("_identity",)

    def __init__(self) -> None:
        super().__init__()
        self._identity: Identity | None = None

    @property
    def identity(self) -> Identity | None:
        return self._identity

    def publish(self, result: tuple[int, Identity]) -> None:
        if type(result) is not tuple or len(result) != 2:
            raise ValueError("FD identity custody result is malformed")
        descriptor, identity = result
        # Take custody of a valid descriptor before validating the companion
        # value, so a malformed trusted-helper result cannot orphan the FD.
        self._publish_descriptor(descriptor)
        if not isinstance(identity, Identity):
            raise ValueError("FD identity custody result has an invalid identity")
        self._identity = identity

    def transfer(self, descriptor: int, identity: Identity) -> None:
        """Settle the handoff after both caller locals are fully stored."""

        if self._identity != identity:
            raise ValueError("FD identity custody transfer is inconsistent")
        self._transfer_descriptor(descriptor)


class FdCloseSettlement:
    """Settle one long-lived custody owner without retrying an ambiguous close.

    Once this method body is entered, ``settle`` absorbs supported trace/profile
    call-boundary exceptions while the owner is still ``owned`` and retries the
    *method entry*, not an attempted close syscall. ``_DescriptorCustody.close``
    publishes ``close-outcome-unproven`` before calling ``os.close``; that state
    is terminal here and is never retried.

    Ordinary Python cannot protect an exception raised at the caller's CALL
    opcode or the callee's profile ``call`` event before this object's method
    body executes. The owner and this settlement must therefore remain reachable
    from a longer-lived scope. The minimal caller boundary is::

        while True:
            try:
                if owner.state != "owned":
                    break
                settlement.settle()
            except BaseException as error:
                settlement.capture(error, "FD close caller boundary")
        while True:
            try:
                settlement.raise_first()
            except BaseException as error:
                if error is settlement.first_error:
                    raise
                settlement.capture(error, "FD close final-raise boundary")
            else:
                break

    A trace/profile callback that raises is disabled by CPython, and a bound
    ``DeferredSignalInterrupt`` delivers only once. Re-arming callbacks, repeated
    independent signals, and owner subclasses are outside this bounded contract.
    """

    __slots__ = ("first_error", "owner", "secondary_errors")

    def __init__(
        self,
        owner: RawFdCustody | FdIdentityCustody,
        first_error: BaseException | None = None,
    ) -> None:
        if type(owner) not in {RawFdCustody, FdIdentityCustody}:
            raise TypeError("exact FD custody owner is required")
        if first_error is not None and not isinstance(first_error, BaseException):
            raise TypeError("first FD close error must be a BaseException")
        self.owner = owner
        self.first_error = first_error
        self.secondary_errors: tuple[tuple[str, BaseException], ...] = ()

    def capture(self, error: BaseException, operation: str) -> None:
        if not isinstance(error, BaseException):
            raise TypeError("FD close error must be a BaseException")
        if self.first_error is None:
            self.first_error = error
        elif error is not self.first_error:
            self.secondary_errors = (*self.secondary_errors, (operation, error))

    def settle(self) -> None:
        while True:
            state = self.owner.state
            if state in {"closed", "close-outcome-unproven"}:
                return
            if state == "transferred":
                raise RuntimeError("transferred FD custody cannot be settled")
            if state not in {"empty", "owned"}:
                raise RuntimeError("FD custody has an invalid settlement state")
            try:
                self.owner.close()
            except BaseException as error:  # noqa: BLE001 - preserves control-flow
                # Inline publication avoids another Python call boundary before
                # the first control-flow object becomes reachable here.
                if self.first_error is None:
                    self.first_error = error
                elif error is not self.first_error:
                    self.secondary_errors = (
                        *self.secondary_errors,
                        ("FD close attempt", error),
                    )

    def raise_first(self) -> None:
        error = self.first_error
        if error is None:
            return
        for operation, secondary in self.secondary_errors:
            _add_secondary_error_note(error, operation, secondary)
        raise error


@contextmanager
def supported_async_publication() -> Iterator[None]:
    """Guard a short non-FD publication transaction under this module's scope.

    The body has the same trusted, non-interfering precondition and the same
    current-thread trace/profile plus four-signal boundary as FD publication.
    It exists for atomic Python state publication that must precede later
    resource acquisition; it does not broaden the asynchronous-exception
    guarantee described by :class:`_SupportedAsyncCriticalSection`.
    """

    with _SupportedAsyncCriticalSection():
        yield


@contextmanager
def supported_async_fd_publication(
    owner: RawFdCustody | FdIdentityCustody,
) -> Iterator[None]:
    """Run one acquisition/publication region under the supported guard.

    ``owner`` must be constructed by the caller before entry. A successful body
    must publish the acquired descriptor before leaving the context. The
    supported interruption boundary is intentionally limited to the current
    thread's trace/profile hooks and SIGHUP, SIGINT, SIGQUIT, and SIGTERM. The
    body is trusted and must not mutate those hooks, masks, or handlers. This
    does not provide a general asynchronous-exception guarantee.
    """

    if owner.state != "empty":
        raise ValueError("FD custody publication owner is already used")
    with _SupportedAsyncCriticalSection():
        try:
            yield
        except BaseException:
            raise
        else:
            if owner.state == "empty":
                raise RuntimeError(
                    "FD custody body returned without publishing its result"
                )


def acquire_raw_fd(
    owner: RawFdCustody,
    trusted_opener: Callable[[], int],
) -> int:
    """Acquire and publish a raw FD from a non-interfering trusted callback."""

    if not isinstance(owner, RawFdCustody):
        raise TypeError("raw FD custody owner is required")
    with supported_async_fd_publication(owner):
        descriptor = trusted_opener()
        owner.publish(descriptor)
    return descriptor


def acquire_fd_identity(
    owner: FdIdentityCustody,
    trusted_opener: Callable[[], tuple[int, Identity]],
) -> tuple[int, Identity]:
    """Publish an ``(fd, Identity)`` pair from a trusted callback."""

    if not isinstance(owner, FdIdentityCustody):
        raise TypeError("FD identity custody owner is required")
    with supported_async_fd_publication(owner):
        result = trusted_opener()
        owner.publish(result)
    return result
