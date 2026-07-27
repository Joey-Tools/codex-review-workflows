from __future__ import annotations

import os
import signal
import threading
from contextvars import ContextVar, Token
from types import FrameType
from typing import Any, Callable


OWNED_TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT)


class DeferredSignalInterrupt:
    """Delay one signal exception across a process-ownership critical section."""

    def __init__(self, exception_factory: Callable[[int], BaseException]) -> None:
        self._exception_factory = exception_factory
        self._defer_depth = 0
        self._requested_signal: int | None = None
        self._delivered = False

    def request(self, signal_number: int) -> None:
        if self._delivered:
            return
        if self._requested_signal is None:
            self._requested_signal = signal_number
        if self._defer_depth == 0:
            self.checkpoint()

    def checkpoint(self, *, force: bool = False) -> None:
        if (
            (self._defer_depth != 0 and not force)
            or self._requested_signal is None
            or self._delivered
        ):
            return
        self._delivered = True
        raise self._exception_factory(self._requested_signal)

    def begin_deferral(self) -> None:
        self._defer_depth += 1

    def end_deferral(self) -> None:
        if self._defer_depth <= 0:
            raise RuntimeError("signal-interrupt deferral is not active")
        self._defer_depth -= 1


class DeferredSignalScope:
    def __init__(self, interrupt: DeferredSignalInterrupt) -> None:
        self._interrupt = interrupt
        self._active = True
        interrupt.begin_deferral()

    def finish(self, *, deliver: bool = True) -> None:
        if not self._active:
            return
        self._interrupt.end_deferral()
        self._active = False
        if deliver:
            self._interrupt.checkpoint()


_BOUND_SIGNAL_INTERRUPT: ContextVar[DeferredSignalInterrupt | None] = ContextVar(
    "bounded_git_signal_interrupt",
    default=None,
)


def activate_deferred_signal_interrupt(
    interrupt: DeferredSignalInterrupt,
) -> Token[DeferredSignalInterrupt | None]:
    return _BOUND_SIGNAL_INTERRUPT.set(interrupt)


def deactivate_deferred_signal_interrupt(
    token: Token[DeferredSignalInterrupt | None],
) -> None:
    _BOUND_SIGNAL_INTERRUPT.reset(token)


def begin_bound_signal_deferral() -> DeferredSignalScope | None:
    interrupt = _BOUND_SIGNAL_INTERRUPT.get()
    if interrupt is None:
        return None
    return DeferredSignalScope(interrupt)


def checkpoint_bound_signal_interrupt(*, force: bool = False) -> None:
    interrupt = _BOUND_SIGNAL_INTERRUPT.get()
    if interrupt is not None:
        interrupt.checkpoint(force=force)


class ForwardedHostSignal(BaseException):
    pass


class HostSignalRelay:
    """Own termination signals until a bound child is cleaned up and reaped."""

    def __init__(self) -> None:
        self._previous: list[tuple[signal.Signals, Any]] = []
        self._original_handlers: dict[signal.Signals, Any] = {}
        self._received: signal.Signals | None = None
        self._target_pid: int | None = None
        self._previous_mask: set[signal.Signals] | None = None

    @property
    def received(self) -> signal.Signals | None:
        return self._received

    def __enter__(self) -> HostSignalRelay:
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("host signal relay requires the main thread")
        pthread_sigmask = getattr(signal, "pthread_sigmask", None)
        if not callable(pthread_sigmask):
            raise RuntimeError("host signal relay requires signal-mask ownership")
        try:
            self._previous_mask = set(
                pthread_sigmask(signal.SIG_BLOCK, OWNED_TERMINATION_SIGNALS)
            )
            for value in OWNED_TERMINATION_SIGNALS:
                previous = signal.getsignal(value)
                signal.signal(value, self._handle)
                self._previous.append((value, previous))
                self._original_handlers[value] = previous
            active_mask = self._previous_mask.difference(OWNED_TERMINATION_SIGNALS)
            pthread_sigmask(signal.SIG_SETMASK, active_mask)
        except BaseException:
            self._restore()
            raise
        return self

    def __exit__(self, *_args: Any) -> None:
        self._restore()

    def bind(self, pid: int) -> None:
        if type(pid) is not int or pid <= 1:
            raise ValueError("signal relay target PID is invalid")
        if self._target_pid is not None and self._target_pid != pid:
            raise RuntimeError("signal relay already owns another process")
        self._target_pid = pid
        if self._received is not None:
            self._forward(self._received)

    def unbind(self, pid: int) -> None:
        if self._target_pid == pid:
            self._target_pid = None

    def checkpoint(self) -> None:
        if self._received is not None:
            self._forward(self._received)
            raise ForwardedHostSignal()

    def redeliver(self) -> None:
        if self._previous:
            raise RuntimeError(
                "host signal handlers must be restored before redelivery"
            )
        if self._received is not None:
            redelivery = self._received
            if (
                redelivery == signal.SIGQUIT
                and self._original_handlers.get(signal.SIGQUIT) == signal.SIG_DFL
            ):
                # Preserve default termination semantics without creating a core
                # image that could retain authentication material.
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                redelivery = signal.SIGTERM
            os.kill(os.getpid(), redelivery)

    def _handle(self, number: int, _frame: FrameType | None) -> None:
        value = signal.Signals(number)
        if self._received is None:
            self._received = value
        self._forward(value)

    def _forward(self, value: signal.Signals) -> None:
        if self._target_pid is None:
            return
        # Preserve host SIGQUIT redelivery without core-dumping authenticated child state.
        target_signal = signal.SIGTERM if value == signal.SIGQUIT else value
        try:
            process_group = os.getpgid(self._target_pid)
        except ProcessLookupError:
            return
        try:
            if process_group == self._target_pid:
                os.killpg(process_group, target_signal)
            else:
                os.kill(self._target_pid, target_signal)
        except ProcessLookupError:
            return

    def _restore(self) -> None:
        errors: list[BaseException] = []
        pthread_sigmask = getattr(signal, "pthread_sigmask", None)
        if self._previous_mask is not None:
            try:
                if not callable(pthread_sigmask):
                    raise RuntimeError("signal-mask restoration is unavailable")
                pthread_sigmask(signal.SIG_BLOCK, OWNED_TERMINATION_SIGNALS)
            except BaseException as error:
                errors.append(error)
        while self._previous:
            value, previous = self._previous.pop()
            try:
                signal.signal(value, previous)
            except BaseException as error:
                errors.append(error)
        if self._previous_mask is not None:
            previous_mask = self._previous_mask
            self._previous_mask = None
            try:
                if not callable(pthread_sigmask):
                    raise RuntimeError("signal-mask restoration is unavailable")
                pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise RuntimeError("host signal relay restoration failed") from errors[0]
