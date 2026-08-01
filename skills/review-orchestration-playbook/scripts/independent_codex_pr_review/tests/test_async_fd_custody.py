from __future__ import annotations

import dis
import os
import signal
import sys
import unittest
from types import FrameType
from unittest import mock

from review_supervisor.models import Identity
from review_supervisor.signal_relay import (
    DeferredSignalInterrupt,
    activate_deferred_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)

from tests import async_fd_custody
from tests.async_fd_custody import (
    FdCloseSettlement,
    FdIdentityCustody,
    RawFdCustody,
    acquire_fd_identity,
    acquire_raw_fd,
)


def _identity() -> Identity:
    return Identity(
        device=1,
        inode=2,
        mode=0o40700,
        link_count=2,
        uid=os.getuid(),
        size=0,
    )


def _call_followup_offset(
    function: object,
    *,
    called_name: str,
    following_opname: str,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 32) : index]
        if not any(candidate.argval == called_name for candidate in prior):
            continue
        following = instructions[index + 1]
        if following.opname == following_opname:
            return following.offset
    raise AssertionError(
        f"cannot find {called_name} CALL-to-{following_opname} boundary"
    )


class AsyncFdCustodyTests(unittest.TestCase):
    def test_normal_raw_close_and_pair_transfer(self) -> None:
        raw_owner = RawFdCustody()
        raw_descriptor = acquire_raw_fd(
            raw_owner,
            lambda: os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC),
        )

        self.assertEqual(raw_owner.state, "owned")
        self.assertEqual(raw_owner.descriptor, raw_descriptor)
        raw_owner.close()
        self.assertEqual(raw_owner.state, "closed")
        self.assertIsNone(raw_owner.descriptor)
        with self.assertRaises(OSError):
            os.fstat(raw_descriptor)

        pair_owner = FdIdentityCustody()
        expected_identity = _identity()
        opened = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            descriptor, identity = acquire_fd_identity(
                pair_owner,
                lambda: (opened, expected_identity),
            )
            self.assertEqual(pair_owner.state, "owned")
            self.assertEqual(pair_owner.descriptor, descriptor)
            self.assertEqual(pair_owner.identity, identity)

            pair_owner.transfer(descriptor, identity)
            self.assertEqual(pair_owner.state, "transferred")
            with self.assertRaisesRegex(RuntimeError, "transferred"):
                pair_owner.close()
        finally:
            os.close(opened)

    def test_open_error_leaves_precreated_owner_empty(self) -> None:
        owner = RawFdCustody()
        expected = OSError("synthetic open failure")

        with self.assertRaises(OSError) as raised:
            acquire_raw_fd(owner, lambda: (_ for _ in ()).throw(expected))

        self.assertIs(raised.exception, expected)
        self.assertEqual(owner.state, "empty")
        self.assertIsNone(owner.descriptor)

    def test_trace_and_profile_cannot_observe_call_to_publication(self) -> None:
        owner = RawFdCustody()
        traced_codes = {
            RawFdCustody.publish.__code__,
            async_fd_custody._DescriptorCustody._publish_descriptor.__code__,
        }
        trace_events: list[tuple[str, str]] = []
        profile_events: list[tuple[str, str]] = []

        def opener() -> int:
            return os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)

        traced_codes.add(opener.__code__)

        def trace(frame: FrameType, event: str, _argument: object) -> object:
            if frame.f_code in traced_codes:
                trace_events.append((frame.f_code.co_name, event))
            return trace

        def profile(frame: FrameType, event: str, _argument: object) -> None:
            if frame.f_code in traced_codes:
                profile_events.append((frame.f_code.co_name, event))

        previous_trace = sys.gettrace()
        previous_profile = sys.getprofile()
        descriptor: int | None = None
        sys.settrace(trace)
        sys.setprofile(profile)
        try:
            descriptor = acquire_raw_fd(owner, opener)
        finally:
            sys.setprofile(previous_profile)
            sys.settrace(previous_trace)

        try:
            self.assertEqual(trace_events, [])
            self.assertEqual(profile_events, [])
        finally:
            owner.close()
        self.assertIsNotNone(descriptor)

    def test_raw_result_owner_survives_caller_call_to_store_interrupt(self) -> None:
        owner = RawFdCustody()
        opened = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)

        def consume() -> None:
            descriptor = acquire_raw_fd(owner, lambda: opened)
            owner.transfer(descriptor)

        target_offset = _call_followup_offset(
            consume,
            called_name="acquire_raw_fd",
            following_opname="STORE_FAST",
        )

        def interrupt_store(
            frame: FrameType,
            event: str,
            _argument: object,
        ) -> object:
            if frame.f_code is consume.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and frame.f_lasti == target_offset:
                    raise KeyboardInterrupt("synthetic raw result-store interrupt")
            return interrupt_store

        previous_trace = sys.gettrace()
        sys.settrace(interrupt_store)
        try:
            with self.assertRaisesRegex(KeyboardInterrupt, "result-store"):
                consume()
        finally:
            sys.settrace(previous_trace)

        self.assertEqual(owner.state, "owned")
        self.assertEqual(owner.descriptor, opened)
        owner.close()

    def test_pair_result_owner_survives_caller_unpack_interrupt(self) -> None:
        owner = FdIdentityCustody()
        opened = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        expected_identity = _identity()

        def consume() -> None:
            descriptor, identity = acquire_fd_identity(
                owner,
                lambda: (opened, expected_identity),
            )
            owner.transfer(descriptor, identity)

        target_offset = _call_followup_offset(
            consume,
            called_name="acquire_fd_identity",
            following_opname="UNPACK_SEQUENCE",
        )

        def interrupt_unpack(
            frame: FrameType,
            event: str,
            _argument: object,
        ) -> object:
            if frame.f_code is consume.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and frame.f_lasti == target_offset:
                    raise KeyboardInterrupt("synthetic pair unpack interrupt")
            return interrupt_unpack

        previous_trace = sys.gettrace()
        sys.settrace(interrupt_unpack)
        try:
            with self.assertRaisesRegex(KeyboardInterrupt, "unpack interrupt"):
                consume()
        finally:
            sys.settrace(previous_trace)

        self.assertEqual(owner.state, "owned")
        self.assertEqual(owner.descriptor, opened)
        self.assertEqual(owner.identity, expected_identity)
        owner.close()

    def test_restoration_order_and_pending_signal_delivery(self) -> None:
        events: list[object] = []
        previous_trace = object()
        previous_profile = object()
        previous_mask = {signal.SIGUSR1}

        class SyntheticScope:
            def finish(self, *, deliver: bool = True) -> None:
                events.append(("scope-finish", deliver))

        def pthread_sigmask(how: int, values: object) -> set[signal.Signals]:
            normalized = set(values)  # type: ignore[arg-type]
            if how == signal.SIG_BLOCK and not normalized:
                events.append("mask-query")
                return previous_mask
            if how == signal.SIG_BLOCK:
                events.append(("mask-block", normalized))
                return previous_mask
            self.assertEqual(how, signal.SIG_SETMASK)
            self.assertEqual(normalized, previous_mask)
            events.append("mask-restore")
            return previous_mask

        def settrace(value: object) -> None:
            events.append(("trace", value))

        def setprofile(value: object) -> None:
            events.append(("profile", value))

        owner = RawFdCustody()
        with (
            mock.patch.object(
                async_fd_custody.sys, "gettrace", return_value=previous_trace
            ),
            mock.patch.object(
                async_fd_custody.sys,
                "getprofile",
                return_value=previous_profile,
            ),
            mock.patch.object(async_fd_custody.sys, "settrace", side_effect=settrace),
            mock.patch.object(
                async_fd_custody.sys,
                "setprofile",
                side_effect=setprofile,
            ),
            mock.patch.object(
                async_fd_custody.signal,
                "pthread_sigmask",
                side_effect=pthread_sigmask,
            ),
            mock.patch.object(
                async_fd_custody,
                "begin_bound_signal_deferral",
                side_effect=lambda: events.append("scope-begin") or SyntheticScope(),
            ),
        ):
            descriptor = acquire_raw_fd(
                owner,
                lambda: events.append("body") or 123,
            )

        self.assertEqual(descriptor, 123)
        self.assertEqual(
            events[-4:],
            [
                "mask-restore",
                ("scope-finish", False),
                ("profile", previous_profile),
                ("trace", previous_trace),
            ],
        )
        owner.transfer(descriptor)

        self.assertEqual(
            set(async_fd_custody._SUPPORTED_SIGNALS),
            {signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM},
        )

        class DeliveredSignal(BaseException):
            def __init__(self, signal_number: int) -> None:
                self.signal_number = signal_number

        for signal_number in async_fd_custody._SUPPORTED_SIGNALS:
            with self.subTest(signal=signal_number):
                delivered = DeferredSignalInterrupt(DeliveredSignal)
                token = activate_deferred_signal_interrupt(delivered)
                try:
                    previous_handler = signal.getsignal(signal_number)
                    signal.signal(
                        signal_number,
                        lambda number, _frame: delivered.request(number),
                    )
                    signal_owner = RawFdCustody()
                    try:

                        def signal_then_open() -> int:
                            os.kill(os.getpid(), signal_number)
                            return os.open(
                                "/dev/null",
                                os.O_RDONLY | os.O_CLOEXEC,
                            )

                        with self.assertRaises(DeliveredSignal) as raised:
                            acquire_raw_fd(signal_owner, signal_then_open)

                        self.assertEqual(
                            raised.exception.signal_number,
                            signal_number,
                        )
                        self.assertEqual(signal_owner.state, "owned")
                        self.assertIsNotNone(signal_owner.descriptor)
                    finally:
                        signal_owner.close()
                        signal.signal(signal_number, previous_handler)
                finally:
                    deactivate_deferred_signal_interrupt(token)

    def test_restoration_preserves_first_base_exception(self) -> None:
        events: list[object] = []
        primary = KeyboardInterrupt("synthetic body interrupt")
        previous_mask = {signal.SIGUSR1}

        class SyntheticScope:
            def finish(self, *, deliver: bool = True) -> None:
                events.append(("scope-finish", deliver))

        def pthread_sigmask(how: int, values: object) -> set[signal.Signals]:
            normalized = set(values)  # type: ignore[arg-type]
            if how == signal.SIG_BLOCK and not normalized:
                return previous_mask
            if how == signal.SIG_SETMASK:
                events.append("mask-restore")
                raise RuntimeError("synthetic mask restoration failure")
            events.append("mask-block")
            return previous_mask

        owner = RawFdCustody()
        with (
            mock.patch.object(
                async_fd_custody.signal,
                "pthread_sigmask",
                side_effect=pthread_sigmask,
            ),
            mock.patch.object(
                async_fd_custody,
                "begin_bound_signal_deferral",
                return_value=SyntheticScope(),
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            acquire_raw_fd(owner, lambda: (_ for _ in ()).throw(primary))

        self.assertIs(raised.exception, primary)
        self.assertIn("mask-restore", events)
        self.assertIn(("scope-finish", False), events)
        self.assertTrue(
            any("signal-mask restoration" in note for note in primary.__notes__)
        )
        self.assertEqual(owner.state, "empty")

        hostile_owner = RawFdCustody()
        scope_finished = False
        hostile_armed = False
        hostile_fired = False

        class HostileScope:
            def finish(self, *, deliver: bool = True) -> None:
                nonlocal scope_finished
                self.assert_false(deliver)
                scope_finished = True

            @staticmethod
            def assert_false(value: bool) -> None:
                if value:
                    raise AssertionError("hostile scope unexpectedly delivered")

        def benign_trace(
            _frame: FrameType,
            _event: str,
            _argument: object,
        ) -> object:
            return benign_trace

        def hostile_profile(
            _frame: FrameType,
            event: str,
            _argument: object,
        ) -> None:
            nonlocal hostile_armed, hostile_fired
            if hostile_armed and not hostile_fired and event in {"call", "c_call"}:
                hostile_fired = True
                hostile_armed = False
                raise RuntimeError("synthetic restored-profile interruption")

        def arm_after_open() -> int:
            nonlocal hostile_armed
            descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            hostile_armed = True
            return descriptor

        previous_trace = sys.gettrace()
        previous_profile = sys.getprofile()
        sys.settrace(benign_trace)
        sys.setprofile(hostile_profile)
        try:
            with (
                mock.patch.object(
                    async_fd_custody,
                    "begin_bound_signal_deferral",
                    return_value=HostileScope(),
                ),
                self.assertRaisesRegex(RuntimeError, "restored-profile"),
            ):
                acquire_raw_fd(hostile_owner, arm_after_open)
        finally:
            restored_trace = sys.gettrace()
            sys.setprofile(previous_profile)
            sys.settrace(previous_trace)

        self.assertTrue(hostile_fired)
        self.assertTrue(scope_finished)
        self.assertIs(restored_trace, benign_trace)
        self.assertEqual(hostile_owner.state, "owned")
        hostile_owner.close()

    def test_close_pre_and_post_call_ambiguity_is_never_retried(self) -> None:
        with self.subTest("pre-call"):
            owner = RawFdCustody()
            descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            owner.publish(descriptor)

            with mock.patch.object(
                async_fd_custody.os,
                "close",
                side_effect=KeyboardInterrupt("synthetic pre-close interrupt"),
            ) as close:
                with self.assertRaisesRegex(KeyboardInterrupt, "pre-close"):
                    owner.close()
                owner.close()

            self.assertEqual(close.call_count, 1)
            self.assertEqual(owner.state, "close-outcome-unproven")
            self.assertEqual(owner.descriptor, descriptor)
            os.close(descriptor)

        with self.subTest("post-call"):
            owner = RawFdCustody()
            descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            owner.publish(descriptor)
            real_close = os.close
            calls = 0

            def close_then_interrupt(candidate: int) -> None:
                nonlocal calls
                calls += 1
                real_close(candidate)
                raise KeyboardInterrupt("synthetic post-close interrupt")

            with mock.patch.object(
                async_fd_custody.os,
                "close",
                side_effect=close_then_interrupt,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "post-close"):
                    owner.close()
                owner.close()

            self.assertEqual(calls, 1)
            self.assertEqual(owner.state, "close-outcome-unproven")
            self.assertEqual(owner.descriptor, descriptor)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_close_settlement_retries_profile_call_event_before_method_body(
        self,
    ) -> None:
        owner = RawFdCustody()
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        owner.publish(descriptor)
        settlement = FdCloseSettlement(owner)
        interruption = RuntimeError("synthetic close profile-call interruption")
        fired = False

        def profile(frame: FrameType, event: str, _argument: object) -> None:
            nonlocal fired
            if (
                not fired
                and frame.f_code is async_fd_custody._DescriptorCustody.close.__code__
                and event == "call"
            ):
                fired = True
                raise interruption

        previous_profile = sys.getprofile()
        try:
            sys.setprofile(profile)
            settlement.settle()
        finally:
            sys.setprofile(previous_profile)

        self.assertTrue(fired)
        self.assertEqual(owner.state, "closed")
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(RuntimeError) as caught:
            settlement.raise_first()
        self.assertIs(caught.exception, interruption)

    def test_long_lived_settlement_covers_caller_call_opcode_interrupt(self) -> None:
        owner = RawFdCustody()
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        owner.publish(descriptor)
        settlement = FdCloseSettlement(owner)
        interruption = KeyboardInterrupt("synthetic close caller-CALL interruption")

        def caller() -> None:
            while True:
                try:
                    if owner.state != "owned":
                        break
                    settlement.settle()
                except BaseException as error:  # noqa: BLE001 - contract boundary
                    settlement.capture(error, "FD close caller boundary")
            while True:
                try:
                    settlement.raise_first()
                except BaseException as error:  # noqa: BLE001 - contract boundary
                    if error is settlement.first_error:
                        raise
                    settlement.capture(error, "FD close final-raise boundary")
                else:
                    break

        instructions = tuple(dis.get_instructions(caller))
        call_offset = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "settle"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        fired = False

        def trace(frame: FrameType, event: str, _argument: object) -> object:
            nonlocal fired
            if frame.f_code is caller.__code__:
                frame.f_trace_opcodes = True
                if not fired and event == "opcode" and frame.f_lasti == call_offset:
                    fired = True
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaises(KeyboardInterrupt) as caught:
                caller()
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(fired)
        self.assertIs(caught.exception, interruption)
        self.assertEqual(owner.state, "closed")
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_close_settlement_preserves_primary_and_never_retries_syscall(
        self,
    ) -> None:
        class DeliveredSignal(BaseException):
            pass

        owner = RawFdCustody()
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        owner.publish(descriptor)
        primary = DeliveredSignal("synthetic prior signal control-flow")
        settlement = FdCloseSettlement(owner, primary)
        real_close = os.close
        calls = 0

        def close_then_interrupt(candidate: int) -> None:
            nonlocal calls
            calls += 1
            real_close(candidate)
            raise RuntimeError("synthetic post-close interruption")

        with mock.patch.object(
            async_fd_custody.os,
            "close",
            side_effect=close_then_interrupt,
        ):
            settlement.settle()
            settlement.settle()

        self.assertEqual(calls, 1)
        self.assertEqual(owner.state, "close-outcome-unproven")
        with self.assertRaises(DeliveredSignal) as caught:
            settlement.raise_first()
        self.assertIs(caught.exception, primary)
        self.assertTrue(any("FD close attempt" in note for note in primary.__notes__))

    def test_long_lived_settlement_covers_final_raise_call_interrupt(self) -> None:
        owner = RawFdCustody()
        owner.close()
        primary = ValueError("synthetic saved close failure")
        settlement = FdCloseSettlement(owner, primary)
        intruder = RuntimeError("synthetic final-raise caller interruption")

        def caller() -> None:
            while True:
                try:
                    settlement.raise_first()
                except BaseException as error:  # noqa: BLE001 - contract boundary
                    if error is settlement.first_error:
                        raise
                    settlement.capture(error, "FD close final-raise boundary")
                else:
                    break

        instructions = tuple(dis.get_instructions(caller))
        call_offset = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "raise_first"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        fired = False

        def trace(frame: FrameType, event: str, _argument: object) -> object:
            nonlocal fired
            if frame.f_code is caller.__code__:
                frame.f_trace_opcodes = True
                if not fired and event == "opcode" and frame.f_lasti == call_offset:
                    fired = True
                    raise intruder
            return trace

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaises(ValueError) as caught:
                caller()
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(fired)
        self.assertIs(caught.exception, primary)
        self.assertTrue(
            any("final-raise boundary" in note for note in primary.__notes__)
        )

    def test_long_lived_settlement_covers_real_signal_at_caller_call(self) -> None:
        class DeliveredSignal(BaseException):
            def __init__(self, signal_number: int) -> None:
                self.signal_number = signal_number

        owner = RawFdCustody()
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        owner.publish(descriptor)
        settlement = FdCloseSettlement(owner)
        delivered = DeferredSignalInterrupt(DeliveredSignal)

        def caller() -> None:
            while True:
                try:
                    if owner.state != "owned":
                        break
                    settlement.settle()
                except BaseException as error:  # noqa: BLE001 - contract boundary
                    settlement.capture(error, "FD close caller boundary")
            while True:
                try:
                    settlement.raise_first()
                except BaseException as error:  # noqa: BLE001 - contract boundary
                    if error is settlement.first_error:
                        raise
                    settlement.capture(error, "FD close final-raise boundary")
                else:
                    break

        instructions = tuple(dis.get_instructions(caller))
        call_offset = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "settle"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        fired = False

        def signal_at_call(
            frame: FrameType,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal fired
            if frame.f_code is caller.__code__:
                frame.f_trace_opcodes = True
                if not fired and event == "opcode" and frame.f_lasti == call_offset:
                    fired = True
                    os.kill(os.getpid(), signal.SIGTERM)
            return signal_at_call

        token = activate_deferred_signal_interrupt(delivered)
        previous_handler = signal.getsignal(signal.SIGTERM)
        previous_trace = sys.gettrace()
        try:
            signal.signal(
                signal.SIGTERM,
                lambda number, _frame: delivered.request(number),
            )
            sys.settrace(signal_at_call)
            with self.assertRaises(DeliveredSignal) as caught:
                caller()
        finally:
            sys.settrace(previous_trace)
            signal.signal(signal.SIGTERM, previous_handler)
            deactivate_deferred_signal_interrupt(token)
            if owner.state == "owned":
                owner.close()

        self.assertTrue(fired)
        self.assertEqual(caught.exception.signal_number, signal.SIGTERM)
        self.assertEqual(owner.state, "closed")
        with self.assertRaises(OSError):
            os.fstat(descriptor)
