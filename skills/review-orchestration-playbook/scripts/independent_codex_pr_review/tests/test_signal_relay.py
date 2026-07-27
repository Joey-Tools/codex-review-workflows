from __future__ import annotations

import os
import signal
import unittest
from unittest import mock

from review_supervisor.signal_relay import ForwardedHostSignal, HostSignalRelay


class HostSignalRelayTests(unittest.TestCase):
    def test_unblocks_inherited_owned_mask_and_restores_it_exactly(self) -> None:
        owned = {signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT}
        original = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGHUP, signal.SIGTERM}
        )
        inherited = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        try:
            with HostSignalRelay():
                active = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                self.assertTrue(owned.isdisjoint(active))
            restored = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            self.assertEqual(restored, inherited)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original)

    def test_pending_inherited_blocked_signal_is_captured_after_unblock(self) -> None:
        original = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP})
        try:
            os.kill(os.getpid(), signal.SIGHUP)
            with HostSignalRelay() as relay:
                self.assertEqual(relay.received, signal.SIGHUP)
            restored = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            self.assertIn(signal.SIGHUP, restored)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original)

    def test_redelivery_restores_default_termination_semantics(self) -> None:
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            with HostSignalRelay() as relay:
                os.kill(os.getpid(), signal.SIGTERM)
                try:
                    relay.checkpoint()
                except ForwardedHostSignal:
                    pass
            relay.redeliver()
            os._exit(99)

        waited, raw_status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFSIGNALED(raw_status))
        self.assertEqual(os.WTERMSIG(raw_status), signal.SIGTERM)

    def test_forwards_term_then_allows_cleanup_before_handler_restoration(self) -> None:
        ready_read, ready_write = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(ready_read)
                os.setsid()
                signal.signal(signal.SIGHUP, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                os.write(ready_write, b"1")
                while True:
                    signal.pause()
            finally:
                os._exit(127)

        os.close(ready_write)
        previous = signal.getsignal(signal.SIGTERM)
        child_reaped = False
        try:
            self.assertEqual(os.read(ready_read, 1), b"1")
            with HostSignalRelay() as relay:
                relay.bind(child)
                os.kill(os.getpid(), signal.SIGTERM)
                with self.assertRaises(ForwardedHostSignal):
                    relay.checkpoint()
                os.killpg(child, signal.SIGKILL)
                relay.unbind(child)
                waited, _ = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                child_reaped = True
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
            self.assertEqual(relay.received, signal.SIGTERM)
        finally:
            os.close(ready_read)
            if not child_reaped:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass

    def test_sigquit_forwards_term_then_restores_exact_handler_for_redelivery(
        self,
    ) -> None:
        redelivered: list[signal.Signals] = []
        previous = signal.getsignal(signal.SIGQUIT)
        target_pid = 424_242

        def previous_handler(number: int, _frame: object) -> None:
            redelivered.append(signal.Signals(number))

        signal.signal(signal.SIGQUIT, previous_handler)
        relay = HostSignalRelay()
        try:
            with relay:
                relay.bind(target_pid)
                with (
                    mock.patch.object(os, "getpgid", return_value=target_pid),
                    mock.patch.object(os, "killpg") as killpg,
                ):
                    os.kill(os.getpid(), signal.SIGQUIT)
                    with self.assertRaises(ForwardedHostSignal):
                        relay.checkpoint()
                relay.unbind(target_pid)
            self.assertIs(signal.getsignal(signal.SIGQUIT), previous_handler)
            self.assertEqual(
                killpg.call_args_list,
                [
                    mock.call(target_pid, signal.SIGTERM),
                    mock.call(target_pid, signal.SIGTERM),
                ],
            )

            relay.redeliver()

            self.assertEqual(redelivered, [signal.SIGQUIT])
        finally:
            signal.signal(signal.SIGQUIT, previous)

    def test_default_sigquit_redelivery_uses_non_core_termination(self) -> None:
        relay = HostSignalRelay()
        relay._received = signal.SIGQUIT
        relay._original_handlers[signal.SIGQUIT] = signal.SIG_DFL
        with (
            mock.patch.object(signal, "signal") as install,
            mock.patch.object(os, "kill") as kill,
        ):
            relay.redeliver()
        install.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(os.getpid(), signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
