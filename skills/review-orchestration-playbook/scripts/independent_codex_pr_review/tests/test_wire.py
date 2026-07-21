from __future__ import annotations

import os
import time
import unittest

from review_supervisor.wire import (
    peer_is_open,
    receive_blob,
    receive_record,
    send_blob,
    send_record,
    socket_pair,
)

from tests.support import owned_temporary_directory


class ControlWireTests(unittest.TestCase):
    def test_stream_framing_and_scm_rights(self) -> None:
        with owned_temporary_directory("wire-") as root:
            artifact = root / "artifact"
            artifact.write_bytes(b"custody")
            source_fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC)
            left, right = socket_pair()
            received_fd: int | None = None
            try:
                deadline = time.monotonic() + 2
                send_record(
                    left,
                    {"type": "custody", "token": "a" * 64},
                    deadline=deadline,
                    fds=(source_fd,),
                )
                record, descriptors = receive_record(
                    right,
                    deadline=deadline,
                    expected_fds=1,
                )
                self.assertEqual(record, {"type": "custody", "token": "a" * 64})
                received_fd = descriptors[0]
                self.assertFalse(os.get_inheritable(received_fd))
                self.assertEqual(os.read(received_fd, 7), b"custody")

                send_blob(left, "b" * 64, b"prompt bytes", deadline=deadline)
                self.assertEqual(
                    receive_blob(right, "b" * 64, deadline=deadline),
                    b"prompt bytes",
                )
                self.assertTrue(peer_is_open(right))
                left.close()
                self.assertFalse(peer_is_open(right))
            finally:
                if received_fd is not None:
                    os.close(received_fd)
                os.close(source_fd)
                left.close()
                right.close()


if __name__ == "__main__":
    unittest.main()
