from __future__ import annotations

import gzip
import unittest
from unittest import mock

from review_supervisor.logs import LogBudget, SegmentedCompressedSink

from tests.support import owned_temporary_directory


class SegmentedCompressedSinkTests(unittest.TestCase):
    def test_archives_exact_bytes_without_interpreting_json_metadata(self) -> None:
        payload = b'{"type":"thread.started","model":"spoofed"}\nnot-json\n'
        with owned_temporary_directory("log-sink-") as root:
            sink = SegmentedCompressedSink(root, "appserver.stderr", LogBudget())
            sink.write(payload[:17])
            sink.write(payload[17:])
            sink.close()

            self.assertEqual(len(sink.paths), 1)
            self.assertEqual(gzip.decompress(sink.paths[0].read_bytes()), payload)
            self.assertEqual(sink.admitted_bytes, len(payload))
            self.assertFalse(hasattr(sink, "metadata"))

    def test_stream_and_aggregate_limits_fail_closed(self) -> None:
        with owned_temporary_directory("log-limits-") as root:
            with mock.patch("review_supervisor.logs.LOG_STREAM_BYTES", 3):
                sink = SegmentedCompressedSink(root, "stream", LogBudget())
                with self.assertRaises(OverflowError):
                    sink.write(b"four")

            with (
                mock.patch("review_supervisor.logs.LOG_SEGMENT_BYTES", 2),
                mock.patch("review_supervisor.logs.LOG_AGGREGATE_BYTES", 1),
            ):
                sink = SegmentedCompressedSink(root, "aggregate", LogBudget())
                with self.assertRaises(OverflowError):
                    sink.write(b"ab")

    def test_closed_sink_rejects_further_writes_and_observer_shape_is_gone(
        self,
    ) -> None:
        with owned_temporary_directory("log-closed-") as root:
            sink = SegmentedCompressedSink(root, "stream", LogBudget())
            sink.close()
            with self.assertRaises(ValueError):
                sink.write(b"late")
            with self.assertRaises(TypeError):
                SegmentedCompressedSink(  # type: ignore[call-arg]
                    root,
                    "stream",
                    LogBudget(),
                    observer=object(),
                )


if __name__ == "__main__":
    unittest.main()
