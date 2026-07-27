from __future__ import annotations

import gzip
import pathlib
from dataclasses import dataclass

from .constants import LOG_AGGREGATE_BYTES, LOG_SEGMENT_BYTES, LOG_STREAM_BYTES
from .secureio import publish_bytes


@dataclass
class LogBudget:
    aggregate_archived_bytes: int = 0


class SegmentedCompressedSink:
    def __init__(
        self,
        directory: pathlib.Path,
        stream_name: str,
        shared_budget: LogBudget,
    ) -> None:
        self.directory = directory
        self.stream_name = stream_name
        self.shared_budget = shared_budget
        self.buffer = bytearray()
        self.admitted_bytes = 0
        self.segment_index = 0
        self.paths: list[pathlib.Path] = []
        self.closed = False

    def write(self, value: bytes) -> None:
        if self.closed:
            raise ValueError("log sink is closed")
        if self.admitted_bytes + len(value) > LOG_STREAM_BYTES:
            raise OverflowError(f"{self.stream_name} exceeded its admitted-byte limit")
        self.admitted_bytes += len(value)
        view = memoryview(value)
        while view:
            room = LOG_SEGMENT_BYTES - len(self.buffer)
            part = view[:room]
            self.buffer.extend(part)
            view = view[len(part) :]
            if len(self.buffer) == LOG_SEGMENT_BYTES:
                self._flush_segment()

    def _flush_segment(self) -> None:
        if not self.buffer:
            return
        compressed = gzip.compress(bytes(self.buffer), compresslevel=6, mtime=0)
        if (
            self.shared_budget.aggregate_archived_bytes + len(compressed)
            > LOG_AGGREGATE_BYTES
        ):
            raise OverflowError("aggregate process-log archive limit would be exceeded")
        path = self.directory / f"{self.stream_name}.{self.segment_index:04d}.gz"
        publish_bytes(path, compressed)
        self.shared_budget.aggregate_archived_bytes += len(compressed)
        self.paths.append(path)
        self.segment_index += 1
        self.buffer.clear()

    def close(self) -> None:
        if not self.closed:
            self._flush_segment()
            self.closed = True
