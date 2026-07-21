from __future__ import annotations

import re


POINTER_MAX_BYTES = 1024
V1_ALIASES = frozenset(
    {
        b"http://git-media.io/v/2",
        b"https://hawser.github.com/spec/v1",
        b"https://git-lfs.github.com/spec/v1",
    }
)
OID_PATTERN = re.compile(rb"sha256:[0-9a-f]{64}\Z")
EXTENSION_PREFIX_PATTERN = re.compile(rb"\Aext-[0-9]{1}-\w+")
SIZE_PATTERN = re.compile(rb"[+-]?[0-9]+\Z")


def _go_is_space(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x09 <= codepoint <= 0x0D
        or codepoint
        in {
            0x20,
            0x85,
            0xA0,
            0x1680,
            0x2028,
            0x2029,
            0x202F,
            0x205F,
            0x3000,
        }
        or 0x2000 <= codepoint <= 0x200A
    )


def _go_bytes_trim_space(payload: bytes) -> bytes:
    text = payload.decode("utf-8", errors="surrogateescape")
    start = 0
    end = len(text)
    while start < end and _go_is_space(text[start]):
        start += 1
    while end > start and _go_is_space(text[end - 1]):
        end -= 1
    return text[start:end].encode("utf-8", errors="surrogateescape")


def _go_scan_lines(payload: bytes) -> list[bytes]:
    if not payload:
        return []
    records = payload.split(b"\n")
    if payload.endswith(b"\n"):
        records.pop()
    return [record[:-1] if record.endswith(b"\r") else record for record in records]


def is_git_lfs_pointer(payload: bytes) -> bool:
    """Mirror git-lfs 3.7.1 DecodePointer acceptance for small blobs."""
    if not payload or len(payload) >= POINTER_MAX_BYTES:
        return False

    pointer_keys = (b"version", b"oid", b"size")
    core: dict[bytes, bytes] = {}
    extensions: list[tuple[bytes, bytes]] = []
    line = 0
    for record in _go_scan_lines(_go_bytes_trim_space(payload)):
        if not record:
            continue
        parts = record.split(b" ", 1)
        if len(parts) != 2 or line >= len(pointer_keys):
            return False
        key, value = parts
        if key != pointer_keys[line]:
            if EXTENSION_PREFIX_PATTERN.match(key) is None:
                return False
            extensions.append((key, value))
            continue
        core[key] = value
        line += 1

    if core.get(b"version") not in V1_ALIASES:
        return False
    if OID_PATTERN.fullmatch(core.get(b"oid", b"")) is None:
        return False
    size_bytes = core.get(b"size", b"")
    if SIZE_PATTERN.fullmatch(size_bytes) is None:
        return False
    try:
        parsed_size = int(size_bytes, 10)
    except ValueError:
        return False
    if parsed_size < 0 or parsed_size > (1 << 63) - 1:
        return False

    priorities: set[int] = set()
    for key, value in extensions:
        key_parts = key.split(b"-", 2)
        if len(key_parts) != 3 or key_parts[0] != b"ext":
            return False
        try:
            priority = int(key_parts[1], 10)
        except ValueError:
            return False
        if priority in priorities:
            return False
        priorities.add(priority)
        if OID_PATTERN.fullmatch(value) is None:
            return False
    return True
