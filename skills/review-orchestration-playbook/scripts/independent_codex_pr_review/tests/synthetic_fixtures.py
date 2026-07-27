from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import pathlib
import subprocess
import sys


_CATALOG_ENTRY = pathlib.Path(__file__).resolve().parents[2] / "synthetic_catalog_entry"


@lru_cache(maxsize=8)
def _catalog_fixture(token_id: str, *, role: str, state: str) -> str:
    completed = subprocess.run(
        (
            str(pathlib.Path(sys.executable).resolve()),
            "-E",
            "-B",
            "-s",
            "-S",
            str(_CATALOG_ENTRY),
            "get",
            token_id,
            "--json",
        ),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict) or set(payload) != {"pool_version", "token"}:
        raise RuntimeError("synthetic catalog entry returned invalid top-level fields")
    token = payload["token"]
    if not isinstance(token, dict) or set(token) != {
        "id",
        "role",
        "rule",
        "state",
        "value",
        "value_sha256",
    }:
        raise RuntimeError("synthetic catalog entry returned invalid token fields")
    if (token["id"], token["role"], token["state"]) != (token_id, role, state):
        raise RuntimeError(f"synthetic catalog metadata changed for {token_id}")
    value = token["value"]
    if not isinstance(value, str):
        raise RuntimeError(f"synthetic catalog value is not text for {token_id}")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError(
            f"synthetic catalog value is not ASCII for {token_id}"
        ) from error
    if hashlib.sha256(encoded).hexdigest() != token["value_sha256"]:
        raise RuntimeError(f"synthetic catalog digest changed for {token_id}")
    return value


SYNTHETIC_REFRESH_TOKEN = _catalog_fixture(
    "refresh-a",
    role="refresh",
    state="active",
)
