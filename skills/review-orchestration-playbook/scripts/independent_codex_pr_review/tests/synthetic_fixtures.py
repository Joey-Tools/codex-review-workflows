"""Load credential-shaped test values without exposing an authoring CLI."""

from __future__ import annotations

from functools import lru_cache
import json
import pathlib


_CATALOG_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "review_runtime"
    / "synthetic-token-catalog.json"
)


@lru_cache(maxsize=8)
def _catalog_fixture(token_id: str, *, role: str, state: str) -> str:
    payload = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("authoring_pool"), dict)
    ):
        raise RuntimeError("synthetic test catalog has invalid top-level fields")
    authoring_pool = payload["authoring_pool"]
    tokens = authoring_pool.get("tokens")
    if not isinstance(tokens, list):
        raise RuntimeError("synthetic test catalog has no authoring token list")
    matches = [
        token
        for token in tokens
        if isinstance(token, dict) and token.get("id") == token_id
    ]
    if len(matches) != 1:
        raise RuntimeError(f"synthetic test catalog has no unique token {token_id}")
    token = matches[0]
    if set(token) != {
        "id",
        "role",
        "rule",
        "state",
        "value",
    }:
        raise RuntimeError("synthetic test catalog returned invalid token fields")
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
    if not encoded:
        raise RuntimeError(f"synthetic catalog value is empty for {token_id}")
    return value


SYNTHETIC_REFRESH_TOKEN = _catalog_fixture(
    "refresh-a",
    role="refresh",
    state="active",
)
