from __future__ import annotations

import base64
import json
import os
import pathlib
import tempfile
import unittest
from typing import Any
from unittest import mock

import review_supervisor.auth_carrier as auth_carrier

from review_supervisor.auth_carrier import (
    AuthCarrierError,
    AuthCarrierRefreshRequired,
    ExternalAuthEvidence,
)
from review_supervisor.codex_executable import ExtendedMetadataEvidence
from tests.synthetic_fixtures import SYNTHETIC_REFRESH_TOKEN


CLEAN_METADATA = ExtendedMetadataEvidence(
    acl_entry_count=0,
    xattrs=(),
    quarantine_present=False,
)


def clean_filesystem_metadata(
    fd: int,
    path: pathlib.Path,
    kind: str,
) -> ExtendedMetadataEvidence:
    del fd, path, kind
    return CLEAN_METADATA


def load_external_auth(
    auth_path: pathlib.Path,
    **kwargs: Any,
) -> ExternalAuthEvidence:
    return auth_carrier.load_external_auth(
        auth_path,
        filesystem_metadata_verifier=clean_filesystem_metadata,
        **kwargs,
    )


def revalidate_external_auth_source(
    auth_path: pathlib.Path,
    evidence: ExternalAuthEvidence,
    **kwargs: Any,
) -> None:
    auth_carrier.revalidate_external_auth_source(
        auth_path,
        evidence,
        filesystem_metadata_verifier=clean_filesystem_metadata,
        **kwargs,
    )


def jwt(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).rstrip(b"=")
    return "header." + encoded.decode("ascii") + ".signature"


class AuthCarrierTests(unittest.TestCase):
    def write_auth(
        self,
        root: pathlib.Path,
        *,
        expiration: int,
        mode: int = 0o600,
    ) -> pathlib.Path:
        path = root / "auth.json"
        value = {
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": jwt({"exp": expiration}),
                "account_id": "account-1",
                "id_token": jwt(
                    {
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "account-1",
                            "chatgpt_plan_type": "pro",
                        }
                    }
                ),
                "refresh_token": SYNTHETIC_REFRESH_TOKEN,
            },
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_loads_only_fresh_external_access_token_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
        self.assertEqual(evidence.auth.chatgpt_account_id, "account-1")
        self.assertEqual(evidence.auth.chatgpt_plan_type, "pro")
        self.assertEqual(evidence.access_token_expires_at, 10_000)
        self.assertNotIn(evidence.auth.access_token, repr(evidence))
        self.assertNotIn(SYNTHETIC_REFRESH_TOKEN, repr(evidence))
        self.assertNotIn("account-1", json.dumps(evidence.to_json()))

    def test_rejects_directory_and_file_extended_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)

            for blocked_path in (root, path):
                with self.subTest(blocked_path=blocked_path.name):

                    def reject_metadata(
                        fd: int,
                        candidate: pathlib.Path,
                        kind: str,
                    ) -> ExtendedMetadataEvidence:
                        del fd, kind
                        if candidate == blocked_path:
                            raise ValueError("synthetic ACL")
                        return CLEAN_METADATA

                    with self.assertRaisesRegex(
                        AuthCarrierError,
                        "could not be inspected safely",
                    ):
                        auth_carrier.load_external_auth(
                            path,
                            filesystem_metadata_verifier=reject_metadata,
                            now=1_000,
                            minimum_remaining_seconds=2_700,
                        )

    def test_verifies_directory_and_file_metadata_at_every_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            calls: list[tuple[pathlib.Path, str]] = []

            def record_metadata(
                fd: int,
                candidate: pathlib.Path,
                kind: str,
            ) -> ExtendedMetadataEvidence:
                del fd
                calls.append((candidate, kind))
                return CLEAN_METADATA

            evidence = auth_carrier.load_external_auth(
                path,
                filesystem_metadata_verifier=record_metadata,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            expected = [
                (root, "directory"),
                (path, "file"),
                (root, "directory"),
                (path, "file"),
            ]
            self.assertEqual(calls, expected)

            calls.clear()
            auth_carrier.revalidate_external_auth_source(
                path,
                evidence,
                filesystem_metadata_verifier=record_metadata,
                now=1_000,
            )
            self.assertEqual(calls, expected)

            def reject_file_metadata(
                fd: int,
                candidate: pathlib.Path,
                kind: str,
            ) -> ExtendedMetadataEvidence:
                del fd, kind
                if candidate == path:
                    raise OSError("synthetic ACL race")
                return CLEAN_METADATA

            with self.assertRaisesRegex(
                AuthCarrierError,
                "could not be inspected safely",
            ):
                auth_carrier.revalidate_external_auth_source(
                    path,
                    evidence,
                    filesystem_metadata_verifier=reject_file_metadata,
                    now=1_000,
                )

    def test_rejects_malformed_filesystem_metadata_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)

            def malformed_metadata(
                fd: int,
                candidate: pathlib.Path,
                kind: str,
            ) -> object:
                del fd, candidate, kind
                return object()

            with self.assertRaisesRegex(
                AuthCarrierError,
                "could not be inspected safely",
            ):
                auth_carrier.load_external_auth(
                    path,
                    filesystem_metadata_verifier=malformed_metadata,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

    def test_close_failure_is_sanitized_and_closes_both_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            original_close = auth_carrier.os.close
            closed: list[int] = []

            def close_then_fail_once(fd: int) -> None:
                original_close(fd)
                closed.append(fd)
                if len(closed) == 1:
                    raise OSError("sensitive close detail")

            with (
                mock.patch.object(
                    auth_carrier.os,
                    "close",
                    side_effect=close_then_fail_once,
                ),
                self.assertRaisesRegex(
                    AuthCarrierError,
                    "could not be inspected safely",
                ) as raised,
            ):
                auth_carrier.load_external_auth(
                    path,
                    filesystem_metadata_verifier=clean_filesystem_metadata,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

            self.assertEqual(len(closed), 2)
            self.assertNotIn("sensitive close detail", str(raised.exception))

    def test_load_preserves_inspection_control_flow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)

            for error in (KeyboardInterrupt(), SystemExit(23)):
                with (
                    self.subTest(error=type(error).__name__),
                    self.assertRaises(type(error)),
                ):
                    auth_carrier.load_external_auth(
                        path,
                        filesystem_metadata_verifier=mock.Mock(side_effect=error),
                        now=1_000,
                        minimum_remaining_seconds=2_700,
                    )

    def test_revalidation_preserves_inspection_control_flow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            for error in (KeyboardInterrupt(), SystemExit(23)):
                with (
                    self.subTest(error=type(error).__name__),
                    self.assertRaises(type(error)) as raised,
                ):
                    auth_carrier.revalidate_external_auth_source(
                        path,
                        evidence,
                        filesystem_metadata_verifier=mock.Mock(side_effect=error),
                        now=1_000,
                    )
                self.assertIs(raised.exception, error)

    def test_cleanup_control_flow_overrides_ordinary_inspection_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            original_close = auth_carrier.os.close
            close_attempts: list[int] = []
            cleanup_failures = (KeyboardInterrupt(), SystemExit(23))

            def close_with_control_flow(fd: int) -> None:
                original_close(fd)
                failure = cleanup_failures[len(close_attempts)]
                close_attempts.append(fd)
                raise failure

            with (
                mock.patch.object(
                    auth_carrier,
                    "read_fd_exact",
                    side_effect=OSError("ordinary inspection failure"),
                ) as read_exact,
                mock.patch.object(
                    auth_carrier.os,
                    "close",
                    side_effect=close_with_control_flow,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

            read_exact.assert_called_once()
            self.assertEqual(len(close_attempts), 2)
            self.assertEqual(len(set(close_attempts)), 2)

    def test_rejects_expiry_mode_links_duplicates_and_malformed_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            expired = self.write_auth(root, expiration=2_000)
            with self.assertRaises(AuthCarrierRefreshRequired):
                load_external_auth(expired, now=1_000, minimum_remaining_seconds=2_700)

            expired.chmod(0o644)
            with self.assertRaises(AuthCarrierError):
                load_external_auth(expired, now=1_000, minimum_remaining_seconds=60)
            expired.chmod(0o600)

            linked = root / "linked.json"
            os.link(expired, linked)
            with self.assertRaises(AuthCarrierError):
                load_external_auth(expired, now=1_000, minimum_remaining_seconds=60)
            linked.unlink()

            expired.write_text('{"tokens":{},"tokens":{}}', encoding="utf-8")
            with self.assertRaises(AuthCarrierError):
                load_external_auth(expired, now=1_000, minimum_remaining_seconds=60)

            expired.write_text(
                json.dumps(
                    {
                        "tokens": {
                            "access_token": "-".join(("not", "a", "jwt")),
                            "account_id": "account-1",
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(AuthCarrierError):
                load_external_auth(expired, now=1_000, minimum_remaining_seconds=60)

    def test_rejects_non_finite_float_in_nested_unknown_json_field(self) -> None:
        with mock.patch.object(
            auth_carrier.json,
            "loads",
            side_effect=RecursionError,
        ):
            with self.assertRaisesRegex(AuthCarrierError, "strict UTF-8 JSON"):
                auth_carrier._decode_json(b"{}")

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            raw = path.read_bytes()
            path.write_bytes(raw[:-1] + b',"unknown":{"nested":[1e400]}}')

            with self.assertRaisesRegex(
                AuthCarrierError,
                "non-finite JSON number",
            ):
                load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

    def test_rejects_wrong_mode_and_malformed_stale_carriers_before_refresh(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=2_000)
            original = json.loads(path.read_text(encoding="utf-8"))
            cases = (
                {**original, "auth_mode": "apikey"},
                {
                    **original,
                    "tokens": {**original["tokens"], "id_token": {}},
                },
                {
                    **original,
                    "tokens": {
                        **original["tokens"],
                        "account_id": None,
                        "id_token": None,
                    },
                },
                {
                    **original,
                    "tokens": {**original["tokens"], "refresh_token": ""},
                },
            )
            for value in cases:
                with self.subTest(auth_mode=value.get("auth_mode")):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    path.chmod(0o600)
                    with self.assertRaises(AuthCarrierError) as raised:
                        load_external_auth(
                            path,
                            now=1_000,
                            minimum_remaining_seconds=2_700,
                        )
                    self.assertNotIsInstance(
                        raised.exception,
                        AuthCarrierRefreshRequired,
                    )

    def test_revalidates_the_exact_auth_generation_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            revalidate_external_auth_source(path, evidence, now=1_000)

            replacement = root / "replacement.json"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, path)
            with self.assertRaisesRegex(AuthCarrierError, "generation changed"):
                revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_rejects_replaced_auth_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw_container:
            container = pathlib.Path(raw_container)
            root = container / ".codex"
            root.mkdir(mode=0o700)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            original = container / "original-codex"
            root.rename(original)
            root.mkdir(mode=0o700)
            replacement = self.write_auth(root, expiration=10_000)
            replacement.write_bytes((original / "auth.json").read_bytes())
            replacement.chmod(0o600)

            with self.assertRaisesRegex(AuthCarrierError, "generation changed"):
                revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_requires_the_full_bounded_runtime_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            revalidate_external_auth_source(path, evidence, now=7_300)
            with self.assertRaisesRegex(
                AuthCarrierError,
                "no longer covers the bounded review runtime",
            ):
                revalidate_external_auth_source(path, evidence, now=7_300.001)
            with (
                mock.patch.object(
                    auth_carrier.time,
                    "time",
                    return_value=7_300.001,
                ),
                self.assertRaisesRegex(
                    AuthCarrierError,
                    "no longer covers the bounded review runtime",
                ),
            ):
                revalidate_external_auth_source(path, evidence)

    def test_revalidation_fails_closed_for_invalid_clock_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            for invalid_now in (True, float("nan"), float("inf")):
                with (
                    self.subTest(now=invalid_now),
                    self.assertRaisesRegex(AuthCarrierError, "clock value is invalid"),
                ):
                    revalidate_external_auth_source(
                        path,
                        evidence,
                        now=invalid_now,
                    )
            with (
                mock.patch.object(
                    auth_carrier.time,
                    "time",
                    side_effect=OSError("clock unavailable"),
                ),
                self.assertRaisesRegex(AuthCarrierError, "clock is unavailable"),
            ):
                revalidate_external_auth_source(path, evidence)

    def test_rejects_same_inode_write_during_descriptor_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            original_read = auth_carrier.read_fd_exact
            before = path.stat()

            def mutate_after_read(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                raw = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                with path.open("r+b") as carrier:
                    offset = raw.index(b"account-1")
                    carrier.seek(offset)
                    carrier.write(b"account-2")
                    carrier.flush()
                    os.fsync(carrier.fileno())
                os.utime(
                    path,
                    ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
                )
                return raw

            with (
                mock.patch.object(
                    auth_carrier,
                    "read_fd_exact",
                    side_effect=mutate_after_read,
                ),
                self.assertRaisesRegex(
                    AuthCarrierError, "changed while it was inspected"
                ),
            ):
                load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

            after = path.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino), (before.st_dev, before.st_ino)
            )
            self.assertEqual(after.st_size, before.st_size)

    def test_rejects_same_inode_write_between_post_read_fd_and_path_checks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            original_lstat = os.lstat
            before = path.stat()
            directory_lstat_calls = 0

            def race_lstat(candidate: os.PathLike[str] | str) -> os.stat_result:
                nonlocal directory_lstat_calls
                if pathlib.Path(candidate) == path.parent:
                    directory_lstat_calls += 1
                    if directory_lstat_calls == 2:
                        with path.open("r+b") as carrier:
                            carrier.seek(0)
                            first = carrier.read(1)
                            carrier.seek(0)
                            carrier.write(first)
                            carrier.flush()
                            os.fsync(carrier.fileno())
                        os.utime(
                            path,
                            ns=(
                                before.st_atime_ns,
                                before.st_mtime_ns + 1_000_000_000,
                            ),
                        )
                return original_lstat(candidate)

            with (
                mock.patch.object(auth_carrier.os, "lstat", side_effect=race_lstat),
                self.assertRaisesRegex(
                    AuthCarrierError, "changed while it was inspected"
                ),
            ):
                load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

            after = path.stat()
            self.assertEqual(directory_lstat_calls, 2)
            self.assertEqual(
                (after.st_dev, after.st_ino), (before.st_dev, before.st_ino)
            )
            self.assertEqual(after.st_size, before.st_size)

    def test_failure_traceback_does_not_retain_raw_auth_payload(self) -> None:
        marker = "-".join(("sensitive", "refresh", "marker"))
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["tokens"]["refresh_token"] = marker
            value["tokens"]["access_token"] = "malformed"
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)

            with self.assertRaises(AuthCarrierError) as raised:
                load_external_auth(path, now=1_000, minimum_remaining_seconds=60)

        traceback = raised.exception.__traceback__
        while traceback is not None:
            rendered = repr(traceback.tb_frame.f_locals)
            self.assertNotIn(marker, rendered)
            self.assertNotIn('"tokens"', rendered)
            traceback = traceback.tb_next
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)


if __name__ == "__main__":
    unittest.main()
