from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import threading
import time
import unittest
from typing import Any
from unittest import mock

import review_supervisor.auth_carrier as auth_carrier

from review_supervisor.auth_carrier import (
    AuthCarrierAccessPolicyMismatch,
    AuthCarrierContentMismatch,
    AuthCarrierError,
    AuthCarrierInspectionFailure,
    AuthCarrierMalformedEvidence,
    AuthCarrierObjectIdentityMismatch,
    AuthCarrierRefreshRequired,
    AuthCarrierSourceMissing,
    ExternalAuthEvidence,
)
from review_supervisor.appserver_protocol import ExternalChatGPTAuth
from review_supervisor.codex_executable import (
    RESTRICTIVE_HOME_ACL_ENTRY,
    ExtendedMetadataEvidence,
)
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
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )
        self.assertEqual(evidence.auth.chatgpt_account_id, "account-1")
        self.assertEqual(evidence.auth.chatgpt_plan_type, "pro")
        self.assertEqual(evidence.access_token_expires_at, 10_000)
        self.assertEqual(evidence.wall_time_baseline, 1_000)
        self.assertEqual(evidence.monotonic_time_baseline, 500)
        self.assertRegex(evidence.source_content_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertFalse(hasattr(evidence, "source_mtime_ns"))
        self.assertFalse(hasattr(evidence, "source_ctime_ns"))
        self.assertNotIn(evidence.auth.access_token, repr(evidence))
        self.assertNotIn(SYNTHETIC_REFRESH_TOKEN, repr(evidence))
        self.assertNotIn("account-1", json.dumps(evidence.to_json()))

    def test_revalidation_rejects_missing_or_malformed_content_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            legacy = object.__new__(ExternalAuthEvidence)
            legacy.__dict__.update(evidence.__dict__)
            del legacy.__dict__["source_content_sha256"]

            for label, malformed in (
                ("missing-digest", legacy),
                (
                    "empty-digest",
                    dataclasses.replace(evidence, source_content_sha256=""),
                ),
                (
                    "short-digest",
                    dataclasses.replace(
                        evidence,
                        source_content_sha256="0" * 63,
                    ),
                ),
                (
                    "non-hex-digest",
                    dataclasses.replace(
                        evidence,
                        source_content_sha256="G" * 64,
                    ),
                ),
                ("zero-size", dataclasses.replace(evidence, source_size=0)),
            ):
                with (
                    self.subTest(case=label),
                    self.assertRaisesRegex(
                        AuthCarrierMalformedEvidence,
                        "external-auth evidence is malformed",
                    ),
                ):
                    revalidate_external_auth_source(
                        path,
                        malformed,
                        now=1_000,
                    )

    def test_revalidation_binds_exact_external_auth_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            class DerivedExternalAuth(ExternalChatGPTAuth):
                pass

            derived_auth = DerivedExternalAuth(
                access_token=evidence.auth.access_token,
                chatgpt_account_id=evidence.auth.chatgpt_account_id,
                chatgpt_plan_type=evidence.auth.chatgpt_plan_type,
            )
            malformed_auth = object.__new__(ExternalChatGPTAuth)
            object.__setattr__(
                malformed_auth,
                "access_token",
                evidence.auth.access_token,
            )
            object.__setattr__(malformed_auth, "chatgpt_account_id", "")
            object.__setattr__(
                malformed_auth,
                "chatgpt_plan_type",
                evidence.auth.chatgpt_plan_type,
            )
            malformed_cases = (
                (
                    "derived-auth-type",
                    dataclasses.replace(evidence, auth=derived_auth),
                ),
                (
                    "invalid-auth-field",
                    dataclasses.replace(evidence, auth=malformed_auth),
                ),
                (
                    "expiry-only",
                    dataclasses.replace(
                        evidence,
                        access_token_expires_at=10_001,
                    ),
                ),
                (
                    "token-hash-only",
                    dataclasses.replace(
                        evidence,
                        access_token_sha256="0" * 64,
                    ),
                ),
                (
                    "account-hash-only",
                    dataclasses.replace(
                        evidence,
                        account_id_sha256="0" * 64,
                    ),
                ),
            )
            for label, malformed in malformed_cases:
                with (
                    self.subTest(case=label),
                    self.assertRaises(
                        AuthCarrierMalformedEvidence,
                    ) as raised,
                ):
                    revalidate_external_auth_source(
                        path,
                        malformed,
                        now=1_000,
                    )
                self.assertIs(type(raised.exception), AuthCarrierMalformedEvidence)
                self.assertEqual(
                    raised.exception.classification,
                    "malformed-evidence",
                )
                self.assertEqual(
                    str(raised.exception),
                    "external-auth evidence is malformed",
                )

            tampered_token = jwt({"exp": 11_000, "marker": "tampered"})
            tampered_token_auth = ExternalChatGPTAuth(
                access_token=tampered_token,
                chatgpt_account_id=evidence.auth.chatgpt_account_id,
                chatgpt_plan_type=evidence.auth.chatgpt_plan_type,
            )
            tampered_account_auth = ExternalChatGPTAuth(
                access_token=evidence.auth.access_token,
                chatgpt_account_id="account-2",
                chatgpt_plan_type=evidence.auth.chatgpt_plan_type,
            )
            tampered_plan_auth = ExternalChatGPTAuth(
                access_token=evidence.auth.access_token,
                chatgpt_account_id=evidence.auth.chatgpt_account_id,
                chatgpt_plan_type="team",
            )
            semantic_cases = (
                (
                    "token-and-expiry",
                    dataclasses.replace(
                        evidence,
                        auth=tampered_token_auth,
                        access_token_expires_at=11_000,
                        access_token_sha256=hashlib.sha256(
                            tampered_token.encode("ascii")
                        ).hexdigest(),
                    ),
                ),
                (
                    "account",
                    dataclasses.replace(
                        evidence,
                        auth=tampered_account_auth,
                        account_id_sha256=hashlib.sha256(b"account-2").hexdigest(),
                    ),
                ),
                (
                    "plan",
                    dataclasses.replace(
                        evidence,
                        auth=tampered_plan_auth,
                    ),
                ),
            )
            for label, malformed in semantic_cases:
                with (
                    self.subTest(case=label),
                    self.assertRaises(
                        AuthCarrierMalformedEvidence,
                    ) as raised,
                ):
                    revalidate_external_auth_source(
                        path,
                        malformed,
                        now=1_000,
                    )
                self.assertIs(type(raised.exception), AuthCarrierMalformedEvidence)
                self.assertEqual(
                    raised.exception.classification,
                    "malformed-evidence",
                )
                self.assertEqual(
                    str(raised.exception),
                    "external-auth evidence semantics do not match committed content",
                )

    def test_revalidation_zeroes_digest_read_buffers(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            original_readv = auth_carrier.os.readv
            observed_buffers: list[bytearray] = []

            def record_readv(fd: int, buffers: tuple[object, ...]) -> int:
                for candidate in buffers:
                    if isinstance(candidate, memoryview):
                        candidate = candidate.obj
                    if isinstance(candidate, bytearray):
                        observed_buffers.append(candidate)
                return original_readv(fd, buffers)

            with mock.patch.object(
                auth_carrier.os,
                "readv",
                side_effect=record_readv,
            ):
                revalidate_external_auth_source(path, evidence, now=1_000)

            self.assertGreaterEqual(len(observed_buffers), 4)
            self.assertTrue(all(not buffer for buffer in observed_buffers))

            observed_buffers.clear()
            read_calls = 0

            def fail_after_content_read(
                fd: int,
                buffers: tuple[object, ...],
            ) -> int:
                nonlocal read_calls
                read_calls += 1
                if read_calls == 2:
                    raise OSError("synthetic digest read failure")
                return record_readv(fd, buffers)

            with (
                mock.patch.object(
                    auth_carrier.os,
                    "readv",
                    side_effect=fail_after_content_read,
                ),
                self.assertRaisesRegex(
                    AuthCarrierInspectionFailure,
                    "auth carrier source inspection failed",
                ),
            ):
                revalidate_external_auth_source(path, evidence, now=1_000)

            self.assertGreaterEqual(len(observed_buffers), 1)
            self.assertTrue(all(not buffer for buffer in observed_buffers))

    def test_load_zeroes_mutable_secret_buffers_on_success_and_failure(
        self,
    ) -> None:
        expected_labels = {
            "access-token-encoding",
            "account-id-encoding",
            "auth-digest-extra",
            "auth-digest-scratch",
            "auth-file-content",
            "auth-file-extra",
            "jwt-decoded-payload",
            "jwt-encoded-payload",
            "jwt-token-encoding",
            "plan-type-encoding",
        }
        original_zero = auth_carrier._zero_bytearray

        def capture_zeroed_buffers(
            action: Any,
        ) -> tuple[object, list[tuple[str, bytearray]]]:
            observed: list[tuple[str, bytearray]] = []

            def record_zero(value: bytearray, *, label: str) -> None:
                original_zero(value, label=label)
                observed.append((label, value))

            with mock.patch.object(
                auth_carrier,
                "_zero_bytearray",
                side_effect=record_zero,
            ):
                result = action()
            return result, observed

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            expected_access_token = json.loads(path.read_text(encoding="utf-8"))[
                "tokens"
            ]["access_token"]
            evidence, success_buffers = capture_zeroed_buffers(
                lambda: load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )
            )

            self.assertIsInstance(evidence, ExternalAuthEvidence)
            self.assertEqual(evidence.auth.access_token, expected_access_token)
            self.assertEqual(
                {label for label, _ in success_buffers},
                expected_labels,
            )
            self.assertTrue(
                all(not buffer for _, buffer in success_buffers),
            )

            value = json.loads(path.read_text(encoding="utf-8"))
            malformed_payload = base64.urlsafe_b64encode(b"{").rstrip(b"=")
            value["tokens"]["access_token"] = (
                f"header.{malformed_payload.decode('ascii')}.signature"
            )
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            failure_buffers: list[tuple[str, bytearray]] = []

            def record_failure_zero(value: bytearray, *, label: str) -> None:
                original_zero(value, label=label)
                failure_buffers.append((label, value))

            with (
                mock.patch.object(
                    auth_carrier,
                    "_zero_bytearray",
                    side_effect=record_failure_zero,
                ),
                self.assertRaisesRegex(
                    AuthCarrierError,
                    "strict UTF-8 JSON",
                ),
            ):
                load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

            self.assertEqual(
                {label for label, _ in failure_buffers},
                expected_labels,
            )
            self.assertTrue(
                all(not buffer for _, buffer in failure_buffers),
            )

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
                        AuthCarrierAccessPolicyMismatch,
                        "auth carrier ACL/xattr policy mismatch",
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
                AuthCarrierInspectionFailure,
                "auth carrier source inspection failed",
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
                AuthCarrierInspectionFailure,
                "auth carrier metadata inspection failed",
            ):
                auth_carrier.load_external_auth(
                    path,
                    filesystem_metadata_verifier=malformed_metadata,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )

    def test_revalidation_classifies_one_stat_projection_by_property(
        self,
    ) -> None:
        class ProjectedStat:
            def __init__(
                self,
                value: os.stat_result,
                overrides: dict[str, int],
            ) -> None:
                self._value = value
                self._overrides = overrides

            def __getattr__(self, name: str) -> Any:
                if name in self._overrides:
                    return self._overrides[name]
                return getattr(self._value, name)

        def project_stat(
            value: os.stat_result,
            field: str,
        ) -> ProjectedStat:
            if field == "type":
                overrides = {
                    "st_mode": stat.S_IFDIR | stat.S_IMODE(value.st_mode),
                }
            else:
                stat_field = {
                    "device": "st_dev",
                    "flags": "st_flags",
                    "generation": "st_gen",
                    "gid": "st_gid",
                    "inode": "st_ino",
                    "uid": "st_uid",
                }[field]
                overrides = {
                    stat_field: getattr(value, stat_field, 0) + 1,
                }
            return ProjectedStat(value, overrides)

        def assert_projection(
            field: str,
            expected_type: type[AuthCarrierError],
            expected_classification: str,
        ) -> None:
            with tempfile.TemporaryDirectory() as raw_root:
                path = self.write_auth(
                    pathlib.Path(raw_root),
                    expiration=10_000,
                )
                evidence = load_external_auth(
                    path,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )
                self.assertFalse(hasattr(evidence.source_identity, "uid"))
                self.assertFalse(hasattr(evidence.source_identity, "gid"))
                self.assertEqual(
                    evidence.source_access_policy.uid,
                    os.getuid(),
                )

                source_fd = -1
                original_open_regular_at = auth_carrier.open_regular_at
                original_fstat = auth_carrier.os.fstat
                original_stat = auth_carrier.os.stat

                def track_source_fd(*args: Any, **kwargs: Any) -> Any:
                    nonlocal source_fd
                    result = original_open_regular_at(*args, **kwargs)
                    source_fd = result[0]
                    return result

                def projected_fstat(fd: int) -> Any:
                    value = original_fstat(fd)
                    if fd == source_fd:
                        return project_stat(value, field)
                    return value

                def projected_path_stat(
                    candidate: os.PathLike[str] | str | bytes,
                    *args: Any,
                    **kwargs: Any,
                ) -> Any:
                    value = original_stat(candidate, *args, **kwargs)
                    if source_fd >= 0 and candidate == b"auth.json":
                        return project_stat(value, field)
                    return value

                with (
                    mock.patch.object(
                        auth_carrier,
                        "open_regular_at",
                        side_effect=track_source_fd,
                    ),
                    mock.patch.object(
                        auth_carrier.os,
                        "fstat",
                        side_effect=projected_fstat,
                    ),
                    mock.patch.object(
                        auth_carrier.os,
                        "stat",
                        side_effect=projected_path_stat,
                    ),
                    self.assertRaises(expected_type) as raised,
                ):
                    revalidate_external_auth_source(
                        path,
                        evidence,
                        now=1_000,
                    )
                self.assertIs(type(raised.exception), expected_type)
                self.assertEqual(
                    raised.exception.classification,
                    expected_classification,
                )

        for field in ("uid", "gid", "flags"):
            with self.subTest(
                property="access-policy",
                field=field,
            ):
                assert_projection(
                    field,
                    AuthCarrierAccessPolicyMismatch,
                    "access-policy-mismatch",
                )

        for field in ("device", "inode", "type", "generation"):
            with self.subTest(
                property="object-identity",
                field=field,
            ):
                assert_projection(
                    field,
                    AuthCarrierObjectIdentityMismatch,
                    "object-identity-mismatch",
                )

    def test_revalidation_binds_exact_acl_and_xattr_policy_evidence(
        self,
    ) -> None:
        acl_metadata = ExtendedMetadataEvidence(
            acl_entry_count=1,
            acl_entries=(RESTRICTIVE_HOME_ACL_ENTRY,),
            xattrs=(),
            quarantine_present=False,
        )
        provenance_metadata = ExtendedMetadataEvidence(
            acl_entry_count=0,
            xattrs=("com.apple.provenance",),
            quarantine_present=False,
        )

        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)

            def directory_acl_metadata(
                fd: int,
                candidate: pathlib.Path,
                kind: str,
            ) -> ExtendedMetadataEvidence:
                del fd, kind
                if candidate == root:
                    return acl_metadata
                return CLEAN_METADATA

            fake_user = mock.Mock(pw_dir=str(root))
            with mock.patch(
                "review_supervisor.codex_executable.pwd.getpwuid",
                return_value=fake_user,
            ):
                evidence = auth_carrier.load_external_auth(
                    path,
                    filesystem_metadata_verifier=directory_acl_metadata,
                    now=1_000,
                    minimum_remaining_seconds=2_700,
                )
                with self.assertRaises(
                    AuthCarrierAccessPolicyMismatch,
                ) as raised:
                    auth_carrier.revalidate_external_auth_source(
                        path,
                        evidence,
                        filesystem_metadata_verifier=clean_filesystem_metadata,
                        now=1_000,
                    )
            self.assertIs(
                type(raised.exception),
                AuthCarrierAccessPolicyMismatch,
            )
            self.assertEqual(
                str(raised.exception),
                "auth carrier access policy mismatch",
            )

        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )

            def file_provenance_metadata(
                fd: int,
                candidate: pathlib.Path,
                kind: str,
            ) -> ExtendedMetadataEvidence:
                del fd, kind
                if candidate == path:
                    return provenance_metadata
                return CLEAN_METADATA

            with self.assertRaises(
                AuthCarrierAccessPolicyMismatch,
            ) as raised:
                auth_carrier.revalidate_external_auth_source(
                    path,
                    evidence,
                    filesystem_metadata_verifier=file_provenance_metadata,
                    now=1_000,
                )
            self.assertIs(
                type(raised.exception),
                AuthCarrierAccessPolicyMismatch,
            )
            self.assertEqual(
                str(raised.exception),
                "auth carrier access policy mismatch",
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
                    AuthCarrierInspectionFailure,
                    "auth carrier source inspection failed",
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

    def test_revalidation_reports_six_distinct_failure_classes(self) -> None:
        observed: dict[str, tuple[type[AuthCarrierError], str]] = {}

        def record_failure(
            label: str,
            expected_type: type[AuthCarrierError],
            expected_message: str,
            action: Any,
        ) -> None:
            with self.assertRaises(expected_type) as raised:
                action()
            self.assertIs(type(raised.exception), expected_type)
            self.assertEqual(
                raised.exception.classification,
                label,
            )
            self.assertEqual(str(raised.exception), expected_message)
            self.assertNotIn("account-1", str(raised.exception))
            self.assertNotIn(SYNTHETIC_REFRESH_TOKEN, str(raised.exception))
            observed[label] = (type(raised.exception), str(raised.exception))

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            path.unlink()
            record_failure(
                "missing",
                AuthCarrierSourceMissing,
                "auth carrier source is missing",
                lambda: revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                ),
            )

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            original_open = auth_carrier.os.open

            def deny_auth_open(
                candidate: os.PathLike[str] | str | bytes,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if candidate == b"auth.json":
                    raise PermissionError("synthetic unreadable auth carrier")
                return original_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(
                auth_carrier.os,
                "open",
                side_effect=deny_auth_open,
            ):
                record_failure(
                    "inspection-failure",
                    AuthCarrierInspectionFailure,
                    "auth carrier source inspection failed",
                    lambda: revalidate_external_auth_source(
                        path,
                        evidence,
                        now=1_000,
                    ),
                )

        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            replacement = root / "replacement.json"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, path)
            record_failure(
                "object-identity-mismatch",
                AuthCarrierObjectIdentityMismatch,
                "auth carrier object identity mismatch",
                lambda: revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                ),
            )

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            original = path.read_bytes()
            mutated = original.replace(b"account-1", b"account-2", 1)
            self.assertEqual(len(mutated), len(original))
            path.write_bytes(mutated)
            record_failure(
                "content-mismatch",
                AuthCarrierContentMismatch,
                "auth carrier content commitment mismatch",
                lambda: revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                ),
            )

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            path.chmod(0o640)
            record_failure(
                "access-policy-mismatch",
                AuthCarrierAccessPolicyMismatch,
                "auth carrier file access policy mismatch",
                lambda: revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                ),
            )

        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            malformed = dataclasses.replace(
                evidence,
                access_token_expires_at=10_001,
            )
            record_failure(
                "malformed-evidence",
                AuthCarrierMalformedEvidence,
                "external-auth evidence is malformed",
                lambda: revalidate_external_auth_source(
                    path,
                    malformed,
                    now=1_000,
                ),
            )

        self.assertEqual(
            set(observed),
            {
                "access-policy-mismatch",
                "content-mismatch",
                "inspection-failure",
                "malformed-evidence",
                "missing",
                "object-identity-mismatch",
            },
        )

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
                    "_read_auth_fd_exact",
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
            with self.assertRaisesRegex(
                AuthCarrierObjectIdentityMismatch,
                "object identity mismatch",
            ):
                revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_ignores_timestamp_only_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            before = path.stat()

            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )

            after = path.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino, after.st_size),
                (before.st_dev, before.st_ino, before.st_size),
            )
            self.assertNotEqual(after.st_mtime_ns, before.st_mtime_ns)
            revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_ignores_completed_file_link_count_churn(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            linked = root / "temporary-auth-link.json"

            os.link(path, linked)
            self.assertEqual(path.stat().st_nlink, 2)
            linked.unlink()

            self.assertEqual(path.stat().st_nlink, 1)
            revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_ignores_completed_directory_child_churn(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            path = self.write_auth(root, expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            before = root.stat()
            child = root / "temporary-child"

            child.mkdir()
            child.rmdir()

            after = root.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode)),
                (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)),
            )
            revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_rejects_same_size_content_with_restored_timestamps(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                minimum_remaining_seconds=2_700,
            )
            before = path.stat()
            original = path.read_bytes()
            mutated = original.replace(b"account-1", b"account-2", 1)
            self.assertEqual(len(mutated), len(original))

            path.write_bytes(mutated)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

            after = path.stat()
            self.assertEqual(after.st_size, before.st_size)
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            with self.assertRaisesRegex(
                AuthCarrierContentMismatch,
                "content commitment mismatch",
            ):
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

            with self.assertRaisesRegex(
                AuthCarrierObjectIdentityMismatch,
                "object identity mismatch",
            ):
                revalidate_external_auth_source(path, evidence, now=1_000)

    def test_revalidation_requires_the_full_bounded_runtime_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            revalidate_external_auth_source(
                path,
                evidence,
                now=7_300,
                monotonic_now=6_800,
            )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "no longer covers the bounded review runtime",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=7_300.001,
                    monotonic_now=6_800.001,
                )
            with (
                mock.patch.object(
                    auth_carrier.time,
                    "time",
                    return_value=7_300.001,
                ),
                mock.patch.object(
                    auth_carrier,
                    "_suspend_aware_monotonic",
                    return_value=6_800.001,
                ),
                self.assertRaisesRegex(
                    AuthCarrierError,
                    "no longer covers the bounded review runtime",
                ),
            ):
                revalidate_external_auth_source(path, evidence)

    def test_revalidation_rejects_wall_clock_rollback_beyond_tolerance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=3_800)
            with (
                mock.patch.object(
                    auth_carrier.time,
                    "time",
                    side_effect=(1_000, 900),
                ) as wall_clock,
                mock.patch.object(
                    auth_carrier,
                    "_suspend_aware_monotonic",
                    side_effect=(500, 600),
                ) as monotonic_clock,
                self.assertRaisesRegex(
                    AuthCarrierError,
                    "wall clock moved backwards",
                ),
            ):
                evidence = load_external_auth(
                    path,
                    minimum_remaining_seconds=2_700,
                )
                revalidate_external_auth_source(path, evidence)
            self.assertEqual(wall_clock.call_count, 2)
            self.assertEqual(monotonic_clock.call_count, 2)

    def test_revalidation_tolerates_sampling_skew_without_extending_lifetime(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=3_710)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            with self.assertRaisesRegex(
                AuthCarrierError,
                "no longer covers the bounded review runtime",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_009.5,
                    monotonic_now=510.5,
                )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "wall clock moved backwards",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_009.499,
                    monotonic_now=510.5,
                )

    def test_revalidation_uses_forward_wall_clock_drift_conservatively(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=3_800)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            revalidate_external_auth_source(
                path,
                evidence,
                now=1_100,
                monotonic_now=510,
            )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "no longer covers the bounded review runtime",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_100.001,
                    monotonic_now=510,
                )

    def test_revalidation_preserves_wall_and_monotonic_high_water(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            revalidate_external_auth_source(
                path,
                evidence,
                now=1_100,
                monotonic_now=510,
            )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "wall clock moved backwards",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_011,
                    monotonic_now=511,
                )

            fresh = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )
            revalidate_external_auth_source(
                path,
                fresh,
                now=1_100,
                monotonic_now=600,
            )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "monotonic clock moved backwards",
            ):
                revalidate_external_auth_source(
                    path,
                    fresh,
                    now=1_050,
                    monotonic_now=550,
                )

    def test_suspend_aware_elapsed_time_detects_sleep_during_wall_rollback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            with self.assertRaisesRegex(
                AuthCarrierError,
                "wall clock moved backwards",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                    monotonic_now=620,
                )

    def test_expiry_failure_latches_the_latest_clock_high_water(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=3_710)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )

            for now in (1_010.001, 1_009.5):
                with (
                    self.subTest(now=now),
                    self.assertRaisesRegex(
                        AuthCarrierError,
                        "no longer covers the bounded review runtime",
                    ),
                ):
                    revalidate_external_auth_source(
                        path,
                        evidence,
                        now=now,
                        monotonic_now=510.001,
                    )

    def test_revalidation_serializes_clock_sampling_with_state_updates(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
                minimum_remaining_seconds=2_700,
            )
            start = threading.Barrier(3)
            sample_lock = threading.Lock()
            samples = iter(
                (
                    auth_carrier._ClockSample(1_010, 510),
                    auth_carrier._ClockSample(1_011, 511),
                )
            )
            active_samples = 0
            maximum_active_samples = 0
            errors: list[BaseException] = []

            def sample_clock(*_args: object) -> auth_carrier._ClockSample:
                nonlocal active_samples, maximum_active_samples
                with sample_lock:
                    active_samples += 1
                    maximum_active_samples = max(
                        maximum_active_samples,
                        active_samples,
                    )
                time.sleep(0.02)
                with sample_lock:
                    active_samples -= 1
                    return next(samples)

            def revalidate() -> None:
                try:
                    start.wait()
                    revalidate_external_auth_source(path, evidence)
                except BaseException as error:
                    errors.append(error)

            workers = tuple(threading.Thread(target=revalidate) for _ in range(2))
            with mock.patch.object(
                auth_carrier,
                "_validated_clock_sample",
                side_effect=sample_clock,
            ):
                for worker in workers:
                    worker.start()
                start.wait()
                for worker in workers:
                    worker.join(timeout=2)

            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertEqual(errors, [])
            self.assertEqual(maximum_active_samples, 1)
            self.assertEqual(evidence.clock_high_water.last_monotonic_time, 511)
            self.assertEqual(evidence.clock_high_water.effective_wall_time, 1_011)

    def test_suspend_aware_clock_selects_only_supported_sources(self) -> None:
        with (
            mock.patch.object(
                auth_carrier.time,
                "CLOCK_BOOTTIME",
                7,
                create=True,
            ),
            mock.patch.object(
                auth_carrier.time,
                "clock_gettime",
                return_value=123.5,
            ) as clock_gettime,
        ):
            self.assertEqual(auth_carrier._suspend_aware_monotonic(), 123.5)
        clock_gettime.assert_called_once_with(7)

        with (
            mock.patch.object(
                auth_carrier.time,
                "CLOCK_BOOTTIME",
                None,
                create=True,
            ),
            mock.patch.object(auth_carrier.sys, "platform", "darwin"),
            mock.patch.object(
                auth_carrier,
                "_darwin_continuous_seconds",
                return_value=456.25,
            ) as darwin_clock,
        ):
            self.assertEqual(auth_carrier._suspend_aware_monotonic(), 456.25)
        darwin_clock.assert_called_once_with()

        with (
            mock.patch.object(
                auth_carrier.time,
                "CLOCK_BOOTTIME",
                None,
                create=True,
            ),
            mock.patch.object(auth_carrier.sys, "platform", "unsupported"),
            self.assertRaisesRegex(OSError, "no suspend-aware"),
        ):
            auth_carrier._suspend_aware_monotonic()

    def test_revalidation_fails_closed_for_invalid_clock_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            evidence = load_external_auth(
                path,
                now=1_000,
                monotonic_now=500,
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
                        monotonic_now=500,
                    )
            for invalid_monotonic_now in (True, float("nan"), float("inf")):
                with (
                    self.subTest(monotonic_now=invalid_monotonic_now),
                    self.assertRaisesRegex(AuthCarrierError, "clock value is invalid"),
                ):
                    revalidate_external_auth_source(
                        path,
                        evidence,
                        now=1_000,
                        monotonic_now=invalid_monotonic_now,
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
            with (
                mock.patch.object(
                    auth_carrier,
                    "_suspend_aware_monotonic",
                    side_effect=OSError("clock unavailable"),
                ),
                self.assertRaisesRegex(AuthCarrierError, "clock is unavailable"),
            ):
                revalidate_external_auth_source(path, evidence, now=1_000)
            with self.assertRaisesRegex(
                AuthCarrierError,
                "monotonic clock moved backwards",
            ):
                revalidate_external_auth_source(
                    path,
                    evidence,
                    now=1_000,
                    monotonic_now=499.999,
                )

            for field in ("wall_time_baseline", "monotonic_time_baseline"):
                malformed = dataclasses.replace(evidence, **{field: float("nan")})
                with (
                    self.subTest(evidence_field=field),
                    self.assertRaisesRegex(
                        AuthCarrierError,
                        "external-auth evidence is malformed",
                    ),
                ):
                    revalidate_external_auth_source(
                        path,
                        malformed,
                        now=1_000,
                        monotonic_now=500,
                    )

            malformed_state = dataclasses.replace(
                evidence,
                clock_high_water=object(),
            )
            with self.assertRaisesRegex(
                AuthCarrierError,
                "external-auth evidence is malformed",
            ):
                revalidate_external_auth_source(
                    path,
                    malformed_state,
                    now=1_000,
                    monotonic_now=500,
                )

    def test_rejects_same_inode_write_during_descriptor_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = self.write_auth(pathlib.Path(raw_root), expiration=10_000)
            original_read = auth_carrier._read_auth_fd_exact
            before = path.stat()

            def mutate_after_read(
                fd: int,
                *,
                expected_size: int,
            ) -> tuple[bytearray, str]:
                raw, digest = original_read(
                    fd,
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
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
                return raw, digest

            with (
                mock.patch.object(
                    auth_carrier,
                    "_read_auth_fd_exact",
                    side_effect=mutate_after_read,
                ),
                self.assertRaisesRegex(
                    AuthCarrierContentMismatch,
                    "content changed during inspection",
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
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

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
                            carrier.write(b"[" if first == b"{" else b"{")
                            carrier.flush()
                            os.fsync(carrier.fileno())
                        os.utime(
                            path,
                            ns=(
                                before.st_atime_ns,
                                before.st_mtime_ns,
                            ),
                        )
                return original_lstat(candidate)

            with (
                mock.patch.object(auth_carrier.os, "lstat", side_effect=race_lstat),
                self.assertRaisesRegex(
                    AuthCarrierContentMismatch,
                    "content changed during inspection",
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
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

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
